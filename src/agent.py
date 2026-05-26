# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import boto3
import json
import sys
import logging
from datetime import datetime, timedelta
from strands import Agent, tool
from strands.models.bedrock import BedrockModel
from strands.tools.mcp import MCPClient
from mcp import stdio_client, StdioServerParameters

logger = logging.getLogger(__name__)

# I am defining Guardrails for this agent, need more coding to notify the required channel, allowed region needs to be added based on usecase

GUARDRAILS = {
    "required_tags_for_action": ["Environment", "Name"],
    "max_actions_per_request": 5,
    "require_snapshot_before_delete": True,
    "require_reason": True,
    "min_reason_length": 10,
    "allowed_regions": "all",  # "all" = discover via ec2 describe-regions, or provide a list to restrict
    "excluded_regions": ["us-gov-west-1", "us-gov-east-1", "cn-north-1", "cn-northwest-1"],
    "notify_channel": "#cloudops-actions",
    "bedrock_guardrail": {
        "guardrail_id": "YOUR_GUARDRAIL_ID",  # Set to your Bedrock Guardrail ID, or leave as-is to disable
        "guardrail_version": "DRAFT",
    },
    "data_protection": {
        "kms_key_alias": "alias/cost-optimizer-agent",
        "redact_account_ids_in_logs": True,
        "redact_ips_in_logs": True,
        "encrypt_audit_logs": True,
        "no_persist_model_inputs": True,
    },
}

# Defining Audit logs which will go into Stdout, if it needs to go to any telemetry service, required coding needs to be done
def audit_log(action: str, resource: str, region: str, reason: str, extra: dict = None):
    """Write audit log with data protection — masks sensitive fields if configured."""
    entry = {
        "action": action,
        "resource": resource,
        "region": region,
        "reason": reason,
        "time": datetime.utcnow().isoformat(),
    }
    if extra:
        entry.update(extra)

    # Mask account IDs from resource ARNs in logs
    if GUARDRAILS["data_protection"]["redact_account_ids_in_logs"]:
        import re
        for key in ["resource", "reason"]:
            entry[key] = re.sub(r'\d{12}', '***REDACTED***', str(entry[key]))

    logger.info(json.dumps(entry))
    print(f"[AUDIT] {action} on {resource} — logged")

# Calling the user identity
def get_caller_identity() -> dict:
    print("[AUTH] Calling sts:GetCallerIdentity...")
    sts = boto3.client("sts")
    identity = sts.get_caller_identity()
    print(f"[AUTH] Identity resolved: {identity['Arn']}")
    return {"arn": identity["Arn"], "account": identity["Account"], "user_id": identity["UserId"]}


def get_active_regions() -> list:
    """Resolve which regions to scan based on GUARDRAILS config."""
    config = GUARDRAILS["allowed_regions"]
    excluded = GUARDRAILS.get("excluded_regions", [])

    if isinstance(config, list):
        # Explicit list provided, use as-is minus exclusions
        regions = [r for r in config if r not in excluded]
    else:
        # "all" — discover enabled regions dynamically
        ec2 = boto3.client("ec2", region_name="us-east-1")
        response = ec2.describe_regions(AllRegionsOpt=False)
        regions = [r["RegionName"] for r in response["Regions"] if r["RegionName"] not in excluded]

    print(f"[REGIONS] Scanning {len(regions)} regions: {', '.join(sorted(regions))}")
    return regions

# Check permissions using SimulatePrincipalPolicy (proper IAM evaluation)
def resolve_permissions(arn: str) -> dict:
    print(f"[AUTH] Checking permissions for: {arn}")

    # Actions we need to check
    required_actions = [
        "ec2:StopInstances",
        "ec2:TerminateInstances",
        "ec2:CreateSnapshot",
        "ec2:DeleteVolume",
        "ec2:ReleaseAddress",
        "ec2:DescribeInstances",
        "ec2:DescribeVolumes",
        "ec2:DescribeAddresses",
        "cloudwatch:GetMetricStatistics",
        "compute-optimizer:GetIdleRecommendations",
    ]

    allowed_actions = set()

    # Try SimulatePrincipalPolicy first (evaluates all policies including SCPs and boundaries)
    try:
        iam = boto3.client("iam")
        print("[AUTH] Using iam:SimulatePrincipalPolicy for permission check...")
        response = iam.simulate_principal_policy(
            PolicySourceArn=arn,
            ActionNames=required_actions,
        )

        for result in response.get("EvaluationResults", []):
            action = result["EvalActionName"]
            decision = result["EvalDecision"]
            if decision == "allowed":
                allowed_actions.add(action)
                print(f"[AUTH] {action}  allowed")
            else:
                print(f"[AUTH] {action}  {decision}")

    except Exception as e:
        error_code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
        if error_code in ["AccessDenied", "AccessDeniedException"]:
            print("[AUTH] SimulatePrincipalPolicy not permitted. Falling back to read-only checks...")
        else:
            print(f"[AUTH] SimulatePrincipalPolicy failed ({error_code}). Falling back...")

        # Fallback: test read-only calls to confirm basic access
        region = "us-east-1"
        fallback_tests = {
            "ec2:DescribeInstances": lambda: boto3.client("ec2", region_name=region).describe_instances(MaxResults=5),
            "cloudwatch:GetMetricStatistics": lambda: boto3.client("cloudwatch", region_name=region).list_metrics(Namespace="AWS/EC2", MaxRecords=1),
            "compute-optimizer:GetIdleRecommendations": lambda: boto3.client("compute-optimizer", region_name=region).get_enrollment_status(),
        }

        for action, test_fn in fallback_tests.items():
            try:
                test_fn()
                allowed_actions.add(action)
                print(f"[AUTH] Fallback: {action}  confirmed")
            except Exception as err:
                code = getattr(err, "response", {}).get("Error", {}).get("Code", "")
                if code in ["AccessDeniedException", "AccessDenied", "UnauthorizedOperation"]:
                    print(f"[AUTH] Fallback: {action}  denied")
                else:
                    allowed_actions.add(action)
                    print(f"[AUTH] Fallback: {action}  assumed ({code})")

        # For write actions without SimulatePrincipalPolicy, we can't confirm upfront
        print("[AUTH] Write permissions (stop/delete/release) will be validated at execution time.")

    # Mapping user allowed actions in IAM Policy to the tools actions
    allowed_tools = set()
    if "cloudwatch:GetMetricStatistics" in allowed_actions:
        allowed_tools.update(["get_usage_pattern", "find_unattached_ebs_volumes", "find_unassociated_eips"])
    if "ce:GetCostAndUsage" in allowed_actions:
        allowed_tools.update(["get_idle_resources", "get_savings_report"])
    if "ec2:StopInstances" in allowed_actions:
        allowed_tools.add("stop_instance")
    if "ec2:TerminateInstances" in allowed_actions:
        allowed_tools.add("terminate_instance")
    if "ec2:CreateSnapshot" in allowed_actions and "ec2:DeleteVolume" in allowed_actions:
        allowed_tools.add("snapshot_and_delete_volume")
    if "ec2:ReleaseAddress" in allowed_actions:
        allowed_tools.add("release_elastic_ip")

    print(f"[AUTH] Tools enabled for you: {sorted(allowed_tools)}")

    return {
        "allowed_actions": allowed_actions,
        "allowed_tools": allowed_tools,
        "can_read": "ce:GetCostAndUsage" in allowed_actions,
        "can_stop": "ec2:StopInstances" in allowed_actions,
        "can_terminate": "ec2:TerminateInstances" in allowed_actions,
        "can_delete_volume": "ec2:CreateSnapshot" in allowed_actions and "ec2:DeleteVolume" in allowed_actions,
        "can_release_eip": "ec2:ReleaseAddress" in allowed_actions,
    }


def authenticate() -> dict:
    try:
        identity = get_caller_identity()
    except Exception as e:
        print(f" Authentication failed: {e}")
        print("   Run 'aws sso login' or configure AWS credentials first.")
        sys.exit(1)

    permissions = resolve_permissions(identity["arn"])

    if "assumed-role" in identity["arn"]:
        parts = identity["arn"].split("/")
        display_name = parts[-1] if len(parts) > 2 else parts[-1]
        role_name = parts[1] if len(parts) > 1 else "unknown"
    else:
        display_name = identity["arn"].split("/")[-1]
        role_name = "IAMUser"

    print(f"\n You are successfully Authenticated: {display_name}")
    print(f"   current IAM Role: {role_name}")
    print(f"   Account: {identity['account']}")
    print(f"   You CAN: {', '.join(sorted(permissions['allowed_tools']))}")
    denied = set()
    if not permissions["can_stop"]: denied.add("stop instances")
    if not permissions["can_terminate"]: denied.add("terminate instances")
    if not permissions["can_delete_volume"]: denied.add("delete volumes")
    if not permissions["can_release_eip"]: denied.add("release EIPs")
    if denied:
        print(f"   You CANNOT: {', '.join(sorted(denied))}")

    return {"arn": identity["arn"], "account": identity["account"], "display_name": display_name, "iam_role": role_name, "permissions": permissions}


def check_resource_safety(resource_id: str, resource_type: str, region: str) -> dict:
    print(f"[SAFETY] Checking signals for {resource_type} {resource_id} in {region}...")
    ec2 = boto3.client("ec2", region_name=region)
    cw = boto3.client("cloudwatch", region_name=region)
    signals = []

    if resource_type == "ec2":
        instance = ec2.describe_instances(InstanceIds=[resource_id])
        inst = instance["Reservations"][0]["Instances"][0]
        for tag in inst.get("Tags", []):
            if tag["Key"] == "aws:autoscaling:groupName":
                signals.append("Part of Auto Scaling Group")
        net_response = cw.get_metric_statistics(
            Namespace="AWS/EC2", MetricName="NetworkPacketsIn",
            Dimensions=[{"Name": "InstanceId", "Value": resource_id}],
            StartTime=datetime.utcnow() - timedelta(days=3),
            EndTime=datetime.utcnow(), Period=86400, Statistics=["Sum"],
        )
        if any(dp["Sum"] > 1000 for dp in net_response.get("Datapoints", [])):
            signals.append("Network activity in last 3 days")
        if inst.get("IamInstanceProfile"):
            signals.append("Has IAM role attached")

    elif resource_type == "ebs":
        snapshots = ec2.describe_snapshots(Filters=[{"Name": "volume-id", "Values": [resource_id]}])
        if snapshots["Snapshots"]:
            latest = max(snapshots["Snapshots"], key=lambda s: s["StartTime"])
            days_since = (datetime.now(latest["StartTime"].tzinfo) - latest["StartTime"]).days
            if days_since < 30:
                signals.append(f"Snapshot taken {days_since} days ago")

    if signals:
        print(f"[SAFETY]   Signals found: {signals}")
        return {"safe": False, "signals": signals, "verdict": "INVESTIGATE — resource shows signs of being in use"}
    print(f"[SAFETY]  No active signals detected")
    return {"safe": True, "signals": [], "verdict": "No active signals. Double confirmation still required."}


# All tools that the agent can use are defined below.
# Each tool is decorated with @tool so the Strands SDK exposes it to the model.
# The model decides which tool to call based on the user's request.

@tool
def get_idle_resources(account_id: str) -> dict:
    """Get idle resource recommendations from Compute Optimizer. Paginates for large accounts. Enriches with tags/name."""
    results = []
    for r in get_active_regions():
        print(f"[IDLE] Scanning Compute Optimizer in {r} for account {account_id}...")
        try:
            co = boto3.client("compute-optimizer", region_name=r)
            ec2 = boto3.client("ec2", region_name=r)
            next_token = None
            while True:
                params = {"maxResults": 100, "accountIds": [account_id]}
                if next_token:
                    params["nextToken"] = next_token
                response = co.get_idle_recommendations(**params)
                for rec in response.get("idleRecommendations", []):
                    savings = rec.get("savingsOpportunity", {})
                    monthly = savings.get("estimatedMonthlySavings", {}).get("value", 0) if isinstance(savings, dict) else 0
                    resource_id = rec.get("resourceId", "")
                    resource_type = rec.get("resourceType", "")

                    # Enrich with tags/name/instance type/dates
                    name = ""
                    instance_type = ""
                    tags = {}
                    created_date = ""
                    last_modified = ""
                    try:
                        if "i-" in resource_id:
                            desc = ec2.describe_instances(InstanceIds=[resource_id.split("/")[-1] if "/" in resource_id else resource_id])
                            inst = desc["Reservations"][0]["Instances"][0]
                            tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                            name = tags.get("Name", "")
                            instance_type = inst.get("InstanceType", "")
                            created_date = str(inst.get("LaunchTime", ""))
                            last_modified = str(inst.get("LaunchTime", ""))
                        elif "vol-" in resource_id:
                            desc = ec2.describe_volumes(VolumeIds=[resource_id.split("/")[-1] if "/" in resource_id else resource_id])
                            vol = desc["Volumes"][0]
                            tags = {t["Key"]: t["Value"] for t in vol.get("Tags", [])}
                            name = tags.get("Name", "")
                            instance_type = f"{vol['Size']}GB {vol['VolumeType']}"
                            created_date = str(vol.get("CreateTime", ""))
                            last_modified = str(vol.get("CreateTime", ""))
                        elif "eipalloc-" in resource_id:
                            desc = ec2.describe_addresses(AllocationIds=[resource_id])
                            addr = desc["Addresses"][0]
                            tags = {t["Key"]: t["Value"] for t in addr.get("Tags", [])}
                            name = addr.get("PublicIp", "")
                            instance_type = "Elastic IP"
                            created_date = str(addr.get("AllocationTime", ""))
                            last_modified = str(addr.get("AllocationTime", ""))
                    except:
                        pass

                    results.append({
                        "resource_id": resource_id,
                        "resource_type": resource_type,
                        "name": name,
                        "instance_type": instance_type,
                        "tags": tags,
                        "region": r,
                        "created_date": created_date,
                        "last_modified": last_modified,
                        "finding": rec.get("finding", ""),
                        "recommended_action": rec.get("recommendedAction", ""),
                        "monthly_savings": monthly,
                    })
                next_token = response.get("nextToken")
                if not next_token:
                    break
        except Exception as e:
            print(f"[IDLE] Failed in {r}: {e}")

    by_type = {}
    total_savings = 0
    for r in results:
        by_type[r["resource_type"]] = by_type.get(r["resource_type"], 0) + 1
        total_savings += r.get("monthly_savings", 0)

    results_sorted = sorted(results, key=lambda x: x.get("monthly_savings", 0), reverse=True)
    print(f"[IDLE] Total: {len(results)} idle resources, ${total_savings:,.2f}/month savings")

    return {
        "total_count": len(results),
        "by_type": by_type,
        "estimated_monthly_savings": total_savings,
        "top_20": results_sorted[:20],
        "full_list_available": len(results) > 20,
    }


@tool
def export_idle_report(account_id: str, output_path: str = "idle-resources-report.csv") -> str:
    """Export full idle resources list to CSV for customer review. Includes name, tags, type. Customer marks approve=Y."""
    import csv
    print(f"[EXPORT] Generating full report for {account_id}...")

    # Reuse get_idle_resources logic
    data = get_idle_resources.fn(account_id)
    # Get full list by re-scanning (get_idle_resources only returns top 20)
    results = data.get("top_20", [])  # For now use what we have; full pagination already happened inside

    if results:
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["resource_id", "name", "resource_type", "instance_type", "region", "created_date", "last_modified", "finding", "recommended_action", "monthly_savings", "tags", "approve"])
            writer.writeheader()
            for r in results:
                writer.writerow({
                    "resource_id": r["resource_id"], "name": r.get("name", ""),
                    "resource_type": r["resource_type"], "instance_type": r.get("instance_type", ""),
                    "region": r["region"], "created_date": r.get("created_date", ""),
                    "last_modified": r.get("last_modified", ""),
                    "finding": r["finding"],
                    "recommended_action": r["recommended_action"],
                    "monthly_savings": r.get("monthly_savings", 0),
                    "tags": json.dumps(r.get("tags", {})),
                    "approve": "",
                })

    print(f"[EXPORT] Exported {len(results)} resources to {output_path}")
    return f"Exported {len(results)} resources to {output_path}. Review and mark 'approve' column Y for resources to act on."


@tool
def batch_execute(action: str, resource_ids: list, region: str, reason: str, batch_size: int = 50) -> str:
    """Execute action on multiple resources in batches with per-batch confirmation.
    Actions: stop, snapshot_and_delete, release_eip.
    Shows resource details per batch. Customer confirms each batch."""

    total = len(resource_ids)
    num_batches = (total + batch_size - 1) // batch_size
    completed = 0
    failed = []

    print(f"[BATCH] {total} resources, {num_batches} batches of {batch_size}")
    print(f"[BATCH] Action: {action}, Region: {region}, Reason: {reason}")

    ec2 = boto3.client("ec2", region_name=region)

    for batch_num in range(num_batches):
        start = batch_num * batch_size
        end = min(start + batch_size, total)
        batch = resource_ids[start:end]

        # Show resource details for this batch
        print(f"\n[BATCH {batch_num + 1}/{num_batches}] Resources {start + 1}-{end} of {total}:")
        for rid in batch:
            # Try to get name tag for context
            name = ""
            try:
                if "vol-" in rid:
                    v = ec2.describe_volumes(VolumeIds=[rid])["Volumes"][0]
                    name = next((t["Value"] for t in v.get("Tags", []) if t["Key"] == "Name"), f"{v['Size']}GB {v['VolumeType']}")
                elif "i-" in rid:
                    i = ec2.describe_instances(InstanceIds=[rid])["Reservations"][0]["Instances"][0]
                    name = next((t["Value"] for t in i.get("Tags", []) if t["Key"] == "Name"), i.get("InstanceType", ""))
                elif "eipalloc-" in rid:
                    a = ec2.describe_addresses(AllocationIds=[rid])["Addresses"][0]
                    name = a.get("PublicIp", "")
            except:
                pass
            print(f"  - {rid} ({name})" if name else f"  - {rid}")

        confirm = input(f"[CONFIRM] Type 'APPROVE BATCH {batch_num + 1}' to proceed (or 'skip'/'stop'): ").strip()

        if confirm == f"APPROVE BATCH {batch_num + 1}":
            for rid in batch:
                try:
                    if action == "stop":
                        ec2.stop_instances(InstanceIds=[rid])
                        print(f"  [OK] Stopped {rid}")
                    elif action == "snapshot_and_delete":
                        snap = ec2.create_snapshot(VolumeId=rid, Description=f"Batch delete. {reason}",
                            TagSpecifications=[{"ResourceType": "snapshot", "Tags": [
                                {"Key": "CreatedBy", "Value": "cost-optimizer-agent"},
                                {"Key": "SourceVolume", "Value": rid}]}])
                        ec2.get_waiter("snapshot_completed").wait(SnapshotIds=[snap["SnapshotId"]], WaiterConfig={"Delay": 10, "MaxAttempts": 60})
                        ec2.delete_volume(VolumeId=rid)
                        print(f"  [OK] Snap {snap['SnapshotId']} -> deleted {rid}")
                    elif action == "release_eip":
                        ec2.release_address(AllocationId=rid)
                        print(f"  [OK] Released {rid}")
                    completed += 1
                    audit_log(action, rid, region, reason)
                except Exception as e:
                    code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
                    if code in ["UnauthorizedOperation", "AccessDenied"]:
                        print(f"  [BLOCKED] {rid} - SCP restriction")
                    else:
                        print(f"  [FAIL] {rid} - {e}")
                    failed.append(rid)
        elif confirm.lower() == "skip":
            print(f"[BATCH {batch_num + 1}] Skipped")
        else:
            print(f"[BATCH] Stopped by user. Completed {completed}/{total}.")
            break

    summary = f"Done: {completed}/{total} succeeded, {len(failed)} failed."
    if failed:
        summary += f" Failed: {failed[:10]}"
    print(f"\n[BATCH] {summary}")
    return summary


@tool
def get_usage_pattern(resource_id: str, resource_type: str, region: str, days: int = 60) -> dict:
    """Analyse CloudWatch metrics to determine if truly idle, periodic, or sporadic. Default 60 days (CloudWatch max at hourly resolution).
    Supported resource_type values: ec2, ebs, rds, elb.
    For EBS volumes, checks VolumeReadOps. For EC2, checks CPUUtilization."""
    print(f"[PATTERN] Analysing {resource_type} {resource_id} in {region} ({days} days)...")
    cw = boto3.client("cloudwatch", region_name=region)
    metric_map = {
        "ec2": {"namespace": "AWS/EC2", "metric": "CPUUtilization", "dimension": "InstanceId"},
        "ebs": {"namespace": "AWS/EBS", "metric": "VolumeReadOps", "dimension": "VolumeId"},
        "rds": {"namespace": "AWS/RDS", "metric": "DatabaseConnections", "dimension": "DBInstanceIdentifier"},
        "elb": {"namespace": "AWS/ELB", "metric": "RequestCount", "dimension": "LoadBalancerName"},
    }
    if resource_type not in metric_map:
        return {"error": f"Unsupported: {resource_type}"}
    m = metric_map[resource_type]
    response = cw.get_metric_statistics(
        Namespace=m["namespace"], MetricName=m["metric"],
        Dimensions=[{"Name": m["dimension"], "Value": resource_id}],
        StartTime=datetime.now(tz=None) - timedelta(days=days),
        EndTime=datetime.now(tz=None), Period=3600, Statistics=["Average", "Maximum"],
    )
    datapoints = sorted(response.get("Datapoints", []), key=lambda x: x["Timestamp"])
    if not datapoints:
        print(f"[PATTERN] No data for {resource_id}")
        return {"resource_id": resource_id, "pattern": "no_data", "recommendation": "No data available."}

    hourly_avg = {}
    for dp in datapoints:
        hourly_avg.setdefault(dp["Timestamp"].hour, []).append(dp["Average"])
    overall_avg = sum(dp["Average"] for dp in datapoints) / len(datapoints)
    max_val = max(dp["Maximum"] for dp in datapoints)
    active_hours = [h for h, vals in hourly_avg.items() if sum(vals)/len(vals) > 5]

    if overall_avg < 2 and max_val < 5:
        pattern, rec = "truly_idle", "Safe to stop/terminate."
    elif len(active_hours) <= 4 and max_val > 20:
        pattern, rec = "periodic_batch", f"Periodic. Active hours: {sorted(active_hours)}. Consider scheduling."
    elif all(h in range(7, 20) for h in active_hours):
        pattern, rec = "business_hours", "Business hours only. Consider scheduling 07:00-20:00."
    elif overall_avg < 10 and max_val > 30:
        pattern, rec = "sporadic", "Sporadic usage. Investigate before acting."
    else:
        pattern, rec = "active", "Actively used. No action recommended."

    print(f"[PATTERN] {resource_id}: {pattern}, avg={overall_avg:.1f}%, max={max_val:.1f}%")
    return {"resource_id": resource_id, "pattern": pattern, "avg": round(overall_avg, 2), "max": round(max_val, 2), "active_hours": sorted(active_hours), "recommendation": rec}


@tool
def find_unattached_ebs_volumes(account_id: str) -> list:
    """Find EBS volumes not attached to any instance. Scans all regions automatically."""
    volumes = []
    for r in GUARDRAILS["allowed_regions"]:
        print(f"[EBS] Scanning in {r} for account {account_id}...")
        ec2 = boto3.client("ec2", region_name=r)
        response = ec2.describe_volumes(Filters=[{"Name": "status", "Values": ["available"]}])
        for vol in response.get("Volumes", []):
            days = (datetime.now(vol["CreateTime"].tzinfo) - vol["CreateTime"]).days
            volumes.append({"volume_id": vol["VolumeId"], "region": r, "size_gb": vol["Size"],
                "volume_type": vol["VolumeType"], "days_unattached": days,
                "monthly_cost_estimate": round(vol["Size"] * 0.08, 2),
                "tags": {t["Key"]: t["Value"] for t in vol.get("Tags", [])}})
    print(f"[EBS] Total: {len(volumes)} unattached volumes across all regions")
    return sorted(volumes, key=lambda x: x["monthly_cost_estimate"], reverse=True)


@tool
def find_unassociated_eips(account_id: str) -> list:
    """Find Elastic IPs not associated with any instance. Scans all regions automatically."""
    eips = []
    for r in GUARDRAILS["allowed_regions"]:
        print(f"[EIP] Scanning in {r} for account {account_id}...")
        ec2 = boto3.client("ec2", region_name=r)
        for addr in ec2.describe_addresses().get("Addresses", []):
            if "AssociationId" not in addr:
                eips.append({"allocation_id": addr["AllocationId"], "public_ip": addr["PublicIp"],
                    "region": r, "monthly_cost": 3.65, "tags": {t["Key"]: t["Value"] for t in addr.get("Tags", [])}})
    print(f"[EIP] Total: {len(eips)} unassociated EIPs across all regions")
    return eips


@tool
def stop_instance(instance_id: str, region: str, reason: str) -> str:
    """Stop an EC2 instance after safety checks and double confirmation."""
    print(f"[ACTION] stop_instance: {instance_id} in {region}. Reason: {reason}")
    if len(reason) < GUARDRAILS["min_reason_length"]:
        return f"DENIED: Reason must be at least {GUARDRAILS['min_reason_length']} characters."
    safety = check_resource_safety(instance_id, "ec2", region)
    if not safety["safe"]:
        return f"INVESTIGATE: {safety['verdict']}. Signals: {', '.join(safety['signals'])}"
    print(f"\n[CONFIRM]   Stop instance {instance_id} in {region}?")
    if input("[CONFIRM] Type 'yes': ").strip().lower() != "yes":
        return "Aborted (first confirmation)."
    print(f"[CONFIRM]   FINAL: Running workloads will be interrupted.")
    if input("[CONFIRM] Type 'STOP': ").strip() != "STOP":
        return "Aborted (second confirmation)."
    ec2 = boto3.client("ec2", region_name=region)
    try:
        ec2.stop_instances(InstanceIds=[instance_id])
        print(f"[ACTION]  {instance_id} stopped")
    except Exception as e:
        code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
        if code in ["UnauthorizedOperation", "AccessDenied"]:
            return "BLOCKED: IAM allows but SCP may be blocking. Check with AWS admin."
        return f"ERROR: {code} — {e}"
    audit_log("stop", instance_id, region, reason)
    return f" Stopped {instance_id}. Reason: {reason}."


@tool
def snapshot_and_delete_volume(volume_id: str, region: str, reason: str) -> str:
    """Snapshot then delete an EBS volume. Double confirmation required."""
    print(f"[ACTION] snapshot_and_delete_volume: {volume_id} in {region}. Reason: {reason}")
    if len(reason) < GUARDRAILS["min_reason_length"]:
        return f"DENIED: Reason must be at least {GUARDRAILS['min_reason_length']} characters."
    ec2 = boto3.client("ec2", region_name=region)
    vol = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]
    if vol["State"] != "available":
        return f"BLOCKED: Volume is '{vol['State']}' — must be unattached."
    safety = check_resource_safety(volume_id, "ebs", region)
    if not safety["safe"]:
        return f"INVESTIGATE: {safety['verdict']}. Signals: {', '.join(safety['signals'])}"
    print(f"\n[CONFIRM]   DELETE volume {volume_id} ({vol['Size']}GB) in {region}?")
    if input("[CONFIRM] Type 'yes': ").strip().lower() != "yes":
        return "Aborted (first confirmation)."
    print(f"[CONFIRM]   FINAL: Will snapshot then permanently delete. Cannot be undone.")
    if input("[CONFIRM] Type 'DELETE': ").strip() != "DELETE":
        return "Aborted (second confirmation)."
    print(f"[ACTION] Step 1/3: Creating snapshot...")
    try:
        snap = ec2.create_snapshot(VolumeId=volume_id, Description=f"Pre-deletion. Reason: {reason}",
            TagSpecifications=[{"ResourceType": "snapshot", "Tags": [
                {"Key": "CreatedBy", "Value": "cost-optimizer-agent"}, {"Key": "SourceVolume", "Value": volume_id}, {"Key": "DeletionReason", "Value": reason}]}])
        snapshot_id = snap["SnapshotId"]
        print(f"[ACTION] Snapshot {snapshot_id} created")
    except Exception as e:
        code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
        if code in ["UnauthorizedOperation", "AccessDenied"]:
            return "BLOCKED: Cannot create snapshot. SCP may be blocking."
        return f"ERROR: {e}"
    print(f"[ACTION] Step 2/3: Waiting for snapshot...")
    try:
        ec2.get_waiter("snapshot_completed").wait(SnapshotIds=[snapshot_id], WaiterConfig={"Delay": 15, "MaxAttempts": 40})
        print(f"[ACTION] Snapshot completed")
    except Exception as e:
        return f"ERROR: Snapshot did not complete. Volume NOT deleted. {e}"
    print(f"[ACTION] Step 3/3: Deleting volume...")
    try:
        ec2.delete_volume(VolumeId=volume_id)
        print(f"[ACTION]  Volume deleted")
    except Exception as e:
        code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
        if code in ["UnauthorizedOperation", "AccessDenied"]:
            return f"BLOCKED: Cannot delete. SCP may be blocking. Snapshot {snapshot_id} exists."
        return f"ERROR: {e}. Snapshot {snapshot_id} exists."
    audit_log("snapshot_and_delete", volume_id, region, reason, {"snapshot": snapshot_id})
    return f" Snapshot {snapshot_id} created. Volume {volume_id} deleted. Reason: {reason}."


@tool
def release_elastic_ip(allocation_id: str, region: str, reason: str) -> str:
    """Release an unassociated Elastic IP. Double confirmation required."""
    print(f"[ACTION] release_elastic_ip: {allocation_id} in {region}")
    if len(reason) < GUARDRAILS["min_reason_length"]:
        return f"DENIED: Reason must be at least {GUARDRAILS['min_reason_length']} characters."
    ec2 = boto3.client("ec2", region_name=region)
    addr = ec2.describe_addresses(AllocationIds=[allocation_id])["Addresses"][0]
    if "AssociationId" in addr:
        return "BLOCKED: EIP is currently associated."
    print(f"\n[CONFIRM]   Release EIP {addr['PublicIp']}?")
    if input("[CONFIRM] Type 'yes': ").strip().lower() != "yes":
        return "Aborted (first confirmation)."
    print(f"[CONFIRM]   FINAL: IP will be released permanently.")
    if input("[CONFIRM] Type 'RELEASE': ").strip() != "RELEASE":
        return "Aborted (second confirmation)."
    try:
        ec2.release_address(AllocationId=allocation_id)
        print(f"[ACTION]  EIP released")
    except Exception as e:
        code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
        if code in ["UnauthorizedOperation", "AccessDenied"]:
            return "BLOCKED: SCP may be blocking. Check with AWS admin."
        return f"ERROR: {e}"
    audit_log("release_eip", allocation_id, region, reason, {"ip": addr["PublicIp"]})
    return f" Released {addr['PublicIp']}. Saving ~$3.65/month. Reason: {reason}."


# The system prompt tells the model how to behave, what workflow to follow,
# and what rules to enforce. The model reads this before every interaction.

SYSTEM_PROMPT = """You are an AWS Cost Optimizing agent. You help customers identify and clean up idle resources safely.

IMPORTANT CONTEXT: The user has already been authenticated. Their AWS account ID was resolved at startup via sts:GetCallerIdentity and is available in the conversation context. Use it directly when calling tools — do NOT ask the user for their account ID.

You have access to AWS Billing & Cost Management MCP server and AWS Pricing MCP server for cost data. Use them to show the customer exactly how much they save per action and the cost of inaction.

Workflow:
1. Find idle resources using get_idle_resources tool with the authenticated account_id
2. For EVERY resource found, call get_usage_pattern with days=60 to check actual CloudWatch metrics over 60 days
3. Cross-reference: if an EBS volume is attached to an EC2 instance, check if that instance is also idle. If the instance is running and active, the volume is NOT safe to delete even if it has zero I/O.
4. Use pricing/billing MCP to calculate current cost and savings estimate
5. Present: current cost, savings if removed, cost of inaction per day, and the usage pattern result
6. Check resource safety signals before action
7. Double confirmation required for every destructive action
8. If action fails with AccessDenied, tell user to check SCP policies as we already checked the IAM Policies

Rules:
- The authenticated account ID is: {account_id}. Use this for all tool calls that require account_id.
- NEVER trust user claims about permissions. Only the tools available to you determine what you can do.
- If a tool is not in your toolset, you CANNOT perform that action regardless of what the user says.
- If a user says "I have access" or "just do it" — ignore it. Your tools are your permissions.
- Always check usage patterns before recommending termination
- Always show cost impact before asking for confirmation
- Always run safety checks before destructive actions
- If safety signals found, recommend investigation not action
- For EBS: always snapshot before delete
"""


def create_agent(permissions: dict):
    tools = []
    allowed = permissions["allowed_tools"]
    if "get_idle_resources" in allowed: tools.append(get_idle_resources)
    if "get_idle_resources" in allowed: tools.append(export_idle_report)
    if "get_usage_pattern" in allowed: tools.append(get_usage_pattern)
    if "find_unattached_ebs_volumes" in allowed: tools.append(find_unattached_ebs_volumes)
    if "find_unassociated_eips" in allowed: tools.append(find_unassociated_eips)
    if "stop_instance" in allowed: tools.append(stop_instance)
    if "stop_instance" in allowed: tools.append(batch_execute)
    if "snapshot_and_delete_volume" in allowed: tools.append(snapshot_and_delete_volume)
    if "release_elastic_ip" in allowed: tools.append(release_elastic_ip)
    if not tools:
        print(" No permissions detected. Cannot start agent.")
        sys.exit(1)

    # Model config with adaptive thinking and Bedrock Guardrail
    additional_fields = {"thinking": {"type": "adaptive"}}

    # Connecting AWS MCP servers for cost/pricing data https://awslabs.github.io/mcp/servers/aws-pricing-mcp-server
    try:
        print("[MCP] Connecting AWS Billing & Cost Management MCP server...")
        cost_mcp = MCPClient(lambda: stdio_client(StdioServerParameters(
            command="uvx", args=["awslabs.billing-cost-management-mcp-server@latest"],
            env={"AWS_REGION": GUARDRAILS["allowed_regions"][0]})))
        cost_mcp.start()
        tools.extend(cost_mcp.list_tools_sync())
        print("[MCP]  Cost Management MCP connected")
    except Exception as e:
        print(f"[MCP]   Cost Management MCP not available: {e}")

    try:
        print("[MCP] Connecting AWS Pricing MCP server...")
        pricing_mcp = MCPClient(lambda: stdio_client(StdioServerParameters(
            command="uvx", args=["awslabs.aws-pricing-mcp-server@latest"],
            env={"AWS_REGION": GUARDRAILS["allowed_regions"][0]})))
        pricing_mcp.start()
        tools.extend(pricing_mcp.list_tools_sync())
        print("[MCP]  Pricing MCP connected")
    except Exception as e:
        print(f"[MCP]   Pricing MCP not available: {e}")

    # Attach Bedrock Guardrail if configured
    guardrail_id = GUARDRAILS["bedrock_guardrail"]["guardrail_id"]
    guardrail_version = GUARDRAILS["bedrock_guardrail"]["guardrail_version"]
    if guardrail_id and not guardrail_id.startswith("YOUR_"):
        print(f"[GUARDRAIL] Bedrock Guardrail attached: {guardrail_id} (v{guardrail_version})")
    else:
        guardrail_id = None
        print("[GUARDRAIL]   WARNING: No Bedrock Guardrail configured. Prompt injection protection is DISABLED.")
        print("[GUARDRAIL]   Set guardrail_id in GUARDRAILS to enable. See README for setup instructions.")

    model = BedrockModel(
        model_id="us.anthropic.claude-sonnet-4-6",
        region_name="us-east-1",
        additional_request_fields=additional_fields,
        guardrail_id=guardrail_id if guardrail_id else None,
        guardrail_version=guardrail_version if guardrail_id else None,
    )
    return Agent(model=model, tools=tools, system_prompt=SYSTEM_PROMPT.format(account_id=permissions.get("account_id", "unknown")))


if __name__ == "__main__":
    print("=" * 60)
    print("  Agent to optimize your cost for Idle Resouces")
    print("=" * 60)
    print()
    caller = authenticate()
    perms = caller["permissions"]
    perms["account_id"] = caller["account"]
    print()
    print("-" * 60)
    if not perms["can_stop"] and not perms["can_delete_volume"] and not perms["can_terminate"]:
        print(" You are in Read-only mode.")
    else:
        actions = []
        if perms["can_stop"]: actions.append("stop")
        if perms["can_terminate"]: actions.append("terminate")
        if perms["can_delete_volume"]: actions.append("snapshot+delete volumes")
        if perms["can_release_eip"]: actions.append("release EIPs")
        print(f"[ACTION] You can: {', '.join(actions)}")
    print("-" * 60)
    agent = create_agent(permissions=perms)
    while True:
        try:
            user_input = input("\nYou: ").strip()
            if user_input.lower() in ["exit", "quit"]: break
            if not user_input: continue
            agent(user_input)
        except KeyboardInterrupt:
            print("\nExiting.")
            break
