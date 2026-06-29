# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""
MCP Server for Idle Resource Remediator.

Exposes the agent's tools as MCP endpoints so customers can plug them
into any GenAI tool that supports MCP (Claude Desktop, Kiro, Cursor, etc).

Usage:
    # Run directly
    python3 src/mcp_server.py

    # Or via uvx (after publishing)
    uvx idle-resource-remediator

    # Add to Claude Desktop config (claude_desktop_config.json):
    {
      "mcpServers": {
        "idle-resource-remediator": {
          "command": "python3",
          "args": ["src/mcp_server.py"],
          "env": {"AWS_PROFILE": "your-profile", "AWS_REGION": "us-east-1"}
        }
      }
    }
"""

import boto3
from botocore.exceptions import ClientError
import json
import os
import re
from datetime import datetime, timedelta, timezone
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("idle-resource-remediator")

# Region config from environment or default to all
EXCLUDED_REGIONS = ["us-gov-west-1", "us-gov-east-1", "cn-north-1", "cn-northwest-1"]


def _get_regions() -> list:
    """Get regions to scan — from env var or discover all."""
    env_regions = os.environ.get("SCAN_REGIONS")
    if env_regions:
        return [r.strip() for r in env_regions.split(",")]
    ec2 = boto3.client("ec2", region_name="us-east-1")
    response = ec2.describe_regions(AllRegionsOpt=False)
    return [r["RegionName"] for r in response["Regions"] if r["RegionName"] not in EXCLUDED_REGIONS]


@mcp.tool()
def get_idle_resources(account_id: str, regions: list[str] | None = None) -> dict:
    """Scan Compute Optimizer for idle resource recommendations.

    Args:
        account_id: AWS account ID to scan
        regions: Optional list of regions. If not provided, scans all enabled regions.

    Returns:
        List of idle resources with resource ID, type, region, name, and estimated monthly savings.
    """
    scan_regions = regions or _get_regions()
    results = []

    for region in scan_regions:
        try:
            co = boto3.client("compute-optimizer", region_name=region)
            ec2 = boto3.client("ec2", region_name=region)
            response = co.get_idle_recommendations(maxResults=100, accountIds=[account_id])

            for rec in response.get("idleRecommendations", []):
                savings = rec.get("savingsOpportunity", {})
                monthly = savings.get("estimatedMonthlySavings", {}).get("value", 0)
                resource_id = rec.get("resourceId", "")

                # Enrich with name tag
                name = ""
                try:
                    if "i-" in resource_id:
                        desc = ec2.describe_instances(InstanceIds=[resource_id])
                        tags = {t["Key"]: t["Value"] for t in desc["Reservations"][0]["Instances"][0].get("Tags", [])}
                        name = tags.get("Name", "")
                    elif "vol-" in resource_id:
                        desc = ec2.describe_volumes(VolumeIds=[resource_id])
                        tags = {t["Key"]: t["Value"] for t in desc["Volumes"][0].get("Tags", [])}
                        name = tags.get("Name", "")
                except (KeyError, IndexError, ClientError):
                    pass

                results.append({
                    "resource_id": resource_id,
                    "resource_type": rec.get("resourceType", ""),
                    "region": region,
                    "name": name,
                    "monthly_savings": monthly,
                })
        except Exception as e:
            results.append({"region": region, "error": re.sub(r'\d{12}', '***REDACTED***', str(e))})

    return {"idle_resources": results, "total_count": len([r for r in results if "error" not in r])}


@mcp.tool()
def get_usage_pattern(resource_id: str, region: str, days: int = 60) -> dict:
    """Get CloudWatch usage metrics for a resource over a time period.

    Args:
        resource_id: EC2 instance ID (i-xxx) or EBS volume ID (vol-xxx)
        region: AWS region
        days: Number of days to look back (default 60)

    Returns:
        Metric summary with peak CPU, total network packets, disk I/O, and idle assessment.
    """
    cw = boto3.client("cloudwatch", region_name=region)
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)

    if resource_id.startswith("i-"):
        metrics = {}
        for metric_name, stat in [("CPUUtilization", "Maximum"), ("NetworkPacketsIn", "Sum"),
                                   ("NetworkPacketsOut", "Sum"), ("DiskReadOps", "Sum"),
                                   ("EBSReadOps", "Sum"), ("EBSWriteOps", "Sum")]:
            resp = cw.get_metric_statistics(
                Namespace="AWS/EC2", MetricName=metric_name,
                Dimensions=[{"Name": "InstanceId", "Value": resource_id}],
                StartTime=start, EndTime=end, Period=86400, Statistics=[stat]
            )
            datapoints = resp.get("Datapoints", [])
            if stat == "Maximum":
                metrics[metric_name] = max((dp[stat] for dp in datapoints), default=0)
            else:
                metrics[metric_name] = sum(dp[stat] for dp in datapoints)

        idle = metrics["CPUUtilization"] < 5 and metrics["NetworkPacketsIn"] == 0
        return {"resource_id": resource_id, "region": region, "days": days, "metrics": metrics, "is_idle": idle}

    elif resource_id.startswith("vol-"):
        read_ops = 0
        write_ops = 0
        for metric_name in ["VolumeReadOps", "VolumeWriteOps"]:
            resp = cw.get_metric_statistics(
                Namespace="AWS/EBS", MetricName=metric_name,
                Dimensions=[{"Name": "VolumeId", "Value": resource_id}],
                StartTime=start, EndTime=end, Period=86400, Statistics=["Sum"]
            )
            total = sum(dp["Sum"] for dp in resp.get("Datapoints", []))
            if metric_name == "VolumeReadOps":
                read_ops = total
            else:
                write_ops = total

        return {"resource_id": resource_id, "region": region, "days": days,
                "metrics": {"VolumeReadOps": read_ops, "VolumeWriteOps": write_ops},
                "is_idle": read_ops == 0 and write_ops == 0}

    return {"error": f"Unsupported resource type: {resource_id}"}


@mcp.tool()
def check_safety(resource_id: str, region: str) -> dict:
    """Run safety signal checks on a resource before any action.

    Args:
        resource_id: EC2 instance ID or EBS volume ID
        region: AWS region

    Returns:
        Safety verdict (SAFE/INVESTIGATE/BLOCKED) with signal details.
    """
    ec2 = boto3.client("ec2", region_name=region)
    cw = boto3.client("cloudwatch", region_name=region)
    signals = []

    if resource_id.startswith("i-"):
        instance = ec2.describe_instances(InstanceIds=[resource_id])
        inst = instance["Reservations"][0]["Instances"][0]

        # ASG check
        for tag in inst.get("Tags", []):
            if tag["Key"] == "aws:autoscaling:groupName":
                signals.append({"signal": "ASG member", "severity": "BLOCKED", "detail": tag["Value"]})

        # Network activity (3 days)
        net = cw.get_metric_statistics(
            Namespace="AWS/EC2", MetricName="NetworkPacketsIn",
            Dimensions=[{"Name": "InstanceId", "Value": resource_id}],
            StartTime=datetime.now(timezone.utc) - timedelta(days=3),
            EndTime=datetime.now(timezone.utc), Period=86400, Statistics=["Sum"]
        )
        if any(dp["Sum"] > 1000 for dp in net.get("Datapoints", [])):
            signals.append({"signal": "Network activity (3d)", "severity": "INVESTIGATE"})

        # IAM role
        if inst.get("IamInstanceProfile"):
            signals.append({"signal": "IAM role attached", "severity": "INVESTIGATE"})

    elif resource_id.startswith("vol-"):
        # Recent snapshot
        snaps = ec2.describe_snapshots(Filters=[{"Name": "volume-id", "Values": [resource_id]}], OwnerIds=["self"])
        if snaps["Snapshots"]:
            latest = max(snaps["Snapshots"], key=lambda s: s["StartTime"])
            days_since = (datetime.now(latest["StartTime"].tzinfo) - latest["StartTime"]).days
            if days_since < 30:
                signals.append({"signal": f"Recent snapshot ({days_since}d ago)", "severity": "INFO"})

    # Determine verdict
    if any(s["severity"] == "BLOCKED" for s in signals):
        verdict = "BLOCKED"
    elif any(s["severity"] == "INVESTIGATE" for s in signals):
        verdict = "INVESTIGATE"
    else:
        verdict = "SAFE"

    return {"resource_id": resource_id, "region": region, "verdict": verdict, "signals": signals}


@mcp.tool()
def stop_instance(instance_id: str, region: str, reason: str) -> dict:
    """Stop an EC2 instance. Requires prior safety check with SAFE verdict.

    Args:
        instance_id: EC2 instance ID (i-xxx)
        region: AWS region
        reason: Reason for stopping (for audit trail)

    Returns:
        Result of the stop operation.
    """
    # Safety check first
    safety = check_safety(instance_id, region)
    if safety["verdict"] != "SAFE":
        return {"error": f"Cannot stop: verdict is {safety['verdict']}", "signals": safety["signals"]}

    ec2 = boto3.client("ec2", region_name=region)
    ec2.stop_instances(InstanceIds=[instance_id])

    return {"action": "stop_instance", "instance_id": instance_id, "region": region,
            "reason": reason, "result": "success", "timestamp": datetime.now(timezone.utc).isoformat()}


@mcp.tool()
def snapshot_and_delete_volume(volume_id: str, region: str, reason: str) -> dict:
    """Create a snapshot of an EBS volume then delete it. Snapshot is mandatory.

    Args:
        volume_id: EBS volume ID (vol-xxx)
        region: AWS region
        reason: Reason for deletion (for audit trail)

    Returns:
        Result including snapshot ID created before deletion.
    """
    # Safety check first
    safety = check_safety(volume_id, region)
    if safety["verdict"] == "BLOCKED":
        return {"error": f"Cannot delete: verdict is BLOCKED", "signals": safety["signals"]}

    ec2 = boto3.client("ec2", region_name=region)

    # Mandatory snapshot
    snap = ec2.create_snapshot(
        VolumeId=volume_id,
        Description=f"Pre-delete backup by idle-resource-remediator {datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
    )
    snapshot_id = snap["SnapshotId"]

    # Wait for snapshot
    waiter = ec2.get_waiter("snapshot_completed")
    waiter.wait(SnapshotIds=[snapshot_id])

    # Delete volume
    ec2.delete_volume(VolumeId=volume_id)

    return {"action": "snapshot_and_delete_volume", "volume_id": volume_id, "region": region,
            "snapshot_id": snapshot_id, "reason": reason, "result": "success",
            "timestamp": datetime.now(timezone.utc).isoformat()}


@mcp.tool()
def release_elastic_ip(allocation_id: str, region: str, reason: str) -> dict:
    """Release an unassociated Elastic IP address.

    Args:
        allocation_id: EIP allocation ID (eipalloc-xxx)
        region: AWS region
        reason: Reason for release (for audit trail)

    Returns:
        Result of the release operation.
    """
    ec2 = boto3.client("ec2", region_name=region)

    # Verify it's unassociated
    addresses = ec2.describe_addresses(AllocationIds=[allocation_id])
    addr = addresses["Addresses"][0]
    if addr.get("AssociationId"):
        return {"error": "EIP is still associated", "association_id": addr["AssociationId"]}

    ec2.release_address(AllocationId=allocation_id)

    return {"action": "release_elastic_ip", "allocation_id": allocation_id, "region": region,
            "public_ip": addr.get("PublicIp"), "reason": reason, "result": "success",
            "timestamp": datetime.now(timezone.utc).isoformat()}


if __name__ == "__main__":
    mcp.run()
