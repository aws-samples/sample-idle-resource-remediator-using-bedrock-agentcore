# idle-resource-remediator

An AI agent built with [Strands Agents SDK](https://github.com/strands-agents/sdk-python) and Amazon Bedrock that scans AWS accounts for idle resources, validates findings with 60-day CloudWatch metrics, and safely remediates waste with mandatory snapshot-before-delete, safety signal checks, double confirmation, and full audit trails.

## Important

**This is sample code for demonstration and educational purposes only. It is not intended for production use.** You should work with your security and legal teams to meet your organizational security, regulatory, and compliance requirements before deploying in any environment. Deploying this sample may incur AWS charges for creating or using AWS chargeable resources.

## How It Works

The agent uses the Strands SDK with Amazon Bedrock (Claude Sonnet with adaptive thinking) as the reasoning engine. Tools are defined as Python functions decorated with `@tool`. The model decides which tools to call based on the conversation context.

```
┌──────────────┐     ┌─────-──────────────────┐     ┌──────────────────┐
│ User         │────▶│ Strands Agent          │────▶│ AWS APIs         │
│              │     │ (Bedrock Claude)       │     │ (EC2, CW, CO, CE)│
└──────────────┘     │                        │     └──────────────────┘
                     │ • Bedrock Guardrail    │
                     │ • DryRun permission    │
                     │ • Safety signal checks │
                     │ • Double confirmation  │
                     │ • Audit logging        │
                     │ • MCP: Billing         │────▶ Cost Explorer
                     │ • MCP: Pricing         │────▶ Price List API
                     └────────────────────────┘
```

## Capabilities

**Phase 1 — Discovery**
* Idle EC2 instances via Compute Optimizer recommendations
* Unattached EBS volumes (status=available, zero I/O)
* Unassociated Elastic IPs
* Enrichment with Name tags, instance types, creation dates

**Phase 2 — Metric Validation (60-day CloudWatch lookback)**
* EC2: CPUUtilization, NetworkPacketsIn/Out, DiskReadOps, EBSReadOps
* EBS: VolumeReadOps, VolumeWriteOps
* Confirms idleness with data, not assumptions

**Phase 3 — Safety Checks**
* Auto Scaling Group membership → BLOCKED
* Recent network activity (3-day lookback) → INVESTIGATE
* IAM instance profile attached → INVESTIGATE
* Recent snapshot < 30 days → INFO
* Verdict per resource: SAFE / INVESTIGATE / BLOCKED

**Phase 4 — Remediation**
* Stop idle EC2 instances
* Snapshot then delete EBS volumes (snapshot mandatory)
* Release Elastic IPs
* Batch limit: 5 per request with summary between batches
* Full audit trail (CSV) for every action

## Safety Architecture

```
User Request
     │
     ▼
┌─────────────────────┐
│ Bedrock Guardrail   │ ← Blocks prompt injection, credential exposure
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ Permission Check    │ ← SimulatePrincipalPolicy evaluates full IAM chain
│ (STS + IAM Simulate)│
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ Resource Signals    │ ← ASG? Network? IAM role? Recent snapshot?
│ (CloudWatch + Tags) │
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ Double Confirmation │ ← Gate 1: "Do you want to proceed?" (yes/no)
│                     │   Gate 2: "Type 'confirm delete vol-xxx'"
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ Snapshot First      │ ← Mandatory before any volume delete (code-enforced)
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ Execute + Audit Log │ ← CSV: who, what, when, why, result, snapshot ID
└─────────────────────┘
```

## Prerequisites

* Python 3.12+
* AWS credentials configured (SSO, IAM role, or environment variables)
* (Recommended) `iam:SimulatePrincipalPolicy` permission on the caller's own ARN for upfront permission validation. Without it, write permissions are validated at execution time.
* Amazon Bedrock access with Claude Sonnet model enabled
* (Optional) AWS Compute Optimizer enabled in the target account for idle recommendations
* (Optional) Amazon Bedrock Guardrail created for prompt injection protection

## Installation

```bash
git clone <repo-url>
cd idle-resource-remediator
python3 --version  # Ensure Python 3.12+
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## Configuration

Edit `GUARDRAILS` in `src/agent.py`:

```python
GUARDRAILS = {
    "allowed_regions": "all",  # "all" discovers via ec2 describe-regions, or pass a list
    "excluded_regions": ["us-gov-west-1", "us-gov-east-1", "cn-north-1", "cn-northwest-1"],
    "max_actions_per_request": 5,
    "require_snapshot_before_delete": True,
    "bedrock_guardrail": {
        "guardrail_id": "YOUR_GUARDRAIL_ID",  # Create via Bedrock console
        "guardrail_version": "DRAFT",
    },
}
```

### Changing the Model

The agent defaults to `us.anthropic.claude-sonnet-4-6` via cross-region inference. You can change this to any Bedrock-supported model by editing the `model_id` in `src/agent.py`:

```python
model = BedrockModel(model_id="us.anthropic.claude-sonnet-4-6")  # Change to your preferred model
```

### Creating a Bedrock Guardrail (optional but recommended)

1. Open the [Amazon Bedrock console](https://console.aws.amazon.com/bedrock/home#/guardrails)
2. Create a guardrail with:
   - Content filter: Prompt attack detection (MEDIUM)
   - Sensitive information: Block AWS access key patterns
   - Denied topics: Data exfiltration attempts
3. Copy the guardrail ID into the config above

## Usage

```bash
# Run the agent
python3 src/agent.py
```

The agent will:
1. Authenticate via STS and display your identity
2. Run DryRun permission checks and show what you CAN/CANNOT do
3. Wait for your instructions

### Example Interaction

```
$ python3 src/agent.py

[AUTH] Identity resolved: arn:aws:iam::123456789012:role/CostOpsRole
[AUTH] Using iam:SimulatePrincipalPolicy for permission check...
[AUTH] ec2:StopInstances  allowed
[AUTH] ec2:CreateSnapshot  allowed
[AUTH] ec2:DeleteVolume  allowed
[AUTH] ec2:ReleaseAddress  denied
[AUTH] ec2:DescribeInstances  allowed
[AUTH] cloudwatch:GetMetricStatistics  allowed
[AUTH] compute-optimizer:GetIdleRecommendations  allowed
[REGIONS] Scanning 16 regions

You are successfully Authenticated: jane.doe
  Role: CostOpsRole
  Account: 123456789012
  You CAN: get_idle_resources, get_usage_pattern, stop_instance, snapshot_and_delete_volume
  You CANNOT: release EIPs

> Scan my account for idle resources

[IDLE] Scanning Compute Optimizer in eu-west-2...
[IDLE] Found 3 idle resources

| # | Resource | Name | Type | Region | Monthly Savings |
|---|----------|------|------|--------|----------------|
| 1 | i-0abc123 | dev-worker | m5.large | eu-west-2 | $67.20 |
| 2 | vol-0def456 | — | 100GB gp3 | eu-west-2 | $8.00 |

> Delete the idle volume vol-0def456

[SAFETY] Checking signals for vol-0def456...
[SAFETY] No active signals detected

Volume: vol-0def456
Size: 100GB gp3 | AZ: eu-west-2a
I/O (60d): 0 read ops, 0 write ops
Safety verdict: SAFE

Do you want to proceed with deleting vol-0def456? A snapshot will be created first. (yes/no)

> yes

Type 'confirm delete vol-0def456' to execute.

> confirm delete vol-0def456

[ACTION] Creating snapshot of vol-0def456...
[ACTION] Snapshot snap-0ghi789 completed
[ACTION] Deleting vol-0def456...
[ACTION] Volume deleted successfully
[AUDIT] Logged to reports/audit-log.csv
```

## MCP Server Integration (Optional)

The agent automatically connects to AWS MCP servers at runtime via `uvx` for enhanced cost analysis (pricing lookups and Cost Explorer queries). No manual installation is needed — `uvx` (provided by the `uv` dependency) downloads and launches the servers on first run.

If `uvx` is unavailable or the MCP servers fail to connect, the agent continues without them — core functionality is unaffected.

## Audit Log

Every destructive action is logged to `reports/audit-log.csv`:

```csv
timestamp,action,resource_id,resource_type,region,account_id,role_arn,verdict,result,snapshot_id
2026-05-25T10:30:00Z,delete-volume,vol-0abc123,ebs,eu-west-2,123456789012,arn:aws:iam::...,SAFE,success,snap-0def456
```

## Use as MCP Server

> **Security Note:** The MCP server exposes destructive tools (stop, delete, release) over stdio transport. It is designed for local use only — do NOT expose it over a network. The server relies on the calling client (Claude Desktop, Kiro, etc.) to handle user confirmation. When used outside the Strands agent, the double-confirmation safety gate is the client's responsibility. Do not include sensitive personal information in your prompts.

The agent's tools are also exposed as an MCP server, so customers can plug them into any GenAI tool that supports MCP (Claude Desktop, Kiro, Amazon Q, Cursor, etc).

### Run the MCP server

```bash
python3 src/mcp_server.py
```

You can attach the MCP server to any MCP-compatible client. Below are examples for popular tools:

### Add to Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "idle-resource-remediator": {
      "command": "python3",
      "args": ["/path/to/idle-resource-remediator/src/mcp_server.py"],
      "env": {
        "AWS_PROFILE": "your-profile",
        "AWS_REGION": "us-east-1"
      }
    }
  }
}
```

### Add to Kiro

```json
{
  "mcpServers": {
    "idle-resource-remediator": {
      "command": "python3",
      "args": ["src/mcp_server.py"],
      "env": {"AWS_PROFILE": "your-profile"}
    }
  }
}
```

### Available MCP Tools

| Tool | Description | Destructive? |
|---|---|---|
| `get_idle_resources` | Scan Compute Optimizer for idle recommendations | No |
| `get_usage_pattern` | Pull 60-day CloudWatch metrics for a resource | No |
| `check_safety` | Run safety signal checks (ASG, network, IAM) | No |
| `stop_instance` | Stop an EC2 instance (requires SAFE verdict) | Yes |
| `snapshot_and_delete_volume` | Snapshot then delete EBS volume | Yes |
| `release_elastic_ip` | Release unassociated EIP | Yes |

### Environment Variables

| Variable | Description | Default |
|---|---|---|
| `AWS_PROFILE` | AWS credentials profile | default |
| `AWS_REGION` | Default region for API calls | us-east-1 |
| `SCAN_REGIONS` | Comma-separated regions to scan | all enabled regions |

## Limitations

* Compute Optimizer must be enabled (opt-in) for idle recommendations — the agent falls back to CloudWatch-only validation if unavailable
* CloudWatch lookback defaults to 60 days but works with whatever history is available — no setup needed
* Bedrock access required in the deployment region
* Single account at a time (multi-account via Organizations planned)
* Guardrail ID is account-specific — create your own via Bedrock console

## Security

See [CONTRIBUTING](CONTRIBUTING.md) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

