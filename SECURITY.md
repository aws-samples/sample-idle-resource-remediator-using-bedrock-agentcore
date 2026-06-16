# Security

## Non-Production Disclaimer

This project is provided as a sample/reference implementation for educational and demonstration purposes only. It is NOT intended for production use without additional security hardening.

## Reporting a Vulnerability

If you discover a potential security issue in this project, we ask that you notify AWS/Amazon Security via our [vulnerability reporting page](https://aws.amazon.com/security/vulnerability-reporting/). Please do **not** create a public GitHub issue.

## AWS Services Used

This project interacts with the following AWS services:

- Amazon Bedrock (AI model invocation)
- AWS Compute Optimizer (idle resource recommendations)
- Amazon CloudWatch (metric retrieval)
- Amazon EC2 (instance, volume, and EIP management)
- AWS IAM (permission validation via SimulatePrincipalPolicy)
- AWS STS (caller identity verification)

## Prerequisites and Permissions

- AWS credentials with appropriate read permissions for the target accounts
- The agent validates permissions before taking any actions using SimulatePrincipalPolicy
- IAM authentication is used (no hardcoded credentials)

## Known Security Considerations

- Bare except clauses exist in non-critical name-lookup paths (best-effort display, no logic affected)
- Development dependencies use minimum version constraints for vulnerability patching

## Production Hardening Recommendations

Before using this in a production environment, implement the following:

1. **Path validation:** Ensure all file output paths are validated against an allowed directory
2. **Bedrock Guardrails:** Configure Amazon Bedrock Guardrails to filter harmful prompts and enforce content policies
3. **Audit logging:** Send all agent actions to CloudWatch Logs with a dedicated log group for audit trail
4. **Network isolation:** Run the agent in a private subnet with no inbound internet access
5. **Encryption:** EBS snapshots are created with encryption enabled by default. For additional control, configure a customer-managed KMS key in the GUARDRAILS configuration.
6. **Least privilege IAM:** Restrict the agent role to only the specific accounts and regions it needs to operate on
7. **Rate limiting:** Implement throttling on the number of remediation actions per execution

## Resource Cleanup

After using this sample, clean up resources to avoid ongoing charges:

- Delete any snapshots created during remediation
- Remove any IAM roles created for the agent
- Delete CloudWatch log groups if no longer needed

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| strands-agents | 0.1.0 | AI agent framework |
| strands-agents-bedrock | 0.1.0 | Bedrock model provider |
| boto3 | 1.35.0 | AWS SDK |
| mcp[cli] | 1.27.2 | Model Context Protocol |
