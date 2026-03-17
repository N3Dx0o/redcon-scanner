from typing import Annotated


async def cdk_general_threats(
    function_explanation: Annotated[str, "What the CDK construct/stack does, purpose, and role. Include environments, accounts, and regions targeted."],
    function_body: Annotated[str, "Exact CDK (TypeScript/Python/Java) code for the construct/stack under review. Include all props and defaults."],
    file_path: Annotated[str, "Repo-relative path (e.g., 'infra/lib/app-stack.ts', 'threat_modeling_tools/infrastructure/aws_cdk_stack.py')."],
    cdk_context: Annotated[str, "CDK version, language, context.json values, bootstrap status, and synth/deploy details. Mention tags and permissions boundary if used."],
    list_of_cdk_threats: Annotated[list[str], "Specific threats to check (e.g., overly broad IAM, public S3, open SG, missing encryption, missing logging, public ALB, missing WAF, default KMS, missing VPC endpoints, unrestricted ECR pulls)."],
) -> str:
    """
    Build an LLM-ready prompt to review AWS CDK code for secure-by-default posture.

    Parameters:
        function_explanation (str): High-level intent and guarantees of the stack/construct.
        function_body (str): Exact CDK code to analyze.
        file_path (str): Path to the file containing the CDK resource definitions.
        cdk_context (str): Important CDK settings and environment details.
        list_of_cdk_threats (list[str]): Concrete checks to perform.

    Output:
        str: Prompt instructing the LLM to produce findings with references and actionable remediations.

    LLM guidance:
        - Validate network exposure (public subnets, SG ingress 0.0.0.0/0, internet-facing LB).
        - Check encryption at rest (S3, EBS, RDS, EFS) and in transit (listeners, policies).
        - Review IAM policies for least privilege; avoid wildcards and * resources/actions.
        - Ensure logging/monitoring (S3 access logs, ALB logs, CloudTrail, CW Logs, WAF). 
        - Prefer VPC endpoints for S3/DynamoDB and block public access where applicable.
    """
    msg = f"""
AWS CDK THREAT ANALYSIS REQUEST

Context:
- Purpose: {function_explanation}
- File: {file_path}
- CDK Context: {cdk_context}
- Threats to Evaluate: {', '.join(list_of_cdk_threats)}

CDK Source To Analyze:
{function_body}

Please analyze the CDK code for the listed threats and provide:
1) Findings with severity and exact code references
2) Exploit/exposure scenarios
3) Concrete remediation steps with secure CDK patterns
"""

    return msg


async def cdk_iam_threats(
    function_explanation: Annotated[str, "IAM roles/policies purpose and required permissions."],
    function_body: Annotated[str, "Exact CDK code defining IAM Role/Policy/PolicyStatement/ManagedPolicy attachments."],
    file_path: Annotated[str, "Path to source with IAM definitions."],
    iam_context: Annotated[str, "Permissions boundaries, SCPs, organization constraints, service principals, tags."],
    list_of_iam_threats: Annotated[list[str], "Over-permissive actions/resources, * wildcards, missing conditions, AssumeRole trust policy risks, cross-account assumptions, secrets/KMS access."],
) -> str:
    """
    Create a prompt to evaluate IAM constructs for least-privilege and safe trust policies.

    Output:
        str: LLM prompt requesting issues with code refs and remediations (conditions, resource scoping, managed policy choices).
    """
    msg = f"""
AWS CDK IAM THREAT ANALYSIS REQUEST
- Purpose: {function_explanation}
- File: {file_path}
- IAM Context: {iam_context}
- IAM Threats: {', '.join(list_of_iam_threats)}

Code:
{function_body}

Please identify over-broad permissions and unsafe trust policies and propose least-privilege fixes (conditions, resource ARNs, principals) with code examples.
"""
    return msg


async def cdk_network_threats(
    function_explanation: Annotated[str, "VPC/LB/SG design intent and exposure model."],
    function_body: Annotated[str, "Exact CDK code for VPCs, subnets, route tables, gateways, security groups, NACLs, load balancers, listeners."],
    file_path: Annotated[str, "Path to networking definitions."],
    network_context: Annotated[str, "AZ count, NAT strategy, ingress requirements, private endpoints, WAF usage."],
    list_of_network_threats: Annotated[list[str], "0.0.0.0/0 ingress, public subnets for data stores, missing WAF, open admin ports, missing VPC endpoints, overly permissive NACLs."],
) -> str:
    """
    Build a prompt to assess CDK networking for unnecessary public exposure and missing controls.
    """
    msg = f"""
AWS CDK NETWORK THREAT ANALYSIS REQUEST
- Purpose: {function_explanation}
- File: {file_path}
- Network Context: {network_context}
- Network Threats: {', '.join(list_of_network_threats)}

Code:
{function_body}

Please evaluate exposure (subnets/SG/LB), recommend private-by-default designs, and propose WAF/endpoints and restricted ingress with specific CDK changes.
"""
    return msg


async def cdk_storage_threats(
    function_explanation: Annotated[str, "Storage design (S3/EBS/EFS/RDS) purpose and data sensitivity."],
    function_body: Annotated[str, "Exact CDK code for buckets/volumes/filesystems/databases."],
    file_path: Annotated[str, "Path to storage definitions."],
    storage_context: Annotated[str, "Encryption requirements (KMS vs SSE-S3), access patterns, logging/retention."],
    list_of_storage_threats: Annotated[list[str], "Public buckets, missing encryption, missing access logs, weak bucket policies, world-readable objects, database public access, missing backups."],
) -> str:
    """
    Construct a prompt to verify encryption, access control, and logging for CDK storage resources.
    """
    msg = f"""
AWS CDK STORAGE THREAT ANALYSIS REQUEST
- Purpose: {function_explanation}
- File: {file_path}
- Storage Context: {storage_context}
- Storage Threats: {', '.join(list_of_storage_threats)}

Code:
{function_body}

Please identify missing encryption/logging and public exposure, and provide hardened CDK property suggestions (block public access, bucket policies, kmsKeys, logging).
"""
    return msg


async def cdk_lambda_threats(
    function_explanation: Annotated[str, "Lambda function purpose, triggers, and required permissions."],
    function_body: Annotated[str, "Exact CDK code for Lambda (runtime, env vars, layers, timeouts, memory)."],
    file_path: Annotated[str, "Path to lambda definitions."],
    lambda_context: Annotated[str, "Packaging method, VPC config, concurrency, env secret handling, logging/metrics."],
    list_of_lambda_threats: Annotated[list[str], "Over-broad IAM, plaintext secrets in env, no timeouts, public URLs, excessive memory/time, missing VPC egress control."],
) -> str:
    """
    Prepare a prompt to assess AWS Lambda definitions and operational hardening in CDK.
    """
    msg = f"""
AWS CDK LAMBDA THREAT ANALYSIS REQUEST
- Purpose: {function_explanation}
- File: {file_path}
- Lambda Context: {lambda_context}
- Lambda Threats: {', '.join(list_of_lambda_threats)}

Code:
{function_body}

Please review IAM scope, secret handling, timeouts, network placement, and logging, and propose hardened CDK config (VPC, security groups, kms, log retention, env redaction).
"""
    return msg


