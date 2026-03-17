"""
Shamir Secret Sharing (SSS) threat modeling utilities.

This module provides async helpers that construct thorough analysis prompts/messages
for reviewing Shamir Secret Sharing implementations. Focus areas include:
- Polynomial generation and coefficient randomness
- Field arithmetic correctness and modulus selection
- Threshold (t, n) configuration and downgrade resistance
- Interpolation safety and side-channel resilience
- Share lifecycle security (serialization, transport, storage, rotation, destruction)

Each function returns a structured message incorporating source code and context
to drive downstream AI-assisted security analysis workflows.
"""

from typing import Annotated


async def shamir_scheme_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Shamir Secret Sharing (SSS) function does, its purpose (e.g., split or combine), and its role in the system. Should include threshold t, total shares n, finite field details, and any security-critical logic."],
    function_body: Annotated[str, "The complete source code of the SSS function including all statements, variable assignments, control flow, math/field operations, and any nested logic. This is the actual SSS code that will be analyzed for vulnerabilities."],
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'crypto/shamir.py', 'src/security/sss.rs'). Used for context and reporting."],
    shamir_context: Annotated[str, "Additional SSS context including (t, n), prime/modulus, interpolation method, randomness source for coefficients, share validation tags/MACs, and encoding/serialization details."],
    list_of_shamir_threats: Annotated[list[str], "A list of SSS-specific threats to check (e.g., 'Weak Coefficient RNG', 'Non-prime/incorrect field modulus', 'Share index collisions', 'Lagrange interpolation mistakes', 'Off-by-one threshold errors', 'Information leakage via share format/length', 'Side-channel leakage in interpolation', 'Unverified share authenticity', 'No checksum/MAC for shares', 'Insecure share transport/storage', 'Threshold downgrade or misuse', 'Small-field brute force', 'Insecure secret padding or encoding', 'Deterministic coefficients', 'Reuse of polynomial across secrets', 'Share reuse across contexts', 'No domain separation for polynomials', 'Lack of share revocation/rotation', 'No binding of shares to identity/purpose', 'Fault-injection resilience', 'Shamir over non-field structures', 'Floating-point usage', 'Integer overflow/underflow', 'Timing differences on combine', 'Error messages revealing indices or t', 'Missing input validation', 'Serialization ambiguities']"],
) -> str:
    """
    Build an analysis request for Shamir Secret Sharing split/combine logic.

    Args:
        function_explanation: Human-readable description of the SSS routine and its role.
        function_body: The full source code of the SSS routine under review.
        file_path: Path to the file containing the SSS routine.
        shamir_context: Operational details such as (t, n), field modulus, interpolation method,
            randomness source, and any share authentication/encoding specifics.
        list_of_shamir_threats: Specific SSS threats to evaluate.

    Returns:
        str: A structured analysis message containing context and the provided source code.
    """
    msg = f"""
SHAMIR SECRET SHARING (SSS) THREAT ANALYSIS REQUEST

Function Context:
- SSS Purpose: {function_explanation}
- File Location: {file_path}
- SSS Context: {shamir_context}
- SSS Threats to Evaluate: {', '.join(list_of_shamir_threats)}

SSS Source Code to Analyze:
{function_body}

Please perform a comprehensive security analysis of the Shamir Secret Sharing implementation focusing on the specified threats. Provide detailed findings, attack scenarios (including side-channel and misuse), threshold soundness checks, and remediation guidance specific to robust SSS design and implementation.
"""

    return msg


async def shamir_threshold_threats(
    function_explanation: Annotated[str, "Explain the threshold logic and its enforcement across the system. Include how t and n are configured, validated, and protected against misuse or downgrade."],
    function_body: Annotated[str, "Source code implementing threshold checks or enforcement (validation of t, n; enforcement on combine; policy checks; configuration loading)."],
    file_path: Annotated[str, "The file path containing threshold-related logic."],
    threshold_context: Annotated[str, "Operational context: who sets t/n, acceptable ranges, policy constraints, dynamic updates/rotations, and auditing requirements."],
    list_of_threshold_threats: Annotated[list[str], "Threats such as 'Threshold downgrade attacks', 'Incorrect boundary checks', 'Mismatched t/n between components', 'Stale configs without rotation', 'Bypass of combine preconditions', 'Silent acceptance of invalid shares', 'Off-by-one in reconstruction', 'Untrusted config sources', 'Missing audit of threshold changes', 'Privilege escalation via threshold edits'."],
) -> str:
    """
    Build an analysis request for threshold (t, n) configuration and enforcement.

    Args:
        function_explanation: Description of how thresholds are validated/enforced.
        function_body: Code responsible for threshold checks and related policy logic.
        file_path: Path to the file containing the threshold logic.
        threshold_context: Operational constraints, policy rules, rotation and auditing details.
        list_of_threshold_threats: Specific threshold-related threats to evaluate.

    Returns:
        str: A structured analysis message to guide threshold security review.
    """
    msg = f"""
SHAMIR THRESHOLD HANDLING THREAT ANALYSIS REQUEST

Function Context:
- Threshold Handling Purpose: {function_explanation}
- File Location: {file_path}
- Threshold Context: {threshold_context}
- Threshold Threats to Evaluate: {', '.join(list_of_threshold_threats)}

Threshold Handling Source Code to Analyze:
{function_body}

Please evaluate the threshold configuration, validation, persistence, and enforcement for correctness and tamper-resistance. Identify downgrade/bypass paths and propose mitigations.
"""

    return msg


async def shamir_share_management_threats(
    function_explanation: Annotated[str, "Explain how shares are generated, labeled, serialized, transported, stored, rotated, and destroyed. Include any authenticity or integrity mechanisms (MAC, signature, AEAD)."],
    function_body: Annotated[str, "Code responsible for share lifecycle: generation, serialization, parsing, verification, transport/storage adapters, rotation, and destruction."],
    file_path: Annotated[str, "The file path containing share lifecycle logic."],
    share_mgmt_context: Annotated[str, "Share lifecycle policies: identity binding, purpose binding, revocation/rotation cadence, at-rest/in-transit protections, DLP, access controls, and backups."],
    list_of_share_mgmt_threats: Annotated[list[str], "Threats like 'Unauthenticated shares (no MAC/signature)', 'Ambiguous serialization', 'No versioning/domain separation', 'Weak KMS/HSM policies', 'Insecure transport', 'No at-rest encryption', 'No tamper-evident storage', 'Improper destruction', 'Share sprawl and leakage', 'Insufficient logging/auditing', 'Recovery without quorum', 'Phishing/social engineering collection of shares', 'Index collisions', 'Loss of share provenance', 'Backup exposure', 'Cross-environment reuse', 'No binding to project/tenant'."],
) -> str:
    """
    Build an analysis request for Shamir share lifecycle security.

    Args:
        function_explanation: Description of share generation, labeling, transport, storage and rotation.
        function_body: Code managing share creation, serialization, verification and destruction.
        file_path: Path to the file containing share lifecycle code.
        share_mgmt_context: Policies for identity/purpose binding, revocation, access control and backups.
        list_of_share_mgmt_threats: Specific lifecycle threats to evaluate.

    Returns:
        str: A structured analysis message to assess share handling robustness.
    """
    msg = f"""
SHAMIR SHARE MANAGEMENT THREAT ANALYSIS REQUEST

Function Context:
- Share Management Purpose: {function_explanation}
- File Location: {file_path}
- Share Management Context: {share_mgmt_context}
- Share Management Threats to Evaluate: {', '.join(list_of_share_mgmt_threats)}

Share Management Source Code to Analyze:
{function_body}

Please analyze the end-to-end share lifecycle with emphasis on authenticity (MAC/signatures), integrity, confidentiality, provenance, rotation, destruction, and operational controls. Provide concrete remediation guidance.
"""

    return msg


