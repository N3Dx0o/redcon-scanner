"""
JavaCard threat modeling utilities.

This module provides async helpers that build comprehensive analysis requests for
JavaCard code and configurations. It targets three core areas:
- Applet security: lifecycle, APDU processing, memory/transient usage, firewall/sharing
- APDU handling: parsing/validation, length checks, dispatch correctness, status words
- Secure channel (SCP): initialization, MAC/ENC checks, SSC management, downgrade resistance

Each function returns a structured message including the code and operational context
to support AI-assisted security reviews of JavaCard deployments.
"""

from typing import Annotated


async def javacard_applet_threats(
    function_explanation: Annotated[str, "Describe the JavaCard applet purpose, lifecycle (install, select, process), use of persistent/transient objects, and interactions with other applets (object sharing, firewall)."],
    function_body: Annotated[str, "Applet code to review (install(), process(APDU), select(), deselect(), object allocations, transactions, exception handling, shareable objects)."],
    file_path: Annotated[str, "Path to applet source (e.g., 'jc/Applet.java')."],
    applet_context: Annotated[str, "JC version, CAP build options, package AIDs, applet AIDs, use of transactions, transient arrays, JCSystem APIs, firewall/shareable interfaces, event handling."],
    list_of_applet_threats: Annotated[list[str], "Threats such as 'APDU parsing errors', 'Buffer overflows/array bounds', 'Lack of input length checks', 'Transaction misuse/atomicity', 'Use-after-free like patterns', 'Leaking sensitive data from transient to persistent', 'Improper object sharing/firewall bypass', 'Sensitive data lifetime in RAM/EEPROM', 'Unhandled exceptions causing info leak', 'Race/atomicity with tear/reset', 'Weak randomness on-card', 'Side-channel sensitive branches', 'CAP export leakage', 'AID enumeration risks'."],
) -> str:
    """
    Build an analysis request for JavaCard applet security.

    Args:
        function_explanation: Applet purpose and lifecycle summary (install/select/process).
        function_body: Applet source code to review.
        file_path: Path to the applet source file.
        applet_context: JavaCard/GlobalPlatform context, AIDs, transactions, transient usage, firewall/sharing.
        list_of_applet_threats: Specific applet threats to evaluate.

    Returns:
        str: A structured analysis message including the code and context.
    """
    msg = f"""
JAVACARD APPLET THREAT ANALYSIS REQUEST

Function Context:
- Applet Purpose: {function_explanation}
- File Location: {file_path}
- Applet Context: {applet_context}
- Applet Threats to Evaluate: {', '.join(list_of_applet_threats)}

Applet Source Code to Analyze:
{function_body}

Please analyze the applet for APDU parsing robustness, transaction usage, memory handling (persistent vs transient), firewall/object sharing, and side-channel safety. Provide concrete findings and mitigations aligned with JavaCard best practices.
"""
    return msg


async def javacard_apdu_threats(
    function_explanation: Annotated[str, "Describe APDU command set, CLA/INS/P1/P2 semantics, data layout, and expected lengths for incoming/outgoing buffers."],
    function_body: Annotated[str, "APDU handling/parsing code including CLA/INS dispatch, length checks, Le/Lc handling, buffer access, and error status words."],
    file_path: Annotated[str, "Path to source implementing APDU handling."],
    apdu_context: Annotated[str, "Transport (contact/contactless), ISO 7816 details, extended length support, secure messaging on/off, max buffer sizes, chaining."],
    list_of_apdu_threats: Annotated[list[str], "Threats like 'Improper Lc/Le validation', 'Negative offsets/overlaps', 'APDU chaining misuse', 'Status word inconsistencies', 'Unexpected INS fallthrough', 'CLA masking errors', 'Buffer aliasing', 'Timing differences by error type', 'Exposure of sensitive data in SW bytes', 'Ambiguous INS routing', 'Extended length parsing errors'."],
) -> str:
    """
    Build an analysis request for APDU parsing and handling.

    Args:
        function_explanation: Overview of CLA/INS/P1/P2 semantics and buffer layout.
        function_body: Source code implementing APDU parsing/dispatch.
        file_path: Path to the APDU handling source.
        apdu_context: Transport, ISO7816 features, extended length, secure messaging, and limits.
        list_of_apdu_threats: Specific APDU threats to evaluate.

    Returns:
        str: A structured analysis message to review APDU robustness.
    """
    msg = f"""
JAVACARD APDU HANDLING THREAT ANALYSIS REQUEST

Function Context:
- APDU Purpose: {function_explanation}
- File Location: {file_path}
- APDU Context: {apdu_context}
- APDU Threats to Evaluate: {', '.join(list_of_apdu_threats)}

APDU Handling Source Code to Analyze:
{function_body}

Please evaluate APDU parsing, length validation, buffer safety, instruction dispatch, status word consistency, chaining semantics, and secure messaging interactions. Provide concrete remediation steps.
"""
    return msg


async def javacard_secure_channel_threats(
    function_explanation: Annotated[str, "Describe secure channel setup (e.g., SCP02/SCP03), key derivation/loading, key versions, sequence counters, and security levels used (C-MAC, C-ENC, R-MAC)."],
    function_body: Annotated[str, "Secure channel code: INITIALIZE UPDATE/EXTERNAL AUTHENTICATE flows, MAC/ENC checks, SSC updates, key selection, error handling."],
    file_path: Annotated[str, "Path to secure channel implementation."],
    scp_context: Annotated[str, "GlobalPlatform version, SCP variant, crypto providers on-card, key sizes, diversification, key rotation policy, channel binding to AID, restrictions on unsecured APDUs."],
    list_of_scp_threats: Annotated[list[str], "Threats like 'Incorrect SSC increment/reset', 'Weak key diversification', 'MAC verification gaps', 'Replay due to SSC desync', 'Downgrade to unsecured level', 'Inconsistent security level per INS', 'Key version mismatch', 'IV/nonce reuse', 'Timing oracles on MAC failure', 'Unprotected R-APDUs', 'Key material exposure in exceptions/logs'."],
) -> str:
    """
    Build an analysis request for JavaCard secure channel (SCP) security.

    Args:
        function_explanation: Description of SCP setup, key handling and security levels.
        function_body: Source code for SCP flows and verifications.
        file_path: Path to the SCP implementation.
        scp_context: GP version, SCP variant, key sizes/derivation, channel binding and policy.
        list_of_scp_threats: Specific SCP threats to evaluate.

    Returns:
        str: A structured analysis message to assess SCP correctness and resilience.
    """
    msg = f"""
JAVACARD SECURE CHANNEL (SCP) THREAT ANALYSIS REQUEST

Function Context:
- SCP Purpose: {function_explanation}
- File Location: {file_path}
- SCP Context: {scp_context}
- SCP Threats to Evaluate: {', '.join(list_of_scp_threats)}

Secure Channel Source Code to Analyze:
{function_body}

Please assess the secure channel initialization, MAC/ENC verification, sequence counter management, downgrade resistance, and key lifecycle. Provide actionable mitigations.
"""
    return msg


