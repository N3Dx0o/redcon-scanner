from typing import Annotated


async def ssl_tls_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the SSL/TLS function does, its purpose in secure communication, and its role in the cryptographic protocol. Should include SSL/TLS operations, handshake procedures, and any SSL/TLS-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the SSL/TLS function including all statements, variable assignments, control flow, function calls, SSL/TLS operations, and any nested logic. This is the actual SSL/TLS code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'crypto/ssl_handler.py', 'src/security/TLSClient.js', 'app/crypto/TLSServer.rs'). Used for context and reporting."], 
    ssl_tls_context: Annotated[str, "Additional SSL/TLS context including the protocol version (e.g., TLS 1.2, TLS 1.3), cipher suites, certificate validation, and critical SSL/TLS operations this function handles."],
    list_of_ssl_tls_threats: Annotated[list[str], "A comprehensive list of SSL/TLS-specific threats and vulnerabilities to check for during analysis. Each item should be a specific SSL/TLS threat type (e.g., 'SSL/TLS Protocol Vulnerabilities', 'SSL/TLS Handshake Attacks', 'SSL/TLS Cipher Suite Vulnerabilities', 'SSL/TLS Certificate Issues', 'SSL/TLS Certificate Validation Bypass', 'SSL/TLS Certificate Chain Issues', 'SSL/TLS Certificate Revocation Issues', 'SSL/TLS Certificate Pinning Issues', 'SSL/TLS Certificate Transparency Issues', 'SSL/TLS Certificate Authority Issues', 'SSL/TLS Certificate Trust Issues', 'SSL/TLS Certificate Verification Issues', 'SSL/TLS Certificate Authentication Issues', 'SSL/TLS Certificate Authorization Issues', 'SSL/TLS Certificate Access Control Issues', 'SSL/TLS Certificate Session Management Issues', 'SSL/TLS Certificate Input Validation Issues', 'SSL/TLS Certificate Output Encoding Issues', 'SSL/TLS Certificate Error Handling Issues', 'SSL/TLS Certificate Logging Issues', 'SSL/TLS Certificate Monitoring Issues', 'SSL/TLS Certificate Auditing Issues', 'SSL/TLS Certificate Reporting Issues', 'SSL/TLS Certificate Analytics Issues', 'SSL/TLS Certificate Mining Issues', 'SSL/TLS Certificate Machine Learning Issues', 'SSL/TLS Certificate AI Issues', 'SSL/TLS Certificate Algorithm Issues', 'SSL/TLS Certificate Model Issues', 'SSL/TLS Certificate Training Issues', 'SSL/TLS Certificate Testing Issues', 'SSL/TLS Certificate Validation Issues', 'SSL/TLS Certificate Cross-Validation Issues', 'SSL/TLS Certificate Overfitting Issues', 'SSL/TLS Certificate Underfitting Issues', 'SSL/TLS Certificate Bias Issues', 'SSL/TLS Certificate Fairness Issues', 'SSL/TLS Certificate Discrimination Issues', 'SSL/TLS Downgrade Attacks', 'SSL/TLS Man-in-the-Middle Attacks', 'SSL/TLS Replay Attacks', 'SSL/TLS Session Hijacking', 'SSL/TLS Session Fixation', 'SSL/TLS Session Management Issues', 'SSL/TLS Input Validation Issues', 'SSL/TLS Output Encoding Issues', 'SSL/TLS Error Handling Issues', 'SSL/TLS Logging Issues', 'SSL/TLS Monitoring Issues', 'SSL/TLS Auditing Issues', 'SSL/TLS Reporting Issues', 'SSL/TLS Analytics Issues', 'SSL/TLS Mining Issues', 'SSL/TLS Machine Learning Issues', 'SSL/TLS AI Issues', 'SSL/TLS Algorithm Issues', 'SSL/TLS Model Issues', 'SSL/TLS Training Issues', 'SSL/TLS Testing Issues', 'SSL/TLS Validation Issues', 'SSL/TLS Cross-Validation Issues', 'SSL/TLS Overfitting Issues', 'SSL/TLS Underfitting Issues', 'SSL/TLS Bias Issues', 'SSL/TLS Fairness Issues', 'SSL/TLS Discrimination Issues', etc.)."]
) -> str:
    """
    Build a TLS-focused prompt for handshake/record/cert validation logic.

    Parameters:
        function_explanation (str): Role in handshake/record/cert flow and guarantees.
        function_body (str): Exact code.
        file_path (str): Repo-relative path.
        ssl_tls_context (str): TLS version, cipher suites, cert pinning/validation rules, ALPN/SNI.
        list_of_ssl_tls_threats (list[str]): Downgrade, MITM, cert path validation, session resumption,
            renegotiation, PSK misuse, weak ciphers, record padding/oracles.

    Output:
        str: Prompt asking LLM to surface precise issues and fixes with references.
    """
    msg = f"""
SSL/TLS THREAT ANALYSIS REQUEST

Function Context:
- SSL/TLS Purpose: {function_explanation}
- File Location: {file_path}
- SSL/TLS Context: {ssl_tls_context}
- SSL/TLS Threats to Evaluate: {', '.join(list_of_ssl_tls_threats)}

SSL/TLS Source Code to Analyze:
{function_body}

Please perform a comprehensive SSL/TLS security analysis focusing on the specified threats and provide detailed findings with SSL/TLS-specific attack vector analysis, potential SSL/TLS impact, and remediation guidance specific to SSL/TLS vulnerabilities and secure SSL/TLS implementation practices.
"""

    return msg


async def handshake_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the handshake function does, its purpose in cryptographic handshake procedures, and its role in establishing secure connections. Should include handshake operations, key exchange, and any handshake-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the handshake function including all statements, variable assignments, control flow, function calls, handshake operations, and any nested logic. This is the actual handshake code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'crypto/handshake.py', 'src/security/HandshakeClient.js', 'app/crypto/HandshakeServer.rs'). Used for context and reporting."], 
    handshake_context: Annotated[str, "Additional handshake context including the handshake protocol (e.g., TLS handshake, DTLS handshake, custom handshake), key exchange method, and critical handshake operations this function handles."],
    list_of_handshake_threats: Annotated[list[str], "A comprehensive list of handshake-specific threats and vulnerabilities to check for during analysis. Each item should be a specific handshake threat type (e.g., 'Handshake Protocol Vulnerabilities', 'Handshake Key Exchange Attacks', 'Handshake Authentication Attacks', 'Handshake Authorization Attacks', 'Handshake Access Control Attacks', 'Handshake Session Management Attacks', 'Handshake Input Validation Attacks', 'Handshake Output Encoding Attacks', 'Handshake Error Handling Attacks', 'Handshake Logging Attacks', 'Handshake Monitoring Attacks', 'Handshake Auditing Attacks', 'Handshake Reporting Attacks', 'Handshake Analytics Attacks', 'Handshake Mining Attacks', 'Handshake Machine Learning Attacks', 'Handshake AI Attacks', 'Handshake Algorithm Attacks', 'Handshake Model Attacks', 'Handshake Training Attacks', 'Handshake Testing Attacks', 'Handshake Validation Attacks', 'Handshake Cross-Validation Attacks', 'Handshake Overfitting Attacks', 'Handshake Underfitting Attacks', 'Handshake Bias Attacks', 'Handshake Fairness Attacks', 'Handshake Discrimination Attacks', 'Handshake Man-in-the-Middle Attacks', 'Handshake Replay Attacks', 'Handshake Session Hijacking', 'Handshake Session Fixation', 'Handshake Downgrade Attacks', 'Handshake Cipher Suite Attacks', 'Handshake Certificate Attacks', 'Handshake Certificate Validation Attacks', 'Handshake Certificate Chain Attacks', 'Handshake Certificate Revocation Attacks', 'Handshake Certificate Pinning Attacks', 'Handshake Certificate Transparency Attacks', 'Handshake Certificate Authority Attacks', 'Handshake Certificate Trust Attacks', 'Handshake Certificate Verification Attacks', 'Handshake Certificate Authentication Attacks', 'Handshake Certificate Authorization Attacks', 'Handshake Certificate Access Control Attacks', 'Handshake Certificate Session Management Attacks', 'Handshake Certificate Input Validation Attacks', 'Handshake Certificate Output Encoding Attacks', 'Handshake Certificate Error Handling Attacks', 'Handshake Certificate Logging Attacks', 'Handshake Certificate Monitoring Attacks', 'Handshake Certificate Auditing Attacks', 'Handshake Certificate Reporting Attacks', 'Handshake Certificate Analytics Attacks', 'Handshake Certificate Mining Attacks', 'Handshake Certificate Machine Learning Attacks', 'Handshake Certificate AI Attacks', 'Handshake Certificate Algorithm Attacks', 'Handshake Certificate Model Attacks', 'Handshake Certificate Training Attacks', 'Handshake Certificate Testing Attacks', 'Handshake Certificate Validation Attacks', 'Handshake Certificate Cross-Validation Attacks', 'Handshake Certificate Overfitting Attacks', 'Handshake Certificate Underfitting Attacks', 'Handshake Certificate Bias Attacks', 'Handshake Certificate Fairness Attacks', 'Handshake Certificate Discrimination Attacks', etc.)."]
) -> str:
    """
    Create a prompt to assess cryptographic handshakes and key exchange flows.

    Parameters:
        function_explanation (str): Exchange method and auth guarantees.
        function_body (str): Exact code.
        file_path (str): Repo-relative path.
        handshake_context (str): Protocol (TLS/DTLS/custom), ciphers, client/server auth, resumption.
        list_of_handshake_threats (list[str]): MITM, downgrade, transcript binding, key share misuse,
            certificate/auth failures, parameter negotiation pitfalls.

    Output:
        str: Prompt guiding LLM to report issues with concrete remediations.
    """
    msg = f"""
HANDSHAKE THREAT ANALYSIS REQUEST

Function Context:
- Handshake Purpose: {function_explanation}
- File Location: {file_path}
- Handshake Context: {handshake_context}
- Handshake Threats to Evaluate: {', '.join(list_of_handshake_threats)}

Handshake Source Code to Analyze:
{function_body}

Please perform a comprehensive handshake security analysis focusing on the specified threats and provide detailed findings with handshake-specific attack vector analysis, potential handshake impact, and remediation guidance specific to handshake vulnerabilities and secure handshake implementation practices.
"""

    return msg


async def protocol_downgrade_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the protocol downgrade function does, its purpose in protocol version management, and its role in handling protocol downgrade attacks. Should include downgrade detection, version negotiation, and any downgrade-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the protocol downgrade function including all statements, variable assignments, control flow, function calls, downgrade operations, and any nested logic. This is the actual protocol downgrade code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'crypto/downgrade_protection.py', 'src/security/ProtocolDowngrade.js', 'app/crypto/DowngradeDetector.rs'). Used for context and reporting."], 
    downgrade_context: Annotated[str, "Additional protocol downgrade context including the protocol type (e.g., TLS, SSH, HTTP), supported versions, downgrade prevention mechanisms, and critical downgrade operations this function handles."],
    list_of_downgrade_threats: Annotated[list[str], "A comprehensive list of protocol downgrade-specific threats and vulnerabilities to check for during analysis. Each item should be a specific downgrade threat type (e.g., 'Protocol Downgrade Attacks', 'Version Negotiation Attacks', 'Downgrade Detection Bypass', 'Downgrade Prevention Bypass', 'Downgrade Exploitation', 'Downgrade Injection', 'Downgrade Manipulation', 'Downgrade Forgery', 'Downgrade Replay', 'Downgrade Reuse', 'Downgrade Amplification', 'Downgrade Chaining', 'Downgrade Cascading', 'Downgrade Propagation', 'Downgrade Escalation', 'Downgrade Privilege Escalation', 'Downgrade Access Control Bypass', 'Downgrade Authentication Bypass', 'Downgrade Authorization Bypass', 'Downgrade Session Hijacking', 'Downgrade Session Fixation', 'Downgrade Session Management Issues', 'Downgrade Input Validation Bypass', 'Downgrade Output Encoding Bypass', 'Downgrade Error Handling Bypass', 'Downgrade Logging Bypass', 'Downgrade Monitoring Bypass', 'Downgrade Auditing Bypass', 'Downgrade Reporting Bypass', 'Downgrade Analytics Bypass', 'Downgrade Mining Bypass', 'Downgrade Machine Learning Bypass', 'Downgrade AI Bypass', 'Downgrade Algorithm Bypass', 'Downgrade Model Bypass', 'Downgrade Training Bypass', 'Downgrade Testing Bypass', 'Downgrade Validation Bypass', 'Downgrade Cross-Validation Bypass', 'Downgrade Overfitting Bypass', 'Downgrade Underfitting Bypass', 'Downgrade Bias Bypass', 'Downgrade Fairness Bypass', 'Downgrade Discrimination Bypass', etc.)."]
) -> str:
    """
    Prepare a prompt to review version negotiation and downgrade defenses.

    Parameters:
        function_explanation (str): Negotiation intent and minimums.
        function_body (str): Exact code.
        file_path (str): Repo-relative path.
        downgrade_context (str): Supported versions, signaling (e.g., TLS 1.3 downgrade SCSV), policy.
        list_of_downgrade_threats (list[str]): Version pinning gaps, SNI/ALPN interactions, SCSV usage,
            logging/alerts, fallback logic, legacy compat risks.

    Output:
        str: Prompt asking for specific issues and remediation guidance.
    """
    msg = f"""
PROTOCOL DOWNGRADE THREAT ANALYSIS REQUEST

Function Context:
- Downgrade Purpose: {function_explanation}
- File Location: {file_path}
- Downgrade Context: {downgrade_context}
- Downgrade Threats to Evaluate: {', '.join(list_of_downgrade_threats)}

Protocol Downgrade Source Code to Analyze:
{function_body}

Please perform a comprehensive protocol downgrade security analysis focusing on the specified threats and provide detailed findings with downgrade-specific attack vector analysis, potential downgrade impact, and remediation guidance specific to protocol downgrade vulnerabilities and secure downgrade prevention practices.
"""

    return msg
