from typing import Annotated


async def mpc_protocol_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the MPC function does, its purpose in multi-party computation, and its role in the MPC protocol. Should include MPC operations, secret sharing, threshold schemes, and any MPC-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the MPC function including all statements, variable assignments, control flow, function calls, MPC operations, and any nested logic. This is the actual MPC code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'crypto/mpc_protocol.py', 'src/security/MPCUtils.js', 'app/crypto/SecretSharing.rs'). Used for context and reporting."], 
    mpc_context: Annotated[str, "Additional MPC context including the MPC protocol type (e.g., Shamir's Secret Sharing, BGW, SPDZ, ABY, GMW), threshold scheme, number of parties, and critical MPC operations this function handles."],
    list_of_mpc_threats: Annotated[list[str], "A comprehensive list of MPC-specific threats and vulnerabilities to check for during analysis. Each item should be a specific MPC threat type (e.g., 'MPC Protocol Vulnerabilities', 'Secret Sharing Attacks', 'Threshold Scheme Attacks', 'Party Collusion Attacks', 'Malicious Party Attacks', 'Semi-Honest Party Attacks', 'Honest-But-Curious Attacks', 'Active Adversary Attacks', 'Passive Adversary Attacks', 'MPC Communication Attacks', 'MPC Synchronization Attacks', 'MPC Coordination Attacks', 'MPC Agreement Attacks', 'MPC Consensus Attacks', 'MPC Finality Attacks', 'MPC Slashing Attacks', 'MPC Reward Attacks', 'MPC Fee Attacks', 'MPC Liquidity Attacks', 'MPC Oracle Attacks', 'MPC Governance Attacks', 'MPC Upgrade Attacks', 'MPC Emergency Attacks', 'MPC Economic Attacks', 'MPC Performance Attacks', 'MPC Reliability Attacks', 'MPC Availability Attacks', 'MPC Consistency Attacks', 'MPC Accuracy Attacks', 'MPC Completeness Attacks', 'MPC Timeliness Attacks', 'MPC Relevance Attacks', 'MPC Quality Attacks', 'MPC Security Attacks', 'MPC Access Attacks', 'MPC Authorization Attacks', 'MPC Authentication Attacks', 'MPC Encryption Attacks', 'MPC Hashing Attacks', 'MPC Compression Attacks', 'MPC Decompression Attacks', 'MPC Transformation Attacks', 'MPC Aggregation Attacks', 'MPC Filtering Attacks', 'MPC Sorting Attacks', 'MPC Searching Attacks', 'MPC Indexing Attacks', 'MPC Caching Attacks', 'MPC Backup Attacks', 'MPC Recovery Attacks', 'MPC Archival Attacks', 'MPC Retention Attacks', 'MPC Deletion Attacks', 'MPC Anonymization Attacks', 'MPC Pseudonymization Attacks', 'MPC Masking Attacks', 'MPC Redaction Attacks', 'MPC Obfuscation Attacks', 'MPC Tokenization Attacks', 'MPC Encryption Attacks', 'MPC Hashing Attacks', 'MPC Signing Attacks', 'MPC Verification Attacks', 'MPC Validation Attacks', 'MPC Sanitization Attacks', 'MPC Normalization Attacks', 'MPC Standardization Attacks', 'MPC Format Attacks', 'MPC Type Attacks', 'MPC Structure Attacks', 'MPC Schema Attacks', 'MPC Model Attacks', 'MPC Relationship Attacks', 'MPC Dependency Attacks', 'MPC Constraint Attacks', 'MPC Rule Attacks', 'MPC Policy Attacks', 'MPC Governance Attacks', 'MPC Compliance Attacks', 'MPC Audit Attacks', 'MPC Monitoring Attacks', 'MPC Logging Attacks', 'MPC Reporting Attacks', 'MPC Analytics Attacks', 'MPC Mining Attacks', 'MPC Machine Learning Attacks', 'MPC AI Attacks', 'MPC Algorithm Attacks', 'MPC Model Attacks', 'MPC Training Attacks', 'MPC Testing Attacks', 'MPC Validation Attacks', 'MPC Cross-Validation Attacks', 'MPC Overfitting Attacks', 'MPC Underfitting Attacks', 'MPC Bias Attacks', 'MPC Fairness Attacks', 'MPC Discrimination Attacks', etc.)."]
) -> str:
    """
    Generate an LLM prompt to review MPC protocol logic and assumptions.

    Parameters:
        function_explanation (str): Protocol goals and adversary model.
        function_body (str): Exact code.
        file_path (str): Repo-relative path.
        mpc_context (str): Protocol (BGW/SPDZ/ABY/GMW/SSS), t-of-n, network/sync model.
        list_of_mpc_threats (list[str]): Collusion, malicious parties, covert channels, fairness/robustness,
            aborts, leakage via transcripts, share/authentication correctness.

    Output:
        str: Prompt asking for precise findings and fixes.
    """
    msg = f"""
MPC PROTOCOL THREAT ANALYSIS REQUEST

Function Context:
- MPC Purpose: {function_explanation}
- File Location: {file_path}
- MPC Context: {mpc_context}
- MPC Threats to Evaluate: {', '.join(list_of_mpc_threats)}

MPC Source Code to Analyze:
{function_body}

Please perform a comprehensive MPC security analysis focusing on the specified threats and provide detailed findings with MPC-specific attack vector analysis, potential MPC impact, and remediation guidance specific to MPC vulnerabilities and secure MPC protocol practices.
"""

    return msg


async def mpc_threshold_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the MPC threshold function does, its purpose in threshold cryptography, and its role in the threshold scheme. Should include threshold operations, secret reconstruction, and any threshold-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the MPC threshold function including all statements, variable assignments, control flow, function calls, threshold operations, and any nested logic. This is the actual MPC threshold code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'crypto/threshold_scheme.py', 'src/security/ThresholdCrypto.js', 'app/crypto/ThresholdScheme.rs'). Used for context and reporting."], 
    threshold_context: Annotated[str, "Additional threshold context including the threshold scheme type (e.g., Shamir's, Blakley's, Asmuth-Bloom), threshold parameters (n,t), and critical threshold operations this function handles."],
    list_of_threshold_threats: Annotated[list[str], "A comprehensive list of MPC threshold-specific threats and vulnerabilities to check for during analysis. Each item should be a specific threshold threat type (e.g., 'Threshold Scheme Vulnerabilities', 'Secret Reconstruction Attacks', 'Threshold Parameter Attacks', 'Threshold Validation Attacks', 'Threshold Verification Attacks', 'Threshold Authentication Attacks', 'Threshold Authorization Attacks', 'Threshold Access Control Attacks', 'Threshold Key Management Attacks', 'Threshold Key Generation Attacks', 'Threshold Key Distribution Attacks', 'Threshold Key Rotation Attacks', 'Threshold Key Recovery Attacks', 'Threshold Key Backup Attacks', 'Threshold Key Archive Attacks', 'Threshold Key Destruction Attacks', 'Threshold Key Escrow Attacks', 'Threshold Key Compromise Attacks', 'Threshold Key Storage Attacks', 'Threshold Key Encryption Attacks', 'Threshold Key Hashing Attacks', 'Threshold Key Compression Attacks', 'Threshold Key Decompression Attacks', 'Threshold Key Transformation Attacks', 'Threshold Key Aggregation Attacks', 'Threshold Key Filtering Attacks', 'Threshold Key Sorting Attacks', 'Threshold Key Searching Attacks', 'Threshold Key Indexing Attacks', 'Threshold Key Caching Attacks', 'Threshold Key Backup Attacks', 'Threshold Key Recovery Attacks', 'Threshold Key Archival Attacks', 'Threshold Key Retention Attacks', 'Threshold Key Deletion Attacks', 'Threshold Key Anonymization Attacks', 'Threshold Key Pseudonymization Attacks', 'Threshold Key Masking Attacks', 'Threshold Key Redaction Attacks', 'Threshold Key Obfuscation Attacks', 'Threshold Key Tokenization Attacks', 'Threshold Key Encryption Attacks', 'Threshold Key Hashing Attacks', 'Threshold Key Signing Attacks', 'Threshold Key Verification Attacks', 'Threshold Key Validation Attacks', 'Threshold Key Sanitization Attacks', 'Threshold Key Normalization Attacks', 'Threshold Key Standardization Attacks', 'Threshold Key Format Attacks', 'Threshold Key Type Attacks', 'Threshold Key Structure Attacks', 'Threshold Key Schema Attacks', 'Threshold Key Model Attacks', 'Threshold Key Relationship Attacks', 'Threshold Key Dependency Attacks', 'Threshold Key Constraint Attacks', 'Threshold Key Rule Attacks', 'Threshold Key Policy Attacks', 'Threshold Key Governance Attacks', 'Threshold Key Compliance Attacks', 'Threshold Key Audit Attacks', 'Threshold Key Monitoring Attacks', 'Threshold Key Logging Attacks', 'Threshold Key Reporting Attacks', 'Threshold Key Analytics Attacks', 'Threshold Key Mining Attacks', 'Threshold Key Machine Learning Attacks', 'Threshold Key AI Attacks', 'Threshold Key Algorithm Attacks', 'Threshold Key Model Attacks', 'Threshold Key Training Attacks', 'Threshold Key Testing Attacks', 'Threshold Key Validation Attacks', 'Threshold Key Cross-Validation Attacks', 'Threshold Key Overfitting Attacks', 'Threshold Key Underfitting Attacks', 'Threshold Key Bias Attacks', 'Threshold Key Fairness Attacks', 'Threshold Key Discrimination Attacks', etc.)."]
) -> str:
    """
    Create a prompt to evaluate threshold parameters and reconstruction safety.

    Parameters:
        function_explanation (str): Enforcement and validation strategy.
        function_body (str): Exact code.
        file_path (str): Repo-relative path.
        threshold_context (str): Scheme details, parameter ranges, storage of metadata, auditing.
        list_of_threshold_threats (list[str]): Downgrade, off-by-one, invalid share acceptance,
            interpolation correctness, stale configs, privilege escalation via thresholds.

    Output:
        str: Prompt requesting precise issues and mitigation steps.
    """
    msg = f"""
MPC THRESHOLD THREAT ANALYSIS REQUEST

Function Context:
- Threshold Purpose: {function_explanation}
- File Location: {file_path}
- Threshold Context: {threshold_context}
- Threshold Threats to Evaluate: {', '.join(list_of_threshold_threats)}

MPC Threshold Source Code to Analyze:
{function_body}

Please perform a comprehensive MPC threshold security analysis focusing on the specified threats and provide detailed findings with threshold-specific attack vector analysis, potential threshold impact, and remediation guidance specific to MPC threshold vulnerabilities and secure threshold scheme practices.
"""

    return msg


async def mpc_party_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the MPC party function does, its purpose in multi-party computation, and its role in the MPC protocol. Should include party operations, communication protocols, and any party-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the MPC party function including all statements, variable assignments, control flow, function calls, party operations, and any nested logic. This is the actual MPC party code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'crypto/mpc_party.py', 'src/security/MPCParty.js', 'app/crypto/MPCParty.rs'). Used for context and reporting."], 
    party_context: Annotated[str, "Additional party context including the party role (e.g., dealer, participant, verifier), party behavior model (e.g., honest, semi-honest, malicious), and critical party operations this function handles."],
    list_of_party_threats: Annotated[list[str], "A comprehensive list of MPC party-specific threats and vulnerabilities to check for during analysis. Each item should be a specific party threat type (e.g., 'Malicious Party Attacks', 'Semi-Honest Party Attacks', 'Honest-But-Curious Attacks', 'Party Collusion Attacks', 'Party Communication Attacks', 'Party Synchronization Attacks', 'Party Coordination Attacks', 'Party Agreement Attacks', 'Party Consensus Attacks', 'Party Finality Attacks', 'Party Slashing Attacks', 'Party Reward Attacks', 'Party Fee Attacks', 'Party Liquidity Attacks', 'Party Oracle Attacks', 'Party Governance Attacks', 'Party Upgrade Attacks', 'Party Emergency Attacks', 'Party Economic Attacks', 'Party Performance Attacks', 'Party Reliability Attacks', 'Party Availability Attacks', 'Party Consistency Attacks', 'Party Accuracy Attacks', 'Party Completeness Attacks', 'Party Timeliness Attacks', 'Party Relevance Attacks', 'Party Quality Attacks', 'Party Security Attacks', 'Party Access Attacks', 'Party Authorization Attacks', 'Party Authentication Attacks', 'Party Encryption Attacks', 'Party Hashing Attacks', 'Party Compression Attacks', 'Party Decompression Attacks', 'Party Transformation Attacks', 'Party Aggregation Attacks', 'Party Filtering Attacks', 'Party Sorting Attacks', 'Party Searching Attacks', 'Party Indexing Attacks', 'Party Caching Attacks', 'Party Backup Attacks', 'Party Recovery Attacks', 'Party Archival Attacks', 'Party Retention Attacks', 'Party Deletion Attacks', 'Party Anonymization Attacks', 'Party Pseudonymization Attacks', 'Party Masking Attacks', 'Party Redaction Attacks', 'Party Obfuscation Attacks', 'Party Tokenization Attacks', 'Party Encryption Attacks', 'Party Hashing Attacks', 'Party Signing Attacks', 'Party Verification Attacks', 'Party Validation Attacks', 'Party Sanitization Attacks', 'Party Normalization Attacks', 'Party Standardization Attacks', 'Party Format Attacks', 'Party Type Attacks', 'Party Structure Attacks', 'Party Schema Attacks', 'Party Model Attacks', 'Party Relationship Attacks', 'Party Dependency Attacks', 'Party Constraint Attacks', 'Party Rule Attacks', 'Party Policy Attacks', 'Party Governance Attacks', 'Party Compliance Attacks', 'Party Audit Attacks', 'Party Monitoring Attacks', 'Party Logging Attacks', 'Party Reporting Attacks', 'Party Analytics Attacks', 'Party Mining Attacks', 'Party Machine Learning Attacks', 'Party AI Attacks', 'Party Algorithm Attacks', 'Party Model Attacks', 'Party Training Attacks', 'Party Testing Attacks', 'Party Validation Attacks', 'Party Cross-Validation Attacks', 'Party Overfitting Attacks', 'Party Underfitting Attacks', 'Party Bias Attacks', 'Party Fairness Attacks', 'Party Discrimination Attacks', etc.)."]
) -> str:
    """
    Build a prompt to examine party behavior, communication, and collusion risks.

    Parameters:
        function_explanation (str): Party role and guarantees.
        function_body (str): Exact code.
        file_path (str): Repo-relative path.
        party_context (str): Role (dealer/participant/verifier), channels, honesty model.
        list_of_party_threats (list[str]): Collusion, message tampering/replay, fairness/robustness,
            leakage via timing/traffic analysis, logging/audit gaps.

    Output:
        str: Prompt requesting concrete issues with actionable remediations.
    """
    msg = f"""
MPC PARTY THREAT ANALYSIS REQUEST

Function Context:
- Party Purpose: {function_explanation}
- File Location: {file_path}
- Party Context: {party_context}
- Party Threats to Evaluate: {', '.join(list_of_party_threats)}

MPC Party Source Code to Analyze:
{function_body}

Please perform a comprehensive MPC party security analysis focusing on the specified threats and provide detailed findings with party-specific attack vector analysis, potential party impact, and remediation guidance specific to MPC party vulnerabilities and secure party behavior practices.
"""

    return msg
