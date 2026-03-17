from typing import Annotated


async def rsa_implementation_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the RSA function does, its purpose in public-key cryptography, and its role in the cryptographic system. Should include RSA operations, key generation, encryption/decryption, and any RSA-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the RSA function including all statements, variable assignments, control flow, function calls, RSA operations, and any nested logic. This is the actual RSA code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'crypto/rsa_encrypt.py', 'src/security/RSAUtils.js', 'app/crypto/RSACipher.rs'). Used for context and reporting."], 
    rsa_context: Annotated[str, "Additional RSA context including the RSA key size (e.g., 1024, 2048, 3072, 4096 bits), padding scheme (e.g., PKCS#1 v1.5, OAEP, PSS), and critical RSA operations this function handles."],
    list_of_rsa_threats: Annotated[list[str], "A comprehensive list of RSA-specific threats and vulnerabilities to check for during analysis. Each item should be a specific RSA threat type (e.g., 'RSA Implementation Bugs', 'RSA Key Generation Issues', 'RSA Key Size Vulnerabilities', 'RSA Padding Oracle Attacks', 'RSA Timing Attacks', 'RSA Side-Channel Attacks', 'RSA Power Analysis Attacks', 'RSA Cache Attacks', 'RSA Memory Attacks', 'RSA Network Attacks', 'RSA Storage Attacks', 'RSA Computation Attacks', 'RSA Verification Attacks', 'RSA Communication Attacks', 'RSA Synchronization Attacks', 'RSA Coordination Attacks', 'RSA Agreement Attacks', 'RSA Consensus Attacks', 'RSA Finality Attacks', 'RSA Slashing Attacks', 'RSA Reward Attacks', 'RSA Fee Attacks', 'RSA Liquidity Attacks', 'RSA Oracle Attacks', 'RSA Governance Attacks', 'RSA Upgrade Attacks', 'RSA Emergency Attacks', 'RSA Economic Attacks', 'RSA Performance Attacks', 'RSA Reliability Attacks', 'RSA Availability Attacks', 'RSA Consistency Attacks', 'RSA Accuracy Attacks', 'RSA Completeness Attacks', 'RSA Timeliness Attacks', 'RSA Relevance Attacks', 'RSA Quality Attacks', 'RSA Security Attacks', 'RSA Access Attacks', 'RSA Authorization Attacks', 'RSA Authentication Attacks', 'RSA Encryption Attacks', 'RSA Hashing Attacks', 'RSA Compression Attacks', 'RSA Decompression Attacks', 'RSA Transformation Attacks', 'RSA Aggregation Attacks', 'RSA Filtering Attacks', 'RSA Sorting Attacks', 'RSA Searching Attacks', 'RSA Indexing Attacks', 'RSA Caching Attacks', 'RSA Backup Attacks', 'RSA Recovery Attacks', 'RSA Archival Attacks', 'RSA Retention Attacks', 'RSA Deletion Attacks', 'RSA Anonymization Attacks', 'RSA Pseudonymization Attacks', 'RSA Masking Attacks', 'RSA Redaction Attacks', 'RSA Obfuscation Attacks', 'RSA Tokenization Attacks', 'RSA Encryption Attacks', 'RSA Hashing Attacks', 'RSA Signing Attacks', 'RSA Verification Attacks', 'RSA Validation Attacks', 'RSA Sanitization Attacks', 'RSA Normalization Attacks', 'RSA Standardization Attacks', 'RSA Format Attacks', 'RSA Type Attacks', 'RSA Structure Attacks', 'RSA Schema Attacks', 'RSA Model Attacks', 'RSA Relationship Attacks', 'RSA Dependency Attacks', 'RSA Constraint Attacks', 'RSA Rule Attacks', 'RSA Policy Attacks', 'RSA Governance Attacks', 'RSA Compliance Attacks', 'RSA Audit Attacks', 'RSA Monitoring Attacks', 'RSA Logging Attacks', 'RSA Reporting Attacks', 'RSA Analytics Attacks', 'RSA Mining Attacks', 'RSA Machine Learning Attacks', 'RSA AI Attacks', 'RSA Algorithm Attacks', 'RSA Model Attacks', 'RSA Training Attacks', 'RSA Testing Attacks', 'RSA Validation Attacks', 'RSA Cross-Validation Attacks', 'RSA Overfitting Attacks', 'RSA Underfitting Attacks', 'RSA Bias Attacks', 'RSA Fairness Attacks', 'RSA Discrimination Attacks', etc.)."]
) -> str:
    """
    Create an LLM prompt to review RSA code (encrypt/decrypt/sign/verify) for risks.

    Parameters:
        function_explanation (str): Purpose, padding scheme, and security invariants.
        function_body (str): Exact RSA-related source code.
        file_path (str): Repo-relative path.
        rsa_context (str): Key sizes, padding (OAEP/PSS/PKCS#1 v1.5), blinding, CRT usage.
        list_of_rsa_threats (list[str]): Padding oracles, timing/side-channel, CRT faults, weak RNG,
            small exponent pitfalls, key import/export safety.

    Output:
        str: Prompt instructing LLM to provide findings with references and actionable fixes.
    """
    msg = f"""
RSA IMPLEMENTATION THREAT ANALYSIS REQUEST

Function Context:
- RSA Purpose: {function_explanation}
- File Location: {file_path}
- RSA Context: {rsa_context}
- RSA Threats to Evaluate: {', '.join(list_of_rsa_threats)}

RSA Source Code to Analyze:
{function_body}

Please perform a comprehensive RSA security analysis focusing on the specified threats and provide detailed findings with RSA-specific attack vector analysis, potential RSA impact, and remediation guidance specific to RSA vulnerabilities and secure RSA implementation practices.
"""

    return msg


async def rsa_key_management_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the RSA key management function does, its purpose in RSA key operations, and its role in RSA key lifecycle management. Should include RSA key generation, storage, distribution, rotation, and any RSA key management-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the RSA key management function including all statements, variable assignments, control flow, function calls, RSA key operations, and any nested logic. This is the actual RSA key management code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'crypto/rsa_key_manager.py', 'src/security/RSAKeyStore.js', 'app/crypto/RSAKeyRotation.rs'). Used for context and reporting."], 
    rsa_key_context: Annotated[str, "Additional RSA key management context including the RSA key management system type (e.g., HSM, KMS, local storage), RSA key types managed, key sizes, and critical RSA key operations this function handles."],
    list_of_rsa_key_threats: Annotated[list[str], "A comprehensive list of RSA key management-specific threats and vulnerabilities to check for during analysis. Each item should be a specific RSA key management threat type (e.g., 'RSA Key Generation Weakness', 'RSA Key Storage Vulnerabilities', 'RSA Key Distribution Issues', 'RSA Key Rotation Problems', 'RSA Key Recovery Attacks', 'RSA Key Compromise', 'RSA Key Escrow Issues', 'RSA Key Backup Vulnerabilities', 'RSA Key Archive Problems', 'RSA Key Destruction Issues', 'RSA Key Access Control Flaws', 'RSA Key Authorization Issues', 'RSA Key Authentication Problems', 'RSA Key Encryption Issues', 'RSA Key Hashing Problems', 'RSA Key Compression Issues', 'RSA Key Decompression Problems', 'RSA Key Transformation Vulnerabilities', 'RSA Key Aggregation Issues', 'RSA Key Filtering Problems', 'RSA Key Sorting Vulnerabilities', 'RSA Key Searching Issues', 'RSA Key Indexing Problems', 'RSA Key Caching Vulnerabilities', 'RSA Key Backup Issues', 'RSA Key Recovery Problems', 'RSA Key Archival Vulnerabilities', 'RSA Key Retention Issues', 'RSA Key Deletion Problems', 'RSA Key Anonymization Vulnerabilities', 'RSA Key Pseudonymization Issues', 'RSA Key Masking Problems', 'RSA Key Redaction Vulnerabilities', 'RSA Key Obfuscation Issues', 'RSA Key Tokenization Problems', 'RSA Key Encryption Vulnerabilities', 'RSA Key Hashing Issues', 'RSA Key Signing Problems', 'RSA Key Verification Vulnerabilities', 'RSA Key Validation Issues', 'RSA Key Sanitization Problems', 'RSA Key Normalization Vulnerabilities', 'RSA Key Standardization Issues', 'RSA Key Format Problems', 'RSA Key Type Vulnerabilities', 'RSA Key Structure Issues', 'RSA Key Schema Problems', 'RSA Key Model Vulnerabilities', 'RSA Key Relationship Issues', 'RSA Key Dependency Problems', 'RSA Key Constraint Vulnerabilities', 'RSA Key Rule Issues', 'RSA Key Policy Problems', 'RSA Key Governance Vulnerabilities', 'RSA Key Compliance Issues', 'RSA Key Audit Problems', 'RSA Key Monitoring Vulnerabilities', 'RSA Key Logging Issues', 'RSA Key Reporting Problems', 'RSA Key Analytics Vulnerabilities', 'RSA Key Mining Issues', 'RSA Key Machine Learning Problems', 'RSA Key AI Vulnerabilities', 'RSA Key Algorithm Issues', 'RSA Key Model Problems', 'RSA Key Training Vulnerabilities', 'RSA Key Testing Issues', 'RSA Key Validation Problems', 'RSA Key Cross-Validation Vulnerabilities', 'RSA Key Overfitting Issues', 'RSA Key Underfitting Problems', 'RSA Key Bias Vulnerabilities', 'RSA Key Fairness Issues', 'RSA Key Discrimination Problems', etc.)."]
) -> str:
    """
    Build a prompt to assess RSA key lifecycle with CRT/blinding considerations.

    Parameters:
        function_explanation (str): Intent and required guarantees.
        function_body (str): Exact implementation.
        file_path (str): Repo-relative path.
        rsa_key_context (str): Generation source, storage (HSM/KMS), export rules, rotation, zeroization.
        list_of_rsa_key_threats (list[str]): Weak RNG, predictable seeds, unsafe PEM handling, CRT param leaks,
            missing blinding, ACL/logging gaps, migration/export exposure.

    Output:
        str: Prompt asking LLM for concrete findings and fixes.
    """
    msg = f"""
RSA KEY MANAGEMENT THREAT ANALYSIS REQUEST

Function Context:
- RSA Key Management Purpose: {function_explanation}
- File Location: {file_path}
- RSA Key Management Context: {rsa_key_context}
- RSA Key Management Threats to Evaluate: {', '.join(list_of_rsa_key_threats)}

RSA Key Management Source Code to Analyze:
{function_body}

Please perform a comprehensive RSA key management security analysis focusing on the specified threats and provide detailed findings with RSA key management-specific attack vector analysis, potential RSA key management impact, and remediation guidance specific to RSA key management vulnerabilities and secure RSA key management practices.
"""

    return msg


async def rsa_padding_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the RSA padding function does, its purpose in RSA padding operations, and its role in RSA security. Should include padding operations, padding scheme, and any RSA padding-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the RSA padding function including all statements, variable assignments, control flow, function calls, padding operations, and any nested logic. This is the actual RSA padding code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'crypto/rsa_padding.py', 'src/security/RSAPadding.js', 'app/crypto/RSAPadding.rs'). Used for context and reporting."], 
    rsa_padding_context: Annotated[str, "Additional RSA padding context including the padding scheme (e.g., PKCS#1 v1.5, OAEP, PSS), padding parameters, and critical RSA padding operations this function handles."],
    list_of_rsa_padding_threats: Annotated[list[str], "A comprehensive list of RSA padding-specific threats and vulnerabilities to check for during analysis. Each item should be a specific RSA padding threat type (e.g., 'RSA Padding Oracle Attacks', 'RSA Padding Validation Issues', 'RSA Padding Scheme Vulnerabilities', 'RSA Padding Implementation Bugs', 'RSA Padding Timing Attacks', 'RSA Padding Side-Channel Attacks', 'RSA Padding Power Analysis Attacks', 'RSA Padding Cache Attacks', 'RSA Padding Memory Attacks', 'RSA Padding Network Attacks', 'RSA Padding Storage Attacks', 'RSA Padding Computation Attacks', 'RSA Padding Verification Attacks', 'RSA Padding Communication Attacks', 'RSA Padding Synchronization Attacks', 'RSA Padding Coordination Attacks', 'RSA Padding Agreement Attacks', 'RSA Padding Consensus Attacks', 'RSA Padding Finality Attacks', 'RSA Padding Slashing Attacks', 'RSA Padding Reward Attacks', 'RSA Padding Fee Attacks', 'RSA Padding Liquidity Attacks', 'RSA Padding Oracle Attacks', 'RSA Padding Governance Attacks', 'RSA Padding Upgrade Attacks', 'RSA Padding Emergency Attacks', 'RSA Padding Economic Attacks', 'RSA Padding Performance Attacks', 'RSA Padding Reliability Attacks', 'RSA Padding Availability Attacks', 'RSA Padding Consistency Attacks', 'RSA Padding Accuracy Attacks', 'RSA Padding Completeness Attacks', 'RSA Padding Timeliness Attacks', 'RSA Padding Relevance Attacks', 'RSA Padding Quality Attacks', 'RSA Padding Security Attacks', 'RSA Padding Access Attacks', 'RSA Padding Authorization Attacks', 'RSA Padding Authentication Attacks', 'RSA Padding Encryption Attacks', 'RSA Padding Hashing Attacks', 'RSA Padding Compression Attacks', 'RSA Padding Decompression Attacks', 'RSA Padding Transformation Attacks', 'RSA Padding Aggregation Attacks', 'RSA Padding Filtering Attacks', 'RSA Padding Sorting Attacks', 'RSA Padding Searching Attacks', 'RSA Padding Indexing Attacks', 'RSA Padding Caching Attacks', 'RSA Padding Backup Attacks', 'RSA Padding Recovery Attacks', 'RSA Padding Archival Attacks', 'RSA Padding Retention Attacks', 'RSA Padding Deletion Attacks', 'RSA Padding Anonymization Attacks', 'RSA Padding Pseudonymization Attacks', 'RSA Padding Masking Attacks', 'RSA Padding Redaction Attacks', 'RSA Padding Obfuscation Attacks', 'RSA Padding Tokenization Attacks', 'RSA Padding Encryption Attacks', 'RSA Padding Hashing Attacks', 'RSA Padding Signing Attacks', 'RSA Padding Verification Attacks', 'RSA Padding Validation Attacks', 'RSA Padding Sanitization Attacks', 'RSA Padding Normalization Attacks', 'RSA Padding Standardization Attacks', 'RSA Padding Format Attacks', 'RSA Padding Type Attacks', 'RSA Padding Structure Attacks', 'RSA Padding Schema Attacks', 'RSA Padding Model Attacks', 'RSA Padding Relationship Attacks', 'RSA Padding Dependency Attacks', 'RSA Padding Constraint Attacks', 'RSA Padding Rule Attacks', 'RSA Padding Policy Attacks', 'RSA Padding Governance Attacks', 'RSA Padding Compliance Attacks', 'RSA Padding Audit Attacks', 'RSA Padding Monitoring Attacks', 'RSA Padding Logging Attacks', 'RSA Padding Reporting Attacks', 'RSA Padding Analytics Attacks', 'RSA Padding Mining Attacks', 'RSA Padding Machine Learning Attacks', 'RSA Padding AI Attacks', 'RSA Padding Algorithm Attacks', 'RSA Padding Model Attacks', 'RSA Padding Training Attacks', 'RSA Padding Testing Attacks', 'RSA Padding Validation Attacks', 'RSA Padding Cross-Validation Attacks', 'RSA Padding Overfitting Attacks', 'RSA Padding Underfitting Attacks', 'RSA Padding Bias Attacks', 'RSA Padding Fairness Attacks', 'RSA Padding Discrimination Attacks', etc.)."]
) -> str:
    """
    Compose a prompt to review RSA padding logic and oracle resistance.

    Parameters:
        function_explanation (str): Padding scheme and error handling guarantees.
        function_body (str): Exact code.
        file_path (str): Repo-relative path.
        rsa_padding_context (str): OAEP/PSS parameters, MGF/hash, label usage, constant-time behavior.
        list_of_rsa_padding_threats (list[str]): Oracle exposure, ambiguous errors, timing leaks,
            non-standard encodings, misuse of PSS salt length, insecure PKCS#1 v1.5 use.

    Output:
        str: Prompt for LLM to surface issues with specific remediations.
    """
    msg = f"""
RSA PADDING THREAT ANALYSIS REQUEST

Function Context:
- RSA Padding Purpose: {function_explanation}
- File Location: {file_path}
- RSA Padding Context: {rsa_padding_context}
- RSA Padding Threats to Evaluate: {', '.join(list_of_rsa_padding_threats)}

RSA Padding Source Code to Analyze:
{function_body}

Please perform a comprehensive RSA padding security analysis focusing on the specified threats and provide detailed findings with RSA padding-specific attack vector analysis, potential RSA padding impact, and remediation guidance specific to RSA padding vulnerabilities and secure RSA padding practices.
"""

    return msg
