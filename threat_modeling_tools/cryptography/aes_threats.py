from typing import Annotated


async def aes_implementation_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the AES function does, its purpose in encryption/decryption, and its role in the cryptographic system. Should include AES operations, mode of operation, key handling, and any AES-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the AES function including all statements, variable assignments, control flow, function calls, AES operations, and any nested logic. This is the actual AES code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'crypto/aes_encrypt.py', 'src/security/AESUtils.js', 'app/crypto/AESCipher.rs'). Used for context and reporting."], 
    aes_context: Annotated[str, "Additional AES context including the AES variant (e.g., AES-128, AES-192, AES-256), mode of operation (e.g., CBC, GCM, CTR, ECB), padding scheme, and critical AES operations this function handles."],
    list_of_aes_threats: Annotated[list[str], "A comprehensive list of AES-specific threats and vulnerabilities to check for during analysis. Each item should be a specific AES threat type (e.g., 'AES Implementation Bugs', 'AES Mode Vulnerabilities', 'AES Padding Oracle Attacks', 'AES Timing Attacks', 'AES Side-Channel Attacks', 'AES Power Analysis Attacks', 'AES Cache Attacks', 'AES Memory Attacks', 'AES Key Schedule Vulnerabilities', 'AES S-Box Vulnerabilities', 'AES MixColumns Vulnerabilities', 'AES AddRoundKey Vulnerabilities', 'AES SubBytes Vulnerabilities', 'AES ShiftRows Vulnerabilities', 'AES Key Expansion Issues', 'AES Key Scheduling Problems', 'AES Round Key Issues', 'AES Initialization Vector Issues', 'AES Nonce Issues', 'AES Counter Issues', 'AES Authentication Issues', 'AES Integrity Issues', 'AES Confidentiality Issues', 'AES Availability Issues', 'AES Performance Issues', 'AES Reliability Issues', 'AES Scalability Issues', 'AES Maintainability Issues', 'AES Usability Issues', 'AES Portability Issues', 'AES Compatibility Issues', 'AES Interoperability Issues', 'AES Standardization Issues', 'AES Compliance Issues', 'AES Certification Issues', 'AES Validation Issues', 'AES Testing Issues', 'AES Debugging Issues', 'AES Monitoring Issues', 'AES Logging Issues', 'AES Auditing Issues', 'AES Reporting Issues', 'AES Analytics Issues', 'AES Mining Issues', 'AES Machine Learning Issues', 'AES AI Issues', 'AES Algorithm Issues', 'AES Model Issues', 'AES Training Issues', 'AES Validation Issues', 'AES Cross-Validation Issues', 'AES Overfitting Issues', 'AES Underfitting Issues', 'AES Bias Issues', 'AES Fairness Issues', 'AES Discrimination Issues', etc.)."]
) -> str:
    """
    Generate an LLM-ready prompt to review AES code against explicit threats.

    Parameters:
        function_explanation (str): Purpose, mode of operation, and security invariants.
        function_body (str): Exact AES-related source code.
        file_path (str): Repo-relative path.
        aes_context (str): Variant (AES-128/192/256), mode (CBC/GCM/CTR/CCM/ECB), IV/nonce/padding rules.
        list_of_aes_threats (list[str]): Concrete checks (IV/nonce reuse, padding oracles, timing/side-channels,
            improper key/IV generation, insecure mode, AAD/tag handling, key schedule misuse).

    Output:
        str: Prompt instructing the LLM to provide issues with references and actionable remediations.

    LLM guidance:
        - Validate IV/nonce uniqueness per key, tag verification ordering, and AEAD misuse.
        - Check constant-time operations for key/branching; avoid ECB and unsafe padding.
        - Review KDF/PRNG usage for keys/nonces and secure wipe of key material.
    """
    msg = f"""
AES IMPLEMENTATION THREAT ANALYSIS REQUEST

Function Context:
- AES Purpose: {function_explanation}
- File Location: {file_path}
- AES Context: {aes_context}
- AES Threats to Evaluate: {', '.join(list_of_aes_threats)}

AES Source Code to Analyze:
{function_body}

Please perform a comprehensive AES security analysis focusing on the specified threats and provide detailed findings with AES-specific attack vector analysis, potential AES impact, and remediation guidance specific to AES vulnerabilities and secure AES implementation practices.
"""

    return msg


async def aes_key_management_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the AES key management function does, its purpose in AES key operations, and its role in AES key lifecycle management. Should include AES key generation, storage, distribution, rotation, and any AES key management-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the AES key management function including all statements, variable assignments, control flow, function calls, AES key operations, and any nested logic. This is the actual AES key management code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'crypto/aes_key_manager.py', 'src/security/AESKeyStore.js', 'app/crypto/AESKeyRotation.rs'). Used for context and reporting."], 
    aes_key_context: Annotated[str, "Additional AES key management context including the AES key management system type (e.g., HSM, KMS, local storage), AES key types managed, and critical AES key operations this function handles."],
    list_of_aes_key_threats: Annotated[list[str], "A comprehensive list of AES key management-specific threats and vulnerabilities to check for during analysis. Each item should be a specific AES key management threat type (e.g., 'AES Key Generation Weakness', 'AES Key Storage Vulnerabilities', 'AES Key Distribution Issues', 'AES Key Rotation Problems', 'AES Key Recovery Attacks', 'AES Key Compromise', 'AES Key Escrow Issues', 'AES Key Backup Vulnerabilities', 'AES Key Archive Problems', 'AES Key Destruction Issues', 'AES Key Access Control Flaws', 'AES Key Authorization Issues', 'AES Key Authentication Problems', 'AES Key Encryption Issues', 'AES Key Hashing Problems', 'AES Key Compression Issues', 'AES Key Decompression Problems', 'AES Key Transformation Vulnerabilities', 'AES Key Aggregation Issues', 'AES Key Filtering Problems', 'AES Key Sorting Vulnerabilities', 'AES Key Searching Issues', 'AES Key Indexing Problems', 'AES Key Caching Vulnerabilities', 'AES Key Backup Issues', 'AES Key Recovery Problems', 'AES Key Archival Vulnerabilities', 'AES Key Retention Issues', 'AES Key Deletion Problems', 'AES Key Anonymization Vulnerabilities', 'AES Key Pseudonymization Issues', 'AES Key Masking Problems', 'AES Key Redaction Vulnerabilities', 'AES Key Obfuscation Issues', 'AES Key Tokenization Problems', 'AES Key Encryption Vulnerabilities', 'AES Key Hashing Issues', 'AES Key Signing Problems', 'AES Key Verification Vulnerabilities', 'AES Key Validation Issues', 'AES Key Sanitization Problems', 'AES Key Normalization Vulnerabilities', 'AES Key Standardization Issues', 'AES Key Format Problems', 'AES Key Type Vulnerabilities', 'AES Key Structure Issues', 'AES Key Schema Problems', 'AES Key Model Vulnerabilities', 'AES Key Relationship Issues', 'AES Key Dependency Problems', 'AES Key Constraint Vulnerabilities', 'AES Key Rule Issues', 'AES Key Policy Problems', 'AES Key Governance Vulnerabilities', 'AES Key Compliance Issues', 'AES Key Audit Problems', 'AES Key Monitoring Vulnerabilities', 'AES Key Logging Issues', 'AES Key Reporting Problems', 'AES Key Analytics Vulnerabilities', 'AES Key Mining Issues', 'AES Key Machine Learning Problems', 'AES Key AI Vulnerabilities', 'AES Key Algorithm Issues', 'AES Key Model Problems', 'AES Key Training Vulnerabilities', 'AES Key Testing Issues', 'AES Key Validation Problems', 'AES Key Cross-Validation Vulnerabilities', 'AES Key Overfitting Issues', 'AES Key Underfitting Problems', 'AES Key Bias Vulnerabilities', 'AES Key Fairness Issues', 'AES Key Discrimination Problems', etc.)."]
) -> str:
    """
    Build a prompt to assess AES key lifecycle (gen/store/rotate/destroy).

    Parameters:
        function_explanation (str): Lifecycle intent and guarantees.
        function_body (str): Exact implementation code.
        file_path (str): Repo-relative path.
        aes_key_context (str): HSM/KMS use, KDFs, wrapping, rotation cadence, zeroization.
        list_of_aes_key_threats (list[str]): Weak RNG/KDF, storage leakage, export paths, ACLs,
            wrap/unwrap misuse, rotation gaps, audit/logging issues.

    Output:
        str: Prompt requesting concrete findings and fixes with references.
    """
    msg = f"""
AES KEY MANAGEMENT THREAT ANALYSIS REQUEST

Function Context:
- AES Key Management Purpose: {function_explanation}
- File Location: {file_path}
- AES Key Management Context: {aes_key_context}
- AES Key Management Threats to Evaluate: {', '.join(list_of_aes_key_threats)}

AES Key Management Source Code to Analyze:
{function_body}

Please perform a comprehensive AES key management security analysis focusing on the specified threats and provide detailed findings with AES key management-specific attack vector analysis, potential AES key management impact, and remediation guidance specific to AES key management vulnerabilities and secure AES key management practices.
"""

    return msg


async def aes_padding_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the AES padding function does, its purpose in AES block cipher operations, and its role in handling data padding for AES encryption/decryption. Should include padding operations, padding scheme, and any AES padding-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the AES padding function including all statements, variable assignments, control flow, function calls, padding operations, and any nested logic. This is the actual AES padding code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'crypto/aes_padding.py', 'src/security/AESPadding.js', 'app/crypto/AESPadding.rs'). Used for context and reporting."], 
    aes_padding_context: Annotated[str, "Additional AES padding context including the padding scheme (e.g., PKCS#7, PKCS#5, ISO 10126, ANSI X9.23, Zero Padding), AES mode of operation, and critical AES padding operations this function handles."],
    list_of_aes_padding_threats: Annotated[list[str], "A comprehensive list of AES padding-specific threats and vulnerabilities to check for during analysis. Each item should be a specific AES padding threat type (e.g., 'AES Padding Oracle Attacks', 'AES Padding Validation Issues', 'AES Padding Scheme Vulnerabilities', 'AES Padding Implementation Bugs', 'AES Padding Timing Attacks', 'AES Padding Side-Channel Attacks', 'AES Padding Power Analysis Attacks', 'AES Padding Cache Attacks', 'AES Padding Memory Attacks', 'AES Padding Network Attacks', 'AES Padding Storage Attacks', 'AES Padding Computation Attacks', 'AES Padding Verification Attacks', 'AES Padding Communication Attacks', 'AES Padding Synchronization Attacks', 'AES Padding Coordination Attacks', 'AES Padding Agreement Attacks', 'AES Padding Consensus Attacks', 'AES Padding Finality Attacks', 'AES Padding Slashing Attacks', 'AES Padding Reward Attacks', 'AES Padding Fee Attacks', 'AES Padding Liquidity Attacks', 'AES Padding Oracle Attacks', 'AES Padding Governance Attacks', 'AES Padding Upgrade Attacks', 'AES Padding Emergency Attacks', 'AES Padding Economic Attacks', 'AES Padding Performance Attacks', 'AES Padding Reliability Attacks', 'AES Padding Availability Attacks', 'AES Padding Consistency Attacks', 'AES Padding Accuracy Attacks', 'AES Padding Completeness Attacks', 'AES Padding Timeliness Attacks', 'AES Padding Relevance Attacks', 'AES Padding Quality Attacks', 'AES Padding Security Attacks', 'AES Padding Access Attacks', 'AES Padding Authorization Attacks', 'AES Padding Authentication Attacks', 'AES Padding Encryption Attacks', 'AES Padding Hashing Attacks', 'AES Padding Compression Attacks', 'AES Padding Decompression Attacks', 'AES Padding Transformation Attacks', 'AES Padding Aggregation Attacks', 'AES Padding Filtering Attacks', 'AES Padding Sorting Attacks', 'AES Padding Searching Attacks', 'AES Padding Indexing Attacks', 'AES Padding Caching Attacks', 'AES Padding Backup Attacks', 'AES Padding Recovery Attacks', 'AES Padding Archival Attacks', 'AES Padding Retention Attacks', 'AES Padding Deletion Attacks', 'AES Padding Anonymization Attacks', 'AES Padding Pseudonymization Attacks', 'AES Padding Masking Attacks', 'AES Padding Redaction Attacks', 'AES Padding Obfuscation Attacks', 'AES Padding Tokenization Attacks', 'AES Padding Encryption Attacks', 'AES Padding Hashing Attacks', 'AES Padding Signing Attacks', 'AES Padding Verification Attacks', 'AES Padding Validation Attacks', 'AES Padding Sanitization Attacks', 'AES Padding Normalization Attacks', 'AES Padding Standardization Attacks', 'AES Padding Format Attacks', 'AES Padding Type Attacks', 'AES Padding Structure Attacks', 'AES Padding Schema Attacks', 'AES Padding Model Attacks', 'AES Padding Relationship Attacks', 'AES Padding Dependency Attacks', 'AES Padding Constraint Attacks', 'AES Padding Rule Attacks', 'AES Padding Policy Attacks', 'AES Padding Governance Attacks', 'AES Padding Compliance Attacks', 'AES Padding Audit Attacks', 'AES Padding Monitoring Attacks', 'AES Padding Logging Attacks', 'AES Padding Reporting Attacks', 'AES Padding Analytics Attacks', 'AES Padding Mining Attacks', 'AES Padding Machine Learning Attacks', 'AES Padding AI Attacks', 'AES Padding Algorithm Attacks', 'AES Padding Model Attacks', 'AES Padding Training Attacks', 'AES Padding Testing Attacks', 'AES Padding Validation Attacks', 'AES Padding Cross-Validation Attacks', 'AES Padding Overfitting Attacks', 'AES Padding Underfitting Attacks', 'AES Padding Bias Attacks', 'AES Padding Fairness Attacks', 'AES Padding Discrimination Attacks', etc.)."]
) -> str:
    """
    Compose a prompt to review padding logic and oracle exposure in AES flows.

    Parameters:
        function_explanation (str): Padding scheme intent and verification rules.
        function_body (str): Exact padding-related code.
        file_path (str): Repo-relative path.
        aes_padding_context (str): Mode (CBC/...), validator behavior, error handling.
        list_of_aes_padding_threats (list[str]): Oracle exposure, error side-channels, timing leaks,
            ambiguous decoding, mixed encodings, incorrect block sizing.

    Output:
        str: Prompt for LLM to report oracle paths and concrete mitigations.
    """
    msg = f"""
AES PADDING THREAT ANALYSIS REQUEST

Function Context:
- AES Padding Purpose: {function_explanation}
- File Location: {file_path}
- AES Padding Context: {aes_padding_context}
- AES Padding Threats to Evaluate: {', '.join(list_of_aes_padding_threats)}

AES Padding Source Code to Analyze:
{function_body}

Please perform a comprehensive AES padding security analysis focusing on the specified threats and provide detailed findings with AES padding-specific attack vector analysis, potential AES padding impact, and remediation guidance specific to AES padding vulnerabilities and secure AES padding practices.
"""

    return msg
