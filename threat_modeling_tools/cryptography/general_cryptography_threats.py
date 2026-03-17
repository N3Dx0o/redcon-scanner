from typing import Annotated


async def general_cryptography_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the cryptographic function does, its purpose in encryption, decryption, key management, digital signatures, or cryptographic protocols. Should include cryptographic operations, key handling, and any security-critical cryptographic logic."],
    function_body: Annotated[str, "The complete source code of the cryptographic function including all statements, variable assignments, control flow, function calls, crypto operations, and any nested logic. This is the actual cryptographic code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'crypto/encryption.py', 'src/security/KeyManager.js', 'app/auth/CryptoUtils.rs'). Used for context and reporting."], 
    crypto_context: Annotated[str, "Additional cryptographic context including the cryptographic algorithms used (e.g., AES, RSA, ECDSA, SHA-256), key management approach, cryptographic libraries, and security requirements this function must meet."],
    list_of_crypto_threats: Annotated[list[str], "A comprehensive list of general cryptographic threats and vulnerabilities to check for during analysis. Each item should be a specific crypto threat type (e.g., 'Weak Cryptographic Algorithm', 'Insecure Key Generation', 'Key Management Flaws', 'Cryptographic Implementation Bugs', 'Side-Channel Attacks', 'Timing Attacks', 'Power Analysis Attacks', 'Cache Attacks', 'Padding Oracle Attacks', 'Cryptographic Protocol Flaws', 'Random Number Generation Issues', 'Hash Collision Attacks', 'Certificate Validation Bypass', 'Cryptographic Library Vulnerabilities', 'Key Storage Issues', 'Cryptographic Protocol Downgrade', 'Man-in-the-Middle Attacks', 'Replay Attacks', 'Birthday Attacks', 'Length Extension Attacks', 'Chosen Plaintext Attacks', 'Known Plaintext Attacks', 'Ciphertext Only Attacks', 'Frequency Analysis', 'Brute Force Attacks', 'Dictionary Attacks', 'Rainbow Table Attacks', 'Cryptographic Constant-Time Violations', 'Memory Disclosure in Crypto Operations', 'Cryptographic Nonce Issues', 'Salt Generation Problems', 'Password Hashing Vulnerabilities', 'Cryptographic Key Recovery', 'Cryptographic Signature Forgery', 'Cryptographic Authentication Bypass', 'Cryptographic Authorization Issues', 'Cryptographic Session Management', 'Cryptographic Input Validation', 'Cryptographic Output Encoding', 'Cryptographic Error Handling', 'Cryptographic Logging Issues', 'Cryptographic Configuration Issues', 'Cryptographic Dependency Issues', 'Cryptographic Supply Chain Issues', 'Cryptographic Import Issues', 'Cryptographic Module Issues', 'Cryptographic Package Issues', 'Cryptographic Virtual Environment Issues', 'Cryptographic Environment Issues', 'Cryptographic Secret Management', 'Cryptographic Random Number Issues', 'Cryptographic Hash Issues', 'Cryptographic Buffer Issues', 'Cryptographic Integer Issues', 'Cryptographic Format String Issues', 'Cryptographic Eval Issues', 'Cryptographic Exec Issues', 'Cryptographic Compile Issues', 'Cryptographic Open Issues', 'Cryptographic Input Issues', 'Cryptographic Output Issues', 'Cryptographic Network Issues', 'Cryptographic File Issues', 'Cryptographic Process Issues', 'Cryptographic System Issues', etc.)."]
) -> str:
    """
    Create a general cryptography review prompt for LLMs.

    Parameters:
        function_explanation (str): Purpose, algorithms, and invariants.
        function_body (str): Exact code to review.
        file_path (str): Repo-relative path.
        crypto_context (str): Algorithms/libraries, key handling, randomness sources, protocol roles.
        list_of_crypto_threats (list[str]): Specific checks spanning RNG, KDFs, AEAD, MACs, certs, etc.

    Output:
        str: Prompt requesting concrete findings, severity, and remediations with references.
    """
    msg = f"""
GENERAL CRYPTOGRAPHY THREAT ANALYSIS REQUEST

Function Context:
- Cryptographic Purpose: {function_explanation}
- File Location: {file_path}
- Cryptographic Context: {crypto_context}
- General Crypto Threats to Evaluate: {', '.join(list_of_crypto_threats)}

Cryptographic Source Code to Analyze:
{function_body}

Please perform a comprehensive general cryptographic security analysis focusing on the specified threats and provide detailed findings with severity ratings and remediation guidance specific to general cryptographic security best practices.
"""

    return msg


async def random_number_generation_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the random number generation function does, its purpose in cryptographic operations, and its role in generating secure random values. Should include random number operations, entropy sources, and any RNG-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the RNG function including all statements, variable assignments, control flow, function calls, random operations, and any nested logic. This is the actual RNG code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'crypto/rng.py', 'src/security/RandomGenerator.js', 'app/crypto/EntropySource.rs'). Used for context and reporting."], 
    rng_context: Annotated[str, "Additional RNG context including the random number generator type (e.g., CSPRNG, PRNG, TRNG), entropy sources used, and critical RNG operations this function handles."],
    list_of_rng_threats: Annotated[list[str], "A comprehensive list of RNG-specific threats and vulnerabilities to check for during analysis. Each item should be a specific RNG threat type (e.g., 'Weak Random Number Generation', 'Predictable Random Numbers', 'Insufficient Entropy', 'Entropy Source Weakness', 'RNG State Prediction', 'RNG Seed Weakness', 'RNG Initialization Issues', 'RNG Reseeding Issues', 'RNG State Recovery', 'RNG State Manipulation', 'RNG Timing Attacks', 'RNG Side-Channel Attacks', 'RNG Power Analysis Attacks', 'RNG Cache Attacks', 'RNG Memory Attacks', 'RNG Network Attacks', 'RNG Storage Attacks', 'RNG Computation Attacks', 'RNG Verification Attacks', 'RNG Communication Attacks', 'RNG Synchronization Attacks', 'RNG Coordination Attacks', 'RNG Agreement Attacks', 'RNG Consensus Attacks', 'RNG Finality Attacks', 'RNG Slashing Attacks', 'RNG Reward Attacks', 'RNG Fee Attacks', 'RNG Liquidity Attacks', 'RNG Oracle Attacks', 'RNG Governance Attacks', 'RNG Upgrade Attacks', 'RNG Emergency Attacks', 'RNG Economic Attacks', 'RNG Performance Attacks', 'RNG Reliability Attacks', 'RNG Availability Attacks', 'RNG Consistency Attacks', 'RNG Accuracy Attacks', 'RNG Completeness Attacks', 'RNG Timeliness Attacks', 'RNG Relevance Attacks', 'RNG Quality Attacks', 'RNG Security Attacks', 'RNG Access Attacks', 'RNG Authorization Attacks', 'RNG Authentication Attacks', 'RNG Encryption Attacks', 'RNG Hashing Attacks', 'RNG Compression Attacks', 'RNG Decompression Attacks', 'RNG Transformation Attacks', 'RNG Aggregation Attacks', 'RNG Filtering Attacks', 'RNG Sorting Attacks', 'RNG Searching Attacks', 'RNG Indexing Attacks', 'RNG Caching Attacks', 'RNG Backup Attacks', 'RNG Recovery Attacks', 'RNG Archival Attacks', 'RNG Retention Attacks', 'RNG Deletion Attacks', 'RNG Anonymization Attacks', 'RNG Pseudonymization Attacks', 'RNG Masking Attacks', 'RNG Redaction Attacks', 'RNG Obfuscation Attacks', 'RNG Tokenization Attacks', 'RNG Encryption Attacks', 'RNG Hashing Attacks', 'RNG Signing Attacks', 'RNG Verification Attacks', 'RNG Validation Attacks', 'RNG Sanitization Attacks', 'RNG Normalization Attacks', 'RNG Standardization Attacks', 'RNG Format Attacks', 'RNG Type Attacks', 'RNG Structure Attacks', 'RNG Schema Attacks', 'RNG Model Attacks', 'RNG Relationship Attacks', 'RNG Dependency Attacks', 'RNG Constraint Attacks', 'RNG Rule Attacks', 'RNG Policy Attacks', 'RNG Governance Attacks', 'RNG Compliance Attacks', 'RNG Audit Attacks', 'RNG Monitoring Attacks', 'RNG Logging Attacks', 'RNG Reporting Attacks', 'RNG Analytics Attacks', 'RNG Mining Attacks', 'RNG Machine Learning Attacks', 'RNG AI Attacks', 'RNG Algorithm Attacks', 'RNG Model Attacks', 'RNG Training Attacks', 'RNG Testing Attacks', 'RNG Validation Attacks', 'RNG Cross-Validation Attacks', 'RNG Overfitting Attacks', 'RNG Underfitting Attacks', 'RNG Bias Attacks', 'RNG Fairness Attacks', 'RNG Discrimination Attacks', etc.)."]
) -> str:
    """
    Analyze a random number generation function for RNG-specific vulnerabilities and threats.
    
    This function focuses specifically on RNG vulnerabilities, entropy source issues,
    and RNG-specific attack vectors that could lead to predictable random numbers,
    cryptographic compromise, or exploitation of RNG functionality.
    
    Args:
        function_explanation: Human-readable description of the RNG function's purpose and behavior
        function_body: Complete source code of the RNG function to be analyzed
        file_path: Full path to the file containing the RNG function for context
        rng_context: Additional RNG context and entropy source information
        list_of_rng_threats: List of specific RNG threats to evaluate
        
    Returns:
        str: Detailed RNG analysis report including identified vulnerabilities,
             RNG-specific attack vector analysis, potential RNG impact, and remediation
             recommendations specific to RNG security.
             
    Example:
        result = await random_number_generation_threats(
            function_explanation="Generate cryptographically secure random numbers for key generation",
            function_body="def generate_random_bytes(length): return os.urandom(length)",
            file_path="crypto/rng.py",
            rng_context="Cryptographically secure random number generator using OS entropy source",
            list_of_rng_threats=["Weak Random Number Generation", "Predictable Random Numbers", "Insufficient Entropy", "RNG State Prediction"]
        )
        
    Note:
        This function should be used for analyzing RNG functions, entropy sources,
        and RNG-specific code where vulnerabilities could lead to RNG compromise
        or RNG functionality exploitation. Focus on RNG security best practices.
    """
    msg = f"""
RNG THREAT ANALYSIS REQUEST

Function Context:
- RNG Purpose: {function_explanation}
- File Location: {file_path}
- RNG Context: {rng_context}
- RNG Threats to Evaluate: {', '.join(list_of_rng_threats)}

RNG Source Code to Analyze:
{function_body}

Please perform a comprehensive RNG security analysis focusing on the specified threats and provide detailed findings with RNG-specific attack vector analysis, potential RNG impact, and remediation guidance specific to RNG vulnerabilities and secure random number generation practices.
"""

    return msg


async def key_management_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the key management function does, its purpose in cryptographic key operations, and its role in key lifecycle management. Should include key generation, storage, distribution, rotation, and any key management-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the key management function including all statements, variable assignments, control flow, function calls, key operations, and any nested logic. This is the actual key management code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'crypto/key_manager.py', 'src/security/KeyStore.js', 'app/crypto/KeyRotation.rs'). Used for context and reporting."], 
    key_context: Annotated[str, "Additional key management context including the key management system type (e.g., HSM, KMS, local storage), key types managed, and critical key operations this function handles."],
    list_of_key_threats: Annotated[list[str], "A comprehensive list of key management-specific threats and vulnerabilities to check for during analysis. Each item should be a specific key management threat type (e.g., 'Key Generation Weakness', 'Key Storage Vulnerabilities', 'Key Distribution Issues', 'Key Rotation Problems', 'Key Recovery Attacks', 'Key Compromise', 'Key Escrow Issues', 'Key Backup Vulnerabilities', 'Key Archive Problems', 'Key Destruction Issues', 'Key Access Control Flaws', 'Key Authorization Issues', 'Key Authentication Problems', 'Key Encryption Issues', 'Key Hashing Problems', 'Key Compression Issues', 'Key Decompression Problems', 'Key Transformation Vulnerabilities', 'Key Aggregation Issues', 'Key Filtering Problems', 'Key Sorting Vulnerabilities', 'Key Searching Issues', 'Key Indexing Problems', 'Key Caching Vulnerabilities', 'Key Backup Issues', 'Key Recovery Problems', 'Key Archival Vulnerabilities', 'Key Retention Issues', 'Key Deletion Problems', 'Key Anonymization Vulnerabilities', 'Key Pseudonymization Issues', 'Key Masking Problems', 'Key Redaction Vulnerabilities', 'Key Obfuscation Issues', 'Key Tokenization Problems', 'Key Encryption Vulnerabilities', 'Key Hashing Issues', 'Key Signing Problems', 'Key Verification Vulnerabilities', 'Key Validation Issues', 'Key Sanitization Problems', 'Key Normalization Vulnerabilities', 'Key Standardization Issues', 'Key Format Problems', 'Key Type Vulnerabilities', 'Key Structure Issues', 'Key Schema Problems', 'Key Model Vulnerabilities', 'Key Relationship Issues', 'Key Dependency Problems', 'Key Constraint Vulnerabilities', 'Key Rule Issues', 'Key Policy Problems', 'Key Governance Vulnerabilities', 'Key Compliance Issues', 'Key Audit Problems', 'Key Monitoring Vulnerabilities', 'Key Logging Issues', 'Key Reporting Problems', 'Key Analytics Vulnerabilities', 'Key Mining Issues', 'Key Machine Learning Problems', 'Key AI Vulnerabilities', 'Key Algorithm Issues', 'Key Model Problems', 'Key Training Vulnerabilities', 'Key Testing Issues', 'Key Validation Problems', 'Key Cross-Validation Vulnerabilities', 'Key Overfitting Issues', 'Key Underfitting Problems', 'Key Bias Vulnerabilities', 'Key Fairness Issues', 'Key Discrimination Problems', etc.)."]
) -> str:
    """
    Analyze a key management function for key management-specific vulnerabilities and threats.
    
    This function focuses specifically on key management vulnerabilities, key lifecycle issues,
    and key management-specific attack vectors that could lead to key compromise,
    unauthorized access, or exploitation of key management functionality.
    
    Args:
        function_explanation: Human-readable description of the key management function's purpose and behavior
        function_body: Complete source code of the key management function to be analyzed
        file_path: Full path to the file containing the key management function for context
        key_context: Additional key management context and key management system information
        list_of_key_threats: List of specific key management threats to evaluate
        
    Returns:
        str: Detailed key management analysis report including identified vulnerabilities,
             key management-specific attack vector analysis, potential key management impact, and remediation
             recommendations specific to key management security.
             
    Example:
        result = await key_management_threats(
            function_explanation="Generate and store cryptographic keys with secure key derivation",
            function_body="def generate_key(): return Fernet.generate_key()",
            file_path="crypto/key_manager.py",
            key_context="Symmetric key management system with secure key storage and rotation",
            list_of_key_threats=["Key Generation Weakness", "Key Storage Vulnerabilities", "Key Distribution Issues", "Key Rotation Problems"]
        )
        
    Note:
        This function should be used for analyzing key management functions, key lifecycle operations,
        and key management-specific code where vulnerabilities could lead to key compromise
        or key management exploitation. Focus on key management security best practices.
    """
    msg = f"""
KEY MANAGEMENT THREAT ANALYSIS REQUEST

Function Context:
- Key Management Purpose: {function_explanation}
- File Location: {file_path}
- Key Management Context: {key_context}
- Key Management Threats to Evaluate: {', '.join(list_of_key_threats)}

Key Management Source Code to Analyze:
{function_body}

Please perform a comprehensive key management security analysis focusing on the specified threats and provide detailed findings with key management-specific attack vector analysis, potential key management impact, and remediation guidance specific to key management vulnerabilities and secure key management practices.
"""

    return msg
