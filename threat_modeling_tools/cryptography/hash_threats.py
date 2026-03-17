from typing import Annotated


async def hash_function_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the hash function does, its purpose in cryptographic hashing, and its role in the cryptographic system. Should include hash operations, hash algorithm, and any hash-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the hash function including all statements, variable assignments, control flow, function calls, hash operations, and any nested logic. This is the actual hash code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'crypto/hash_utils.py', 'src/security/HashUtils.js', 'app/crypto/HashFunction.rs'). Used for context and reporting."], 
    hash_context: Annotated[str, "Additional hash context including the hash algorithm used (e.g., SHA-256, SHA-3, BLAKE2, MD5, SHA-1), hash purpose (e.g., password hashing, data integrity, digital signatures), and critical hash operations this function handles."],
    list_of_hash_threats: Annotated[list[str], "A comprehensive list of hash-specific threats and vulnerabilities to check for during analysis. Each item should be a specific hash threat type (e.g., 'Hash Collision Attacks', 'Preimage Attacks', 'Second Preimage Attacks', 'Length Extension Attacks', 'Birthday Attacks', 'Hash Function Vulnerabilities', 'Weak Hash Algorithms', 'Hash Implementation Bugs', 'Hash Timing Attacks', 'Hash Side-Channel Attacks', 'Hash Power Analysis Attacks', 'Hash Cache Attacks', 'Hash Memory Attacks', 'Hash Network Attacks', 'Hash Storage Attacks', 'Hash Computation Attacks', 'Hash Verification Attacks', 'Hash Communication Attacks', 'Hash Synchronization Attacks', 'Hash Coordination Attacks', 'Hash Agreement Attacks', 'Hash Consensus Attacks', 'Hash Finality Attacks', 'Hash Slashing Attacks', 'Hash Reward Attacks', 'Hash Fee Attacks', 'Hash Liquidity Attacks', 'Hash Oracle Attacks', 'Hash Governance Attacks', 'Hash Upgrade Attacks', 'Hash Emergency Attacks', 'Hash Economic Attacks', 'Hash Performance Attacks', 'Hash Reliability Attacks', 'Hash Availability Attacks', 'Hash Consistency Attacks', 'Hash Accuracy Attacks', 'Hash Completeness Attacks', 'Hash Timeliness Attacks', 'Hash Relevance Attacks', 'Hash Quality Attacks', 'Hash Security Attacks', 'Hash Access Attacks', 'Hash Authorization Attacks', 'Hash Authentication Attacks', 'Hash Encryption Attacks', 'Hash Hashing Attacks', 'Hash Compression Attacks', 'Hash Decompression Attacks', 'Hash Transformation Attacks', 'Hash Aggregation Attacks', 'Hash Filtering Attacks', 'Hash Sorting Attacks', 'Hash Searching Attacks', 'Hash Indexing Attacks', 'Hash Caching Attacks', 'Hash Backup Attacks', 'Hash Recovery Attacks', 'Hash Archival Attacks', 'Hash Retention Attacks', 'Hash Deletion Attacks', 'Hash Anonymization Attacks', 'Hash Pseudonymization Attacks', 'Hash Masking Attacks', 'Hash Redaction Attacks', 'Hash Obfuscation Attacks', 'Hash Tokenization Attacks', 'Hash Encryption Attacks', 'Hash Hashing Attacks', 'Hash Signing Attacks', 'Hash Verification Attacks', 'Hash Validation Attacks', 'Hash Sanitization Attacks', 'Hash Normalization Attacks', 'Hash Standardization Attacks', 'Hash Format Attacks', 'Hash Type Attacks', 'Hash Structure Attacks', 'Hash Schema Attacks', 'Hash Model Attacks', 'Hash Relationship Attacks', 'Hash Dependency Attacks', 'Hash Constraint Attacks', 'Hash Rule Attacks', 'Hash Policy Attacks', 'Hash Governance Attacks', 'Hash Compliance Attacks', 'Hash Audit Attacks', 'Hash Monitoring Attacks', 'Hash Logging Attacks', 'Hash Reporting Attacks', 'Hash Analytics Attacks', 'Hash Mining Attacks', 'Hash Machine Learning Attacks', 'Hash AI Attacks', 'Hash Algorithm Attacks', 'Hash Model Attacks', 'Hash Training Attacks', 'Hash Testing Attacks', 'Hash Validation Attacks', 'Hash Cross-Validation Attacks', 'Hash Overfitting Attacks', 'Hash Underfitting Attacks', 'Hash Bias Attacks', 'Hash Fairness Attacks', 'Hash Discrimination Attacks', etc.)."]
) -> str:
    """
    Build an LLM prompt to review hashing usage and implementation safety.

    Parameters:
        function_explanation (str): Purpose of hashing and invariants.
        function_body (str): Exact hashing code.
        file_path (str): Repo-relative path.
        hash_context (str): Algorithm choice (SHA-2/3/BLAKE2), truncation, domain separation, HMAC.
        list_of_hash_threats (list[str]): Length extension, collisions/preimage, misuse for passwords,
            encoding pitfalls, non-constant-time compares, random salts/nonces handling.

    Output:
        str: Prompt instructing LLM to produce concrete findings and fixes with references.
    """
    msg = f"""
HASH FUNCTION THREAT ANALYSIS REQUEST

Function Context:
- Hash Purpose: {function_explanation}
- File Location: {file_path}
- Hash Context: {hash_context}
- Hash Threats to Evaluate: {', '.join(list_of_hash_threats)}

Hash Source Code to Analyze:
{function_body}

Please perform a comprehensive hash security analysis focusing on the specified threats and provide detailed findings with hash-specific attack vector analysis, potential hash impact, and remediation guidance specific to hash vulnerabilities and secure hash implementation practices.
"""

    return msg


async def password_hashing_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the password hashing function does, its purpose in password security, and its role in authentication systems. Should include password hashing operations, salt generation, and any password-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the password hashing function including all statements, variable assignments, control flow, function calls, password operations, and any nested logic. This is the actual password hashing code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'crypto/password_hash.py', 'src/security/PasswordUtils.js', 'app/crypto/PasswordHash.rs'). Used for context and reporting."], 
    password_context: Annotated[str, "Additional password hashing context including the hashing algorithm (e.g., bcrypt, scrypt, Argon2, PBKDF2), salt generation method, work factor, and critical password operations this function handles."],
    list_of_password_threats: Annotated[list[str], "A comprehensive list of password hashing-specific threats and vulnerabilities to check for during analysis. Each item should be a specific password hashing threat type (e.g., 'Weak Password Hashing', 'Insufficient Salt', 'Salt Reuse', 'Salt Predictability', 'Insufficient Work Factor', 'Password Hash Timing Attacks', 'Password Hash Side-Channel Attacks', 'Password Hash Power Analysis Attacks', 'Password Hash Cache Attacks', 'Password Hash Memory Attacks', 'Password Hash Rainbow Table Attacks', 'Password Hash Dictionary Attacks', 'Password Hash Brute Force Attacks', 'Password Hash Precomputed Hash Attacks', 'Password Hash Lookup Table Attacks', 'Password Hash Reverse Lookup Attacks', 'Password Hash Collision Attacks', 'Password Hash Preimage Attacks', 'Password Hash Second Preimage Attacks', 'Password Hash Length Extension Attacks', 'Password Hash Birthday Attacks', 'Password Hash Function Vulnerabilities', 'Password Hash Implementation Bugs', 'Password Hash Algorithm Weaknesses', 'Password Hash Parameter Issues', 'Password Hash Configuration Issues', 'Password Hash Storage Issues', 'Password Hash Transmission Issues', 'Password Hash Validation Issues', 'Password Hash Verification Issues', 'Password Hash Authentication Issues', 'Password Hash Authorization Issues', 'Password Hash Access Control Issues', 'Password Hash Session Management Issues', 'Password Hash Input Validation Issues', 'Password Hash Output Encoding Issues', 'Password Hash Error Handling Issues', 'Password Hash Logging Issues', 'Password Hash Monitoring Issues', 'Password Hash Auditing Issues', 'Password Hash Reporting Issues', 'Password Hash Analytics Issues', 'Password Hash Mining Issues', 'Password Hash Machine Learning Issues', 'Password Hash AI Issues', 'Password Hash Algorithm Issues', 'Password Hash Model Issues', 'Password Hash Training Issues', 'Password Hash Testing Issues', 'Password Hash Validation Issues', 'Password Hash Cross-Validation Issues', 'Password Hash Overfitting Issues', 'Password Hash Underfitting Issues', 'Password Hash Bias Issues', 'Password Hash Fairness Issues', 'Password Hash Discrimination Issues', etc.)."]
) -> str:
    """
    Generate a prompt to assess password hashing choices and configurations.

    Parameters:
        function_explanation (str): Intended password storage guarantees.
        function_body (str): Exact code.
        file_path (str): Repo-relative path.
        password_context (str): Algorithm (Argon2/bcrypt/scrypt/PBKDF2), params, salt handling, pepper.
        list_of_password_threats (list[str]): Weak params, salt reuse/predictability, timing leaks,
            missing memory-hardness, encoding/migration pitfalls, compare timing safety.

    Output:
        str: Prompt asking the LLM for specific findings and parameter recommendations.
    """
    msg = f"""
PASSWORD HASHING THREAT ANALYSIS REQUEST

Function Context:
- Password Hashing Purpose: {function_explanation}
- File Location: {file_path}
- Password Context: {password_context}
- Password Hashing Threats to Evaluate: {', '.join(list_of_password_threats)}

Password Hashing Source Code to Analyze:
{function_body}

Please perform a comprehensive password hashing security analysis focusing on the specified threats and provide detailed findings with password-specific attack vector analysis, potential password impact, and remediation guidance specific to password hashing vulnerabilities and secure password hashing practices.
"""

    return msg


async def hash_collision_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the hash collision function does, its purpose in hash collision detection/prevention, and its role in hash security. Should include collision detection operations, collision prevention measures, and any collision-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the hash collision function including all statements, variable assignments, control flow, function calls, collision operations, and any nested logic. This is the actual hash collision code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'crypto/collision_detection.py', 'src/security/HashCollision.js', 'app/crypto/CollisionDetector.rs'). Used for context and reporting."], 
    collision_context: Annotated[str, "Additional hash collision context including the collision detection method, hash algorithm used, collision prevention strategies, and critical collision operations this function handles."],
    list_of_collision_threats: Annotated[list[str], "A comprehensive list of hash collision-specific threats and vulnerabilities to check for during analysis. Each item should be a specific collision threat type (e.g., 'Hash Collision Attacks', 'Collision Detection Bypass', 'Collision Prevention Bypass', 'Collision Exploitation', 'Collision Injection', 'Collision Manipulation', 'Collision Forgery', 'Collision Replay', 'Collision Reuse', 'Collision Amplification', 'Collision Chaining', 'Collision Cascading', 'Collision Propagation', 'Collision Escalation', 'Collision Privilege Escalation', 'Collision Access Control Bypass', 'Collision Authentication Bypass', 'Collision Authorization Bypass', 'Collision Session Hijacking', 'Collision Session Fixation', 'Collision Session Management Issues', 'Collision Input Validation Bypass', 'Collision Output Encoding Bypass', 'Collision Error Handling Bypass', 'Collision Logging Bypass', 'Collision Monitoring Bypass', 'Collision Auditing Bypass', 'Collision Reporting Bypass', 'Collision Analytics Bypass', 'Collision Mining Bypass', 'Collision Machine Learning Bypass', 'Collision AI Bypass', 'Collision Algorithm Bypass', 'Collision Model Bypass', 'Collision Training Bypass', 'Collision Testing Bypass', 'Collision Validation Bypass', 'Collision Cross-Validation Bypass', 'Collision Overfitting Bypass', 'Collision Underfitting Bypass', 'Collision Bias Bypass', 'Collision Fairness Bypass', 'Collision Discrimination Bypass', etc.)."]
) -> str:
    """
    Compose a prompt to examine collision handling and misuse prevention.

    Parameters:
        function_explanation (str): Collision risk model and safeguards.
        function_body (str): Exact code.
        file_path (str): Repo-relative path.
        collision_context (str): Algorithm, domain separation, salt/nonce usage, MAC/HMAC.
        list_of_collision_threats (list[str]): Collision exploitation, length-extension contexts,
            reliance on non-strong hashes, ambiguous comparisons, truncation misuse.

    Output:
        str: Prompt requesting concrete issues and mitigations.
    """
    msg = f"""
HASH COLLISION THREAT ANALYSIS REQUEST

Function Context:
- Collision Purpose: {function_explanation}
- File Location: {file_path}
- Collision Context: {collision_context}
- Collision Threats to Evaluate: {', '.join(list_of_collision_threats)}

Hash Collision Source Code to Analyze:
{function_body}

Please perform a comprehensive hash collision security analysis focusing on the specified threats and provide detailed findings with collision-specific attack vector analysis, potential collision impact, and remediation guidance specific to hash collision vulnerabilities and secure collision detection practices.
"""

    return msg
