from typing import Annotated


async def rust_general_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Rust function does, its purpose, and its role in the application. Should include Rust-specific operations, ownership patterns, borrowing, lifetimes, and any Rust-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the Rust function including all statements, variable assignments, control flow, function calls, Rust operations, and any nested logic. This is the actual Rust code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'src/main.rs', 'lib/crypto_utils.rs', 'app/network_handler.rs'). Used for context and reporting."], 
    rust_context: Annotated[str, "Additional Rust context including the Rust edition (e.g., 2018, 2021), unsafe usage, unsafe blocks, unsafe functions, unsafe traits, unsafe impls, and critical Rust operations this function handles."],
    list_of_rust_threats: Annotated[list[str], "A comprehensive list of Rust-specific threats and vulnerabilities to check for during analysis. Each item should be a specific Rust threat type (e.g., 'Rust Unsafe Code Vulnerabilities', 'Rust Memory Safety Violations', 'Rust Ownership Violations', 'Rust Borrowing Violations', 'Rust Lifetime Violations', 'Rust Type Safety Violations', 'Rust Panic Vulnerabilities', 'Rust Unwrap Vulnerabilities', 'Rust Expect Vulnerabilities', 'Rust Unreachable Vulnerabilities', 'Rust Integer Overflow Vulnerabilities', 'Rust Buffer Overflow Vulnerabilities', 'Rust Use-After-Free Vulnerabilities', 'Rust Double-Free Vulnerabilities', 'Rust Memory Leak Vulnerabilities', 'Rust Race Condition Vulnerabilities', 'Rust Data Race Vulnerabilities', 'Rust Deadlock Vulnerabilities', 'Rust Livelock Vulnerabilities', 'Rust Stack Overflow Vulnerabilities', 'Rust Heap Overflow Vulnerabilities', 'Rust Format String Vulnerabilities', 'Rust Injection Vulnerabilities', 'Rust Deserialization Vulnerabilities', 'Rust Serialization Vulnerabilities', 'Rust FFI Vulnerabilities', 'Rust Unsafe Block Vulnerabilities', 'Rust Unsafe Function Vulnerabilities', 'Rust Unsafe Trait Vulnerabilities', 'Rust Unsafe Impl Vulnerabilities', 'Rust Raw Pointer Vulnerabilities', 'Rust Mutable Static Vulnerabilities', 'Rust Interior Mutability Vulnerabilities', 'Rust Unsafe Cell Vulnerabilities', 'Rust RefCell Vulnerabilities', 'Rust Mutex Vulnerabilities', 'Rust RwLock Vulnerabilities', 'Rust Arc Vulnerabilities', 'Rust Rc Vulnerabilities', 'Rust Send Vulnerabilities', 'Rust Sync Vulnerabilities', 'Rust Drop Vulnerabilities', 'Rust Clone Vulnerabilities', 'Rust Copy Vulnerabilities', etc.)."]
) -> str:
    """
    Create an LLM-ready prompt for general Rust code review focusing on Rust-specific security concerns.

    Parameters:
        function_explanation (str): Purpose, ownership patterns, borrowing, lifetimes, and expected behavior.
        function_body (str): Exact code under review.
        file_path (str): Repo-relative path.
        rust_context (str): Rust edition, unsafe usage, concurrency patterns, error handling.
        list_of_rust_threats (list[str]): Memory safety, ownership violations, unsafe code misuse,
            panic handling, integer overflows, race conditions, FFI safety.

    Output:
        str: Prompt instructing the LLM to provide findings with references and fixes.

    LLM guidance:
        - Validate ownership and borrowing patterns for correctness.
        - Check unsafe code blocks for proper safety invariants.
        - Review panic handling and error propagation.
        - Verify integer arithmetic for overflow/underflow.
        - Check for data races in concurrent code.
        - Validate FFI boundaries and foreign function safety.
    """
    msg = f"""
RUST GENERAL THREAT ANALYSIS REQUEST

Function Context:
- Rust Purpose: {function_explanation}
- File Location: {file_path}
- Rust Context: {rust_context}
- Rust Threats to Evaluate: {', '.join(list_of_rust_threats)}

Rust Source Code to Analyze:
{function_body}

Please perform a comprehensive Rust security analysis focusing on the specified threats and provide detailed findings with Rust-specific attack vector analysis, potential Rust impact, and remediation guidance specific to Rust vulnerabilities and secure Rust development practices.

Key areas to analyze:
- Memory safety and ownership violations
- Unsafe code usage and safety invariants
- Panic handling and error propagation
- Integer overflow and arithmetic safety
- Concurrency and data race conditions
- FFI safety and foreign function boundaries
- Lifetime and borrowing correctness
"""

    return msg


async def rust_kms_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Rust KMS (Key Management System) function does, its purpose in key management, and its role in the cryptographic system. Should include KMS operations, key generation, key storage, key rotation, and any KMS-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the Rust KMS function including all statements, variable assignments, control flow, function calls, KMS operations, and any nested logic. This is the actual Rust KMS code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'src/kms/key_manager.rs', 'lib/crypto/kms_handler.rs', 'app/security/key_storage.rs'). Used for context and reporting."], 
    kms_context: Annotated[str, "Additional Rust KMS context including the KMS type (e.g., AWS KMS, HashiCorp Vault, custom KMS), key types supported, encryption at rest, and critical KMS operations this function handles."],
    list_of_kms_threats: Annotated[list[str], "A comprehensive list of Rust KMS-specific threats and vulnerabilities to check for during analysis. Each item should be a specific KMS threat type (e.g., 'KMS Key Generation Vulnerabilities', 'KMS Key Storage Vulnerabilities', 'KMS Key Rotation Vulnerabilities', 'KMS Key Access Control Vulnerabilities', 'KMS Key Encryption Vulnerabilities', 'KMS Key Decryption Vulnerabilities', 'KMS Key Backup Vulnerabilities', 'KMS Key Recovery Vulnerabilities', 'KMS Key Deletion Vulnerabilities', 'KMS Key Import Vulnerabilities', 'KMS Key Export Vulnerabilities', 'KMS Key Versioning Vulnerabilities', 'KMS Key Metadata Vulnerabilities', 'KMS Key Policy Vulnerabilities', 'KMS Key Audit Vulnerabilities', 'KMS Key Logging Vulnerabilities', 'KMS Key Monitoring Vulnerabilities', 'KMS Key Authorization Vulnerabilities', 'KMS Key Authentication Vulnerabilities', 'KMS Key Session Vulnerabilities', 'KMS Key Replay Vulnerabilities', 'KMS Key Injection Vulnerabilities', 'KMS Key Tampering Vulnerabilities', 'KMS Key Leakage Vulnerabilities', 'KMS Key Compromise Vulnerabilities', 'KMS Key Escalation Vulnerabilities', 'KMS Key Privilege Vulnerabilities', 'KMS Key Bypass Vulnerabilities', 'KMS Key Race Condition Vulnerabilities', 'KMS Key Concurrency Vulnerabilities', 'KMS Key Memory Safety Vulnerabilities', 'KMS Key Unsafe Code Vulnerabilities', 'KMS Key FFI Vulnerabilities', 'KMS Key Deserialization Vulnerabilities', 'KMS Key Serialization Vulnerabilities', etc.)."]
) -> str:
    """
    Create an LLM-ready prompt for Rust KMS code review focusing on key management security.

    Parameters:
        function_explanation (str): Purpose, key lifecycle, access control, and security guarantees.
        function_body (str): Exact code under review.
        file_path (str): Repo-relative path.
        kms_context (str): KMS type, key types, encryption methods, access patterns.
        list_of_kms_threats (list[str]): Key generation, storage, rotation, access control,
            encryption/decryption, backup/recovery, audit logging.

    Output:
        str: Prompt instructing the LLM to provide findings with references and fixes.

    LLM guidance:
        - Validate key generation uses cryptographically secure random number generators.
        - Check key storage uses proper encryption at rest.
        - Review key rotation mechanisms for completeness.
        - Verify access control and authorization checks.
        - Ensure key material is properly zeroized when no longer needed.
        - Check for key leakage in logs, error messages, or memory dumps.
    """
    msg = f"""
RUST KMS THREAT ANALYSIS REQUEST

Function Context:
- Rust KMS Purpose: {function_explanation}
- File Location: {file_path}
- Rust KMS Context: {kms_context}
- Rust KMS Threats to Evaluate: {', '.join(list_of_kms_threats)}

Rust KMS Source Code to Analyze:
{function_body}

Please perform a comprehensive Rust KMS security analysis focusing on the specified threats and provide detailed findings with KMS-specific attack vector analysis, potential KMS impact, and remediation guidance specific to Rust KMS vulnerabilities and secure KMS development practices.

Key areas to analyze:
- Key generation using secure random number generators
- Key storage with proper encryption at rest
- Key rotation mechanisms and completeness
- Access control and authorization checks
- Key material zeroization and memory safety
- Key leakage prevention in logs and error messages
- Audit logging and monitoring
"""

    return msg


async def rust_web_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Rust web function does, its purpose in web applications, and its role in handling HTTP requests/responses. Should include web operations, request handling, response generation, and any web-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the Rust web function including all statements, variable assignments, control flow, function calls, web operations, and any nested logic. This is the actual Rust web code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'src/web/handlers.rs', 'lib/http/request_handler.rs', 'app/api/endpoints.rs'). Used for context and reporting."], 
    web_context: Annotated[str, "Additional Rust web context including the web framework (e.g., Actix-web, Rocket, Warp, Axum), HTTP methods, routing, middleware, and critical web operations this function handles."],
    list_of_web_threats: Annotated[list[str], "A comprehensive list of Rust web-specific threats and vulnerabilities to check for during analysis. Each item should be a specific web threat type (e.g., 'Rust Web Injection Vulnerabilities', 'Rust Web XSS Vulnerabilities', 'Rust Web CSRF Vulnerabilities', 'Rust Web SQL Injection Vulnerabilities', 'Rust Web NoSQL Injection Vulnerabilities', 'Rust Web Command Injection Vulnerabilities', 'Rust Web Path Traversal Vulnerabilities', 'Rust Web File Upload Vulnerabilities', 'Rust Web Deserialization Vulnerabilities', 'Rust Web Serialization Vulnerabilities', 'Rust Web Authentication Vulnerabilities', 'Rust Web Authorization Vulnerabilities', 'Rust Web Session Vulnerabilities', 'Rust Web Cookie Vulnerabilities', 'Rust Web Header Vulnerabilities', 'Rust Web CORS Vulnerabilities', 'Rust Web Rate Limiting Vulnerabilities', 'Rust Web DoS Vulnerabilities', 'Rust Web DDoS Vulnerabilities', 'Rust Web Input Validation Vulnerabilities', 'Rust Web Output Encoding Vulnerabilities', 'Rust Web Error Handling Vulnerabilities', 'Rust Web Logging Vulnerabilities', 'Rust Web Information Disclosure Vulnerabilities', 'Rust Web Sensitive Data Exposure Vulnerabilities', 'Rust Web Broken Access Control Vulnerabilities', 'Rust Web Security Misconfiguration Vulnerabilities', 'Rust Web Unsafe Direct Object Reference Vulnerabilities', 'Rust Web Missing Function Level Access Control Vulnerabilities', 'Rust Web XXE Vulnerabilities', 'Rust Web Insecure Deserialization Vulnerabilities', 'Rust Web Insufficient Logging Vulnerabilities', 'Rust Web Memory Safety Vulnerabilities', 'Rust Web Unsafe Code Vulnerabilities', 'Rust Web FFI Vulnerabilities', 'Rust Web Concurrency Vulnerabilities', 'Rust Web Race Condition Vulnerabilities', etc.)."]
) -> str:
    """
    Create an LLM-ready prompt for Rust web application code review focusing on web security.

    Parameters:
        function_explanation (str): Purpose, HTTP methods, routing, authentication, authorization.
        function_body (str): Exact code under review.
        file_path (str): Repo-relative path.
        web_context (str): Web framework, middleware, request/response handling, session management.
        list_of_web_threats (list[str]): Injection attacks, XSS, CSRF, authentication/authorization,
            input validation, output encoding, session management, CORS, rate limiting.

    Output:
        str: Prompt instructing the LLM to provide findings with references and fixes.

    LLM guidance:
        - Validate all user input for type, length, format, and range.
        - Check output encoding to prevent XSS attacks.
        - Review authentication and authorization mechanisms.
        - Verify CSRF protection is implemented.
        - Check session management for secure handling.
        - Ensure sensitive data is not exposed in logs or error messages.
    """
    msg = f"""
RUST WEB THREAT ANALYSIS REQUEST

Function Context:
- Rust Web Purpose: {function_explanation}
- File Location: {file_path}
- Rust Web Context: {web_context}
- Rust Web Threats to Evaluate: {', '.join(list_of_web_threats)}

Rust Web Source Code to Analyze:
{function_body}

Please perform a comprehensive Rust web security analysis focusing on the specified threats and provide detailed findings with web-specific attack vector analysis, potential web impact, and remediation guidance specific to Rust web vulnerabilities and secure web development practices.

Key areas to analyze:
- Input validation and sanitization
- Output encoding to prevent XSS
- Authentication and authorization mechanisms
- CSRF protection implementation
- Session management and security
- CORS configuration and security
- Rate limiting and DoS protection
- Sensitive data exposure prevention
"""

    return msg


async def rust_ecdsa_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Rust ECDSA function does, its purpose in digital signatures, and its role in the cryptographic system. Should include ECDSA operations, key generation, signature creation/verification, and any ECDSA-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the Rust ECDSA function including all statements, variable assignments, control flow, function calls, ECDSA operations, and any nested logic. This is the actual Rust ECDSA code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'src/crypto/ecdsa.rs', 'lib/security/ecdsa_signer.rs', 'app/crypto/ecdsa_verifier.rs'). Used for context and reporting."], 
    ecdsa_context: Annotated[str, "Additional Rust ECDSA context including the elliptic curve used (e.g., secp256k1, secp256r1, secp384r1, secp521r1), hash function, library used (e.g., secp256k1, p256, k256), and critical ECDSA operations this function handles."],
    list_of_ecdsa_threats: Annotated[list[str], "A comprehensive list of Rust ECDSA-specific threats and vulnerabilities to check for during analysis. Each item should be a specific ECDSA threat type (e.g., 'Rust ECDSA Implementation Bugs', 'Rust ECDSA Key Generation Issues', 'Rust ECDSA Signature Vulnerabilities', 'Rust ECDSA Verification Flaws', 'Rust ECDSA Nonce Reuse', 'Rust ECDSA Nonce Predictability', 'Rust ECDSA Side-Channel Attacks', 'Rust ECDSA Timing Attacks', 'Rust ECDSA Power Analysis Attacks', 'Rust ECDSA Cache Attacks', 'Rust ECDSA Memory Attacks', 'Rust ECDSA Integer Overflow Vulnerabilities', 'Rust ECDSA Buffer Overflow Vulnerabilities', 'Rust ECDSA Memory Safety Violations', 'Rust ECDSA Unsafe Code Vulnerabilities', 'Rust ECDSA FFI Vulnerabilities', 'Rust ECDSA Deserialization Vulnerabilities', 'Rust ECDSA Serialization Vulnerabilities', 'Rust ECDSA Curve Validation Vulnerabilities', 'Rust ECDSA Point Validation Vulnerabilities', 'Rust ECDSA Scalar Validation Vulnerabilities', 'Rust ECDSA Invalid Point Attacks', 'Rust ECDSA Small Subgroup Attacks', 'Rust ECDSA Invalid Curve Attacks', 'Rust ECDSA Malleability Issues', 'Rust ECDSA Constant-Time Vulnerabilities', 'Rust ECDSA Secret Leakage Vulnerabilities', 'Rust ECDSA Key Leakage Vulnerabilities', 'Rust ECDSA Nonce Leakage Vulnerabilities', etc.)."]
) -> str:
    """
    Create an LLM-ready prompt for Rust ECDSA code review focusing on signature security.

    Parameters:
        function_explanation (str): Purpose, curve/hash, signature operations, and invariants.
        function_body (str): Exact code under review.
        file_path (str): Repo-relative path.
        ecdsa_context (str): Curve, library, deterministic nonce usage, hashing, constant-time operations.
        list_of_ecdsa_threats (list[str]): Nonce reuse/predictability, side-channels, malleability,
            invalid point checks, timing variations, memory safety, unsafe code usage.

    Output:
        str: Prompt instructing the LLM to provide findings with references and fixes.

    LLM guidance:
        - Validate nonce generation uses RFC 6979 or cryptographically secure randomness.
        - Check for constant-time operations to prevent timing attacks.
        - Review point and scalar validation for invalid inputs.
        - Verify signature verification handles edge cases correctly.
        - Ensure secret keys and nonces are properly zeroized.
        - Check for memory safety issues in unsafe code blocks.
    """
    msg = f"""
RUST ECDSA THREAT ANALYSIS REQUEST

Function Context:
- Rust ECDSA Purpose: {function_explanation}
- File Location: {file_path}
- Rust ECDSA Context: {ecdsa_context}
- Rust ECDSA Threats to Evaluate: {', '.join(list_of_ecdsa_threats)}

Rust ECDSA Source Code to Analyze:
{function_body}

Please perform a comprehensive Rust ECDSA security analysis focusing on the specified threats and provide detailed findings with ECDSA-specific attack vector analysis, potential ECDSA impact, and remediation guidance specific to Rust ECDSA vulnerabilities and secure ECDSA implementation practices.

Key areas to analyze:
- Nonce generation using RFC 6979 or secure randomness
- Constant-time operations to prevent timing attacks
- Point and scalar validation for invalid inputs
- Signature verification edge case handling
- Secret key and nonce zeroization
- Memory safety in unsafe code blocks
- Side-channel attack prevention
"""

    return msg


async def rust_general_crypto_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Rust cryptographic function does, its purpose in cryptographic operations, and its role in the security system. Should include cryptographic operations, encryption, decryption, hashing, signing, and any cryptographic-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the Rust cryptographic function including all statements, variable assignments, control flow, function calls, cryptographic operations, and any nested logic. This is the actual Rust cryptographic code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'src/crypto/encryption.rs', 'lib/security/crypto_utils.rs', 'app/crypto/hash_function.rs'). Used for context and reporting."], 
    crypto_context: Annotated[str, "Additional Rust cryptographic context including the cryptographic algorithms used (e.g., AES, ChaCha20, SHA-256, BLAKE2, Ed25519), cryptographic library (e.g., ring, openssl, sodiumoxide), and critical cryptographic operations this function handles."],
    list_of_crypto_threats: Annotated[list[str], "A comprehensive list of Rust cryptographic-specific threats and vulnerabilities to check for during analysis. Each item should be a specific cryptographic threat type (e.g., 'Rust Cryptographic Implementation Bugs', 'Rust Encryption Vulnerabilities', 'Rust Decryption Vulnerabilities', 'Rust Hashing Vulnerabilities', 'Rust Key Derivation Vulnerabilities', 'Rust Random Number Generation Vulnerabilities', 'Rust IV/Nonce Reuse Vulnerabilities', 'Rust Padding Oracle Vulnerabilities', 'Rust Side-Channel Attacks', 'Rust Timing Attacks', 'Rust Power Analysis Attacks', 'Rust Cache Attacks', 'Rust Memory Attacks', 'Rust Constant-Time Vulnerabilities', 'Rust Secret Leakage Vulnerabilities', 'Rust Key Leakage Vulnerabilities', 'Rust Integer Overflow Vulnerabilities', 'Rust Buffer Overflow Vulnerabilities', 'Rust Memory Safety Violations', 'Rust Unsafe Code Vulnerabilities', 'Rust FFI Vulnerabilities', 'Rust Deserialization Vulnerabilities', 'Rust Serialization Vulnerabilities', 'Rust Algorithm Weakness Vulnerabilities', 'Rust Key Size Vulnerabilities', 'Rust Mode of Operation Vulnerabilities', 'Rust Authentication Tag Vulnerabilities', 'Rust MAC Vulnerabilities', 'Rust HMAC Vulnerabilities', 'Rust AEAD Vulnerabilities', 'Rust Authenticated Encryption Vulnerabilities', etc.)."]
) -> str:
    """
    Create an LLM-ready prompt for Rust cryptographic code review focusing on crypto security.

    Parameters:
        function_explanation (str): Purpose, algorithms, operations, and security guarantees.
        function_body (str): Exact code under review.
        file_path (str): Repo-relative path.
        crypto_context (str): Algorithms, libraries, modes of operation, key management.
        list_of_crypto_threats (list[str]): Implementation bugs, side-channels, key management,
            IV/nonce reuse, padding oracles, constant-time operations, memory safety.

    Output:
        str: Prompt instructing the LLM to provide findings with references and fixes.

    LLM guidance:
        - Validate use of cryptographically secure algorithms and libraries.
        - Check for constant-time operations to prevent timing attacks.
        - Review IV/nonce generation for uniqueness and randomness.
        - Verify key derivation uses appropriate KDFs (e.g., PBKDF2, Argon2).
        - Ensure secret material is properly zeroized.
        - Check for side-channel vulnerabilities in implementations.
    """
    msg = f"""
RUST GENERAL CRYPTO THREAT ANALYSIS REQUEST

Function Context:
- Rust Crypto Purpose: {function_explanation}
- File Location: {file_path}
- Rust Crypto Context: {crypto_context}
- Rust Crypto Threats to Evaluate: {', '.join(list_of_crypto_threats)}

Rust Crypto Source Code to Analyze:
{function_body}

Please perform a comprehensive Rust cryptographic security analysis focusing on the specified threats and provide detailed findings with cryptographic-specific attack vector analysis, potential cryptographic impact, and remediation guidance specific to Rust cryptographic vulnerabilities and secure cryptographic implementation practices.

Key areas to analyze:
- Use of cryptographically secure algorithms and libraries
- Constant-time operations to prevent timing attacks
- IV/nonce generation for uniqueness and randomness
- Key derivation using appropriate KDFs
- Secret material zeroization
- Side-channel attack prevention
- Memory safety in cryptographic operations
"""

    return msg


async def rust_tss_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Rust TSS (Threshold Signature Scheme) function does, its purpose in threshold cryptography, and its role in the cryptographic system. Should include TSS operations, key generation, signature generation, signature verification, and any TSS-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the Rust TSS function including all statements, variable assignments, control flow, function calls, TSS operations, and any nested logic. This is the actual Rust TSS code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'src/crypto/tss.rs', 'lib/security/threshold_signature.rs', 'app/crypto/tss_protocol.rs'). Used for context and reporting."], 
    tss_context: Annotated[str, "Additional Rust TSS context including the TSS scheme (e.g., FROST, GG18, GG20, ECDSA-TSS), threshold parameters (n, t), number of parties, and critical TSS operations this function handles."],
    list_of_tss_threats: Annotated[list[str], "A comprehensive list of Rust TSS-specific threats and vulnerabilities to check for during analysis. Each item should be a specific TSS threat type (e.g., 'Rust TSS Protocol Vulnerabilities', 'Rust TSS Key Generation Vulnerabilities', 'Rust TSS Signature Generation Vulnerabilities', 'Rust TSS Signature Verification Vulnerabilities', 'Rust TSS Threshold Vulnerabilities', 'Rust TSS Party Collusion Vulnerabilities', 'Rust TSS Malicious Party Vulnerabilities', 'Rust TSS Communication Vulnerabilities', 'Rust TSS Synchronization Vulnerabilities', 'Rust TSS Coordination Vulnerabilities', 'Rust TSS Secret Sharing Vulnerabilities', 'Rust TSS Share Validation Vulnerabilities', 'Rust TSS Share Reconstruction Vulnerabilities', 'Rust TSS Nonce Generation Vulnerabilities', 'Rust TSS Nonce Reuse Vulnerabilities', 'Rust TSS Side-Channel Attacks', 'Rust TSS Timing Attacks', 'Rust TSS Memory Safety Violations', 'Rust TSS Unsafe Code Vulnerabilities', 'Rust TSS FFI Vulnerabilities', 'Rust TSS Deserialization Vulnerabilities', 'Rust TSS Serialization Vulnerabilities', 'Rust TSS Integer Overflow Vulnerabilities', 'Rust TSS Buffer Overflow Vulnerabilities', 'Rust TSS Secret Leakage Vulnerabilities', 'Rust TSS Key Leakage Vulnerabilities', 'Rust TSS Share Leakage Vulnerabilities', 'Rust TSS Constant-Time Vulnerabilities', 'Rust TSS Zero-Knowledge Proof Vulnerabilities', 'Rust TSS Commitment Vulnerabilities', etc.)."]
) -> str:
    """
    Create an LLM-ready prompt for Rust TSS code review focusing on threshold signature security.

    Parameters:
        function_explanation (str): Purpose, TSS scheme, threshold parameters, and security model.
        function_body (str): Exact code under review.
        file_path (str): Repo-relative path.
        tss_context (str): TSS scheme, threshold (n, t), party roles, communication model.
        list_of_tss_threats (list[str]): Protocol correctness, threshold enforcement, collusion resistance,
            secret sharing, nonce generation, side-channels, memory safety.

    Output:
        str: Prompt instructing the LLM to provide findings with references and fixes.

    LLM guidance:
        - Validate threshold parameters are correctly enforced.
        - Check secret sharing implementation for correctness.
        - Review nonce generation for uniqueness and randomness.
        - Verify signature generation and verification logic.
        - Ensure secret shares are properly protected and zeroized.
        - Check for collusion resistance and malicious party handling.
    """
    msg = f"""
RUST TSS THREAT ANALYSIS REQUEST

Function Context:
- Rust TSS Purpose: {function_explanation}
- File Location: {file_path}
- Rust TSS Context: {tss_context}
- Rust TSS Threats to Evaluate: {', '.join(list_of_tss_threats)}

Rust TSS Source Code to Analyze:
{function_body}

Please perform a comprehensive Rust TSS security analysis focusing on the specified threats and provide detailed findings with TSS-specific attack vector analysis, potential TSS impact, and remediation guidance specific to Rust TSS vulnerabilities and secure TSS implementation practices.

Key areas to analyze:
- Threshold parameter enforcement
- Secret sharing implementation correctness
- Nonce generation for uniqueness and randomness
- Signature generation and verification logic
- Secret share protection and zeroization
- Collusion resistance and malicious party handling
- Memory safety in TSS operations
"""

    return msg


async def rust_mpc_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Rust MPC (Multi-Party Computation) function does, its purpose in secure multi-party computation, and its role in the cryptographic protocol. Should include MPC operations, secret sharing, computation protocols, and any MPC-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the Rust MPC function including all statements, variable assignments, control flow, function calls, MPC operations, and any nested logic. This is the actual Rust MPC code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'src/crypto/mpc.rs', 'lib/security/mpc_protocol.rs', 'app/crypto/mpc_computation.rs'). Used for context and reporting."], 
    mpc_context: Annotated[str, "Additional Rust MPC context including the MPC protocol (e.g., BGW, SPDZ, ABY, GMW, Shamir's Secret Sharing), threshold scheme, number of parties, adversary model, and critical MPC operations this function handles."],
    list_of_mpc_threats: Annotated[list[str], "A comprehensive list of Rust MPC-specific threats and vulnerabilities to check for during analysis. Each item should be a specific MPC threat type (e.g., 'Rust MPC Protocol Vulnerabilities', 'Rust MPC Secret Sharing Vulnerabilities', 'Rust MPC Threshold Vulnerabilities', 'Rust MPC Party Collusion Vulnerabilities', 'Rust MPC Malicious Party Vulnerabilities', 'Rust MPC Semi-Honest Party Vulnerabilities', 'Rust MPC Honest-But-Curious Vulnerabilities', 'Rust MPC Communication Vulnerabilities', 'Rust MPC Synchronization Vulnerabilities', 'Rust MPC Coordination Vulnerabilities', 'Rust MPC Agreement Vulnerabilities', 'Rust MPC Consensus Vulnerabilities', 'Rust MPC Fairness Vulnerabilities', 'Rust MPC Robustness Vulnerabilities', 'Rust MPC Abort Vulnerabilities', 'Rust MPC Leakage Vulnerabilities', 'Rust MPC Transcript Vulnerabilities', 'Rust MPC Share Vulnerabilities', 'Rust MPC Authentication Vulnerabilities', 'Rust MPC Verification Vulnerabilities', 'Rust MPC Memory Safety Violations', 'Rust MPC Unsafe Code Vulnerabilities', 'Rust MPC FFI Vulnerabilities', 'Rust MPC Deserialization Vulnerabilities', 'Rust MPC Serialization Vulnerabilities', 'Rust MPC Integer Overflow Vulnerabilities', 'Rust MPC Buffer Overflow Vulnerabilities', 'Rust MPC Secret Leakage Vulnerabilities', 'Rust MPC Key Leakage Vulnerabilities', 'Rust MPC Share Leakage Vulnerabilities', 'Rust MPC Constant-Time Vulnerabilities', 'Rust MPC Side-Channel Attacks', 'Rust MPC Timing Attacks', etc.)."]
) -> str:
    """
    Create an LLM-ready prompt for Rust MPC code review focusing on multi-party computation security.

    Parameters:
        function_explanation (str): Purpose, MPC protocol, adversary model, and security guarantees.
        function_body (str): Exact code under review.
        file_path (str): Repo-relative path.
        mpc_context (str): MPC protocol, threshold scheme, party roles, communication model, adversary model.
        list_of_mpc_threats (list[str]): Protocol correctness, collusion resistance, fairness, robustness,
            secret sharing, communication security, memory safety.

    Output:
        str: Prompt instructing the LLM to provide findings with references and fixes.

    LLM guidance:
        - Validate protocol correctness and security properties.
        - Check secret sharing implementation for correctness.
        - Review communication security and authentication.
        - Verify fairness and robustness properties.
        - Ensure secret shares are properly protected and zeroized.
        - Check for collusion resistance and malicious party handling.
        - Validate abort handling and recovery mechanisms.
    """
    msg = f"""
RUST MPC THREAT ANALYSIS REQUEST

Function Context:
- Rust MPC Purpose: {function_explanation}
- File Location: {file_path}
- Rust MPC Context: {mpc_context}
- Rust MPC Threats to Evaluate: {', '.join(list_of_mpc_threats)}

Rust MPC Source Code to Analyze:
{function_body}

Please perform a comprehensive Rust MPC security analysis focusing on the specified threats and provide detailed findings with MPC-specific attack vector analysis, potential MPC impact, and remediation guidance specific to Rust MPC vulnerabilities and secure MPC protocol practices.

Key areas to analyze:
- Protocol correctness and security properties
- Secret sharing implementation correctness
- Communication security and authentication
- Fairness and robustness properties
- Secret share protection and zeroization
- Collusion resistance and malicious party handling
- Abort handling and recovery mechanisms
- Memory safety in MPC operations
"""

    return msg

