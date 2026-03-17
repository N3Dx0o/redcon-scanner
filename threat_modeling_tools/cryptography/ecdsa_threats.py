from typing import Annotated


async def ecdsa_implementation_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the ECDSA function does, its purpose in digital signatures, and its role in the cryptographic system. Should include ECDSA operations, key generation, signature creation/verification, and any ECDSA-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the ECDSA function including all statements, variable assignments, control flow, function calls, ECDSA operations, and any nested logic. This is the actual ECDSA code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'crypto/ecdsa_sign.py', 'src/security/ECDSAUtils.js', 'app/crypto/ECDSASigner.rs'). Used for context and reporting."], 
    ecdsa_context: Annotated[str, "Additional ECDSA context including the elliptic curve used (e.g., secp256k1, secp256r1, secp384r1, secp521r1), hash function, and critical ECDSA operations this function handles."],
    list_of_ecdsa_threats: Annotated[list[str], "A comprehensive list of ECDSA-specific threats and vulnerabilities to check for during analysis. Each item should be a specific ECDSA threat type (e.g., 'ECDSA Implementation Bugs', 'ECDSA Key Generation Issues', 'ECDSA Signature Vulnerabilities', 'ECDSA Verification Flaws', 'ECDSA Nonce Reuse', 'ECDSA Nonce Predictability', 'ECDSA Side-Channel Attacks', 'ECDSA Timing Attacks', 'ECDSA Power Analysis Attacks', 'ECDSA Cache Attacks', 'ECDSA Memory Attacks', 'ECDSA Network Attacks', 'ECDSA Storage Attacks', 'ECDSA Computation Attacks', 'ECDSA Verification Attacks', 'ECDSA Communication Attacks', 'ECDSA Synchronization Attacks', 'ECDSA Coordination Attacks', 'ECDSA Agreement Attacks', 'ECDSA Consensus Attacks', 'ECDSA Finality Attacks', 'ECDSA Slashing Attacks', 'ECDSA Reward Attacks', 'ECDSA Fee Attacks', 'ECDSA Liquidity Attacks', 'ECDSA Oracle Attacks', 'ECDSA Governance Attacks', 'ECDSA Upgrade Attacks', 'ECDSA Emergency Attacks', 'ECDSA Economic Attacks', 'ECDSA Performance Attacks', 'ECDSA Reliability Attacks', 'ECDSA Availability Attacks', 'ECDSA Consistency Attacks', 'ECDSA Accuracy Attacks', 'ECDSA Completeness Attacks', 'ECDSA Timeliness Attacks', 'ECDSA Relevance Attacks', 'ECDSA Quality Attacks', 'ECDSA Security Attacks', 'ECDSA Access Attacks', 'ECDSA Authorization Attacks', 'ECDSA Authentication Attacks', 'ECDSA Encryption Attacks', 'ECDSA Hashing Attacks', 'ECDSA Compression Attacks', 'ECDSA Decompression Attacks', 'ECDSA Transformation Attacks', 'ECDSA Aggregation Attacks', 'ECDSA Filtering Attacks', 'ECDSA Sorting Attacks', 'ECDSA Searching Attacks', 'ECDSA Indexing Attacks', 'ECDSA Caching Attacks', 'ECDSA Backup Attacks', 'ECDSA Recovery Attacks', 'ECDSA Archival Attacks', 'ECDSA Retention Attacks', 'ECDSA Deletion Attacks', 'ECDSA Anonymization Attacks', 'ECDSA Pseudonymization Attacks', 'ECDSA Masking Attacks', 'ECDSA Redaction Attacks', 'ECDSA Obfuscation Attacks', 'ECDSA Tokenization Attacks', 'ECDSA Encryption Attacks', 'ECDSA Hashing Attacks', 'ECDSA Signing Attacks', 'ECDSA Verification Attacks', 'ECDSA Validation Attacks', 'ECDSA Sanitization Attacks', 'ECDSA Normalization Attacks', 'ECDSA Standardization Attacks', 'ECDSA Format Attacks', 'ECDSA Type Attacks', 'ECDSA Structure Attacks', 'ECDSA Schema Attacks', 'ECDSA Model Attacks', 'ECDSA Relationship Attacks', 'ECDSA Dependency Attacks', 'ECDSA Constraint Attacks', 'ECDSA Rule Attacks', 'ECDSA Policy Attacks', 'ECDSA Governance Attacks', 'ECDSA Compliance Attacks', 'ECDSA Audit Attacks', 'ECDSA Monitoring Attacks', 'ECDSA Logging Attacks', 'ECDSA Reporting Attacks', 'ECDSA Analytics Attacks', 'ECDSA Mining Attacks', 'ECDSA Machine Learning Attacks', 'ECDSA AI Attacks', 'ECDSA Algorithm Attacks', 'ECDSA Model Attacks', 'ECDSA Training Attacks', 'ECDSA Testing Attacks', 'ECDSA Validation Attacks', 'ECDSA Cross-Validation Attacks', 'ECDSA Overfitting Attacks', 'ECDSA Underfitting Attacks', 'ECDSA Bias Attacks', 'ECDSA Fairness Attacks', 'ECDSA Discrimination Attacks', etc.)."]
) -> str:
    """
    Build an LLM prompt to assess ECDSA code for signature safety.

    Parameters:
        function_explanation (str): Purpose, curve/hash, and invariants.
        function_body (str): Exact ECDSA-related code.
        file_path (str): Repo-relative path.
        ecdsa_context (str): Curve (secp256k1/r1/...), deterministic nonce (RFC6979) usage, hashing.
        list_of_ecdsa_threats (list[str]): Nonce reuse/predictability, side-channels, malleability,
            small-subgroup/invalid-point checks, timing variations, signature verification pitfalls.

    Output:
        str: Prompt instructing LLM to return findings with references and fixes.
    """
    msg = f"""
ECDSA IMPLEMENTATION THREAT ANALYSIS REQUEST

Function Context:
- ECDSA Purpose: {function_explanation}
- File Location: {file_path}
- ECDSA Context: {ecdsa_context}
- ECDSA Threats to Evaluate: {', '.join(list_of_ecdsa_threats)}

ECDSA Source Code to Analyze:
{function_body}

Please perform a comprehensive ECDSA security analysis focusing on the specified threats and provide detailed findings with ECDSA-specific attack vector analysis, potential ECDSA impact, and remediation guidance specific to ECDSA vulnerabilities and secure ECDSA implementation practices.
"""

    return msg


async def ecdsa_nonce_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the ECDSA nonce function does, its purpose in ECDSA signature generation, and its role in nonce generation. Should include nonce operations, random number generation, and any nonce-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the ECDSA nonce function including all statements, variable assignments, control flow, function calls, nonce operations, and any nested logic. This is the actual ECDSA nonce code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'crypto/ecdsa_nonce.py', 'src/security/ECDSAKGen.js', 'app/crypto/ECDSAKGen.rs'). Used for context and reporting."], 
    nonce_context: Annotated[str, "Additional nonce context including the nonce generation method (e.g., RFC 6979, random generation, deterministic generation), entropy sources, and critical nonce operations this function handles."],
    list_of_nonce_threats: Annotated[list[str], "A comprehensive list of ECDSA nonce-specific threats and vulnerabilities to check for during analysis. Each item should be a specific nonce threat type (e.g., 'Nonce Reuse Attacks', 'Nonce Predictability', 'Nonce Bias', 'Nonce Correlation', 'Nonce Leakage', 'Nonce Recovery', 'Nonce Manipulation', 'Nonce Injection', 'Nonce Replay', 'Nonce Collision', 'Nonce Birthday Attacks', 'Nonce Length Extension Attacks', 'Nonce Padding Attacks', 'Nonce Oracle Attacks', 'Nonce Timing Attacks', 'Nonce Side-Channel Attacks', 'Nonce Power Analysis Attacks', 'Nonce Cache Attacks', 'Nonce Memory Attacks', 'Nonce Network Attacks', 'Nonce Storage Attacks', 'Nonce Computation Attacks', 'Nonce Verification Attacks', 'Nonce Communication Attacks', 'Nonce Synchronization Attacks', 'Nonce Coordination Attacks', 'Nonce Agreement Attacks', 'Nonce Consensus Attacks', 'Nonce Finality Attacks', 'Nonce Slashing Attacks', 'Nonce Reward Attacks', 'Nonce Fee Attacks', 'Nonce Liquidity Attacks', 'Nonce Oracle Attacks', 'Nonce Governance Attacks', 'Nonce Upgrade Attacks', 'Nonce Emergency Attacks', 'Nonce Economic Attacks', 'Nonce Performance Attacks', 'Nonce Reliability Attacks', 'Nonce Availability Attacks', 'Nonce Consistency Attacks', 'Nonce Accuracy Attacks', 'Nonce Completeness Attacks', 'Nonce Timeliness Attacks', 'Nonce Relevance Attacks', 'Nonce Quality Attacks', 'Nonce Security Attacks', 'Nonce Access Attacks', 'Nonce Authorization Attacks', 'Nonce Authentication Attacks', 'Nonce Encryption Attacks', 'Nonce Hashing Attacks', 'Nonce Compression Attacks', 'Nonce Decompression Attacks', 'Nonce Transformation Attacks', 'Nonce Aggregation Attacks', 'Nonce Filtering Attacks', 'Nonce Sorting Attacks', 'Nonce Searching Attacks', 'Nonce Indexing Attacks', 'Nonce Caching Attacks', 'Nonce Backup Attacks', 'Nonce Recovery Attacks', 'Nonce Archival Attacks', 'Nonce Retention Attacks', 'Nonce Deletion Attacks', 'Nonce Anonymization Attacks', 'Nonce Pseudonymization Attacks', 'Nonce Masking Attacks', 'Nonce Redaction Attacks', 'Nonce Obfuscation Attacks', 'Nonce Tokenization Attacks', 'Nonce Encryption Attacks', 'Nonce Hashing Attacks', 'Nonce Signing Attacks', 'Nonce Verification Attacks', 'Nonce Validation Attacks', 'Nonce Sanitization Attacks', 'Nonce Normalization Attacks', 'Nonce Standardization Attacks', 'Nonce Format Attacks', 'Nonce Type Attacks', 'Nonce Structure Attacks', 'Nonce Schema Attacks', 'Nonce Model Attacks', 'Nonce Relationship Attacks', 'Nonce Dependency Attacks', 'Nonce Constraint Attacks', 'Nonce Rule Attacks', 'Nonce Policy Attacks', 'Nonce Governance Attacks', 'Nonce Compliance Attacks', 'Nonce Audit Attacks', 'Nonce Monitoring Attacks', 'Nonce Logging Attacks', 'Nonce Reporting Attacks', 'Nonce Analytics Attacks', 'Nonce Mining Attacks', 'Nonce Machine Learning Attacks', 'Nonce AI Attacks', 'Nonce Algorithm Attacks', 'Nonce Model Attacks', 'Nonce Training Attacks', 'Nonce Testing Attacks', 'Nonce Validation Attacks', 'Nonce Cross-Validation Attacks', 'Nonce Overfitting Attacks', 'Nonce Underfitting Attacks', 'Nonce Bias Attacks', 'Nonce Fairness Attacks', 'Nonce Discrimination Attacks', etc.)."]
) -> str:
    """
    Compose a prompt to review ECDSA nonce generation and handling.

    Parameters:
        function_explanation (str): RNG/deterministic nonce design and guarantees.
        function_body (str): Exact code.
        file_path (str): Repo-relative path.
        nonce_context (str): RFC6979 usage, entropy sources, seeding/reseeding, persistence.
        list_of_nonce_threats (list[str]): Reuse/predictability/bias, correlation, leakage, timing,
            side-channels, poor seeding, reuse across signatures.

    Output:
        str: Prompt for LLM to flag nonce risks with concrete mitigations.
    """
    msg = f"""
ECDSA NONCE THREAT ANALYSIS REQUEST

Function Context:
- Nonce Purpose: {function_explanation}
- File Location: {file_path}
- Nonce Context: {nonce_context}
- Nonce Threats to Evaluate: {', '.join(list_of_nonce_threats)}

ECDSA Nonce Source Code to Analyze:
{function_body}

Please perform a comprehensive ECDSA nonce security analysis focusing on the specified threats and provide detailed findings with nonce-specific attack vector analysis, potential nonce impact, and remediation guidance specific to ECDSA nonce vulnerabilities and secure nonce generation practices.
"""

    return msg


async def ecdsa_curve_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the ECDSA curve function does, its purpose in elliptic curve operations, and its role in ECDSA signature generation/verification. Should include curve operations, point operations, and any curve-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the ECDSA curve function including all statements, variable assignments, control flow, function calls, curve operations, and any nested logic. This is the actual ECDSA curve code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'crypto/ecdsa_curve.py', 'src/security/ECDSACurve.js', 'app/crypto/ECDSACurve.rs'). Used for context and reporting."], 
    curve_context: Annotated[str, "Additional curve context including the elliptic curve used (e.g., secp256k1, secp256r1, secp384r1, secp521r1), curve parameters, and critical curve operations this function handles."],
    list_of_curve_threats: Annotated[list[str], "A comprehensive list of ECDSA curve-specific threats and vulnerabilities to check for during analysis. Each item should be a specific curve threat type (e.g., 'Curve Implementation Bugs', 'Curve Parameter Issues', 'Curve Point Operations', 'Curve Scalar Operations', 'Curve Addition Attacks', 'Curve Doubling Attacks', 'Curve Multiplication Attacks', 'Curve Inversion Attacks', 'Curve Square Root Attacks', 'Curve Modular Arithmetic Attacks', 'Curve Field Arithmetic Attacks', 'Curve Group Operations', 'Curve Generator Point Issues', 'Curve Order Issues', 'Curve Cofactor Issues', 'Curve Embedding Degree Issues', 'Curve Twist Attacks', 'Curve Invalid Point Attacks', 'Curve Small Subgroup Attacks', 'Curve Invalid Curve Attacks', 'Curve Invalid Point Attacks', 'Curve Point Compression Issues', 'Curve Point Decompression Issues', 'Curve Coordinate Systems', 'Curve Affine Coordinates', 'Curve Projective Coordinates', 'Curve Jacobian Coordinates', 'Curve Edwards Coordinates', 'Curve Montgomery Coordinates', 'Curve Weierstrass Coordinates', 'Curve Short Weierstrass Coordinates', 'Curve Twisted Edwards Coordinates', 'Curve Extended Coordinates', 'Curve Homogeneous Coordinates', 'Curve Inverted Coordinates', 'Curve Mixed Coordinates', 'Curve Unified Coordinates', 'Curve Complete Coordinates', 'Curve Safe Coordinates', 'Curve Fast Coordinates', 'Curve Memory-Efficient Coordinates', 'Curve Time-Efficient Coordinates', 'Curve Space-Efficient Coordinates', 'Curve Energy-Efficient Coordinates', 'Curve Power-Efficient Coordinates', 'Curve Cache-Efficient Coordinates', 'Curve Network-Efficient Coordinates', 'Curve Storage-Efficient Coordinates', 'Curve Computation-Efficient Coordinates', 'Curve Verification-Efficient Coordinates', 'Curve Communication-Efficient Coordinates', 'Curve Synchronization-Efficient Coordinates', 'Curve Coordination-Efficient Coordinates', 'Curve Agreement-Efficient Coordinates', 'Curve Consensus-Efficient Coordinates', 'Curve Finality-Efficient Coordinates', 'Curve Slashing-Efficient Coordinates', 'Curve Reward-Efficient Coordinates', 'Curve Fee-Efficient Coordinates', 'Curve Liquidity-Efficient Coordinates', 'Curve Oracle-Efficient Coordinates', 'Curve Governance-Efficient Coordinates', 'Curve Upgrade-Efficient Coordinates', 'Curve Emergency-Efficient Coordinates', 'Curve Economic-Efficient Coordinates', 'Curve Performance-Efficient Coordinates', 'Curve Reliability-Efficient Coordinates', 'Curve Availability-Efficient Coordinates', 'Curve Consistency-Efficient Coordinates', 'Curve Accuracy-Efficient Coordinates', 'Curve Completeness-Efficient Coordinates', 'Curve Timeliness-Efficient Coordinates', 'Curve Relevance-Efficient Coordinates', 'Curve Quality-Efficient Coordinates', 'Curve Security-Efficient Coordinates', 'Curve Access-Efficient Coordinates', 'Curve Authorization-Efficient Coordinates', 'Curve Authentication-Efficient Coordinates', 'Curve Encryption-Efficient Coordinates', 'Curve Hashing-Efficient Coordinates', 'Curve Compression-Efficient Coordinates', 'Curve Decompression-Efficient Coordinates', 'Curve Transformation-Efficient Coordinates', 'Curve Aggregation-Efficient Coordinates', 'Curve Filtering-Efficient Coordinates', 'Curve Sorting-Efficient Coordinates', 'Curve Searching-Efficient Coordinates', 'Curve Indexing-Efficient Coordinates', 'Curve Caching-Efficient Coordinates', 'Curve Backup-Efficient Coordinates', 'Curve Recovery-Efficient Coordinates', 'Curve Archival-Efficient Coordinates', 'Curve Retention-Efficient Coordinates', 'Curve Deletion-Efficient Coordinates', 'Curve Anonymization-Efficient Coordinates', 'Curve Pseudonymization-Efficient Coordinates', 'Curve Masking-Efficient Coordinates', 'Curve Redaction-Efficient Coordinates', 'Curve Obfuscation-Efficient Coordinates', 'Curve Tokenization-Efficient Coordinates', 'Curve Encryption-Efficient Coordinates', 'Curve Hashing-Efficient Coordinates', 'Curve Signing-Efficient Coordinates', 'Curve Verification-Efficient Coordinates', 'Curve Validation-Efficient Coordinates', 'Curve Sanitization-Efficient Coordinates', 'Curve Normalization-Efficient Coordinates', 'Curve Standardization-Efficient Coordinates', 'Curve Format-Efficient Coordinates', 'Curve Type-Efficient Coordinates', 'Curve Structure-Efficient Coordinates', 'Curve Schema-Efficient Coordinates', 'Curve Model-Efficient Coordinates', 'Curve Relationship-Efficient Coordinates', 'Curve Dependency-Efficient Coordinates', 'Curve Constraint-Efficient Coordinates', 'Curve Rule-Efficient Coordinates', 'Curve Policy-Efficient Coordinates', 'Curve Governance-Efficient Coordinates', 'Curve Compliance-Efficient Coordinates', 'Curve Audit-Efficient Coordinates', 'Curve Monitoring-Efficient Coordinates', 'Curve Logging-Efficient Coordinates', 'Curve Reporting-Efficient Coordinates', 'Curve Analytics-Efficient Coordinates', 'Curve Mining-Efficient Coordinates', 'Curve Machine Learning-Efficient Coordinates', 'Curve AI-Efficient Coordinates', 'Curve Algorithm-Efficient Coordinates', 'Curve Model-Efficient Coordinates', 'Curve Training-Efficient Coordinates', 'Curve Testing-Efficient Coordinates', 'Curve Validation-Efficient Coordinates', 'Curve Cross-Validation-Efficient Coordinates', 'Curve Overfitting-Efficient Coordinates', 'Curve Underfitting-Efficient Coordinates', 'Curve Bias-Efficient Coordinates', 'Curve Fairness-Efficient Coordinates', 'Curve Discrimination-Efficient Coordinates', etc.)."]
) -> str:
    """
    Prepare a prompt to inspect elliptic-curve operations and validations.

    Parameters:
        function_explanation (str): Intended curve ops and constraints.
        function_body (str): Exact code.
        file_path (str): Repo-relative path.
        curve_context (str): Curve parameters, coordinate system, field arithmetic details.
        list_of_curve_threats (list[str]): Invalid-point checks, small-subgroup, coordinate bugs,
            side-channels in ladders, constant-time arithmetic, parameter validation.

    Output:
        str: Prompt asking for concrete issues with references and fixes.
    """
    msg = f"""
ECDSA CURVE THREAT ANALYSIS REQUEST

Function Context:
- Curve Purpose: {function_explanation}
- File Location: {file_path}
- Curve Context: {curve_context}
- Curve Threats to Evaluate: {', '.join(list_of_curve_threats)}

ECDSA Curve Source Code to Analyze:
{function_body}

Please perform a comprehensive ECDSA curve security analysis focusing on the specified threats and provide detailed findings with curve-specific attack vector analysis, potential curve impact, and remediation guidance specific to ECDSA curve vulnerabilities and secure curve implementation practices.
"""

    return msg
