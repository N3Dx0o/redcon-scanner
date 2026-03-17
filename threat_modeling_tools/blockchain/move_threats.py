from typing import Annotated


async def move_general_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Move function does, its purpose in the Move ecosystem, and its role in the application. Should include Move-specific operations, resource management, and any Move-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the Move function including all statements, variable assignments, control flow, function calls, Move operations, and any nested logic. This is the actual Move code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'sources/token.move', 'modules/nft.move', 'scripts/transfer.move'). Used for context and reporting."], 
    move_context: Annotated[str, "Additional Move context including the module type (e.g., token, NFT, DeFi, DAO), resource types used, abilities defined, and critical Move operations this function handles."],
    list_of_move_threats: Annotated[list[str], "A comprehensive list of Move-specific threats and vulnerabilities to check for during analysis. Each item should be a specific Move threat type (e.g., 'Resource Safety Violations', 'Access Control Issues', 'Signer Authentication', 'Global Storage Access', 'Ability Misuse', 'Type Safety Violations', 'Module Visibility Issues', 'Struct Field Access', 'Resource Account Security', etc.)."]
) -> str:
    """
    Compose an LLM prompt to review Move code against explicit threat categories.

    Parameters:
        function_explanation (str): Purpose, resources touched, abilities, and expected signers.
        function_body (str): Exact Move module/function code under review.
        file_path (str): Repo-relative path to the Move code.
        move_context (str): Module type, resource usage, abilities, global storage access.
        list_of_move_threats (list[str]): Specific checks (resource safety, access control,
            signer validation, ability constraints, type safety).

    Output:
        str: Prompt instructing the LLM to produce findings with references and fixes.

    LLM guidance:
        - Validate resource safety (no accidental duplication or drop).
        - Check access control through module boundaries and visibility.
        - Confirm signer authentication for privileged operations.
        - Review global storage access patterns and permissions.
        - Verify ability constraints (copy, drop, store, key).
    """
    msg = f"""
MOVE GENERAL THREAT ANALYSIS REQUEST

Function Context:
- Move Purpose: {function_explanation}
- File Location: {file_path}
- Move Context: {move_context}
- Move Threats to Evaluate: {', '.join(list_of_move_threats)}

Move Source Code to Analyze:
{function_body}

Please perform a comprehensive Move security analysis focusing on the specified threats and provide detailed findings with Move-specific attack vector analysis, potential Aptos/Move impact, and remediation guidance specific to Move vulnerabilities and secure Move development practices.

Key Move Security Principles to Verify:
1. Resource Safety: Ensure resources cannot be duplicated or dropped unless explicitly allowed
2. Access Control: Verify module-level and struct-level access restrictions
3. Signer Authentication: Confirm proper signer validation for privileged operations
4. Ability Constraints: Check that copy, drop, store, and key abilities are properly defined
5. Type Safety: Validate type parameters and generic constraints
6. Global Storage: Review global storage access patterns and permissions
"""

    return msg


async def move_resource_safety_threats(
    function_explanation: Annotated[str, "Explanation of the Move function's resource handling, including what resources it creates, moves, borrows, or destroys."],
    function_body: Annotated[str, "The complete Move function source code that handles resources."],
    file_path: Annotated[str, "Path to the Move file (e.g., 'sources/token.move')."],
    resource_context: Annotated[str, "Context about resources used: struct definitions, abilities (copy/drop/store/key), and resource lifecycle."],
    list_of_resource_threats: Annotated[list[str], "List of resource safety threats: 'Resource Duplication', 'Resource Loss/Drop', 'Resource Leakage', 'Invalid Resource Transfer', 'Resource Borrowing Violations', 'Resource Destruction Without Permission', 'Resource State Corruption', 'Resource Ownership Confusion', etc."]
) -> str:
    """
    Analyze Move code for resource safety violations.
    
    Move enforces scarcity through its resource model. This function checks for:
    - Accidental or intentional resource duplication
    - Resource drops without explicit drop ability
    - Resource moves that violate ownership
    - Borrowing violations (mutable/immutable conflicts)
    - Resource leakage through unconsumed values
    """
    msg = f"""
MOVE RESOURCE SAFETY THREAT ANALYSIS

Function Context:
- Resource Operations: {function_explanation}
- File Location: {file_path}
- Resource Context: {resource_context}
- Resource Threats: {', '.join(list_of_resource_threats)}

Move Code to Analyze:
{function_body}

RESOURCE SAFETY ANALYSIS REQUIREMENTS:

1. SCARCITY ENFORCEMENT:
   - Verify resources cannot be accidentally duplicated
   - Check that only structs with 'copy' ability can be copied
   - Ensure resources without 'drop' are explicitly consumed or moved
   
2. RESOURCE LIFECYCLE:
   - Track resource creation, movement, and destruction
   - Verify all resources are properly handled in all code paths
   - Check for resource leakage in error paths
   
3. BORROWING RULES:
   - Validate mutable and immutable reference usage
   - Check for conflicting borrows (mutable + immutable)
   - Ensure borrows don't outlive their parent resource
   
4. ABILITY CONSTRAINTS:
   - Verify 'copy' ability is only on duplicatable types
   - Check 'drop' ability for safe resource disposal
   - Validate 'store' ability for nested resource storage
   - Ensure 'key' ability for global storage resources

Provide findings with specific line references, exploit scenarios, and Move-specific remediation.
"""
    return msg


async def move_access_control_threats(
    function_explanation: Annotated[str, "Explanation of the function's access control mechanisms, including visibility modifiers, signer requirements, and permission checks."],
    function_body: Annotated[str, "The complete Move function source code with access control logic."],
    file_path: Annotated[str, "Path to the Move file."],
    access_context: Annotated[str, "Context about access control: public/private functions, friend declarations, struct visibility, and permission models."],
    list_of_access_threats: Annotated[list[str], "List of access control threats: 'Missing Signer Validation', 'Public Function Exposure', 'Struct Field Access Bypass', 'Module Boundary Violation', 'Friend Declaration Misuse', 'Privilege Escalation', 'Unauthorized Resource Access', etc."]
) -> str:
    """
    Analyze Move code for access control vulnerabilities.
    
    Move provides access control through:
    - Module boundaries (public vs private functions)
    - Signer authentication
    - Struct field visibility
    - Friend declarations
    - Ability-based permissions
    """
    msg = f"""
MOVE ACCESS CONTROL THREAT ANALYSIS

Function Context:
- Access Control Operations: {function_explanation}
- File Location: {file_path}
- Access Context: {access_context}
- Access Threats: {', '.join(list_of_access_threats)}

Move Code to Analyze:
{function_body}

ACCESS CONTROL ANALYSIS REQUIREMENTS:

1. SIGNER VALIDATION:
   - Verify signer parameter is properly validated
   - Check that privileged operations require signer
   - Ensure signer ownership matches resource owner
   - Validate signer in multi-agent transactions
   
2. MODULE BOUNDARIES:
   - Check public function exposure is intentional
   - Verify private functions aren't bypassable
   - Validate friend declarations are necessary and safe
   - Ensure entry functions have proper access checks
   
3. STRUCT VISIBILITY:
   - Verify struct fields are properly protected
   - Check that constructors validate inputs
   - Ensure accessors and setters have proper checks
   - Validate struct can only be created in defining module
   
4. RESOURCE PERMISSIONS:
   - Check global storage operations (move_to, move_from, borrow_global)
   - Verify only authorized accounts can access resources
   - Validate resource account permissions
   - Ensure proper ownership transfers

Provide findings with attack vectors for unauthorized access and Move-specific fixes.
"""
    return msg


async def move_object_threats(
    function_explanation: Annotated[str, "Explanation of Move Object operations in the function, including object creation, transfer, and deletion."],
    function_body: Annotated[str, "The complete Move function source code working with Move Objects."],
    file_path: Annotated[str, "Path to the Move file."],
    object_context: Annotated[str, "Context about Move Objects: object types, ownership model, transferability, deletability, and extensibility features."],
    list_of_object_threats: Annotated[list[str], "List of Move Object threats: 'Object Creation Vulnerabilities', 'Object Ownership Issues', 'Object Transfer Exploits', 'Object Deletion Race Conditions', 'Object Reference Manipulation', 'Object Extension Security', 'Object Event Spoofing', etc."]
) -> str:
    """
    Analyze Move code for Object-specific vulnerabilities.
    
    Move Objects (AIP-10) provide:
    - Globally accessible resources at single addresses
    - Heterogeneous resource storage
    - Flexible ownership and transfer models
    - Extensibility through dynamic fields
    """
    msg = f"""
MOVE OBJECT THREAT ANALYSIS

Function Context:
- Object Operations: {function_explanation}
- File Location: {file_path}
- Object Context: {object_context}
- Object Threats: {', '.join(list_of_object_threats)}

Move Code to Analyze:
{function_body}

MOVE OBJECT SECURITY ANALYSIS:

1. OBJECT CREATION:
   - Verify object constructors validate all inputs
   - Check object initialization is complete and atomic
   - Ensure object references are properly generated
   - Validate object metadata and properties
   
2. OBJECT OWNERSHIP:
   - Check ownership transfers are authorized
   - Verify owner validation before operations
   - Ensure ownership changes emit proper events
   - Validate multi-owner scenarios
   
3. OBJECT TRANSFER:
   - Check transfer restrictions are enforced
   - Verify transferability flags are respected
   - Ensure atomic transfers prevent race conditions
   - Validate transfer hooks and callbacks
   
4. OBJECT DELETION:
   - Verify only owners can delete objects
   - Check deletability restrictions
   - Ensure proper cleanup of nested resources
   - Validate deletion finality
   
5. OBJECT EXTENSION:
   - Check dynamic field additions are authorized
   - Verify extension data is properly validated
   - Ensure extension doesn't break object invariants
   - Validate extension permissions

Provide findings with Object-specific attack scenarios and Aptos best practices.
"""
    return msg


async def move_token_threats(
    function_explanation: Annotated[str, "Explanation of token operations: creation, transfer, burn, or fungible asset management."],
    function_body: Annotated[str, "The complete Move function source code handling tokens or fungible assets."],
    file_path: Annotated[str, "Path to the Move file."],
    token_context: Annotated[str, "Context about token implementation: Coin standard, Fungible Asset (FA), Token Objects, or legacy tokens. Include supply management and permissions."],
    list_of_token_threats: Annotated[list[str], "List of token threats: 'Unauthorized Minting', 'Burn Permission Bypass', 'Transfer Authorization', 'Supply Manipulation', 'Balance Overflow/Underflow', 'Token Freezing Issues', 'Metadata Tampering', 'Royalty Bypass', etc."]
) -> str:
    """
    Analyze Move token and fungible asset code for vulnerabilities.
    
    Aptos supports multiple token standards:
    - Coin (legacy)
    - Fungible Asset (FA) - AIP-21
    - Token Objects - AIP-11, AIP-22
    """
    msg = f"""
MOVE TOKEN/FUNGIBLE ASSET THREAT ANALYSIS

Function Context:
- Token Operations: {function_explanation}
- File Location: {file_path}
- Token Context: {token_context}
- Token Threats: {', '.join(list_of_token_threats)}

Move Code to Analyze:
{function_body}

TOKEN SECURITY ANALYSIS:

1. SUPPLY MANAGEMENT:
   - Verify minting is properly authorized
   - Check max supply constraints are enforced
   - Ensure burn operations decrease supply correctly
   - Validate supply tracking accuracy
   
2. TRANSFER CONTROLS:
   - Check transfer authorization and permissions
   - Verify balance checks prevent overdrafts
   - Ensure transfer atomicity
   - Validate transfer hooks and callbacks
   
3. BALANCE SAFETY:
   - Check for balance overflow in additions
   - Verify balance underflow prevention in transfers
   - Ensure atomic balance updates
   - Validate concurrent balance modifications
   
4. FUNGIBLE ASSET (FA) SPECIFIC:
   - Verify FA metadata is immutable or properly controlled
   - Check FA store operations are authorized
   - Ensure FA primary store handling is correct
   - Validate FA freezing and pausing mechanisms
   
5. TOKEN OBJECTS (AIP-11/22):
   - Check token property mutations are authorized
   - Verify royalty calculations and enforcement
   - Ensure collection-level controls
   - Validate token burning and deletion

Provide findings with token-specific exploit vectors and Aptos token standard compliance.
"""
    return msg


async def move_nft_threats(
    function_explanation: Annotated[str, "Explanation of NFT operations: creation, transfer, mutation, or Digital Asset management."],
    function_body: Annotated[str, "The complete Move function source code handling NFTs or Digital Assets."],
    file_path: Annotated[str, "Path to the Move file."],
    nft_context: Annotated[str, "Context about NFT implementation: Token Objects (AIP-11), Digital Assets, or legacy tokens. Include collection details and property mutability."],
    list_of_nft_threats: Annotated[list[str], "List of NFT threats: 'Unauthorized Minting', 'Metadata Tampering', 'Property Mutation Exploits', 'Collection Authority Bypass', 'Royalty Evasion', 'Token URI Manipulation', 'Burning Without Permission', 'Soulbound Token Violations', etc."]
) -> str:
    """
    Analyze Move NFT and Digital Asset code for vulnerabilities.
    
    Aptos NFT standards:
    - Token Objects (AIP-11, AIP-22)
    - Digital Asset standard
    - Legacy Aptos Token (deprecated)
    """
    msg = f"""
MOVE NFT/DIGITAL ASSET THREAT ANALYSIS

Function Context:
- NFT Operations: {function_explanation}
- File Location: {file_path}
- NFT Context: {nft_context}
- NFT Threats: {', '.join(list_of_nft_threats)}

Move Code to Analyze:
{function_body}

NFT SECURITY ANALYSIS:

1. MINTING CONTROLS:
   - Verify minting authorization (creator, collection authority)
   - Check supply limits are enforced
   - Ensure unique token IDs/names
   - Validate minting fee collection
   
2. METADATA INTEGRITY:
   - Check metadata immutability or controlled mutation
   - Verify URI update permissions
   - Ensure property schema enforcement
   - Validate off-chain metadata references
   
3. PROPERTY MUTATION:
   - Check property mutation authorization
   - Verify mutable properties are explicitly defined
   - Ensure property type safety
   - Validate mutation tracking and events
   
4. COLLECTION MANAGEMENT:
   - Verify collection creator rights
   - Check collection-level settings enforcement
   - Ensure collection metadata integrity
   - Validate collection royalty enforcement
   
5. ROYALTY ENFORCEMENT:
   - Check royalty percentage validation (0-100%)
   - Verify royalty recipient address
   - Ensure royalty calculations are correct
   - Validate royalty payment enforcement in transfers
   
6. SOULBOUND TOKENS:
   - Verify non-transferability is enforced
   - Check burn permissions for soulbound tokens
   - Ensure soulbound flag cannot be toggled
   - Validate creation restrictions

Provide findings with NFT-specific attack scenarios and Token Object standard compliance.
"""
    return msg


async def move_defi_threats(
    function_explanation: Annotated[str, "Explanation of DeFi operations: swaps, liquidity provision, lending, borrowing, or yield farming."],
    function_body: Annotated[str, "The complete Move function source code implementing DeFi logic."],
    file_path: Annotated[str, "Path to the Move file."],
    defi_context: Annotated[str, "Context about DeFi protocol: AMM, lending protocol, yield aggregator, etc. Include oracle usage, price calculations, and liquidity mechanisms."],
    list_of_defi_threats: Annotated[list[str], "List of DeFi threats: 'Price Oracle Manipulation', 'Slippage Exploitation', 'Flash Loan Attacks', 'Reentrancy', 'Liquidity Pool Draining', 'Interest Rate Manipulation', 'Collateral Calculation Errors', 'Front-Running', 'Sandwich Attacks', etc."]
) -> str:
    """
    Analyze Move DeFi code for financial vulnerabilities.
    
    DeFi-specific concerns in Move:
    - Price oracle reliability
    - AMM math correctness
    - Liquidity management
    - Interest calculations
    - Collateralization ratios
    """
    msg = f"""
MOVE DEFI THREAT ANALYSIS

Function Context:
- DeFi Operations: {function_explanation}
- File Location: {file_path}
- DeFi Context: {defi_context}
- DeFi Threats: {', '.join(list_of_defi_threats)}

Move Code to Analyze:
{function_body}

DEFI SECURITY ANALYSIS:

1. PRICE ORACLE SECURITY:
   - Verify oracle data source reliability
   - Check oracle update frequency and staleness
   - Ensure price manipulation resistance
   - Validate fallback oracle mechanisms
   
2. AMM MATHEMATICS:
   - Verify constant product formula correctness
   - Check for rounding errors and precision loss
   - Ensure slippage calculations are accurate
   - Validate fee calculations
   
3. LIQUIDITY MANAGEMENT:
   - Check LP token minting/burning correctness
   - Verify liquidity provision ratio calculations
   - Ensure atomic swaps prevent arbitrage
   - Validate minimum liquidity requirements
   
4. LENDING/BORROWING:
   - Verify collateralization ratio enforcement
   - Check interest rate calculations
   - Ensure liquidation thresholds are safe
   - Validate health factor calculations
   
5. FLASH LOAN PROTECTION:
   - Check for same-transaction exploits
   - Verify state invariants are maintained
   - Ensure atomic operation guarantees
   - Validate balance checks before and after
   
6. MEV PROTECTION:
   - Check for front-running vulnerabilities
   - Verify transaction ordering protections
   - Ensure sandwich attack resistance
   - Validate deadline parameters

Provide findings with DeFi-specific exploit scenarios, mathematical proofs, and Move best practices.
"""
    return msg


async def move_global_storage_threats(
    function_explanation: Annotated[str, "Explanation of global storage operations: move_to, move_from, borrow_global, borrow_global_mut, exists checks."],
    function_body: Annotated[str, "The complete Move function source code using global storage."],
    file_path: Annotated[str, "Path to the Move file."],
    storage_context: Annotated[str, "Context about global storage: resource types stored, addresses used, and storage patterns."],
    list_of_storage_threats: Annotated[list[str], "List of storage threats: 'Unauthorized Storage Access', 'Storage Collision', 'Resource Already Exists', 'Resource Not Found', 'Borrow Conflicts', 'Storage State Inconsistency', 'Storage Exhaustion', etc."]
) -> str:
    """
    Analyze Move global storage operations for vulnerabilities.
    
    Global storage operations:
    - move_to: Store resource at address
    - move_from: Remove resource from address
    - borrow_global: Immutable borrow
    - borrow_global_mut: Mutable borrow
    - exists: Check resource existence
    """
    msg = f"""
MOVE GLOBAL STORAGE THREAT ANALYSIS

Function Context:
- Storage Operations: {function_explanation}
- File Location: {file_path}
- Storage Context: {storage_context}
- Storage Threats: {', '.join(list_of_storage_threats)}

Move Code to Analyze:
{function_body}

GLOBAL STORAGE SECURITY ANALYSIS:

1. MOVE_TO OPERATIONS:
   - Verify resource doesn't already exist at address
   - Check address ownership/permission
   - Ensure proper signer validation
   - Validate resource initialization state
   
2. MOVE_FROM OPERATIONS:
   - Verify resource exists before removal
   - Check removal authorization
   - Ensure proper resource handling after removal
   - Validate cascading deletions
   
3. BORROW_GLOBAL OPERATIONS:
   - Check resource existence before borrowing
   - Verify read permissions
   - Ensure borrow scope doesn't outlive resource
   - Validate concurrent immutable borrows
   
4. BORROW_GLOBAL_MUT OPERATIONS:
   - Verify exclusive mutable access
   - Check no conflicting immutable borrows
   - Ensure mutations maintain invariants
   - Validate authorization for mutations
   
5. EXISTS CHECKS:
   - Verify TOCTOU (Time-of-Check-Time-of-Use) safety
   - Check exists before operations
   - Ensure atomic check-and-operate patterns
   - Validate error handling for missing resources
   
6. STORAGE PATTERNS:
   - Check for storage address collisions
   - Verify storage key uniqueness
   - Ensure proper storage cleanup
   - Validate storage size limits

Provide findings with storage-specific vulnerabilities and safe global storage patterns.
"""
    return msg


async def move_parallelization_threats(
    function_explanation: Annotated[str, "Explanation of the function's potential parallel execution behavior and transaction dependencies."],
    function_body: Annotated[str, "The complete Move function source code that may execute in parallel."],
    file_path: Annotated[str, "Path to the Move file."],
    parallel_context: Annotated[str, "Context about parallelization: Block-STM usage, transaction dependencies, shared state, and conflict detection."],
    list_of_parallel_threats: Annotated[list[str], "List of parallelization threats: 'Race Conditions', 'Read-Write Conflicts', 'Write-Write Conflicts', 'State Inconsistency', 'Transaction Ordering Dependencies', 'Atomic Operation Violations', 'Concurrent Access Exploits', etc."]
) -> str:
    """
    Analyze Move code for parallel execution vulnerabilities.
    
    Aptos uses Block-STM for parallel transaction execution:
    - Automatic conflict detection
    - Optimistic execution with validation
    - Transaction re-execution on conflicts
    - No explicit parallel programming required
    """
    msg = f"""
MOVE PARALLELIZATION THREAT ANALYSIS

Function Context:
- Parallel Behavior: {function_explanation}
- File Location: {file_path}
- Parallel Context: {parallel_context}
- Parallelization Threats: {', '.join(list_of_parallel_threats)}

Move Code to Analyze:
{function_body}

PARALLELIZATION SECURITY ANALYSIS:

1. RACE CONDITION DETECTION:
   - Identify shared state access patterns
   - Check for non-atomic read-modify-write operations
   - Verify invariants hold under concurrent execution
   - Validate critical sections are properly protected
   
2. TRANSACTION DEPENDENCIES:
   - Check for implicit transaction ordering requirements
   - Verify operations are commutative when possible
   - Ensure dependent transactions are sequenced
   - Validate transaction execution assumptions
   
3. STATE CONSISTENCY:
   - Verify state invariants under parallel execution
   - Check for partial state updates
   - Ensure atomic multi-resource operations
   - Validate rollback safety
   
4. CONFLICT RESOLUTION:
   - Check behavior under transaction re-execution
   - Verify idempotency where required
   - Ensure deterministic conflict resolution
   - Validate optimistic execution assumptions
   
5. SHARED RESOURCE ACCESS:
   - Identify hotspot resources (high contention)
   - Check for unnecessary serialization points
   - Verify efficient conflict detection
   - Validate resource access patterns
   
6. BLOCK-STM INTERACTION:
   - Understand automatic conflict detection
   - Check for false conflict triggers
   - Verify performance under contention
   - Validate parallel execution benefits

Provide findings with race condition scenarios and parallel-safe Move patterns.
"""
    return msg


async def move_cryptography_threats(
    function_explanation: Annotated[str, "Explanation of cryptographic operations: signatures, hashing, encryption, or randomness usage."],
    function_body: Annotated[str, "The complete Move function source code using cryptographic primitives."],
    file_path: Annotated[str, "Path to the Move file."],
    crypto_context: Annotated[str, "Context about cryptography: algorithms used, key management, signature schemes, hash functions, and randomness sources."],
    list_of_crypto_threats: Annotated[list[str], "List of cryptography threats: 'Weak Signature Validation', 'Hash Collision', 'Predictable Randomness', 'Key Exposure', 'Algorithm Misuse', 'Nonce Reuse', 'Weak Key Generation', 'Side-Channel Attacks', etc."]
) -> str:
    """
    Analyze Move cryptography usage for vulnerabilities.
    
    Aptos cryptography features:
    - ED25519 signatures
    - Multi-ED25519 signatures
    - Secp256k1 for Ethereum compatibility
    - BLS12-381 for advanced cryptography
    - Secure randomness (aptos_framework::randomness)
    """
    msg = f"""
MOVE CRYPTOGRAPHY THREAT ANALYSIS

Function Context:
- Cryptographic Operations: {function_explanation}
- File Location: {file_path}
- Crypto Context: {crypto_context}
- Crypto Threats: {', '.join(list_of_crypto_threats)}

Move Code to Analyze:
{function_body}

CRYPTOGRAPHY SECURITY ANALYSIS:

1. SIGNATURE VERIFICATION:
   - Verify signature validation is performed correctly
   - Check for signature malleability vulnerabilities
   - Ensure proper public key verification
   - Validate multi-signature threshold requirements
   
2. HASH FUNCTION USAGE:
   - Check for appropriate hash algorithm selection
   - Verify hash collision resistance requirements
   - Ensure proper hash input encoding
   - Validate hash comparison operations
   
3. RANDOMNESS SECURITY:
   - Verify use of secure randomness source
   - Check for predictable random number generation
   - Ensure proper entropy sources
   - Validate randomness usage in security-critical operations
   
4. KEY MANAGEMENT:
   - Check for hardcoded keys or secrets
   - Verify key rotation mechanisms
   - Ensure secure key storage
   - Validate key derivation functions
   
5. ALGORITHM SELECTION:
   - Verify appropriate algorithm for use case
   - Check for deprecated or weak algorithms
   - Ensure proper parameter selection
   - Validate cryptographic mode of operation
   
6. APTOS RANDOMNESS (aptos_framework::randomness):
   - Verify randomness module usage is correct
   - Check for proper randomness commitment
   - Ensure randomness cannot be predicted
   - Validate randomness usage in critical operations

Provide findings with cryptography-specific vulnerabilities and Aptos crypto best practices.
"""
    return msg


async def move_upgrade_threats(
    function_explanation: Annotated[str, "Explanation of module upgrade mechanisms and compatibility requirements."],
    function_body: Annotated[str, "The complete Move module code with upgrade capabilities."],
    file_path: Annotated[str, "Path to the Move file."],
    upgrade_context: Annotated[str, "Context about upgradability: upgrade policies, compatibility requirements, migration logic, and upgrade authorization."],
    list_of_upgrade_threats: Annotated[list[str], "List of upgrade threats: 'Unauthorized Upgrade', 'Breaking Changes', 'Storage Layout Changes', 'Compatibility Issues', 'Migration Failures', 'Upgrade Policy Bypass', 'Version Confusion', 'State Corruption During Upgrade', etc."]
) -> str:
    """
    Analyze Move module upgrades for vulnerabilities.
    
    Move supports module upgrades with compatibility checks:
    - Compatible upgrades (add functions, maintain existing)
    - Incompatible upgrades (require careful handling)
    - Upgrade policies (immutable, arbitrary, package)
    """
    msg = f"""
MOVE MODULE UPGRADE THREAT ANALYSIS

Function Context:
- Upgrade Mechanisms: {function_explanation}
- File Location: {file_path}
- Upgrade Context: {upgrade_context}
- Upgrade Threats: {', '.join(list_of_upgrade_threats)}

Move Code to Analyze:
{function_body}

MODULE UPGRADE SECURITY ANALYSIS:

1. UPGRADE AUTHORIZATION:
   - Verify upgrade permission checks
   - Check upgrade signer validation
   - Ensure upgrade policy enforcement
   - Validate governance approval for upgrades
   
2. COMPATIBILITY CHECKS:
   - Verify struct layout compatibility
   - Check function signature compatibility
   - Ensure ability changes are safe
   - Validate type parameter changes
   
3. STORAGE MIGRATION:
   - Check data migration correctness
   - Verify state transformation validity
   - Ensure migration atomicity
   - Validate rollback capabilities
   
4. UPGRADE POLICIES:
   - Verify immutable policy enforcement
   - Check arbitrary upgrade restrictions
   - Ensure package upgrade coordination
   - Validate policy transition rules
   
5. BREAKING CHANGES:
   - Identify potential breaking changes
   - Check impact on dependent modules
   - Verify deprecation handling
   - Validate backward compatibility
   
6. VERSION MANAGEMENT:
   - Check version numbering consistency
   - Verify version compatibility checks
   - Ensure proper version dependencies
   - Validate version upgrade paths

Provide findings with upgrade-specific risks and safe upgrade patterns in Move.
"""
    return msg


async def move_multi_agent_threats(
    function_explanation: Annotated[str, "Explanation of multi-agent transaction logic involving multiple signers."],
    function_body: Annotated[str, "The complete Move function source code handling multi-agent transactions."],
    file_path: Annotated[str, "Path to the Move file."],
    multi_agent_context: Annotated[str, "Context about multi-agent operations: number of signers, roles, permissions, and coordination requirements."],
    list_of_multi_agent_threats: Annotated[list[str], "List of multi-agent threats: 'Missing Signer Validation', 'Signer Role Confusion', 'Partial Authorization', 'Signer Impersonation', 'Transaction Malleability', 'Coordination Failures', 'Replay Attacks', etc."]
) -> str:
    """
    Analyze Move multi-agent transactions for vulnerabilities.
    
    Aptos supports multi-agent transactions where:
    - Multiple distinct signers can participate
    - Each signer has independent authorization
    - Transaction requires all signers to execute
    - Useful for atomic multi-party operations
    """
    msg = f"""
MOVE MULTI-AGENT TRANSACTION THREAT ANALYSIS

Function Context:
- Multi-Agent Operations: {function_explanation}
- File Location: {file_path}
- Multi-Agent Context: {multi_agent_context}
- Multi-Agent Threats: {', '.join(list_of_multi_agent_threats)}

Move Code to Analyze:
{function_body}

MULTI-AGENT SECURITY ANALYSIS:

1. SIGNER VALIDATION:
   - Verify all required signers are present
   - Check signer roles and permissions
   - Ensure proper signer authentication
   - Validate signer order and precedence
   
2. AUTHORIZATION LOGIC:
   - Check each signer authorizes their portion
   - Verify partial authorization prevention
   - Ensure atomic multi-signer operations
   - Validate authorization scope per signer
   
3. ROLE SEPARATION:
   - Verify clear signer role definitions
   - Check for role confusion vulnerabilities
   - Ensure proper privilege separation
   - Validate role-based access control
   
4. TRANSACTION ATOMICITY:
   - Check all-or-nothing execution
   - Verify rollback on any signer failure
   - Ensure consistent state across signers
   - Validate transaction ordering
   
5. REPLAY PROTECTION:
   - Verify sequence number usage per signer
   - Check transaction uniqueness
   - Ensure nonce or timestamp validation
   - Validate replay attack prevention
   
6. COORDINATION SAFETY:
   - Check for race conditions between signers
   - Verify timeout handling
   - Ensure proper error propagation
   - Validate signer agreement mechanisms

Provide findings with multi-agent specific attack vectors and safe multi-signer patterns.
"""
    return msg


async def move_resource_account_threats(
    function_explanation: Annotated[str, "Explanation of resource account usage for programmable on-chain accounts."],
    function_body: Annotated[str, "The complete Move function source code managing resource accounts."],
    file_path: Annotated[str, "Path to the Move file."],
    resource_account_context: Annotated[str, "Context about resource accounts: creation, management, signer delegation, and use cases (DAO, shared accounts, complex dapps)."],
    list_of_resource_account_threats: Annotated[list[str], "List of resource account threats: 'Unauthorized Signer Capability Use', 'Capability Leakage', 'Resource Account Hijacking', 'Signer Capability Duplication', 'Account Creation Exploits', 'Capability Transfer Vulnerabilities', etc."]
) -> str:
    """
    Analyze Move resource account security.
    
    Resource accounts are programmable accounts:
    - Created by modules
    - Signer capability stored in module
    - No private key exists
    - Useful for DAOs, shared accounts, and complex dapps
    """
    msg = f"""
MOVE RESOURCE ACCOUNT THREAT ANALYSIS

Function Context:
- Resource Account Operations: {function_explanation}
- File Location: {file_path}
- Resource Account Context: {resource_account_context}
- Resource Account Threats: {', '.join(list_of_resource_account_threats)}

Move Code to Analyze:
{function_body}

RESOURCE ACCOUNT SECURITY ANALYSIS:

1. SIGNER CAPABILITY MANAGEMENT:
   - Verify signer capability is securely stored
   - Check capability access is properly restricted
   - Ensure capability cannot be duplicated
   - Validate capability lifecycle management
   
2. ACCOUNT CREATION:
   - Verify deterministic address generation
   - Check seed uniqueness and security
   - Ensure proper capability initialization
   - Validate account creation authorization
   
3. CAPABILITY USAGE:
   - Check signer capability is used correctly
   - Verify operations require proper authorization
   - Ensure capability isn't exposed publicly
   - Validate capability delegation if applicable
   
4. ACCESS CONTROL:
   - Verify who can use the resource account
   - Check authorization logic for operations
   - Ensure proper governance mechanisms
   - Validate multi-sig requirements if applicable
   
5. CAPABILITY TRANSFER:
   - Check if capability transfer is necessary
   - Verify transfer authorization
   - Ensure atomic capability handoff
   - Validate new capability holder

Provide findings with resource account specific vulnerabilities and secure patterns.
"""
    return msg


