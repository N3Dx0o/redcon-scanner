from typing import Annotated


# ============================================================================
# SECTION 1: CORE SECURITY THREAT FUNCTIONS
# Fundamental security vulnerabilities that apply to most Solidity contracts
# ============================================================================

async def solidity_general_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solidity function does, its purpose in the smart contract, and its role in the application. Should include business logic context, state management, and any security-relevant behaviors specific to Solidity smart contracts."],
    function_body: Annotated[str, "The complete Solidity source code of the function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual Solidity code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/Token.sol', 'src/MyContract.sol', 'contracts/Staking.sol'). Used for context and reporting."], 
    list_of_solidity_threats: Annotated[list[str], "A comprehensive list of general Solidity security threats and vulnerabilities to check for during analysis. Each item should be a specific Solidity threat type (e.g., 'Reentrancy Attacks', 'Integer Overflow/Underflow', 'Access Control Issues', 'Unchecked External Calls', 'State Variable Manipulation', 'Function Visibility Issues', 'Constructor Issues', 'Selfdestruct Vulnerabilities', 'Delegatecall Vulnerabilities', 'Gas Limit Issues', 'Denial of Service', 'Timestamp Dependence', 'Block Number Dependence', 'Random Number Generation Issues', 'Front-running Vulnerabilities', 'MEV Attacks', 'Flash Loan Attacks', 'Oracle Manipulation', 'Price Manipulation', 'Token Standard Violations', etc.)."]
) -> str:
    """
    Generate an LLM-ready prompt to review a Solidity function against named threats.

    Parameters:
        function_explanation (str): Human description of behavior, state changes, and invariants.
        function_body (str): Exact Solidity source of the function; do not elide lines.
        file_path (str): Repo-relative path to the contract file.
        list_of_solidity_threats (list[str]): Specific checks (e.g., reentrancy, access control,
            authorization, unchecked external calls, integer math, timestamp/block deps, etc.).

    Output:
        str: Structured prompt asking the LLM to produce findings with severity, exploitability,
            concrete references, and actionable code-level fixes.

    LLM guidance:
        - Confirm effects ordering (checks-effects-interactions) and reentrancy guards.
        - Validate visibility, modifiers, access control, and role assumptions.
        - Verify overflow/underflow handling (solc version, SafeMath/checked ops).
        - Ensure external calls are handled safely and return values checked.

    Example:
        await solidity_general_threats(
            function_explanation="Transfer with fee and event emission",
            function_body="function transfer(address to, uint256 amount) public returns (bool) { ... }",
            file_path="contracts/Token.sol",
            list_of_solidity_threats=["Reentrancy", "Access control", "Unchecked calls", "Math correctness"]
        )
    """
    msg = f"""
SOLIDITY GENERAL THREAT ANALYSIS REQUEST

Function Context:
- Solidity Purpose: {function_explanation}
- File Location: {file_path}
- Solidity Threats to Evaluate: {', '.join(list_of_solidity_threats)}

Solidity Source Code to Analyze:
{function_body}

Please perform a comprehensive Solidity security analysis focusing on the specified threats and provide detailed findings with severity ratings and remediation guidance specific to Solidity security best practices.
"""

    return msg


# ============================================================================
# SECTION 2: CODE QUALITY & CORRECTNESS THREAT FUNCTIONS
# Functions for analyzing code quality, correctness, and logical issues
# ============================================================================

async def solidity_assembly_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solidity assembly function does, its purpose in low-level operations, and its role in the smart contract. Should include assembly operations, memory manipulation, and any security-relevant behaviors specific to Solidity inline assembly."],
    function_body: Annotated[str, "The complete Solidity source code with inline assembly including all statements, variable assignments, control flow, assembly operations, and any nested logic. This is the actual Solidity assembly code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/LowLevel.sol', 'src/AssemblyUtils.sol', 'contracts/OptimizedMath.sol'). Used for context and reporting."], 
    assembly_context: Annotated[str, "Additional assembly context including the assembly operations used (e.g., memory operations, storage operations, call operations), optimization goals, and critical low-level operations this function handles."],
    list_of_assembly_threats: Annotated[list[str], "A comprehensive list of Solidity assembly-specific threats and vulnerabilities to check for during analysis. Each item should be a specific assembly threat type (e.g., 'Memory Corruption', 'Storage Collision', 'Stack Overflow', 'Stack Underflow', 'Invalid Opcode', 'Gas Manipulation', 'Assembly Logic Errors', 'Memory Layout Issues', 'Storage Layout Issues', 'Call Stack Manipulation', 'Return Data Manipulation', 'Assembly Reentrancy', 'Assembly Access Control Bypass', 'Assembly Integer Overflow', 'Assembly Integer Underflow', 'Assembly Type Confusion', 'Assembly Memory Disclosure', 'Assembly Storage Disclosure', 'Assembly Call Injection', 'Assembly Return Value Manipulation', 'Assembly Gas Limit Bypass', 'Assembly Exception Handling', 'Assembly State Corruption', 'Assembly Control Flow Manipulation', etc.)."]
) -> str:
    """
    Build a prompt for low-level review of Solidity inline assembly blocks.

    Parameters:
        function_explanation (str): Purpose, expected memory/storage effects, and invariants.
        function_body (str): Full function code including the assembly block.
        file_path (str): Repo-relative source path.
        assembly_context (str): Memory layout assumptions, ABI expectations, optimizer settings.
        list_of_assembly_threats (list[str]): Specific low-level concerns to validate
            (memory corruption, storage collision, stack misuse, invalid opcodes, gas griefing).

    Output:
        str: Prompt that elicits precise findings, reproduction snippets, and concrete fixes.

    LLM guidance:
        - Validate mload/mstore offsets, alignment, and bounds.
        - Check storage slot calculations and collision risks.
        - Confirm call/return data handling and revert paths.
        - Ensure stack discipline and safe control flow.
    """
    msg = f"""
SOLIDITY ASSEMBLY THREAT ANALYSIS REQUEST

Function Context:
- Assembly Purpose: {function_explanation}
- File Location: {file_path}
- Assembly Context: {assembly_context}
- Assembly Threats to Evaluate: {', '.join(list_of_assembly_threats)}

Solidity Assembly Source Code to Analyze:
{function_body}

Please perform a comprehensive Solidity assembly security analysis focusing on the specified threats and provide detailed findings with assembly-specific attack vector analysis, potential low-level impact, and remediation guidance specific to Solidity assembly vulnerabilities and secure low-level programming practices.
"""

    return msg


async def solidity_logical_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solidity function does, its purpose in business logic, and its role in the smart contract. Should include business rules, state transitions, and any logical security behaviors specific to Solidity smart contracts."],
    function_body: Annotated[str, "The complete Solidity source code of the function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual Solidity code that will be analyzed for logical vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/Token.sol', 'src/Staking.sol', 'contracts/Governance.sol'). Used for context and reporting."], 
    logical_context: Annotated[str, "Additional logical context including the business domain (e.g., DeFi, NFT, governance, staking), business rules, state management, and critical logical operations this function handles."],
    list_of_logical_threats: Annotated[list[str], "A comprehensive list of Solidity logical threats and vulnerabilities to check for during analysis. Each item should be a specific logical threat type (e.g., 'Business Logic Flaws', 'State Transition Errors', 'Access Control Logic Errors', 'Permission Escalation', 'Business Rule Bypass', 'State Corruption', 'Logic Race Conditions', 'Business Process Manipulation', 'Financial Logic Errors', 'Governance Logic Flaws', 'Staking Logic Errors', 'Token Logic Flaws', 'Auction Logic Errors', 'Voting Logic Flaws', 'Reward Distribution Errors', 'Liquidation Logic Errors', 'Interest Calculation Errors', 'Fee Calculation Errors', 'Balance Update Errors', 'Event Emission Errors', 'State Validation Errors', 'Business Constraint Violations', 'Workflow Manipulation', 'Business Process Bypass', 'Financial Manipulation', 'Governance Manipulation', etc.)."]
) -> str:
    """
    Construct a business-logic review prompt for a Solidity function.

    Parameters:
        function_explanation (str): Intended workflow, pre/post-conditions, and invariants.
        function_body (str): Exact function body under review.
        file_path (str): Repo-relative path.
        logical_context (str): Protocol/domain context (DeFi, NFT, governance), key rules, constraints.
        list_of_logical_threats (list[str]): Targeted logic checks (authorization, state transitions,
            economic correctness, rounding, race conditions, and event/data consistency).

    Output:
        str: Prompt instructing the LLM to examine logic flaws with examples and fixes.

    LLM guidance:
        - Validate authorization flow and role assumptions.
        - Check state transition completeness and failure modes.
        - Confirm economic/arithmetical correctness and rounding safety.
        - Ensure events and storage reflect actual state.
    """
    msg = f"""
SOLIDITY LOGICAL THREAT ANALYSIS REQUEST

Function Context:
- Logical Purpose: {function_explanation}
- File Location: {file_path}
- Logical Context: {logical_context}
- Logical Threats to Evaluate: {', '.join(list_of_logical_threats)}

Solidity Logical Source Code to Analyze:
{function_body}

Please perform a comprehensive Solidity logical security analysis focusing on the specified threats and provide detailed findings with logical attack vector analysis, potential business impact, and remediation guidance specific to Solidity logical vulnerabilities and secure business logic practices.
"""

    return msg


# ============================================================================
# SECTION 3: CRITICAL SECURITY VULNERABILITIES
# High-severity security issues: reentrancy, access control, gas DoS, etc.
# ============================================================================

async def solidity_reentrancy_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solidity function does, its purpose in the smart contract, and its role in the application. Should include external calls, state changes, and any reentrancy-relevant behaviors."],
    function_body: Annotated[str, "The complete Solidity source code of the function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual Solidity code that will be analyzed for reentrancy vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/Vault.sol', 'src/Withdraw.sol', 'contracts/Payment.sol'). Used for context and reporting."], 
    reentrancy_context: Annotated[str, "Additional reentrancy context including external call patterns, state update ordering, reentrancy guard usage, checks-effects-interactions pattern compliance, and critical state variables that could be manipulated during reentrancy."],
    list_of_reentrancy_threats: Annotated[list[str], "A comprehensive list of reentrancy-specific threats and vulnerabilities to check for during analysis. Each item should be a specific reentrancy threat type (e.g., 'Single-Function Reentrancy', 'Cross-Function Reentrancy', 'Cross-Contract Reentrancy', 'Read-Only Reentrancy', 'Storage-Based Reentrancy', 'ETH Transfer Reentrancy', 'ERC20 Transfer Reentrancy', 'Callback Reentrancy', 'Delegatecall Reentrancy', 'Missing Reentrancy Guard', 'Incorrect Guard Placement', 'State Update Order Violations', 'Checks-Effects-Interactions Violations', 'External Call Before State Update', 'State Variable Manipulation During Reentrancy', 'Balance Manipulation Reentrancy', 'Allowance Manipulation Reentrancy', 'Event Emission Reentrancy', 'Gas Griefing Reentrancy', etc.)."]
) -> str:
    """
    Create a reentrancy-focused security review prompt for Solidity functions with external calls.
    This is one of the most critical and common vulnerabilities in smart contracts.

    Parameters:
        function_explanation (str): Intended behavior, external calls, and state management.
        function_body (str): Exact function code with external calls.
        file_path (str): Repo-relative path.
        reentrancy_context (str): External call patterns, state update ordering, guard usage, CEI compliance.
        list_of_reentrancy_threats (list[str]): Threats like single/cross-function reentrancy, read-only reentrancy,
            storage-based reentrancy, missing guards, CEI violations, and state manipulation.

    Output:
        str: Prompt instructing LLM to identify all reentrancy vectors with focus on checks-effects-interactions pattern.
    """
    msg = f"""
SOLIDITY REENTRANCY THREAT ANALYSIS REQUEST

Function Context:
- Reentrancy Purpose: {function_explanation}
- File Location: {file_path}
- Reentrancy Context: {reentrancy_context}
- Reentrancy Threats to Evaluate: {', '.join(list_of_reentrancy_threats)}

Solidity Reentrancy Source Code to Analyze:
{function_body}

Please perform a comprehensive Solidity reentrancy security analysis focusing on the specified reentrancy threats. Pay special attention to:
1. Checks-Effects-Interactions (CEI) pattern compliance
2. External call ordering relative to state updates
3. Reentrancy guard placement and effectiveness
4. Cross-function and cross-contract reentrancy vectors
5. Read-only reentrancy through view functions
6. State variable manipulation during external calls
7. Reentrancy in repay functions (e.g., repayETH) allowing repeated repayments
8. Reentrancy through callback functions and hooks
9. Missing reentrancy guards in critical state-changing functions

Provide detailed findings with reentrancy-specific attack vector analysis, potential fund loss scenarios, and remediation guidance specific to reentrancy vulnerabilities and secure external call handling practices.
"""

    return msg


async def solidity_crypto_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solidity cryptographic function does, its purpose in cryptographic operations, and its role in the smart contract. Should include cryptographic operations, hash functions, signature verification, encryption, and any crypto-specific security behaviors."],
    function_body: Annotated[str, "The complete Solidity source code of the cryptographic function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual Solidity code that will be analyzed for cryptographic vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/CryptoUtils.sol', 'contracts/SignatureVerifier.sol', 'contracts/HashFunction.sol'). Used for context and reporting."], 
    crypto_context: Annotated[str, "Additional cryptographic context including the cryptographic operations used (e.g., ECDSA, RSA, hash functions, encryption schemes), cryptographic primitives, key management, and critical cryptographic operations this function handles."],
    list_of_crypto_threats: Annotated[list[str], "A comprehensive list of cryptographic threats and vulnerabilities to check for during analysis. Each item should be a specific cryptographic threat type (e.g., 'Weak Cryptographic Algorithms', 'Insecure Random Number Generation', 'Key Management Vulnerabilities', 'Signature Verification Bypass', 'Hash Collision Attacks', 'Timing Attacks', 'Side-Channel Attacks', 'Nonce Reuse', 'ECDSA Nonce Reuse', 'Signature Malleability', 'Weak Hash Functions', 'Insecure Key Derivation', 'Key Exposure', 'Cryptographic Protocol Vulnerabilities', 'Encryption Implementation Flaws', 'Decryption Vulnerabilities', 'Cryptographic Constant-Time Violations', 'Weak Entropy Sources', 'Predictable Randomness', 'Cryptographic Library Vulnerabilities', etc.)."]
) -> str:
    """
    Create a cryptographic security review prompt for Solidity code implementing crypto operations.

    Parameters:
        function_explanation (str): Intended cryptographic behavior, algorithms used, and security assumptions.
        function_body (str): Exact cryptographic function code.
        file_path (str): Repo-relative path.
        crypto_context (str): Algorithms, key sizes, entropy sources, constant-time requirements, library choices.
        list_of_crypto_threats (list[str]): Threats like weak algorithms, nonce reuse, key exposure,
            timing attacks, signature malleability, and implementation flaws.

    Output:
        str: Prompt instructing LLM to validate cryptographic correctness and resistance to known attacks.
    """
    msg = f"""
SOLIDITY CRYPTOGRAPHIC THREAT ANALYSIS REQUEST

Function Context:
- Cryptographic Purpose: {function_explanation}
- File Location: {file_path}
- Cryptographic Context: {crypto_context}
- Cryptographic Threats to Evaluate: {', '.join(list_of_crypto_threats)}

Solidity Cryptographic Source Code to Analyze:
{function_body}

Please perform a comprehensive Solidity cryptographic security analysis focusing on the specified cryptographic threats and provide detailed findings with cryptographic attack vector analysis, potential security impact, and remediation guidance specific to cryptographic vulnerabilities and cryptographic security best practices.
"""

    return msg


async def solidity_correctness_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solidity function does, its purpose in ensuring correctness, and its role in the smart contract. Should include correctness requirements, invariants, preconditions, postconditions, and any correctness-specific behaviors."],
    function_body: Annotated[str, "The complete Solidity source code of the function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual Solidity code that will be analyzed for correctness issues."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/Math.sol', 'contracts/StateMachine.sol', 'contracts/Validator.sol'). Used for context and reporting."], 
    correctness_context: Annotated[str, "Additional correctness context including the correctness requirements (e.g., mathematical correctness, state machine correctness, protocol correctness), invariants, preconditions, postconditions, and critical correctness properties this function must maintain."],
    list_of_correctness_threats: Annotated[list[str], "A comprehensive list of correctness threats and vulnerabilities to check for during analysis. Each item should be a specific correctness threat type (e.g., 'Mathematical Errors', 'Integer Overflow/Underflow', 'Precision Loss', 'Rounding Errors', 'State Machine Violations', 'Invariant Violations', 'Precondition Violations', 'Postcondition Violations', 'Logic Errors', 'Control Flow Errors', 'State Transition Errors', 'Boundary Condition Errors', 'Edge Case Handling', 'Null Pointer Issues', 'Array Bounds Violations', 'Type Conversion Errors', 'Data Consistency Issues', 'Race Conditions', 'Concurrency Errors', 'Synchronization Issues', etc.)."]
) -> str:
    """
    Build a correctness-focused review prompt for Solidity functions requiring mathematical/logical precision.

    Parameters:
        function_explanation (str): Intended behavior, invariants, and correctness guarantees.
        function_body (str): Exact function implementation.
        file_path (str): Repo-relative path.
        correctness_context (str): Required invariants, pre/post-conditions, mathematical properties, state machine rules.
        list_of_correctness_threats (list[str]): Threats like math errors, overflow, precision loss,
            invariant violations, state machine bugs, and edge case failures.

    Output:
        str: Prompt targeting functional correctness with emphasis on mathematical and logical precision.
    """
    msg = f"""
SOLIDITY CORRECTNESS THREAT ANALYSIS REQUEST

Function Context:
- Correctness Purpose: {function_explanation}
- File Location: {file_path}
- Correctness Context: {correctness_context}
- Correctness Threats to Evaluate: {', '.join(list_of_correctness_threats)}

Solidity Correctness Source Code to Analyze:
{function_body}

Please perform a comprehensive Solidity correctness analysis focusing on the specified correctness threats and provide detailed findings with correctness issue analysis, potential functional impact, and remediation guidance specific to correctness vulnerabilities and correctness best practices.
"""

    return msg


async def solidity_funds_loss_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solidity function does, its purpose in fund management, and its role in the smart contract. Should include fund operations, transfers, withdrawals, deposits, and any fund-related security behaviors."],
    function_body: Annotated[str, "The complete Solidity source code of the function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual Solidity code that will be analyzed for fund loss vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/Vault.sol', 'contracts/Treasury.sol', 'contracts/Escrow.sol'). Used for context and reporting."], 
    funds_context: Annotated[str, "Additional funds context including the fund management type (e.g., vault, treasury, escrow, payment contract), fund sources, fund destinations, fund locking mechanisms, and critical fund operations this function handles."],
    list_of_funds_loss_threats: Annotated[list[str], "A comprehensive list of fund loss threats and vulnerabilities to check for during analysis. Each item should be a specific fund loss threat type (e.g., 'Unauthorized Withdrawals', 'Reentrancy Fund Drain', 'Integer Overflow Fund Loss', 'Access Control Bypass', 'Treasury Drain', 'Vault Exploitation', 'Escrow Manipulation', 'Fund Lock Bypass', 'Withdrawal Race Conditions', 'Balance Manipulation', 'Fund Accounting Errors', 'Transfer Logic Flaws', 'Fee Calculation Errors', 'Refund Vulnerabilities', 'Deposit Vulnerabilities', 'Withdrawal Vulnerabilities', 'Fund Lock Vulnerabilities', 'Multi-Sig Fund Drain', 'Emergency Withdrawal Vulnerabilities', 'Fund Recovery Vulnerabilities', etc.)."]
) -> str:
    """
    Create a fund loss prevention review prompt for Solidity functions handling value transfers.

    Parameters:
        function_explanation (str): Intended fund flow, authorization, and safety mechanisms.
        function_body (str): Exact function code handling funds.
        file_path (str): Repo-relative path.
        funds_context (str): Fund type, sources, destinations, locking mechanisms, emergency procedures.
        list_of_funds_loss_threats (list[str]): Threats like unauthorized withdrawals, reentrancy drains,
            accounting errors, access control bypass, and fund lock manipulation.

    Output:
        str: Prompt instructing LLM to identify all vectors that could lead to permanent fund loss.
    """
    msg = f"""
SOLIDITY FUNDS LOSS THREAT ANALYSIS REQUEST

Function Context:
- Funds Purpose: {function_explanation}
- File Location: {file_path}
- Funds Context: {funds_context}
- Funds Loss Threats to Evaluate: {', '.join(list_of_funds_loss_threats)}

Solidity Funds Source Code to Analyze:
{function_body}

Please perform a comprehensive Solidity funds loss security analysis focusing on the specified fund loss threats and provide detailed findings with fund loss attack vector analysis, potential financial impact, and remediation guidance specific to fund loss vulnerabilities and fund security best practices. Pay special attention to scenarios that could result in permanent or irreversible loss of funds.
"""

    return msg


async def solidity_upgrade_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solidity upgrade function does, its purpose in contract upgrades, and its role in the upgradeable contract. Should include upgrade mechanisms, proxy patterns, storage layout, and any upgrade-specific security behaviors."],
    function_body: Annotated[str, "The complete Solidity source code of the upgrade function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual Solidity code that will be analyzed for upgrade vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/UpgradeableContract.sol', 'contracts/Proxy.sol', 'contracts/Implementation.sol'). Used for context and reporting."], 
    upgrade_context: Annotated[str, "Additional upgrade context including the upgrade pattern (e.g., Transparent Proxy, UUPS, Beacon Proxy), storage layout, upgrade authorization, and critical upgrade operations this function handles."],
    list_of_upgrade_threats: Annotated[list[str], "A comprehensive list of upgrade-specific threats and vulnerabilities to check for during analysis. Each item should be a specific upgrade threat type (e.g., 'Storage Collision', 'Function Selector Clashing', 'Initialization Vulnerabilities', 'Upgrade Authorization Bypass', 'Storage Layout Violations', 'Proxy Implementation Mismatch', 'Delegatecall Vulnerabilities', 'Upgrade Race Conditions', 'Storage Corruption', 'Implementation Contract Vulnerabilities', 'Proxy Admin Vulnerabilities', 'Upgrade Function Visibility', 'Storage Slot Collision', 'Upgrade Function Selector Collision', 'Initialization Function Vulnerabilities', 'Upgrade Governance Vulnerabilities', 'Storage Variable Reordering', 'Upgrade Backdoor Vulnerabilities', etc.)."]
) -> str:
    """
    Build an upgradeable contract security review prompt for Solidity proxy/upgrade patterns.

    Parameters:
        function_explanation (str): Intended upgrade behavior, proxy pattern, and storage layout.
        function_body (str): Exact upgrade function implementation.
        file_path (str): Repo-relative path.
        upgrade_context (str): Proxy pattern, storage layout, upgrade authorization, initialization.
        list_of_upgrade_threats (list[str]): Threats like storage collision, selector clashing,
            initialization vulnerabilities, and upgrade authorization bypass.

    Output:
        str: Prompt targeting upgrade safety with focus on storage layout and proxy pattern correctness.
    """
    msg = f"""
SOLIDITY UPGRADE THREAT ANALYSIS REQUEST

Function Context:
- Upgrade Purpose: {function_explanation}
- File Location: {file_path}
- Upgrade Context: {upgrade_context}
- Upgrade Threats to Evaluate: {', '.join(list_of_upgrade_threats)}

Solidity Upgrade Source Code to Analyze:
{function_body}

Please perform a comprehensive Solidity upgrade security analysis focusing on the specified upgrade threats and provide detailed findings with upgrade-specific attack vector analysis, potential contract compromise impact, and remediation guidance specific to upgrade vulnerabilities and upgradeable contract security best practices.
"""

    return msg


# ============================================================================
# SECTION 4: ORACLE & EXTERNAL DATA THREAT FUNCTIONS
# Functions for analyzing oracle integrations and external data dependencies
# ============================================================================

async def solidity_oracle_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solidity oracle function does, its purpose in oracle operations, and its role in the smart contract. Should include oracle data fetching, price feeds, external data integration, API versions, and any oracle-specific security behaviors."],
    function_body: Annotated[str, "The complete Solidity source code of the oracle function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual Solidity code that will be analyzed for oracle vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/Oracle.sol', 'contracts/PriceFeed.sol', 'contracts/ChainlinkIntegration.sol'). Used for context and reporting."], 
    oracle_context: Annotated[str, "Additional oracle context including the oracle type (e.g., Chainlink, Band Protocol, custom oracle), data sources, update mechanisms, staleness handling, API versions used, deprecated functions (e.g., latestAnswer), and critical oracle operations this function handles."],
    list_of_oracle_threats: Annotated[list[str], "A comprehensive list of oracle-specific threats and vulnerabilities to check for during analysis. Each item should be a specific oracle threat type (e.g., 'Oracle Price Manipulation', 'Stale Price Data', 'Oracle Downtime', 'Single Point of Failure', 'Oracle Front-running', 'Price Feed Manipulation', 'Oracle Data Source Compromise', 'Flash Loan Oracle Manipulation', 'Oracle Update Delay', 'Oracle Rounding Errors', 'Oracle Access Control', 'Oracle Data Validation', 'Oracle Reentrancy', 'Oracle Gas Limit Issues', 'Oracle Network Issues', 'Oracle Centralization Risks', 'Oracle Data Freshness', 'Oracle Price Deviation', 'Oracle Circuit Breaker Bypass', 'Deprecated latestAnswer Usage', 'Outdated Oracle API', 'Missing Round Data Validation', 'Stale Round Data', 'Deprecated Function Calls', 'Oracle Version Compatibility Issues', 'Missing Round ID Validation', 'Deprecated Price Feed Methods', 'Oracle Upgrade Path Issues', 'Missing Timestamp Validation', 'Deprecated Chainlink Functions', 'Oracle API Migration Needed', 'Missing Round Completeness Check', etc.)."]
) -> str:
    """
    Create a comprehensive oracle security review prompt for Solidity functions consuming external price/data feeds.
    Includes both general oracle threats and deprecation issues.

    Parameters:
        function_explanation (str): Intended oracle behavior, data sources, staleness handling, and API usage.
        function_body (str): Exact oracle function code.
        file_path (str): Repo-relative path.
        oracle_context (str): Oracle type, data sources, update frequency, staleness thresholds, circuit breakers, API versions, deprecated functions.
        list_of_oracle_threats (list[str]): Threats like price manipulation, stale data, downtime, front-running,
            flash loan attacks, centralization risks, deprecated API usage, and compatibility issues.

    Output:
        str: Prompt instructing LLM to validate oracle security, manipulation resistance, and future-proof integration.
    """
    msg = f"""
SOLIDITY ORACLE THREAT ANALYSIS REQUEST

Function Context:
- Oracle Purpose: {function_explanation}
- File Location: {file_path}
- Oracle Context: {oracle_context}
- Oracle Threats to Evaluate: {', '.join(list_of_oracle_threats)}

Solidity Oracle Source Code to Analyze:
{function_body}

Please perform a comprehensive Solidity oracle security analysis focusing on the specified oracle threats. Pay special attention to:
1. Oracle price manipulation and flash loan attacks
2. Stale price data and oracle downtime issues
3. Oracle centralization and single point of failure risks
4. Use of deprecated oracle functions (e.g., Chainlink's latestAnswer)
5. Missing round data validation and staleness checks
6. Outdated oracle API versions and compatibility issues
7. Missing timestamp and round ID validation
8. Deprecated price feed access patterns and upgrade paths

Provide detailed findings with oracle-specific attack vector analysis, potential price manipulation impact, future breakage scenarios, and remediation guidance specific to oracle vulnerabilities, oracle deprecation issues, and modern oracle integration best practices.
"""

    return msg


async def solidity_defi_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solidity function does, its purpose in the DeFi protocol, and its role in the smart contract. Should include DeFi business logic context, token operations, financial calculations, and any security-relevant behaviors specific to DeFi applications."],
    function_body: Annotated[str, "The complete Solidity source code of the function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual Solidity code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/Token.sol', 'src/UniswapV2Pair.sol', 'contracts/Staking.sol'). Used for context and reporting."], 
    defi_context: Annotated[str, "Additional DeFi context including the protocol type (e.g., AMM, lending, governance, staking), token economics, financial mechanisms, and critical DeFi operations this function handles."],
    list_of_defi_threats: Annotated[list[str], "A comprehensive list of DeFi-specific security threats and vulnerabilities to check for during analysis. Each item should be a specific DeFi threat type (e.g., 'Liquidity Pool Exploits', 'Price Manipulation', 'Front-running Vulnerabilities', 'MEV Attacks', 'Flash Loan Attacks', 'Arbitrage Vulnerabilities', 'Liquidity Drain Attacks', 'Impermanent Loss', 'Slippage Vulnerabilities', 'Oracle Price Manipulation', 'Sandwich Attacks', 'JIT Liquidity Attacks', 'Liquidation Vulnerabilities', 'Collateral Manipulation', 'Interest Rate Manipulation', 'Governance Attacks', 'Vote Manipulation', 'Treasury Drain Attacks', 'Token Standard Violations', 'Token Supply Manipulation', 'Balance Manipulation', etc.)."]
) -> str:
    """
    Create a DeFi-focused analysis prompt for an LLM reviewing Solidity code.

    Parameters:
        function_explanation (str): Protocol behavior and intended financial invariants.
        function_body (str): Exact function code.
        file_path (str): Repo-relative path.
        defi_context (str): AMM/lending/governance specifics, oracle design, fee model, slippage limits.
        list_of_defi_threats (list[str]): Threats like price/oracle manipulation, sandwiching/MEV,
            flash loans, liquidity drain, liquidation edge cases, rounding/precision.

    Output:
        str: Prompt instructing LLM to reason about adversarial market conditions and protocol safety.
    """
    msg = f"""
SOLIDITY DEFI THREAT ANALYSIS REQUEST

Function Context:
- DeFi Purpose: {function_explanation}
- File Location: {file_path}
- DeFi Context: {defi_context}
- DeFi Threats to Evaluate: {', '.join(list_of_defi_threats)}

Solidity DeFi Source Code to Analyze:
{function_body}

Please perform a comprehensive Solidity DeFi security analysis focusing on the specified DeFi threats and provide detailed findings with DeFi-specific attack vector analysis, potential financial impact, and remediation guidance specific to DeFi vulnerabilities and DeFi security best practices.
"""

    return msg


async def solidity_token_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solidity token function does, its purpose in token operations, and its role in the token contract. Should include token transfers, approvals, minting, burning, and any token-specific security behaviors."],
    function_body: Annotated[str, "The complete Solidity source code of the token function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual Solidity code that will be analyzed for token vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/ERC20.sol', 'contracts/ERC721.sol', 'contracts/Token.sol'). Used for context and reporting."], 
    token_context: Annotated[str, "Additional token context including the token standard (e.g., ERC-20, ERC-721, ERC-1155), token type (e.g., utility, governance, staking), token supply model, and critical token operations this function handles."],
    list_of_token_threats: Annotated[list[str], "A comprehensive list of token-specific threats and vulnerabilities to check for during analysis. Each item should be a specific token threat type (e.g., 'Token Standard Violations', 'Transfer Function Vulnerabilities', 'Approval Vulnerabilities', 'Minting Vulnerabilities', 'Burning Vulnerabilities', 'Token Supply Manipulation', 'Balance Manipulation', 'Allowance Vulnerabilities', 'Token Metadata Issues', 'Token URI Vulnerabilities', 'Token Ownership Issues', 'Token Access Control', 'Token Upgrade Vulnerabilities', 'Token Pause Vulnerabilities', 'Token Blacklist Issues', 'Token Fee Manipulation', 'Token Tax Vulnerabilities', 'Token Lock Vulnerabilities', 'Token Vesting Issues', 'Token Distribution Vulnerabilities', etc.)."]
) -> str:
    """
    Build a token-standard-centric review prompt for ERC-20/721/1155 functions.

    Parameters:
        function_explanation (str): Intended token semantics and constraints.
        function_body (str): Exact function implementation.
        file_path (str): Repo-relative path.
        token_context (str): Standard/version, hooks, metadata rules, allowance/approval semantics.
        list_of_token_threats (list[str]): Standard compliance, approval/allowance pitfalls,
            supply/decimals math, metadata/URI integrity, pause/upgrade safety.

    Output:
        str: Prompt targeting correctness, compliance, and abuse-resistance with concrete fixes.
    """
    msg = f"""
SOLIDITY TOKEN THREAT ANALYSIS REQUEST

Function Context:
- Token Purpose: {function_explanation}
- File Location: {file_path}
- Token Context: {token_context}
- Token Threats to Evaluate: {', '.join(list_of_token_threats)}

Solidity Token Source Code to Analyze:
{function_body}

Please perform a comprehensive Solidity token security analysis focusing on the specified token threats and provide detailed findings with token-specific attack vector analysis, potential token security impact, and remediation guidance specific to token vulnerabilities and token security best practices.
"""

    return msg


async def solidity_access_control_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solidity function does, its purpose in access control, and its role in the smart contract. Should include authorization checks, role management, permission systems, and any access control behaviors."],
    function_body: Annotated[str, "The complete Solidity source code of the function including all statements, variable assignments, control flow, function calls, modifiers, and any nested logic. This is the actual Solidity code that will be analyzed for access control vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/Admin.sol', 'src/AccessControl.sol', 'contracts/Ownable.sol'). Used for context and reporting."], 
    access_control_context: Annotated[str, "Additional access control context including the access control pattern (e.g., Ownable, Role-Based Access Control, Multi-Sig, Permission System), role definitions, permission levels, and critical access control operations this function handles."],
    list_of_access_control_threats: Annotated[list[str], "A comprehensive list of access control-specific threats and vulnerabilities to check for during analysis. Each item should be a specific access control threat type (e.g., 'Missing Access Control', 'Incorrect Modifier Usage', 'Role Bypass Vulnerabilities', 'Permission Escalation', 'Missing OnlyOwner', 'Missing OnlyRole', 'Public Function Without Access Control', 'External Function Without Access Control', 'Inheritance Access Control Bypass', 'Interface Access Control Bypass', 'Delegatecall Access Control Bypass', 'Proxy Access Control Bypass', 'Initialization Access Control', 'Upgrade Access Control', 'Emergency Function Access Control', 'Admin Function Access Control', 'Multi-Sig Bypass', 'Role Assignment Vulnerabilities', 'Role Revocation Vulnerabilities', 'Centralization Risks', etc.)."]
) -> str:
    """
    Build an access control security review prompt for Solidity functions handling authorization.

    Parameters:
        function_explanation (str): Intended access control behavior, roles, and permissions.
        function_body (str): Exact function code with access control checks.
        file_path (str): Repo-relative path.
        access_control_context (str): Access control pattern, roles, permissions, inheritance structure.
        list_of_access_control_threats (list[str]): Threats like missing checks, role bypass, permission escalation,
            modifier misuse, inheritance issues, and centralization risks.

    Output:
        str: Prompt targeting access control correctness with focus on authorization safety.
    """
    msg = f"""
SOLIDITY ACCESS CONTROL THREAT ANALYSIS REQUEST

Function Context:
- Access Control Purpose: {function_explanation}
- File Location: {file_path}
- Access Control Context: {access_control_context}
- Access Control Threats to Evaluate: {', '.join(list_of_access_control_threats)}

Solidity Access Control Source Code to Analyze:
{function_body}

Please perform a comprehensive Solidity access control security analysis focusing on the specified access control threats. Pay special attention to:
1. Missing or incorrect access control modifiers
2. Public/external functions without proper authorization
3. Role-based access control bypass vectors
4. Permission escalation vulnerabilities
5. Inheritance and interface access control issues
6. Centralization and single point of failure risks

Provide detailed findings with access control-specific attack vector analysis, potential unauthorized access scenarios, and remediation guidance specific to access control vulnerabilities and secure authorization practices.
"""

    return msg


async def solidity_gas_dos_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solidity function does, its purpose in gas consumption, and its role in the smart contract. Should include gas optimization, loop operations, storage operations, and any gas-related behaviors."],
    function_body: Annotated[str, "The complete Solidity source code of the function including all statements, variable assignments, control flow, loops, storage operations, and any nested logic. This is the actual Solidity code that will be analyzed for gas and denial-of-service vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/Batch.sol', 'src/Iteration.sol', 'contracts/Array.sol'). Used for context and reporting."], 
    gas_dos_context: Annotated[str, "Additional gas and DoS context including loop patterns, array operations, storage access patterns, unbounded operations, and critical gas-consuming operations this function handles."],
    list_of_gas_dos_threats: Annotated[list[str], "A comprehensive list of gas and DoS-specific threats and vulnerabilities to check for during analysis. Each item should be a specific gas/DoS threat type (e.g., 'Unbounded Loops', 'Gas Limit DoS', 'Array Length Manipulation', 'Storage Gas DoS', 'External Call Gas DoS', 'Loop Gas Consumption', 'Unbounded Iteration', 'Storage Slot DoS', 'Mapping Iteration DoS', 'Array Push DoS', 'String Concatenation DoS', 'Complex Computation DoS', 'Recursive Call DoS', 'Delegatecall Gas DoS', 'Low-Level Call Gas DoS', 'Event Emission Gas DoS', 'Log Data Gas DoS', 'Contract Creation Gas DoS', 'Selfdestruct Gas DoS', 'Gas Griefing Attacks', etc.)."]
) -> str:
    """
    Create a gas optimization and denial-of-service review prompt for Solidity functions.

    Parameters:
        function_explanation (str): Intended behavior, loops, and gas consumption patterns.
        function_body (str): Exact function code with potential gas issues.
        file_path (str): Repo-relative path.
        gas_dos_context (str): Loop patterns, array operations, storage access, unbounded operations.
        list_of_gas_dos_threats (list[str]): Threats like unbounded loops, gas limit DoS, array manipulation,
            storage DoS, and gas griefing attacks.

    Output:
        str: Prompt instructing LLM to identify gas optimization issues and DoS vectors.
    """
    msg = f"""
SOLIDITY GAS AND DENIAL-OF-SERVICE THREAT ANALYSIS REQUEST

Function Context:
- Gas/DoS Purpose: {function_explanation}
- File Location: {file_path}
- Gas/DoS Context: {gas_dos_context}
- Gas/DoS Threats to Evaluate: {', '.join(list_of_gas_dos_threats)}

Solidity Gas/DoS Source Code to Analyze:
{function_body}

Please perform a comprehensive Solidity gas and denial-of-service security analysis focusing on the specified gas/DoS threats. Pay special attention to:
1. Unbounded loops and iterations that could exceed gas limits
2. Array length manipulation leading to DoS
3. Storage operations causing excessive gas consumption
4. External calls that could fail due to gas limits
5. Gas griefing attacks through complex operations
6. Optimization opportunities for gas efficiency

Provide detailed findings with gas/DoS-specific attack vector analysis, potential transaction failure scenarios, and remediation guidance specific to gas optimization and denial-of-service vulnerabilities.
"""

    return msg


async def solidity_frontrunning_mev_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solidity function does, its purpose in transaction ordering, and its role in the smart contract. Should include transaction ordering, MEV opportunities, front-running vectors, and any ordering-dependent behaviors."],
    function_body: Annotated[str, "The complete Solidity source code of the function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual Solidity code that will be analyzed for front-running and MEV vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/Auction.sol', 'src/PriceOracle.sol', 'contracts/Trading.sol'). Used for context and reporting."], 
    frontrunning_mev_context: Annotated[str, "Additional front-running and MEV context including transaction ordering dependencies, price discovery mechanisms, auction patterns, and critical operations vulnerable to front-running or MEV extraction."],
    list_of_frontrunning_mev_threats: Annotated[list[str], "A comprehensive list of front-running and MEV-specific threats and vulnerabilities to check for during analysis. Each item should be a specific front-running/MEV threat type (e.g., 'Transaction Ordering Dependence', 'Front-Running Vulnerabilities', 'Sandwich Attacks', 'Back-Running Attacks', 'MEV Extraction', 'Priority Gas Auction Exploitation', 'Arbitrage Opportunities', 'Price Manipulation Through Front-Running', 'Auction Front-Running', 'Liquidation Front-Running', 'Slippage Exploitation', 'Price Oracle Front-Running', 'Flash Loan Front-Running', 'Governance Front-Running', 'Vote Front-Running', 'Reward Front-Running', 'Withdrawal Front-Running', 'Deposit Front-Running', 'Commit-Reveal Scheme Vulnerabilities', 'Time-Based Front-Running', etc.)."]
) -> str:
    """
    Build a front-running and MEV security review prompt for Solidity functions vulnerable to transaction ordering.

    Parameters:
        function_explanation (str): Intended behavior, transaction ordering dependencies, and MEV exposure.
        function_body (str): Exact function code vulnerable to front-running.
        file_path (str): Repo-relative path.
        frontrunning_mev_context (str): Transaction ordering dependencies, price discovery, auction patterns, MEV vectors.
        list_of_frontrunning_mev_threats (list[str]): Threats like front-running, sandwich attacks, MEV extraction,
            transaction ordering dependence, and arbitrage exploitation.

    Output:
        str: Prompt targeting front-running and MEV resistance with focus on transaction ordering safety.
    """
    msg = f"""
SOLIDITY FRONT-RUNNING AND MEV THREAT ANALYSIS REQUEST

Function Context:
- Front-Running/MEV Purpose: {function_explanation}
- File Location: {file_path}
- Front-Running/MEV Context: {frontrunning_mev_context}
- Front-Running/MEV Threats to Evaluate: {', '.join(list_of_frontrunning_mev_threats)}

Solidity Front-Running/MEV Source Code to Analyze:
{function_body}

Please perform a comprehensive Solidity front-running and MEV security analysis focusing on the specified front-running/MEV threats. Pay special attention to:
1. Transaction ordering dependencies that enable front-running
2. Price discovery mechanisms vulnerable to manipulation
3. Sandwich attack vectors (front-run and back-run)
4. MEV extraction opportunities
5. Commit-reveal scheme effectiveness
6. Time-based vulnerabilities enabling front-running

Provide detailed findings with front-running/MEV-specific attack vector analysis, potential value extraction scenarios, and remediation guidance specific to front-running vulnerabilities and MEV-resistant design patterns.
"""

    return msg


async def solidity_flash_loan_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solidity function does, its purpose in handling flash loans, and its role in the smart contract. Should include flash loan interactions, price calculations, liquidity checks, and any flash loan-related behaviors."],
    function_body: Annotated[str, "The complete Solidity source code of the function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual Solidity code that will be analyzed for flash loan vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/Lending.sol', 'src/FlashLoan.sol', 'contracts/PriceOracle.sol'). Used for context and reporting."], 
    flash_loan_context: Annotated[str, "Additional flash loan context including flash loan integration, price oracle usage, liquidity checks, and critical operations vulnerable to flash loan manipulation."],
    list_of_flash_loan_threats: Annotated[list[str], "A comprehensive list of flash loan-specific threats and vulnerabilities to check for during analysis. Each item should be a specific flash loan threat type (e.g., 'Flash Loan Price Manipulation', 'Oracle Manipulation via Flash Loan', 'Liquidity Pool Manipulation', 'Collateral Manipulation', 'Price Oracle Flash Loan Attack', 'AMM Price Manipulation', 'Lending Protocol Flash Loan Attack', 'Governance Flash Loan Attack', 'Vote Manipulation via Flash Loan', 'Liquidation Flash Loan Attack', 'Arbitrage Flash Loan Attack', 'Reentrancy via Flash Loan', 'Balance Manipulation via Flash Loan', 'Reserve Manipulation', 'Exchange Rate Manipulation', 'Interest Rate Manipulation', 'Fee Calculation Manipulation', 'Reward Calculation Manipulation', 'Flash Loan Without Repayment Check', 'Flash Loan Reentrancy', etc.)."]
) -> str:
    """
    Create a flash loan attack security review prompt for Solidity functions interacting with flash loans.

    Parameters:
        function_explanation (str): Intended behavior, flash loan interactions, and price dependencies.
        function_body (str): Exact function code vulnerable to flash loan attacks.
        file_path (str): Repo-relative path.
        flash_loan_context (str): Flash loan integration, oracle usage, liquidity checks, price dependencies.
        list_of_flash_loan_threats (list[str]): Threats like price manipulation, oracle manipulation, liquidity manipulation,
            collateral manipulation, and governance attacks via flash loans.

    Output:
        str: Prompt instructing LLM to identify flash loan attack vectors and manipulation resistance.
    """
    msg = f"""
SOLIDITY FLASH LOAN THREAT ANALYSIS REQUEST

Function Context:
- Flash Loan Purpose: {function_explanation}
- File Location: {file_path}
- Flash Loan Context: {flash_loan_context}
- Flash Loan Threats to Evaluate: {', '.join(list_of_flash_loan_threats)}

Solidity Flash Loan Source Code to Analyze:
{function_body}

Please perform a comprehensive Solidity flash loan security analysis focusing on the specified flash loan threats. Pay special attention to:
1. Price oracle manipulation through flash loans
2. Liquidity pool price manipulation
3. Collateral and reserve manipulation
4. Governance and voting manipulation via flash loans
5. Lending protocol exploitation through flash loans
6. Repayment validation and reentrancy in flash loan callbacks

Provide detailed findings with flash loan-specific attack vector analysis, potential manipulation scenarios, and remediation guidance specific to flash loan vulnerabilities and flash loan-resistant design patterns.
"""

    return msg


async def solidity_governance_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solidity governance function does, its purpose in governance operations, and its role in the governance contract. Should include voting mechanisms, proposal systems, execution logic, and any governance-specific behaviors."],
    function_body: Annotated[str, "The complete Solidity source code of the governance function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual Solidity code that will be analyzed for governance vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/Governance.sol', 'contracts/DAO.sol', 'contracts/Voting.sol'). Used for context and reporting."], 
    governance_context: Annotated[str, "Additional governance context including the governance model (e.g., token-weighted voting, quadratic voting, time-locked voting), proposal lifecycle, quorum requirements, and critical governance operations this function handles."],
    list_of_governance_threats: Annotated[list[str], "A comprehensive list of governance-specific threats and vulnerabilities to check for during analysis. Each item should be a specific governance threat type (e.g., 'Vote Manipulation', 'Flash Loan Governance Attack', 'Proposal Execution Vulnerabilities', 'Quorum Manipulation', 'Voting Power Manipulation', 'Proposal Timing Attacks', 'Governance Takeover', 'Centralization Risks', 'Proposal Spam Attacks', 'Vote Buying', 'Double Voting', 'Vote Sniping', 'Proposal Cancellation Vulnerabilities', 'Emergency Powers Abuse', 'Governance Delay Attacks', 'Proposal Parameter Manipulation', 'Vote Weight Calculation Errors', 'Delegation Vulnerabilities', 'Governance Reentrancy', 'Proposal Execution Reentrancy', etc.)."]
) -> str:
    """
    Build a governance security review prompt for Solidity DAO and governance contracts.

    Parameters:
        function_explanation (str): Intended governance behavior, voting mechanisms, and proposal lifecycle.
        function_body (str): Exact governance function implementation.
        file_path (str): Repo-relative path.
        governance_context (str): Governance model, voting mechanism, proposal lifecycle, quorum requirements.
        list_of_governance_threats (list[str]): Threats like vote manipulation, flash loan attacks, quorum manipulation,
            proposal execution issues, centralization, and governance takeover.

    Output:
        str: Prompt targeting governance security with focus on voting integrity and proposal safety.
    """
    msg = f"""
SOLIDITY GOVERNANCE THREAT ANALYSIS REQUEST

Function Context:
- Governance Purpose: {function_explanation}
- File Location: {file_path}
- Governance Context: {governance_context}
- Governance Threats to Evaluate: {', '.join(list_of_governance_threats)}

Solidity Governance Source Code to Analyze:
{function_body}

Please perform a comprehensive Solidity governance security analysis focusing on the specified governance threats. Pay special attention to:
1. Vote manipulation and flash loan governance attacks
2. Proposal execution vulnerabilities and reentrancy
3. Quorum and voting power manipulation
4. Governance takeover and centralization risks
5. Proposal spam and timing attacks
6. Emergency powers and admin function abuse

Provide detailed findings with governance-specific attack vector analysis, potential governance compromise scenarios, and remediation guidance specific to governance vulnerabilities and secure DAO design practices.
"""

    return msg


async def solidity_lending_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solidity lending function does, its purpose in lending operations, and its role in the lending protocol. Should include lending mechanics, collateral management, interest calculations, liquidation logic, and any lending-specific behaviors."],
    function_body: Annotated[str, "The complete Solidity source code of the lending function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual Solidity code that will be analyzed for lending vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/LendingPool.sol', 'contracts/Collateral.sol', 'contracts/Liquidation.sol'). Used for context and reporting."], 
    lending_context: Annotated[str, "Additional lending context including the lending model (e.g., over-collateralized, under-collateralized), collateral types, interest rate model, liquidation mechanisms, and critical lending operations this function handles."],
    list_of_lending_threats: Annotated[list[str], "A comprehensive list of lending-specific threats and vulnerabilities to check for during analysis. Each item should be a specific lending threat type (e.g., 'Liquidation Vulnerabilities', 'Collateral Manipulation', 'Interest Rate Manipulation', 'Oracle Price Manipulation', 'Flash Loan Lending Attack', 'Collateral Factor Vulnerabilities', 'Borrow Limit Vulnerabilities', 'Liquidation Threshold Issues', 'Health Factor Calculation Errors', 'Interest Accrual Errors', 'Collateral Seizure Vulnerabilities', 'Liquidation Bonus Manipulation', 'Price Oracle Staleness', 'Collateral Price Manipulation', 'Borrow Rate Manipulation', 'Supply Rate Manipulation', 'Reserve Factor Vulnerabilities', 'Liquidation Incentive Issues', 'Bad Debt Accumulation', 'Liquidation Front-Running', etc.)."]
) -> str:
    """
    Create a lending protocol security review prompt for Solidity lending contracts.

    Parameters:
        function_explanation (str): Intended lending behavior, collateral management, and liquidation logic.
        function_body (str): Exact lending function code.
        file_path (str): Repo-relative path.
        lending_context (str): Lending model, collateral types, interest rates, liquidation mechanisms.
        list_of_lending_threats (list[str]): Threats like liquidation vulnerabilities, collateral manipulation,
            interest rate manipulation, oracle manipulation, and flash loan attacks.

    Output:
        str: Prompt instructing LLM to validate lending protocol safety and economic correctness.
    """
    msg = f"""
SOLIDITY LENDING PROTOCOL THREAT ANALYSIS REQUEST

Function Context:
- Lending Purpose: {function_explanation}
- File Location: {file_path}
- Lending Context: {lending_context}
- Lending Threats to Evaluate: {', '.join(list_of_lending_threats)}

Solidity Lending Source Code to Analyze:
{function_body}

Please perform a comprehensive Solidity lending protocol security analysis focusing on the specified lending threats. Pay special attention to:
1. Liquidation mechanism vulnerabilities and front-running
2. Collateral manipulation and price oracle attacks
3. Interest rate calculation and accrual errors (including residual debt from interest accrual)
4. Health factor and collateral factor calculations
5. Flash loan attacks on lending protocols
6. Bad debt accumulation and protocol insolvency risks
7. eMode validation issues (missing collateral asset checks against eMode category)
8. Total supply calculation errors affecting protocol accounting
9. Missing zero-balance checks leading to gas wastage and poor UX
10. Interest accrual causing residual debt even after full repayment attempts

Provide detailed findings with lending-specific attack vector analysis, potential protocol insolvency scenarios, and remediation guidance specific to lending vulnerabilities and secure lending protocol design practices.
"""

    return msg


async def solidity_amm_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solidity AMM function does, its purpose in automated market maker operations, and its role in the DEX protocol. Should include AMM mechanics, liquidity pool management, price calculations, swap logic, and any AMM-specific behaviors."],
    function_body: Annotated[str, "The complete Solidity source code of the AMM function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual Solidity code that will be analyzed for AMM vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/UniswapV2Pair.sol', 'contracts/Pool.sol', 'contracts/Swap.sol'). Used for context and reporting."], 
    amm_context: Annotated[str, "Additional AMM context including the AMM model (e.g., constant product, constant sum, hybrid), liquidity pool structure, price calculation formula, fee mechanisms, and critical AMM operations this function handles."],
    list_of_amm_threats: Annotated[list[str], "A comprehensive list of AMM-specific threats and vulnerabilities to check for during analysis. Each item should be a specific AMM threat type (e.g., 'Price Manipulation', 'Liquidity Pool Manipulation', 'Flash Loan AMM Attack', 'Sandwich Attacks', 'Front-Running AMM', 'Slippage Exploitation', 'Impermanent Loss', 'Liquidity Drain Attacks', 'Reserve Manipulation', 'Price Oracle Manipulation', 'K Value Manipulation', 'Rounding Errors in Price Calculation', 'Fee Calculation Errors', 'Liquidity Provider Exploitation', 'JIT Liquidity Attacks', 'Arbitrage Vulnerabilities', 'MEV Extraction from AMM', 'Price Impact Manipulation', 'Liquidity Addition Vulnerabilities', 'Liquidity Removal Vulnerabilities', etc.)."]
) -> str:
    """
    Build an AMM (Automated Market Maker) security review prompt for Solidity DEX contracts.

    Parameters:
        function_explanation (str): Intended AMM behavior, price calculation, and liquidity management.
        function_body (str): Exact AMM function implementation.
        file_path (str): Repo-relative path.
        amm_context (str): AMM model, liquidity pool structure, price formula, fee mechanisms.
        list_of_amm_threats (list[str]): Threats like price manipulation, liquidity manipulation, flash loan attacks,
            sandwich attacks, slippage exploitation, and impermanent loss.

    Output:
        str: Prompt targeting AMM security with focus on price integrity and liquidity safety.
    """
    msg = f"""
SOLIDITY AMM THREAT ANALYSIS REQUEST

Function Context:
- AMM Purpose: {function_explanation}
- File Location: {file_path}
- AMM Context: {amm_context}
- AMM Threats to Evaluate: {', '.join(list_of_amm_threats)}

Solidity AMM Source Code to Analyze:
{function_body}

Please perform a comprehensive Solidity AMM security analysis focusing on the specified AMM threats. Pay special attention to:
1. Price manipulation through flash loans and large swaps
2. Liquidity pool manipulation and reserve attacks
3. Sandwich attacks and front-running vulnerabilities
4. Slippage and price impact calculation errors
5. Impermanent loss and liquidity provider risks
6. K value and price calculation rounding errors

Provide detailed findings with AMM-specific attack vector analysis, potential liquidity drain scenarios, and remediation guidance specific to AMM vulnerabilities and secure DEX design practices.
"""

    return msg


async def solidity_staking_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solidity staking function does, its purpose in staking operations, and its role in the staking contract. Should include staking mechanics, reward distribution, slashing conditions, withdrawal logic, and any staking-specific behaviors."],
    function_body: Annotated[str, "The complete Solidity source code of the staking function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual Solidity code that will be analyzed for staking vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/Staking.sol', 'contracts/Validator.sol', 'contracts/Rewards.sol'). Used for context and reporting."], 
    staking_context: Annotated[str, "Additional staking context including the staking model (e.g., proof-of-stake, delegated staking, liquid staking), reward mechanism, slashing conditions, lock periods, and critical staking operations this function handles."],
    list_of_staking_threats: Annotated[list[str], "A comprehensive list of staking-specific threats and vulnerabilities to check for during analysis. Each item should be a specific staking threat type (e.g., 'Reward Distribution Errors', 'Slashing Vulnerabilities', 'Stake Withdrawal Vulnerabilities', 'Reward Calculation Errors', 'Stake Lock Bypass', 'Reward Manipulation', 'Stake Front-Running', 'Validator Selection Vulnerabilities', 'Delegation Vulnerabilities', 'Unbonding Period Bypass', 'Reward Accrual Errors', 'Stake Accounting Errors', 'Reward Rate Manipulation', 'Stake Reentrancy', 'Reward Reentrancy', 'Stake Lock Vulnerabilities', 'Validator Slashing Bypass', 'Reward Pool Drain', 'Stake Pool Manipulation', 'Reward Timing Attacks', etc.)."]
) -> str:
    """
    Create a staking protocol security review prompt for Solidity staking contracts.

    Parameters:
        function_explanation (str): Intended staking behavior, reward distribution, and slashing logic.
        function_body (str): Exact staking function code.
        file_path (str): Repo-relative path.
        staking_context (str): Staking model, reward mechanism, slashing conditions, lock periods.
        list_of_staking_threats (list[str]): Threats like reward distribution errors, slashing vulnerabilities,
            withdrawal issues, reward manipulation, and stake accounting errors.

    Output:
        str: Prompt instructing LLM to validate staking protocol safety and economic correctness.
    """
    msg = f"""
SOLIDITY STAKING THREAT ANALYSIS REQUEST

Function Context:
- Staking Purpose: {function_explanation}
- File Location: {file_path}
- Staking Context: {staking_context}
- Staking Threats to Evaluate: {', '.join(list_of_staking_threats)}

Solidity Staking Source Code to Analyze:
{function_body}

Please perform a comprehensive Solidity staking security analysis focusing on the specified staking threats. Pay special attention to:
1. Reward distribution and calculation accuracy
2. Slashing mechanism vulnerabilities and bypass vectors
3. Stake withdrawal and unbonding period enforcement
4. Reward manipulation and front-running attacks
5. Stake accounting and balance tracking errors
6. Reentrancy in stake and reward operations

Provide detailed findings with staking-specific attack vector analysis, potential reward pool drain scenarios, and remediation guidance specific to staking vulnerabilities and secure staking protocol design practices.
"""

    return msg


async def solidity_nft_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solidity NFT function does, its purpose in NFT operations, and its role in the NFT contract. Should include NFT minting, transfers, approvals, metadata management, and any NFT-specific behaviors."],
    function_body: Annotated[str, "The complete Solidity source code of the NFT function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual Solidity code that will be analyzed for NFT vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/ERC721.sol', 'contracts/ERC1155.sol', 'contracts/NFT.sol'). Used for context and reporting."], 
    nft_context: Annotated[str, "Additional NFT context including the NFT standard (e.g., ERC-721, ERC-1155), metadata storage, royalty mechanisms, and critical NFT operations this function handles."],
    list_of_nft_threats: Annotated[list[str], "A comprehensive list of NFT-specific threats and vulnerabilities to check for during analysis. Each item should be a specific NFT threat type (e.g., 'NFT Standard Violations', 'Minting Vulnerabilities', 'Transfer Vulnerabilities', 'Approval Vulnerabilities', 'Metadata Manipulation', 'Token URI Vulnerabilities', 'Royalty Bypass', 'Reentrancy in NFT Transfers', 'Ownership Verification Issues', 'Token ID Collision', 'Metadata Injection', 'URI Manipulation', 'Royalty Calculation Errors', 'Batch Transfer Vulnerabilities', 'NFT Access Control', 'Minting Access Control', 'Burn Function Vulnerabilities', 'NFT Upgrade Vulnerabilities', 'Metadata Storage Issues', 'Token ID Predictability', etc.)."]
) -> str:
    """
    Build an NFT security review prompt for Solidity ERC-721/1155 contracts.

    Parameters:
        function_explanation (str): Intended NFT behavior, standard compliance, and metadata management.
        function_body (str): Exact NFT function implementation.
        file_path (str): Repo-relative path.
        nft_context (str): NFT standard, metadata storage, royalty mechanisms, ownership tracking.
        list_of_nft_threats (list[str]): Threats like standard violations, minting vulnerabilities, metadata manipulation,
            royalty bypass, and ownership verification issues.

    Output:
        str: Prompt targeting NFT security with focus on standard compliance and metadata integrity.
    """
    msg = f"""
SOLIDITY NFT THREAT ANALYSIS REQUEST

Function Context:
- NFT Purpose: {function_explanation}
- File Location: {file_path}
- NFT Context: {nft_context}
- NFT Threats to Evaluate: {', '.join(list_of_nft_threats)}

Solidity NFT Source Code to Analyze:
{function_body}

Please perform a comprehensive Solidity NFT security analysis focusing on the specified NFT threats. Pay special attention to:
1. ERC-721/ERC-1155 standard compliance violations
2. Minting access control and token ID management
3. Metadata and URI manipulation vulnerabilities
4. Royalty mechanism bypass and calculation errors
5. Ownership verification and transfer security
6. Reentrancy in NFT transfer and approval operations

Provide detailed findings with NFT-specific attack vector analysis, potential metadata manipulation scenarios, and remediation guidance specific to NFT vulnerabilities and secure NFT contract design practices.
"""

    return msg


async def solidity_bridge_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solidity bridge function does, its purpose in cross-chain operations, and its role in the bridge contract. Should include cross-chain message passing, asset locking/unlocking, validation logic, and any bridge-specific behaviors."],
    function_body: Annotated[str, "The complete Solidity source code of the bridge function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual Solidity code that will be analyzed for bridge vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/Bridge.sol', 'contracts/CrossChain.sol', 'contracts/Validator.sol'). Used for context and reporting."], 
    bridge_context: Annotated[str, "Additional bridge context including the bridge architecture (e.g., lock-and-mint, burn-and-mint, optimistic, zk-based), validator set, message verification, and critical bridge operations this function handles."],
    list_of_bridge_threats: Annotated[list[str], "A comprehensive list of bridge-specific threats and vulnerabilities to check for during analysis. Each item should be a specific bridge threat type (e.g., 'Validator Set Manipulation', 'Message Verification Bypass', 'Double Spending', 'Replay Attacks', 'Message Forgery', 'Validator Collusion', 'Signature Verification Bypass', 'Message Ordering Attacks', 'Relay Attack', 'Lock Mechanism Bypass', 'Mint Mechanism Bypass', 'Burn Mechanism Bypass', 'Cross-Chain Message Replay', 'Validator Key Compromise', 'Message Delay Attacks', 'Bridge Centralization Risks', 'Message Validation Errors', 'Asset Lock Vulnerabilities', 'Asset Unlock Vulnerabilities', 'Bridge Upgrade Vulnerabilities', etc.)."]
) -> str:
    """
    Create a cross-chain bridge security review prompt for Solidity bridge contracts.

    Parameters:
        function_explanation (str): Intended bridge behavior, message verification, and asset management.
        function_body (str): Exact bridge function code.
        file_path (str): Repo-relative path.
        bridge_context (str): Bridge architecture, validator set, message verification, lock/unlock mechanisms.
        list_of_bridge_threats (list[str]): Threats like validator manipulation, message forgery, double spending,
            replay attacks, and bridge centralization.

    Output:
        str: Prompt instructing LLM to validate bridge security and cross-chain message integrity.
    """
    msg = f"""
SOLIDITY CROSS-CHAIN BRIDGE THREAT ANALYSIS REQUEST

Function Context:
- Bridge Purpose: {function_explanation}
- File Location: {file_path}
- Bridge Context: {bridge_context}
- Bridge Threats to Evaluate: {', '.join(list_of_bridge_threats)}

Solidity Bridge Source Code to Analyze:
{function_body}

Please perform a comprehensive Solidity bridge security analysis focusing on the specified bridge threats. Pay special attention to:
1. Validator set manipulation and collusion attacks
2. Message verification and signature validation bypass
3. Double spending and replay attack vectors
4. Cross-chain message ordering and delay attacks
5. Asset lock and unlock mechanism vulnerabilities
6. Bridge centralization and single point of failure risks

Provide detailed findings with bridge-specific attack vector analysis, potential cross-chain asset loss scenarios, and remediation guidance specific to bridge vulnerabilities and secure cross-chain design practices.
"""

    return msg


async def solidity_timestamp_block_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solidity function does, its purpose in time-dependent operations, and its role in the smart contract. Should include timestamp usage, block number dependencies, time-based logic, and any temporal behaviors."],
    function_body: Annotated[str, "The complete Solidity source code of the function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual Solidity code that will be analyzed for timestamp and block number vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/Random.sol', 'contracts/Lottery.sol', 'contracts/Vesting.sol'). Used for context and reporting."], 
    timestamp_block_context: Annotated[str, "Additional timestamp and block context including time-based operations (e.g., random number generation, vesting schedules, time-locked functions), block number usage, and critical temporal operations this function handles."],
    list_of_timestamp_block_threats: Annotated[list[str], "A comprehensive list of timestamp and block number-specific threats and vulnerabilities to check for during analysis. Each item should be a specific timestamp/block threat type (e.g., 'Timestamp Manipulation', 'Block Number Manipulation', 'Block Timestamp Dependence', 'Block Number Dependence', 'Miner Manipulation', 'Timestamp Predictability', 'Block Number Predictability', 'Time-Based Random Number Generation', 'Vesting Schedule Manipulation', 'Time-Lock Bypass', 'Block Timestamp Precision Issues', 'Block Number Precision Issues', 'Timestamp Comparison Errors', 'Block Number Comparison Errors', 'Time-Based Access Control Bypass', 'Random Number Predictability', 'Lottery Manipulation via Timestamp', 'Auction Timing Manipulation', 'Governance Timing Attacks', 'Time-Based Reentrancy', etc.)."]
) -> str:
    """
    Build a timestamp and block number security review prompt for Solidity functions using temporal data.

    Parameters:
        function_explanation (str): Intended time-based behavior, timestamp usage, and block dependencies.
        function_body (str): Exact function code using timestamps or block numbers.
        file_path (str): Repo-relative path.
        timestamp_block_context (str): Time-based operations, block number usage, temporal dependencies.
        list_of_timestamp_block_threats (list[str]): Threats like timestamp manipulation, block number manipulation,
            miner manipulation, time-based random number generation, and vesting schedule manipulation.

    Output:
        str: Prompt targeting temporal security with focus on timestamp and block number safety.
    """
    msg = f"""
SOLIDITY TIMESTAMP AND BLOCK NUMBER THREAT ANALYSIS REQUEST

Function Context:
- Timestamp/Block Purpose: {function_explanation}
- File Location: {file_path}
- Timestamp/Block Context: {timestamp_block_context}
- Timestamp/Block Threats to Evaluate: {', '.join(list_of_timestamp_block_threats)}

Solidity Timestamp/Block Source Code to Analyze:
{function_body}

Please perform a comprehensive Solidity timestamp and block number security analysis focusing on the specified timestamp/block threats. Pay special attention to:
1. Timestamp and block number manipulation by miners
2. Time-based random number generation predictability
3. Vesting schedule and time-lock bypass vectors
4. Block timestamp precision and comparison errors
5. Time-based access control and governance timing attacks
6. Dependence on manipulable temporal data sources

Provide detailed findings with timestamp/block-specific attack vector analysis, potential time-based manipulation scenarios, and remediation guidance specific to timestamp vulnerabilities and secure temporal data usage practices.
"""

    return msg


async def solidity_dust_liquidation_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solidity liquidation function does, its purpose in liquidation operations, and its role in the protocol. Should include liquidation mechanics, incentive distribution, dust threshold handling, and any liquidation-specific behaviors."],
    function_body: Annotated[str, "The complete Solidity source code of the liquidation function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual Solidity code that will be analyzed for dust liquidation vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/Liquidation.sol', 'contracts/Clipper.sol', 'contracts/Keeper.sol'). Used for context and reporting."], 
    liquidation_context: Annotated[str, "Additional liquidation context including the liquidation mechanism (e.g., auction-based, instant, keeper-based), incentive structure (tip, chip, flat fees), dust thresholds, and critical liquidation operations this function handles."],
    list_of_dust_liquidation_threats: Annotated[list[str], "A comprehensive list of dust liquidation-specific threats and vulnerabilities to check for during analysis. Each item should be a specific dust liquidation threat type (e.g., 'Dust Liquidation Incentive Farming', 'Missing Minimum Amount Checks', 'Flat Tip Without Threshold', 'Dust Urn Creation', 'Instant Liquidation of Dust Positions', 'Keeper Fee Theft', 'Incentive Distribution Without Validation', 'Dust Threshold Bypass', 'Repeated Dust Liquidation Attacks', 'Protocol Debt Accumulation from Dust', 'Liquidation Incentive Manipulation', 'Dust Position Exploitation', 'Minimum Collateral Bypass', 'Liquidation Fee Farming', 'Dust Urn Reuse Attacks', 'Incentive Calculation Errors', 'Dust Amount Validation Missing', 'Liquidation Kick Without Checks', 'Protocol Insolvency from Dust Attacks', 'Incentive Theft via Dust Positions', etc.)."]
) -> str:
    """
    Create a dust liquidation and incentive farming security review prompt for Solidity liquidation contracts.
    Based on real-world findings where attackers create dust positions to farm liquidation incentives.

    Parameters:
        function_explanation (str): Intended liquidation behavior, incentive distribution, and dust handling.
        function_body (str): Exact liquidation function code.
        file_path (str): Repo-relative path.
        liquidation_context (str): Liquidation mechanism, incentive structure, dust thresholds, keeper operations.
        list_of_dust_liquidation_threats (list[str]): Threats like dust incentive farming, missing minimum checks,
            flat tip vulnerabilities, dust urn creation, and protocol debt accumulation.

    Output:
        str: Prompt instructing LLM to validate dust liquidation resistance and incentive farming prevention.
    """
    msg = f"""
SOLIDITY DUST LIQUIDATION THREAT ANALYSIS REQUEST

Function Context:
- Dust Liquidation Purpose: {function_explanation}
- File Location: {file_path}
- Liquidation Context: {liquidation_context}
- Dust Liquidation Threats to Evaluate: {', '.join(list_of_dust_liquidation_threats)}

Solidity Dust Liquidation Source Code to Analyze:
{function_body}

Please perform a comprehensive Solidity dust liquidation security analysis focusing on the specified dust liquidation threats. Pay special attention to:
1. Missing minimum amount checks before distributing liquidation incentives
2. Flat tip/chip incentives that can be farmed through dust positions
3. Dust threshold validation and enforcement mechanisms
4. Ability to create and instantly liquidate dust urns/positions
5. Repeated attack vectors that could drain protocol incentives
6. Protocol debt accumulation from repeated dust liquidations

Provide detailed findings with dust liquidation-specific attack vector analysis, potential incentive theft scenarios, and remediation guidance specific to dust liquidation vulnerabilities and secure liquidation incentive design practices.
"""

    return msg


async def solidity_chain_compatibility_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solidity function does, its purpose in cross-chain or multi-chain operations, and its role in the contract. Should include chain-specific operations, compatibility requirements, and any chain-dependent behaviors."],
    function_body: Annotated[str, "The complete Solidity source code of the function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual Solidity code that will be analyzed for chain compatibility vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/CrossChain.sol', 'contracts/MultiChain.sol', 'contracts/ChainAdapter.sol'). Used for context and reporting."], 
    chain_compatibility_context: Annotated[str, "Additional chain compatibility context including target chains (e.g., Ethereum, Arbitrum, Optimism, ZKSync, Polygon), chain-specific features used (e.g., delegatecall, CREATE2, precompiles), and critical chain-dependent operations this function handles."],
    list_of_chain_compatibility_threats: Annotated[list[str], "A comprehensive list of chain compatibility-specific threats and vulnerabilities to check for during analysis. Each item should be a specific chain compatibility threat type (e.g., 'Delegatecall Not Supported', 'CREATE2 Differences', 'Precompile Availability', 'Gas Limit Differences', 'Opcode Differences', 'Chain-Specific Revert Behavior', 'Address Format Differences', 'Transaction Format Differences', 'Block Structure Differences', 'Storage Layout Differences', 'EVM Version Differences', 'Chain-Specific Function Failures', 'Missing Chain Feature Checks', 'Incompatible Opcode Usage', 'Chain-Specific Gas Costs', 'Cross-Chain State Inconsistency', 'Chain-Specific Oracle Issues', 'Chain-Specific Upgrade Patterns', 'Chain-Specific Access Control', 'Chain-Specific Error Handling', etc.)."]
) -> str:
    """
    Build a chain compatibility security review prompt for Solidity functions targeting multiple chains.

    Parameters:
        function_explanation (str): Intended cross-chain behavior, chain-specific operations, and compatibility requirements.
        function_body (str): Exact function code with chain-dependent operations.
        file_path (str): Repo-relative path.
        chain_compatibility_context (str): Target chains, chain-specific features, compatibility requirements.
        list_of_chain_compatibility_threats (list[str]): Threats like unsupported opcodes, delegatecall issues,
            chain-specific failures, and cross-chain inconsistencies.

    Output:
        str: Prompt targeting chain compatibility with focus on multi-chain deployment safety.
    """
    msg = f"""
SOLIDITY CHAIN COMPATIBILITY THREAT ANALYSIS REQUEST

Function Context:
- Chain Compatibility Purpose: {function_explanation}
- File Location: {file_path}
- Chain Compatibility Context: {chain_compatibility_context}
- Chain Compatibility Threats to Evaluate: {', '.join(list_of_chain_compatibility_threats)}

Solidity Chain Compatibility Source Code to Analyze:
{function_body}

Please perform a comprehensive Solidity chain compatibility security analysis focusing on the specified chain compatibility threats. Pay special attention to:
1. Use of opcodes or features not supported on all target chains (e.g., delegatecall on ZKSync)
2. Chain-specific gas limits and transaction formats
3. Differences in revert behavior and error handling across chains
4. Chain-specific precompiles and their availability
5. Address format and CREATE2 differences
6. Missing chain feature detection and fallback mechanisms

Provide detailed findings with chain compatibility-specific attack vector analysis, potential chain-specific failure scenarios, and remediation guidance specific to chain compatibility vulnerabilities and secure multi-chain deployment practices.
"""

    return msg


async def solidity_error_handling_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solidity function does, its purpose in error handling, and its role in the contract. Should include error handling patterns, revert message processing, try-catch usage, and any error-related behaviors."],
    function_body: Annotated[str, "The complete Solidity source code of the function including all statements, variable assignments, control flow, error handling, try-catch blocks, and any nested logic. This is the actual Solidity code that will be analyzed for error handling vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/ErrorHandler.sol', 'contracts/Callback.sol', 'contracts/Keeper.sol'). Used for context and reporting."], 
    error_handling_context: Annotated[str, "Additional error handling context including error handling patterns (e.g., try-catch, require statements, custom errors), callback mechanisms, keeper operations, and critical error handling operations this function handles."],
    list_of_error_handling_threats: Annotated[list[str], "A comprehensive list of error handling-specific threats and vulnerabilities to check for during analysis. Each item should be a specific error handling threat type (e.g., 'Return Bomb Attacks', 'Gas Griefing via Revert Messages', 'Malicious Revert Reason Exploitation', 'Incomplete Error Handling', 'Error Message Parsing Vulnerabilities', 'Try-Catch Block Exploitation', 'Callback Error Manipulation', 'Keeper Gas Griefing', 'Long Revert Message Attacks', 'Error Data Corruption', 'ABI Decoding from Revert Exploitation', 'Error Handling Bypass', 'Silent Failure Scenarios', 'Error Propagation Issues', 'Error Message Injection', 'Gas Limit Exhaustion via Errors', 'Error-Based DoS Attacks', 'Incomplete Catch Block Handling', 'Error Data Length Manipulation', 'Error-Based Execution Control', etc.)."]
) -> str:
    """
    Create an error handling security review prompt for Solidity functions with error handling logic.

    Parameters:
        function_explanation (str): Intended error handling behavior, revert processing, and callback safety.
        function_body (str): Exact function code with error handling.
        file_path (str): Repo-relative path.
        error_handling_context (str): Error handling patterns, callback mechanisms, keeper operations.
        list_of_error_handling_threats (list[str]): Threats like return bombs, gas griefing, malicious revert reasons,
            incomplete error handling, and ABI decoding exploitation.

    Output:
        str: Prompt instructing LLM to validate error handling safety and gas griefing resistance.
    """
    msg = f"""
SOLIDITY ERROR HANDLING THREAT ANALYSIS REQUEST

Function Context:
- Error Handling Purpose: {function_explanation}
- File Location: {file_path}
- Error Handling Context: {error_handling_context}
- Error Handling Threats to Evaluate: {', '.join(list_of_error_handling_threats)}

Solidity Error Handling Source Code to Analyze:
{function_body}

Please perform a comprehensive Solidity error handling security analysis focusing on the specified error handling threats. Pay special attention to:
1. Return bomb attacks through malicious revert messages with faked lengths
2. Gas griefing attacks via long revert messages forcing keeper gas waste
3. Incomplete error handling in try-catch blocks allowing execution control
4. ABI decoding vulnerabilities from revert data manipulation
5. Error message parsing and length validation issues
6. Silent failure scenarios from incomplete error handling

Provide detailed findings with error handling-specific attack vector analysis, potential gas griefing scenarios, and remediation guidance specific to error handling vulnerabilities and secure error handling practices.
"""

    return msg


async def solidity_slippage_protection_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solidity function does, its purpose in slippage protection, and its role in the contract. Should include slippage validation, price checks, swap operations, and any slippage-related behaviors."],
    function_body: Annotated[str, "The complete Solidity source code of the function including all statements, variable assignments, control flow, slippage checks, and any nested logic. This is the actual Solidity code that will be analyzed for slippage protection vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/Swap.sol', 'contracts/Withdraw.sol', 'contracts/Trade.sol'). Used for context and reporting."], 
    slippage_context: Annotated[str, "Additional slippage context including the operation type (e.g., swap, withdrawal, liquidation, ADL), slippage calculation method, price sources, and critical slippage protection operations this function handles."],
    list_of_slippage_protection_threats: Annotated[list[str], "A comprehensive list of slippage protection-specific threats and vulnerabilities to check for during analysis. Each item should be a specific slippage protection threat type (e.g., 'Missing Slippage Protection', 'Incorrect Slippage Calculation', 'Slippage Check After Execution', 'Slippage Bypass Vulnerabilities', 'Price Manipulation Before Slippage Check', 'Stale Price Data in Slippage Calculation', 'Slippage Protection in Wrong Order', 'Missing Slippage for Withdrawal Paths', 'ADL Slippage Protection Missing', 'Slippage Check Using Wrong Price', 'MEV Attacks via Slippage', 'Front-Running Slippage Exploitation', 'Slippage Tolerance Too High', 'Slippage Check Bypass via Reentrancy', 'Slippage Calculation Errors', 'Missing Slippage for Direct Swaps', 'Slippage Protection Timing Issues', 'Price Impact Not Considered in Slippage', 'Slippage Check Using Manipulated Reserves', 'Slippage Validation Logic Errors', etc.)."]
) -> str:
    """
    Build a slippage protection security review prompt for Solidity functions handling swaps and withdrawals.

    Parameters:
        function_explanation (str): Intended slippage protection behavior, price validation, and swap safety.
        function_body (str): Exact function code with slippage checks.
        file_path (str): Repo-relative path.
        slippage_context (str): Operation type, slippage calculation, price sources, swap mechanisms.
        list_of_slippage_protection_threats (list[str]): Threats like missing slippage, incorrect calculation,
            slippage bypass, price manipulation, and MEV exploitation.

    Output:
        str: Prompt targeting slippage protection correctness with focus on user fund safety.
    """
    msg = f"""
SOLIDITY SLIPPAGE PROTECTION THREAT ANALYSIS REQUEST

Function Context:
- Slippage Protection Purpose: {function_explanation}
- File Location: {file_path}
- Slippage Context: {slippage_context}
- Slippage Protection Threats to Evaluate: {', '.join(list_of_slippage_protection_threats)}

Solidity Slippage Protection Source Code to Analyze:
{function_body}

Please perform a comprehensive Solidity slippage protection security analysis focusing on the specified slippage protection threats. Pay special attention to:
1. Missing or incorrect slippage protection for swaps, withdrawals, and ADL operations
2. Slippage checks performed after execution or in wrong order
3. Price manipulation before slippage validation
4. Stale price data used in slippage calculations
5. Missing slippage protection for direct swap paths
6. MEV and front-running exploitation via slippage vulnerabilities

Provide detailed findings with slippage protection-specific attack vector analysis, potential user fund loss scenarios, and remediation guidance specific to slippage protection vulnerabilities and secure slippage validation practices.
"""

    return msg


async def solidity_fee_calculation_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solidity function does, its purpose in fee calculation, and its role in the contract. Should include fee computation, fee distribution, fee accrual, and any fee-related behaviors."],
    function_body: Annotated[str, "The complete Solidity source code of the function including all statements, variable assignments, control flow, fee calculations, and any nested logic. This is the actual Solidity code that will be analyzed for fee calculation vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/FeeCalculator.sol', 'contracts/Pool.sol', 'contracts/Trading.sol'). Used for context and reporting."], 
    fee_calculation_context: Annotated[str, "Additional fee calculation context including the fee types (e.g., trading fees, borrowing fees, liquidation fees, protocol fees), fee calculation formulas, fee distribution mechanisms, and critical fee operations this function handles."],
    list_of_fee_calculation_threats: Annotated[list[str], "A comprehensive list of fee calculation-specific threats and vulnerabilities to check for during analysis. Each item should be a specific fee calculation threat type (e.g., 'Double Fee Charging', 'Incorrect Fee Calculation', 'Fee Calculation Errors', 'Fee Distribution Errors', 'Fee Accrual Errors', 'Fee Receiver Gets Wrong Amount', 'Fee Calculation Using Wrong Values', 'Missing Fee Validation', 'Fee Overflow/Underflow', 'Fee Rounding Errors', 'Fee Calculation Timing Issues', 'Fee Bypass Vulnerabilities', 'Fee Calculation Logic Errors', 'Fee Component Double Counting', 'Fee Rate Manipulation', 'Fee Calculation Precision Loss', 'Fee Distribution to Wrong Address', 'Fee Accumulation Errors', 'Fee Calculation Using Stale Data', 'Fee Formula Errors', etc.)."]
) -> str:
    """
    Create a fee calculation security review prompt for Solidity functions computing and distributing fees.

    Parameters:
        function_explanation (str): Intended fee calculation behavior, fee formulas, and distribution logic.
        function_body (str): Exact function code with fee calculations.
        file_path (str): Repo-relative path.
        fee_calculation_context (str): Fee types, calculation formulas, distribution mechanisms, fee receivers.
        list_of_fee_calculation_threats (list[str]): Threats like double charging, calculation errors,
            distribution errors, fee bypass, and precision loss.

    Output:
        str: Prompt instructing LLM to validate fee calculation correctness and economic safety.
    """
    msg = f"""
SOLIDITY FEE CALCULATION THREAT ANALYSIS REQUEST

Function Context:
- Fee Calculation Purpose: {function_explanation}
- File Location: {file_path}
- Fee Calculation Context: {fee_calculation_context}
- Fee Calculation Threats to Evaluate: {', '.join(list_of_fee_calculation_threats)}

Solidity Fee Calculation Source Code to Analyze:
{function_body}

Please perform a comprehensive Solidity fee calculation security analysis focusing on the specified fee calculation threats. Pay special attention to:
1. Double charging of fees or fee components
2. Incorrect fee calculation formulas and logic errors
3. Fee distribution errors causing wrong amounts to receivers
4. Fee calculation using wrong values or stale data
5. Fee overflow/underflow and precision loss issues
6. Fee bypass vulnerabilities and missing fee validation

Provide detailed findings with fee calculation-specific attack vector analysis, potential economic impact scenarios, and remediation guidance specific to fee calculation vulnerabilities and secure fee computation practices.
"""

    return msg


# ============================================================================
# SECTION 5: FINANCIAL & FUND SAFETY THREAT FUNCTIONS
# Functions for analyzing fund safety, refunds, and financial operations
# ============================================================================

async def solidity_residual_refund_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solidity function does, its purpose in handling residual amounts and refunds, and its role in the contract. Should include refund mechanisms, residual amount handling, excess fund management, and any refund-related behaviors."],
    function_body: Annotated[str, "The complete Solidity source code of the function including all statements, variable assignments, control flow, refund logic, and any nested logic. This is the actual Solidity code that will be analyzed for residual refund vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/Repay.sol', 'contracts/Withdraw.sol', 'contracts/Settlement.sol'). Used for context and reporting."], 
    residual_refund_context: Annotated[str, "Additional residual refund context including the operation type (e.g., repayment, withdrawal, settlement, swap), refund mechanisms, excess amount handling, and critical refund operations this function handles."],
    list_of_residual_refund_threats: Annotated[list[str], "A comprehensive list of residual refund-specific threats and vulnerabilities to check for during analysis. Each item should be a specific residual refund threat type (e.g., 'Residual Amount Not Refunded', 'Excess Funds Locked', 'Missing Refund Logic', 'Refund Calculation Errors', 'Residual Cash Loss', 'Excess ETH Not Returned', 'Refund Amount Incorrect', 'Missing Refund After Operation', 'Residual Debt Not Handled', 'Excess Collateral Not Refunded', 'Refund Gas Cost Issues', 'Refund Reentrancy', 'Refund Access Control', 'Residual Amount Accumulation', 'Missing Refund Validation', 'Refund Timing Issues', 'Residual Amount in Wrong Currency', 'Refund to Wrong Address', 'Partial Refund Issues', 'Refund Logic Bypass', etc.)."]
) -> str:
    """
    Create a residual refund security review prompt for Solidity functions handling refunds and excess amounts.

    Parameters:
        function_explanation (str): Intended refund behavior, residual handling, and excess fund management.
        function_body (str): Exact function code with refund logic.
        file_path (str): Repo-relative path.
        residual_refund_context (str): Operation type, refund mechanisms, excess handling.
        list_of_residual_refund_threats (list[str]): Threats like missing refunds, locked funds,
            calculation errors, and refund bypass.

    Output:
        str: Prompt instructing LLM to validate refund correctness and user fund safety.
    """
    msg = f"""
SOLIDITY RESIDUAL REFUND THREAT ANALYSIS REQUEST

Function Context:
- Residual Refund Purpose: {function_explanation}
- File Location: {file_path}
- Residual Refund Context: {residual_refund_context}
- Residual Refund Threats to Evaluate: {', '.join(list_of_residual_refund_threats)}

Solidity Residual Refund Source Code to Analyze:
{function_body}

Please perform a comprehensive Solidity residual refund security analysis focusing on the specified residual refund threats. Pay special attention to:
1. Missing refund logic for residual amounts after operations
2. Excess funds (ETH, tokens) not being returned to users
3. Residual cash/debt amounts not properly handled or refunded
4. Refund calculation errors causing incorrect amounts
5. Missing refund validation and access control
6. Refund reentrancy and timing issues

Provide detailed findings with residual refund-specific attack vector analysis, potential user fund loss scenarios, and remediation guidance specific to residual refund vulnerabilities and secure refund handling practices.
"""

    return msg


async def solidity_settlement_griefing_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solidity settlement function does, its purpose in settlement operations, and its role in the contract. Should include settlement mechanisms, account settlement, liquidation settlement, and any settlement-related behaviors."],
    function_body: Annotated[str, "The complete Solidity source code of the settlement function including all statements, variable assignments, control flow, settlement logic, and any nested logic. This is the actual Solidity code that will be analyzed for settlement griefing vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/Settlement.sol', 'contracts/Vault.sol', 'contracts/Account.sol'). Used for context and reporting."], 
    settlement_context: Annotated[str, "Additional settlement context including the settlement type (e.g., account settlement, vault settlement, liquidation settlement), settlement requirements, rejection mechanisms, and critical settlement operations this function handles."],
    list_of_settlement_griefing_threats: Annotated[list[str], "A comprehensive list of settlement griefing-specific threats and vulnerabilities to check for during analysis. Each item should be a specific settlement griefing threat type (e.g., 'Settlement Rejection Griefing', 'Account Settlement Denial', 'Vault Settlement Avoidance', 'Liquidation Avoidance via Settlement', 'Settlement Blocking Attacks', 'Settlement Timing Manipulation', 'Settlement Requirement Bypass', 'Settlement Griefing via Revert', 'Settlement State Manipulation', 'Settlement Access Control Bypass', 'Settlement DoS Attacks', 'Settlement Front-Running', 'Settlement Parameter Manipulation', 'Settlement Validation Bypass', 'Settlement Ordering Attacks', 'Settlement State Corruption', 'Settlement Replay Attacks', 'Settlement Authorization Bypass', 'Settlement Logic Errors', 'Settlement Griefing via Gas Limit', etc.)."]
) -> str:
    """
    Build a settlement griefing security review prompt for Solidity functions handling settlements.

    Parameters:
        function_explanation (str): Intended settlement behavior, rejection handling, and griefing resistance.
        function_body (str): Exact settlement function code.
        file_path (str): Repo-relative path.
        settlement_context (str): Settlement type, requirements, rejection mechanisms, access control.
        list_of_settlement_griefing_threats (list[str]): Threats like settlement rejection, avoidance,
            blocking attacks, and liquidation avoidance.

    Output:
        str: Prompt targeting settlement griefing resistance with focus on protocol safety.
    """
    msg = f"""
SOLIDITY SETTLEMENT GRIEFING THREAT ANALYSIS REQUEST

Function Context:
- Settlement Griefing Purpose: {function_explanation}
- File Location: {file_path}
- Settlement Context: {settlement_context}
- Settlement Griefing Threats to Evaluate: {', '.join(list_of_settlement_griefing_threats)}

Solidity Settlement Griefing Source Code to Analyze:
{function_body}

Please perform a comprehensive Solidity settlement griefing security analysis focusing on the specified settlement griefing threats. Pay special attention to:
1. Ability to reject or deny account/vault settlements easily
2. Vault liquidation avoidance through settlement manipulation
3. Settlement blocking and DoS attack vectors
4. Settlement timing and ordering manipulation
5. Settlement requirement and validation bypass
6. Settlement state corruption and replay attacks

Provide detailed findings with settlement griefing-specific attack vector analysis, potential protocol safety impact, and remediation guidance specific to settlement griefing vulnerabilities and secure settlement design practices.
"""

    return msg


async def solidity_external_call_return_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solidity function does, its purpose in external call handling, and its role in the contract. Should include external calls, return value handling, call validation, and any external call-related behaviors."],
    function_body: Annotated[str, "The complete Solidity source code of the function including all statements, variable assignments, control flow, external calls, return value handling, and any nested logic. This is the actual Solidity code that will be analyzed for external call return vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/ExternalCall.sol', 'contracts/Integration.sol', 'contracts/Adapter.sol'). Used for context and reporting."], 
    external_call_context: Annotated[str, "Additional external call context including the external call types (e.g., ERC20 transfers, cToken operations, external protocol calls), return value expectations, call validation requirements, and critical external call operations this function handles."],
    list_of_external_call_return_threats: Annotated[list[str], "A comprehensive list of external call return-specific threats and vulnerabilities to check for during analysis. Each item should be a specific external call return threat type (e.g., 'Return Value Not Checked', 'Return Value Not Handled', 'Missing Return Value Validation', 'cToken Return Value Ignored', 'ERC20 Return Value Not Verified', 'External Call Success Assumed', 'Return Data Not Validated', 'Missing Approval Check', 'External Call Return Corruption', 'Return Value Type Mismatch', 'Missing Return Value in Conditional', 'External Call Failure Not Handled', 'Return Value Used Incorrectly', 'Missing Return Value Bounds Check', 'External Call Return Reentrancy', 'Return Value Manipulation', 'Missing Return Value in Loop', 'External Call Return DoS', 'Return Value Precision Loss', 'External Call Return Timing Issues', etc.)."]
) -> str:
    """
    Create an external call return value security review prompt for Solidity functions making external calls.

    Parameters:
        function_explanation (str): Intended external call behavior, return value handling, and validation.
        function_body (str): Exact function code with external calls.
        file_path (str): Repo-relative path.
        external_call_context (str): External call types, return value expectations, validation requirements.
        list_of_external_call_return_threats (list[str]): Threats like missing return checks, unhandled returns,
            validation failures, and return value misuse.

    Output:
        str: Prompt instructing LLM to validate external call safety and return value handling.
    """
    msg = f"""
SOLIDITY EXTERNAL CALL RETURN THREAT ANALYSIS REQUEST

Function Context:
- External Call Return Purpose: {function_explanation}
- File Location: {file_path}
- External Call Context: {external_call_context}
- External Call Return Threats to Evaluate: {', '.join(list_of_external_call_return_threats)}

Solidity External Call Return Source Code to Analyze:
{function_body}

Please perform a comprehensive Solidity external call return security analysis focusing on the specified external call return threats. Pay special attention to:
1. Missing checks for return values from external calls (e.g., cToken mint/redeem, ERC20 transfers)
2. Return values not being handled or validated properly
3. Assumption that external calls always succeed without checking returns
4. Missing approval checks before external calls requiring approvals
5. Return value type mismatches and incorrect usage
6. External call failures not being handled gracefully

Provide detailed findings with external call return-specific attack vector analysis, potential protocol failure scenarios, and remediation guidance specific to external call return vulnerabilities and secure external call handling practices.
"""

    return msg


async def solidity_money_market_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solidity money market function does, its purpose in money market integration, and its role in the contract. Should include money market operations, deposit/withdrawal mechanics, rebalancing, and any money market-related behaviors."],
    function_body: Annotated[str, "The complete Solidity source code of the money market function including all statements, variable assignments, control flow, money market calls, and any nested logic. This is the actual Solidity code that will be analyzed for money market vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/MoneyMarket.sol', 'contracts/CompoundIntegration.sol', 'contracts/Rebalance.sol'). Used for context and reporting."], 
    money_market_context: Annotated[str, "Additional money market context including the money market protocol (e.g., Compound, Aave, external protocols), integration type, rebalancing mechanisms, and critical money market operations this function handles."],
    list_of_money_market_threats: Annotated[list[str], "A comprehensive list of money market-specific threats and vulnerabilities to check for during analysis. Each item should be a specific money market threat type (e.g., 'Money Market Overwithdrawal', 'Incorrect Withdrawal Amount', 'Missing Money Market Approval', 'Money Market Rebalance Errors', 'Idle Funds Accounting Errors', 'Money Market Withdrawal Failures', 'Excess Funds Withdrawn', 'Money Market Deposit Errors', 'Rebalance Amount Incorrect', 'Money Market Return Value Not Handled', 'Money Market Integration Failures', 'Money Market State Inconsistency', 'Money Market Reentrancy', 'Money Market Slippage Issues', 'Money Market Liquidity Issues', 'Money Market Rate Manipulation', 'Money Market Withdrawal Timing', 'Money Market Accounting Errors', 'Money Market Protocol Changes', 'Money Market Integration DoS', etc.)."]
) -> str:
    """
    Build a money market integration security review prompt for Solidity functions integrating with external money markets.

    Parameters:
        function_explanation (str): Intended money market behavior, integration patterns, and rebalancing logic.
        function_body (str): Exact money market function code.
        file_path (str): Repo-relative path.
        money_market_context (str): Money market protocol, integration type, rebalancing mechanisms.
        list_of_money_market_threats (list[str]): Threats like overwithdrawal, accounting errors,
            integration failures, and rebalance issues.

    Output:
        str: Prompt targeting money market integration safety with focus on fund management correctness.
    """
    msg = f"""
SOLIDITY MONEY MARKET THREAT ANALYSIS REQUEST

Function Context:
- Money Market Purpose: {function_explanation}
- File Location: {file_path}
- Money Market Context: {money_market_context}
- Money Market Threats to Evaluate: {', '.join(list_of_money_market_threats)}

Solidity Money Market Source Code to Analyze:
{function_body}

Please perform a comprehensive Solidity money market security analysis focusing on the specified money market threats. Pay special attention to:
1. Overwithdrawal from money markets causing excess funds or accounting errors
2. Incorrect withdrawal amounts and rebalance calculations
3. Missing approvals for money market operations
4. Idle funds accounting errors during money market operations
5. Money market return values not being handled properly
6. Money market integration failures and state inconsistencies

Provide detailed findings with money market-specific attack vector analysis, potential fund loss scenarios, and remediation guidance specific to money market vulnerabilities and secure money market integration practices.
"""

    return msg


async def solidity_cross_chain_gas_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solidity cross-chain function does, its purpose in cross-chain operations, and its role in the contract. Should include cross-chain messaging, gas estimation, withdrawal finalization, and any cross-chain-related behaviors."],
    function_body: Annotated[str, "The complete Solidity source code of the cross-chain function including all statements, variable assignments, control flow, gas calculations, and any nested logic. This is the actual Solidity code that will be analyzed for cross-chain gas vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/CrossChain.sol', 'contracts/Bridge.sol', 'contracts/Messenger.sol'). Used for context and reporting."], 
    cross_chain_gas_context: Annotated[str, "Additional cross-chain gas context including the cross-chain mechanism (e.g., Optimism, Arbitrum, L2 bridges), gas estimation methods, withdrawal finalization, and critical cross-chain gas operations this function handles."],
    list_of_cross_chain_gas_threats: Annotated[list[str], "A comprehensive list of cross-chain gas-specific threats and vulnerabilities to check for during analysis. Each item should be a specific cross-chain gas threat type (e.g., 'Incorrect Gas Estimation', 'Gas Left Check Inaccurate', 'Cross-Chain Message Gas Insufficient', 'Withdrawal Gas Limit Issues', 'EIP-150 Gas Logic Errors', 'Gas Estimation Not Accurate', 'Cross-Chain Call Gas Mismatch', 'Withdrawal Finalization Gas Issues', 'Gas Limit Bricking Attacks', 'Cross-Chain Gas DoS', 'Gas Estimation Manipulation', 'Withdrawal Gas Permanently Locked', 'Cross-Chain Message Gas Exhaustion', 'Gas Estimation Timing Issues', 'Withdrawal Gas Limit Too Low', 'Cross-Chain Gas Calculation Errors', 'Gas Left Estimation Failures', 'Withdrawal Gas Limit Manipulation', 'Cross-Chain Gas Griefing', 'Gas Estimation Precision Loss', etc.)."]
) -> str:
    """
    Create a cross-chain gas estimation security review prompt for Solidity functions handling cross-chain operations.

    Parameters:
        function_explanation (str): Intended cross-chain behavior, gas estimation, and withdrawal handling.
        function_body (str): Exact cross-chain function code.
        file_path (str): Repo-relative path.
        cross_chain_gas_context (str): Cross-chain mechanism, gas estimation methods, withdrawal finalization.
        list_of_cross_chain_gas_threats (list[str]): Threats like incorrect gas estimation, gas limit issues,
            withdrawal bricking, and gas calculation errors.

    Output:
        str: Prompt instructing LLM to validate cross-chain gas safety and withdrawal reliability.
    """
    msg = f"""
SOLIDITY CROSS-CHAIN GAS THREAT ANALYSIS REQUEST

Function Context:
- Cross-Chain Gas Purpose: {function_explanation}
- File Location: {file_path}
- Cross-Chain Gas Context: {cross_chain_gas_context}
- Cross-Chain Gas Threats to Evaluate: {', '.join(list_of_cross_chain_gas_threats)}

Solidity Cross-Chain Gas Source Code to Analyze:
{function_body}

Please perform a comprehensive Solidity cross-chain gas security analysis focusing on the specified cross-chain gas threats. Pay special attention to:
1. Incorrect gas estimation for cross-chain messages leading to insufficient gas
2. Gas left checks that are inaccurate or fail to account for EIP-150 logic
3. Withdrawal gas limits that can be bricked, permanently locking funds
4. Cross-chain message calls with less gas than anticipated by sender
5. Gas estimation manipulation and griefing attacks
6. Withdrawal finalization gas issues causing permanent fund locks

Provide detailed findings with cross-chain gas-specific attack vector analysis, potential fund lock scenarios, and remediation guidance specific to cross-chain gas vulnerabilities and secure cross-chain gas handling practices.
"""

    return msg


async def solidity_debt_reporting_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solidity debt reporting function does, its purpose in debt tracking and reporting, and its role in the contract. Should include debt calculation, debt updates, selective reporting, and any debt reporting-related behaviors."],
    function_body: Annotated[str, "The complete Solidity source code of the debt reporting function including all statements, variable assignments, control flow, debt calculations, and any nested logic. This is the actual Solidity code that will be analyzed for debt reporting vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/DebtReporting.sol', 'contracts/Vault.sol', 'contracts/Accounting.sol'). Used for context and reporting."], 
    debt_reporting_context: Annotated[str, "Additional debt reporting context including the debt reporting mechanism (e.g., vault debt, destination vault debt), update mechanisms, selective reporting, and critical debt reporting operations this function handles."],
    list_of_debt_reporting_threats: Annotated[list[str], "A comprehensive list of debt reporting-specific threats and vulnerabilities to check for during analysis. Each item should be a specific debt reporting threat type (e.g., 'Selective Debt Reporting', 'Debt Reporting Manipulation', 'Debt Update Front-Running', 'Selective Vault Debt Updates', 'Debt Reporting Profit Theft', 'Debt Loss Ignored in Reporting', 'Debt Reporting Timing Attacks', 'Selective Destination Vault Updates', 'Debt Reporting Fee Manipulation', 'Debt Reporting State Corruption', 'Debt Reporting Access Control', 'Debt Reporting Ordering Issues', 'Debt Reporting Calculation Errors', 'Debt Reporting Bypass', 'Debt Reporting Reentrancy', 'Debt Reporting DoS', 'Debt Reporting Validation Errors', 'Debt Reporting Precision Loss', 'Debt Reporting Front-Running', 'Debt Reporting State Inconsistency', etc.)."]
) -> str:
    """
    Build a debt reporting security review prompt for Solidity functions handling debt tracking and reporting.

    Parameters:
        function_explanation (str): Intended debt reporting behavior, update mechanisms, and selective reporting prevention.
        function_body (str): Exact debt reporting function code.
        file_path (str): Repo-relative path.
        debt_reporting_context (str): Debt reporting mechanism, update mechanisms, selective reporting risks.
        list_of_debt_reporting_threats (list[str]): Threats like selective reporting, manipulation,
            front-running, and fee theft.

    Output:
        str: Prompt targeting debt reporting correctness with focus on economic safety.
    """
    msg = f"""
SOLIDITY DEBT REPORTING THREAT ANALYSIS REQUEST

Function Context:
- Debt Reporting Purpose: {function_explanation}
- File Location: {file_path}
- Debt Reporting Context: {debt_reporting_context}
- Debt Reporting Threats to Evaluate: {', '.join(list_of_debt_reporting_threats)}

Solidity Debt Reporting Source Code to Analyze:
{function_body}

Please perform a comprehensive Solidity debt reporting security analysis focusing on the specified debt reporting threats. Pay special attention to:
1. Selective debt reporting allowing only profitable vaults to be updated
2. Debt reporting manipulation to collect fees on profits while ignoring losses
3. Front-running debt reporting updates to gain profits or steal funds
4. Selective destination vault updates causing unfair fee distribution
5. Debt reporting timing attacks and ordering manipulation
6. Debt reporting state corruption and inconsistency

Provide detailed findings with debt reporting-specific attack vector analysis, potential economic manipulation scenarios, and remediation guidance specific to debt reporting vulnerabilities and secure debt reporting practices.
"""

    return msg
