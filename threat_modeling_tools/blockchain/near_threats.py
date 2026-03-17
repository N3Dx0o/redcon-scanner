from typing import Annotated


async def near_general_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the NEAR function does, its purpose in the NEAR protocol ecosystem, and its role in the application. Should include NEAR-specific operations, smart contract development, and any NEAR-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the NEAR function including all statements, variable assignments, control flow, function calls, NEAR operations, and any nested logic. This is the actual NEAR code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/near_contract.rs', 'src/near/account_manager.js', 'app/near/transaction_handler.py'). Used for context and reporting."], 
    near_context: Annotated[str, "Additional NEAR context including the component type (e.g., smart contract, account, transaction, block), NEAR version, and critical NEAR operations this function handles."],
    list_of_near_threats: Annotated[list[str], "A comprehensive list of NEAR-specific threats and vulnerabilities to check for during analysis. Each item should be a specific NEAR threat type (e.g., 'NEAR Account Vulnerabilities', 'NEAR Contract Vulnerabilities', 'NEAR Transaction Vulnerabilities', 'NEAR Block Vulnerabilities', 'NEAR Storage Vulnerabilities', 'NEAR Event Vulnerabilities', 'NEAR Call Vulnerabilities', 'NEAR Origin Vulnerabilities', 'NEAR Weight Vulnerabilities', 'NEAR Fee Vulnerabilities', 'NEAR Gas Vulnerabilities', 'NEAR Consensus Vulnerabilities', 'NEAR Finality Vulnerabilities', 'NEAR Slashing Vulnerabilities', 'NEAR Staking Vulnerabilities', 'NEAR Governance Vulnerabilities', 'NEAR Treasury Vulnerabilities', 'NEAR Democracy Vulnerabilities', 'NEAR Council Vulnerabilities', 'NEAR Technical Committee Vulnerabilities', 'NEAR Referendum Vulnerabilities', 'NEAR Proposal Vulnerabilities', 'NEAR Voting Vulnerabilities', 'NEAR Delegation Vulnerabilities', 'NEAR Bonding Vulnerabilities', 'NEAR Unbonding Vulnerabilities', 'NEAR Validator Vulnerabilities', 'NEAR Nominator Vulnerabilities', 'NEAR Era Vulnerabilities', 'NEAR Session Vulnerabilities', 'NEAR Epoch Vulnerabilities', 'NEAR Slot Vulnerabilities', 'NEAR Block Production Vulnerabilities', 'NEAR Block Import Vulnerabilities', 'NEAR Block Validation Vulnerabilities', 'NEAR Block Finalization Vulnerabilities', 'NEAR Block Reorganization Vulnerabilities', 'NEAR Block Fork Vulnerabilities', 'NEAR Block Chain Vulnerabilities', 'NEAR Block State Vulnerabilities', 'NEAR Block Storage Vulnerabilities', 'NEAR Block Memory Vulnerabilities', 'NEAR Block Network Vulnerabilities', 'NEAR Block Consensus Vulnerabilities', 'NEAR Block Finality Vulnerabilities', 'NEAR Block Slashing Vulnerabilities', 'NEAR Block Staking Vulnerabilities', 'NEAR Block Governance Vulnerabilities', 'NEAR Block Treasury Vulnerabilities', 'NEAR Block Democracy Vulnerabilities', 'NEAR Block Council Vulnerabilities', 'NEAR Block Technical Committee Vulnerabilities', 'NEAR Block Referendum Vulnerabilities', 'NEAR Block Proposal Vulnerabilities', 'NEAR Block Voting Vulnerabilities', 'NEAR Block Delegation Vulnerabilities', 'NEAR Block Bonding Vulnerabilities', 'NEAR Block Unbonding Vulnerabilities', 'NEAR Block Validator Vulnerabilities', 'NEAR Block Nominator Vulnerabilities', 'NEAR Block Era Vulnerabilities', 'NEAR Block Session Vulnerabilities', 'NEAR Block Epoch Vulnerabilities', 'NEAR Block Slot Vulnerabilities', 'NEAR Block Production Vulnerabilities', 'NEAR Block Import Vulnerabilities', 'NEAR Block Validation Vulnerabilities', 'NEAR Block Finalization Vulnerabilities', 'NEAR Block Reorganization Vulnerabilities', 'NEAR Block Fork Vulnerabilities', 'NEAR Block Chain Vulnerabilities', 'NEAR Block State Vulnerabilities', 'NEAR Block Storage Vulnerabilities', 'NEAR Block Memory Vulnerabilities', 'NEAR Block Network Vulnerabilities', etc.)."]
) -> str:
    """
    Generate an LLM-ready prompt for analyzing NEAR contract code.

    Parameters:
        function_explanation (str): Purpose, expected pre/post-conditions, and invariants.
        function_body (str): Full source of the function under review.
        file_path (str): Repo-relative path.
        near_context (str): Contract type, gas/economics, storage model, cross-contract calls.
        list_of_near_threats (list[str]): Threats like reentrancy via callbacks, storage refunds,
            cross-contract call safety, access control, input validation, and state consistency.

    Output:
        str: Prompt asking for specific findings, examples, and actionable fixes with references.
    """
    msg = f"""
NEAR GENERAL THREAT ANALYSIS REQUEST

Function Context:
- NEAR Purpose: {function_explanation}
- File Location: {file_path}
- NEAR Context: {near_context}
- NEAR Threats to Evaluate: {', '.join(list_of_near_threats)}

NEAR Source Code to Analyze:
{function_body}

Please perform a comprehensive NEAR security analysis focusing on the specified threats and provide detailed findings with NEAR-specific attack vector analysis, potential NEAR impact, and remediation guidance specific to NEAR vulnerabilities and secure NEAR development practices.
"""

    return msg


async def near_contract_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the NEAR contract function does, its purpose in smart contract development, and its role in the NEAR protocol. Should include contract operations, state management, and any contract-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the NEAR contract function including all statements, variable assignments, control flow, function calls, contract operations, and any nested logic. This is the actual NEAR contract code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/near_contract.rs', 'contracts/token_contract.rs', 'contracts/governance_contract.rs'). Used for context and reporting."], 
    contract_context: Annotated[str, "Additional NEAR contract context including the contract type (e.g., token, governance, staking, treasury), contract dependencies, and critical contract operations this function handles."],
    list_of_contract_threats: Annotated[list[str], "A comprehensive list of NEAR contract-specific threats and vulnerabilities to check for during analysis. Each item should be a specific contract threat type (e.g., 'Contract Storage Vulnerabilities', 'Contract Call Vulnerabilities', 'Contract Event Vulnerabilities', 'Contract Origin Vulnerabilities', 'Contract Weight Vulnerabilities', 'Contract Fee Vulnerabilities', 'Contract Gas Vulnerabilities', 'Contract Logic Vulnerabilities', 'Contract Validation Vulnerabilities', 'Contract Authorization Vulnerabilities', 'Contract Authentication Vulnerabilities', 'Contract Access Control Vulnerabilities', 'Contract Session Management Vulnerabilities', 'Contract Input Validation Vulnerabilities', 'Contract Output Encoding Vulnerabilities', 'Contract Error Handling Vulnerabilities', 'Contract Logging Vulnerabilities', 'Contract Monitoring Vulnerabilities', 'Contract Auditing Vulnerabilities', 'Contract Reporting Vulnerabilities', 'Contract Analytics Vulnerabilities', 'Contract Mining Vulnerabilities', 'Contract Machine Learning Vulnerabilities', 'Contract AI Vulnerabilities', 'Contract Algorithm Vulnerabilities', 'Contract Model Vulnerabilities', 'Contract Training Vulnerabilities', 'Contract Testing Vulnerabilities', 'Contract Validation Vulnerabilities', 'Contract Cross-Validation Vulnerabilities', 'Contract Overfitting Vulnerabilities', 'Contract Underfitting Vulnerabilities', 'Contract Bias Vulnerabilities', 'Contract Fairness Vulnerabilities', 'Contract Discrimination Vulnerabilities', etc.)."]
) -> str:
    """
    Create a NEAR contract-specific review prompt for LLMs.

    Parameters:
        function_explanation (str): Intended behavior and invariants.
        function_body (str): Exact function code.
        file_path (str): Repo-relative path.
        contract_context (str): Access control, callbacks, storage accounting, gas budgeting.
        list_of_contract_threats (list[str]): Storage consistency, cross-contract call ordering,
            access control, panic/unwind safety, input validation.

    Output:
        str: Prompt requesting concrete findings, exploit paths, and code-level remediations.
    """
    msg = f"""
NEAR CONTRACT THREAT ANALYSIS REQUEST

Function Context:
- Contract Purpose: {function_explanation}
- File Location: {file_path}
- Contract Context: {contract_context}
- Contract Threats to Evaluate: {', '.join(list_of_contract_threats)}

NEAR Contract Source Code to Analyze:
{function_body}

Please perform a comprehensive NEAR contract security analysis focusing on the specified threats and provide detailed findings with contract-specific attack vector analysis, potential contract impact, and remediation guidance specific to NEAR contract vulnerabilities and secure contract development practices.
"""

    return msg


async def near_account_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the NEAR account function does, its purpose in account management, and its role in the NEAR protocol. Should include account operations, account validation, and any account-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the NEAR account function including all statements, variable assignments, control flow, function calls, account operations, and any nested logic. This is the actual NEAR account code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/account_manager.rs', 'src/near/account_validation.js', 'app/near/account_handler.py'). Used for context and reporting."], 
    account_context: Annotated[str, "Additional NEAR account context including the account type (e.g., user account, contract account, system account), account permissions, and critical account operations this function handles."],
    list_of_account_threats: Annotated[list[str], "A comprehensive list of NEAR account-specific threats and vulnerabilities to check for during analysis. Each item should be a specific account threat type (e.g., 'Account Ownership Bypass', 'Account Data Manipulation', 'Account Size Attacks', 'Account Rent Exemption Attacks', 'Account Lamport Manipulation', 'Account Executable Flag Attacks', 'Account Signer Validation Bypass', 'Account Writable Flag Attacks', 'Account Delegate Attacks', 'Account Close Attacks', 'Account Transfer Attacks', 'Account Allocate Attacks', 'Account Assign Attacks', 'Account Create Attacks', 'Account Initialize Attacks', 'Account Upgrade Attacks', 'Account Migration Attacks', 'Account Versioning Attacks', 'Account Compatibility Attacks', 'Account Interoperability Attacks', 'Account Standardization Attacks', 'Account Compliance Attacks', 'Account Certification Attacks', 'Account Validation Attacks', 'Account Testing Attacks', 'Account Debugging Attacks', 'Account Monitoring Attacks', 'Account Logging Attacks', 'Account Auditing Attacks', 'Account Reporting Attacks', 'Account Analytics Attacks', 'Account Mining Attacks', 'Account Machine Learning Attacks', 'Account AI Attacks', 'Account Algorithm Attacks', 'Account Model Attacks', 'Account Training Attacks', 'Account Testing Attacks', 'Account Validation Attacks', 'Account Cross-Validation Attacks', 'Account Overfitting Attacks', 'Account Underfitting Attacks', 'Account Bias Attacks', 'Account Fairness Attacks', 'Account Discrimination Attacks', etc.)."]
) -> str:
    """
    Prepare a prompt focused on NEAR account semantics and safety.

    Parameters:
        function_explanation (str): Ownership, permissions, and lifecycle expectations.
        function_body (str): Exact function code.
        file_path (str): Repo-relative path.
        account_context (str): Account categories, permission model, storage/gas nuances.
        list_of_account_threats (list[str]): Ownership/signature checks, size/rent rules,
            account closing/transfers, data bounds, migration/versioning.

    Output:
        str: Prompt targeting concrete, actionable findings with references and remediations.
    """
    msg = f"""
NEAR ACCOUNT THREAT ANALYSIS REQUEST

Function Context:
- Account Purpose: {function_explanation}
- File Location: {file_path}
- Account Context: {account_context}
- Account Threats to Evaluate: {', '.join(list_of_account_threats)}

NEAR Account Source Code to Analyze:
{function_body}

Please perform a comprehensive NEAR account security analysis focusing on the specified threats and provide detailed findings with account-specific attack vector analysis, potential account impact, and remediation guidance specific to NEAR account vulnerabilities and secure account management practices.
"""

    return msg
