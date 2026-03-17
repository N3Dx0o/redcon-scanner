from typing import Annotated


async def solana_general_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solana function does, its purpose in the Solana ecosystem, and its role in the application. Should include Solana-specific operations, account management, and any Solana-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the Solana function including all statements, variable assignments, control flow, function calls, Solana operations, and any nested logic. This is the actual Solana code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'programs/solana_program.rs', 'src/solana/account_manager.js', 'app/solana/transaction_handler.py'). Used for context and reporting."], 
    solana_context: Annotated[str, "Additional Solana context including the program type (e.g., SPL Token, DeFi, NFT, GameFi), account types used, and critical Solana operations this function handles."],
    list_of_solana_threats: Annotated[list[str], "A comprehensive list of Solana-specific threats and vulnerabilities to check for during analysis. Each item should be a specific Solana threat type (e.g., 'Solana Account Vulnerabilities', 'Solana Program Vulnerabilities', 'Solana Transaction Vulnerabilities', 'Solana Instruction Vulnerabilities', 'Solana Cross-Program Invocation Issues', 'Solana Rent Exemption Issues', 'Solana Account Size Issues', 'Solana Account Ownership Issues', 'Solana Account Data Issues', 'Solana Account Lamports Issues', 'Solana Account Executable Issues', 'Solana Account Signer Issues', 'Solana Account Writable Issues', 'Solana Account Delegate Issues', 'Solana Account Close Issues', 'Solana Account Transfer Issues', 'Solana Account Allocate Issues', 'Solana Account Assign Issues', 'Solana Account Create Issues', 'Solana Account Initialize Issues', 'Solana Account Upgrade Issues', 'Solana Account Migration Issues', 'Solana Account Versioning Issues', 'Solana Account Compatibility Issues', 'Solana Account Interoperability Issues', 'Solana Account Standardization Issues', 'Solana Account Compliance Issues', 'Solana Account Certification Issues', 'Solana Account Validation Issues', 'Solana Account Testing Issues', 'Solana Account Debugging Issues', 'Solana Account Monitoring Issues', 'Solana Account Logging Issues', 'Solana Account Auditing Issues', 'Solana Account Reporting Issues', 'Solana Account Analytics Issues', 'Solana Account Mining Issues', 'Solana Account Machine Learning Issues', 'Solana Account AI Issues', 'Solana Account Algorithm Issues', 'Solana Account Model Issues', 'Solana Account Training Issues', 'Solana Account Testing Issues', 'Solana Account Validation Issues', 'Solana Account Cross-Validation Issues', 'Solana Account Overfitting Issues', 'Solana Account Underfitting Issues', 'Solana Account Bias Issues', 'Solana Account Fairness Issues', 'Solana Account Discrimination Issues', etc.)."]
) -> str:
    """
    Compose an LLM prompt to review Solana code against explicit threat categories.

    Parameters:
        function_explanation (str): Purpose, accounts touched, invariants, and expected signers.
        function_body (str): Exact program function code (Rust/other) under review.
        file_path (str): Repo-relative path to the code.
        solana_context (str): Program type, CPI usage, sysvars, rent, account models, serialization.
        list_of_solana_threats (list[str]): Specific checks (account ownership/writable/signer,
            account size/initialization, CPI safety, instruction/data validation, rent exemptions).

    Output:
        str: Prompt instructing the LLM to produce findings with references and fixes.

    LLM guidance:
        - Validate account metas (writable/signer) and ownership assertions.
        - Check serialization/deserialization (borsh) safety and bounds.
        - Confirm rent and size constraints; avoid account data overflows.
        - Review CPI invariants and re-entrancy-like patterns.
    """
    msg = f"""
SOLANA GENERAL THREAT ANALYSIS REQUEST

Function Context:
- Solana Purpose: {function_explanation}
- File Location: {file_path}
- Solana Context: {solana_context}
- Solana Threats to Evaluate: {', '.join(list_of_solana_threats)}

Solana Source Code to Analyze:
{function_body}

Please perform a comprehensive Solana security analysis focusing on the specified threats and provide detailed findings with Solana-specific attack vector analysis, potential Solana impact, and remediation guidance specific to Solana vulnerabilities and secure Solana development practices.
"""

    return msg


async def solana_account_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solana account function does, its purpose in account management, and its role in the Solana program. Should include account operations, account validation, and any account-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the Solana account function including all statements, variable assignments, control flow, function calls, account operations, and any nested logic. This is the actual Solana account code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'programs/account_manager.rs', 'src/solana/account_validation.js', 'app/solana/account_handler.py'). Used for context and reporting."], 
    account_context: Annotated[str, "Additional Solana account context including the account type (e.g., system account, program account, token account), account data structure, and critical account operations this function handles."],
    list_of_account_threats: Annotated[list[str], "A comprehensive list of Solana account-specific threats and vulnerabilities to check for during analysis. Each item should be a specific account threat type (e.g., 'Account Ownership Bypass', 'Account Data Manipulation', 'Account Size Attacks', 'Account Rent Exemption Attacks', 'Account Lamport Manipulation', 'Account Executable Flag Attacks', 'Account Signer Validation Bypass', 'Account Writable Flag Attacks', 'Account Delegate Attacks', 'Account Close Attacks', 'Account Transfer Attacks', 'Account Allocate Attacks', 'Account Assign Attacks', 'Account Create Attacks', 'Account Initialize Attacks', 'Account Upgrade Attacks', 'Account Migration Attacks', 'Account Versioning Attacks', 'Account Compatibility Attacks', 'Account Interoperability Attacks', 'Account Standardization Attacks', 'Account Compliance Attacks', 'Account Certification Attacks', 'Account Validation Attacks', 'Account Testing Attacks', 'Account Debugging Attacks', 'Account Monitoring Attacks', 'Account Logging Attacks', 'Account Auditing Attacks', 'Account Reporting Attacks', 'Account Analytics Attacks', 'Account Mining Attacks', 'Account Machine Learning Attacks', 'Account AI Attacks', 'Account Algorithm Attacks', 'Account Model Attacks', 'Account Training Attacks', 'Account Testing Attacks', 'Account Validation Attacks', 'Account Cross-Validation Attacks', 'Account Overfitting Attacks', 'Account Underfitting Attacks', 'Account Bias Attacks', 'Account Fairness Attacks', 'Account Discrimination Attacks', etc.)."]
) -> str:
    """
    Build a prompt to validate Solana account handling and invariants.

    Parameters:
        function_explanation (str): Expected account states and transitions.
        function_body (str): Exact function code.
        file_path (str): Repo-relative path.
        account_context (str): Account types, ownership, seeds/PDAs, rent rules.
        list_of_account_threats (list[str]): Ownership checks, signer/writable flags, size/zero-init,
            rent exemption, close/transfer semantics, data bounds, seed derivations.

    Output:
        str: Prompt for LLM to report findings with remediation.
    """
    msg = f"""
SOLANA ACCOUNT THREAT ANALYSIS REQUEST

Function Context:
- Account Purpose: {function_explanation}
- File Location: {file_path}
- Account Context: {account_context}
- Account Threats to Evaluate: {', '.join(list_of_account_threats)}

Solana Account Source Code to Analyze:
{function_body}

Please perform a comprehensive Solana account security analysis focusing on the specified threats and provide detailed findings with account-specific attack vector analysis, potential account impact, and remediation guidance specific to Solana account vulnerabilities and secure account management practices.
"""

    return msg


async def solana_program_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Solana program function does, its purpose in program execution, and its role in the Solana program. Should include program operations, instruction handling, and any program-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the Solana program function including all statements, variable assignments, control flow, function calls, program operations, and any nested logic. This is the actual Solana program code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'programs/solana_program.rs', 'src/solana/program_handler.js', 'app/solana/program_executor.py'). Used for context and reporting."], 
    program_context: Annotated[str, "Additional Solana program context including the program type (e.g., SPL Token, DeFi, NFT, GameFi), program architecture, and critical program operations this function handles."],
    list_of_program_threats: Annotated[list[str], "A comprehensive list of Solana program-specific threats and vulnerabilities to check for during analysis. Each item should be a specific program threat type (e.g., 'Program Execution Vulnerabilities', 'Instruction Processing Vulnerabilities', 'Cross-Program Invocation Vulnerabilities', 'Program Data Vulnerabilities', 'Program State Vulnerabilities', 'Program Logic Vulnerabilities', 'Program Validation Vulnerabilities', 'Program Authorization Vulnerabilities', 'Program Authentication Vulnerabilities', 'Program Access Control Vulnerabilities', 'Program Session Management Vulnerabilities', 'Program Input Validation Vulnerabilities', 'Program Output Encoding Vulnerabilities', 'Program Error Handling Vulnerabilities', 'Program Logging Vulnerabilities', 'Program Monitoring Vulnerabilities', 'Program Auditing Vulnerabilities', 'Program Reporting Vulnerabilities', 'Program Analytics Vulnerabilities', 'Program Mining Vulnerabilities', 'Program Machine Learning Vulnerabilities', 'Program AI Vulnerabilities', 'Program Algorithm Vulnerabilities', 'Program Model Vulnerabilities', 'Program Training Vulnerabilities', 'Program Testing Vulnerabilities', 'Program Validation Vulnerabilities', 'Program Cross-Validation Vulnerabilities', 'Program Overfitting Vulnerabilities', 'Program Underfitting Vulnerabilities', 'Program Bias Vulnerabilities', 'Program Fairness Vulnerabilities', 'Program Discrimination Vulnerabilities', etc.)."]
) -> str:
    """
    Create a program-level Solana analysis prompt for LLM review.

    Parameters:
        function_explanation (str): Instruction handling, constraints, and safety properties.
        function_body (str): Full source of the handler/dispatcher.
        file_path (str): Repo-relative path.
        program_context (str): CPI usage, sysvars, constraints framework, deserialization rules.
        list_of_program_threats (list[str]): Execution flow validation, CPI invariants, data validation,
            authorization, logging/auditing, and error propagation.

    Output:
        str: Prompt instructing the LLM to return findings with references and actionable fixes.
    """
    msg = f"""
SOLANA PROGRAM THREAT ANALYSIS REQUEST

Function Context:
- Program Purpose: {function_explanation}
- File Location: {file_path}
- Program Context: {program_context}
- Program Threats to Evaluate: {', '.join(list_of_program_threats)}

Solana Program Source Code to Analyze:
{function_body}

Please perform a comprehensive Solana program security analysis focusing on the specified threats and provide detailed findings with program-specific attack vector analysis, potential program impact, and remediation guidance specific to Solana program vulnerabilities and secure program development practices.
"""

    return msg
