from typing import Annotated


async def avalanche_general_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Avalanche function does, its purpose in the Avalanche ecosystem, and its role in the application. Should include Avalanche-specific operations, subnet development, and any Avalanche-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the Avalanche function including all statements, variable assignments, control flow, function calls, Avalanche operations, and any nested logic. This is the actual Avalanche code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'subnets/avalanche_subnet.go', 'src/avalanche/vm_handler.js', 'app/avalanche/transaction_processor.py'). Used for context and reporting."], 
    avalanche_context: Annotated[str, "Additional Avalanche context including the component type (e.g., subnet, VM, chain), Avalanche version, and critical Avalanche operations this function handles."],
    list_of_avalanche_threats: Annotated[list[str], "A comprehensive list of Avalanche-specific threats and vulnerabilities to check for during analysis. Each item should be a specific Avalanche threat type (e.g., 'Avalanche Subnet Vulnerabilities', 'Avalanche VM Vulnerabilities', 'Avalanche Chain Vulnerabilities', 'Avalanche Consensus Vulnerabilities', 'Avalanche Snowball Vulnerabilities', 'Avalanche Snowman Vulnerabilities', 'Avalanche AvalancheGo Vulnerabilities', 'Avalanche P-Chain Vulnerabilities', 'Avalanche X-Chain Vulnerabilities', 'Avalanche C-Chain Vulnerabilities', 'Avalanche Validator Vulnerabilities', 'Avalanche Delegator Vulnerabilities', 'Avalanche Staking Vulnerabilities', 'Avalanche Governance Vulnerabilities', 'Avalanche Treasury Vulnerabilities', 'Avalanche Cross-Chain Vulnerabilities', 'Avalanche Bridge Vulnerabilities', 'Avalanche Asset Vulnerabilities', 'Avalanche Transaction Vulnerabilities', 'Avalanche Block Vulnerabilities', 'Avalanche Network Vulnerabilities', 'Avalanche Security Vulnerabilities', 'Avalanche Access Control Vulnerabilities', 'Avalanche Authentication Vulnerabilities', 'Avalanche Authorization Vulnerabilities', 'Avalanche Session Management Vulnerabilities', 'Avalanche Input Validation Vulnerabilities', 'Avalanche Output Encoding Vulnerabilities', 'Avalanche Error Handling Vulnerabilities', 'Avalanche Logging Vulnerabilities', 'Avalanche Monitoring Vulnerabilities', 'Avalanche Auditing Vulnerabilities', 'Avalanche Reporting Vulnerabilities', 'Avalanche Analytics Vulnerabilities', 'Avalanche Mining Vulnerabilities', 'Avalanche Machine Learning Vulnerabilities', 'Avalanche AI Vulnerabilities', 'Avalanche Algorithm Vulnerabilities', 'Avalanche Model Vulnerabilities', 'Avalanche Training Vulnerabilities', 'Avalanche Testing Vulnerabilities', 'Avalanche Validation Vulnerabilities', 'Avalanche Cross-Validation Vulnerabilities', 'Avalanche Overfitting Vulnerabilities', 'Avalanche Underfitting Vulnerabilities', 'Avalanche Bias Vulnerabilities', 'Avalanche Fairness Vulnerabilities', 'Avalanche Discrimination Vulnerabilities', etc.)."]
) -> str:
    """
    Build an Avalanche-focused prompt for subnet/chain/VM code review.

    Parameters:
        function_explanation (str): Purpose and invariants.
        function_body (str): Exact code under review.
        file_path (str): Repo-relative path.
        avalanche_context (str): Subnet/VM type, Snow/Snowball/Snowman usage, chain config.
        list_of_avalanche_threats (list[str]): Validator set mgmt, consensus safety/liveness,
            cross-chain bridges, fee/gas/accounting, network partitions.

    Output:
        str: Prompt asking LLM for concrete findings and fixes with references.
    """
    msg = f"""
AVALANCHE GENERAL THREAT ANALYSIS REQUEST

Function Context:
- Avalanche Purpose: {function_explanation}
- File Location: {file_path}
- Avalanche Context: {avalanche_context}
- Avalanche Threats to Evaluate: {', '.join(list_of_avalanche_threats)}

Avalanche Source Code to Analyze:
{function_body}

Please perform a comprehensive Avalanche security analysis focusing on the specified threats and provide detailed findings with Avalanche-specific attack vector analysis, potential Avalanche impact, and remediation guidance specific to Avalanche vulnerabilities and secure Avalanche development practices.
"""

    return msg


async def avalanche_subnet_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Avalanche subnet function does, its purpose in subnet management, and its role in the Avalanche ecosystem. Should include subnet operations, VM management, and any subnet-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the Avalanche subnet function including all statements, variable assignments, control flow, function calls, subnet operations, and any nested logic. This is the actual Avalanche subnet code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'subnets/custom_subnet.go', 'src/avalanche/subnet_manager.js', 'app/avalanche/subnet_handler.py'). Used for context and reporting."], 
    subnet_context: Annotated[str, "Additional Avalanche subnet context including the subnet type (e.g., custom VM, EVM, custom consensus), subnet configuration, and critical subnet operations this function handles."],
    list_of_subnet_threats: Annotated[list[str], "A comprehensive list of Avalanche subnet-specific threats and vulnerabilities to check for during analysis. Each item should be a specific subnet threat type (e.g., 'Subnet Configuration Vulnerabilities', 'Subnet VM Vulnerabilities', 'Subnet Consensus Vulnerabilities', 'Subnet Validator Vulnerabilities', 'Subnet Delegator Vulnerabilities', 'Subnet Staking Vulnerabilities', 'Subnet Governance Vulnerabilities', 'Subnet Treasury Vulnerabilities', 'Subnet Cross-Chain Vulnerabilities', 'Subnet Bridge Vulnerabilities', 'Subnet Asset Vulnerabilities', 'Subnet Transaction Vulnerabilities', 'Subnet Block Vulnerabilities', 'Subnet Network Vulnerabilities', 'Subnet Security Vulnerabilities', 'Subnet Access Control Vulnerabilities', 'Subnet Authentication Vulnerabilities', 'Subnet Authorization Vulnerabilities', 'Subnet Session Management Vulnerabilities', 'Subnet Input Validation Vulnerabilities', 'Subnet Output Encoding Vulnerabilities', 'Subnet Error Handling Vulnerabilities', 'Subnet Logging Vulnerabilities', 'Subnet Monitoring Vulnerabilities', 'Subnet Auditing Vulnerabilities', 'Subnet Reporting Vulnerabilities', 'Subnet Analytics Vulnerabilities', 'Subnet Mining Vulnerabilities', 'Subnet Machine Learning Vulnerabilities', 'Subnet AI Vulnerabilities', 'Subnet Algorithm Vulnerabilities', 'Subnet Model Vulnerabilities', 'Subnet Training Vulnerabilities', 'Subnet Testing Vulnerabilities', 'Subnet Validation Vulnerabilities', 'Subnet Cross-Validation Vulnerabilities', 'Subnet Overfitting Vulnerabilities', 'Subnet Underfitting Vulnerabilities', 'Subnet Bias Vulnerabilities', 'Subnet Fairness Vulnerabilities', 'Subnet Discrimination Vulnerabilities', etc.)."]
) -> str:
    """
    Compose a subnet-centric prompt for Avalanche VM/subnet operations.

    Parameters:
        function_explanation (str): Intended subnet operation and guardrails.
        function_body (str): Exact code under review.
        file_path (str): Repo-relative path.
        subnet_context (str): VM type, validator set rules, chain params, upgrade paths.
        list_of_subnet_threats (list[str]): Config validation, validator churn, governance/upgrade
            safety, cross-chain sync, fee/gas settings.

    Output:
        str: Prompt for LLM to provide issues with remediation guidance.
    """
    msg = f"""
AVALANCHE SUBNET THREAT ANALYSIS REQUEST

Function Context:
- Subnet Purpose: {function_explanation}
- File Location: {file_path}
- Subnet Context: {subnet_context}
- Subnet Threats to Evaluate: {', '.join(list_of_subnet_threats)}

Avalanche Subnet Source Code to Analyze:
{function_body}

Please perform a comprehensive Avalanche subnet security analysis focusing on the specified threats and provide detailed findings with subnet-specific attack vector analysis, potential subnet impact, and remediation guidance specific to Avalanche subnet vulnerabilities and secure subnet development practices.
"""

    return msg
