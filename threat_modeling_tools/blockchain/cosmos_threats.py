from typing import Annotated


async def cosmos_general_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Cosmos function does, its purpose in the Cosmos/Tendermint ecosystem, and its role in the application. Should include Cosmos-specific operations, IBC development, and any Cosmos-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the Cosmos function including all statements, variable assignments, control flow, function calls, Cosmos operations, and any nested logic. This is the actual Cosmos code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'modules/cosmos_module.go', 'src/cosmos/ibc_handler.js', 'app/cosmos/transaction_processor.py'). Used for context and reporting."], 
    cosmos_context: Annotated[str, "Additional Cosmos context including the component type (e.g., IBC module, staking module, governance module), Cosmos SDK version, and critical Cosmos operations this function handles."],
    list_of_cosmos_threats: Annotated[list[str], "A comprehensive list of Cosmos-specific threats and vulnerabilities to check for during analysis. Each item should be a specific Cosmos threat type (e.g., 'Cosmos Module Vulnerabilities', 'Cosmos IBC Vulnerabilities', 'Cosmos Staking Vulnerabilities', 'Cosmos Governance Vulnerabilities', 'Cosmos Treasury Vulnerabilities', 'Cosmos Democracy Vulnerabilities', 'Cosmos Council Vulnerabilities', 'Cosmos Technical Committee Vulnerabilities', 'Cosmos Referendum Vulnerabilities', 'Cosmos Proposal Vulnerabilities', 'Cosmos Voting Vulnerabilities', 'Cosmos Delegation Vulnerabilities', 'Cosmos Bonding Vulnerabilities', 'Cosmos Unbonding Vulnerabilities', 'Cosmos Validator Vulnerabilities', 'Cosmos Nominator Vulnerabilities', 'Cosmos Era Vulnerabilities', 'Cosmos Session Vulnerabilities', 'Cosmos Epoch Vulnerabilities', 'Cosmos Slot Vulnerabilities', 'Cosmos Block Production Vulnerabilities', 'Cosmos Block Import Vulnerabilities', 'Cosmos Block Validation Vulnerabilities', 'Cosmos Block Finalization Vulnerabilities', 'Cosmos Block Reorganization Vulnerabilities', 'Cosmos Block Fork Vulnerabilities', 'Cosmos Block Chain Vulnerabilities', 'Cosmos Block State Vulnerabilities', 'Cosmos Block Storage Vulnerabilities', 'Cosmos Block Memory Vulnerabilities', 'Cosmos Block Network Vulnerabilities', 'Cosmos Block Consensus Vulnerabilities', 'Cosmos Block Finality Vulnerabilities', 'Cosmos Block Slashing Vulnerabilities', 'Cosmos Block Staking Vulnerabilities', 'Cosmos Block Governance Vulnerabilities', 'Cosmos Block Treasury Vulnerabilities', 'Cosmos Block Democracy Vulnerabilities', 'Cosmos Block Council Vulnerabilities', 'Cosmos Block Technical Committee Vulnerabilities', 'Cosmos Block Referendum Vulnerabilities', 'Cosmos Block Proposal Vulnerabilities', 'Cosmos Block Voting Vulnerabilities', 'Cosmos Block Delegation Vulnerabilities', 'Cosmos Block Bonding Vulnerabilities', 'Cosmos Block Unbonding Vulnerabilities', 'Cosmos Block Validator Vulnerabilities', 'Cosmos Block Nominator Vulnerabilities', 'Cosmos Block Era Vulnerabilities', 'Cosmos Block Session Vulnerabilities', 'Cosmos Block Epoch Vulnerabilities', 'Cosmos Block Slot Vulnerabilities', 'Cosmos Block Production Vulnerabilities', 'Cosmos Block Import Vulnerabilities', 'Cosmos Block Validation Vulnerabilities', 'Cosmos Block Finalization Vulnerabilities', 'Cosmos Block Reorganization Vulnerabilities', 'Cosmos Block Fork Vulnerabilities', 'Cosmos Block Chain Vulnerabilities', 'Cosmos Block State Vulnerabilities', 'Cosmos Block Storage Vulnerabilities', 'Cosmos Block Memory Vulnerabilities', 'Cosmos Block Network Vulnerabilities', etc.)."]
) -> str:
    """
    Create an LLM-ready prompt for Cosmos SDK/IBC code review.

    Parameters:
        function_explanation (str): Purpose, module interactions, invariants.
        function_body (str): Exact code under review.
        file_path (str): Repo-relative path.
        cosmos_context (str): Module type, keeper usage, params, IBC channels/ports/versions.
        list_of_cosmos_threats (list[str]): Module auth/keeper misuse, parameter checks, IBC proofs,
            packet/ack handling, fee/gas correctness, state invariants.

    Output:
        str: Prompt instructing the LLM to provide findings with references and fixes.
    """
    msg = f"""
COSMOS GENERAL THREAT ANALYSIS REQUEST

Function Context:
- Cosmos Purpose: {function_explanation}
- File Location: {file_path}
- Cosmos Context: {cosmos_context}
- Cosmos Threats to Evaluate: {', '.join(list_of_cosmos_threats)}

Cosmos Source Code to Analyze:
{function_body}

Please perform a comprehensive Cosmos security analysis focusing on the specified threats and provide detailed findings with Cosmos-specific attack vector analysis, potential Cosmos impact, and remediation guidance specific to Cosmos vulnerabilities and secure Cosmos development practices.
"""

    return msg


async def tendermint_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Tendermint function does, its purpose in consensus mechanisms, and its role in the Tendermint consensus. Should include consensus operations, block validation, and any Tendermint-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the Tendermint function including all statements, variable assignments, control flow, function calls, consensus operations, and any nested logic. This is the actual Tendermint code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'consensus/tendermint.go', 'src/tendermint/block_validator.js', 'app/tendermint/consensus_handler.py'). Used for context and reporting."], 
    tendermint_context: Annotated[str, "Additional Tendermint context including the consensus type (e.g., Tendermint Core, Tendermint BFT), consensus parameters, and critical Tendermint operations this function handles."],
    list_of_tendermint_threats: Annotated[list[str], "A comprehensive list of Tendermint-specific threats and vulnerabilities to check for during analysis. Each item should be a specific Tendermint threat type (e.g., 'Tendermint Consensus Vulnerabilities', 'Tendermint Block Vulnerabilities', 'Tendermint Transaction Vulnerabilities', 'Tendermint Validator Vulnerabilities', 'Tendermint Proposer Vulnerabilities', 'Tendermint Vote Vulnerabilities', 'Tendermint Precommit Vulnerabilities', 'Tendermint Prevote Vulnerabilities', 'Tendermint Commit Vulnerabilities', 'Tendermint Finality Vulnerabilities', 'Tendermint Slashing Vulnerabilities', 'Tendermint Staking Vulnerabilities', 'Tendermint Governance Vulnerabilities', 'Tendermint Treasury Vulnerabilities', 'Tendermint Democracy Vulnerabilities', 'Tendermint Council Vulnerabilities', 'Tendermint Technical Committee Vulnerabilities', 'Tendermint Referendum Vulnerabilities', 'Tendermint Proposal Vulnerabilities', 'Tendermint Voting Vulnerabilities', 'Tendermint Delegation Vulnerabilities', 'Tendermint Bonding Vulnerabilities', 'Tendermint Unbonding Vulnerabilities', 'Tendermint Era Vulnerabilities', 'Tendermint Session Vulnerabilities', 'Tendermint Epoch Vulnerabilities', 'Tendermint Slot Vulnerabilities', 'Tendermint Block Production Vulnerabilities', 'Tendermint Block Import Vulnerabilities', 'Tendermint Block Validation Vulnerabilities', 'Tendermint Block Finalization Vulnerabilities', 'Tendermint Block Reorganization Vulnerabilities', 'Tendermint Block Fork Vulnerabilities', 'Tendermint Block Chain Vulnerabilities', 'Tendermint Block State Vulnerabilities', 'Tendermint Block Storage Vulnerabilities', 'Tendermint Block Memory Vulnerabilities', 'Tendermint Block Network Vulnerabilities', etc.)."]
) -> str:
    """
    Build a Tendermint consensus review prompt for LLMs.

    Parameters:
        function_explanation (str): Role in propose/prevote/precommit/commit.
        function_body (str): Exact function source.
        file_path (str): Repo-relative path.
        tendermint_context (str): Consensus params, evidence handling, light client assumptions.
        list_of_tendermint_threats (list[str]): Validator equivocation, evidence processing, fork safety,
            finality, time-drift, P2P DoS.

    Output:
        str: Prompt asking for concrete issues, exploits, and fixes with references.
    """
    msg = f"""
TENDERMINT THREAT ANALYSIS REQUEST

Function Context:
- Tendermint Purpose: {function_explanation}
- File Location: {file_path}
- Tendermint Context: {tendermint_context}
- Tendermint Threats to Evaluate: {', '.join(list_of_tendermint_threats)}

Tendermint Source Code to Analyze:
{function_body}

Please perform a comprehensive Tendermint security analysis focusing on the specified threats and provide detailed findings with Tendermint-specific attack vector analysis, potential Tendermint impact, and remediation guidance specific to Tendermint vulnerabilities and secure Tendermint development practices.
"""

    return msg


async def ibc_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the IBC function does, its purpose in inter-blockchain communication, and its role in the IBC protocol. Should include IBC operations, packet handling, and any IBC-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the IBC function including all statements, variable assignments, control flow, function calls, IBC operations, and any nested logic. This is the actual IBC code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'modules/ibc_module.go', 'src/ibc/packet_handler.js', 'app/ibc/relay_handler.py'). Used for context and reporting."], 
    ibc_context: Annotated[str, "Additional IBC context including the IBC component type (e.g., client, connection, channel, packet), IBC version, and critical IBC operations this function handles."],
    list_of_ibc_threats: Annotated[list[str], "A comprehensive list of IBC-specific threats and vulnerabilities to check for during analysis. Each item should be a specific IBC threat type (e.g., 'IBC Client Vulnerabilities', 'IBC Connection Vulnerabilities', 'IBC Channel Vulnerabilities', 'IBC Packet Vulnerabilities', 'IBC Relay Vulnerabilities', 'IBC Validation Vulnerabilities', 'IBC Authorization Vulnerabilities', 'IBC Authentication Vulnerabilities', 'IBC Access Control Vulnerabilities', 'IBC Session Management Vulnerabilities', 'IBC Input Validation Vulnerabilities', 'IBC Output Encoding Vulnerabilities', 'IBC Error Handling Vulnerabilities', 'IBC Logging Vulnerabilities', 'IBC Monitoring Vulnerabilities', 'IBC Auditing Vulnerabilities', 'IBC Reporting Vulnerabilities', 'IBC Analytics Vulnerabilities', 'IBC Mining Vulnerabilities', 'IBC Machine Learning Vulnerabilities', 'IBC AI Vulnerabilities', 'IBC Algorithm Vulnerabilities', 'IBC Model Vulnerabilities', 'IBC Training Vulnerabilities', 'IBC Testing Vulnerabilities', 'IBC Validation Vulnerabilities', 'IBC Cross-Validation Vulnerabilities', 'IBC Overfitting Vulnerabilities', 'IBC Underfitting Vulnerabilities', 'IBC Bias Vulnerabilities', 'IBC Fairness Vulnerabilities', 'IBC Discrimination Vulnerabilities', etc.)."]
) -> str:
    """
    Compose an IBC-specific prompt for packet/client/connection/channel logic.

    Parameters:
        function_explanation (str): Intended IBC operation and guarantees.
        function_body (str): Exact code under review.
        file_path (str): Repo-relative path.
        ibc_context (str): ICS spec versions, proofs, ports/channels/clients.
        list_of_ibc_threats (list[str]): Proof verification, replay protection, timeout/ordering,
            packet/ack handling, misconfigured relayers.

    Output:
        str: LLM prompt requesting findings with references and fixes.
    """
    msg = f"""
IBC THREAT ANALYSIS REQUEST

Function Context:
- IBC Purpose: {function_explanation}
- File Location: {file_path}
- IBC Context: {ibc_context}
- IBC Threats to Evaluate: {', '.join(list_of_ibc_threats)}

IBC Source Code to Analyze:
{function_body}

Please perform a comprehensive IBC security analysis focusing on the specified threats and provide detailed findings with IBC-specific attack vector analysis, potential IBC impact, and remediation guidance specific to IBC vulnerabilities and secure IBC development practices.
"""

    return msg


async def cosmos_sdk_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Cosmos SDK function does, its purpose in the Cosmos SDK framework, and its role in the application. Should include Cosmos SDK-specific operations, keeper usage, message handling, and any Cosmos SDK-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the Cosmos SDK function including all statements, variable assignments, control flow, function calls, Cosmos SDK operations, and any nested logic. This is the actual Cosmos SDK code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'x/module/keeper/keeper.go', 'x/module/keeper/msg_server.go', 'x/module/keeper/query.go', 'app/ante/ante.go'). Used for context and reporting."], 
    cosmos_sdk_context: Annotated[str, "Additional Cosmos SDK context including the component type (e.g., keeper, message handler, query handler, ante handler, module, params), Cosmos SDK version, module name, and critical Cosmos SDK operations this function handles."],
    list_of_cosmos_sdk_threats: Annotated[list[str], "A comprehensive list of Cosmos SDK-specific threats and vulnerabilities to check for during analysis. Each item should be a specific Cosmos SDK threat type (e.g., 'Keeper Access Control Vulnerabilities', 'Message Handler Authorization Vulnerabilities', 'Query Handler Validation Vulnerabilities', 'Ante Handler Bypass Vulnerabilities', 'Store Key Collision Vulnerabilities', 'Gas Metering Vulnerabilities', 'Fee Calculation Vulnerabilities', 'Parameter Validation Vulnerabilities', 'Module Initialization Vulnerabilities', 'Upgrade Handler Vulnerabilities', 'State Transition Vulnerabilities', 'Invariant Violations', 'Store Iterator Vulnerabilities', 'Context Propagation Vulnerabilities', 'Event Emission Vulnerabilities', 'Module Interdependencies Vulnerabilities', 'Bank Module Vulnerabilities', 'Staking Module Vulnerabilities', 'Governance Module Vulnerabilities', 'Distribution Module Vulnerabilities', 'Slashing Module Vulnerabilities', 'Mint Module Vulnerabilities', 'Auth Module Vulnerabilities', 'Crisis Module Vulnerabilities', 'Evidence Module Vulnerabilities', 'Capability Module Vulnerabilities', 'Vesting Module Vulnerabilities', 'Custom Module Vulnerabilities', 'Store Read/Write Vulnerabilities', 'State Machine Vulnerabilities', 'Consensus State Vulnerabilities', 'Validator Set Vulnerabilities', 'Delegation Vulnerabilities', 'Unbonding Vulnerabilities', 'Reward Distribution Vulnerabilities', 'Commission Calculation Vulnerabilities', 'Proposal Submission Vulnerabilities', 'Voting Vulnerabilities', 'Deposit Vulnerabilities', 'Tally Vulnerabilities', 'Upgrade Proposal Vulnerabilities', 'Software Upgrade Vulnerabilities', 'Cancel Upgrade Vulnerabilities', 'Store Migration Vulnerabilities', 'Genesis State Vulnerabilities', 'Export/Import Vulnerabilities', etc.)."]
) -> str:
    """
    Create an LLM-ready prompt for Cosmos SDK code review focusing on framework-specific security concerns.

    Parameters:
        function_explanation (str): Purpose, keeper usage, module interactions, invariants, and expected message/query types.
        function_body (str): Exact code under review.
        file_path (str): Repo-relative path.
        cosmos_sdk_context (str): Module type, keeper structure, store keys, params, SDK version, ante handlers, upgrade handlers.
        list_of_cosmos_sdk_threats (list[str]): Keeper access control, message authorization, query validation, ante handler bypass,
            store key collisions, gas/fee correctness, parameter validation, state invariants, module interdependencies.

    Output:
        str: Prompt instructing the LLM to provide findings with references and fixes.

    LLM guidance:
        - Validate keeper access patterns and ensure proper authorization checks.
        - Check message handlers for proper signer validation and authorization.
        - Review query handlers for proper access control and data validation.
        - Verify ante handlers cannot be bypassed and properly validate transactions.
        - Ensure store keys are unique and properly namespaced.
        - Confirm gas metering and fee calculation are correct and cannot be manipulated.
        - Validate module parameters and ensure they cannot be set to unsafe values.
        - Check for invariant violations in state transitions.
        - Review module interdependencies for circular dependencies or unsafe cross-module calls.
        - Verify upgrade handlers properly migrate state and maintain invariants.
    """
    msg = f"""
COSMOS SDK THREAT ANALYSIS REQUEST

Function Context:
- Cosmos SDK Purpose: {function_explanation}
- File Location: {file_path}
- Cosmos SDK Context: {cosmos_sdk_context}
- Cosmos SDK Threats to Evaluate: {', '.join(list_of_cosmos_sdk_threats)}

Cosmos SDK Source Code to Analyze:
{function_body}

Please perform a comprehensive Cosmos SDK security analysis focusing on the specified threats and provide detailed findings with Cosmos SDK-specific attack vector analysis, potential Cosmos SDK impact, and remediation guidance specific to Cosmos SDK vulnerabilities and secure Cosmos SDK development practices.

Key areas to analyze:
- Keeper access control and authorization patterns
- Message handler signer validation and authorization
- Query handler access control and data validation
- Ante handler bypass vulnerabilities
- Store key collision and namespace issues
- Gas metering and fee calculation vulnerabilities
- Parameter validation and unsafe parameter settings
- State invariant violations
- Module interdependency vulnerabilities
- Upgrade handler state migration issues
- Store iterator and context propagation issues
- Event emission and logging vulnerabilities
"""

    return msg
