from typing import Annotated


async def l1_consensus_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the L1 consensus function does, its purpose in blockchain consensus, and its role in the consensus protocol. Should include consensus operations, block validation, and any consensus-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the L1 consensus function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual L1 consensus code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'consensus/pow.go', 'consensus/pos.rs', 'consensus/pbft.py'). Used for context and reporting."], 
    consensus_context: Annotated[str, "Additional L1 consensus context including the consensus mechanism (e.g., Proof of Work, Proof of Stake, Delegated Proof of Stake, PBFT), blockchain type, and critical consensus operations this function handles."],
    list_of_consensus_threats: Annotated[list[str], "A comprehensive list of L1 consensus-specific threats and vulnerabilities to check for during analysis. Each item should be a specific consensus threat type (e.g., '51% Attack', 'Nothing at Stake Problem', 'Long Range Attack', 'Grinding Attack', 'Eclipse Attack', 'Sybil Attack', 'Selfish Mining', 'Block Withholding', 'Fork Choice Rule Manipulation', 'Validator Slashing', 'Double Spending', 'Finality Violations', 'Consensus Fork', 'Validator Collusion', 'Stake Bleeding Attack', 'Weak Subjectivity', 'Checkpoint Vulnerabilities', 'Economic Attacks', 'Governance Attacks', 'Consensus Parameter Manipulation', 'Consensus State Attack', 'Consensus Message Attack', 'Consensus Time Attack', 'Consensus Order Attack', 'Consensus Priority Attack', 'Consensus Resource Attack', 'Consensus Capacity Attack', 'Consensus Performance Attack', 'Consensus Reliability Attack', 'Consensus Availability Attack', 'Consensus Consistency Attack', 'Consensus Partition Attack', etc.)."]
) -> str:
    """
    Generate an LLM prompt to assess L1 consensus code against explicit threats.

    Parameters:
        function_explanation (str): Purpose, assumptions, and trust boundaries of the consensus step.
        function_body (str): Exact function source code.
        file_path (str): Repo-relative path.
        consensus_context (str): Mechanism (PoW/PoS/PBFT…), slashing/finality rules, fork-choice.
        list_of_consensus_threats (list[str]): Concrete items (e.g., 51% attack, long-range, eclipse,
            selfish mining, equivocation, weak subjectivity violations).

    Output:
        str: Prompt instructing the LLM to provide findings, exploit narratives, and fixes with refs.

    LLM guidance:
        - Validate proposer/validator selection, quorum, and message validation.
        - Check fork-choice correctness and finality assumptions.
        - Consider network partitions, time skew, and DoS on critical paths.
        - Review slashing/incentive alignment and replay protections.
    """
    msg = f"""
L1 CONSENSUS THREAT ANALYSIS REQUEST

Function Context:
- L1 Consensus Purpose: {function_explanation}
- File Location: {file_path}
- Consensus Context: {consensus_context}
- L1 Consensus Threats to Evaluate: {', '.join(list_of_consensus_threats)}

L1 Consensus Source Code to Analyze:
{function_body}

Please perform a comprehensive L1 consensus security analysis focusing on the specified threats and provide detailed findings with consensus-specific attack vector analysis, potential consensus impact, and remediation guidance specific to L1 consensus vulnerabilities and secure consensus mechanism practices.
"""

    return msg


async def l1_chain_split_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the L1 chain split function does, its purpose in blockchain forking, and its role in the chain split protocol. Should include fork operations, chain reorganization, and any chain split-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the L1 chain split function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual L1 chain split code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'fork/chain_split.py', 'l1/reorganization.rs', 'consensus/fork_manager.go'). Used for context and reporting."], 
    chain_split_context: Annotated[str, "Additional L1 chain split context including the fork type (e.g., Hard Fork, Soft Fork, Chain Reorganization), blockchain type, and critical chain split operations this function handles."],
    list_of_chain_split_threats: Annotated[list[str], "A comprehensive list of L1 chain split-specific threats and vulnerabilities to check for during analysis. Each item should be a specific chain split threat type (e.g., 'Chain Reorganization Attack', 'Fork Choice Attack', 'Fork Selection Attack', 'Fork Resolution Attack', 'Fork Conflict Attack', 'Fork State Attack', 'Fork Message Attack', 'Fork Time Attack', 'Fork Order Attack', 'Fork Priority Attack', 'Fork Resource Attack', 'Fork Capacity Attack', 'Fork Performance Attack', 'Fork Reliability Attack', 'Fork Availability Attack', 'Fork Consistency Attack', 'Fork Partition Attack', 'Fork Consensus Attack', 'Fork Finality Attack', 'Fork Slashing Attack', 'Fork Reward Attack', 'Fork Fee Attack', 'Fork Liquidity Attack', 'Fork Oracle Attack', 'Fork Governance Attack', 'Fork Upgrade Attack', 'Fork Emergency Attack', 'Fork Economic Attack', 'Fork Network Attack', 'Fork Storage Attack', 'Fork Computation Attack', 'Fork Verification Attack', etc.)."]
) -> str:
    """
    Compose a prompt to review fork/chain-reorg handling logic for safety.

    Parameters:
        function_explanation (str): Intended fork handling behavior and invariants.
        function_body (str): Exact source under review.
        file_path (str): Repo-relative path.
        chain_split_context (str): Consensus, reorg limits, finality horizon, checkpoints.
        list_of_chain_split_threats (list[str]): Reorg abuse, fork-choice manipulation, stale block
            injection, replay/state inconsistency, orphan handling.

    Output:
        str: Prompt directing the LLM to provide precise findings and remediations.
    """
    msg = f"""
L1 CHAIN SPLIT THREAT ANALYSIS REQUEST

Function Context:
- L1 Chain Split Purpose: {function_explanation}
- File Location: {file_path}
- Chain Split Context: {chain_split_context}
- L1 Chain Split Threats to Evaluate: {', '.join(list_of_chain_split_threats)}

L1 Chain Split Source Code to Analyze:
{function_body}

Please perform a comprehensive L1 chain split security analysis focusing on the specified threats and provide detailed findings with chain split-specific attack vector analysis, potential chain split impact, and remediation guidance specific to L1 chain split vulnerabilities and secure fork mechanism practices.
"""

    return msg


async def l1_protocol_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the L1 protocol function does, its purpose in blockchain protocol, and its role in the protocol implementation. Should include protocol operations, transaction processing, and any protocol-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the L1 protocol function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual L1 protocol code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'protocol/transaction.py', 'l1/block_processor.rs', 'consensus/protocol_manager.go'). Used for context and reporting."], 
    protocol_context: Annotated[str, "Additional L1 protocol context including the protocol type (e.g., Bitcoin-like, Ethereum-like, custom), protocol features, and critical protocol operations this function handles."],
    list_of_protocol_threats: Annotated[list[str], "A comprehensive list of L1 protocol-specific threats and vulnerabilities to check for during analysis. Each item should be a specific protocol threat type (e.g., 'Protocol State Attack', 'Protocol Message Attack', 'Protocol Time Attack', 'Protocol Order Attack', 'Protocol Priority Attack', 'Protocol Resource Attack', 'Protocol Capacity Attack', 'Protocol Performance Attack', 'Protocol Reliability Attack', 'Protocol Availability Attack', 'Protocol Consistency Attack', 'Protocol Partition Attack', 'Protocol Consensus Attack', 'Protocol Finality Attack', 'Protocol Slashing Attack', 'Protocol Reward Attack', 'Protocol Fee Attack', 'Protocol Liquidity Attack', 'Protocol Oracle Attack', 'Protocol Governance Attack', 'Protocol Upgrade Attack', 'Protocol Emergency Attack', 'Protocol Economic Attack', 'Protocol Network Attack', 'Protocol Storage Attack', 'Protocol Computation Attack', 'Protocol Verification Attack', 'Protocol Communication Attack', 'Protocol Synchronization Attack', 'Protocol Coordination Attack', 'Protocol Agreement Attack', etc.)."]
) -> str:
    """
    Build an L1 protocol-level review prompt for transaction/state logic.

    Parameters:
        function_explanation (str): What this protocol step does and guarantees.
        function_body (str): Exact code under review.
        file_path (str): Repo-relative path.
        protocol_context (str): Execution model (EVM/UTXO/custom), fee model, validation stages.
        list_of_protocol_threats (list[str]): State validity, message verification, ordering/time,
            DoS vectors, replay, fee/accounting correctness.

    Output:
        str: Prompt for LLM to return issues with references and actionable fixes.
    """
    msg = f"""
L1 PROTOCOL THREAT ANALYSIS REQUEST

Function Context:
- L1 Protocol Purpose: {function_explanation}
- File Location: {file_path}
- Protocol Context: {protocol_context}
- L1 Protocol Threats to Evaluate: {', '.join(list_of_protocol_threats)}

L1 Protocol Source Code to Analyze:
{function_body}

Please perform a comprehensive L1 protocol security analysis focusing on the specified threats and provide detailed findings with protocol-specific attack vector analysis, potential protocol impact, and remediation guidance specific to L1 protocol vulnerabilities and secure protocol implementation practices.
"""

    return msg
