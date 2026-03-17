from typing import Annotated


async def l2_rollup_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the L2 rollup function does, its purpose in Layer 2 scaling, and its role in the rollup protocol. Should include rollup operations, state commitments, and any L2-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the L2 rollup function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual L2 rollup code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'rollup/state_manager.py', 'l2/optimistic_rollup.rs', 'scaling/zk_rollup.go'). Used for context and reporting."], 
    rollup_context: Annotated[str, "Additional L2 rollup context including the rollup type (e.g., Optimistic Rollup, ZK Rollup, Validium, Plasma), L1 chain (e.g., Ethereum, Polygon), and critical L2 operations this function handles."],
    list_of_l2_threats: Annotated[list[str], "A comprehensive list of L2 rollup-specific threats and vulnerabilities to check for during analysis. Each item should be a specific L2 threat type (e.g., 'State Root Manipulation', 'Invalid State Transition', 'Withdrawal Delay Attack', 'Sequencer Censorship', 'Sequencer Failure', 'Data Availability Attack', 'Fraud Proof Bypass', 'Validity Proof Bypass', 'State Commitment Attack', 'Batch Submission Attack', 'Challenge Period Manipulation', 'L1-L2 Communication Attack', 'Cross-Rollup Attack', 'MEV in L2', 'L2 Reorg Attack', 'Validator Collusion', 'Prover Collusion', 'State Transition Attack', 'Withdrawal Attack', 'Deposit Attack', 'L2 Consensus Attack', 'L2 Finality Attack', 'L2 Fork Attack', 'L2 Upgrade Attack', 'L2 Governance Attack', 'L2 Economic Attack', 'L2 Network Attack', 'L2 Storage Attack', 'L2 Computation Attack', 'L2 Verification Attack', etc.)."]
) -> str:
    """
    Create a rollup-focused prompt for Optimistic/ZK/Plasma/Validium logic.

    Parameters:
        function_explanation (str): Expected state transition and guarantees.
        function_body (str): Exact code under review.
        file_path (str): Repo-relative path.
        rollup_context (str): Rollup type, DA model, challenge window, proof system.
        list_of_l2_threats (list[str]): State root manipulation, fraud/validity proof bypass,
            DA failures, sequencer censorship/failure, withdrawal/escape hatches.

    Output:
        str: Prompt instructing LLM to provide findings with references and remediations.
    """
    msg = f"""
L2 ROLLUP THREAT ANALYSIS REQUEST

Function Context:
- L2 Rollup Purpose: {function_explanation}
- File Location: {file_path}
- Rollup Context: {rollup_context}
- L2 Rollup Threats to Evaluate: {', '.join(list_of_l2_threats)}

L2 Rollup Source Code to Analyze:
{function_body}

Please perform a comprehensive L2 rollup security analysis focusing on the specified threats and provide detailed findings with L2-specific attack vector analysis, potential L2 impact, and remediation guidance specific to L2 rollup vulnerabilities and secure scaling solution practices.
"""

    return msg


async def l2_bridge_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the L2 bridge function does, its purpose in cross-chain communication, and its role in the bridge protocol. Should include bridge operations, asset locking/unlocking, and any bridge-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the L2 bridge function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual L2 bridge code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'bridge/cross_chain.py', 'l2/asset_bridge.rs', 'scaling/bridge_manager.go'). Used for context and reporting."], 
    bridge_context: Annotated[str, "Additional L2 bridge context including the bridge type (e.g., Lock-and-Mint, Burn-and-Mint, Atomic Swap, Liquidity Network), supported chains, and critical bridge operations this function handles."],
    list_of_bridge_threats: Annotated[list[str], "A comprehensive list of L2 bridge-specific threats and vulnerabilities to check for during analysis. Each item should be a specific bridge threat type (e.g., 'Bridge Asset Theft', 'Double Spending Attack', 'Replay Attack', 'Signature Forgery', 'Validator Collusion', 'Bridge Operator Attack', 'Cross-Chain Message Manipulation', 'Asset Lock Attack', 'Asset Unlock Attack', 'Bridge State Manipulation', 'Bridge Governance Attack', 'Bridge Upgrade Attack', 'Bridge Pause Attack', 'Bridge Emergency Stop Attack', 'Bridge Economic Attack', 'Bridge Network Attack', 'Bridge Storage Attack', 'Bridge Computation Attack', 'Bridge Verification Attack', 'Bridge Communication Attack', 'Bridge Consensus Attack', 'Bridge Finality Attack', 'Bridge Fork Attack', 'Bridge Slashing Attack', 'Bridge Reward Attack', 'Bridge Fee Attack', 'Bridge Liquidity Attack', 'Bridge Oracle Attack', 'Bridge Time Attack', 'Bridge Order Attack', etc.)."]
) -> str:
    """
    Build a cross-chain bridge review prompt for LLMs.

    Parameters:
        function_explanation (str): Asset flow and guarantees (lock/mint/burn/unlock).
        function_body (str): Exact code.
        file_path (str): Repo-relative path.
        bridge_context (str): Bridge design (validators/oracles/light client), chains, finality.
        list_of_bridge_threats (list[str]): Replay/double spend, signature/attestation forgery,
            validator collusion, message tampering, timeout/ordering.

    Output:
        str: Prompt requesting concrete findings and fixes with references.
    """
    msg = f"""
L2 BRIDGE THREAT ANALYSIS REQUEST

Function Context:
- L2 Bridge Purpose: {function_explanation}
- File Location: {file_path}
- Bridge Context: {bridge_context}
- L2 Bridge Threats to Evaluate: {', '.join(list_of_bridge_threats)}

L2 Bridge Source Code to Analyze:
{function_body}

Please perform a comprehensive L2 bridge security analysis focusing on the specified threats and provide detailed findings with bridge-specific attack vector analysis, potential bridge impact, and remediation guidance specific to L2 bridge vulnerabilities and secure cross-chain communication practices.
"""

    return msg


async def l2_scaling_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the L2 scaling function does, its purpose in Layer 2 scaling solutions, and its role in the scaling protocol. Should include scaling operations, throughput optimization, and any scaling-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the L2 scaling function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual L2 scaling code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'scaling/throughput.py', 'l2/optimization.rs', 'performance/scaling_manager.go'). Used for context and reporting."], 
    scaling_context: Annotated[str, "Additional L2 scaling context including the scaling solution type (e.g., State Channels, Sidechains, Plasma, Rollups), scaling mechanisms, and critical scaling operations this function handles."],
    list_of_scaling_threats: Annotated[list[str], "A comprehensive list of L2 scaling-specific threats and vulnerabilities to check for during analysis. Each item should be a specific scaling threat type (e.g., 'Scaling Throughput Attack', 'Scaling Latency Attack', 'Scaling Cost Attack', 'Scaling Security Attack', 'Scaling Decentralization Attack', 'Scaling Finality Attack', 'Scaling Consensus Attack', 'Scaling State Attack', 'Scaling Data Attack', 'Scaling Computation Attack', 'Scaling Storage Attack', 'Scaling Network Attack', 'Scaling Economic Attack', 'Scaling Governance Attack', 'Scaling Upgrade Attack', 'Scaling Fork Attack', 'Scaling Slashing Attack', 'Scaling Reward Attack', 'Scaling Fee Attack', 'Scaling Liquidity Attack', 'Scaling Oracle Attack', 'Scaling Time Attack', 'Scaling Order Attack', 'Scaling Priority Attack', 'Scaling Resource Attack', 'Scaling Capacity Attack', 'Scaling Performance Attack', 'Scaling Reliability Attack', 'Scaling Availability Attack', 'Scaling Consistency Attack', 'Scaling Partition Attack', etc.)."]
) -> str:
    """
    Prepare a general L2 scaling prompt for channels/sidechains/rollups.

    Parameters:
        function_explanation (str): Intended scaling behavior and constraints.
        function_body (str): Exact code under review.
        file_path (str): Repo-relative path.
        scaling_context (str): Scaling type, settlement/finality model, data availability.
        list_of_scaling_threats (list[str]): Throughput/latency DoS, finality/consistency, fee/economic
            breaks, state sync/migration, reorg handling.

    Output:
        str: Prompt instructing LLM to return issues with references and fixes.
    """
    msg = f"""
L2 SCALING THREAT ANALYSIS REQUEST

Function Context:
- L2 Scaling Purpose: {function_explanation}
- File Location: {file_path}
- Scaling Context: {scaling_context}
- L2 Scaling Threats to Evaluate: {', '.join(list_of_scaling_threats)}

L2 Scaling Source Code to Analyze:
{function_body}

Please perform a comprehensive L2 scaling security analysis focusing on the specified threats and provide detailed findings with scaling-specific attack vector analysis, potential scaling impact, and remediation guidance specific to L2 scaling vulnerabilities and secure scaling solution practices.
"""

    return msg
