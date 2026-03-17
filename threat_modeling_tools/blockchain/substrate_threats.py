from typing import Annotated


async def substrate_general_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Substrate function does, its purpose in the Substrate/Polkadot ecosystem, and its role in the application. Should include Substrate-specific operations, runtime development, and any Substrate-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the Substrate function including all statements, variable assignments, control flow, function calls, Substrate operations, and any nested logic. This is the actual Substrate code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'runtime/src/lib.rs', 'pallets/custom_pallet.rs', 'node/src/chain_spec.rs'). Used for context and reporting."], 
    substrate_context: Annotated[str, "Additional Substrate context including the component type (e.g., runtime, pallet, node, client), Substrate version, and critical Substrate operations this function handles."],
    list_of_substrate_threats: Annotated[list[str], "A comprehensive list of Substrate-specific threats and vulnerabilities to check for during analysis. Each item should be a specific Substrate threat type (e.g., 'Substrate Runtime Vulnerabilities', 'Substrate Pallet Vulnerabilities', 'Substrate Node Vulnerabilities', 'Substrate Client Vulnerabilities', 'Substrate Storage Vulnerabilities', 'Substrate Event Vulnerabilities', 'Substrate Call Vulnerabilities', 'Substrate Origin Vulnerabilities', 'Substrate Weight Vulnerabilities', 'Substrate Fee Vulnerabilities', 'Substrate Gas Vulnerabilities', 'Substrate Block Vulnerabilities', 'Substrate Transaction Vulnerabilities', 'Substrate Consensus Vulnerabilities', 'Substrate Finality Vulnerabilities', 'Substrate Slashing Vulnerabilities', 'Substrate Staking Vulnerabilities', 'Substrate Governance Vulnerabilities', 'Substrate Treasury Vulnerabilities', 'Substrate Democracy Vulnerabilities', 'Substrate Council Vulnerabilities', 'Substrate Technical Committee Vulnerabilities', 'Substrate Referendum Vulnerabilities', 'Substrate Proposal Vulnerabilities', 'Substrate Voting Vulnerabilities', 'Substrate Delegation Vulnerabilities', 'Substrate Bonding Vulnerabilities', 'Substrate Unbonding Vulnerabilities', 'Substrate Validator Vulnerabilities', 'Substrate Nominator Vulnerabilities', 'Substrate Era Vulnerabilities', 'Substrate Session Vulnerabilities', 'Substrate Epoch Vulnerabilities', 'Substrate Slot Vulnerabilities', 'Substrate Block Production Vulnerabilities', 'Substrate Block Import Vulnerabilities', 'Substrate Block Validation Vulnerabilities', 'Substrate Block Finalization Vulnerabilities', 'Substrate Block Reorganization Vulnerabilities', 'Substrate Block Fork Vulnerabilities', 'Substrate Block Chain Vulnerabilities', 'Substrate Block State Vulnerabilities', 'Substrate Block Storage Vulnerabilities', 'Substrate Block Memory Vulnerabilities', 'Substrate Block Network Vulnerabilities', 'Substrate Block Consensus Vulnerabilities', 'Substrate Block Finality Vulnerabilities', 'Substrate Block Slashing Vulnerabilities', 'Substrate Block Staking Vulnerabilities', 'Substrate Block Governance Vulnerabilities', 'Substrate Block Treasury Vulnerabilities', 'Substrate Block Democracy Vulnerabilities', 'Substrate Block Council Vulnerabilities', 'Substrate Block Technical Committee Vulnerabilities', 'Substrate Block Referendum Vulnerabilities', 'Substrate Block Proposal Vulnerabilities', 'Substrate Block Voting Vulnerabilities', 'Substrate Block Delegation Vulnerabilities', 'Substrate Block Bonding Vulnerabilities', 'Substrate Block Unbonding Vulnerabilities', 'Substrate Block Validator Vulnerabilities', 'Substrate Block Nominator Vulnerabilities', 'Substrate Block Era Vulnerabilities', 'Substrate Block Session Vulnerabilities', 'Substrate Block Epoch Vulnerabilities', 'Substrate Block Slot Vulnerabilities', 'Substrate Block Production Vulnerabilities', 'Substrate Block Import Vulnerabilities', 'Substrate Block Validation Vulnerabilities', 'Substrate Block Finalization Vulnerabilities', 'Substrate Block Reorganization Vulnerabilities', 'Substrate Block Fork Vulnerabilities', 'Substrate Block Chain Vulnerabilities', 'Substrate Block State Vulnerabilities', 'Substrate Block Storage Vulnerabilities', 'Substrate Block Memory Vulnerabilities', 'Substrate Block Network Vulnerabilities', etc.)."]
) -> str:
    """
    Analyze Substrate code for platform-specific security risks and produce a prompt-ready request.

    Overview:
        Builds a structured analysis prompt for an LLM to review Substrate code (runtime, pallets,
        node/client pieces) against a caller-supplied list of threat categories. The returned string
        is suitable to send directly to a model.

    Parameters:
        function_explanation (str):
            Plain-English summary of the function purpose, side effects, and invariants.
            Include component type (runtime/pallet/node/client) and expected call contexts.
        function_body (str):
            Full, exact source of the function under review. Do not trim or elide lines.
        file_path (str):
            Repository-relative path to the source file for context in reports.
        substrate_context (str):
            Key platform details: versions, FRAME dependencies, origin/weight/fee behavior,
            storage scheme, consensus assumptions, and other execution constraints.
        list_of_substrate_threats (list[str]):
            Concrete threat names to check (e.g., Origin validation, Weight/fees, Storage encoding,
            Event emission, Call dispatch, Transaction validation, Consensus/finality, etc.).

    Expected input format:
        - function_body must be compilable/parsable as-is and include all necessary context
          for the reviewed function body (generics, bounds, macros) or clearly note omissions.
        - Threat list should be specific and de-duplicated.

    Output:
        str: A fully composed prompt that asks the LLM to analyze the provided code with:
            - Findings (issue, severity, likelihood, impact)
            - Concrete exploit scenarios if applicable
            - Direct code references (line/fragment) where possible
            - Actionable remediations with Substrate-specific guidance

    Quality requirements for LLM consumers:
        - Prefer precise checks around Origin, Weight, DispatchResult, SignedExtensions,
          storage read/write costs, and re-entrancy via hooks.
        - Consider fee-less calls, benchmarking assumptions, and off-chain workers.
        - Highlight unsafe usage of unchecked math, decode/encode pitfalls, and critical macros.

    Example:
        result = await substrate_general_threats(
            function_explanation="Token transfer extrinsic with balance checks and events",
            function_body="fn transfer(origin: OriginFor<T>, to: T::AccountId, amount: T::Balance) -> DispatchResult { ... }",
            file_path="pallets/token/src/lib.rs",
            substrate_context="FRAME vN, weight-based fees, signed origin required, event emission",
            list_of_substrate_threats=[
                "Origin validation", "Weight correctness", "Storage consistency", "Event correctness"
            ]
        )

    Notes:
        Use when the caller wants a model-ready, Substrate-aware prompt rather than raw analysis.
    """
    msg = f"""
SUBSTRATE GENERAL THREAT ANALYSIS REQUEST

Function Context:
- Substrate Purpose: {function_explanation}
- File Location: {file_path}
- Substrate Context: {substrate_context}
- Substrate Threats to Evaluate: {', '.join(list_of_substrate_threats)}

Substrate Source Code to Analyze:
{function_body}

Please perform a comprehensive Substrate security analysis focusing on the specified threats and provide detailed findings with Substrate-specific attack vector analysis, potential Substrate impact, and remediation guidance specific to Substrate vulnerabilities and secure Substrate development practices.
"""

    return msg


async def substrate_pallet_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Substrate pallet function does, its purpose in pallet development, and its role in the Substrate runtime. Should include pallet operations, storage management, and any pallet-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the Substrate pallet function including all statements, variable assignments, control flow, function calls, pallet operations, and any nested logic. This is the actual Substrate pallet code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'pallets/custom_pallet.rs', 'pallets/token_pallet.rs', 'pallets/governance_pallet.rs'). Used for context and reporting."], 
    pallet_context: Annotated[str, "Additional Substrate pallet context including the pallet type (e.g., token, governance, staking, treasury), pallet dependencies, and critical pallet operations this function handles."],
    list_of_pallet_threats: Annotated[list[str], "A comprehensive list of Substrate pallet-specific threats and vulnerabilities to check for during analysis. Each item should be a specific pallet threat type (e.g., 'Pallet Storage Vulnerabilities', 'Pallet Call Vulnerabilities', 'Pallet Event Vulnerabilities', 'Pallet Origin Vulnerabilities', 'Pallet Weight Vulnerabilities', 'Pallet Fee Vulnerabilities', 'Pallet Gas Vulnerabilities', 'Pallet Logic Vulnerabilities', 'Pallet Validation Vulnerabilities', 'Pallet Authorization Vulnerabilities', 'Pallet Authentication Vulnerabilities', 'Pallet Access Control Vulnerabilities', 'Pallet Session Management Vulnerabilities', 'Pallet Input Validation Vulnerabilities', 'Pallet Output Encoding Vulnerabilities', 'Pallet Error Handling Vulnerabilities', 'Pallet Logging Vulnerabilities', 'Pallet Monitoring Vulnerabilities', 'Pallet Auditing Vulnerabilities', 'Pallet Reporting Vulnerabilities', 'Pallet Analytics Vulnerabilities', 'Pallet Mining Vulnerabilities', 'Pallet Machine Learning Vulnerabilities', 'Pallet AI Vulnerabilities', 'Pallet Algorithm Vulnerabilities', 'Pallet Model Vulnerabilities', 'Pallet Training Vulnerabilities', 'Pallet Testing Vulnerabilities', 'Pallet Validation Vulnerabilities', 'Pallet Cross-Validation Vulnerabilities', 'Pallet Overfitting Vulnerabilities', 'Pallet Underfitting Vulnerabilities', 'Pallet Bias Vulnerabilities', 'Pallet Fairness Vulnerabilities', 'Pallet Discrimination Vulnerabilities', etc.)."]
) -> str:
    """
    Create a focused, LLM-ready prompt to review a FRAME pallet function.

    Parameters:
        function_explanation (str): What the pallet function is supposed to do and its invariants.
        function_body (str): Exact Rust code of the pallet function, unmodified.
        file_path (str): Repo-relative path where the code resides.
        pallet_context (str): FRAME dependencies, storage layout, hooks, origins, weights, fees.
        list_of_pallet_threats (list[str]): Targeted checks (e.g., origin/ensure_signed, bounded
            storage, dispatch weight/fees, event emission, error handling, benchmarking parity).

    Output:
        str: Prompt text instructing an LLM to report findings with severity, references, and fixes.

    Guidance for LLM:
        - Validate origin and privileges for state-changing extrinsics.
        - Check bounded collections and weight accounting for unbounded loops.
        - Verify events and errors reflect actual state transitions.
        - Consider hooks (on_finalize/on_initialize) and unsigned or inherent calls.

    Example:
        await substrate_pallet_threats(
            function_explanation="Mint tokens to an account under Admin origin",
            function_body="fn mint(origin: OriginFor<T>, to: T::AccountId, amount: T::Balance) -> DispatchResult { ... }",
            file_path="pallets/token/src/lib.rs",
            pallet_context="Admin origin, bounded maps, weight fees",
            list_of_pallet_threats=["Origin validation", "Weight correctness", "Storage bounds", "Event correctness"]
        )
    """
    msg = f"""
SUBSTRATE PALLET THREAT ANALYSIS REQUEST

Function Context:
- Pallet Purpose: {function_explanation}
- File Location: {file_path}
- Pallet Context: {pallet_context}
- Pallet Threats to Evaluate: {', '.join(list_of_pallet_threats)}

Substrate Pallet Source Code to Analyze:
{function_body}

Please perform a comprehensive Substrate pallet security analysis focusing on the specified threats and provide detailed findings with pallet-specific attack vector analysis, potential pallet impact, and remediation guidance specific to Substrate pallet vulnerabilities and secure pallet development practices.
"""

    return msg


async def substrate_runtime_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Substrate runtime function does, its purpose in runtime execution, and its role in the Substrate runtime. Should include runtime operations, execution environment, and any runtime-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the Substrate runtime function including all statements, variable assignments, control flow, function calls, runtime operations, and any nested logic. This is the actual Substrate runtime code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'runtime/src/lib.rs', 'runtime/src/runtime.rs', 'runtime/src/executive.rs'). Used for context and reporting."], 
    runtime_context: Annotated[str, "Additional Substrate runtime context including the runtime type (e.g., mainnet, testnet, development), runtime version, and critical runtime operations this function handles."],
    list_of_runtime_threats: Annotated[list[str], "A comprehensive list of Substrate runtime-specific threats and vulnerabilities to check for during analysis. Each item should be a specific runtime threat type (e.g., 'Runtime Execution Vulnerabilities', 'Runtime Storage Vulnerabilities', 'Runtime Event Vulnerabilities', 'Runtime Call Vulnerabilities', 'Runtime Origin Vulnerabilities', 'Runtime Weight Vulnerabilities', 'Runtime Fee Vulnerabilities', 'Runtime Gas Vulnerabilities', 'Runtime Block Vulnerabilities', 'Runtime Transaction Vulnerabilities', 'Runtime Consensus Vulnerabilities', 'Runtime Finality Vulnerabilities', 'Runtime Slashing Vulnerabilities', 'Runtime Staking Vulnerabilities', 'Runtime Governance Vulnerabilities', 'Runtime Treasury Vulnerabilities', 'Runtime Democracy Vulnerabilities', 'Runtime Council Vulnerabilities', 'Runtime Technical Committee Vulnerabilities', 'Runtime Referendum Vulnerabilities', 'Runtime Proposal Vulnerabilities', 'Runtime Voting Vulnerabilities', 'Runtime Delegation Vulnerabilities', 'Runtime Bonding Vulnerabilities', 'Runtime Unbonding Vulnerabilities', 'Runtime Validator Vulnerabilities', 'Runtime Nominator Vulnerabilities', 'Runtime Era Vulnerabilities', 'Runtime Session Vulnerabilities', 'Runtime Epoch Vulnerabilities', 'Runtime Slot Vulnerabilities', 'Runtime Block Production Vulnerabilities', 'Runtime Block Import Vulnerabilities', 'Runtime Block Validation Vulnerabilities', 'Runtime Block Finalization Vulnerabilities', 'Runtime Block Reorganization Vulnerabilities', 'Runtime Block Fork Vulnerabilities', 'Runtime Block Chain Vulnerabilities', 'Runtime Block State Vulnerabilities', 'Runtime Block Storage Vulnerabilities', 'Runtime Block Memory Vulnerabilities', 'Runtime Block Network Vulnerabilities', etc.)."]
) -> str:
    """
    Prepare a runtime-level security review prompt for an LLM.

    Parameters:
        function_explanation (str): Summary of runtime behavior, invariants, and trust boundaries.
        function_body (str): Exact Rust code for the runtime function under review.
        file_path (str): Repo-relative file path.
        runtime_context (str): Chain type, SignedExtensions, fees, benchmarking, consensus/finality.
        list_of_runtime_threats (list[str]): Explicit checks (dispatch filtering, weight safety,
            transaction validation, integrity checks, off-chain workers, upgrades/migrations).

    Output:
        str: Prompt instructing the LLM to produce precise findings with line references and fixes.

    LLM focus points:
        - Signed vs unsigned, filtering, and origin guarantees.
        - Weight accounting and DoS vectors via heavy loops or unbounded state.
        - Transaction validity (pre-dispatch) and post-state consistency.
        - Upgrade/migration safety and storage compatibility.

    Example:
        await substrate_runtime_threats(
            function_explanation="Dispatch a call with filters and fees enforcement",
            function_body="fn apply_extrinsic(uxt: UncheckedExtrinsic) -> ApplyExtrinsicResult { ... }",
            file_path="runtime/src/lib.rs",
            runtime_context="Custom SignedExtensions, weight fees, Aura+Babe finality",
            list_of_runtime_threats=["Dispatch filtering", "Weight correctness", "Transaction validity", "Storage integrity"]
        )
    """
    msg = f"""
SUBSTRATE RUNTIME THREAT ANALYSIS REQUEST

Function Context:
- Runtime Purpose: {function_explanation}
- File Location: {file_path}
- Runtime Context: {runtime_context}
- Runtime Threats to Evaluate: {', '.join(list_of_runtime_threats)}

Substrate Runtime Source Code to Analyze:
{function_body}

Please perform a comprehensive Substrate runtime security analysis focusing on the specified threats and provide detailed findings with runtime-specific attack vector analysis, potential runtime impact, and remediation guidance specific to Substrate runtime vulnerabilities and secure runtime development practices.
"""

    return msg
