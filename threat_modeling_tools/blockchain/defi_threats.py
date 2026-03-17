from typing import Annotated


async def defi_protocol_threats(
    defi_explanation: Annotated[str, "A clear, human-readable explanation of the DeFi protocol implementation, including its purpose (e.g., DEX, AMM, lending, yield farming, staking, derivatives), core mechanisms, token economics, and key protocol features."],
    defi_code: Annotated[str, "The complete source code of the DeFi protocol implementation including smart contracts, protocol logic, token interactions, liquidity management, and any DeFi-specific algorithms."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing the DeFi implementation (e.g., 'contracts/DEX.sol', 'protocols/amm.py', 'defi/lending.rs'). Used for context and reporting."], 
    protocol_type: Annotated[str, "The specific type of DeFi protocol being analyzed (e.g., 'AMM/DEX', 'Lending Protocol', 'Yield Farming', 'Staking Protocol', 'Derivatives', 'Cross-chain Bridge', 'Liquidity Mining', 'Governance Token', 'Synthetic Assets', 'Options Protocol', 'Perpetual Futures', 'Flash Loan Protocol', 'Insurance Protocol', 'NFT Marketplace', 'Multi-signature Wallet', 'Vault Strategy', etc.)."],
    list_of_defi_threats: Annotated[list[str], "A comprehensive list of DeFi-specific security threats and vulnerabilities to check for during analysis. Each item should be a specific DeFi threat type (e.g., 'Flash Loan Attack', 'MEV Attack', 'Sandwich Attack', 'Liquidity Drain Attack', 'Price Oracle Manipulation', 'Reentrancy Attack', 'Integer Overflow/Underflow', 'Access Control Bypass', 'Economic Exploit', 'Governance Attack', 'Token Inflation Attack', 'Liquidity Pool Manipulation', 'Arbitrage Exploit', 'Front-running Attack', 'Back-running Attack', 'JIT Liquidity Attack', 'Impermanent Loss Exploit', 'Slippage Attack', 'Rug Pull', 'Exit Scam', 'Smart Contract Bug', 'Upgrade Mechanism Attack', 'Proxy Pattern Attack', 'Delegate Call Attack', 'Self-destruct Attack', 'Gas Griefing', 'Denial of Service', 'Cross-chain Bridge Attack', 'Validator Slashing', 'Stake Manipulation', 'Yield Farming Exploit', 'Liquidation Attack', 'Collateral Manipulation', 'Interest Rate Manipulation', 'Liquidity Mining Exploit', 'Governance Token Manipulation', 'Voting Power Attack', 'Treasury Drain', 'Fee Manipulation', 'Token Standard Attack', 'ERC-20/ERC-721/ERC-1155 Exploit', 'Multi-sig Attack', 'Time-based Attack', 'Random Number Attack', 'Oracle Price Feed Attack', 'Chainlink Manipulation', 'Bandwidth Oracle Attack', 'TWAP Manipulation', 'VWAP Manipulation', 'Liquidity Sniping', 'Token Launch Attack', 'Initial Liquidity Attack', 'Pump and Dump', 'Wash Trading', 'Market Manipulation', 'Sybil Attack', 'Whale Attack', 'Coordinated Attack', 'Social Engineering', 'Phishing Attack', 'Private Key Compromise', 'Seed Phrase Attack', 'Hardware Wallet Attack', 'Social Recovery Attack', 'Multi-sig Social Engineering', 'Governance Social Engineering', 'Community Manipulation', 'Fake Token Attack', 'Honeypot Attack', 'Hidden Mint Function', 'Hidden Burn Function', 'Hidden Transfer Function', 'Hidden Approve Function', 'Hidden Pause Function', 'Hidden Upgrade Function', 'Hidden Admin Function', 'Backdoor Function', 'Malicious Code Injection', 'Supply Chain Attack', 'Dependency Attack', 'Library Attack', 'Import Attack', 'Inheritance Attack', 'Interface Attack', 'Abstract Contract Attack', 'Proxy Upgrade Attack', 'Implementation Attack', 'Storage Collision', 'Delegate Call Attack', 'Self-destruct Attack', 'Create2 Attack', 'Contract Creation Attack', 'Factory Pattern Attack', 'Clone Pattern Attack', 'Beacon Pattern Attack', 'Diamond Pattern Attack', 'EIP-1967 Attack', 'EIP-1822 Attack', 'EIP-2535 Attack', 'EIP-1167 Attack', 'EIP-897 Attack', etc.)."]
) -> str:
    """
    Create an LLM prompt for holistic DeFi protocol security and economic analysis.

    Parameters:
        defi_explanation (str): Purpose, economics, core mechanisms, and invariants.
        defi_code (str): Exact source for the protocol components under review.
        file_path (str): Repo-relative path.
        protocol_type (str): DEX/AMM/lending/staking/derivatives/etc.
        list_of_defi_threats (list[str]): Specific economic and technical threats to test.

    Output:
        str: Prompt directing the LLM to produce both technical and economic findings with fixes.

    LLM guidance:
        - Validate oracle design, manipulation resistance, and fallback behavior.
        - Analyze MEV/sandwich/flash loan exposure and mitigation.
        - Check collateralization/liquidation math, rounding, and solvency conditions.
        - Review upgrade/proxy patterns, access control, and pause/guardian logic.
    """
    msg = f"""
DEFI PROTOCOL THREAT ANALYSIS REQUEST

DeFi Protocol Context:
- Protocol Type: {protocol_type}
- Protocol Purpose: {defi_explanation}
- File Location: {file_path}
- DeFi Threats to Evaluate: {', '.join(list_of_defi_threats)}

DeFi Protocol Source Code to Analyze:
{defi_code}

Please perform a comprehensive DeFi protocol security analysis focusing on the specified threats and provide detailed findings with DeFi-specific attack vector analysis, potential economic impact, and remediation guidance specific to DeFi protocol vulnerabilities and security best practices. Pay special attention to:

1. Economic attack vectors (flash loans, MEV, arbitrage exploits)
2. Liquidity manipulation attacks (sandwich attacks, JIT liquidity)
3. Oracle manipulation and price feed attacks
4. Governance and token economics vulnerabilities
5. Smart contract specific vulnerabilities (reentrancy, access control)
6. Cross-protocol interaction risks
7. User fund safety and protocol solvency
8. AMM-specific vulnerabilities (impermanent loss, slippage attacks)
9. Lending protocol risks (liquidation attacks, collateral manipulation)
10. Yield farming and staking protocol exploits

Focus on both technical vulnerabilities and economic attack vectors that are specific to DeFi protocols and AMMs.
"""

    return msg


async def amm_specific_threats(
    amm_explanation: Annotated[str, "A clear, human-readable explanation of the AMM (Automated Market Maker) implementation, including the pricing formula (e.g., x*y=k, x*y*z=k, constant sum, weighted geometric mean), fee structure, liquidity provision mechanism, and trading algorithms."],
    amm_code: Annotated[str, "The complete source code of the AMM implementation including swap functions, liquidity management, price calculation, fee collection, and any AMM-specific algorithms."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing the AMM implementation (e.g., 'contracts/AMM.sol', 'protocols/uniswap.py', 'amm/curve.rs'). Used for context and reporting."], 
    amm_type: Annotated[str, "The specific type of AMM being analyzed (e.g., 'Constant Product (x*y=k)', 'Constant Sum', 'Weighted Geometric Mean', 'StableSwap', 'Curve AMM', 'Balancer Weighted Pool', 'Uniswap V2', 'Uniswap V3', 'SushiSwap', 'PancakeSwap', '1inch Liquidity Protocol', 'Bancor V2/V3', 'Kyber Network', '0x Protocol', 'Matcha', 'ParaSwap', 'DODO', 'Balancer V2', 'Curve V2', 'Convex', 'Yearn Vault', 'Harvest Finance', 'Badger DAO', 'Pickle Finance', 'Alchemix', 'Rari Capital', 'Compound', 'Aave', 'MakerDAO', 'Synthetix', 'UMA', 'Chainlink', 'Band Protocol', 'Tellor', 'API3', 'Nest Protocol', 'DOS Network', 'TLSNotary', 'Witnet', 'Provable', 'Reality.eth', 'Augur', 'Gnosis', 'Polymarket', 'Omen', 'Veil', 'Predictions', 'Futureswap', 'Perpetual Protocol', 'dYdX', 'DerivaDEX', 'MCDEX', 'Injective Protocol', 'Serum', 'Raydium', 'Orca', 'Saber', 'Mercurial', 'Aldrin', 'Crema Finance', 'Orion Protocol', 'THORChain', 'Ren Protocol', 'Keep Network', 'tBTC', 'wBTC', 'HBTC', 'imBTC', 'pBTC', 'sBTC', 'rBTC', 'oBTC', etc.)."],
    list_of_amm_threats: Annotated[list[str], "A comprehensive list of AMM-specific security threats and vulnerabilities to check for during analysis. Each item should be a specific AMM threat type (e.g., 'Impermanent Loss', 'Slippage Attack', 'Price Impact Manipulation', 'Liquidity Sniping', 'JIT Liquidity Attack', 'MEV Sandwich Attack', 'Front-running Attack', 'Back-running Attack', 'Arbitrage Exploit', 'Flash Loan Attack', 'Price Oracle Manipulation', 'TWAP Manipulation', 'VWAP Manipulation', 'Liquidity Pool Drain', 'Token Pair Manipulation', 'Reserve Manipulation', 'Fee Manipulation', 'Governance Attack', 'Liquidity Mining Exploit', 'Yield Farming Attack', 'Staking Attack', 'Validator Attack', 'Delegation Attack', 'Slashing Attack', 'Unbonding Attack', 'Reward Manipulation', 'Inflation Attack', 'Deflation Attack', 'Burn Attack', 'Mint Attack', 'Transfer Attack', 'Approve Attack', 'Allowance Attack', 'Balance Manipulation', 'Supply Manipulation', 'Total Supply Attack', 'Circulating Supply Attack', 'Max Supply Attack', 'Decimals Attack', 'Symbol Attack', 'Name Attack', 'URI Attack', 'Metadata Attack', 'Token Standard Attack', 'ERC-20 Attack', 'ERC-721 Attack', 'ERC-1155 Attack', 'ERC-777 Attack', 'ERC-1400 Attack', 'ERC-1410 Attack', 'ERC-1643 Attack', 'ERC-1644 Attack', 'ERC-1820 Attack', 'ERC-1822 Attack', 'ERC-1967 Attack', 'ERC-2535 Attack', 'ERC-1167 Attack', 'ERC-897 Attack', 'EIP-20 Attack', 'EIP-721 Attack', 'EIP-1155 Attack', 'EIP-777 Attack', 'EIP-1400 Attack', 'EIP-1410 Attack', 'EIP-1643 Attack', 'EIP-1644 Attack', 'EIP-1820 Attack', 'EIP-1822 Attack', 'EIP-1967 Attack', 'EIP-2535 Attack', 'EIP-1167 Attack', 'EIP-897 Attack', etc.)."]
) -> str:
    """
    Build an LLM prompt for AMM-specific security and market-mechanism review.

    Parameters:
        amm_explanation (str): Pricing formula, fee model, liquidity mechanisms, invariants.
        amm_code (str): Exact source under review.
        file_path (str): Repo-relative path.
        amm_type (str): AMM type (constant product, stableswap, weighted, CL/MM, etc.).
        list_of_amm_threats (list[str]): Targeted threats (MEV, slippage, price impact, LP drain).

    Output:
        str: Prompt asking the LLM to surface issues with concrete fixes and references.
    """
    msg = f"""
AMM THREAT ANALYSIS REQUEST

AMM Context:
- AMM Type: {amm_type}
- AMM Purpose: {amm_explanation}
- File Location: {file_path}
- AMM Threats to Evaluate: {', '.join(list_of_amm_threats)}

AMM Source Code to Analyze:
{amm_code}

Please perform a comprehensive AMM security analysis focusing on the specified threats and provide detailed findings with AMM-specific attack vector analysis, potential economic impact, and remediation guidance specific to AMM vulnerabilities and security best practices. Pay special attention to:

1. Liquidity manipulation attacks (sandwich attacks, JIT liquidity, liquidity sniping)
2. Price impact and slippage vulnerabilities
3. MEV (Maximal Extractable Value) attack vectors
4. Flash loan exploitation of AMM mechanisms
5. Oracle manipulation and price feed attacks
6. Impermanent loss and liquidity provider risks
7. Fee structure and economic model vulnerabilities
8. Token pair and reserve manipulation
9. Governance and protocol upgrade risks
10. Cross-AMM arbitrage and exploitation opportunities

Focus on both technical vulnerabilities and economic attack vectors that are specific to AMM implementations and liquidity management systems.
"""

    return msg


async def lending_protocol_threats(
    lending_explanation: Annotated[str, "A clear, human-readable explanation of the lending protocol implementation, including collateral types, loan-to-value ratios, liquidation mechanisms, interest rate models, and risk management features."],
    lending_code: Annotated[str, "The complete source code of the lending protocol including deposit/borrow/repay/liquidate functions, collateral management, interest calculation, and risk assessment logic."],
    file_path: Annotated[str, "The full relative path from the project root to the file containing the lending protocol (e.g., 'contracts/Lending.sol', 'protocols/compound.rs', 'lending/aave.py')."],
    lending_context: Annotated[str, "Additional context including protocol type (peer-to-peer, pool-based, CDP), supported assets, oracle dependencies, and liquidation parameters."],
    list_of_lending_threats: Annotated[list[str], "Comprehensive list of lending-specific threats like 'Oracle Manipulation', 'Liquidation Front-Running', 'Under-Collateralization', 'Interest Rate Manipulation', 'Flash Loan Attack', 'Bad Debt Accumulation', 'Liquidation Cascades', 'Price Oracle Failure', 'Collateral Token Devaluation', 'Borrowing Limit Bypass', 'Health Factor Manipulation', 'Liquidation Threshold Exploit', 'Interest Model Exploit', 'Reserve Depletion', 'Liquidity Crunch', 'Governance Attack on Parameters', 'Collateral Seizure Issues', 'Partial Liquidation Abuse', 'Liquidation Bonus Exploitation', 'Debt Ceiling Bypass', etc."]
) -> str:
    """
    Analyze lending protocol security focusing on collateralization, liquidation, and solvency.
    
    Critical Focus:
        - Collateral management and valuation
        - Liquidation mechanisms and incentives
        - Interest rate models and manipulation
        - Oracle dependencies and price feeds
        - Flash loan attack vectors
        - Protocol solvency and bad debt
        - Borrowing and lending limits
        - Health factor calculations
    """
    prompt = f"""
You are a DeFi security expert specializing in Lending Protocol vulnerabilities.

**LENDING PROTOCOL CONTEXT:**
{lending_context}

**FILE:** {file_path}

**PROTOCOL EXPLANATION:**
{lending_explanation}

**CODE:**
```
{lending_code}
```

**LENDING THREATS TO ANALYZE:**
{chr(10).join(f'- {threat}' for threat in list_of_lending_threats)}

**CRITICAL LENDING PROTOCOL SECURITY CHECKS:**

1. **Collateral Management:**
   - Is collateral valuation using reliable oracles?
   - Are collateral factors (LTV ratios) appropriate for asset volatility?
   - Is collateral seizure mechanism secure and fair?
   - Are multiple collateral types properly isolated?
   - Is collateral token reentrancy prevented?
   - Are ERC-777 or token-with-hooks safely handled?

2. **Liquidation Security:**
   - Is liquidation threshold set appropriately (typically 120-150%)?
   - Is liquidation bonus/discount fair (typically 5-15%)?
   - Are partial liquidations allowed to prevent cascades?
   - Is liquidation front-running mitigated?
   - Can flash loans be used for atomic liquidation?
   - Is liquidation process resistant to DoS?
   - Are liquidation auctions implemented securely?

3. **Oracle Security:**
   - Are multiple oracle sources used (Chainlink, Band, TWAP)?
   - Is there a fallback oracle mechanism?
   - Are oracle price updates timely (heartbeat checks)?
   - Is price manipulation via flash loans prevented?
   - Are TWAP oracles using sufficient time windows?
   - Is oracle freshness validated?
   - Are circuit breakers in place for price anomalies?

4. **Interest Rate Model:**
   - Is interest rate calculation correct (compound vs simple)?
   - Are utilization rate thresholds appropriate?
   - Is the kink/optimal utilization point reasonable?
   - Can interest rates be manipulated via large deposits/borrows?
   - Are interest accrual calculations safe from overflow?
   - Is interest rate update frequency appropriate?

5. **Health Factor & Solvency:**
   - Is health factor calculation correct: (collateral * LTV) / debt?
   - Is liquidation triggered at health factor < 1?
   - Are all user positions properly tracked?
   - Is protocol-wide solvency monitored?
   - Is bad debt detection and handling implemented?
   - Are insolvency scenarios handled gracefully?

6. **Flash Loan Attack Vectors:**
   - Can flash loans manipulate oracle prices?
   - Can flash loans drain protocol reserves?
   - Is atomic borrow/repay/liquidate prevented if exploitable?
   - Are flash loan fees sufficient to deter attacks?
   - Is re-entrancy in flash loan callbacks prevented?

7. **Borrowing & Lending Limits:**
   - Are per-user borrow limits enforced?
   - Are per-asset debt ceilings set?
   - Is total protocol borrow capacity limited?
   - Are reserve ratios maintained?
   - Is liquidity sufficient for withdrawals?

8. **Economic Attacks:**
   - Can large positions manipulate interest rates?
   - Are governance attacks on risk parameters prevented?
   - Is cross-collateral liquidation risk managed?
   - Are correlated asset risks understood?
   - Is protocol profitable at all utilization rates?

9. **Reserve Management:**
   - Are protocol reserves sufficient for bad debt coverage?
   - Is reserve factor appropriate (typically 10-20%)?
   - Are reserves protected from unauthorized withdrawal?
   - Is reserve depletion monitored?

10. **Access Control & Governance:**
    - Are admin functions properly protected?
    - Can governance change risk parameters safely?
    - Are there time locks on critical parameter changes?
    - Is emergency pause functionality available?
    - Are admin keys secure (multi-sig)?

**OUTPUT:** For each vulnerability, provide:
- Title and severity rating
- Affected component (collateral/liquidation/interest/oracle)
- Attack scenario with concrete numbers and transactions
- Economic impact (potential loss, bad debt, insolvency)
- Likelihood based on current market conditions
- Remediation with specific parameter recommendations
- Code fixes if applicable
- Testing approach to verify fix

Focus on oracle security, liquidation mechanics, and protocol solvency.
"""
    return prompt


async def borrowing_security_threats(
    borrowing_explanation: Annotated[str, "Explanation of borrowing functionality including borrow limits, health factor checks, interest accrual, and repayment mechanisms."],
    borrowing_code: Annotated[str, "Complete source code handling borrow operations, debt tracking, interest calculation, and repayment processing."],
    file_path: Annotated[str, "Path to the borrowing implementation file."],
    borrowing_context: Annotated[str, "Borrowing context: supported borrow assets, overcollateralization requirements, interest model, liquidation triggers, and debt management approach."],
    list_of_borrowing_threats: Annotated[list[str], "Borrowing threats like 'Borrow Limit Bypass', 'Overcollateralization Bypass', 'Interest Manipulation', 'Repayment Front-Running', 'Debt Token Manipulation', 'Borrow Rate Exploit', 'Flash Borrow Attack', 'Atomic Borrow-Liquidate', 'Debt Ceiling Overflow', 'Utilization Manipulation', etc."]
) -> str:
    """
    Analyze borrowing mechanism security and debt management.
    
    Critical Focus:
        - Borrow limit enforcement
        - Health factor validation before borrow
        - Interest accrual correctness
        - Debt tracking and accounting
        - Repayment and debt reduction
        - Flash borrowing attack prevention
    """
    prompt = f"""
You are a DeFi security expert focusing on Borrowing Mechanism vulnerabilities.

**BORROWING CONTEXT:**
{borrowing_context}

**FILE:** {file_path}

**FUNCTION EXPLANATION:**
{borrowing_explanation}

**CODE:**
```
{borrowing_code}
```

**BORROWING THREATS TO ANALYZE:**
{chr(10).join(f'- {threat}' for threat in list_of_borrowing_threats)}

**CRITICAL BORROWING SECURITY CHECKS:**

1. **Borrow Limit Enforcement:**
   - Is maximum borrow amount calculated correctly from collateral?
   - Is borrow limit: collateral_value * collateral_factor?
   - Are existing borrows subtracted from available borrow capacity?
   - Is per-asset debt ceiling enforced?
   - Is protocol-wide borrow cap respected?

2. **Health Factor Validation:**
   - Is health factor checked BEFORE allowing new borrows?
   - Is minimum health factor enforced (typically > 1.0)?
   - Are all user positions aggregated in health calculation?
   - Is health factor updated atomically with borrow?

3. **Interest Accrual:**
   - Is interest accrued before every borrow operation?
   - Is compound interest calculated correctly?
   - Is interest rate updated based on new utilization?
   - Are interest calculations safe from overflow?
   - Is accrual timestamp properly updated?

4. **Debt Tracking:**
   - Is user debt balance increased correctly?
   - Is total protocol debt updated atomically?
   - Are debt tokens minted/tracked properly?
   - Is debt denominated correctly (principal vs principal + interest)?
   - Are debt shares calculated correctly if using share-based system?

5. **Asset Availability:**
   - Is there sufficient liquidity in pool for borrow?
   - Is reserve factor maintained after borrow?
   - Are withdrawals still possible after large borrows?
   - Is utilization rate within safe limits (typically < 90%)?

6. **Flash Borrow Protection:**
   - Are same-block borrow-repay patterns prevented if exploitable?
   - Is flash borrow fee sufficient?
   - Is re-entrancy in borrow function prevented?
   - Can flash borrows manipulate interest rates?

7. **Repayment Security:**
   - Is debt reduced correctly on repayment?
   - Are excess payments handled (full repayment)?
   - Is interest settled before applying repayment?
   - Are repayments protected from front-running?
   - Can third parties repay on behalf of borrowers?

8. **Oracle Dependency:**
   - Is asset price checked during borrow?
   - Is oracle freshness validated?
   - Are stale prices rejected?
   - Is price manipulation via flash loans prevented?

9. **Economic Attacks:**
   - Can large borrows manipulate interest rates?
   - Is borrow rate exploitable via utilization manipulation?
   - Are cross-market manipulations prevented?
   - Is the borrow profitable for the protocol?

10. **Edge Cases:**
    - What if collateral value drops immediately after borrow?
    - What if interest accrual causes health factor < 1?
    - What if asset becomes deprecated/delisted?
    - What if oracle fails during borrow?
    - What if repayment is frontrun by liquidation?

**OUTPUT:** For each vulnerability, provide:
- Title and severity
- Specific borrow calculation or check that's flawed
- Attack scenario showing exploit steps
- Impact (overborrowing amount, protocol loss)
- Remediation with corrected logic
- Test cases to verify fix

Focus on borrow limit enforcement, health factor validation, and interest correctness.
"""
    return prompt


async def liquidation_mechanism_threats(
    liquidation_explanation: Annotated[str, "Explanation of liquidation mechanism including liquidation triggers, liquidation discounts, partial vs full liquidation, and liquidator incentives."],
    liquidation_code: Annotated[str, "Complete source code handling liquidation logic, collateral seizure, debt repayment, and liquidation rewards."],
    file_path: Annotated[str, "Path to the liquidation implementation file."],
    liquidation_context: Annotated[str, "Liquidation context: liquidation threshold (health factor), liquidation bonus/discount, close factor (max liquidatable portion), auction mechanism if applicable, and liquidation bot infrastructure."],
    list_of_liquidation_threats: Annotated[list[str], "Liquidation threats like 'Liquidation Front-Running', 'Liquidation Cascade', 'Unfair Liquidation Bonus', 'Partial Liquidation Abuse', 'Liquidation Threshold Manipulation', 'Self-Liquidation', 'Atomic Liquidation Attack', 'Liquidation Bot Monopoly', 'Collateral Seizure Errors', 'Bad Debt From Failed Liquidation', 'Oracle Manipulation For Liquidation', 'Gas Price Manipulation', 'Liquidation DoS', etc."]
) -> str:
    """
    Analyze liquidation mechanism security and fairness.
    
    Critical Focus:
        - Liquidation trigger accuracy (health factor)
        - Liquidation incentives (bonus/discount)
        - Partial liquidation to prevent cascades
        - Liquidation DoS prevention
        - Fair liquidation competition
        - Bad debt prevention
    """
    prompt = f"""
You are a DeFi security expert focusing on Liquidation Mechanism vulnerabilities.

**LIQUIDATION CONTEXT:**
{liquidation_context}

**FILE:** {file_path}

**FUNCTION EXPLANATION:**
{liquidation_explanation}

**CODE:**
```
{liquidation_code}
```

**LIQUIDATION THREATS TO ANALYZE:**
{chr(10).join(f'- {threat}' for threat in list_of_liquidation_threats)}

**CRITICAL LIQUIDATION SECURITY CHECKS:**

1. **Liquidation Trigger:**
   - Is health factor calculated correctly before liquidation?
   - Is liquidation only allowed when health factor < 1?
   - Are all user positions included in health calculation?
   - Is oracle price used for health check fresh and accurate?
   - Can liquidation be triggered prematurely via oracle manipulation?

2. **Liquidation Bonus/Discount:**
   - Is liquidation bonus fair (typically 5-15%)?
   - Is bonus sufficient to incentivize liquidators?
   - Is bonus not excessive to avoid unfair loss to borrowers?
   - Is bonus calculated correctly: collateral_seized = debt_repaid * (1 + bonus)?
   - Are bonuses different per asset based on volatility?

3. **Partial Liquidation:**
   - Is partial liquidation allowed to prevent cascades?
   - Is close factor enforced (typically 50%)?
   - Does partial liquidation restore health factor above threshold?
   - Is minimum liquidation amount reasonable?
   - Can liquidators choose liquidation amount within limits?

4. **Collateral Seizure:**
   - Is collateral value calculated correctly?
   - Is seized collateral transferred atomically with debt repayment?
   - Is collateral of correct type seized (if multiple collaterals)?
   - Are remaining collateral and debt updated correctly?
   - Is collateral seizure safe from reentrancy?

5. **Liquidation Competition:**
   - Is liquidation mempool front-running mitigated?
   - Are liquidation auctions fair and transparent?
   - Can multiple liquidators participate fairly?
   - Is liquidation monopoly by MEV bots prevented?
   - Are gas price wars discouraged?

6. **Bad Debt Prevention:**
   - What if collateral value < debt at liquidation time?
   - Is protocol insolvency handled (socialized loss)?
   - Are reserves used to cover bad debt?
   - Is bad debt detection and reporting implemented?
   - Are liquidations prioritized by size/risk?

7. **Liquidation Cascades:**
   - Can large liquidations cause price impact affecting others?
   - Are liquidation amounts limited to prevent cascades?
   - Is oracle price manipulation during liquidation detected?
   - Are correlated asset liquidations managed?

8. **Self-Liquidation & Atomic Attacks:**
   - Can users self-liquidate to capture bonus?
   - Can flash loans enable atomic borrow-liquidate attacks?
   - Is same-block liquidation after borrow prevented?
   - Are liquidation bypass patterns detected?

9. **Liquidation DoS:**
   - Can liquidations be DoS'd via gas limit?
   - Are liquidation calls protected from griefing?
   - Is liquidation retry/recovery mechanism available?
   - Are stuck positions handled?

10. **Oracle Dependency:**
    - Is oracle price manipulation for liquidation detected?
    - Are multiple price sources used?
    - Is price deviation threshold enforced?
    - Are circuit breakers in place for volatile conditions?

11. **Economic Fairness:**
    - Is liquidation penalty fair to borrowers?
    - Are liquidators sufficiently incentivized?
    - Is liquidation profitable even with gas costs?
    - Are liquidation economics sustainable?

**OUTPUT:** For each vulnerability, provide:
- Title and severity
- Specific liquidation logic flaw
- Attack scenario (with sample numbers)
- Impact (unfair liquidation, bad debt, cascade risk)
- Remediation with improved liquidation logic
- Parameter recommendations (bonus, close factor, threshold)
- Testing approach for different market conditions

Focus on liquidation trigger accuracy, fair incentives, and bad debt prevention.
"""
    return prompt


async def collateral_management_threats(
    collateral_explanation: Annotated[str, "Explanation of collateral management including collateral deposits, withdrawals, collateral factors, multi-collateral support, and collateral valuation."],
    collateral_code: Annotated[str, "Complete source code handling collateral operations, collateral factor configuration, collateral valuation, and collateral accounting."],
    file_path: Annotated[str, "Path to the collateral management file."],
    collateral_context: Annotated[str, "Collateral context: supported collateral types, collateral factors (LTV), oracle dependencies, collateral isolation mode, cross-collateral borrowing, and reserve requirements."],
    list_of_collateral_threats: Annotated[list[str], "Collateral threats like 'Collateral Token Reentrancy', 'Collateral Valuation Manipulation', 'Collateral Factor Exploit', 'Unauthorized Collateral Withdrawal', 'Cross-Collateral Attack', 'Collateral Token Upgrade Risk', 'ERC-777 Hook Exploitation', 'Deflation Token Issues', 'Fee-On-Transfer Token Problems', 'Collateral Oracle Failure', 'Collateral Correlation Risk', etc."]
) -> str:
    """
    Analyze collateral management security and valuation correctness.
    
    Critical Focus:
        - Collateral token safety (reentrancy, hooks)
        - Collateral valuation accuracy
        - Collateral factor appropriateness
        - Withdrawal restrictions based on health
        - Multi-collateral isolation
        - Unusual token types (fee-on-transfer, rebase, etc.)
    """
    prompt = f"""
You are a DeFi security expert focusing on Collateral Management vulnerabilities.

**COLLATERAL CONTEXT:**
{collateral_context}

**FILE:** {file_path}

**FUNCTION EXPLANATION:**
{collateral_explanation}

**CODE:**
```
{collateral_code}
```

**COLLATERAL THREATS TO ANALYZE:**
{chr(10).join(f'- {threat}' for threat in list_of_collateral_threats)}

**CRITICAL COLLATERAL SECURITY CHECKS:**

1. **Collateral Token Safety:**
   - Are ERC-777 tokens with hooks safely handled?
   - Is reentrancy during collateral deposit/withdrawal prevented?
   - Are fee-on-transfer tokens detected and handled?
   - Are rebase tokens (e.g., stETH) properly tracked?
   - Are deflation tokens accounting for burn correctly?
   - Is token pause functionality considered?
   - Are upgradeable token risks managed?

2. **Collateral Deposit:**
   - Is collateral transfer amount validated?
   - Is actual received amount checked (for fee-on-transfer)?
   - Is collateral balance updated atomically?
   - Is collateral factor applied correctly?
   - Are deposit limits per asset enforced?
   - Is token approve/transferFrom pattern secure?

3. **Collateral Withdrawal:**
   - Is health factor checked before withdrawal?
   - Is remaining collateral sufficient for existing borrows?
   - Is withdrawal amount validated against available?
   - Is collateral accounting updated correctly?
   - Are partial withdrawals handled properly?

4. **Collateral Valuation:**
   - Is collateral valued using reliable oracles?
   - Is oracle freshness checked (heartbeat)?
   - Are stale prices rejected?
   - Is price manipulation via flash loans prevented?
   - Are multiple oracle sources aggregated?
   - Is price deviation monitored?

5. **Collateral Factor (LTV):**
   - Are collateral factors appropriate for asset volatility?
   - Is LTV typically 50-80% for volatile assets?
   - Is LTV higher (85-95%) for stable assets?
   - Can governance change factors safely (timelock)?
   - Are factor changes gradual to prevent sudden liquidations?

6. **Multi-Collateral Management:**
   - Are different collateral types properly isolated?
   - Is cross-collateral liquidation risk managed?
   - Are correlated assets identified?
   - Is total collateral value aggregated correctly?
   - Are collateral weights applied correctly?

7. **Collateral Accounting:**
   - Is collateral balance tracked per user?
   - Is total protocol collateral updated atomically?
   - Are collateral shares calculated correctly if using shares?
   - Is collateral yield (if interest-bearing) handled?
   - Are rounding errors in favor of protocol?

8. **Unusual Token Types:**
   - **Rebase tokens**: Is changing balance handled?
   - **Fee-on-transfer**: Is actual received amount used?
   - **Deflation tokens**: Is burn amount tracked?
   - **Upgradeable tokens**: Is upgrade risk mitigated?
   - **Pausable tokens**: Is pause scenario handled?
   - **Blacklist tokens**: Are blacklisted users handled?

9. **Oracle Failures:**
   - What if oracle stops updating?
   - What if oracle price deviates significantly?
   - Is fallback oracle available?
   - Are circuit breakers in place?
   - Is manual intervention possible?

10. **Economic Attacks:**
    - Can collateral valuation be manipulated?
    - Are flash loan oracle attacks prevented?
    - Is collateral market manipulation detected?
    - Are large collateral deposits/withdrawals monitored?
    - Is collateral concentration risk managed?

**OUTPUT:** For each vulnerability, provide:
- Title and severity
- Affected collateral operation or token type
- Attack scenario with specific token example
- Impact (unauthorized withdrawal, valuation manipulation)
- Remediation with safe token handling patterns
- Token compatibility checklist
- Testing approach for various token types

Focus on token safety (reentrancy, hooks), valuation accuracy, and unusual token types.
"""
    return prompt


async def interest_rate_model_threats(
    interest_explanation: Annotated[str, "Explanation of interest rate model including utilization rate calculation, base rate, slope parameters, kink/optimal point, and interest accrual mechanism."],
    interest_code: Annotated[str, "Complete source code implementing interest rate calculation, utilization tracking, rate updates, and interest accrual."],
    file_path: Annotated[str, "Path to the interest rate model file."],
    interest_context: Annotated[str, "Interest context: interest model type (linear, kinked, dynamic), base rate, slope before/after kink, optimal utilization rate, compound vs simple interest, and accrual frequency."],
    list_of_interest_threats: Annotated[list[str], "Interest rate threats like 'Utilization Manipulation', 'Interest Rate Exploit', 'Accrual Overflow', 'Kink Point Manipulation', 'Rate Update Front-Running', 'Compound Interest Errors', 'Timestamp Manipulation For Accrual', 'Extreme Rate Conditions', 'Rate Parameter Governance Attack', 'Interest Rounding Errors', etc."]
) -> str:
    """
    Analyze interest rate model security and economic soundness.
    
    Critical Focus:
        - Utilization rate calculation accuracy
        - Interest rate formula correctness
        - Accrual calculation (compound interest)
        - Rate manipulation prevention
        - Extreme rate handling
        - Economic sustainability
    """
    prompt = f"""
You are a DeFi security expert focusing on Interest Rate Model vulnerabilities.

**INTEREST RATE CONTEXT:**
{interest_context}

**FILE:** {file_path}

**FUNCTION EXPLANATION:**
{interest_explanation}

**CODE:**
```
{interest_code}
```

**INTEREST RATE THREATS TO ANALYZE:**
{chr(10).join(f'- {threat}' for threat in list_of_interest_threats)}

**CRITICAL INTEREST RATE MODEL SECURITY CHECKS:**

1. **Utilization Rate Calculation:**
   - Is utilization = total_borrows / (total_cash + total_borrows - total_reserves)?
   - Is division by zero handled (when no liquidity)?
   - Is utilization capped at 100% (1e18)?
   - Is calculation updated atomically with borrow/repay?
   - Are rounding errors in favor of protocol?

2. **Interest Rate Formula:**
   - **Below kink**: rate = base_rate + utilization * slope1
   - **Above kink**: rate = base_rate + optimal_util * slope1 + (util - optimal) * slope2
   - Are slope parameters reasonable?
   - Is kink point (optimal utilization) typically 80-90%?
   - Is slope2 steep enough to discourage over-utilization?
   - Are rates in appropriate range (e.g., 0-100% APY)?

3. **Compound Interest Accrual:**
   - Is compound interest formula correct: principal * (1 + rate)^time?
   - Is time calculated accurately (block.timestamp - lastAccrualTime)?
   - Are interest calculations safe from overflow (use 256-bit)?
   - Is accrual called before every rate-sensitive operation?
   - Is accrual timestamp updated correctly?

4. **Interest Accrual Frequency:**
   - Is interest accrued on every interaction (optimal)?
   - If batched, is accrual at least once per block?
   - Is stale interest (long time since last accrual) handled?
   - Are very long accrual periods (e.g., years) safe from overflow?

5. **Rate Manipulation:**
   - Can large deposits manipulate rates downward?
   - Can large borrows manipulate rates upward?
   - Are flash loan manipulations prevented?
   - Is atomic deposit-borrow-withdraw profitable for attacker?
   - Are rate changes bounded per transaction?

6. **Extreme Rate Conditions:**
   - What if utilization approaches 100%?
   - Are rates capped at maximum (e.g., 1000% APY)?
   - Is protocol functional at extreme rates?
   - Are withdrawals still possible near 100% utilization?
   - Is reserve factor applied correctly at all rates?

7. **Reserve Factor:**
   - Is reserve factor deducted from borrow interest?
   - Is reserve factor typically 10-20%?
   - Are reserves accumulated correctly over time?
   - Is reserve factor applied before distributing to lenders?

8. **Precision & Rounding:**
   - Are calculations using sufficient precision (1e18)?
   - Are rounding errors always in favor of protocol?
   - Is precision loss over many accruals minimized?
   - Are integer division truncations handled correctly?

9. **Timestamp Dependency:**
   - Is block.timestamp used for time calculations?
   - Is miner timestamp manipulation impact minimal?
   - Are time-based calculations resistant to clock skew?
   - Is accrual based on actual elapsed time?

10. **Economic Sustainability:**
    - Is borrow rate > supply rate (protocol profits)?
    - Is rate spread sufficient to cover risks and operations?
    - Are rates competitive with other protocols?
    - Is the model stable at various utilization levels?
    - Are parameter changes tested thoroughly?

11. **Governance & Parameter Changes:**
    - Can governance change rate parameters safely?
    - Are parameter changes timelocked?
    - Are changes gradual to prevent shock?
    - Is parameter validation enforced (reasonable ranges)?

**OUTPUT:** For each vulnerability, provide:
- Title and severity
- Specific formula or calculation flaw
- Attack scenario showing manipulation
- Impact (protocol profit loss, user loss)
- Remediation with corrected formula
- Parameter recommendations for stability
- Simulation results at various utilization levels

Focus on utilization calculation, accrual correctness, and manipulation prevention.
"""
    return prompt
