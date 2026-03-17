from typing import Annotated


async def ripple_general_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Ripple/XRPL function does, its purpose in the XRP Ledger ecosystem, and its role in the application. Should include transaction types, account operations, and any XRPL-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the Ripple/XRPL function including all statements, variable assignments, control flow, function calls, transaction submissions, and any nested logic. This is the actual code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'src/transactions/payment.js', 'lib/xrpl/escrow.ts', 'services/trustlines.py'). Used for context and reporting."], 
    ripple_context: Annotated[str, "Additional XRP Ledger context including the network (mainnet/testnet/devnet), xrpl library version, wallet management approach, and critical XRPL operations this function handles."],
    list_of_ripple_threats: Annotated[list[str], "A comprehensive list of Ripple/XRPL-specific threats and vulnerabilities to check for during analysis. Each item should be a specific XRPL threat type (e.g., 'Partial Payment Exploit', 'Trust Line Manipulation', 'Fee Escalation Attack', 'Transaction Malleability', 'Account Deletion/Reserve Issues', 'Rippling Configuration Errors', 'Escrow Time Manipulation', 'Payment Channel Exploits', 'Offer Book Front-Running', 'Path Finding Manipulation', 'Multi-Sign Threshold Issues', 'Regular Key Compromise', 'Unfunded Offers', 'Freeze Abuse', 'Preflight Check Bypass', 'Transaction Result Misinterpretation', 'Amendment Incompatibility', 'Ledger Close Timing Issues', 'Sequence Number Gaps', 'LastLedgerSequence Expiration', 'DepositAuth Bypass', 'RequireDest Missing', 'Global Freeze Exploitation', 'Individual Freeze Issues', 'No Ripple Flag Misconfiguration', 'Default Ripple Problems', 'Transfer Fee Manipulation', 'Tick Size Exploitation', 'Quality In/Out Issues', 'Send Max Specification Errors', 'Deliver Min Manipulation', 'Destination Tag Missing', 'Source Tag Issues', 'Account Set Flag Manipulation', 'Master Key Disable Without Regular Key', 'Signer List Quorum Issues', 'Multisigning Weight Manipulation', etc.)."]
) -> str:
    """
    Analyze Ripple/XRP Ledger code for platform-specific security risks.

    Overview:
        Builds a structured analysis prompt for an LLM to review XRPL integration code against
        a caller-supplied list of threat categories specific to the XRP Ledger protocol.

    Parameters:
        function_explanation (str): Plain-English summary of the function purpose and XRPL operations
        function_body (str): Full source code of the function under review
        file_path (str): Repository-relative path to the source file
        ripple_context (str): Key XRPL details: network, library versions, wallet setup, transaction flow
        list_of_ripple_threats (list[str]): Specific XRPL threat names to check

    Focus Areas:
        - Transaction type-specific vulnerabilities (Payment, OfferCreate, TrustSet, etc.)
        - Preflight checks and validation before submission
        - Partial payment exploits (tfPartialPayment flag)
        - Trust line and issued currency security
        - Fee escalation and transaction cost management
        - Account reserves and deletion risks
        - Escrow and payment channel security
        - Multi-signing and key management
        - Ledger timing and sequence number handling
        - Path finding and rippling configuration
        - Account flags and security settings (DepositAuth, RequireDest, etc.)

    Output:
        str: A fully composed prompt for LLM analysis with findings, severity ratings,
             exploit scenarios, and Ripple-specific remediations.
    """
    prompt = f"""
You are a blockchain security expert specializing in Ripple/XRP Ledger (XRPL) protocol security.

**CONTEXT:**
{ripple_context}

**FILE PATH:**
{file_path}

**FUNCTION EXPLANATION:**
{function_explanation}

**FUNCTION CODE:**
```
{function_body}
```

**XRPL THREAT CATEGORIES TO ANALYZE:**
{chr(10).join(f'- {threat}' for threat in list_of_ripple_threats)}

**YOUR TASK:**
Perform a comprehensive security analysis of this XRP Ledger integration code focusing on:

1. **Transaction Type Security:**
   - Payment transactions: Partial payment exploits, amount validation, destination verification
   - OfferCreate/OfferCancel: Price manipulation, unfunded offers, offer book attacks
   - TrustSet: Trust line limits, rippling configuration, unauthorized trust lines
   - EscrowCreate/EscrowFinish/EscrowCancel: Time/condition manipulation, premature/late execution
   - PaymentChannelCreate/Claim/Fund: Channel state manipulation, signature verification
   - AccountSet: Dangerous flag combinations, security setting disablement
   - SignerListSet: Quorum manipulation, weight distribution issues
   - CheckCreate/CheckCash/CheckCancel: Unauthorized cashing, amount manipulation

2. **Preflight Checks & Validation:**
   - Are transactions validated locally before submission?
   - Is the account sequence number properly managed?
   - Are LastLedgerSequence values set to prevent indefinite pending?
   - Is fee escalation handled (maximum fee limits)?
   - Are account reserves checked before operations?
   - Is destination tag validation performed when required?

3. **Partial Payment Security:**
   - Is delivered_amount checked instead of Amount field?
   - Are tfPartialPayment transactions properly detected?
   - Is there protection against partial payment exploits in exchanges/merchants?
   - Are payment results verified from transaction metadata?

4. **Trust Line & Issued Currency:**
   - Are trust line limits properly validated?
   - Is NoRipple flag set appropriately to prevent rippling?
   - Are freeze features (global/individual) properly handled?
   - Is transfer fee validation implemented for issued currencies?
   - Are trust line balances checked for overflow/underflow?

5. **Account Security & Flags:**
   - Is DepositAuth respected for incoming payments?
   - Is RequireDest enforced for destination tags?
   - Is DisallowXRP used correctly for issuer accounts?
   - Are master key disablement and regular key setup done safely?
   - Is DefaultRipple configured correctly for issuers?

6. **Fee Management:**
   - Is fee escalation during high load accounted for?
   - Are maximum fee limits set to prevent overpaying?
   - Is the account reserve requirement maintained?
   - Are owner reserves for objects (offers, trust lines) tracked?

7. **Multi-Signing Security:**
   - Is signer list quorum sufficient for security?
   - Are signer weights properly distributed?
   - Is multi-sign transaction assembly secure?
   - Are all required signatures verified?

8. **Timing & Sequence:**
   - Are sequence numbers incremented correctly?
   - Is LastLedgerSequence used to prevent stuck transactions?
   - Are escrow/payment channel expiration times validated?
   - Is ledger close timing considered for time-sensitive operations?

9. **Path Finding & Rippling:**
   - Are payment paths validated before use?
   - Is rippling properly restricted where needed?
   - Are cross-currency payment risks understood?
   - Is path quality (slippage) acceptable?

10. **Transaction Result Handling:**
    - Are all transaction result codes properly handled?
    - Is tec* (claimed fee) vs tes* (success) distinguished?
    - Are transaction metadata and balanceChanges checked?
    - Is retry logic safe and bounded?

11. **Key Management:**
    - Are master/regular keys properly secured?
    - Is key rotation implemented safely?
    - Are multi-sign credentials stored securely?
    - Is there prevention of master key disable without regular key?

**OUTPUT REQUIREMENTS:**

For each identified vulnerability, provide:

1. **Vulnerability Title**: Clear, specific name
2. **XRPL-Specific Category**: (e.g., "Partial Payment Exploit", "Trust Line Manipulation")
3. **Severity**: Critical / High / Medium / Low
4. **Likelihood**: High / Medium / Low
5. **Affected Transaction Types**: Specific XRPL transaction types involved
6. **Detailed Description**: 
   - Explain the vulnerability in XRPL context
   - Reference specific transaction fields or flags
   - Describe the attack vector
7. **Code Location**: Specific line numbers or code fragments
8. **Exploit Scenario**: 
   - Step-by-step attack using XRPL transactions
   - Example transaction JSON if applicable
   - Expected vs actual behavior
9. **Impact**: 
   - Fund loss potential
   - Account compromise risk
   - Service disruption
   - Reputation damage
10. **XRPL-Specific Remediation**:
    - Specific transaction field validations needed
    - Preflight checks to implement
    - Account flags to set/verify
    - xrpl.js or ripple-lib API calls to use
    - Transaction result codes to handle
11. **Prevention Best Practices**:
    - XRPL security patterns to follow
    - Common pitfalls to avoid
    - Testing approaches for XRPL integrations

**CRITICAL XRPL SECURITY PATTERNS TO VERIFY:**

✓ Always check `delivered_amount` for payments (not `Amount`)
✓ Set `LastLedgerSequence` on all transactions
✓ Verify transaction success via result codes (tesSUCCESS)
✓ Validate destination tags when RequireDest is set
✓ Check account reserves before operations
✓ Use DepositAuth for exchange/service accounts
✓ Set NoRipple on trust lines for non-issuers
✓ Implement maximum fee limits
✓ Never disable master key without setting regular key first
✓ Validate signer list quorum for multi-sig
✓ Handle fee claimed (tec*) vs success (tes*) results
✓ Check for partial payment flag (tfPartialPayment)
✓ Validate escrow/payment channel conditions and timing
✓ Monitor for account deletion and reserve reclamation
✓ Handle amendment activations gracefully

Provide XRPL-specific, actionable findings with emphasis on transaction security and protocol compliance.
"""
    return prompt


async def ripple_payment_threats(
    function_explanation: Annotated[str, "Explanation of payment processing function including amount handling, destination verification, and payment result validation."],
    function_body: Annotated[str, "Complete source code handling XRPL Payment transactions."],
    file_path: Annotated[str, "Path to the payment processing file."],
    payment_context: Annotated[str, "Payment-specific context: currency types (XRP/IOU), partial payment handling, path finding usage, and settlement verification approach."],
    list_of_payment_threats: Annotated[list[str], "Payment-specific threats like 'Partial Payment Exploit', 'Deliver Min Manipulation', 'Send Max Bypass', 'Destination Tag Missing', 'Cross-Currency Slippage', 'Path Finding Manipulation', 'Amount Precision Loss', 'Delivered Amount Misreading', etc."]
) -> str:
    """
    Analyze XRPL Payment transaction handling for security vulnerabilities.
    
    Critical Focus:
        - Partial payment exploit prevention (tfPartialPayment flag)
        - delivered_amount vs Amount field distinction
        - Destination tag enforcement for RequireDest accounts
        - SendMax and DeliverMin validation
        - Cross-currency payment path security
        - Payment result verification
        - Fee deduction handling
    """
    prompt = f"""
You are an XRPL security expert focusing on Payment transaction vulnerabilities.

**PAYMENT CONTEXT:**
{payment_context}

**FILE:** {file_path}

**FUNCTION EXPLANATION:**
{function_explanation}

**CODE:**
```
{function_body}
```

**PAYMENT THREATS TO ANALYZE:**
{chr(10).join(f'- {threat}' for threat in list_of_payment_threats)}

**CRITICAL PAYMENT SECURITY CHECKS:**

1. **Partial Payment Exploit Prevention:**
   - Is `delivered_amount` from metadata checked instead of `Amount`?
   - Is `tfPartialPayment` (0x00020000) flag detected and rejected if unwanted?
   - For exchange deposits: Are partial payments rejected completely?
   - Is the actual received amount verified on-ledger?

2. **Amount Validation:**
   - Are XRP amounts in drops (1 XRP = 1,000,000 drops) validated?
   - Are IOU amounts checked for reasonable precision?
   - Is `SendMax` validated to prevent overpayment?
   - Is `DeliverMin` set appropriately for cross-currency payments?
   - Are amount calculations safe from overflow/underflow?

3. **Destination Security:**
   - Is destination account existence verified?
   - Is `DestinationTag` included when required by receiver?
   - Is `RequireDest` flag on destination account checked?
   - Is destination account validation done in preflight?

4. **Cross-Currency Payment Security:**
   - Are payment paths validated before use?
   - Is slippage acceptable between SendMax and DeliverMin?
   - Are intermediary trust lines checked?
   - Is path finding from trusted sources?
   - Are exchange rates validated against oracles?

5. **Payment Result Verification:**
   - Is transaction result code checked (tesSUCCESS required)?
   - Are tec* codes (claimed fee but failed) handled?
   - Is balanceChanges from metadata verified?
   - Is delivered_amount extracted from metadata?
   - Are payment retries handled safely?

6. **Fee Handling:**
   - Is the transaction fee within acceptable limits?
   - Is fee deduction from sender balance accounted for?
   - Is fee escalation during high load handled?
   - Are minimum reserve requirements maintained?

**OUTPUT:** For each vulnerability, provide:
- Title and severity
- Specific payment field or flag involved
- Attack scenario with example Payment transaction JSON
- Impact (fund loss amount, exploit difficulty)
- Remediation with specific checks/validations needed
- Code showing correct delivered_amount verification

Focus on partial payment exploits, amount validation, and payment result verification.
"""
    return prompt


async def ripple_trustline_threats(
    function_explanation: Annotated[str, "Explanation of trust line management function including trust line creation, rippling configuration, and balance validation."],
    function_body: Annotated[str, "Complete source code handling XRPL TrustSet transactions."],
    file_path: Annotated[str, "Path to the trust line management file."],
    trustline_context: Annotated[str, "Trust line context: issuer/holder role, currency codes handled, rippling policy, freeze feature usage, and balance monitoring approach."],
    list_of_trustline_threats: Annotated[list[str], "Trust line threats like 'NoRipple Misconfiguration', 'Trust Line Limit Bypass', 'Rippling Exploitation', 'Freeze Abuse', 'Transfer Fee Manipulation', 'Unauthorized Trust Line Creation', 'Balance Overflow', 'Quality In/Out Issues', etc."]
) -> str:
    """
    Analyze XRPL TrustSet transaction handling for trust line security.
    
    Critical Focus:
        - NoRipple flag configuration
        - Trust line limits and balance validation
        - Freeze feature proper usage
        - Transfer fee validation for issued currencies
        - Rippling prevention for non-issuers
        - Authorized trust line enforcement
    """
    prompt = f"""
You are an XRPL security expert focusing on Trust Line vulnerabilities.

**TRUSTLINE CONTEXT:**
{trustline_context}

**FILE:** {file_path}

**FUNCTION EXPLANATION:**
{function_explanation}

**CODE:**
```
{function_body}
```

**TRUSTLINE THREATS TO ANALYZE:**
{chr(10).join(f'- {threat}' for threat in list_of_trustline_threats)}

**CRITICAL TRUST LINE SECURITY CHECKS:**

1. **NoRipple Configuration:**
   - Is `tfSetNoRipple` (0x00020000) flag set for non-issuer accounts?
   - Is rippling prevented where it should be (e.g., trading accounts)?
   - For issuers: Is DefaultRipple flag used appropriately?
   - Are both sides of trust line rippling settings considered?

2. **Trust Line Limits:**
   - Is `LimitAmount` validated against reasonable maximums?
   - Are zero-limit trust lines (closure) handled correctly?
   - Is balance checked before reducing limits?
   - Are trust line reserve costs accounted for?

3. **Freeze Features:**
   - Is Global Freeze (AccountSet: asfGlobalFreeze) used only by issuers?
   - Is Individual Freeze (TrustSet: tfSetFreeze) properly authorized?
   - Is No Freeze flag (asfNoFreeze) irrevocable nature understood?
   - Are frozen trust lines prevented from transacting?

4. **Issuer Security:**
   - Is authorized trust line (RequireAuth) enforced if needed?
   - Is transfer fee (0-2 billion = 0%-100%) validated?
   - Are unauthorized trust line creations rejected?
   - Is issuer account properly configured (DefaultRipple, DisallowXRP)?

5. **Balance Validation:**
   - Are trust line balances checked for overflow?
   - Is negative balance (owing to issuer) vs positive (owed by issuer) understood?
   - Are balance changes from rippling monitored?
   - Is balance precision maintained (15 significant digits)?

6. **Quality Settings:**
   - Is QualityIn/QualityOut validated (0-4,294,967,295)?
   - Are quality settings used to prevent unfavorable exchanges?
   - Is quality setting abuse by counterparties detected?

**OUTPUT:** For each vulnerability, provide:
- Title and severity
- Specific TrustSet field or flag involved
- Attack scenario with example TrustSet transaction
- Impact (fund loss, liquidity issues, rippling exploitation)
- Remediation with proper flag usage and validation
- Configuration example for secure trust line setup

Focus on NoRipple configuration, freeze feature security, and trust line limit validation.
"""
    return prompt


async def ripple_escrow_threats(
    function_explanation: Annotated[str, "Explanation of escrow management function including escrow creation, finish/cancel conditions, and time-based execution."],
    function_body: Annotated[str, "Complete source code handling XRPL Escrow transactions (EscrowCreate, EscrowFinish, EscrowCancel)."],
    file_path: Annotated[str, "Path to the escrow management file."],
    escrow_context: Annotated[str, "Escrow context: crypto-condition usage, time lock settings, finish/cancel authorization, and escrow monitoring approach."],
    list_of_escrow_threats: Annotated[list[str], "Escrow threats like 'Time Manipulation', 'Condition Bypass', 'Premature Finish', 'Escrow Front-Running', 'Cancel Time Exploitation', 'Condition Fulfillment Forgery', 'Finish After Cancel Time', 'Escrow Reserve Lock', etc."]
) -> str:
    """
    Analyze XRPL Escrow transaction handling for security vulnerabilities.
    
    Critical Focus:
        - FinishAfter and CancelAfter time validation
        - Crypto-condition security (preimage, prefix, threshold conditions)
        - Authorization for finish/cancel operations
        - Escrow expiration and fund recovery
        - Time-based attack prevention
    """
    prompt = f"""
You are an XRPL security expert focusing on Escrow vulnerabilities.

**ESCROW CONTEXT:**
{escrow_context}

**FILE:** {file_path}

**FUNCTION EXPLANATION:**
{function_explanation}

**CODE:**
```
{function_body}
```

**ESCROW THREATS TO ANALYZE:**
{chr(10).join(f'- {threat}' for threat in list_of_escrow_threats)}

**CRITICAL ESCROW SECURITY CHECKS:**

1. **Time Lock Validation:**
   - Is `FinishAfter` (earliest finish time) validated?
   - Is `CancelAfter` (expiration time) set and reasonable?
   - Is CancelAfter > FinishAfter verified?
   - Are ledger close times (unix epoch + 946684800) properly handled?
   - Is time zone and clock skew considered?

2. **Crypto-Condition Security:**
   - Is condition hash properly generated and validated?
   - Are preimage conditions kept secret until finish?
   - For prefix conditions: Is prefix matching secure?
   - For threshold conditions: Are sub-conditions properly validated?
   - Is condition fulfillment verified before EscrowFinish?
   - Are condition size limits (< 256 bytes) respected?

3. **Authorization & Execution:**
   - Can only destination account finish the escrow (or anyone if no condition)?
   - Can only source account cancel after CancelAfter time?
   - Is premature finish attempt prevented (before FinishAfter)?
   - Is premature cancel prevented (before CancelAfter)?
   - Are finish/cancel race conditions handled?

4. **Fund Security:**
   - Is escrow amount validated (reasonable, within account balance)?
   - Are escrow reserve requirements (owner reserve) tracked?
   - Is fund recovery process after cancel understood?
   - Are stuck escrows (no CancelAfter) monitored?
   - Is escrow expiration handled automatically?

5. **Escrow Monitoring:**
   - Are pending escrows tracked off-chain?
   - Is finish time approaching monitored for time-critical escrows?
   - Are expired but uncanceled escrows detected?
   - Is unauthorized finish/cancel attempt detected?

6. **Edge Cases:**
   - What if destination account doesn't exist at finish time?
   - What if source account is deleted before cancel?
   - What if escrow expires (past CancelAfter) without cancel?
   - What if condition fulfillment is discovered by others?
   - What if multiple finish attempts occur simultaneously?

**OUTPUT:** For each vulnerability, provide:
- Title and severity
- Specific escrow field or condition involved
- Attack scenario with example EscrowCreate/Finish/Cancel transactions
- Timing attack details (ledger close time manipulation)
- Impact (fund lock, premature release, cancellation failure)
- Remediation with proper time/condition validation
- Secure escrow creation pattern with appropriate time locks

Focus on time-based attacks, condition security, and proper authorization.
"""
    return prompt


async def ripple_payment_channel_threats(
    function_explanation: Annotated[str, "Explanation of payment channel function including channel creation, claim authorization, and settlement."],
    function_body: Annotated[str, "Complete source code handling XRPL Payment Channel transactions (PaymentChannelCreate, PaymentChannelClaim, PaymentChannelFund)."],
    file_path: Annotated[str, "Path to the payment channel file."],
    channel_context: Annotated[str, "Payment channel context: channel amount, settle delay, claim signature verification, and channel expiration handling."],
    list_of_channel_threats: Annotated[list[str], "Payment channel threats like 'Claim Signature Forgery', 'Settlement Delay Bypass', 'Channel Balance Manipulation', 'Unauthorized Claim', 'Expired Channel Claims', 'Close After Manipulation', 'Public Key Mismatch', 'Double Claim Attack', etc."]
) -> str:
    """
    Analyze XRPL Payment Channel handling for security vulnerabilities.
    
    Critical Focus:
        - Claim signature verification (secp256k1 or ed25519)
        - Settlement delay enforcement
        - Channel balance and amount validation
        - Expiration and close timing
        - Public key authorization
    """
    prompt = f"""
You are an XRPL security expert focusing on Payment Channel vulnerabilities.

**PAYMENT CHANNEL CONTEXT:**
{channel_context}

**FILE:** {file_path}

**FUNCTION EXPLANATION:**
{function_explanation}

**CODE:**
```
{function_body}
```

**PAYMENT CHANNEL THREATS TO ANALYZE:**
{chr(10).join(f'- {threat}' for threat in list_of_channel_threats)}

**CRITICAL PAYMENT CHANNEL SECURITY CHECKS:**

1. **Claim Signature Verification:**
   - Is claim signature (secp256k1 or ed25519) properly verified?
   - Is signature message format correct (channel ID, amount in drops)?
   - Is public key matched to authorized destination?
   - Are signature replay attacks prevented?
   - Is signature verification done before claim processing?

2. **Channel Authorization:**
   - Can only destination or public key holder claim?
   - Can only source account fund or close the channel?
   - Is unauthorized claim attempt rejected?
   - Is public key properly authorized in channel creation?

3. **Amount & Balance Validation:**
   - Is claimed amount <= channel balance?
   - Is claimed amount monotonically increasing?
   - Are previous claim amounts tracked to prevent double-spend?
   - Is channel funding amount validated?
   - Are amount overflows prevented?

4. **Settlement Delay:**
   - Is SettleDelay (in seconds) set appropriately?
   - Is premature channel close prevented during settle delay?
   - Can destination close immediately with valid claim?
   - Is settle delay expiration properly calculated?

5. **Expiration & Close Timing:**
   - Is CancelAfter expiration time validated?
   - Can expired channels be closed by anyone?
   - Is close timing (immediate vs delayed) correctly handled?
   - Are funds returned to source after expiration?

6. **Channel Lifecycle:**
   - Is channel creation with sufficient amount verified?
   - Is channel funding incremental increase validated?
   - Is channel closure (source vs destination initiated) handled correctly?
   - Are channel owner reserves properly tracked?

7. **Claim Processing:**
   - Is claim amount in drops (1 XRP = 1,000,000 drops)?
   - Is claim transaction result verified?
   - Are partial claims vs full channel close distinguished?
   - Is claim timing relative to expiration checked?

**OUTPUT:** For each vulnerability, provide:
- Title and severity
- Specific channel field or signature issue
- Attack scenario with example PaymentChannelClaim transaction
- Signature forgery or manipulation details
- Impact (fund theft, channel manipulation)
- Remediation with proper signature verification
- Secure claim verification code example

Focus on signature security, amount validation, and settlement delay enforcement.
"""
    return prompt


async def ripple_account_security_threats(
    function_explanation: Annotated[str, "Explanation of account management function including flag settings, key management, and account deletion."],
    function_body: Annotated[str, "Complete source code handling XRPL account operations (AccountSet, AccountDelete, SetRegularKey, SignerListSet)."],
    file_path: Annotated[str, "Path to the account management file."],
    account_context: Annotated[str, "Account context: master/regular key usage, multi-sign setup, account flags configured, and deletion/reserve reclamation approach."],
    list_of_account_threats: Annotated[list[str], "Account threats like 'Master Key Disable Without Regular Key', 'DepositAuth Bypass', 'RequireDest Missing', 'Account Deletion Reserve Loss', 'Signer Quorum Manipulation', 'DisableMaster Without Backup', 'Global Freeze Abuse', 'RequireAuth Bypass', 'Default Ripple Misconfiguration', etc."]
) -> str:
    """
    Analyze XRPL account management for security vulnerabilities.
    
    Critical Focus:
        - Safe master key disablement (asfDisableMaster)
        - Regular key setup and rotation
        - Multi-signing configuration (quorum, weights)
        - Account flags (DepositAuth, RequireDest, DisallowXRP, etc.)
        - Account deletion and reserve reclamation
        - Security flag combinations
    """
    prompt = f"""
You are an XRPL security expert focusing on Account Security vulnerabilities.

**ACCOUNT CONTEXT:**
{account_context}

**FILE:** {file_path}

**FUNCTION EXPLANATION:**
{function_explanation}

**CODE:**
```
{function_body}
```

**ACCOUNT THREATS TO ANALYZE:**
{chr(10).join(f'- {threat}' for threat in list_of_account_threats)}

**CRITICAL ACCOUNT SECURITY CHECKS:**

1. **Key Management Safety:**
   - Is regular key set BEFORE disabling master key?
   - Is master key disable (asfDisableMaster) flag properly authorized?
   - Is SetRegularKey transaction validated?
   - Is key rotation process secure?
   - Are key compromise scenarios handled?

2. **Multi-Signing Configuration:**
   - Is SignerListSet quorum sufficient (typically >= 2/3 of total weight)?
   - Are signer weights properly distributed (1-65535 per signer)?
   - Is maximum signer list size (8-32 depending on quorum) respected?
   - Can quorum be reached with realistic signer availability?
   - Is signer list modification properly authorized?

3. **Security Flags (AccountSet):**
   - **asfRequireDest**: Is destination tag required for incoming payments?
   - **asfRequireAuth**: Are trust lines pre-authorized for issuer accounts?
   - **asfDepositAuth**: Is unauthorized deposit prevented (exchange/service accounts)?
   - **asfDisallowXRP**: Is XRP sending prevented for issuer accounts?
   - **asfGlobalFreeze**: Is global freeze used only in emergencies by issuers?
   - **asfNoFreeze**: Is irrevocable no-freeze flag understood?
   - **asfDefaultRipple**: Is rippling allowed for issuer accounts only?

4. **Flag Combinations:**
   - Is DisableMaster + no regular key prevented?
   - Is DisableMaster + no signer list prevented?
   - Is RequireAuth + DefaultRipple conflict handled?
   - Are dangerous flag combinations detected?

5. **Account Deletion (AccountDelete):**
   - Is account sequence >= 256 before deletion?
   - Are all owned objects (offers, trust lines, escrows, channels) removed first?
   - Is destination for reserve refund validated?
   - Is deletion only done when truly needed (reserve = 2 XRP)?
   - Are deletion implications understood (account can be re-created)?

6. **Deposit Authorization:**
   - With DepositAuth: Are only pre-authorized incoming payments allowed?
   - Is DepositPreauth used for whitelisting senders?
   - Are unauthorized deposit attempts properly rejected?
   - Is DepositAuth bypass via trust lines understood?

7. **Reserve Requirements:**
   - Is base reserve (10 XRP mainnet) maintained?
   - Is owner reserve (2 XRP per owned object) tracked?
   - Is account deletion reserve refund (2 XRP) handled?
   - Are reserve changes from amendments monitored?

**OUTPUT:** For each vulnerability, provide:
- Title and severity
- Specific account flag or key management issue
- Attack scenario with example AccountSet/SignerListSet transaction
- Impact (account lockout, unauthorized access, fund loss)
- Remediation with proper flag usage and key management
- Secure account configuration pattern

Focus on key management safety, flag configuration, and multi-sign security.
"""
    return prompt


async def ripple_offer_threats(
    function_explanation: Annotated[str, "Explanation of offer management function including offer creation, cancellation, and order book interaction."],
    function_body: Annotated[str, "Complete source code handling XRPL offer transactions (OfferCreate, OfferCancel)."],
    file_path: Annotated[str, "Path to the offer management file."],
    offer_context: Annotated[str, "Offer context: trading pairs, order book monitoring, offer funding, partial fills, and exchange rate validation approach."],
    list_of_offer_threats: Annotated[list[str], "Offer threats like 'Unfunded Offer Spam', 'Offer Front-Running', 'Offer Book Manipulation', 'Price Manipulation', 'Partial Fill Exploitation', 'Immediate Or Cancel Abuse', 'Fill Or Kill Manipulation', 'Tick Size Exploitation', 'Quality Threshold Issues', etc."]
) -> str:
    """
    Analyze XRPL Offer handling for trading security vulnerabilities.
    
    Critical Focus:
        - Unfunded offer prevention (tfSell flag)
        - Offer front-running and MEV
        - Exchange rate and price validation
        - Partial fill handling (tfFillOrKill, tfImmediateOrCancel)
        - Offer book manipulation
        - Tick size and quality validation
    """
    prompt = f"""
You are an XRPL security expert focusing on Offer/Trading vulnerabilities.

**OFFER CONTEXT:**
{offer_context}

**FILE:** {file_path}

**FUNCTION EXPLANATION:**
{function_explanation}

**CODE:**
```
{function_body}
```

**OFFER THREATS TO ANALYZE:**
{chr(10).join(f'- {threat}' for threat in list_of_offer_threats)}

**CRITICAL OFFER SECURITY CHECKS:**

1. **Offer Funding:**
   - Is offer funded at creation time?
   - Are unfunded offers detected and removed?
   - Is TakerPays amount available in account balance/trust line?
   - Is TakerGets amount validated?
   - Are funded offer checks done before interaction?

2. **Exchange Rate Validation:**
   - Is TakerPays/TakerGets rate validated against expected price?
   - Is slippage acceptable for order execution?
   - Is rate manipulation via tick size detected?
   - Are price oracle comparisons performed?
   - Is rate precision maintained?

3. **Offer Flags:**
   - **tfSell** (0x00080000): Is sell vs buy correctly implemented?
   - **tfPassive** (0x00010000): Are passive offers not consuming existing offers?
   - **tfImmediateOrCancel** (0x00040000): Is IOC partial fill acceptable?
   - **tfFillOrKill** (0x00020000): Is FOK full fill requirement enforced?
   - Are flag combinations validated?

4. **Front-Running Protection:**
   - Is offer placement timing considered?
   - Are large offers split to reduce MEV?
   - Is offer execution monitored for front-running?
   - Are slippage limits set?
   - Is LastLedgerSequence used to limit exposure window?

5. **Partial Fill Handling:**
   - Are partial fills (less than TakerPays) acceptable?
   - Is fill amount validated from transaction metadata?
   - Are unfilled offers left on book properly tracked?
   - Is offer cancellation needed after partial fill?

6. **Offer Book Manipulation:**
   - Is offer spam (many small unfunded offers) detected?
   - Are wash trading patterns identified?
   - Is offer cancellation rate monitored?
   - Are suspicious offer patterns flagged?

7. **Tick Size & Quality:**
   - Is tick size respected for currency pairs?
   - Is Quality (0-4,294,967,295) threshold validated?
   - Are quality-based rejections handled?
   - Is quality setting abuse detected?

8. **Offer Expiration:**
   - Are offers set with expiration (OfferSequence + TTL)?
   - Are expired offers cancelled automatically?
   - Is offer monitoring for expiration implemented?

**OUTPUT:** For each vulnerability, provide:
- Title and severity
- Specific offer field or flag involved
- Attack scenario with example OfferCreate transaction
- Front-running or manipulation details
- Impact (unfavorable fills, market manipulation, fund loss)
- Remediation with proper rate validation and flags
- Secure offer creation pattern with protections

Focus on unfunded offers, front-running, and exchange rate validation.
"""
    return prompt


async def ripple_transaction_validation_threats(
    function_explanation: Annotated[str, "Explanation of transaction validation function including preflight checks, fee validation, and result code handling."],
    function_body: Annotated[str, "Complete source code handling XRPL transaction submission, validation, and result processing."],
    file_path: Annotated[str, "Path to the transaction validation file."],
    validation_context: Annotated[str, "Validation context: preflight check usage, fee escalation handling, sequence number management, LastLedgerSequence usage, and retry logic approach."],
    list_of_validation_threats: Annotated[list[str], "Validation threats like 'Preflight Check Bypass', 'Fee Escalation Attack', 'Sequence Number Gap', 'LastLedgerSequence Expiration', 'Result Code Misinterpretation', 'Tec* vs Tes* Confusion', 'Transaction Malleability', 'Retry Loop Exploitation', 'Metadata Missing Validation', etc."]
) -> str:
    """
    Analyze XRPL transaction validation and submission for security issues.
    
    Critical Focus:
        - Preflight validation before submission
        - Fee management and escalation handling
        - Sequence number proper management
        - LastLedgerSequence usage to prevent stuck transactions
        - Transaction result code proper handling
        - Retry logic safety
    """
    prompt = f"""
You are an XRPL security expert focusing on Transaction Validation vulnerabilities.

**VALIDATION CONTEXT:**
{validation_context}

**FILE:** {file_path}

**FUNCTION EXPLANATION:**
{function_explanation}

**CODE:**
```
{function_body}
```

**VALIDATION THREATS TO ANALYZE:**
{chr(10).join(f'- {threat}' for threat in list_of_validation_threats)}

**CRITICAL TRANSACTION VALIDATION CHECKS:**

1. **Preflight Validation:**
   - Is local preflight check performed before submission?
   - Are account existence and balance verified?
   - Is account sequence number validated?
   - Are required reserves checked?
   - Are destination account requirements (tags, flags) validated?
   - Is transaction malformation detected early?

2. **Fee Management:**
   - Is fee set to reasonable value (typically 10-12 drops minimum)?
   - Is maximum fee limit configured (e.g., 1000 drops = 0.001 XRP)?
   - Is fee escalation during high load handled?
   - Is fee multiplication factor validated (typically 1.1x-1.5x)?
   - Are overpayment scenarios prevented?

3. **Sequence Number Management:**
   - Is account sequence incremented correctly after each transaction?
   - Are sequence gaps detected and handled?
   - Is sequence synchronization maintained?
   - Are out-of-order submission scenarios handled?
   - Is sequence ticket usage considered for parallel transactions?

4. **LastLedgerSequence:**
   - Is LastLedgerSequence set on all transactions?
   - Is expiration window reasonable (e.g., current + 4 ledgers = ~20 seconds)?
   - Are expired transactions detected via telapsed result?
   - Is retry needed after expiration?
   - Is LastLedgerSequence too far in future prevented?

5. **Result Code Handling:**
   - **tesSUCCESS**: Transaction succeeded and applied to ledger
   - **tec*** (claimed fee): Transaction failed but fee was charged
     - tecUNFUNDED_PAYMENT, tecNO_DST, tecNO_PERMISSION, tecPATH_DRY, etc.
   - **tem*** (malformed): Transaction rejected, no fee charged
   - **tef*** (failed): Transaction failed preflight, no fee charged
   - **ter*** (retry): Temporary failure, retry may succeed
   - **tel*** (local): Local error, not submitted
   - **tes*** vs **tec***: Is distinction properly handled?

6. **Metadata Validation:**
   - Is transaction metadata extracted after success?
   - Are balanceChanges validated?
   - Is delivered_amount checked for payments?
   - Are affected nodes (CreatedNode, ModifiedNode, DeletedNode) analyzed?
   - Is final result verified from ledger state?

7. **Retry Logic:**
   - Are retries limited (max 3-5 attempts)?
   - Is exponential backoff used?
   - Are retry-able result codes (ter*, tel*) distinguished from fatal ones?
   - Is sequence number re-fetched on retry?
   - Is LastLedgerSequence reset on retry?

8. **Transaction Malleability:**
   - Is transaction hash used for idempotency?
   - Are transaction IDs properly tracked?
   - Is duplicate submission prevented?
   - Are malleability attacks via signature modification considered?

9. **Network & RPC:**
   - Is RPC endpoint trusted and reliable?
   - Are multiple RPC failover endpoints configured?
   - Is network latency and timeout handled?
   - Is connection security (WSS, HTTPS) enforced?

**OUTPUT:** For each vulnerability, provide:
- Title and severity
- Specific validation or result code issue
- Attack scenario with example transaction submission flow
- Impact (fund loss via fee, stuck transactions, double-spend)
- Remediation with proper preflight checks and result handling
- Secure transaction submission pattern with retry logic

Focus on preflight validation, fee management, and result code handling.
"""
    return prompt


async def ripple_amendment_threats(
    function_explanation: Annotated[str, "Explanation of amendment handling function including feature detection, compatibility checks, and amendment activation monitoring."],
    function_body: Annotated[str, "Complete source code handling XRPL amendment status checking and feature compatibility."],
    file_path: Annotated[str, "Path to the amendment handling file."],
    amendment_context: Annotated[str, "Amendment context: feature flag usage, amendment activation monitoring, compatibility testing approach, and upgrade strategy."],
    list_of_amendment_threats: Annotated[list[str], "Amendment threats like 'Amendment Incompatibility', 'Feature Flag Missing', 'Upgrade Breaking Changes', 'Deprecated Feature Usage', 'Amendment Activation Surprise', 'Consensus Rule Changes', 'New Transaction Type Unhandled', etc."]
) -> str:
    """
    Analyze XRPL amendment handling for compatibility and upgrade security.
    
    Critical Focus:
        - Amendment status detection (enabled, supported, vetoed)
        - Feature flag compatibility checks
        - New transaction types and fields
        - Deprecated feature handling
        - Smooth upgrade paths
    """
    prompt = f"""
You are an XRPL security expert focusing on Amendment/Upgrade vulnerabilities.

**AMENDMENT CONTEXT:**
{amendment_context}

**FILE:** {file_path}

**FUNCTION EXPLANATION:**
{function_explanation}

**CODE:**
```
{function_body}
```

**AMENDMENT THREATS TO ANALYZE:**
{chr(10).join(f'- {threat}' for threat in list_of_amendment_threats)}

**CRITICAL AMENDMENT SECURITY CHECKS:**

1. **Amendment Detection:**
   - Is server_state checked for amendment status?
   - Are feature amendment IDs tracked?
   - Is amendment activation monitored?
   - Are enabled amendments queried regularly?

2. **Feature Compatibility:**
   - Is code compatible with both pre and post-amendment states?
   - Are new transaction types gracefully handled?
   - Are deprecated features avoided?
   - Is backward compatibility maintained?

3. **Critical Amendments to Monitor:**
   - **Checks**: Check-based payments (new transaction types)
   - **DepositAuth**: Deposit authorization (account flag changes)
   - **fixAmendmentMajorityCalc**: Consensus rule changes
   - **FlowCross**: Offer crossing behavior changes
   - **NonFungibleTokensV1**: NFT transaction types
   - **XRPFees**: Fee distribution changes
   - **DeletableAccounts**: Account deletion feature
   - **ExpandedSignerList**: Signer list size changes

4. **New Transaction Types:**
   - Are new transaction types in API handled?
   - Is transaction parsing forward-compatible?
   - Are unknown transaction types gracefully ignored?

5. **Field Changes:**
   - Are new transaction fields parsed correctly?
   - Are deprecated fields still supported during transition?
   - Is field presence/absence validated correctly?

6. **Testing & Validation:**
   - Is code tested against devnet with amendments?
   - Are amendment activation dates tracked?
   - Is gradual rollout strategy in place?
   - Are amendment-specific tests written?

7. **Upgrade Strategy:**
   - Is amendment whitelist maintained?
   - Are breaking changes documented?
   - Is rollback plan available?
   - Is user communication plan ready?

**OUTPUT:** For each vulnerability, provide:
- Title and severity
- Specific amendment or feature involved
- Incompatibility scenario with pre/post-amendment behavior
- Impact (service disruption, transaction failures)
- Remediation with compatibility checks and feature flags
- Upgrade pattern for smooth amendment transitions

Focus on compatibility, feature detection, and smooth upgrade handling.
"""
    return prompt

