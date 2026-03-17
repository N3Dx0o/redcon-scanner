from typing import Annotated


async def typescript_general_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the TypeScript function does, its purpose, and its role in the application. Should include TypeScript-specific operations, type safety, and any TypeScript-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the TypeScript function including all statements, variable assignments, control flow, function calls, TypeScript operations, and any nested logic. This is the actual TypeScript code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'src/utils/auth.ts', 'lib/types/User.ts', 'app/components/UserProfile.tsx'). Used for context and reporting."], 
    typescript_context: Annotated[str, "Additional TypeScript context including the TypeScript version, compiler settings (strict mode, noImplicitAny), and critical TypeScript operations this function handles."],
    list_of_typescript_threats: Annotated[list[str], "A comprehensive list of TypeScript-specific threats and vulnerabilities to check for during analysis. Each item should be a specific TypeScript threat type (e.g., 'Type Assertion Bypass', 'Any Type Abuse', 'Type Casting Vulnerabilities', 'Interface Manipulation', 'Generic Type Exploits', 'Union Type Confusion', 'Unsafe Type Guards', 'Runtime Type Mismatch', 'Declaration Merging Issues', 'Module Augmentation Risks', 'Decorator Injection', 'Metadata Reflection Attacks', 'Strict Mode Bypass', 'Non-Null Assertion Misuse', 'Optional Chaining Errors', 'Type Inference Flaws', 'Enum Value Manipulation', 'Namespace Pollution', 'Import Type Confusion', 'Branded Type Bypass', 'Discriminated Union Bypass', 'Mapped Type Vulnerabilities', 'Conditional Type Exploits', 'Template Literal Type Issues', 'Prototype Pollution via Types', 'Type Predicate Bypass', 'This Type Manipulation', 'Index Signature Abuse', 'Readonly Bypass', 'Partial Type Exploitation')."] = None
) -> str:
    """
    Analyze a TypeScript function for TypeScript-specific security vulnerabilities and threats.
    
    This function focuses specifically on TypeScript vulnerabilities, type system bypass,
    and TypeScript-specific attack vectors that could lead to type confusion,
    runtime type mismatches, or exploitation of TypeScript's compile-time guarantees.
    
    Args:
        function_explanation: Human-readable description of the TypeScript function's purpose and behavior
        function_body: Complete source code of the TypeScript function to be analyzed
        file_path: Full path to the file containing the TypeScript function for context
        typescript_context: Additional TypeScript context and compiler configuration information
        list_of_typescript_threats: List of specific TypeScript threats to evaluate
        
    Returns:
        str: Detailed TypeScript analysis report including identified vulnerabilities,
             TypeScript-specific attack vector analysis, potential impact, and remediation
             recommendations specific to TypeScript security.
             
    Example:
        result = await typescript_general_threats(
            function_explanation="Type-safe user authentication with interface validation",
            function_body="function authenticateUser(user: User): Promise<AuthResult> { ... }",
            file_path="src/utils/auth.ts",
            typescript_context="TypeScript 5.0 with strict mode enabled and noImplicitAny",
            list_of_typescript_threats=["Type Assertion Bypass", "Any Type Abuse", "Unsafe Type Guards", "Runtime Type Mismatch"]
        )
        
    Note:
        This function should be used for analyzing TypeScript functions where type safety
        vulnerabilities could lead to runtime errors, security bypasses, or exploitation
        of TypeScript's static type guarantees at runtime.
    """
    msg = f"""
TYPESCRIPT GENERAL THREAT ANALYSIS REQUEST

Function Context:
- TypeScript Purpose: {function_explanation}
- File Location: {file_path}
- TypeScript Context: {typescript_context}
- TypeScript Threats to Evaluate: {', '.join(list_of_typescript_threats or ['General security threats, Common vulnerabilities, OWASP Top 10'])}

TypeScript Source Code to Analyze:
{function_body}

Please perform a comprehensive TypeScript security analysis focusing on the specified threats and provide detailed findings with TypeScript-specific attack vector analysis, potential impact, and remediation guidance specific to TypeScript vulnerabilities and secure TypeScript development practices.
"""

    return msg


async def typescript_web3_wallet_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Web3 wallet TypeScript function does, its purpose in wallet operations, and its role in handling cryptocurrency transactions, key management, or dApp interactions. Should include wallet-specific operations like signing, connecting, and transaction handling."],
    function_body: Annotated[str, "The complete TypeScript source code of the wallet function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual wallet code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'src/wallet/connect.ts', 'lib/signing/transaction.ts', 'packages/adapter/phantom.ts'). Used for context and reporting."], 
    wallet_context: Annotated[str, "Additional Web3 wallet context including the wallet provider (e.g., MetaMask, Phantom, WalletConnect, Coinbase Wallet), blockchain network (Ethereum, Solana, Polygon), and critical wallet operations this function handles."],
    list_of_wallet_threats: Annotated[list[str], "A comprehensive list of Web3 wallet-specific threats and vulnerabilities to check for during analysis. Each item should be a specific wallet threat type (e.g., 'Private Key Exposure', 'Seed Phrase Leakage', 'Signature Malleability', 'Blind Signing Vulnerabilities', 'Transaction Simulation Bypass', 'Approval Hijacking', 'Unlimited Token Approval', 'Permit Signature Exploits', 'EIP-712 Message Manipulation', 'Phishing via eth_sign', 'personal_sign Abuse', 'signTypedData Vulnerabilities', 'Provider Injection Attacks', 'RPC Endpoint Manipulation', 'Chain ID Confusion', 'Network Switching Attacks', 'Connection Request Spoofing', 'Wallet State Desync', 'Transaction Replay Attacks', 'Nonce Manipulation', 'Gas Price Manipulation', 'Front-Running via Mempool', 'MEV Extraction Vulnerabilities', 'Address Poisoning', 'Clipboard Hijacking', 'Deep Link Injection', 'QR Code Manipulation', 'WalletConnect Session Hijacking', 'Adapter Impersonation', 'Balance Caching Exploits', 'Event Listener Memory Leaks', 'Pop-up Blocker Bypass', 'Extension Message Spoofing', 'Content Script Injection', 'Background Script Vulnerabilities', 'Storage Encryption Weaknesses', 'IndexedDB Data Exposure', 'Cross-Origin Wallet Access', 'iframe Wallet Embedding', 'postMessage Origin Bypass')."] = None
) -> str:
    """
    Analyze a TypeScript Web3 wallet function for wallet-specific security vulnerabilities and threats.
    
    This function focuses specifically on Web3 wallet vulnerabilities in browser extensions
    and dApp integrations like MetaMask, Phantom, Rainbow, and other wallet providers.
    It covers signature security, key management, transaction handling, and dApp connection flows.
    
    Args:
        function_explanation: Human-readable description of the wallet function's purpose and behavior
        function_body: Complete TypeScript source code of the wallet function to be analyzed
        file_path: Full path to the file containing the wallet function for context
        wallet_context: Additional wallet context including provider type and blockchain network
        list_of_wallet_threats: List of specific Web3 wallet threats to evaluate
        
    Returns:
        str: Detailed Web3 wallet analysis report including identified vulnerabilities,
             wallet-specific attack vector analysis, potential fund loss impact, and remediation
             recommendations specific to Web3 wallet security.
             
    Example:
        result = await typescript_web3_wallet_threats(
            function_explanation="MetaMask connection handler that requests account access and handles chain switching",
            function_body="async function connectWallet(): Promise<string[]> { return await window.ethereum.request({ method: 'eth_requestAccounts' }); }",
            file_path="src/wallet/metamask-adapter.ts",
            wallet_context="MetaMask integration for Ethereum mainnet dApp with EIP-1193 provider",
            list_of_wallet_threats=["Provider Injection Attacks", "Chain ID Confusion", "Connection Request Spoofing", "Unlimited Token Approval"]
        )
        
    Note:
        This function should be used for analyzing wallet integration code, dApp connectors,
        signing flows, and transaction handling where vulnerabilities could lead to
        private key exposure, unauthorized transactions, or fund theft.
    """
    msg = f"""
WEB3 WALLET THREAT ANALYSIS REQUEST

Function Context:
- Wallet Function Purpose: {function_explanation}
- File Location: {file_path}
- Wallet Context: {wallet_context}
- Web3 Wallet Threats to Evaluate: {', '.join(list_of_wallet_threats or ['General security threats, Common vulnerabilities, OWASP Top 10'])}

Wallet TypeScript Source Code to Analyze:
{function_body}

Please perform a comprehensive Web3 wallet security analysis focusing on the specified threats and provide detailed findings with wallet-specific attack vector analysis, potential fund loss impact, and remediation guidance specific to Web3 wallet vulnerabilities and secure wallet integration practices.

Key areas to analyze:
1. Private key and seed phrase handling
2. Signature request validation and display
3. Transaction parameter verification
4. Provider detection and injection security
5. Connection flow and session management
6. Cross-origin communication security
7. Approval and permission management
"""

    return msg


async def typescript_sdk_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the TypeScript SDK function does, its purpose as a library/SDK component, and its role in providing APIs to consumers. Should include SDK design patterns, public API surface, and any SDK-specific security behaviors."],
    function_body: Annotated[str, "The complete TypeScript source code of the SDK function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual SDK code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'packages/sdk/src/client.ts', 'lib/api/requests.ts', 'src/core/auth.ts'). Used for context and reporting."], 
    sdk_context: Annotated[str, "Additional TypeScript SDK context including the SDK type (e.g., REST API client, GraphQL client, Web3 SDK, payment SDK), distribution method (npm package, CDN), and critical SDK operations this function handles."],
    list_of_sdk_threats: Annotated[list[str], "A comprehensive list of TypeScript SDK-specific threats and vulnerabilities to check for during analysis. Each item should be a specific SDK threat type (e.g., 'API Key Exposure in Bundle', 'Hardcoded Secrets in Source', 'Credential Leakage via Logs', 'Request Signing Bypass', 'Authentication Token Exposure', 'Insecure Default Configuration', 'Permissive CORS Handling', 'SSL/TLS Certificate Validation Bypass', 'HTTP Downgrade Attacks', 'Request Parameter Injection', 'Response Parsing Vulnerabilities', 'JSON Prototype Pollution', 'XML External Entity (XXE)', 'Deserialization Attacks', 'Rate Limit Bypass', 'Retry Logic Exploitation', 'Timeout Denial of Service', 'Connection Pool Exhaustion', 'Memory Leak in Long-Running Connections', 'WebSocket Hijacking', 'Event Emitter Memory Leaks', 'Callback Hell Security', 'Promise Rejection Handling', 'Async Error Propagation', 'Dependency Confusion', 'Supply Chain Attacks', 'Package Typosquatting', 'Malicious Transitive Dependencies', 'Bundler Configuration Leaks', 'Source Map Exposure', 'Tree Shaking Security', 'Dead Code Inclusion', 'Type Definition Poisoning', 'Declaration File Manipulation', 'Ambient Type Pollution', 'Version Compatibility Exploits', 'Polyfill Vulnerabilities', 'Browser Detection Bypass', 'Feature Detection Manipulation', 'Plugin System Injection')."] = None
) -> str:
    """
    Analyze a TypeScript SDK function for SDK-specific security vulnerabilities and threats.
    
    This function focuses specifically on TypeScript SDK vulnerabilities, library security,
    and SDK-specific attack vectors that could lead to credential exposure, supply chain
    attacks, or exploitation of SDK functionality by consumers or attackers.
    
    Args:
        function_explanation: Human-readable description of the SDK function's purpose and behavior
        function_body: Complete TypeScript source code of the SDK function to be analyzed
        file_path: Full path to the file containing the SDK function for context
        sdk_context: Additional SDK context including SDK type and distribution method
        list_of_sdk_threats: List of specific TypeScript SDK threats to evaluate
        
    Returns:
        str: Detailed TypeScript SDK analysis report including identified vulnerabilities,
             SDK-specific attack vector analysis, potential consumer impact, and remediation
             recommendations specific to TypeScript SDK security.
             
    Example:
        result = await typescript_sdk_threats(
            function_explanation="REST API client initialization that configures authentication and base URL",
            function_body="export class ApiClient { constructor(config: ApiConfig) { this.apiKey = config.apiKey; ... }}",
            file_path="packages/sdk/src/client.ts",
            sdk_context="npm-distributed REST API SDK for payment processing with OAuth2 authentication",
            list_of_sdk_threats=["API Key Exposure in Bundle", "Insecure Default Configuration", "Credential Leakage via Logs", "Source Map Exposure"]
        )
        
    Note:
        This function should be used for analyzing SDK code, library implementations,
        and public API surfaces where vulnerabilities could affect all consumers
        of the SDK and lead to widespread security issues.
    """
    msg = f"""
TYPESCRIPT SDK THREAT ANALYSIS REQUEST

Function Context:
- SDK Function Purpose: {function_explanation}
- File Location: {file_path}
- SDK Context: {sdk_context}
- TypeScript SDK Threats to Evaluate: {', '.join(list_of_sdk_threats or ['General security threats, Common vulnerabilities, OWASP Top 10'])}

SDK TypeScript Source Code to Analyze:
{function_body}

Please perform a comprehensive TypeScript SDK security analysis focusing on the specified threats and provide detailed findings with SDK-specific attack vector analysis, potential consumer impact, and remediation guidance specific to TypeScript SDK vulnerabilities and secure SDK development practices.

Key areas to analyze:
1. Credential and secret handling in distributed code
2. Default configuration security
3. Input validation on public API surface
4. Error handling and information disclosure
5. Dependency security and supply chain
6. Bundle and distribution security
7. Type safety across API boundaries
8. Backward compatibility security implications
"""

    return msg
