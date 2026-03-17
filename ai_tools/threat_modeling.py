from typing import Annotated


import os

async def validate_finding_before_db(
    finding_text: Annotated[str, "The text of the finding to be validated before adding to the database"],
    target_file_full_path: Annotated[str, "The full path to the target file that the finding refers to"],
) -> str:
    """
    Pre-database validation: Validate a reported finding against a code path before adding it to the database.

    Args:
        finding_text: The text of the finding to be validated.
        target_file_full_path: The full filesystem path to the target file being checked.

    Returns:
        str: Detailed validation result with existence and logical analysis of the code path.
    """

    msg = f"""
FINDING PRE-DB VALIDATION ANALYSIS

Finding Text:
{finding_text}

Target File Full Path:
{target_file_full_path}

Instructions:
- Before submitting this finding into the database, check if the file path exists and is accessible.
- If the file or directory does not exist, explain why the finding cannot be added, and do not proceed.
- If the file exists, perform a logical assessment of whether the finding is accurate and relevant, based on the code in the given file.
- Reference specific code (if possible) and articulate clearly whether the finding should be accepted or rejected before storing it in the database.

Your validation report must include:
1. Code path existence and accessibility status.
2. Logical assessment and argument for accepting or rejecting the finding in the present context.
3. Explicitly state any doubts, uncertainties, or assumptions made during the validation.

This step ensures only findings confirmed against real, accessible code paths are added to the project database.
"""
    return msg

# Annotate functions and parameters to describe them to the agent.
async def parameters_possible_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the function does, its purpose, and its role in the application. Should include business logic context and any security-relevant behaviors."],
    function_body: Annotated[str, "The complete source code of the function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'src/controllers/UserController.py', 'app/models/User.js'). Used for context and reporting."], 
    list_of_possible_threats: Annotated[list[str], "A comprehensive list of potential security threats and vulnerabilities to check for during analysis. Each item should be a specific threat type (e.g., 'SQL Injection', 'XSS', 'CSRF', 'Authentication Bypass', 'Authorization Issues', 'Input Validation Flaws', 'Path Traversal', 'Command Injection', etc.)."] = None
) -> str:
    """
    Analyze a function for security vulnerabilities and potential threats.
    
    This function serves as the primary entry point for threat modeling analysis.
    It takes a function's metadata and source code, along with a list of threats
    to check for, and returns a comprehensive security analysis.
    
    Args:
        function_explanation: Human-readable description of the function's purpose and behavior
        function_body: Complete source code of the function to be analyzed
        file_path: Full path to the file containing the function for context
        list_of_possible_threats: List of specific security threats to evaluate
        
    Returns:
        str: Detailed analysis report including identified vulnerabilities, 
             severity assessments, impact analysis, and remediation recommendations.
             
    Example:
        result = await parameters_possible_threats(
            function_explanation="User login function that validates credentials against database",
            function_body="def login(username, password): return db.query(f'SELECT * FROM users WHERE username={username} AND password={password}')",
            file_path="app/auth/login.py",
            list_of_possible_threats=["SQL Injection", "Authentication Bypass", "Brute Force"]
        )
        
    Note:
        This function should be used as part of a comprehensive security review process.
        The analysis quality depends on the completeness of the threat list and
        the accuracy of the function explanation provided.
    """
    msg = f"""
THREAT MODELING ANALYSIS REQUEST

Function Context:
- Purpose: {function_explanation}
- File Location: {file_path}
- Threats to Evaluate: {', '.join(list_of_possible_threats or ['General security threats, Common vulnerabilities, OWASP Top 10'])}

Source Code to Analyze:
{function_body}

Please perform a comprehensive security analysis focusing on the specified threats and provide detailed findings with severity ratings and remediation guidance.
"""

    return msg


async def business_logic_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the function does, its business purpose, and its role in the application's business logic. Should include business rules, workflows, and any business-critical operations."],
    function_body: Annotated[str, "The complete source code of the function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual code that will be analyzed for business logic vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'src/controllers/PaymentController.py', 'app/services/OrderService.js'). Used for context and reporting."], 
    business_context: Annotated[str, "Additional business context including the domain (e.g., e-commerce, banking, healthcare), key business rules, regulatory requirements, and critical business processes that this function supports."],
    list_of_business_threats: Annotated[list[str], "A comprehensive list of business logic threats and logical vulnerabilities to check for during analysis. Each item should be a specific business threat type (e.g., 'Race Condition in Payment Processing', 'Business Rule Bypass', 'Workflow Manipulation', 'Data Integrity Violation', 'Business Logic Flaw', 'Privilege Escalation in Business Context', 'Resource Exhaustion', 'Business Process Bypass', 'Financial Logic Error', 'Audit Trail Manipulation', etc.)."] = None
) -> str:
    """
    Analyze a function for business logic vulnerabilities and threats that could impact business operations.
    
    This function focuses specifically on business logic flaws, workflow vulnerabilities,
    and logical errors that could lead to business impact such as financial losses,
    regulatory violations, data integrity issues, or operational disruptions.
    
    Args:
        function_explanation: Human-readable description of the function's business purpose and behavior
        function_body: Complete source code of the function to be analyzed
        file_path: Full path to the file containing the function for context
        business_context: Additional business domain context and critical business rules
        list_of_business_threats: List of specific business logic threats to evaluate
        
    Returns:
        str: Detailed business logic analysis report including identified vulnerabilities,
             business impact assessments, potential financial/operational consequences,
             and remediation recommendations specific to business logic flaws.
             
    Example:
        result = await business_logic_threats(
            function_explanation="Process payment for order with discount validation and inventory check",
            function_body="def process_payment(order_id, discount_code): ...",
            file_path="app/services/PaymentService.py",
            business_context="E-commerce platform with discount rules, inventory management, and payment processing",
            list_of_business_threats=["Race Condition in Payment Processing", "Discount Code Manipulation", "Inventory Overselling"]
        )
        
    Note:
        This function should be used for analyzing business-critical functions where
        logical flaws could lead to significant business impact. Focus on workflows,
        business rules, and processes that directly affect business operations.
    """
    msg = f"""
BUSINESS LOGIC THREAT ANALYSIS REQUEST

Function Context:
- Business Purpose: {function_explanation}
- File Location: {file_path}
- Business Domain: {business_context}
- Business Threats to Evaluate: {', '.join(list_of_business_threats or ['General security threats, Common vulnerabilities, OWASP Top 10'])}

Source Code to Analyze:
{function_body}

Please perform a comprehensive business logic analysis focusing on the specified business threats and provide detailed findings with business impact assessments, potential financial/operational consequences, and remediation guidance specific to business logic vulnerabilities.
"""

    return msg


async def blockchain_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the function does in the blockchain context, its purpose in smart contracts, DeFi protocols, or blockchain applications. Should include blockchain-specific operations, token interactions, and decentralized logic."],
    function_body: Annotated[str, "The complete source code of the function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual code that will be analyzed for blockchain vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'contracts/Token.sol', 'src/defi/StakingPool.js', 'app/smart_contracts/Vault.py'). Used for context and reporting."], 
    blockchain_context: Annotated[str, "Additional blockchain context including the platform (e.g., Ethereum, Solana, Polygon), smart contract type (e.g., ERC-20, ERC-721, DeFi protocol, NFT marketplace), and critical blockchain operations this function handles."],
    list_of_blockchain_threats: Annotated[list[str], "A comprehensive list of blockchain-specific threats and vulnerabilities to check for during analysis. Each item should be a specific blockchain threat type (e.g., 'Reentrancy Attack', 'Integer Overflow/Underflow', 'Front-running', 'MEV Exploitation', 'Flash Loan Attack', 'Oracle Manipulation', 'Smart Contract Logic Flaw', 'Gas Limit DoS', 'Unchecked External Calls', 'State Variable Manipulation', 'Access Control Bypass', 'Random Number Generation Flaw', 'Timestamp Dependence', 'Transaction Ordering Dependence', etc.)."] = None
) -> str:
    """
    Analyze a function for blockchain-specific vulnerabilities and threats in smart contracts and DeFi protocols.
    
    This function focuses specifically on blockchain vulnerabilities, smart contract flaws,
    and DeFi-specific attacks that could lead to loss of funds, protocol manipulation,
    or exploitation of decentralized systems.
    
    Args:
        function_explanation: Human-readable description of the function's blockchain purpose and behavior
        function_body: Complete source code of the function to be analyzed
        file_path: Full path to the file containing the function for context
        blockchain_context: Additional blockchain platform context and smart contract type information
        list_of_blockchain_threats: List of specific blockchain threats to evaluate
        
    Returns:
        str: Detailed blockchain analysis report including identified vulnerabilities,
             attack vector analysis, potential financial impact, and remediation
             recommendations specific to blockchain and smart contract security.
             
    Example:
        result = await blockchain_threats(
            function_explanation="Transfer tokens between users with balance validation and event emission",
            function_body="function transfer(address to, uint256 amount) public { ... }",
            file_path="contracts/ERC20Token.sol",
            blockchain_context="Ethereum ERC-20 token contract with transfer functionality and event logging",
            list_of_blockchain_threats=["Reentrancy Attack", "Integer Overflow", "Access Control Bypass", "Front-running"]
        )
        
    Note:
        This function should be used for analyzing smart contracts, DeFi protocols,
        and blockchain applications where vulnerabilities could lead to loss of funds
        or protocol exploitation. Focus on blockchain-specific attack vectors and
        smart contract security best practices.
    """
    msg = f"""
BLOCKCHAIN THREAT ANALYSIS REQUEST

Function Context:
- Blockchain Purpose: {function_explanation}
- File Location: {file_path}
- Blockchain Platform: {blockchain_context}
- Blockchain Threats to Evaluate: {', '.join(list_of_blockchain_threats or ['General security threats, Common vulnerabilities, OWASP Top 10'])}

Source Code to Analyze:
{function_body}

Please perform a comprehensive blockchain security analysis focusing on the specified blockchain threats and provide detailed findings with attack vector analysis, potential financial impact, and remediation guidance specific to blockchain and smart contract vulnerabilities.
"""

    return msg


async def cryptographic_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the function does in the cryptographic context, its purpose in encryption, decryption, key management, digital signatures, or cryptographic protocols. Should include cryptographic operations, key handling, and security-critical cryptographic logic."],
    function_body: Annotated[str, "The complete source code of the function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual code that will be analyzed for cryptographic vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'crypto/encryption.py', 'src/security/Cipher.js', 'app/auth/KeyManager.py'). Used for context and reporting."], 
    cryptographic_context: Annotated[str, "Additional cryptographic context including the cryptographic algorithms used (e.g., AES, RSA, ECDSA, SHA-256), key management approach, cryptographic protocols, and security requirements this function must meet."],
    list_of_cryptographic_threats: Annotated[list[str], "A comprehensive list of cryptographic threats and vulnerabilities to check for during analysis. Each item should be a specific cryptographic threat type (e.g., 'Weak Cryptographic Algorithm', 'Insecure Key Generation', 'Key Management Flaws', 'Cryptographic Implementation Bugs', 'Side-Channel Attacks', 'Timing Attacks', 'Padding Oracle Attacks', 'Cryptographic Protocol Flaws', 'Random Number Generation Issues', 'Hash Collision Attacks', 'Certificate Validation Bypass', 'Cryptographic Library Vulnerabilities', 'Key Storage Issues', 'Cryptographic Protocol Downgrade', 'Man-in-the-Middle Attacks', etc.)."] = None
) -> str:
    """
    Analyze a function for cryptographic vulnerabilities and threats in encryption, key management, and cryptographic protocols.
    
    This function focuses specifically on cryptographic vulnerabilities, implementation flaws,
    and cryptographic protocol issues that could lead to data exposure, authentication bypass,
    or compromise of cryptographic security.
    
    Args:
        function_explanation: Human-readable description of the function's cryptographic purpose and behavior
        function_body: Complete source code of the function to be analyzed
        file_path: Full path to the file containing the function for context
        cryptographic_context: Additional cryptographic context and algorithm information
        list_of_cryptographic_threats: List of specific cryptographic threats to evaluate
        
    Returns:
        str: Detailed cryptographic analysis report including identified vulnerabilities,
             cryptographic attack vector analysis, potential security impact, and remediation
             recommendations specific to cryptographic security.
             
    Example:
        result = await cryptographic_threats(
            function_explanation="Encrypt sensitive data using AES-256-GCM with secure key derivation",
            function_body="def encrypt_data(data, password): ...",
            file_path="crypto/encryption.py",
            cryptographic_context="AES-256-GCM encryption with PBKDF2 key derivation and authenticated encryption",
            list_of_cryptographic_threats=["Weak Key Generation", "Timing Attacks", "Padding Oracle Attacks", "Key Storage Issues"]
        )
        
    Note:
        This function should be used for analyzing cryptographic functions, encryption/decryption
        routines, key management systems, and cryptographic protocols where vulnerabilities
        could lead to data exposure or cryptographic compromise. Focus on cryptographic
        best practices and secure implementation patterns.
    """
    msg = f"""
CRYPTOGRAPHIC THREAT ANALYSIS REQUEST

Function Context:
- Cryptographic Purpose: {function_explanation}
- File Location: {file_path}
- Cryptographic Context: {cryptographic_context}
- Cryptographic Threats to Evaluate: {', '.join(list_of_cryptographic_threats or ['General security threats, Common vulnerabilities, OWASP Top 10'])}

Source Code to Analyze:
{function_body}

Please perform a comprehensive cryptographic security analysis focusing on the specified cryptographic threats and provide detailed findings with cryptographic attack vector analysis, potential security impact, and remediation guidance specific to cryptographic vulnerabilities and secure implementation practices.
"""

    return msg


async def mathematical_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the function does in the mathematical context, its purpose in mathematical computations, statistical analysis, numerical algorithms, or mathematical modeling. Should include mathematical operations, computational logic, and numerical precision requirements."],
    function_body: Annotated[str, "The complete source code of the function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual code that will be analyzed for mathematical vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'math/calculations.py', 'src/algorithms/Statistics.js', 'app/analytics/MathUtils.py'). Used for context and reporting."], 
    mathematical_context: Annotated[str, "Additional mathematical context including the mathematical domain (e.g., statistics, linear algebra, calculus, discrete mathematics), computational requirements, precision needs, and mathematical algorithms this function implements."],
    list_of_mathematical_threats: Annotated[list[str], "A comprehensive list of mathematical threats and vulnerabilities to check for during analysis. Each item should be a specific mathematical threat type (e.g., 'Integer Overflow/Underflow', 'Floating Point Precision Errors', 'Division by Zero', 'Mathematical Logic Flaws', 'Numerical Instability', 'Rounding Errors', 'Statistical Bias', 'Algorithm Complexity Issues', 'Mathematical Model Flaws', 'Computational Errors', 'Precision Loss', 'Mathematical Assumption Violations', 'Numerical Overflow', 'Underflow Conditions', 'Mathematical Edge Cases', etc.)."] = None
) -> str:
    """
    Analyze a function for mathematical vulnerabilities and threats in computational algorithms and mathematical operations.
    
    This function focuses specifically on mathematical vulnerabilities, computational errors,
    and numerical precision issues that could lead to incorrect calculations, data corruption,
    or mathematical model failures.
    
    Args:
        function_explanation: Human-readable description of the function's mathematical purpose and behavior
        function_body: Complete source code of the function to be analyzed
        file_path: Full path to the file containing the function for context
        mathematical_context: Additional mathematical context and computational requirements
        list_of_mathematical_threats: List of specific mathematical threats to evaluate
        
    Returns:
        str: Detailed mathematical analysis report including identified vulnerabilities,
             computational error analysis, potential mathematical impact, and remediation
             recommendations specific to mathematical and numerical security.
             
    Example:
        result = await mathematical_threats(
            function_explanation="Calculate compound interest with high precision for financial calculations",
            function_body="def calculate_compound_interest(principal, rate, time): ...",
            file_path="math/financial_calculations.py",
            mathematical_context="Financial mathematics with compound interest calculations requiring high precision and decimal accuracy",
            list_of_mathematical_threats=["Floating Point Precision Errors", "Integer Overflow", "Division by Zero", "Rounding Errors"]
        )
        
    Note:
        This function should be used for analyzing mathematical functions, computational
        algorithms, statistical calculations, and numerical operations where mathematical
        errors could lead to incorrect results or computational failures. Focus on
        mathematical correctness and numerical precision requirements.
    """
    msg = f"""
MATHEMATICAL THREAT ANALYSIS REQUEST

Function Context:
- Mathematical Purpose: {function_explanation}
- File Location: {file_path}
- Mathematical Context: {mathematical_context}
- Mathematical Threats to Evaluate: {', '.join(list_of_mathematical_threats or ['General security threats, Common vulnerabilities, OWASP Top 10'])}

Source Code to Analyze:
{function_body}

Please perform a comprehensive mathematical security analysis focusing on the specified mathematical threats and provide detailed findings with computational error analysis, potential mathematical impact, and remediation guidance specific to mathematical vulnerabilities and numerical precision requirements.
"""

    return msg