from typing import Annotated


async def php_general_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the PHP function does, its purpose, and its role in the application. Should include PHP-specific operations, web development, and any PHP-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the PHP function including all statements, variable assignments, control flow, function calls, PHP operations, and any nested logic. This is the actual PHP code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'src/UserController.php', 'lib/AuthService.php', 'public/index.php'). Used for context and reporting."], 
    php_context: Annotated[str, "Additional PHP context including the PHP version (e.g., PHP 7.4, 8.0, 8.1, 8.2), framework used, and critical PHP operations this function handles."],
    list_of_php_threats: Annotated[list[str], "A comprehensive list of PHP-specific threats and vulnerabilities to check for during analysis. Each item should be a specific PHP threat type (e.g., 'PHP SQL Injection Vulnerabilities', 'PHP XSS Vulnerabilities', 'PHP CSRF Vulnerabilities', 'PHP File Upload Vulnerabilities', 'PHP Path Traversal Vulnerabilities', 'PHP Command Injection Vulnerabilities', 'PHP Code Injection Vulnerabilities', 'PHP Eval Vulnerabilities', 'PHP Include Vulnerabilities', 'PHP Require Vulnerabilities', 'PHP Deserialization Vulnerabilities', 'PHP Serialization Vulnerabilities', 'PHP Session Vulnerabilities', 'PHP Cookie Vulnerabilities', 'PHP Header Vulnerabilities', 'PHP Input Vulnerabilities', 'PHP Output Vulnerabilities', 'PHP Error Handling Vulnerabilities', 'PHP Logging Vulnerabilities', 'PHP Monitoring Vulnerabilities', 'PHP Auditing Vulnerabilities', 'PHP Reporting Vulnerabilities', 'PHP Analytics Vulnerabilities', 'PHP Mining Vulnerabilities', 'PHP Machine Learning Vulnerabilities', 'PHP AI Vulnerabilities', 'PHP Algorithm Vulnerabilities', 'PHP Model Vulnerabilities', 'PHP Training Vulnerabilities', 'PHP Testing Vulnerabilities', 'PHP Validation Vulnerabilities', 'PHP Cross-Validation Vulnerabilities', 'PHP Overfitting Vulnerabilities', 'PHP Underfitting Vulnerabilities', 'PHP Bias Vulnerabilities', 'PHP Fairness Vulnerabilities', 'PHP Discrimination Vulnerabilities', etc.)."] = None
) -> str:
    """
    Analyze a PHP function for PHP-specific security vulnerabilities and threats.
    
    This function focuses specifically on PHP vulnerabilities, PHP implementation flaws,
    and PHP-specific attack vectors that could lead to web application compromise,
    code injection, or exploitation of PHP functionality.
    
    Args:
        function_explanation: Human-readable description of the PHP function's purpose and behavior
        function_body: Complete source code of the PHP function to be analyzed
        file_path: Full path to the file containing the PHP function for context
        php_context: Additional PHP context and PHP implementation information
        list_of_php_threats: List of specific PHP threats to evaluate
        
    Returns:
        str: Detailed PHP analysis report including identified vulnerabilities,
             PHP-specific attack vector analysis, potential PHP impact, and remediation
             recommendations specific to PHP security.
             
    Example:
        result = await php_general_threats(
            function_explanation="User authentication with database queries and session management",
            function_body="function authenticateUser($username, $password) { ... }",
            file_path="src/UserController.php",
            php_context="PHP 8.1 with PDO database queries and session handling",
            list_of_php_threats=["PHP SQL Injection Vulnerabilities", "PHP XSS Vulnerabilities", "PHP Session Vulnerabilities", "PHP Input Vulnerabilities"]
        )
        
    Note:
        This function should be used for analyzing PHP functions, PHP implementations,
        and PHP-specific code where vulnerabilities could lead to PHP compromise
        or PHP functionality exploitation. Focus on PHP security best practices.
    """
    msg = f"""
PHP GENERAL THREAT ANALYSIS REQUEST

Function Context:
- PHP Purpose: {function_explanation}
- File Location: {file_path}
- PHP Context: {php_context}
- PHP Threats to Evaluate: {', '.join(list_of_php_threats or ['General security threats, Common vulnerabilities, OWASP Top 10'])}

PHP Source Code to Analyze:
{function_body}

Please perform a comprehensive PHP security analysis focusing on the specified threats and provide detailed findings with PHP-specific attack vector analysis, potential PHP impact, and remediation guidance specific to PHP vulnerabilities and secure PHP development practices.
"""

    return msg
