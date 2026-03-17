from typing import Annotated


async def python_general_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Python function does, its purpose, and its role in the application. Should include business logic context, Python-specific behaviors, and any security-relevant operations."],
    function_body: Annotated[str, "The complete Python source code of the function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual Python code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'src/controllers/user_controller.py', 'app/services/auth_service.py', 'lib/utils/validation.py'). Used for context and reporting."], 
    list_of_python_threats: Annotated[list[str], "A comprehensive list of Python-specific security threats and vulnerabilities to check for during analysis. Each item should be a specific Python threat type (e.g., 'Code Injection', 'Command Injection', 'SQL Injection', 'NoSQL Injection', 'Path Traversal', 'File Inclusion', 'Deserialization Vulnerabilities', 'Pickle Deserialization', 'YAML Deserialization', 'JSON Deserialization', 'XML External Entity (XXE)', 'Server-Side Request Forgery (SSRF)', 'Cross-Site Scripting (XSS)', 'Cross-Site Request Forgery (CSRF)', 'Authentication Bypass', 'Authorization Issues', 'Session Management Issues', 'Input Validation Flaws', 'Type Confusion', 'Memory Issues', 'Resource Exhaustion', 'Race Conditions', 'Timing Attacks', 'Side-Channel Attacks', 'Dependency Vulnerabilities', 'Supply Chain Attacks', 'Import Vulnerabilities', 'Module Injection', 'Package Vulnerabilities', 'Virtual Environment Issues', 'Environment Variable Exposure', 'Configuration Issues', 'Logging Vulnerabilities', 'Error Information Disclosure', 'Debug Information Exposure', 'Hardcoded Secrets', 'Weak Random Number Generation', 'Cryptographic Issues', 'Hash Collision Attacks', 'Buffer Overflow', 'Integer Overflow', 'Format String Vulnerabilities', 'Unsafe Eval', 'Unsafe Exec', 'Unsafe Compile', 'Unsafe Import', 'Unsafe Open', 'Unsafe Input', 'Unsafe Output', 'Unsafe Network Operations', 'Unsafe File Operations', 'Unsafe Process Operations', 'Unsafe System Operations', etc.)."] = None
) -> str:
    """
    Analyze a Python function for general security vulnerabilities and potential threats.
    
    This function serves as the primary entry point for Python threat modeling analysis.
    It takes a Python function's metadata and source code, along with a list of Python-specific threats
    to check for, and returns a comprehensive security analysis focused on Python application security.
    
    Args:
        function_explanation: Human-readable description of the Python function's purpose and behavior
        function_body: Complete Python source code of the function to be analyzed
        file_path: Full path to the Python file containing the function for context
        list_of_python_threats: List of specific Python security threats to evaluate
        
    Returns:
        str: Detailed analysis report including identified vulnerabilities, 
             severity assessments, impact analysis, and remediation recommendations
             specific to Python application security.
             
    Example:
        result = await python_general_threats(
            function_explanation="User authentication function that validates credentials and creates session tokens",
            function_body="def authenticate_user(username, password): return db.query(f'SELECT * FROM users WHERE username={username} AND password={password}')",
            file_path="app/auth/login.py",
            list_of_python_threats=["SQL Injection", "Authentication Bypass", "Input Validation Flaws", "Hardcoded Secrets"]
        )
        
    Note:
        This function should be used as part of a comprehensive Python security review process.
        The analysis quality depends on the completeness of the Python threat list and
        the accuracy of the function explanation provided.
    """
    msg = f"""
PYTHON GENERAL THREAT ANALYSIS REQUEST

Function Context:
- Python Purpose: {function_explanation}
- File Location: {file_path}
- Python Threats to Evaluate: {', '.join(list_of_python_threats or ['General security threats, Common vulnerabilities, OWASP Top 10'])}

Python Source Code to Analyze:
{function_body}

Please perform a comprehensive Python security analysis focusing on the specified threats and provide detailed findings with severity ratings and remediation guidance specific to Python security best practices.
"""

    return msg


async def python_web_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Python web function does, its purpose in web applications, and its role in handling HTTP requests and responses. Should include web framework operations, request processing, and any web-specific security behaviors."],
    function_body: Annotated[str, "The complete Python source code of the web function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual Python web code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'app/routes/users.py', 'api/controllers/product_controller.py', 'web/views/auth.py'). Used for context and reporting."], 
    web_context: Annotated[str, "Additional Python web context including the web framework used (e.g., Django, Flask, FastAPI, Pyramid), web server (e.g., Gunicorn, uWSGI, ASGI), and critical web operations this function handles."],
    list_of_web_threats: Annotated[list[str], "A comprehensive list of Python web-specific threats and vulnerabilities to check for during analysis. Each item should be a specific web threat type (e.g., 'Web Framework Vulnerabilities', 'Template Injection', 'Server-Side Template Injection (SSTI)', 'Jinja2 Template Injection', 'Django Template Injection', 'Flask Template Injection', 'Web Request Forgery', 'HTTP Parameter Pollution', 'HTTP Header Injection', 'HTTP Response Splitting', 'CRLF Injection', 'Web Cache Poisoning', 'Web Session Fixation', 'Web Session Hijacking', 'Web Cookie Manipulation', 'Web CSRF Token Issues', 'Web CORS Misconfiguration', 'Web Content Security Policy Bypass', 'Web Clickjacking', 'Web UI Redressing', 'Web Form Tampering', 'Web File Upload Vulnerabilities', 'Web Directory Traversal', 'Web Path Traversal', 'Web LFI', 'Web RFI', 'Web SSRF', 'Web XXE', 'Web XML Bomb', 'Web JSON Bomb', 'Web YAML Bomb', 'Web Deserialization', 'Web Pickle Deserialization', 'Web YAML Deserialization', 'Web JSON Deserialization', 'Web Authentication Bypass', 'Web Authorization Issues', 'Web Session Management', 'Web Input Validation', 'Web Output Encoding', 'Web Error Handling', 'Web Logging Issues', 'Web Configuration Issues', 'Web Dependency Issues', 'Web Supply Chain Issues', 'Web Import Issues', 'Web Module Issues', 'Web Package Issues', 'Web Virtual Environment Issues', 'Web Environment Issues', 'Web Secret Management', 'Web Cryptography Issues', 'Web Random Number Issues', 'Web Hash Issues', 'Web Buffer Issues', 'Web Integer Issues', 'Web Format String Issues', 'Web Eval Issues', 'Web Exec Issues', 'Web Compile Issues', 'Web Import Issues', 'Web Open Issues', 'Web Input Issues', 'Web Output Issues', 'Web Network Issues', 'Web File Issues', 'Web Process Issues', 'Web System Issues', etc.)."] = None
) -> str:
    """
    Analyze a Python web function for web application vulnerabilities and threats.
    
    This function focuses specifically on Python web vulnerabilities, web framework issues,
    and web-specific attack vectors that could lead to web compromise, data exposure,
    or exploitation of web functionality.
    
    Args:
        function_explanation: Human-readable description of the Python web function's purpose and behavior
        function_body: Complete Python source code of the web function to be analyzed
        file_path: Full path to the Python web file containing the function for context
        web_context: Additional Python web context and web framework information
        list_of_web_threats: List of specific Python web threats to evaluate
        
    Returns:
        str: Detailed Python web analysis report including identified vulnerabilities,
             web-specific attack vector analysis, potential web impact, and remediation
             recommendations specific to Python web security.
             
    Example:
        result = await python_web_threats(
            function_explanation="Flask route handler that processes user file uploads and stores them securely",
            function_body="@app.route('/upload', methods=['POST'])\ndef upload_file(): ...",
            file_path="app/routes/upload.py",
            web_context="Flask web application with file upload handling and AWS S3 storage",
            list_of_web_threats=["Web File Upload Vulnerabilities", "Web Path Traversal", "Web Template Injection", "Web CSRF Token Issues"]
        )
        
    Note:
        This function should be used for analyzing Python web functions, web frameworks,
        and web-specific code where vulnerabilities could lead to web compromise
        or web functionality exploitation. Focus on Python web security best practices.
    """
    msg = f"""
PYTHON WEB THREAT ANALYSIS REQUEST

Function Context:
- Python Web Purpose: {function_explanation}
- File Location: {file_path}
- Web Context: {web_context}
- Python Web Threats to Evaluate: {', '.join(list_of_web_threats or ['General security threats, Common vulnerabilities, OWASP Top 10'])}

Python Web Source Code to Analyze:
{function_body}

Please perform a comprehensive Python web security analysis focusing on the specified threats and provide detailed findings with web-specific attack vector analysis, potential web impact, and remediation guidance specific to Python web vulnerabilities and secure web development practices.
"""

    return msg


async def python_data_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Python data function does, its purpose in data processing, and its role in handling data operations. Should include data processing operations, data validation, and any data-specific security behaviors."],
    function_body: Annotated[str, "The complete Python source code of the data function including all statements, variable assignments, control flow, function calls, and any nested logic. This is the actual Python data code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'data/processors.py', 'ml/models.py', 'analytics/calculations.py'). Used for context and reporting."], 
    data_context: Annotated[str, "Additional Python data context including the data processing type (e.g., machine learning, data analysis, ETL, data validation), data libraries used (e.g., pandas, numpy, scikit-learn, tensorflow), and critical data operations this function handles."],
    list_of_data_threats: Annotated[list[str], "A comprehensive list of Python data-specific threats and vulnerabilities to check for during analysis. Each item should be a specific data threat type (e.g., 'Data Injection', 'Data Validation Issues', 'Data Sanitization Issues', 'Data Encoding Issues', 'Data Decoding Issues', 'Data Serialization Issues', 'Data Deserialization Issues', 'Data Pickle Issues', 'Data YAML Issues', 'Data JSON Issues', 'Data XML Issues', 'Data CSV Issues', 'Data Excel Issues', 'Data Database Issues', 'Data SQL Issues', 'Data NoSQL Issues', 'Data File Issues', 'Data Network Issues', 'Data Memory Issues', 'Data Performance Issues', 'Data Privacy Issues', 'Data Confidentiality Issues', 'Data Integrity Issues', 'Data Availability Issues', 'Data Consistency Issues', 'Data Accuracy Issues', 'Data Completeness Issues', 'Data Timeliness Issues', 'Data Relevance Issues', 'Data Quality Issues', 'Data Security Issues', 'Data Access Issues', 'Data Authorization Issues', 'Data Authentication Issues', 'Data Encryption Issues', 'Data Hashing Issues', 'Data Compression Issues', 'Data Decompression Issues', 'Data Transformation Issues', 'Data Aggregation Issues', 'Data Filtering Issues', 'Data Sorting Issues', 'Data Searching Issues', 'Data Indexing Issues', 'Data Caching Issues', 'Data Backup Issues', 'Data Recovery Issues', 'Data Archival Issues', 'Data Retention Issues', 'Data Deletion Issues', 'Data Anonymization Issues', 'Data Pseudonymization Issues', 'Data Masking Issues', 'Data Redaction Issues', 'Data Obfuscation Issues', 'Data Tokenization Issues', 'Data Encryption Issues', 'Data Hashing Issues', 'Data Signing Issues', 'Data Verification Issues', 'Data Validation Issues', 'Data Sanitization Issues', 'Data Normalization Issues', 'Data Standardization Issues', 'Data Format Issues', 'Data Type Issues', 'Data Structure Issues', 'Data Schema Issues', 'Data Model Issues', 'Data Relationship Issues', 'Data Dependency Issues', 'Data Constraint Issues', 'Data Rule Issues', 'Data Policy Issues', 'Data Governance Issues', 'Data Compliance Issues', 'Data Audit Issues', 'Data Monitoring Issues', 'Data Logging Issues', 'Data Reporting Issues', 'Data Analytics Issues', 'Data Mining Issues', 'Data Machine Learning Issues', 'Data AI Issues', 'Data Algorithm Issues', 'Data Model Issues', 'Data Training Issues', 'Data Testing Issues', 'Data Validation Issues', 'Data Cross-Validation Issues', 'Data Overfitting Issues', 'Data Underfitting Issues', 'Data Bias Issues', 'Data Fairness Issues', 'Data Discrimination Issues', 'Data Privacy Issues', 'Data Confidentiality Issues', 'Data Integrity Issues', 'Data Availability Issues', 'Data Consistency Issues', 'Data Accuracy Issues', 'Data Completeness Issues', 'Data Timeliness Issues', 'Data Relevance Issues', 'Data Quality Issues', 'Data Security Issues', 'Data Access Issues', 'Data Authorization Issues', 'Data Authentication Issues', 'Data Encryption Issues', 'Data Hashing Issues', 'Data Compression Issues', 'Data Decompression Issues', 'Data Transformation Issues', 'Data Aggregation Issues', 'Data Filtering Issues', 'Data Sorting Issues', 'Data Searching Issues', 'Data Indexing Issues', 'Data Caching Issues', 'Data Backup Issues', 'Data Recovery Issues', 'Data Archival Issues', 'Data Retention Issues', 'Data Deletion Issues', 'Data Anonymization Issues', 'Data Pseudonymization Issues', 'Data Masking Issues', 'Data Redaction Issues', 'Data Obfuscation Issues', 'Data Tokenization Issues', 'Data Encryption Issues', 'Data Hashing Issues', 'Data Signing Issues', 'Data Verification Issues', 'Data Validation Issues', 'Data Sanitization Issues', 'Data Normalization Issues', 'Data Standardization Issues', 'Data Format Issues', 'Data Type Issues', 'Data Structure Issues', 'Data Schema Issues', 'Data Model Issues', 'Data Relationship Issues', 'Data Dependency Issues', 'Data Constraint Issues', 'Data Rule Issues', 'Data Policy Issues', 'Data Governance Issues', 'Data Compliance Issues', 'Data Audit Issues', 'Data Monitoring Issues', 'Data Logging Issues', 'Data Reporting Issues', 'Data Analytics Issues', 'Data Mining Issues', 'Data Machine Learning Issues', 'Data AI Issues', 'Data Algorithm Issues', 'Data Model Issues', 'Data Training Issues', 'Data Testing Issues', 'Data Validation Issues', 'Data Cross-Validation Issues', 'Data Overfitting Issues', 'Data Underfitting Issues', 'Data Bias Issues', 'Data Fairness Issues', 'Data Discrimination Issues', etc.)."] = None
) -> str:
    """
    Analyze a Python data function for data processing vulnerabilities and threats.
    
    This function focuses specifically on Python data vulnerabilities, data processing issues,
    and data-specific attack vectors that could lead to data compromise, data corruption,
    or exploitation of data functionality.
    
    Args:
        function_explanation: Human-readable description of the Python data function's purpose and behavior
        function_body: Complete Python source code of the data function to be analyzed
        file_path: Full path to the Python data file containing the function for context
        data_context: Additional Python data context and data processing information
        list_of_data_threats: List of specific Python data threats to evaluate
        
    Returns:
        str: Detailed Python data analysis report including identified vulnerabilities,
             data-specific attack vector analysis, potential data impact, and remediation
             recommendations specific to Python data security.
             
    Example:
        result = await python_data_threats(
            function_explanation="Machine learning model training function that processes sensitive user data",
            function_body="def train_model(data): return model.fit(data)",
            file_path="ml/models.py",
            data_context="Scikit-learn machine learning pipeline with pandas data processing",
            list_of_data_threats=["Data Privacy Issues", "Data Bias Issues", "Data Validation Issues", "Data Injection"]
        )
        
    Note:
        This function should be used for analyzing Python data functions, data processing,
        and data-specific code where vulnerabilities could lead to data compromise
        or data functionality exploitation. Focus on Python data security best practices.
    """
    msg = f"""
PYTHON DATA THREAT ANALYSIS REQUEST

Function Context:
- Python Data Purpose: {function_explanation}
- File Location: {file_path}
- Data Context: {data_context}
- Python Data Threats to Evaluate: {', '.join(list_of_data_threats or ['General security threats, Common vulnerabilities, OWASP Top 10'])}

Python Data Source Code to Analyze:
{function_body}

Please perform a comprehensive Python data security analysis focusing on the specified threats and provide detailed findings with data-specific attack vector analysis, potential data impact, and remediation guidance specific to Python data vulnerabilities and secure data processing practices.
"""

    return msg
