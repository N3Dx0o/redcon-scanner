from typing import Annotated


async def owasp_top10_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the web function does, its purpose in the web application, and its role in handling user requests. Should include web operations, data processing, and any web-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the web function including all statements, variable assignments, control flow, function calls, web operations, and any nested logic. This is the actual web code that will be analyzed for OWASP vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'src/controllers/auth.py', 'app/routes/users.js', 'controllers/UserController.java'). Used for context and reporting."], 
    web_context: Annotated[str, "Additional web context including the framework used (e.g., Django, Express, Spring Boot), web server (e.g., Apache, Nginx), and critical web operations this function handles."],
    list_of_owasp_threats: Annotated[list[str], "A comprehensive list of OWASP Top 10 threats and vulnerabilities to check for during analysis. Each item should be a specific OWASP threat type (e.g., 'A01:2021 - Broken Access Control', 'A02:2021 - Cryptographic Failures', 'A03:2021 - Injection', 'A04:2021 - Insecure Design', 'A05:2021 - Security Misconfiguration', 'A06:2021 - Vulnerable and Outdated Components', 'A07:2021 - Identification and Authentication Failures', 'A08:2021 - Software and Data Integrity Failures', 'A09:2021 - Security Logging and Monitoring Failures', 'A10:2021 - Server-Side Request Forgery (SSRF)', 'SQL Injection', 'Cross-Site Scripting (XSS)', 'Cross-Site Request Forgery (CSRF)', 'XML External Entity (XXE)', 'Broken Authentication', 'Sensitive Data Exposure', 'XML External Entities', 'Insecure Deserialization', 'Using Components with Known Vulnerabilities', 'Insufficient Logging & Monitoring', etc.)."]
) -> str:
    """
    Analyze a web function for OWASP Top 10 security vulnerabilities and threats.
    
    This function focuses specifically on OWASP Top 10 vulnerabilities, web application security issues,
    and web-specific attack vectors that could lead to application compromise,
    data breaches, or exploitation of web functionality.
    
    Args:
        function_explanation: Human-readable description of the web function's purpose and behavior
        function_body: Complete source code of the web function to be analyzed
        file_path: Full path to the file containing the web function for context
        web_context: Additional web context and web application information
        list_of_owasp_threats: List of specific OWASP threats to evaluate
        
    Returns:
        str: Detailed OWASP analysis report including identified vulnerabilities,
             OWASP-specific attack vector analysis, potential web impact, and remediation
             recommendations specific to web application security.
             
    Example:
        result = await owasp_top10_threats(
            function_explanation="User authentication endpoint with session management and password validation",
            function_body="def login(request): return authenticate_user(request.POST['username'], request.POST['password'])",
            file_path="src/controllers/auth.py",
            web_context="Django web application with session-based authentication",
            list_of_owasp_threats=["A01:2021 - Broken Access Control", "A07:2021 - Identification and Authentication Failures", "SQL Injection", "Cross-Site Scripting (XSS)"]
        )
        
    Note:
        This function should be used for analyzing web functions, web applications,
        and web-specific code where vulnerabilities could lead to web compromise
        or web functionality exploitation. Focus on OWASP security best practices.
    """
    msg = f"""
OWASP TOP 10 THREAT ANALYSIS REQUEST

Function Context:
- Web Purpose: {function_explanation}
- File Location: {file_path}
- Web Context: {web_context}
- OWASP Threats to Evaluate: {', '.join(list_of_owasp_threats)}

Web Source Code to Analyze:
{function_body}

Please perform a comprehensive OWASP Top 10 security analysis focusing on the specified threats and provide detailed findings with OWASP-specific attack vector analysis, potential web impact, and remediation guidance specific to web application security vulnerabilities and secure web development practices.
"""

    return msg


async def api_security_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the API function does, its purpose in the API service, and its role in handling API requests. Should include API operations, data serialization, and any API-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the API function including all statements, variable assignments, control flow, function calls, API operations, and any nested logic. This is the actual API code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'api/endpoints/users.py', 'src/routes/api.js', 'controllers/ApiController.java'). Used for context and reporting."], 
    api_context: Annotated[str, "Additional API context including the API type (e.g., REST, GraphQL, gRPC), authentication method (e.g., JWT, OAuth, API keys), and critical API operations this function handles."],
    list_of_api_threats: Annotated[list[str], "A comprehensive list of API-specific threats and vulnerabilities to check for during analysis. Each item should be a specific API threat type (e.g., 'API Authentication Bypass', 'API Authorization Flaws', 'API Rate Limiting Bypass', 'API Input Validation Issues', 'API Output Encoding Problems', 'API Error Information Disclosure', 'API Mass Assignment', 'API Injection Attacks', 'API Business Logic Flaws', 'API Resource Exhaustion', 'API Data Exposure', 'API Improper Assets Management', 'API Security Logging and Monitoring Failures', 'API Broken Function Level Authorization', 'API Excessive Data Exposure', 'API Lack of Resources and Rate Limiting', 'API Mass Assignment', 'API Security Misconfiguration', 'API Improper Inventory Management', 'API Insufficient Logging and Monitoring', 'API Broken Object Level Authorization', 'API Broken User Authentication', 'API Excessive Data Exposure', 'API Lack of Resources and Rate Limiting', 'API Mass Assignment', 'API Security Misconfiguration', 'API Improper Inventory Management', 'API Insufficient Logging and Monitoring', etc.)."]
) -> str:
    """
    Analyze an API function for API-specific security vulnerabilities and threats.
    
    This function focuses specifically on API vulnerabilities, API security issues,
    and API-specific attack vectors that could lead to API compromise,
    data exposure, or exploitation of API functionality.
    
    Args:
        function_explanation: Human-readable description of the API function's purpose and behavior
        function_body: Complete source code of the API function to be analyzed
        file_path: Full path to the file containing the API function for context
        api_context: Additional API context and API implementation information
        list_of_api_threats: List of specific API threats to evaluate
        
    Returns:
        str: Detailed API analysis report including identified vulnerabilities,
             API-specific attack vector analysis, potential API impact, and remediation
             recommendations specific to API security.
             
    Example:
        result = await api_security_threats(
            function_explanation="REST API endpoint for user data retrieval with JWT authentication",
            function_body="def get_user_data(request): return User.objects.filter(id=request.user.id).values()",
            file_path="api/endpoints/users.py",
            api_context="Django REST API with JWT authentication and user data access",
            list_of_api_threats=["API Authentication Bypass", "API Authorization Flaws", "API Data Exposure", "API Input Validation Issues"]
        )
        
    Note:
        This function should be used for analyzing API functions, API services,
        and API-specific code where vulnerabilities could lead to API compromise
        or API functionality exploitation. Focus on API security best practices.
    """
    msg = f"""
API SECURITY THREAT ANALYSIS REQUEST

Function Context:
- API Purpose: {function_explanation}
- File Location: {file_path}
- API Context: {api_context}
- API Threats to Evaluate: {', '.join(list_of_api_threats)}

API Source Code to Analyze:
{function_body}

Please perform a comprehensive API security analysis focusing on the specified threats and provide detailed findings with API-specific attack vector analysis, potential API impact, and remediation guidance specific to API security vulnerabilities and secure API development practices.
"""

    return msg


async def xss_security_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the web function does, its purpose in the web application, and its role in handling user input and rendering content. Should include HTML generation, template rendering, and output operations."],
    function_body: Annotated[str, "The complete source code of the web function including all statements, variable assignments, control flow, function calls, HTML rendering, and any nested logic. This is the actual web code that will be analyzed for XSS vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'src/views/users.php', 'app/components/UserProfile.jsx', 'templates/user.html'). Used for context and reporting."], 
    web_context: Annotated[str, "Additional web context including the template engine used (e.g., Jinja2, Handlebars, React), output encoding mechanism, and user input handling."],
    list_of_xss_threats: Annotated[list[str], "A comprehensive list of XSS-related threats to check for during analysis. Each item should be a specific XSS threat type (e.g., 'Reflected XSS', 'Stored XSS', 'DOM-based XSS', 'Blind XSS', 'XSS in Templates', 'XSS in JavaScript Context', 'XSS in HTML Context', 'XSS in URL Context', 'XSS in CSS Context', 'XSS in Event Handlers', 'XSS via InnerHTML', 'XSS via document.write', 'XSS in JSON Response', 'XSS Filter Bypass', 'CSP Bypass for XSS', 'XSS in AJAX Responses', 'XSS in Error Messages', etc.)."]
) -> str:
    """
    Analyze a web function for Cross-Site Scripting (XSS) security vulnerabilities and threats.
    
    This function focuses specifically on XSS vulnerabilities, where untrusted user input
    is rendered in web pages without proper encoding or sanitization, potentially allowing
    attacker-controlled JavaScript to execute in other users' browsers.
    
    Args:
        function_explanation: Human-readable description of the web function's purpose and behavior
        function_body: Complete source code of the web function to be analyzed
        file_path: Full path to the file containing the web function for context
        web_context: Additional web context and template rendering information
        list_of_xss_threats: List of specific XSS threats to evaluate
        
    Returns:
        str: Detailed XSS analysis report including identified vulnerabilities,
             XSS attack vector analysis, potential impact, and remediation
             recommendations specific to preventing XSS attacks.
             
    Example:
        result = await xss_security_threats(
            function_explanation="User profile page that displays user-provided bio and comments with HTML rendering",
            function_body="def user_profile(request): return render(request, 'profile.html', {'bio': request.user.bio})",
            file_path="src/views/profiles.py",
            web_context="Django template engine with auto-escaping enabled",
            list_of_xss_threats=["Stored XSS", "Reflected XSS", "XSS in Templates", "XSS Filter Bypass"]
        )
        
    Note:
        This function should be used for analyzing web functions that render user input
        or dynamic content in HTML, JavaScript, or other web contexts. Focus on proper
        output encoding and XSS prevention techniques.
    """
    msg = f"""
XSS SECURITY THREAT ANALYSIS REQUEST

Function Context:
- Web Purpose: {function_explanation}
- File Location: {file_path}
- Web Context: {web_context}
- XSS Threats to Evaluate: {', '.join(list_of_xss_threats)}

Web Source Code to Analyze:
{function_body}

Please perform a comprehensive XSS security analysis focusing on the specified threats and provide detailed findings with XSS attack vector analysis, potential impact (session hijacking, credential theft, malware distribution), and remediation guidance specific to preventing Cross-Site Scripting attacks, including proper output encoding, Content Security Policy implementation, and input sanitization.
"""

    return msg


async def csrf_security_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the web function does, its purpose in the web application, and its role in handling state-changing operations. Should include form processing, state modifications, and any operations that change application state."],
    function_body: Annotated[str, "The complete source code of the web function including all statements, variable assignments, control flow, function calls, form processing, and any nested logic. This is the actual web code that will be analyzed for CSRF vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'src/routes/admin.py', 'app/controllers/payments.php', 'routes/transfer.js'). Used for context and reporting."], 
    web_context: Annotated[str, "Additional web context including the framework used (e.g., Django, Flask, Express), CSRF protection mechanism (e.g., tokens, SameSite cookies), and authentication method."],
    list_of_csrf_threats: Annotated[list[str], "A comprehensive list of CSRF-related threats to check for during analysis. Each item should be a specific CSRF threat type (e.g., 'CSRF Token Missing', 'CSRF Token Validation Failure', 'CSRF with GET Requests', 'CSRF with PUT/DELETE Requests', 'CSRF SameSite Cookie Bypass', 'CSRF in AJAX Requests', 'CSRF Token Replay Attacks', 'CSRF Token Predictability', 'CSRF in File Uploads', 'CSRF in API Calls', 'Double Submit Cookie Bypass', 'Origin Header Bypass', 'Referer Header Bypass', 'CSRF in REST APIs', 'CSRF in State-Changing Operations', etc.)."]
) -> str:
    """
    Analyze a web function for Cross-Site Request Forgery (CSRF) security vulnerabilities and threats.
    
    This function focuses specifically on CSRF vulnerabilities, where an attacker can trick
    authenticated users into performing unintended actions on behalf of their authenticated
    session by submitting malicious requests.
    
    Args:
        function_explanation: Human-readable description of the web function's purpose and behavior
        function_body: Complete source code of the web function to be analyzed
        file_path: Full path to the file containing the web function for context
        web_context: Additional web context and CSRF protection information
        list_of_csrf_threats: List of specific CSRF threats to evaluate
        
    Returns:
        str: Detailed CSRF analysis report including identified vulnerabilities,
             CSRF attack vector analysis, potential impact, and remediation
             recommendations specific to preventing CSRF attacks.
             
    Example:
        result = await csrf_security_threats(
            function_explanation="Admin function to delete user accounts with administrative privileges",
            function_body="def delete_user(request): User.objects.filter(id=request.POST['user_id']).delete()",
            file_path="src/admin/users.py",
            web_context="Django application with CSRF middleware enabled",
            list_of_csrf_threats=["CSRF Token Missing", "CSRF Token Validation Failure", "CSRF in State-Changing Operations"]
        )
        
    Note:
        This function should be used for analyzing web functions that perform state-changing
        operations (create, update, delete, transfer, etc.). Focus on proper CSRF token
        implementation and validation.
    """
    msg = f"""
CSRF SECURITY THREAT ANALYSIS REQUEST

Function Context:
- Web Purpose: {function_explanation}
- File Location: {file_path}
- Web Context: {web_context}
- CSRF Threats to Evaluate: {', '.join(list_of_csrf_threats)}

Web Source Code to Analyze:
{function_body}

Please perform a comprehensive CSRF security analysis focusing on the specified threats and provide detailed findings with CSRF attack vector analysis, potential impact (unauthorized actions, data modification, account takeover), and remediation guidance specific to preventing Cross-Site Request Forgery attacks, including CSRF token implementation, SameSite cookie attributes, and proper request validation.
"""

    return msg


async def sql_injection_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the web function does, its purpose in the web application, and its role in database operations. Should include database queries, data retrieval, and any database interactions."],
    function_body: Annotated[str, "The complete source code of the web function including all statements, variable assignments, control flow, function calls, database queries, and any nested logic. This is the actual web code that will be analyzed for SQL injection vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'src/dao/users.js', 'app/models/AuthModel.php', 'models/UserDao.java'). Used for context and reporting."], 
    web_context: Annotated[str, "Additional web context including the database type (e.g., MySQL, PostgreSQL, SQLite), ORM used (e.g., SQLAlchemy, Sequelize, Hibernate), and query construction method."],
    list_of_sqli_threats: Annotated[list[str], "A comprehensive list of SQL injection-related threats to check for during analysis. Each item should be a specific SQL injection threat type (e.g., 'Classic SQL Injection', 'Blind SQL Injection', 'Time-based Blind SQL Injection', 'Boolean-based Blind SQL Injection', 'Union-based SQL Injection', 'Error-based SQL Injection', 'Second-order SQL Injection', 'SQL Injection in ORM', 'NoSQL Injection', 'SQL Injection via Prepared Statements Bypass', 'SQL Injection via String Concatenation', 'SQL Injection in Stored Procedures', 'SQL Injection via API Parameters', 'SQL Injection in Dynamic Queries', 'LDAP Injection', 'XPath Injection', etc.)."]
) -> str:
    """
    Analyze a web function for SQL Injection security vulnerabilities and threats.
    
    This function focuses specifically on SQL injection vulnerabilities, where untrusted user input
    is directly concatenated into database queries without proper parameterization or escaping,
    potentially allowing an attacker to manipulate database queries.
    
    Args:
        function_explanation: Human-readable description of the web function's purpose and behavior
        function_body: Complete source code of the web function to be analyzed
        file_path: Full path to the file containing the web function for context
        web_context: Additional web context and database interaction information
        list_of_sqli_threats: List of specific SQL injection threats to evaluate
        
    Returns:
        str: Detailed SQL injection analysis report including identified vulnerabilities,
             attack vector analysis, potential impact, and remediation
             recommendations specific to preventing SQL injection attacks.
             
    Example:
        result = await sql_injection_threats(
            function_explanation="User authentication function that queries database using user-provided credentials",
            function_body="query = 'SELECT * FROM users WHERE username = \\'' + username + '\\' AND password = \\'' + password + '\\''",
            file_path="src/auth/login.py",
            web_context="Raw SQL queries in Python with string concatenation",
            list_of_sqli_threats=["Classic SQL Injection", "Blind SQL Injection", "Error-based SQL Injection"]
        )
        
    Note:
        This function should be used for analyzing web functions that interact with databases.
        Focus on proper parameterized queries, prepared statements, input validation, and ORM usage.
    """
    msg = f"""
SQL INJECTION SECURITY THREAT ANALYSIS REQUEST

Function Context:
- Web Purpose: {function_explanation}
- File Location: {file_path}
- Web Context: {web_context}
- SQL Injection Threats to Evaluate: {', '.join(list_of_sqli_threats)}

Web Source Code to Analyze:
{function_body}

Please perform a comprehensive SQL injection security analysis focusing on the specified threats and provide detailed findings with attack vector analysis, potential impact (data disclosure, data manipulation, authentication bypass, complete database compromise), and remediation guidance specific to preventing SQL injection attacks, including parameterized queries, input validation, least privilege database access, and secure coding practices.
"""

    return msg


async def session_security_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the web function does, its purpose in the web application, and its role in session management. Should include session creation, validation, modification, and destruction operations."],
    function_body: Annotated[str, "The complete source code of the web function including all statements, variable assignments, control flow, function calls, session operations, and any nested logic. This is the actual web code that will be analyzed for session security vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'src/middleware/sessions.py', 'app/auth/sessionManager.js', 'security/SessionHandler.java'). Used for context and reporting."], 
    web_context: Annotated[str, "Additional web context including the session storage mechanism (e.g., server-side, client-side cookies, Redis, database), session ID generation, and cookie attributes."],
    list_of_session_threats: Annotated[list[str], "A comprehensive list of session management-related threats to check for during analysis. Each item should be a specific session threat type (e.g., 'Session Fixation', 'Session Hijacking', 'Session Timeout Issues', 'Session Prediction', 'Insecure Session Cookies', 'Missing Secure Flag on Cookies', 'Missing HttpOnly Flag on Cookies', 'Session Regeneration Not Implemented', 'Session Storage on Client Side', 'Session Replay Attacks', 'Concurrent Session Management', 'Session After Logout', 'Session on Plain HTTP', 'Weak Session IDs', 'Session Expiration Issues', etc.)."]
) -> str:
    """
    Analyze a web function for session management security vulnerabilities and threats.
    
    This function focuses specifically on session security vulnerabilities, where improper
    session handling can lead to session hijacking, fixation, prediction, or other session-related
    attacks that compromise user authentication and authorization.
    
    Args:
        function_explanation: Human-readable description of the web function's purpose and behavior
        function_body: Complete source code of the web function to be analyzed
        file_path: Full path to the file containing the web function for context
        web_context: Additional web context and session management information
        list_of_session_threats: List of specific session security threats to evaluate
        
    Returns:
        str: Detailed session security analysis report including identified vulnerabilities,
             attack vector analysis, potential impact, and remediation
             recommendations specific to secure session management.
             
    Example:
        result = await session_security_threats(
            function_explanation="Authentication function that creates new sessions for logged-in users",
            function_body="session['user_id'] = user.id; session['authenticated'] = True",
            file_path="src/auth/login.py",
            web_context="Flask sessions stored in server-side with signed cookies",
            list_of_session_threats=["Session Hijacking", "Session Fixation", "Insecure Session Cookies"]
        )
        
    Note:
        This function should be used for analyzing web functions that handle user sessions.
        Focus on proper session ID generation, secure cookie attributes, session lifecycle
        management, and protection against session-based attacks.
    """
    msg = f"""
SESSION SECURITY THREAT ANALYSIS REQUEST

Function Context:
- Web Purpose: {function_explanation}
- File Location: {file_path}
- Web Context: {web_context}
- Session Threats to Evaluate: {', '.join(list_of_session_threats)}

Web Source Code to Analyze:
{function_body}

Please perform a comprehensive session security analysis focusing on the specified threats and provide detailed findings with attack vector analysis, potential impact (account takeover, privilege escalation, unauthorized access), and remediation guidance specific to secure session management, including secure cookie attributes, session ID generation, session fixation prevention, and proper session lifecycle management.
"""

    return msg


async def authentication_authorization_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the web function does, its purpose in the web application, and its role in authentication or authorization operations. Should include user authentication, access control, permission checks, and authorization logic."],
    function_body: Annotated[str, "The complete source code of the web function including all statements, variable assignments, control flow, function calls, auth operations, and any nested logic. This is the actual web code that will be analyzed for authentication and authorization vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'src/auth/login.py', 'app/middleware/auth.js', 'security/AuthFilter.java'). Used for context and reporting."], 
    web_context: Annotated[str, "Additional web context including the authentication method (e.g., username/password, OAuth, JWT, API keys), authorization mechanism (e.g., RBAC, ABAC), and access control implementation."],
    list_of_auth_threats: Annotated[list[str], "A comprehensive list of authentication and authorization-related threats to check for during analysis. Each item should be a specific auth threat type (e.g., 'Weak Password Policy', 'Credential Stuffing', 'Brute Force Attacks', 'Password Storage Issues', 'Authentication Bypass', 'Insufficient Authentication', 'Broken Authentication', 'Broken Authorization', 'Insecure Direct Object References (IDOR)', 'Missing Function Level Access Control', 'Mass Assignment', 'Privilege Escalation', 'Path Traversal via Auth', 'JWT Security Issues', 'OAuth Security Flaws', 'Password Reset Vulnerabilities', etc.)."]
) -> str:
    """
    Analyze a web function for authentication and authorization security vulnerabilities and threats.
    
    This function focuses specifically on authentication and authorization vulnerabilities,
    including weak authentication mechanisms, improper access control, privilege escalation,
    and other authentication/authorization flaws that can lead to unauthorized access.
    
    Args:
        function_explanation: Human-readable description of the web function's purpose and behavior
        function_body: Complete source code of the web function to be analyzed
        file_path: Full path to the file containing the web function for context
        web_context: Additional web context and authentication/authorization information
        list_of_auth_threats: List of specific authentication/authorization threats to evaluate
        
    Returns:
        str: Detailed authentication/authorization analysis report including identified vulnerabilities,
             attack vector analysis, potential impact, and remediation
             recommendations specific to secure authentication and authorization.
             
    Example:
        result = await authentication_authorization_threats(
            function_explanation="User login endpoint that verifies credentials and assigns privileges",
            function_body="if username and password match: grant_admin_access()",
            file_path="src/auth/login.py",
            web_context="Basic authentication with role-based access control",
            list_of_auth_threats=["Weak Password Policy", "Broken Authentication", "Privilege Escalation"]
        )
        
    Note:
        This function should be used for analyzing web functions that handle user authentication
        and authorization. Focus on secure password storage, strong authentication mechanisms,
        proper access control, and protection against authentication bypass and privilege escalation.
    """
    msg = f"""
AUTHENTICATION AND AUTHORIZATION THREAT ANALYSIS REQUEST

Function Context:
- Web Purpose: {function_explanation}
- File Location: {file_path}
- Web Context: {web_context}
- Auth Threats to Evaluate: {', '.join(list_of_auth_threats)}

Web Source Code to Analyze:
{function_body}

Please perform a comprehensive authentication and authorization security analysis focusing on the specified threats and provide detailed findings with attack vector analysis, potential impact (unauthorized access, privilege escalation, account compromise), and remediation guidance specific to secure authentication and authorization, including strong password policies, secure credential storage, proper access control, and protection against authentication bypass and privilege escalation attacks.
"""

    return msg


async def file_upload_security_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the web function does, its purpose in the web application, and its role in handling file uploads. Should include file upload processing, storage operations, and file serving."],
    function_body: Annotated[str, "The complete source code of the web function including all statements, variable assignments, control flow, function calls, file operations, and any nested logic. This is the actual web code that will be analyzed for file upload security vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'src/uploads/handlers.py', 'app/files/upload.js', 'controllers/FileController.java'). Used for context and reporting."], 
    web_context: Annotated[str, "Additional web context including file storage location, allowed file types, file size limits, and file access mechanisms."],
    list_of_upload_threats: Annotated[list[str], "A comprehensive list of file upload-related threats to check for during analysis. Each item should be a specific file upload threat type (e.g., 'Unrestricted File Upload', 'Malicious File Upload', 'File Extension Bypass', 'Double Extension Attack', 'Content Type Validation Bypass', 'File Size Exhaustion', 'Path Traversal in File Names', 'Execution of Uploaded Files', 'File Overwrite Attack', 'Storage Path Disclosure', 'MIME Type Confusion', 'File Content Validation Missing', 'Web Shell Upload', 'PHP File Upload', 'JavaScript File Upload', etc.)."]
) -> str:
    """
    Analyze a web function for file upload security vulnerabilities and threats.
    
    This function focuses specifically on file upload vulnerabilities, where improper file upload
    handling can lead to remote code execution, system compromise, or data exfiltration.
    
    Args:
        function_explanation: Human-readable description of the web function's purpose and behavior
        function_body: Complete source code of the web function to be analyzed
        file_path: Full path to the file containing the web function for context
        web_context: Additional web context and file upload handling information
        list_of_upload_threats: List of specific file upload threats to evaluate
        
    Returns:
        str: Detailed file upload security analysis report including identified vulnerabilities,
             attack vector analysis, potential impact, and remediation
             recommendations specific to secure file upload handling.
             
    Example:
        result = await file_upload_security_threats(
            function_explanation="User profile picture upload handler that accepts image files and stores them",
            function_body="uploaded_file = request.files['avatar']; uploaded_file.save('uploads/' + filename)",
            file_path="src/upload/handler.py",
            web_context="Flask file uploads stored in local filesystem",
            list_of_upload_threats=["Unrestricted File Upload", "File Extension Bypass", "Execution of Uploaded Files"]
        )
        
    Note:
        This function should be used for analyzing web functions that handle file uploads.
        Focus on proper file type validation, safe file storage, content scanning, filename
        sanitization, and preventing execution of uploaded files.
    """
    msg = f"""
FILE UPLOAD SECURITY THREAT ANALYSIS REQUEST

Function Context:
- Web Purpose: {function_explanation}
- File Location: {file_path}
- Web Context: {web_context}
- File Upload Threats to Evaluate: {', '.join(list_of_upload_threats)}

Web Source Code to Analyze:
{function_body}

Please perform a comprehensive file upload security analysis focusing on the specified threats and provide detailed findings with attack vector analysis, potential impact (remote code execution, system compromise, web shell deployment), and remediation guidance specific to secure file upload handling, including proper file type validation, safe storage practices, content scanning, filename sanitization, and execution prevention.
"""

    return msg
