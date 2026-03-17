from typing import Annotated


async def java_general_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Java function does, its purpose, and its role in the application. Should include Java-specific operations, JVM usage, and any Java-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the Java function including all statements, variable assignments, control flow, function calls, Java operations, and any nested logic. This is the actual Java code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'src/main/java/UserService.java', 'lib/security/CryptoUtils.java', 'app/network/HttpHandler.java'). Used for context and reporting."], 
    java_context: Annotated[str, "Additional Java context including the Java version (e.g., Java 8, 11, 17, 21), JVM settings, and critical Java operations this function handles."],
    list_of_java_threats: Annotated[list[str], "A comprehensive list of Java-specific threats and vulnerabilities to check for during analysis. Each item should be a specific Java threat type (e.g., 'Java Deserialization Vulnerabilities', 'Java Reflection Vulnerabilities', 'Java ClassLoader Vulnerabilities', 'Java RMI Vulnerabilities', 'Java JMX Vulnerabilities', 'Java JNDI Vulnerabilities', 'Java LDAP Vulnerabilities', 'Java SQL Injection Vulnerabilities', 'Java XSS Vulnerabilities', 'Java CSRF Vulnerabilities', 'Java Path Traversal Vulnerabilities', 'Java File Upload Vulnerabilities', 'Java Command Injection Vulnerabilities', 'Java XML External Entity Vulnerabilities', 'Java XXE Vulnerabilities', 'Java XML Bomb Vulnerabilities', 'Java JSON Bomb Vulnerabilities', 'Java YAML Bomb Vulnerabilities', 'Java Zip Bomb Vulnerabilities', 'Java Resource Exhaustion Vulnerabilities', 'Java Memory Exhaustion Vulnerabilities', 'Java CPU Exhaustion Vulnerabilities', 'Java Disk Exhaustion Vulnerabilities', 'Java Network Exhaustion Vulnerabilities', 'Java Thread Exhaustion Vulnerabilities', 'Java Connection Exhaustion Vulnerabilities', 'Java File Handle Exhaustion Vulnerabilities', 'Java Socket Exhaustion Vulnerabilities', 'Java Database Connection Exhaustion Vulnerabilities', 'Java Cache Exhaustion Vulnerabilities', 'Java Buffer Exhaustion Vulnerabilities', 'Java Stack Exhaustion Vulnerabilities', 'Java Heap Exhaustion Vulnerabilities', 'Java PermGen Exhaustion Vulnerabilities', 'Java Metaspace Exhaustion Vulnerabilities', 'Java CodeCache Exhaustion Vulnerabilities', 'Java Compressed Class Space Exhaustion Vulnerabilities', 'Java Direct Memory Exhaustion Vulnerabilities', 'Java Native Memory Exhaustion Vulnerabilities', 'Java Off-Heap Memory Exhaustion Vulnerabilities', 'Java On-Heap Memory Exhaustion Vulnerabilities', 'Java Memory Leak Vulnerabilities', 'Java Resource Leak Vulnerabilities', 'Java Connection Leak Vulnerabilities', 'Java File Handle Leak Vulnerabilities', 'Java Socket Leak Vulnerabilities', 'Java Database Connection Leak Vulnerabilities', 'Java Cache Leak Vulnerabilities', 'Java Buffer Leak Vulnerabilities', 'Java Thread Leak Vulnerabilities', 'Java Object Leak Vulnerabilities', 'Java Reference Leak Vulnerabilities', 'Java Weak Reference Leak Vulnerabilities', 'Java Soft Reference Leak Vulnerabilities', 'Java Phantom Reference Leak Vulnerabilities', 'Java Finalizer Leak Vulnerabilities', 'Java Cleaner Leak Vulnerabilities', 'Java Resource Cleanup Vulnerabilities', 'Java Exception Handling Vulnerabilities', 'Java Error Handling Vulnerabilities', 'Java Logging Vulnerabilities', 'Java Monitoring Vulnerabilities', 'Java Auditing Vulnerabilities', 'Java Reporting Vulnerabilities', 'Java Analytics Vulnerabilities', 'Java Mining Vulnerabilities', 'Java Machine Learning Vulnerabilities', 'Java AI Vulnerabilities', 'Java Algorithm Vulnerabilities', 'Java Model Vulnerabilities', 'Java Training Vulnerabilities', 'Java Testing Vulnerabilities', 'Java Validation Vulnerabilities', 'Java Cross-Validation Vulnerabilities', 'Java Overfitting Vulnerabilities', 'Java Underfitting Vulnerabilities', 'Java Bias Vulnerabilities', 'Java Fairness Vulnerabilities', 'Java Discrimination Vulnerabilities', etc.)."] = None
) -> str:
    """
    Analyze a Java function for Java-specific security vulnerabilities and threats.
    
    This function focuses specifically on Java vulnerabilities, Java implementation flaws,
    and Java-specific attack vectors that could lead to deserialization attacks,
    reflection abuse, or exploitation of Java functionality.
    
    Args:
        function_explanation: Human-readable description of the Java function's purpose and behavior
        function_body: Complete source code of the Java function to be analyzed
        file_path: Full path to the file containing the Java function for context
        java_context: Additional Java context and Java implementation information
        list_of_java_threats: List of specific Java threats to evaluate
        
    Returns:
        str: Detailed Java analysis report including identified vulnerabilities,
             Java-specific attack vector analysis, potential Java impact, and remediation
             recommendations specific to Java security.
             
    Example:
        result = await java_general_threats(
            function_explanation="User authentication service with JWT token validation",
            function_body="public User authenticate(String token) { ... }",
            file_path="src/main/java/UserService.java",
            java_context="Java 17 service with JWT authentication and user validation",
            list_of_java_threats=["Java Deserialization Vulnerabilities", "Java Reflection Vulnerabilities", "Java SQL Injection Vulnerabilities", "Java XSS Vulnerabilities"]
        )
        
    Note:
        This function should be used for analyzing Java functions, Java implementations,
        and Java-specific code where vulnerabilities could lead to Java compromise
        or Java functionality exploitation. Focus on Java security best practices.
    """
    msg = f"""
JAVA GENERAL THREAT ANALYSIS REQUEST

Function Context:
- Java Purpose: {function_explanation}
- File Location: {file_path}
- Java Context: {java_context}
- Java Threats to Evaluate: {', '.join(list_of_java_threats or ['General security threats, Common vulnerabilities, OWASP Top 10'])}

Java Source Code to Analyze:
{function_body}

Please perform a comprehensive Java security analysis focusing on the specified threats and provide detailed findings with Java-specific attack vector analysis, potential Java impact, and remediation guidance specific to Java vulnerabilities and secure Java development practices.
"""

    return msg
