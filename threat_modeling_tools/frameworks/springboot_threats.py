from typing import Annotated


async def springboot_general_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Spring Boot function does, its purpose in the Spring Boot application, and its role in the application. Should include Spring Boot-specific operations, dependency injection, and any Spring Boot-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the Spring Boot function including all statements, variable assignments, control flow, function calls, Spring Boot operations, and any nested logic. This is the actual Spring Boot code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'UserController.java', 'UserService.java', 'UserRepository.java'). Used for context and reporting."], 
    springboot_context: Annotated[str, "Additional Spring Boot context including the component type (e.g., controller, service, repository, configuration), Spring Boot version, and critical Spring Boot operations this function handles."],
    list_of_springboot_threats: Annotated[list[str], "A comprehensive list of Spring Boot-specific threats and vulnerabilities to check for during analysis. Each item should be a specific Spring Boot threat type (e.g., 'Spring Boot Controller Vulnerabilities', 'Spring Boot Service Vulnerabilities', 'Spring Boot Repository Vulnerabilities', 'Spring Boot Configuration Vulnerabilities', 'Spring Boot Security Vulnerabilities', 'Spring Boot Authentication Vulnerabilities', 'Spring Boot Authorization Vulnerabilities', 'Spring Boot Session Vulnerabilities', 'Spring Boot CSRF Vulnerabilities', 'Spring Boot XSS Vulnerabilities', 'Spring Boot SQL Injection Vulnerabilities', 'Spring Boot File Upload Vulnerabilities', 'Spring Boot Path Traversal Vulnerabilities', 'Spring Boot Deserialization Vulnerabilities', 'Spring Boot Serialization Vulnerabilities', 'Spring Boot JSON Vulnerabilities', 'Spring Boot XML Vulnerabilities', 'Spring Boot YAML Vulnerabilities', 'Spring Boot CSV Vulnerabilities', 'Spring Boot Excel Vulnerabilities', 'Spring Boot PDF Vulnerabilities', 'Spring Boot Image Vulnerabilities', 'Spring Boot Video Vulnerabilities', 'Spring Boot Audio Vulnerabilities', 'Spring Boot Document Vulnerabilities', 'Spring Boot Archive Vulnerabilities', 'Spring Boot Compression Vulnerabilities', 'Spring Boot Encryption Vulnerabilities', 'Spring Boot Hashing Vulnerabilities', 'Spring Boot Signing Vulnerabilities', 'Spring Boot Verification Vulnerabilities', 'Spring Boot Validation Vulnerabilities', 'Spring Boot Sanitization Vulnerabilities', 'Spring Boot Normalization Vulnerabilities', 'Spring Boot Standardization Vulnerabilities', 'Spring Boot Format Vulnerabilities', 'Spring Boot Type Vulnerabilities', 'Spring Boot Structure Vulnerabilities', 'Spring Boot Schema Vulnerabilities', 'Spring Boot Model Vulnerabilities', 'Spring Boot Relationship Vulnerabilities', 'Spring Boot Dependency Vulnerabilities', 'Spring Boot Constraint Vulnerabilities', 'Spring Boot Rule Vulnerabilities', 'Spring Boot Policy Vulnerabilities', 'Spring Boot Governance Vulnerabilities', 'Spring Boot Compliance Vulnerabilities', 'Spring Boot Audit Vulnerabilities', 'Spring Boot Monitoring Vulnerabilities', 'Spring Boot Logging Vulnerabilities', 'Spring Boot Reporting Vulnerabilities', 'Spring Boot Analytics Vulnerabilities', 'Spring Boot Mining Vulnerabilities', 'Spring Boot Machine Learning Vulnerabilities', 'Spring Boot AI Vulnerabilities', 'Spring Boot Algorithm Vulnerabilities', 'Spring Boot Model Vulnerabilities', 'Spring Boot Training Vulnerabilities', 'Spring Boot Testing Vulnerabilities', 'Spring Boot Validation Vulnerabilities', 'Spring Boot Cross-Validation Vulnerabilities', 'Spring Boot Overfitting Vulnerabilities', 'Spring Boot Underfitting Vulnerabilities', 'Spring Boot Bias Vulnerabilities', 'Spring Boot Fairness Vulnerabilities', 'Spring Boot Discrimination Vulnerabilities', etc.)."]
) -> str:
    """
    Generate an LLM-ready prompt to review Spring Boot controllers/services/repos.

    Parameters:
        function_explanation (str): Purpose and guarantees.
        function_body (str): Exact Java/Kotlin code.
        file_path (str): Repo-relative path.
        springboot_context (str): Spring Security, CSRF/session, validation, JPA/JDBC usage, profiles.
        list_of_springboot_threats (list[str]): AuthZ/AuthN, CSRF, XSS, SQLi/JPA injection, file upload,
            path traversal, CORS, exception handling, actuator exposure, config/secrets leaks.

    Output:
        str: Prompt instructing LLM to provide issues with references and actionable remediations.
    """
    msg = f"""
SPRING BOOT GENERAL THREAT ANALYSIS REQUEST

Function Context:
- Spring Boot Purpose: {function_explanation}
- File Location: {file_path}
- Spring Boot Context: {springboot_context}
- Spring Boot Threats to Evaluate: {', '.join(list_of_springboot_threats)}

Spring Boot Source Code to Analyze:
{function_body}

Please perform a comprehensive Spring Boot security analysis focusing on the specified threats and provide detailed findings with Spring Boot-specific attack vector analysis, potential Spring Boot impact, and remediation guidance specific to Spring Boot vulnerabilities and secure Spring Boot development practices.
"""

    return msg
