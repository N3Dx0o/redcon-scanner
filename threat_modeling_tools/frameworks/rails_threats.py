from typing import Annotated


async def rails_general_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Rails function does, its purpose in the Rails application, and its role in the application. Should include Rails-specific operations, MVC patterns, and any Rails-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the Rails function including all statements, variable assignments, control flow, function calls, Rails operations, and any nested logic. This is the actual Rails code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'app/controllers/users_controller.rb', 'app/models/user.rb', 'app/views/users/index.html.erb'). Used for context and reporting."], 
    rails_context: Annotated[str, "Additional Rails context including the component type (e.g., controller, model, view, helper), Rails version, and critical Rails operations this function handles."],
    list_of_rails_threats: Annotated[list[str], "A comprehensive list of Rails-specific threats and vulnerabilities to check for during analysis. Each item should be a specific Rails threat type (e.g., 'Rails Controller Vulnerabilities', 'Rails Model Vulnerabilities', 'Rails View Vulnerabilities', 'Rails Helper Vulnerabilities', 'Rails Route Vulnerabilities', 'Rails Middleware Vulnerabilities', 'Rails Configuration Vulnerabilities', 'Rails Database Vulnerabilities', 'Rails Migration Vulnerabilities', 'Rails Seed Vulnerabilities', 'Rails Fixture Vulnerabilities', 'Rails Test Vulnerabilities', 'Rails Spec Vulnerabilities', 'Rails Feature Vulnerabilities', 'Rails System Vulnerabilities', 'Rails Integration Vulnerabilities', 'Rails Unit Vulnerabilities', 'Rails Functional Vulnerabilities', 'Rails Performance Vulnerabilities', 'Rails Load Vulnerabilities', 'Rails Stress Vulnerabilities', 'Rails Volume Vulnerabilities', 'Rails Scalability Vulnerabilities', 'Rails Reliability Vulnerabilities', 'Rails Availability Vulnerabilities', 'Rails Consistency Vulnerabilities', 'Rails Accuracy Vulnerabilities', 'Rails Completeness Vulnerabilities', 'Rails Timeliness Vulnerabilities', 'Rails Relevance Vulnerabilities', 'Rails Quality Vulnerabilities', 'Rails Security Vulnerabilities', 'Rails Access Vulnerabilities', 'Rails Authorization Vulnerabilities', 'Rails Authentication Vulnerabilities', 'Rails Session Vulnerabilities', 'Rails CSRF Vulnerabilities', 'Rails XSS Vulnerabilities', 'Rails SQL Injection Vulnerabilities', 'Rails File Upload Vulnerabilities', 'Rails Path Traversal Vulnerabilities', 'Rails Deserialization Vulnerabilities', 'Rails Serialization Vulnerabilities', 'Rails JSON Vulnerabilities', 'Rails XML Vulnerabilities', 'Rails YAML Vulnerabilities', 'Rails CSV Vulnerabilities', 'Rails Excel Vulnerabilities', 'Rails PDF Vulnerabilities', 'Rails Image Vulnerabilities', 'Rails Video Vulnerabilities', 'Rails Audio Vulnerabilities', 'Rails Document Vulnerabilities', 'Rails Archive Vulnerabilities', 'Rails Compression Vulnerabilities', 'Rails Encryption Vulnerabilities', 'Rails Hashing Vulnerabilities', 'Rails Signing Vulnerabilities', 'Rails Verification Vulnerabilities', 'Rails Validation Vulnerabilities', 'Rails Sanitization Vulnerabilities', 'Rails Normalization Vulnerabilities', 'Rails Standardization Vulnerabilities', 'Rails Format Vulnerabilities', 'Rails Type Vulnerabilities', 'Rails Structure Vulnerabilities', 'Rails Schema Vulnerabilities', 'Rails Model Vulnerabilities', 'Rails Relationship Vulnerabilities', 'Rails Dependency Vulnerabilities', 'Rails Constraint Vulnerabilities', 'Rails Rule Vulnerabilities', 'Rails Policy Vulnerabilities', 'Rails Governance Vulnerabilities', 'Rails Compliance Vulnerabilities', 'Rails Audit Vulnerabilities', 'Rails Monitoring Vulnerabilities', 'Rails Logging Vulnerabilities', 'Rails Reporting Vulnerabilities', 'Rails Analytics Vulnerabilities', 'Rails Mining Vulnerabilities', 'Rails Machine Learning Vulnerabilities', 'Rails AI Vulnerabilities', 'Rails Algorithm Vulnerabilities', 'Rails Model Vulnerabilities', 'Rails Training Vulnerabilities', 'Rails Testing Vulnerabilities', 'Rails Validation Vulnerabilities', 'Rails Cross-Validation Vulnerabilities', 'Rails Overfitting Vulnerabilities', 'Rails Underfitting Vulnerabilities', 'Rails Bias Vulnerabilities', 'Rails Fairness Vulnerabilities', 'Rails Discrimination Vulnerabilities', etc.)."]
) -> str:
    """
    Create an LLM prompt to review Rails MVC code for framework-specific risks.

    Parameters:
        function_explanation (str): Purpose, component type, and guarantees.
        function_body (str): Exact controller/model/view/helper code.
        file_path (str): Repo-relative path.
        rails_context (str): Auth/session/CSRF setup, strong params, ActiveRecord usage, template engine.
        list_of_rails_threats (list[str]): AuthZ/AuthN, CSRF, XSS, SQLi, mass assignment, file upload,
            path traversal, cookie flags, session fixation, configuration leaks.

    Output:
        str: Prompt instructing LLM to return issues with references and actionable remediations.
    """
    msg = f"""
RAILS GENERAL THREAT ANALYSIS REQUEST

Function Context:
- Rails Purpose: {function_explanation}
- File Location: {file_path}
- Rails Context: {rails_context}
- Rails Threats to Evaluate: {', '.join(list_of_rails_threats)}

Rails Source Code to Analyze:
{function_body}

Please perform a comprehensive Rails security analysis focusing on the specified threats and provide detailed findings with Rails-specific attack vector analysis, potential Rails impact, and remediation guidance specific to Rails vulnerabilities and secure Rails development practices.
"""

    return msg
