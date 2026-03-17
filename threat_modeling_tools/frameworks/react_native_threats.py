from typing import Annotated


async def react_native_general_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the React Native function does, its purpose in the React Native application, and its role in the application. Should include React Native-specific operations, native module usage, and any React Native-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the React Native function including all statements, variable assignments, control flow, function calls, React Native operations, and any nested logic. This is the actual React Native code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'src/components/UserProfile.js', 'android/app/src/main/java/com/app/MainActivity.java', 'ios/App/AppDelegate.m'). Used for context and reporting."], 
    react_native_context: Annotated[str, "Additional React Native context including the component type (e.g., JavaScript component, native module, bridge), platform (e.g., iOS, Android, both), and critical React Native operations this function handles."],
    list_of_react_native_threats: Annotated[list[str], "A comprehensive list of React Native-specific threats and vulnerabilities to check for during analysis. Each item should be a specific React Native threat type (e.g., 'React Native Bridge Vulnerabilities', 'React Native Native Module Vulnerabilities', 'React Native JavaScript Vulnerabilities', 'React Native iOS Vulnerabilities', 'React Native Android Vulnerabilities', 'React Native Cross-Platform Vulnerabilities', 'React Native Component Vulnerabilities', 'React Native Navigation Vulnerabilities', 'React Native Storage Vulnerabilities', 'React Native Network Vulnerabilities', 'React Native Security Vulnerabilities', 'React Native Authentication Vulnerabilities', 'React Native Authorization Vulnerabilities', 'React Native Session Vulnerabilities', 'React Native CSRF Vulnerabilities', 'React Native XSS Vulnerabilities', 'React Native Injection Vulnerabilities', 'React Native SQL Injection Vulnerabilities', 'React Native NoSQL Injection Vulnerabilities', 'React Native Command Injection Vulnerabilities', 'React Native Path Traversal Vulnerabilities', 'React Native File Upload Vulnerabilities', 'React Native Deserialization Vulnerabilities', 'React Native Serialization Vulnerabilities', 'React Native JSON Vulnerabilities', 'React Native XML Vulnerabilities', 'React Native YAML Vulnerabilities', 'React Native CSV Vulnerabilities', 'React Native Excel Vulnerabilities', 'React Native PDF Vulnerabilities', 'React Native Image Vulnerabilities', 'React Native Video Vulnerabilities', 'React Native Audio Vulnerabilities', 'React Native Document Vulnerabilities', 'React Native Archive Vulnerabilities', 'React Native Compression Vulnerabilities', 'React Native Encryption Vulnerabilities', 'React Native Hashing Vulnerabilities', 'React Native Signing Vulnerabilities', 'React Native Verification Vulnerabilities', 'React Native Validation Vulnerabilities', 'React Native Sanitization Vulnerabilities', 'React Native Normalization Vulnerabilities', 'React Native Standardization Vulnerabilities', 'React Native Format Vulnerabilities', 'React Native Type Vulnerabilities', 'React Native Structure Vulnerabilities', 'React Native Schema Vulnerabilities', 'React Native Model Vulnerabilities', 'React Native Relationship Vulnerabilities', 'React Native Dependency Vulnerabilities', 'React Native Constraint Vulnerabilities', 'React Native Rule Vulnerabilities', 'React Native Policy Vulnerabilities', 'React Native Governance Vulnerabilities', 'React Native Compliance Vulnerabilities', 'React Native Audit Vulnerabilities', 'React Native Monitoring Vulnerabilities', 'React Native Logging Vulnerabilities', 'React Native Reporting Vulnerabilities', 'React Native Analytics Vulnerabilities', 'React Native Mining Vulnerabilities', 'React Native Machine Learning Vulnerabilities', 'React Native AI Vulnerabilities', 'React Native Algorithm Vulnerabilities', 'React Native Model Vulnerabilities', 'React Native Training Vulnerabilities', 'React Native Testing Vulnerabilities', 'React Native Validation Vulnerabilities', 'React Native Cross-Validation Vulnerabilities', 'React Native Overfitting Vulnerabilities', 'React Native Underfitting Vulnerabilities', 'React Native Bias Vulnerabilities', 'React Native Fairness Vulnerabilities', 'React Native Discrimination Vulnerabilities', etc.)."]
) -> str:
    """
    Build a prompt to review React Native JS/native module interactions and app safety.

    Parameters:
        function_explanation (str): Component/module purpose and invariants.
        function_body (str): Exact JS/Java/Kotlin/ObjC/Swift code.
        file_path (str): Repo-relative path.
        react_native_context (str): Platform, bridge/native modules, storage/network libs, permissions.
        list_of_react_native_threats (list[str]): Insecure storage, MITM, JS<->native injection,
            WebView risks, deep link/intent handling, permissions, code push/tamper resistance.

    Output:
        str: Prompt asking LLM to provide issues with references and actionable fixes.
    """
    msg = f"""
REACT NATIVE GENERAL THREAT ANALYSIS REQUEST

Function Context:
- React Native Purpose: {function_explanation}
- File Location: {file_path}
- React Native Context: {react_native_context}
- React Native Threats to Evaluate: {', '.join(list_of_react_native_threats)}

React Native Source Code to Analyze:
{function_body}

Please perform a comprehensive React Native security analysis focusing on the specified threats and provide detailed findings with React Native-specific attack vector analysis, potential React Native impact, and remediation guidance specific to React Native vulnerabilities and secure React Native development practices.
"""

    return msg
