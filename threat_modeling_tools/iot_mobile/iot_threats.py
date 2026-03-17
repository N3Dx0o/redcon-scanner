from typing import Annotated


async def iot_security_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the IoT function does, its purpose in the IoT ecosystem, and its role in the connected device. Should include IoT operations, sensor data processing, and any IoT-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the IoT function including all statements, variable assignments, control flow, function calls, IoT operations, and any nested logic. This is the actual IoT code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'iot/sensors/temperature.py', 'devices/actuator_control.c', 'firmware/device_handler.ino'). Used for context and reporting."], 
    iot_context: Annotated[str, "Additional IoT context including the device type (e.g., sensor, actuator, gateway), communication protocol (e.g., MQTT, CoAP, HTTP), and critical IoT operations this function handles."],
    list_of_iot_threats: Annotated[list[str], "A comprehensive list of IoT-specific threats and vulnerabilities to check for during analysis. Each item should be a specific IoT threat type (e.g., 'Device Compromise', 'Firmware Vulnerabilities', 'Communication Interception', 'Data Tampering', 'Unauthorized Access', 'Denial of Service', 'Physical Attacks', 'Side-Channel Attacks', 'Power Analysis Attacks', 'Timing Attacks', 'Fault Injection Attacks', 'Glitch Attacks', 'Electromagnetic Attacks', 'Acoustic Attacks', 'Optical Attacks', 'Thermal Attacks', 'Voltage Attacks', 'Clock Attacks', 'Reset Attacks', 'Interrupt Attacks', 'Memory Attacks', 'Buffer Overflow', 'Stack Overflow', 'Heap Overflow', 'Use-After-Free', 'Double-Free', 'Memory Leaks', 'Dangling Pointers', 'Null Pointer Dereference', 'Integer Overflow', 'Integer Underflow', 'Type Confusion', 'Format String Vulnerabilities', 'Command Injection', 'Code Injection', 'SQL Injection', 'Path Traversal', 'File Upload Vulnerabilities', 'Deserialization Vulnerabilities', 'Cryptographic Vulnerabilities', 'Weak Encryption', 'Weak Authentication', 'Weak Authorization', 'Session Management Issues', 'Input Validation Issues', 'Output Encoding Issues', 'Error Handling Issues', 'Logging Issues', 'Monitoring Issues', 'Backup Issues', 'Recovery Issues', 'Update Issues', 'Patch Management Issues', 'Configuration Issues', 'Network Security Issues', 'Protocol Vulnerabilities', 'Transport Security Issues', 'Application Security Issues', 'Data Security Issues', 'Privacy Issues', 'Compliance Issues', 'Audit Issues', 'Incident Response Issues', 'Forensics Issues', 'Threat Intelligence Issues', 'Vulnerability Management Issues', 'Risk Management Issues', 'Governance Issues', 'Policy Issues', 'Standards Issues', 'Best Practices Issues', 'Guidelines Issues', 'Procedures Issues', 'Workflows Issues', 'Processes Issues', 'Operations Issues', 'Maintenance Issues', 'Support Issues', 'Troubleshooting Issues', 'Debugging Issues', 'Performance Issues', 'Optimization Issues', 'Tuning Issues', 'Capacity Issues', 'Planning Issues', 'Forecasting Issues', 'Prediction Issues', 'Analytics Issues', 'Metrics Issues', 'KPIs Issues', 'SLAs Issues', 'SLOs Issues', 'SLIs Issues', 'MTTR Issues', 'MTBF Issues', 'Availability Issues', 'Reliability Issues', 'Scalability Issues', 'Maintainability Issues', 'Usability Issues', 'Accessibility Issues', 'Portability Issues', 'Interoperability Issues', 'Compatibility Issues', 'Integration Issues', 'Migration Issues', 'Transformation Issues', 'Modernization Issues', 'Legacy Issues', 'Technical Debt Issues', 'Refactoring Issues', 'Optimization Issues', 'Performance Issues', 'Efficiency Issues', 'Productivity Issues', 'Quality Issues', 'Security Issues', 'Privacy Issues', 'Compliance Issues', 'Audit Issues', 'Monitoring Issues', 'Logging Issues', 'Alerting Issues', 'Incident Response Issues', 'Forensics Issues', 'Threat Intelligence Issues', 'Vulnerability Management Issues', 'Patch Management Issues', 'Update Issues', 'Rollback Issues', 'Disaster Recovery Issues', 'Business Continuity Issues', 'Risk Management Issues', 'Governance Issues', 'Policy Issues', 'Standards Issues', 'Best Practices Issues', 'Guidelines Issues', 'Procedures Issues', 'Workflows Issues', 'Processes Issues', 'Operations Issues', 'Maintenance Issues', 'Support Issues', 'Troubleshooting Issues', 'Debugging Issues', etc.)."]
) -> str:
    """
    Analyze an IoT function for IoT-specific security vulnerabilities and threats.
    
    This function focuses specifically on IoT vulnerabilities, IoT security issues,
    and IoT-specific attack vectors that could lead to device compromise,
    data breaches, or exploitation of IoT functionality.
    
    Args:
        function_explanation: Human-readable description of the IoT function's purpose and behavior
        function_body: Complete source code of the IoT function to be analyzed
        file_path: Full path to the file containing the IoT function for context
        iot_context: Additional IoT context and IoT implementation information
        list_of_iot_threats: List of specific IoT threats to evaluate
        
    Returns:
        str: Detailed IoT analysis report including identified vulnerabilities,
             IoT-specific attack vector analysis, potential IoT impact, and remediation
             recommendations specific to IoT security.
             
    Example:
        result = await iot_security_threats(
            function_explanation="Temperature sensor data collection and transmission via MQTT",
            function_body="def read_temperature(): return sensor.read()",
            file_path="iot/sensors/temperature.py",
            iot_context="Raspberry Pi with DHT22 sensor and MQTT communication",
            list_of_iot_threats=["Device Compromise", "Firmware Vulnerabilities", "Communication Interception", "Data Tampering"]
        )
        
    Note:
        This function should be used for analyzing IoT functions, IoT devices,
        and IoT-specific code where vulnerabilities could lead to IoT compromise
        or IoT functionality exploitation. Focus on IoT security best practices.
    """
    msg = f"""
IoT SECURITY THREAT ANALYSIS REQUEST

Function Context:
- IoT Purpose: {function_explanation}
- File Location: {file_path}
- IoT Context: {iot_context}
- IoT Threats to Evaluate: {', '.join(list_of_iot_threats)}

IoT Source Code to Analyze:
{function_body}

Please perform a comprehensive IoT security analysis focusing on the specified threats and provide detailed findings with IoT-specific attack vector analysis, potential IoT impact, and remediation guidance specific to IoT security vulnerabilities and secure IoT development practices.
"""

    return msg


async def mobile_security_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the mobile function does, its purpose in the mobile application, and its role in the mobile ecosystem. Should include mobile operations, user interface, and any mobile-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the mobile function including all statements, variable assignments, control flow, function calls, mobile operations, and any nested logic. This is the actual mobile code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'android/app/src/main/java/com/example/MainActivity.java', 'ios/MyApp/ViewController.swift', 'react-native/src/components/Login.js'). Used for context and reporting."], 
    mobile_context: Annotated[str, "Additional mobile context including the platform (e.g., Android, iOS, React Native), framework (e.g., Flutter, Xamarin), and critical mobile operations this function handles."],
    list_of_mobile_threats: Annotated[list[str], "A comprehensive list of mobile-specific threats and vulnerabilities to check for during analysis. Each item should be a specific mobile threat type (e.g., 'Mobile App Vulnerabilities', 'Platform Vulnerabilities', 'Framework Vulnerabilities', 'Library Vulnerabilities', 'Dependency Vulnerabilities', 'Configuration Vulnerabilities', 'Permission Vulnerabilities', 'Data Storage Vulnerabilities', 'Network Vulnerabilities', 'Authentication Vulnerabilities', 'Authorization Vulnerabilities', 'Session Management Vulnerabilities', 'Input Validation Vulnerabilities', 'Output Encoding Vulnerabilities', 'Error Handling Vulnerabilities', 'Logging Vulnerabilities', 'Monitoring Vulnerabilities', 'Backup Vulnerabilities', 'Recovery Vulnerabilities', 'Update Vulnerabilities', 'Patch Management Vulnerabilities', 'Code Signing Vulnerabilities', 'Certificate Vulnerabilities', 'Encryption Vulnerabilities', 'Key Management Vulnerabilities', 'Secure Storage Vulnerabilities', 'Secure Communication Vulnerabilities', 'API Vulnerabilities', 'WebView Vulnerabilities', 'Intent Vulnerabilities', 'Broadcast Vulnerabilities', 'Service Vulnerabilities', 'Activity Vulnerabilities', 'Fragment Vulnerabilities', 'Content Provider Vulnerabilities', 'File Provider Vulnerabilities', 'Database Vulnerabilities', 'Shared Preferences Vulnerabilities', 'Keychain Vulnerabilities', 'KeyStore Vulnerabilities', 'Biometric Vulnerabilities', 'Fingerprint Vulnerabilities', 'Face ID Vulnerabilities', 'Touch ID Vulnerabilities', 'PIN Vulnerabilities', 'Password Vulnerabilities', 'OTP Vulnerabilities', 'SMS Vulnerabilities', 'Email Vulnerabilities', 'Push Notification Vulnerabilities', 'Deep Link Vulnerabilities', 'URL Scheme Vulnerabilities', 'Custom URL Vulnerabilities', 'Universal Link Vulnerabilities', 'App Link Vulnerabilities', 'Intent Filter Vulnerabilities', 'Intent Resolution Vulnerabilities', 'Intent Spoofing Vulnerabilities', 'Intent Hijacking Vulnerabilities', 'Intent Injection Vulnerabilities', 'Intent Redirection Vulnerabilities', 'Intent Manipulation Vulnerabilities', 'Intent Tampering Vulnerabilities', 'Intent Forgery Vulnerabilities', 'Intent Replay Vulnerabilities', 'Intent Reuse Vulnerabilities', 'Intent Leakage Vulnerabilities', 'Intent Disclosure Vulnerabilities', 'Intent Exposure Vulnerabilities', 'Intent Information Disclosure Vulnerabilities', 'Intent Data Leakage Vulnerabilities', 'Intent Privacy Violations Vulnerabilities', 'Intent Confidentiality Breaches Vulnerabilities', 'Intent Integrity Violations Vulnerabilities', 'Intent Availability Issues Vulnerabilities', 'Intent Denial of Service Vulnerabilities', 'Intent Resource Exhaustion Vulnerabilities', 'Intent Memory Exhaustion Vulnerabilities', 'Intent CPU Exhaustion Vulnerabilities', 'Intent Battery Exhaustion Vulnerabilities', 'Intent Storage Exhaustion Vulnerabilities', 'Intent Network Exhaustion Vulnerabilities', 'Intent Bandwidth Exhaustion Vulnerabilities', 'Intent Connection Exhaustion Vulnerabilities', 'Intent Socket Exhaustion Vulnerabilities', 'Intent File Handle Exhaustion Vulnerabilities', 'Intent Process Exhaustion Vulnerabilities', 'Intent Thread Exhaustion Vulnerabilities', 'Intent Database Connection Exhaustion Vulnerabilities', 'Intent Cache Exhaustion Vulnerabilities', 'Intent Buffer Exhaustion Vulnerabilities', 'Intent Stack Exhaustion Vulnerabilities', 'Intent Heap Exhaustion Vulnerabilities', 'Intent PermGen Exhaustion Vulnerabilities', 'Intent Metaspace Exhaustion Vulnerabilities', 'Intent CodeCache Exhaustion Vulnerabilities', 'Intent Compressed Class Space Exhaustion Vulnerabilities', 'Intent Direct Memory Exhaustion Vulnerabilities', 'Intent Native Memory Exhaustion Vulnerabilities', 'Intent Off-Heap Memory Exhaustion Vulnerabilities', 'Intent On-Heap Memory Exhaustion Vulnerabilities', 'Intent Memory Leak Vulnerabilities', 'Intent Resource Leak Vulnerabilities', 'Intent Connection Leak Vulnerabilities', 'Intent File Handle Leak Vulnerabilities', 'Intent Socket Leak Vulnerabilities', 'Intent Database Connection Leak Vulnerabilities', 'Intent Cache Leak Vulnerabilities', 'Intent Buffer Leak Vulnerabilities', 'Intent Thread Leak Vulnerabilities', 'Intent Object Leak Vulnerabilities', 'Intent Reference Leak Vulnerabilities', 'Intent Weak Reference Leak Vulnerabilities', 'Intent Soft Reference Leak Vulnerabilities', 'Intent Phantom Reference Leak Vulnerabilities', 'Intent Finalizer Leak Vulnerabilities', 'Intent Cleaner Leak Vulnerabilities', 'Intent Resource Cleanup Vulnerabilities', 'Intent Exception Handling Vulnerabilities', 'Intent Error Handling Vulnerabilities', 'Intent Logging Vulnerabilities', 'Intent Monitoring Vulnerabilities', 'Intent Auditing Vulnerabilities', 'Intent Reporting Vulnerabilities', 'Intent Analytics Vulnerabilities', 'Intent Mining Vulnerabilities', 'Intent Machine Learning Vulnerabilities', 'Intent AI Vulnerabilities', 'Intent Algorithm Vulnerabilities', 'Intent Model Vulnerabilities', 'Intent Training Vulnerabilities', 'Intent Testing Vulnerabilities', 'Intent Validation Vulnerabilities', 'Intent Cross-Validation Vulnerabilities', 'Intent Overfitting Vulnerabilities', 'Intent Underfitting Vulnerabilities', 'Intent Bias Vulnerabilities', 'Intent Fairness Vulnerabilities', 'Intent Discrimination Vulnerabilities', etc.)."]
) -> str:
    """
    Analyze a mobile function for mobile-specific security vulnerabilities and threats.
    
    This function focuses specifically on mobile vulnerabilities, mobile security issues,
    and mobile-specific attack vectors that could lead to app compromise,
    data breaches, or exploitation of mobile functionality.
    
    Args:
        function_explanation: Human-readable description of the mobile function's purpose and behavior
        function_body: Complete source code of the mobile function to be analyzed
        file_path: Full path to the file containing the mobile function for context
        mobile_context: Additional mobile context and mobile implementation information
        list_of_mobile_threats: List of specific mobile threats to evaluate
        
    Returns:
        str: Detailed mobile analysis report including identified vulnerabilities,
             mobile-specific attack vector analysis, potential mobile impact, and remediation
             recommendations specific to mobile security.
             
    Example:
        result = await mobile_security_threats(
            function_explanation="User authentication with biometric login and secure token storage",
            function_body="func authenticateUser() { return biometricAuth.authenticate() }",
            file_path="ios/MyApp/AuthViewController.swift",
            mobile_context="iOS app with Face ID authentication and Keychain storage",
            list_of_mobile_threats=["Mobile App Vulnerabilities", "Authentication Vulnerabilities", "Data Storage Vulnerabilities", "Biometric Vulnerabilities"]
        )
        
    Note:
        This function should be used for analyzing mobile functions, mobile applications,
        and mobile-specific code where vulnerabilities could lead to mobile compromise
        or mobile functionality exploitation. Focus on mobile security best practices.
    """
    msg = f"""
MOBILE SECURITY THREAT ANALYSIS REQUEST

Function Context:
- Mobile Purpose: {function_explanation}
- File Location: {file_path}
- Mobile Context: {mobile_context}
- Mobile Threats to Evaluate: {', '.join(list_of_mobile_threats)}

Mobile Source Code to Analyze:
{function_body}

Please perform a comprehensive mobile security analysis focusing on the specified threats and provide detailed findings with mobile-specific attack vector analysis, potential mobile impact, and remediation guidance specific to mobile security vulnerabilities and secure mobile development practices.
"""

    return msg
