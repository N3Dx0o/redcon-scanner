from typing import Annotated


async def network_security_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the network function does, its purpose in network communication, and its role in the network infrastructure. Should include network operations, protocol handling, and any network-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the network function including all statements, variable assignments, control flow, function calls, network operations, and any nested logic. This is the actual network code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'network/tcp_handler.py', 'src/protocols/http.c', 'app/network/socket_manager.js'). Used for context and reporting."], 
    network_context: Annotated[str, "Additional network context including the protocol (e.g., TCP, UDP, HTTP, HTTPS, MQTT), network layer (e.g., L2, L3, L4, L7), and critical network operations this function handles."],
    list_of_network_threats: Annotated[list[str], "A comprehensive list of network-specific threats and vulnerabilities to check for during analysis. Each item should be a specific network threat type (e.g., 'Network Eavesdropping', 'Man-in-the-Middle Attacks', 'Packet Sniffing', 'ARP Spoofing', 'DNS Spoofing', 'DHCP Spoofing', 'VLAN Hopping', 'MAC Address Spoofing', 'IP Spoofing', 'TCP SYN Flood', 'UDP Flood', 'ICMP Flood', 'DDoS Attacks', 'Distributed Denial of Service', 'Botnet Attacks', 'Malware Propagation', 'Worm Attacks', 'Virus Attacks', 'Trojan Attacks', 'Rootkit Attacks', 'Backdoor Attacks', 'Ransomware Attacks', 'Spyware Attacks', 'Adware Attacks', 'Keylogger Attacks', 'Screen Capture Attacks', 'Audio Recording Attacks', 'Video Recording Attacks', 'Webcam Attacks', 'Microphone Attacks', 'GPS Tracking Attacks', 'Location Tracking Attacks', 'Bluetooth Attacks', 'WiFi Attacks', 'NFC Attacks', 'RFID Attacks', 'Zigbee Attacks', 'Z-Wave Attacks', 'LoRaWAN Attacks', 'Sigfox Attacks', 'NB-IoT Attacks', 'LTE Attacks', '5G Attacks', '6G Attacks', 'Satellite Attacks', 'Fiber Optic Attacks', 'Copper Wire Attacks', 'Wireless Attacks', 'Wired Attacks', 'Hybrid Attacks', 'Multi-Vector Attacks', 'Advanced Persistent Threats', 'Zero-Day Attacks', 'Exploit Attacks', 'Vulnerability Exploitation', 'Code Execution Attacks', 'Privilege Escalation Attacks', 'Lateral Movement Attacks', 'Persistence Attacks', 'Defense Evasion Attacks', 'Credential Access Attacks', 'Discovery Attacks', 'Collection Attacks', 'Command and Control Attacks', 'Exfiltration Attacks', 'Impact Attacks', 'Reconnaissance Attacks', 'Initial Access Attacks', 'Execution Attacks', 'Persistence Attacks', 'Privilege Escalation Attacks', 'Defense Evasion Attacks', 'Credential Access Attacks', 'Discovery Attacks', 'Lateral Movement Attacks', 'Collection Attacks', 'Command and Control Attacks', 'Exfiltration Attacks', 'Impact Attacks', 'Data Breaches', 'Data Theft', 'Data Exfiltration', 'Data Leakage', 'Data Loss', 'Data Corruption', 'Data Manipulation', 'Data Tampering', 'Data Spoofing', 'Data Forgery', 'Data Replay', 'Data Injection', 'Data Poisoning', 'Data Contamination', 'Data Pollution', 'Data Degradation', 'Data Quality Issues', 'Data Integrity Issues', 'Data Confidentiality Issues', 'Data Availability Issues', 'Data Privacy Issues', 'Data Compliance Issues', 'Data Governance Issues', 'Data Management Issues', 'Data Lifecycle Issues', 'Data Retention Issues', 'Data Disposal Issues', 'Data Archival Issues', 'Data Backup Issues', 'Data Recovery Issues', 'Data Migration Issues', 'Data Transformation Issues', 'Data Processing Issues', 'Data Analytics Issues', 'Data Mining Issues', 'Data Science Issues', 'Data Engineering Issues', 'Data Architecture Issues', 'Data Modeling Issues', 'Data Design Issues', 'Data Implementation Issues', 'Data Testing Issues', 'Data Validation Issues', 'Data Verification Issues', 'Data Quality Assurance Issues', 'Data Quality Control Issues', 'Data Monitoring Issues', 'Data Logging Issues', 'Data Auditing Issues', 'Data Reporting Issues', 'Data Visualization Issues', 'Data Dashboard Issues', 'Data Metrics Issues', 'Data KPIs Issues', 'Data SLAs Issues', 'Data SLOs Issues', 'Data SLIs Issues', 'Data MTTR Issues', 'Data MTBF Issues', 'Data Availability Issues', 'Data Reliability Issues', 'Data Scalability Issues', 'Data Maintainability Issues', 'Data Usability Issues', 'Data Accessibility Issues', 'Data Portability Issues', 'Data Interoperability Issues', 'Data Compatibility Issues', 'Data Integration Issues', 'Data Migration Issues', 'Data Transformation Issues', 'Data Modernization Issues', 'Data Legacy Issues', 'Data Technical Debt Issues', 'Data Refactoring Issues', 'Data Optimization Issues', 'Data Performance Issues', 'Data Efficiency Issues', 'Data Productivity Issues', 'Data Quality Issues', 'Data Security Issues', 'Data Privacy Issues', 'Data Compliance Issues', 'Data Audit Issues', 'Data Monitoring Issues', 'Data Logging Issues', 'Data Alerting Issues', 'Data Incident Response Issues', 'Data Forensics Issues', 'Data Threat Intelligence Issues', 'Data Vulnerability Management Issues', 'Data Patch Management Issues', 'Data Update Issues', 'Data Rollback Issues', 'Data Disaster Recovery Issues', 'Data Business Continuity Issues', 'Data Risk Management Issues', 'Data Governance Issues', 'Data Policy Issues', 'Data Standards Issues', 'Data Best Practices Issues', 'Data Guidelines Issues', 'Data Procedures Issues', 'Data Workflows Issues', 'Data Processes Issues', 'Data Operations Issues', 'Data Maintenance Issues', 'Data Support Issues', 'Data Troubleshooting Issues', 'Data Debugging Issues', etc.)."]
) -> str:
    """
    Analyze a network function for network-specific security vulnerabilities and threats.
    
    This function focuses specifically on network vulnerabilities, network security issues,
    and network-specific attack vectors that could lead to network compromise,
    data interception, or exploitation of network functionality.
    
    Args:
        function_explanation: Human-readable description of the network function's purpose and behavior
        function_body: Complete source code of the network function to be analyzed
        file_path: Full path to the file containing the network function for context
        network_context: Additional network context and network implementation information
        list_of_network_threats: List of specific network threats to evaluate
        
    Returns:
        str: Detailed network analysis report including identified vulnerabilities,
             network-specific attack vector analysis, potential network impact, and remediation
             recommendations specific to network security.
             
    Example:
        result = await network_security_threats(
            function_explanation="TCP socket handler for secure client-server communication",
            function_body="def handle_connection(socket): return process_secure_data(socket.recv(1024))",
            file_path="network/tcp_handler.py",
            network_context="Python TCP server with SSL/TLS encryption and authentication",
            list_of_network_threats=["Network Eavesdropping", "Man-in-the-Middle Attacks", "Packet Sniffing", "DDoS Attacks"]
        )
        
    Note:
        This function should be used for analyzing network functions, network protocols,
        and network-specific code where vulnerabilities could lead to network compromise
        or network functionality exploitation. Focus on network security best practices.
    """
    msg = f"""
NETWORK SECURITY THREAT ANALYSIS REQUEST

Function Context:
- Network Purpose: {function_explanation}
- File Location: {file_path}
- Network Context: {network_context}
- Network Threats to Evaluate: {', '.join(list_of_network_threats)}

Network Source Code to Analyze:
{function_body}

Please perform a comprehensive network security analysis focusing on the specified threats and provide detailed findings with network-specific attack vector analysis, potential network impact, and remediation guidance specific to network security vulnerabilities and secure network development practices.
"""

    return msg


async def data_privacy_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the data function does, its purpose in data processing, and its role in the data pipeline. Should include data operations, privacy controls, and any data-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the data function including all statements, variable assignments, control flow, function calls, data operations, and any nested logic. This is the actual data code that will be analyzed for privacy vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'data/processors/privacy_filter.py', 'src/analytics/data_anonymizer.js', 'app/data/gdpr_compliance.rs'). Used for context and reporting."], 
    data_context: Annotated[str, "Additional data context including the data type (e.g., PII, PHI, financial data), privacy regulation (e.g., GDPR, CCPA, HIPAA), and critical data operations this function handles."],
    list_of_privacy_threats: Annotated[list[str], "A comprehensive list of data privacy threats and vulnerabilities to check for during analysis. Each item should be a specific privacy threat type (e.g., 'Data Breaches', 'Data Leakage', 'Data Exposure', 'Data Theft', 'Data Exfiltration', 'Data Loss', 'Data Corruption', 'Data Manipulation', 'Data Tampering', 'Data Spoofing', 'Data Forgery', 'Data Replay', 'Data Injection', 'Data Poisoning', 'Data Contamination', 'Data Pollution', 'Data Degradation', 'Data Quality Issues', 'Data Integrity Issues', 'Data Confidentiality Issues', 'Data Availability Issues', 'Data Privacy Issues', 'Data Compliance Issues', 'Data Governance Issues', 'Data Management Issues', 'Data Lifecycle Issues', 'Data Retention Issues', 'Data Disposal Issues', 'Data Archival Issues', 'Data Backup Issues', 'Data Recovery Issues', 'Data Migration Issues', 'Data Transformation Issues', 'Data Processing Issues', 'Data Analytics Issues', 'Data Mining Issues', 'Data Science Issues', 'Data Engineering Issues', 'Data Architecture Issues', 'Data Modeling Issues', 'Data Design Issues', 'Data Implementation Issues', 'Data Testing Issues', 'Data Validation Issues', 'Data Verification Issues', 'Data Quality Assurance Issues', 'Data Quality Control Issues', 'Data Monitoring Issues', 'Data Logging Issues', 'Data Auditing Issues', 'Data Reporting Issues', 'Data Visualization Issues', 'Data Dashboard Issues', 'Data Metrics Issues', 'Data KPIs Issues', 'Data SLAs Issues', 'Data SLOs Issues', 'Data SLIs Issues', 'Data MTTR Issues', 'Data MTBF Issues', 'Data Availability Issues', 'Data Reliability Issues', 'Data Scalability Issues', 'Data Maintainability Issues', 'Data Usability Issues', 'Data Accessibility Issues', 'Data Portability Issues', 'Data Interoperability Issues', 'Data Compatibility Issues', 'Data Integration Issues', 'Data Migration Issues', 'Data Transformation Issues', 'Data Modernization Issues', 'Data Legacy Issues', 'Data Technical Debt Issues', 'Data Refactoring Issues', 'Data Optimization Issues', 'Data Performance Issues', 'Data Efficiency Issues', 'Data Productivity Issues', 'Data Quality Issues', 'Data Security Issues', 'Data Privacy Issues', 'Data Compliance Issues', 'Data Audit Issues', 'Data Monitoring Issues', 'Data Logging Issues', 'Data Alerting Issues', 'Data Incident Response Issues', 'Data Forensics Issues', 'Data Threat Intelligence Issues', 'Data Vulnerability Management Issues', 'Data Patch Management Issues', 'Data Update Issues', 'Data Rollback Issues', 'Data Disaster Recovery Issues', 'Data Business Continuity Issues', 'Data Risk Management Issues', 'Data Governance Issues', 'Data Policy Issues', 'Data Standards Issues', 'Data Best Practices Issues', 'Data Guidelines Issues', 'Data Procedures Issues', 'Data Workflows Issues', 'Data Processes Issues', 'Data Operations Issues', 'Data Maintenance Issues', 'Data Support Issues', 'Data Troubleshooting Issues', 'Data Debugging Issues', 'GDPR Violations', 'CCPA Violations', 'HIPAA Violations', 'SOX Violations', 'PCI DSS Violations', 'FERPA Violations', 'COPPA Violations', 'PIPEDA Violations', 'LGPD Violations', 'PDPA Violations', 'PDPB Violations', 'DPA Violations', 'DPO Violations', 'DPIA Violations', 'LIA Violations', 'PIA Violations', 'TIA Violations', 'SIA Violations', 'CIA Violations', 'BIA Violations', 'RIA Violations', 'MIA Violations', 'FIA Violations', 'GIA Violations', 'HIA Violations', 'IIA Violations', 'JIA Violations', 'KIA Violations', 'LIA Violations', 'MIA Violations', 'NIA Violations', 'OIA Violations', 'PIA Violations', 'QIA Violations', 'RIA Violations', 'SIA Violations', 'TIA Violations', 'UIA Violations', 'VIA Violations', 'WIA Violations', 'XIA Violations', 'YIA Violations', 'ZIA Violations', etc.)."]
) -> str:
    """
    Analyze a data function for data privacy vulnerabilities and threats.
    
    This function focuses specifically on data privacy vulnerabilities, data protection issues,
    and data-specific attack vectors that could lead to privacy violations,
    data breaches, or exploitation of data functionality.
    
    Args:
        function_explanation: Human-readable description of the data function's purpose and behavior
        function_body: Complete source code of the data function to be analyzed
        file_path: Full path to the file containing the data function for context
        data_context: Additional data context and data implementation information
        list_of_privacy_threats: List of specific privacy threats to evaluate
        
    Returns:
        str: Detailed privacy analysis report including identified vulnerabilities,
             privacy-specific attack vector analysis, potential data impact, and remediation
             recommendations specific to data privacy security.
             
    Example:
        result = await data_privacy_threats(
            function_explanation="GDPR-compliant data anonymization for user personal information",
            function_body="def anonymize_pii(data): return apply_differential_privacy(data)",
            file_path="data/processors/privacy_filter.py",
            data_context="Python data processor with GDPR compliance and differential privacy",
            list_of_privacy_threats=["Data Breaches", "Data Leakage", "GDPR Violations", "Data Exposure"]
        )
        
    Note:
        This function should be used for analyzing data functions, data processing,
        and data-specific code where vulnerabilities could lead to privacy violations
        or data functionality exploitation. Focus on data privacy best practices.
    """
    msg = f"""
DATA PRIVACY THREAT ANALYSIS REQUEST

Function Context:
- Data Purpose: {function_explanation}
- File Location: {file_path}
- Data Context: {data_context}
- Privacy Threats to Evaluate: {', '.join(list_of_privacy_threats)}

Data Source Code to Analyze:
{function_body}

Please perform a comprehensive data privacy analysis focusing on the specified threats and provide detailed findings with privacy-specific attack vector analysis, potential data impact, and remediation guidance specific to data privacy security vulnerabilities and secure data processing practices.
"""

    return msg
