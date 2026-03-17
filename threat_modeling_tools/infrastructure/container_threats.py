from typing import Annotated


async def container_security_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the container function does, its purpose in container orchestration, and its role in the containerized application. Should include container operations, image management, and any container-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the container function including all statements, variable assignments, control flow, function calls, container operations, and any nested logic. This is the actual container code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'docker/Dockerfile', 'k8s/deployment.yaml', 'scripts/container_setup.sh'). Used for context and reporting."], 
    container_context: Annotated[str, "Additional container context including the container technology (e.g., Docker, Podman, containerd), orchestration platform (e.g., Kubernetes, Docker Swarm), and critical container operations this function handles."],
    list_of_container_threats: Annotated[list[str], "A comprehensive list of container-specific threats and vulnerabilities to check for during analysis. Each item should be a specific container threat type (e.g., 'Container Escape Vulnerabilities', 'Privilege Escalation', 'Image Vulnerabilities', 'Runtime Vulnerabilities', 'Network Security Issues', 'Storage Security Issues', 'Secrets Management Issues', 'Configuration Vulnerabilities', 'Resource Exhaustion', 'Container Breakout', 'Host System Compromise', 'Container Image Tampering', 'Container Registry Vulnerabilities', 'Container Orchestration Vulnerabilities', 'Container Networking Vulnerabilities', 'Container Storage Vulnerabilities', 'Container Logging Vulnerabilities', 'Container Monitoring Vulnerabilities', 'Container Backup Vulnerabilities', 'Container Recovery Vulnerabilities', 'Container Scaling Vulnerabilities', 'Container Load Balancing Vulnerabilities', 'Container Service Discovery Vulnerabilities', 'Container Health Check Vulnerabilities', 'Container Lifecycle Vulnerabilities', 'Container Resource Management Vulnerabilities', 'Container Security Policy Violations', 'Container Compliance Violations', 'Container Audit Vulnerabilities', 'Container Incident Response Vulnerabilities', 'Container Forensics Vulnerabilities', 'Container Threat Intelligence Vulnerabilities', 'Container Vulnerability Management Vulnerabilities', 'Container Patch Management Vulnerabilities', 'Container Update Vulnerabilities', 'Container Rollback Vulnerabilities', 'Container Disaster Recovery Vulnerabilities', 'Container Business Continuity Vulnerabilities', 'Container Risk Management Vulnerabilities', 'Container Governance Vulnerabilities', 'Container Policy Violations', 'Container Standards Violations', 'Container Best Practices Violations', 'Container Guidelines Violations', 'Container Procedures Violations', 'Container Workflows Violations', 'Container Processes Violations', 'Container Operations Violations', 'Container Maintenance Violations', 'Container Support Violations', 'Container Troubleshooting Violations', 'Container Debugging Violations', 'Container Performance Violations', 'Container Optimization Violations', 'Container Tuning Violations', 'Container Capacity Violations', 'Container Planning Violations', 'Container Forecasting Violations', 'Container Prediction Violations', 'Container Analytics Violations', 'Container Metrics Violations', 'Container KPIs Violations', 'Container SLAs Violations', 'Container SLOs Violations', 'Container SLIs Violations', 'Container MTTR Violations', 'Container MTBF Violations', 'Container Availability Violations', 'Container Reliability Violations', 'Container Scalability Violations', 'Container Maintainability Violations', 'Container Usability Violations', 'Container Accessibility Violations', 'Container Portability Violations', 'Container Interoperability Violations', 'Container Compatibility Violations', 'Container Integration Violations', 'Container Migration Violations', 'Container Transformation Violations', 'Container Modernization Violations', 'Container Legacy Violations', 'Container Technical Debt Violations', 'Container Refactoring Violations', 'Container Optimization Violations', 'Container Performance Violations', 'Container Efficiency Violations', 'Container Productivity Violations', 'Container Quality Violations', 'Container Security Violations', 'Container Privacy Violations', 'Container Compliance Violations', 'Container Audit Violations', 'Container Monitoring Violations', 'Container Logging Violations', 'Container Alerting Violations', 'Container Incident Response Violations', 'Container Forensics Violations', 'Container Threat Intelligence Violations', 'Container Vulnerability Management Violations', 'Container Patch Management Violations', 'Container Update Violations', 'Container Rollback Violations', 'Container Disaster Recovery Violations', 'Container Business Continuity Violations', 'Container Risk Management Violations', 'Container Governance Violations', 'Container Policy Violations', 'Container Standards Violations', 'Container Best Practices Violations', 'Container Guidelines Violations', 'Container Procedures Violations', 'Container Workflows Violations', 'Container Processes Violations', 'Container Operations Violations', 'Container Maintenance Violations', 'Container Support Violations', 'Container Troubleshooting Violations', 'Container Debugging Violations', etc.)."]
) -> str:
    """
    Analyze a container function for container-specific security vulnerabilities and threats.
    
    This function focuses specifically on container vulnerabilities, container security issues,
    and container-specific attack vectors that could lead to container escape,
    privilege escalation, or exploitation of container functionality.
    
    Args:
        function_explanation: Human-readable description of the container function's purpose and behavior
        function_body: Complete source code of the container function to be analyzed
        file_path: Full path to the file containing the container function for context
        container_context: Additional container context and container implementation information
        list_of_container_threats: List of specific container threats to evaluate
        
    Returns:
        str: Detailed container analysis report including identified vulnerabilities,
             container-specific attack vector analysis, potential container impact, and remediation
             recommendations specific to container security.
             
    Example:
        result = await container_security_threats(
            function_explanation="Docker container setup with multi-stage build and security hardening",
            function_body="FROM node:18-alpine AS builder\nWORKDIR /app\nCOPY package*.json ./\nRUN npm ci --only=production",
            file_path="docker/Dockerfile",
            container_context="Docker container with Node.js application and Alpine Linux base image",
            list_of_container_threats=["Container Escape Vulnerabilities", "Privilege Escalation", "Image Vulnerabilities", "Runtime Vulnerabilities"]
        )
        
    Note:
        This function should be used for analyzing container functions, container configurations,
        and container-specific code where vulnerabilities could lead to container compromise
        or container functionality exploitation. Focus on container security best practices.
    """
    msg = f"""
CONTAINER SECURITY THREAT ANALYSIS REQUEST

Function Context:
- Container Purpose: {function_explanation}
- File Location: {file_path}
- Container Context: {container_context}
- Container Threats to Evaluate: {', '.join(list_of_container_threats)}

Container Source Code to Analyze:
{function_body}

Please perform a comprehensive container security analysis focusing on the specified threats and provide detailed findings with container-specific attack vector analysis, potential container impact, and remediation guidance specific to container security vulnerabilities and secure container development practices.
"""

    return msg


async def cloud_security_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the cloud function does, its purpose in cloud infrastructure, and its role in the cloud application. Should include cloud operations, resource management, and any cloud-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the cloud function including all statements, variable assignments, control flow, function calls, cloud operations, and any nested logic. This is the actual cloud code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'terraform/main.tf', 'cloudformation/template.yaml', 'scripts/aws_setup.py'). Used for context and reporting."], 
    cloud_context: Annotated[str, "Additional cloud context including the cloud provider (e.g., AWS, Azure, GCP), service type (e.g., IaaS, PaaS, SaaS), and critical cloud operations this function handles."],
    list_of_cloud_threats: Annotated[list[str], "A comprehensive list of cloud-specific threats and vulnerabilities to check for during analysis. Each item should be a specific cloud threat type (e.g., 'Cloud Misconfiguration', 'Data Breaches', 'Insecure APIs', 'Weak Identity and Access Management', 'Insufficient Logging and Monitoring', 'Account Takeover', 'Insider Threats', 'Advanced Persistent Threats', 'Data Loss', 'Service Disruption', 'Cloud Resource Abuse', 'Malicious Insiders', 'Insecure Interfaces', 'Data Breaches', 'System Vulnerabilities', 'Account Hijacking', 'Malicious Insiders', 'Insecure APIs', 'Data Loss', 'Service Disruption', 'Cloud Resource Abuse', 'Insufficient Due Diligence', 'Shared Technology Vulnerabilities', 'Cloud Provider Vulnerabilities', 'Cloud Service Vulnerabilities', 'Cloud Infrastructure Vulnerabilities', 'Cloud Platform Vulnerabilities', 'Cloud Application Vulnerabilities', 'Cloud Data Vulnerabilities', 'Cloud Network Vulnerabilities', 'Cloud Storage Vulnerabilities', 'Cloud Compute Vulnerabilities', 'Cloud Database Vulnerabilities', 'Cloud Security Vulnerabilities', 'Cloud Privacy Vulnerabilities', 'Cloud Compliance Vulnerabilities', 'Cloud Audit Vulnerabilities', 'Cloud Monitoring Vulnerabilities', 'Cloud Logging Vulnerabilities', 'Cloud Alerting Vulnerabilities', 'Cloud Incident Response Vulnerabilities', 'Cloud Forensics Vulnerabilities', 'Cloud Threat Intelligence Vulnerabilities', 'Cloud Vulnerability Management Vulnerabilities', 'Cloud Patch Management Vulnerabilities', 'Cloud Update Vulnerabilities', 'Cloud Rollback Vulnerabilities', 'Cloud Disaster Recovery Vulnerabilities', 'Cloud Business Continuity Vulnerabilities', 'Cloud Risk Management Vulnerabilities', 'Cloud Governance Vulnerabilities', 'Cloud Policy Violations', 'Cloud Standards Violations', 'Cloud Best Practices Violations', 'Cloud Guidelines Violations', 'Cloud Procedures Violations', 'Cloud Workflows Violations', 'Cloud Processes Violations', 'Cloud Operations Violations', 'Cloud Maintenance Violations', 'Cloud Support Violations', 'Cloud Troubleshooting Violations', 'Cloud Debugging Violations', 'Cloud Performance Violations', 'Cloud Optimization Violations', 'Cloud Tuning Violations', 'Cloud Capacity Violations', 'Cloud Planning Violations', 'Cloud Forecasting Violations', 'Cloud Prediction Violations', 'Cloud Analytics Violations', 'Cloud Metrics Violations', 'Cloud KPIs Violations', 'Cloud SLAs Violations', 'Cloud SLOs Violations', 'Cloud SLIs Violations', 'Cloud MTTR Violations', 'Cloud MTBF Violations', 'Cloud Availability Violations', 'Cloud Reliability Violations', 'Cloud Scalability Violations', 'Cloud Maintainability Violations', 'Cloud Usability Violations', 'Cloud Accessibility Violations', 'Cloud Portability Violations', 'Cloud Interoperability Violations', 'Cloud Compatibility Violations', 'Cloud Integration Violations', 'Cloud Migration Violations', 'Cloud Transformation Violations', 'Cloud Modernization Violations', 'Cloud Legacy Violations', 'Cloud Technical Debt Violations', 'Cloud Refactoring Violations', 'Cloud Optimization Violations', 'Cloud Performance Violations', 'Cloud Efficiency Violations', 'Cloud Productivity Violations', 'Cloud Quality Violations', 'Cloud Security Violations', 'Cloud Privacy Violations', 'Cloud Compliance Violations', 'Cloud Audit Violations', 'Cloud Monitoring Violations', 'Cloud Logging Violations', 'Cloud Alerting Violations', 'Cloud Incident Response Violations', 'Cloud Forensics Violations', 'Cloud Threat Intelligence Violations', 'Cloud Vulnerability Management Violations', 'Cloud Patch Management Violations', 'Cloud Update Violations', 'Cloud Rollback Violations', 'Cloud Disaster Recovery Violations', 'Cloud Business Continuity Violations', 'Cloud Risk Management Violations', 'Cloud Governance Violations', 'Cloud Policy Violations', 'Cloud Standards Violations', 'Cloud Best Practices Violations', 'Cloud Guidelines Violations', 'Cloud Procedures Violations', 'Cloud Workflows Violations', 'Cloud Processes Violations', 'Cloud Operations Violations', 'Cloud Maintenance Violations', 'Cloud Support Violations', 'Cloud Troubleshooting Violations', 'Cloud Debugging Violations', etc.)."]
) -> str:
    """
    Analyze a cloud function for cloud-specific security vulnerabilities and threats.
    
    This function focuses specifically on cloud vulnerabilities, cloud security issues,
    and cloud-specific attack vectors that could lead to cloud compromise,
    data breaches, or exploitation of cloud functionality.
    
    Args:
        function_explanation: Human-readable description of the cloud function's purpose and behavior
        function_body: Complete source code of the cloud function to be analyzed
        file_path: Full path to the file containing the cloud function for context
        cloud_context: Additional cloud context and cloud implementation information
        list_of_cloud_threats: List of specific cloud threats to evaluate
        
    Returns:
        str: Detailed cloud analysis report including identified vulnerabilities,
             cloud-specific attack vector analysis, potential cloud impact, and remediation
             recommendations specific to cloud security.
             
    Example:
        result = await cloud_security_threats(
            function_explanation="AWS Lambda function for processing user data with S3 storage",
            function_body="def lambda_handler(event, context): return process_user_data(event['Records'])",
            file_path="lambda/user_processor.py",
            cloud_context="AWS Lambda with S3 triggers and DynamoDB storage",
            list_of_cloud_threats=["Cloud Misconfiguration", "Data Breaches", "Insecure APIs", "Weak Identity and Access Management"]
        )
        
    Note:
        This function should be used for analyzing cloud functions, cloud infrastructure,
        and cloud-specific code where vulnerabilities could lead to cloud compromise
        or cloud functionality exploitation. Focus on cloud security best practices.
    """
    msg = f"""
CLOUD SECURITY THREAT ANALYSIS REQUEST

Function Context:
- Cloud Purpose: {function_explanation}
- File Location: {file_path}
- Cloud Context: {cloud_context}
- Cloud Threats to Evaluate: {', '.join(list_of_cloud_threats)}

Cloud Source Code to Analyze:
{function_body}

Please perform a comprehensive cloud security analysis focusing on the specified threats and provide detailed findings with cloud-specific attack vector analysis, potential cloud impact, and remediation guidance specific to cloud security vulnerabilities and secure cloud development practices.
"""

    return msg
