from typing import Annotated


async def nestjs_general_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the NestJS function does, its purpose in the NestJS application, and its role in the application. Should include NestJS-specific operations, decorators, dependency injection, and any NestJS-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the NestJS function including all statements, variable assignments, control flow, function calls, NestJS operations, and any nested logic. This is the actual NestJS code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'src/controllers/users.controller.ts', 'src/services/auth.service.ts', 'src/guards/auth.guard.ts'). Used for context and reporting."], 
    nestjs_context: Annotated[str, "Additional NestJS context including the component type (e.g., controller, service, guard, interceptor, middleware), NestJS version, and critical NestJS operations this function handles."],
    list_of_nestjs_threats: Annotated[list[str], "A comprehensive list of NestJS-specific threats and vulnerabilities to check for during analysis. Each item should be a specific NestJS threat type (e.g., 'NestJS Controller Vulnerabilities', 'NestJS Service Vulnerabilities', 'NestJS Guard Vulnerabilities', 'NestJS Interceptor Vulnerabilities', 'NestJS Middleware Vulnerabilities', 'NestJS Decorator Vulnerabilities', 'NestJS Dependency Injection Vulnerabilities', 'NestJS Module Vulnerabilities', 'NestJS Provider Vulnerabilities', 'NestJS Injectable Vulnerabilities', 'NestJS Request Vulnerabilities', 'NestJS Response Vulnerabilities', 'NestJS Body Vulnerabilities', 'NestJS Query Vulnerabilities', 'NestJS Param Vulnerabilities', 'NestJS Headers Vulnerabilities', 'NestJS Cookies Vulnerabilities', 'NestJS Session Vulnerabilities', 'NestJS Authentication Vulnerabilities', 'NestJS Authorization Vulnerabilities', 'NestJS Validation Vulnerabilities', 'NestJS Serialization Vulnerabilities', 'NestJS Deserialization Vulnerabilities', 'NestJS Exception Vulnerabilities', 'NestJS Filter Vulnerabilities', 'NestJS Pipe Vulnerabilities', 'NestJS Transformer Vulnerabilities', 'NestJS Logger Vulnerabilities', 'NestJS Configuration Vulnerabilities', 'NestJS Environment Vulnerabilities', 'NestJS Database Vulnerabilities', 'NestJS ORM Vulnerabilities', 'NestJS TypeORM Vulnerabilities', 'NestJS Prisma Vulnerabilities', 'NestJS Mongoose Vulnerabilities', 'NestJS Redis Vulnerabilities', 'NestJS Cache Vulnerabilities', 'NestJS Queue Vulnerabilities', 'NestJS Event Vulnerabilities', 'NestJS WebSocket Vulnerabilities', 'NestJS GraphQL Vulnerabilities', 'NestJS Microservice Vulnerabilities', 'NestJS Gateway Vulnerabilities', 'NestJS Health Vulnerabilities', 'NestJS Metrics Vulnerabilities', 'NestJS Monitoring Vulnerabilities', 'NestJS Swagger Vulnerabilities', 'NestJS OpenAPI Vulnerabilities', etc.)."]
) -> str:
    """
    Create an LLM-ready prompt to review NestJS components (controllers/services/guards/etc.).

    Parameters:
        function_explanation (str): Purpose and guarantees.
        function_body (str): Exact code.
        file_path (str): Repo-relative path.
        nestjs_context (str): Decorators, DI providers, pipes/guards/interceptors, ORM/DB, transport.
        list_of_nestjs_threats (list[str]): AuthZ/AuthN, injection, DTO validation, exception filters,
            serialization, CSRF (if cookies), rate limiting, logging of secrets.

    Output:
        str: Prompt instructing LLM to provide issues with references and actionable remediations.
    """
    msg = f"""
NESTJS GENERAL THREAT ANALYSIS REQUEST

Function Context:
- NestJS Purpose: {function_explanation}
- File Location: {file_path}
- NestJS Context: {nestjs_context}
- NestJS Threats to Evaluate: {', '.join(list_of_nestjs_threats)}

NestJS Source Code to Analyze:
{function_body}

Please perform a comprehensive NestJS security analysis focusing on the specified threats and provide detailed findings with NestJS-specific attack vector analysis, potential NestJS impact, and remediation guidance specific to NestJS vulnerabilities and secure NestJS development practices.
"""

    return msg


async def nestjs_controller_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the NestJS controller function does, its purpose in handling HTTP requests, and its role in the NestJS application. Should include controller operations, route handling, and any controller-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the NestJS controller function including all statements, variable assignments, control flow, function calls, controller operations, and any nested logic. This is the actual NestJS controller code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'src/controllers/users.controller.ts', 'src/controllers/auth.controller.ts', 'src/controllers/admin.controller.ts'). Used for context and reporting."], 
    controller_context: Annotated[str, "Additional NestJS controller context including the controller type (e.g., REST API, GraphQL resolver), authentication method, and critical controller operations this function handles."],
    list_of_controller_threats: Annotated[list[str], "A comprehensive list of NestJS controller-specific threats and vulnerabilities to check for during analysis. Each item should be a specific controller threat type (e.g., 'Controller Route Vulnerabilities', 'Controller Method Vulnerabilities', 'Controller Parameter Vulnerabilities', 'Controller Body Vulnerabilities', 'Controller Query Vulnerabilities', 'Controller Headers Vulnerabilities', 'Controller Authentication Vulnerabilities', 'Controller Authorization Vulnerabilities', 'Controller Input Validation Vulnerabilities', 'Controller Output Serialization Vulnerabilities', 'Controller Error Handling Vulnerabilities', 'Controller Rate Limiting Vulnerabilities', 'Controller CORS Vulnerabilities', 'Controller CSRF Vulnerabilities', 'Controller XSS Vulnerabilities', 'Controller Injection Vulnerabilities', 'Controller SQL Injection Vulnerabilities', 'Controller NoSQL Injection Vulnerabilities', 'Controller Command Injection Vulnerabilities', 'Controller Path Traversal Vulnerabilities', 'Controller File Upload Vulnerabilities', 'Controller Deserialization Vulnerabilities', 'Controller Mass Assignment Vulnerabilities', 'Controller IDOR Vulnerabilities', 'Controller Privilege Escalation Vulnerabilities', 'Controller Session Vulnerabilities', 'Controller Cookie Vulnerabilities', 'Controller JWT Vulnerabilities', 'Controller OAuth Vulnerabilities', 'Controller API Key Vulnerabilities', etc.)."]
) -> str:
    """
    Build a prompt to assess NestJS controller handlers for security.

    Parameters:
        function_explanation (str): Handler intent and auth model.
        function_body (str): Exact controller code.
        file_path (str): Repo-relative path.
        controller_context (str): DTOs/validation pipes, guards, interceptors, filters.
        list_of_controller_threats (list[str]): AuthZ/AuthN, input validation, mass assignment,
            injection (SQL/NoSQL/command), file upload, error handling, rate limiting.

    Output:
        str: Prompt instructing LLM to return issues with references and fixes.
    """
    msg = f"""
NESTJS CONTROLLER THREAT ANALYSIS REQUEST

Function Context:
- Controller Purpose: {function_explanation}
- File Location: {file_path}
- Controller Context: {controller_context}
- Controller Threats to Evaluate: {', '.join(list_of_controller_threats)}

NestJS Controller Source Code to Analyze:
{function_body}

Please perform a comprehensive NestJS controller security analysis focusing on the specified threats and provide detailed findings with controller-specific attack vector analysis, potential controller impact, and remediation guidance specific to NestJS controller vulnerabilities and secure controller development practices.
"""

    return msg


async def nestjs_service_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the NestJS service function does, its purpose in business logic, and its role in the NestJS application. Should include service operations, data processing, and any service-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the NestJS service function including all statements, variable assignments, control flow, function calls, service operations, and any nested logic. This is the actual NestJS service code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'src/services/users.service.ts', 'src/services/auth.service.ts', 'src/services/email.service.ts'). Used for context and reporting."], 
    service_context: Annotated[str, "Additional NestJS service context including the service type (e.g., business logic, data access, external API), dependencies, and critical service operations this function handles."],
    list_of_service_threats: Annotated[list[str], "A comprehensive list of NestJS service-specific threats and vulnerabilities to check for during analysis. Each item should be a specific service threat type (e.g., 'Service Business Logic Vulnerabilities', 'Service Data Access Vulnerabilities', 'Service External API Vulnerabilities', 'Service Database Vulnerabilities', 'Service ORM Vulnerabilities', 'Service Query Vulnerabilities', 'Service Transaction Vulnerabilities', 'Service Cache Vulnerabilities', 'Service Validation Vulnerabilities', 'Service Serialization Vulnerabilities', 'Service Deserialization Vulnerabilities', 'Service Encryption Vulnerabilities', 'Service Hashing Vulnerabilities', 'Service Authentication Vulnerabilities', 'Service Authorization Vulnerabilities', 'Service Input Validation Vulnerabilities', 'Service Output Sanitization Vulnerabilities', 'Service Error Handling Vulnerabilities', 'Service Logging Vulnerabilities', 'Service Monitoring Vulnerabilities', 'Service Rate Limiting Vulnerabilities', 'Service Circuit Breaker Vulnerabilities', 'Service Retry Vulnerabilities', 'Service Timeout Vulnerabilities', 'Service Resource Exhaustion Vulnerabilities', 'Service Memory Vulnerabilities', 'Service CPU Vulnerabilities', 'Service Disk Vulnerabilities', 'Service Network Vulnerabilities', 'Service Dependency Vulnerabilities', etc.)."]
) -> str:
    """
    Create a prompt to evaluate NestJS service logic and data access.

    Parameters:
        function_explanation (str): Business logic expectations and invariants.
        function_body (str): Exact service code.
        file_path (str): Repo-relative path.
        service_context (str): ORM/client usage, transactions, caching, retries/timeouts.
        list_of_service_threats (list[str]): Data validation, injection, transaction integrity,
            secrets handling, retries/timeouts/circuit breaking, logging.

    Output:
        str: Prompt asking LLM to provide issues with references and remediations.
    """
    msg = f"""
NESTJS SERVICE THREAT ANALYSIS REQUEST

Function Context:
- Service Purpose: {function_explanation}
- File Location: {file_path}
- Service Context: {service_context}
- Service Threats to Evaluate: {', '.join(list_of_service_threats)}

NestJS Service Source Code to Analyze:
{function_body}

Please perform a comprehensive NestJS service security analysis focusing on the specified threats and provide detailed findings with service-specific attack vector analysis, potential service impact, and remediation guidance specific to NestJS service vulnerabilities and secure service development practices.
"""

    return msg


async def nestjs_guard_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the NestJS guard function does, its purpose in authentication and authorization, and its role in the NestJS application. Should include guard operations, access control, and any guard-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the NestJS guard function including all statements, variable assignments, control flow, function calls, guard operations, and any nested logic. This is the actual NestJS guard code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'src/guards/auth.guard.ts', 'src/guards/roles.guard.ts', 'src/guards/jwt.guard.ts'). Used for context and reporting."], 
    guard_context: Annotated[str, "Additional NestJS guard context including the guard type (e.g., authentication, authorization, role-based), authentication method, and critical guard operations this function handles."],
    list_of_guard_threats: Annotated[list[str], "A comprehensive list of NestJS guard-specific threats and vulnerabilities to check for during analysis. Each item should be a specific guard threat type (e.g., 'Guard Authentication Vulnerabilities', 'Guard Authorization Vulnerabilities', 'Guard JWT Vulnerabilities', 'Guard OAuth Vulnerabilities', 'Guard Session Vulnerabilities', 'Guard Cookie Vulnerabilities', 'Guard Token Vulnerabilities', 'Guard Role Vulnerabilities', 'Guard Permission Vulnerabilities', 'Guard Access Control Vulnerabilities', 'Guard Bypass Vulnerabilities', 'Guard Privilege Escalation Vulnerabilities', 'Guard Session Fixation Vulnerabilities', 'Guard Session Hijacking Vulnerabilities', 'Guard CSRF Vulnerabilities', 'Guard XSS Vulnerabilities', 'Guard Injection Vulnerabilities', 'Guard Input Validation Vulnerabilities', 'Guard Output Encoding Vulnerabilities', 'Guard Error Handling Vulnerabilities', 'Guard Logging Vulnerabilities', 'Guard Monitoring Vulnerabilities', 'Guard Rate Limiting Vulnerabilities', 'Guard Brute Force Vulnerabilities', 'Guard Credential Stuffing Vulnerabilities', 'Guard Password Vulnerabilities', 'Guard Multi-Factor Vulnerabilities', 'Guard Biometric Vulnerabilities', 'Guard Hardware Token Vulnerabilities', 'Guard Software Token Vulnerabilities', etc.)."]
) -> str:
    """
    Generate a prompt to review NestJS guard authn/authz enforcement.

    Parameters:
        function_explanation (str): Guard purpose and enforcement guarantees.
        function_body (str): Exact guard code.
        file_path (str): Repo-relative path.
        guard_context (str): Token/session strategy, roles/permissions, public routes.
        list_of_guard_threats (list[str]): Bypass paths, missing role/permission checks, token parsing,
            error handling, logging, timing leaks.

    Output:
        str: Prompt instructing LLM to return issues with references and fixes.
    """
    msg = f"""
NESTJS GUARD THREAT ANALYSIS REQUEST

Function Context:
- Guard Purpose: {function_explanation}
- File Location: {file_path}
- Guard Context: {guard_context}
- Guard Threats to Evaluate: {', '.join(list_of_guard_threats)}

NestJS Guard Source Code to Analyze:
{function_body}

Please perform a comprehensive NestJS guard security analysis focusing on the specified threats and provide detailed findings with guard-specific attack vector analysis, potential guard impact, and remediation guidance specific to NestJS guard vulnerabilities and secure guard development practices.
"""

    return msg
