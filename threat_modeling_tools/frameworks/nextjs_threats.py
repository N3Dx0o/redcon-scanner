from typing import Annotated


async def nextjs_general_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Next.js function does, its purpose in the Next.js application, and its role in the application. Should include Next.js-specific operations, SSR/SSG, and any Next.js-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the Next.js function including all statements, variable assignments, control flow, function calls, Next.js operations, and any nested logic. This is the actual Next.js code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'pages/api/users.js', 'components/UserProfile.tsx', 'middleware/auth.js'). Used for context and reporting."], 
    nextjs_context: Annotated[str, "Additional Next.js context including the component type (e.g., API route, page component, middleware, custom hook), Next.js version, and critical Next.js operations this function handles."],
    list_of_nextjs_threats: Annotated[list[str], "A comprehensive list of Next.js-specific threats and vulnerabilities to check for during analysis. Each item should be a specific Next.js threat type (e.g., 'Next.js SSR Vulnerabilities', 'Next.js SSG Vulnerabilities', 'Next.js API Route Vulnerabilities', 'Next.js Middleware Vulnerabilities', 'Next.js Component Vulnerabilities', 'Next.js Hook Vulnerabilities', 'Next.js Context Vulnerabilities', 'Next.js State Vulnerabilities', 'Next.js Props Vulnerabilities', 'Next.js Router Vulnerabilities', 'Next.js Link Vulnerabilities', 'Next.js Image Vulnerabilities', 'Next.js Script Vulnerabilities', 'Next.js Head Vulnerabilities', 'Next.js Document Vulnerabilities', 'Next.js App Vulnerabilities', 'Next.js Pages Vulnerabilities', 'Next.js Components Vulnerabilities', 'Next.js Styles Vulnerabilities', 'Next.js Assets Vulnerabilities', 'Next.js Public Vulnerabilities', 'Next.js Static Vulnerabilities', 'Next.js Server Vulnerabilities', 'Next.js Client Vulnerabilities', 'Next.js Build Vulnerabilities', 'Next.js Deploy Vulnerabilities', 'Next.js Runtime Vulnerabilities', 'Next.js Development Vulnerabilities', 'Next.js Production Vulnerabilities', 'Next.js Environment Vulnerabilities', 'Next.js Configuration Vulnerabilities', 'Next.js Plugin Vulnerabilities', 'Next.js Extension Vulnerabilities', 'Next.js Custom Vulnerabilities', 'Next.js Third-Party Vulnerabilities', 'Next.js Dependency Vulnerabilities', 'Next.js Package Vulnerabilities', 'Next.js Module Vulnerabilities', 'Next.js Import Vulnerabilities', 'Next.js Export Vulnerabilities', 'Next.js Default Vulnerabilities', 'Next.js Named Vulnerabilities', 'Next.js Destructured Vulnerabilities', 'Next.js Spread Vulnerabilities', 'Next.js Rest Vulnerabilities', 'Next.js Optional Vulnerabilities', 'Next.js Required Vulnerabilities', 'Next.js Type Vulnerabilities', 'Next.js Interface Vulnerabilities', 'Next.js Class Vulnerabilities', 'Next.js Function Vulnerabilities', 'Next.js Arrow Vulnerabilities', 'Next.js Async Vulnerabilities', 'Next.js Await Vulnerabilities', 'Next.js Promise Vulnerabilities', 'Next.js Callback Vulnerabilities', 'Next.js Event Vulnerabilities', 'Next.js Handler Vulnerabilities', 'Next.js Listener Vulnerabilities', 'Next.js Observer Vulnerabilities', 'Next.js Subscription Vulnerabilities', 'Next.js Unsubscribe Vulnerabilities', 'Next.js Cleanup Vulnerabilities', 'Next.js Effect Vulnerabilities', 'Next.js Dependency Vulnerabilities', 'Next.js Memo Vulnerabilities', 'Next.js Callback Vulnerabilities', 'Next.js Ref Vulnerabilities', 'Next.js Forward Vulnerabilities', 'Next.js Imperative Vulnerabilities', 'Next.js Declarative Vulnerabilities', 'Next.js Functional Vulnerabilities', 'Next.js Class Vulnerabilities', 'Next.js HOC Vulnerabilities', 'Next.js Render Vulnerabilities', 'Next.js Props Vulnerabilities', 'Next.js Children Vulnerabilities', 'Next.js Key Vulnerabilities', 'Next.js Ref Vulnerabilities', 'Next.js Forward Vulnerabilities', 'Next.js Imperative Vulnerabilities', 'Next.js Declarative Vulnerabilities', 'Next.js Functional Vulnerabilities', 'Next.js Class Vulnerabilities', 'Next.js HOC Vulnerabilities', 'Next.js Render Vulnerabilities', 'Next.js Props Vulnerabilities', 'Next.js Children Vulnerabilities', 'Next.js Key Vulnerabilities', 'Next.js Ref Vulnerabilities', 'Next.js Forward Vulnerabilities', 'Next.js Imperative Vulnerabilities', 'Next.js Declarative Vulnerabilities', 'Next.js Functional Vulnerabilities', 'Next.js Class Vulnerabilities', 'Next.js HOC Vulnerabilities', 'Next.js Render Vulnerabilities', 'Next.js Props Vulnerabilities', 'Next.js Children Vulnerabilities', 'Next.js Key Vulnerabilities', etc.)."]
) -> str:
    """
    Build an LLM prompt to review Next.js server/client code (API, SSR/SSG, components).

    Parameters:
        function_explanation (str): Purpose and security invariants.
        function_body (str): Exact code (API route/page/middleware/component).
        file_path (str): Repo-relative path.
        nextjs_context (str): App router vs pages, SSR/SSG/ISR mode, edge/node runtime, cookies.
        list_of_nextjs_threats (list[str]): SSRF/XSS/CSRF, API auth, header/cookie handling, image/script
            component safety, middleware redirects, environment/config exposure.

    Output:
        str: Prompt instructing LLM to provide issues with references and actionable fixes.
    """
    msg = f"""
NEXT.JS GENERAL THREAT ANALYSIS REQUEST

Function Context:
- Next.js Purpose: {function_explanation}
- File Location: {file_path}
- Next.js Context: {nextjs_context}
- Next.js Threats to Evaluate: {', '.join(list_of_nextjs_threats)}

Next.js Source Code to Analyze:
{function_body}

Please perform a comprehensive Next.js security analysis focusing on the specified threats and provide detailed findings with Next.js-specific attack vector analysis, potential Next.js impact, and remediation guidance specific to Next.js vulnerabilities and secure Next.js development practices.
"""

    return msg


async def nextjs_api_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Next.js API function does, its purpose in API handling, and its role in the Next.js application. Should include API operations, request/response handling, and any API-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the Next.js API function including all statements, variable assignments, control flow, function calls, API operations, and any nested logic. This is the actual Next.js API code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'pages/api/users.js', 'app/api/auth/route.js', 'api/middleware.js'). Used for context and reporting."], 
    api_context: Annotated[str, "Additional Next.js API context including the API type (e.g., REST API, GraphQL, WebSocket), authentication method, and critical API operations this function handles."],
    list_of_api_threats: Annotated[list[str], "A comprehensive list of Next.js API-specific threats and vulnerabilities to check for during analysis. Each item should be a specific API threat type (e.g., 'API Route Vulnerabilities', 'API Authentication Vulnerabilities', 'API Authorization Vulnerabilities', 'API Input Validation Vulnerabilities', 'API Output Encoding Vulnerabilities', 'API Error Handling Vulnerabilities', 'API Rate Limiting Vulnerabilities', 'API CORS Vulnerabilities', 'API CSRF Vulnerabilities', 'API XSS Vulnerabilities', 'API Injection Vulnerabilities', 'API SQL Injection Vulnerabilities', 'API NoSQL Injection Vulnerabilities', 'API Command Injection Vulnerabilities', 'API Path Traversal Vulnerabilities', 'API File Upload Vulnerabilities', 'API Deserialization Vulnerabilities', 'API Serialization Vulnerabilities', 'API JSON Vulnerabilities', 'API XML Vulnerabilities', 'API YAML Vulnerabilities', 'API CSV Vulnerabilities', 'API Excel Vulnerabilities', 'API PDF Vulnerabilities', 'API Image Vulnerabilities', 'API Video Vulnerabilities', 'API Audio Vulnerabilities', 'API Document Vulnerabilities', 'API Archive Vulnerabilities', 'API Compression Vulnerabilities', 'API Encryption Vulnerabilities', 'API Hashing Vulnerabilities', 'API Signing Vulnerabilities', 'API Verification Vulnerabilities', 'API Validation Vulnerabilities', 'API Sanitization Vulnerabilities', 'API Normalization Vulnerabilities', 'API Standardization Vulnerabilities', 'API Format Vulnerabilities', 'API Type Vulnerabilities', 'API Structure Vulnerabilities', 'API Schema Vulnerabilities', 'API Model Vulnerabilities', 'API Relationship Vulnerabilities', 'API Dependency Vulnerabilities', 'API Constraint Vulnerabilities', 'API Rule Vulnerabilities', 'API Policy Vulnerabilities', 'API Governance Vulnerabilities', 'API Compliance Vulnerabilities', 'API Audit Vulnerabilities', 'API Monitoring Vulnerabilities', 'API Logging Vulnerabilities', 'API Reporting Vulnerabilities', 'API Analytics Vulnerabilities', 'API Mining Vulnerabilities', 'API Machine Learning Vulnerabilities', 'API AI Vulnerabilities', 'API Algorithm Vulnerabilities', 'API Model Vulnerabilities', 'API Training Vulnerabilities', 'API Testing Vulnerabilities', 'API Validation Vulnerabilities', 'API Cross-Validation Vulnerabilities', 'API Overfitting Vulnerabilities', 'API Underfitting Vulnerabilities', 'API Bias Vulnerabilities', 'API Fairness Vulnerabilities', 'API Discrimination Vulnerabilities', etc.)."]
) -> str:
    """
    Create a prompt to assess Next.js API routes (pages/app router) for security.

    Parameters:
        function_explanation (str): Handler intent and auth model.
        function_body (str): Exact handler code.
        file_path (str): Repo-relative path.
        api_context (str): Runtime (edge/node), body parsing, CORS/CSRF, cookies/headers.
        list_of_api_threats (list[str]): AuthZ/AuthN, injection, rate limiting, CORS/CSRF, file upload,
            secrets exposure, error responses.

    Output:
        str: Prompt instructing LLM to return issues with references and fixes.
    """
    msg = f"""
NEXT.JS API THREAT ANALYSIS REQUEST

Function Context:
- API Purpose: {function_explanation}
- File Location: {file_path}
- API Context: {api_context}
- API Threats to Evaluate: {', '.join(list_of_api_threats)}

Next.js API Source Code to Analyze:
{function_body}

Please perform a comprehensive Next.js API security analysis focusing on the specified threats and provide detailed findings with API-specific attack vector analysis, potential API impact, and remediation guidance specific to Next.js API vulnerabilities and secure API development practices.
"""

    return msg


async def nextjs_component_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Next.js component function does, its purpose in component rendering, and its role in the Next.js application. Should include component operations, state management, and any component-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the Next.js component function including all statements, variable assignments, control flow, function calls, component operations, and any nested logic. This is the actual Next.js component code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'components/UserProfile.tsx', 'pages/index.js', 'app/layout.tsx'). Used for context and reporting."], 
    component_context: Annotated[str, "Additional Next.js component context including the component type (e.g., page component, layout component, custom component), component props, and critical component operations this function handles."],
    list_of_component_threats: Annotated[list[str], "A comprehensive list of Next.js component-specific threats and vulnerabilities to check for during analysis. Each item should be a specific component threat type (e.g., 'Component XSS Vulnerabilities', 'Component Props Vulnerabilities', 'Component State Vulnerabilities', 'Component Effect Vulnerabilities', 'Component Context Vulnerabilities', 'Component Ref Vulnerabilities', 'Component Key Vulnerabilities', 'Component Children Vulnerabilities', 'Component Render Vulnerabilities', 'Component Mount Vulnerabilities', 'Component Unmount Vulnerabilities', 'Component Update Vulnerabilities', 'Component Re-render Vulnerabilities', 'Component Memo Vulnerabilities', 'Component Callback Vulnerabilities', 'Component Event Vulnerabilities', 'Component Handler Vulnerabilities', 'Component Listener Vulnerabilities', 'Component Observer Vulnerabilities', 'Component Subscription Vulnerabilities', 'Component Unsubscribe Vulnerabilities', 'Component Cleanup Vulnerabilities', 'Component Error Vulnerabilities', 'Component Boundary Vulnerabilities', 'Component Fallback Vulnerabilities', 'Component Suspense Vulnerabilities', 'Component Lazy Vulnerabilities', 'Component Dynamic Vulnerabilities', 'Component Import Vulnerabilities', 'Component Export Vulnerabilities', 'Component Default Vulnerabilities', 'Component Named Vulnerabilities', 'Component Destructured Vulnerabilities', 'Component Spread Vulnerabilities', 'Component Rest Vulnerabilities', 'Component Optional Vulnerabilities', 'Component Required Vulnerabilities', 'Component Type Vulnerabilities', 'Component Interface Vulnerabilities', 'Component Class Vulnerabilities', 'Component Function Vulnerabilities', 'Component Arrow Vulnerabilities', 'Component Async Vulnerabilities', 'Component Await Vulnerabilities', 'Component Promise Vulnerabilities', 'Component Callback Vulnerabilities', 'Component Event Vulnerabilities', 'Component Handler Vulnerabilities', 'Component Listener Vulnerabilities', 'Component Observer Vulnerabilities', 'Component Subscription Vulnerabilities', 'Component Unsubscribe Vulnerabilities', 'Component Cleanup Vulnerabilities', 'Component Effect Vulnerabilities', 'Component Dependency Vulnerabilities', 'Component Memo Vulnerabilities', 'Component Callback Vulnerabilities', 'Component Ref Vulnerabilities', 'Component Forward Vulnerabilities', 'Component Imperative Vulnerabilities', 'Component Declarative Vulnerabilities', 'Component Functional Vulnerabilities', 'Component Class Vulnerabilities', 'Component HOC Vulnerabilities', 'Component Render Vulnerabilities', 'Component Props Vulnerabilities', 'Component Children Vulnerabilities', 'Component Key Vulnerabilities', 'Component Ref Vulnerabilities', 'Component Forward Vulnerabilities', 'Component Imperative Vulnerabilities', 'Component Declarative Vulnerabilities', 'Component Functional Vulnerabilities', 'Component Class Vulnerabilities', 'Component HOC Vulnerabilities', 'Component Render Vulnerabilities', 'Component Props Vulnerabilities', 'Component Children Vulnerabilities', 'Component Key Vulnerabilities', etc.)."]
) -> str:
    """
    Generate a prompt to review Next.js React component safety.

    Parameters:
        function_explanation (str): Rendering behavior and data sources.
        function_body (str): Exact component code.
        file_path (str): Repo-relative path.
        component_context (str): Server vs client component, props/state/effects, sanitation strategy.
        list_of_component_threats (list[str]): XSS from props/state, dangerouslySetInnerHTML,
            unsafe URL construction, event handler injection, SSR/client boundary leaks.

    Output:
        str: Prompt asking for concrete issues and remediations with references.
    """
    msg = f"""
NEXT.JS COMPONENT THREAT ANALYSIS REQUEST

Function Context:
- Component Purpose: {function_explanation}
- File Location: {file_path}
- Component Context: {component_context}
- Component Threats to Evaluate: {', '.join(list_of_component_threats)}

Next.js Component Source Code to Analyze:
{function_body}

Please perform a comprehensive Next.js component security analysis focusing on the specified threats and provide detailed findings with component-specific attack vector analysis, potential component impact, and remediation guidance specific to Next.js component vulnerabilities and secure component development practices.
"""

    return msg
