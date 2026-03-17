from typing import Annotated


async def fastapi_general_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the FastAPI function does, its purpose in the FastAPI application, and its role in the application. Should include FastAPI-specific operations, dependency injection, and any FastAPI-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the FastAPI function including all statements, variable assignments, control flow, function calls, FastAPI operations, and any nested logic. This is the actual FastAPI code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'main.py', 'routers/users.py', 'dependencies/auth.py'). Used for context and reporting."], 
    fastapi_context: Annotated[str, "Additional FastAPI context including the component type (e.g., route handler, dependency, middleware), FastAPI version, and critical FastAPI operations this function handles."],
    list_of_fastapi_threats: Annotated[list[str], "A comprehensive list of FastAPI-specific threats and vulnerabilities to check for during analysis. Each item should be a specific FastAPI threat type (e.g., 'FastAPI Route Vulnerabilities', 'FastAPI Dependency Vulnerabilities', 'FastAPI Middleware Vulnerabilities', 'FastAPI Request Vulnerabilities', 'FastAPI Response Vulnerabilities', 'FastAPI Body Vulnerabilities', 'FastAPI Query Vulnerabilities', 'FastAPI Path Vulnerabilities', 'FastAPI Header Vulnerabilities', 'FastAPI Cookie Vulnerabilities', 'FastAPI Session Vulnerabilities', 'FastAPI Authentication Vulnerabilities', 'FastAPI Authorization Vulnerabilities', 'FastAPI Input Validation Vulnerabilities', 'FastAPI Output Encoding Vulnerabilities', 'FastAPI Error Handling Vulnerabilities', 'FastAPI Logging Vulnerabilities', 'FastAPI Monitoring Vulnerabilities', 'FastAPI Auditing Vulnerabilities', 'FastAPI Reporting Vulnerabilities', 'FastAPI Analytics Vulnerabilities', 'FastAPI Mining Vulnerabilities', 'FastAPI Machine Learning Vulnerabilities', 'FastAPI AI Vulnerabilities', 'FastAPI Algorithm Vulnerabilities', 'FastAPI Model Vulnerabilities', 'FastAPI Training Vulnerabilities', 'FastAPI Testing Vulnerabilities', 'FastAPI Validation Vulnerabilities', 'FastAPI Cross-Validation Vulnerabilities', 'FastAPI Overfitting Vulnerabilities', 'FastAPI Underfitting Vulnerabilities', 'FastAPI Bias Vulnerabilities', 'FastAPI Fairness Vulnerabilities', 'FastAPI Discrimination Vulnerabilities', etc.)."]
) -> str:
    """
    Generate an LLM prompt to review FastAPI handlers/dependencies/middleware.

    Parameters:
        function_explanation (str): Purpose, auth model, and invariants.
        function_body (str): Exact code (route/dependency/middleware).
        file_path (str): Repo-relative path.
        fastapi_context (str): Pydantic models/validators, dependencies, CORS, session/cookies.
        list_of_fastapi_threats (list[str]): AuthZ/AuthN, injection, CSRF on cookies, CORS, rate limits,
            request body/params validation, error handling, response serialization.

    Output:
        str: Prompt instructing the LLM to return issues with references and actionable fixes.
    """
    msg = f"""
FASTAPI GENERAL THREAT ANALYSIS REQUEST

Function Context:
- FastAPI Purpose: {function_explanation}
- File Location: {file_path}
- FastAPI Context: {fastapi_context}
- FastAPI Threats to Evaluate: {', '.join(list_of_fastapi_threats)}

FastAPI Source Code to Analyze:
{function_body}

Please perform a comprehensive FastAPI security analysis focusing on the specified threats and provide detailed findings with FastAPI-specific attack vector analysis, potential FastAPI impact, and remediation guidance specific to FastAPI vulnerabilities and secure FastAPI development practices.
"""

    return msg
