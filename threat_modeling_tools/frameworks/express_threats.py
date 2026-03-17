from typing import Annotated


async def express_general_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Express.js function does, its purpose in the Express application, and its role in the application. Should include Express-specific operations, middleware usage, and any Express-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the Express.js function including all statements, variable assignments, control flow, function calls, Express operations, and any nested logic. This is the actual Express.js code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'routes/users.js', 'middleware/auth.js', 'app.js'). Used for context and reporting."], 
    express_context: Annotated[str, "Additional Express.js context including the component type (e.g., route handler, middleware, app configuration), Express version, and critical Express operations this function handles."],
    list_of_express_threats: Annotated[list[str], "A comprehensive list of Express.js-specific threats and vulnerabilities to check for during analysis. Each item should be a specific Express threat type (e.g., 'Express Route Vulnerabilities', 'Express Middleware Vulnerabilities', 'Express Request Vulnerabilities', 'Express Response Vulnerabilities', 'Express Body Parser Vulnerabilities', 'Express JSON Vulnerabilities', 'Express URL Encoded Vulnerabilities', 'Express Multipart Vulnerabilities', 'Express Cookie Vulnerabilities', 'Express Session Vulnerabilities', 'Express CORS Vulnerabilities', 'Express Helmet Vulnerabilities', 'Express Rate Limiting Vulnerabilities', 'Express Authentication Vulnerabilities', 'Express Authorization Vulnerabilities', 'Express Input Validation Vulnerabilities', 'Express Output Encoding Vulnerabilities', 'Express Error Handling Vulnerabilities', 'Express Logging Vulnerabilities', 'Express Monitoring Vulnerabilities', 'Express Auditing Vulnerabilities', 'Express Reporting Vulnerabilities', 'Express Analytics Vulnerabilities', 'Express Mining Vulnerabilities', 'Express Machine Learning Vulnerabilities', 'Express AI Vulnerabilities', 'Express Algorithm Vulnerabilities', 'Express Model Vulnerabilities', 'Express Training Vulnerabilities', 'Express Testing Vulnerabilities', 'Express Validation Vulnerabilities', 'Express Cross-Validation Vulnerabilities', 'Express Overfitting Vulnerabilities', 'Express Underfitting Vulnerabilities', 'Express Bias Vulnerabilities', 'Express Fairness Vulnerabilities', 'Express Discrimination Vulnerabilities', etc.)."]
) -> str:
    """
    Create an LLM-ready prompt to review Express route/middleware/app config.

    Parameters:
        function_explanation (str): Purpose and security guarantees.
        function_body (str): Exact Express code (handler/middleware/app setup).
        file_path (str): Repo-relative path.
        express_context (str): Helmet/CORS/body parsers, sessions/cookies, auth strategy.
        list_of_express_threats (list[str]): Input validation, injection, CSRF, CORS, cookie flags,
            error handling, logging of secrets, rate limiting, file upload safety.

    Output:
        str: Prompt instructing LLM to provide issues with references and remediations.
    """
    msg = f"""
EXPRESS.JS GENERAL THREAT ANALYSIS REQUEST

Function Context:
- Express Purpose: {function_explanation}
- File Location: {file_path}
- Express Context: {express_context}
- Express Threats to Evaluate: {', '.join(list_of_express_threats)}

Express.js Source Code to Analyze:
{function_body}

Please perform a comprehensive Express.js security analysis focusing on the specified threats and provide detailed findings with Express-specific attack vector analysis, potential Express impact, and remediation guidance specific to Express.js vulnerabilities and secure Express.js development practices.
"""

    return msg
