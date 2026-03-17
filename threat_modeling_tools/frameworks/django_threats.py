from typing import Annotated


async def django_general_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Django function does, its purpose in the Django application, and its role in the application. Should include Django-specific operations, ORM usage, and any Django-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the Django function including all statements, variable assignments, control flow, function calls, Django operations, and any nested logic. This is the actual Django code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'views.py', 'models.py', 'forms.py', 'urls.py'). Used for context and reporting."], 
    django_context: Annotated[str, "Additional Django context including the component type (e.g., view, model, form, middleware), Django version, and critical Django operations this function handles."],
    list_of_django_threats: Annotated[list[str], "A comprehensive list of Django-specific threats and vulnerabilities to check for during analysis. Each item should be a specific Django threat type (e.g., 'Django ORM Vulnerabilities', 'Django View Vulnerabilities', 'Django Model Vulnerabilities', 'Django Form Vulnerabilities', 'Django URL Vulnerabilities', 'Django Middleware Vulnerabilities', 'Django Template Vulnerabilities', 'Django Static Vulnerabilities', 'Django Media Vulnerabilities', 'Django Settings Vulnerabilities', 'Django Database Vulnerabilities', 'Django Migration Vulnerabilities', 'Django Admin Vulnerabilities', 'Django Authentication Vulnerabilities', 'Django Authorization Vulnerabilities', 'Django Session Vulnerabilities', 'Django CSRF Vulnerabilities', 'Django XSS Vulnerabilities', 'Django SQL Injection Vulnerabilities', 'Django File Upload Vulnerabilities', 'Django Path Traversal Vulnerabilities', 'Django Deserialization Vulnerabilities', 'Django Serialization Vulnerabilities', 'Django JSON Vulnerabilities', 'Django XML Vulnerabilities', 'Django YAML Vulnerabilities', 'Django CSV Vulnerabilities', 'Django Excel Vulnerabilities', 'Django PDF Vulnerabilities', 'Django Image Vulnerabilities', 'Django Video Vulnerabilities', 'Django Audio Vulnerabilities', 'Django Document Vulnerabilities', 'Django Archive Vulnerabilities', 'Django Compression Vulnerabilities', 'Django Encryption Vulnerabilities', 'Django Hashing Vulnerabilities', 'Django Signing Vulnerabilities', 'Django Verification Vulnerabilities', 'Django Validation Vulnerabilities', 'Django Sanitization Vulnerabilities', 'Django Normalization Vulnerabilities', 'Django Standardization Vulnerabilities', 'Django Format Vulnerabilities', 'Django Type Vulnerabilities', 'Django Structure Vulnerabilities', 'Django Schema Vulnerabilities', 'Django Model Vulnerabilities', 'Django Relationship Vulnerabilities', 'Django Dependency Vulnerabilities', 'Django Constraint Vulnerabilities', 'Django Rule Vulnerabilities', 'Django Policy Vulnerabilities', 'Django Governance Vulnerabilities', 'Django Compliance Vulnerabilities', 'Django Audit Vulnerabilities', 'Django Monitoring Vulnerabilities', 'Django Logging Vulnerabilities', 'Django Reporting Vulnerabilities', 'Django Analytics Vulnerabilities', 'Django Mining Vulnerabilities', 'Django Machine Learning Vulnerabilities', 'Django AI Vulnerabilities', 'Django Algorithm Vulnerabilities', 'Django Model Vulnerabilities', 'Django Training Vulnerabilities', 'Django Testing Vulnerabilities', 'Django Validation Vulnerabilities', 'Django Cross-Validation Vulnerabilities', 'Django Overfitting Vulnerabilities', 'Django Underfitting Vulnerabilities', 'Django Bias Vulnerabilities', 'Django Fairness Vulnerabilities', 'Django Discrimination Vulnerabilities', etc.)."]
) -> str:
    """
    Build an LLM-ready prompt to review Django code for framework-specific risks.

    Parameters:
        function_explanation (str): Purpose, component type, and security invariants.
        function_body (str): Exact Django code (view/model/form/middleware/etc.).
        file_path (str): Repo-relative path.
        django_context (str): Version, middleware, auth/session/CSRF setup, ORM usage, template engine.
        list_of_django_threats (list[str]): Concrete checks (authz/authn, CSRF, XSS, SQLi, file upload,
            path traversal, template autoescape, session/cookie flags, settings misconfig).

    Output:
        str: Prompt instructing LLM to return issues with references and actionable remediations.
    """
    msg = f"""
DJANGO GENERAL THREAT ANALYSIS REQUEST

Function Context:
- Django Purpose: {function_explanation}
- File Location: {file_path}
- Django Context: {django_context}
- Django Threats to Evaluate: {', '.join(list_of_django_threats)}

Django Source Code to Analyze:
{function_body}

Please perform a comprehensive Django security analysis focusing on the specified threats and provide detailed findings with Django-specific attack vector analysis, potential Django impact, and remediation guidance specific to Django vulnerabilities and secure Django development practices.
"""

    return msg


async def django_orm_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the Django ORM function does, its purpose in database operations, and its role in the Django application. Should include ORM operations, query building, and any ORM-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the Django ORM function including all statements, variable assignments, control flow, function calls, ORM operations, and any nested logic. This is the actual Django ORM code that will be analyzed for vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'models.py', 'views.py', 'managers.py'). Used for context and reporting."], 
    orm_context: Annotated[str, "Additional Django ORM context including the ORM operation type (e.g., query, create, update, delete), database backend, and critical ORM operations this function handles."],
    list_of_orm_threats: Annotated[list[str], "A comprehensive list of Django ORM-specific threats and vulnerabilities to check for during analysis. Each item should be a specific ORM threat type (e.g., 'ORM SQL Injection Vulnerabilities', 'ORM Query Vulnerabilities', 'ORM Filter Vulnerabilities', 'ORM Exclude Vulnerabilities', 'ORM Order By Vulnerabilities', 'ORM Group By Vulnerabilities', 'ORM Having Vulnerabilities', 'ORM Join Vulnerabilities', 'ORM Select Related Vulnerabilities', 'ORM Prefetch Related Vulnerabilities', 'ORM Raw SQL Vulnerabilities', 'ORM Extra Vulnerabilities', 'ORM Values Vulnerabilities', 'ORM Values List Vulnerabilities', 'ORM Distinct Vulnerabilities', 'ORM Union Vulnerabilities', 'ORM Intersection Vulnerabilities', 'ORM Difference Vulnerabilities', 'ORM Exists Vulnerabilities', 'ORM Count Vulnerabilities', 'ORM Sum Vulnerabilities', 'ORM Avg Vulnerabilities', 'ORM Min Vulnerabilities', 'ORM Max Vulnerabilities', 'ORM Stddev Vulnerabilities', 'ORM Variance Vulnerabilities', 'ORM Annotate Vulnerabilities', 'ORM Aggregate Vulnerabilities', 'ORM F Vulnerabilities', 'ORM Q Vulnerabilities', 'ORM Case Vulnerabilities', 'ORM When Vulnerabilities', 'ORM Then Vulnerabilities', 'ORM Else Vulnerabilities', 'ORM Subquery Vulnerabilities', 'ORM Outer Ref Vulnerabilities', 'ORM Exists Vulnerabilities', 'ORM In Vulnerabilities', 'ORM Lookup Vulnerabilities', 'ORM Transform Vulnerabilities', 'ORM Expression Vulnerabilities', 'ORM Func Vulnerabilities', 'ORM Value Vulnerabilities', 'ORM Ref Vulnerabilities', 'ORM Col Vulnerabilities', 'ORM Outer Ref Vulnerabilities', 'ORM Subquery Vulnerabilities', 'ORM Exists Vulnerabilities', 'ORM In Vulnerabilities', 'ORM Lookup Vulnerabilities', 'ORM Transform Vulnerabilities', 'ORM Expression Vulnerabilities', 'ORM Func Vulnerabilities', 'ORM Value Vulnerabilities', 'ORM Ref Vulnerabilities', 'ORM Col Vulnerabilities', 'ORM Outer Ref Vulnerabilities', 'ORM Subquery Vulnerabilities', 'ORM Exists Vulnerabilities', 'ORM In Vulnerabilities', 'ORM Lookup Vulnerabilities', 'ORM Transform Vulnerabilities', 'ORM Expression Vulnerabilities', 'ORM Func Vulnerabilities', 'ORM Value Vulnerabilities', 'ORM Ref Vulnerabilities', 'ORM Col Vulnerabilities', etc.)."]
) -> str:
    """
    Create a prompt to assess Django ORM usage and query safety.

    Parameters:
        function_explanation (str): Intended query behavior and constraints.
        function_body (str): Exact code building/executing ORM queries.
        file_path (str): Repo-relative path.
        orm_context (str): Backend, raw SQL usage, transaction/atomic context, pagination patterns.
        list_of_orm_threats (list[str]): SQLi via raw() or unsafe filters, N+1, unbounded queries,
            mass assignment, injection in order_by, data leakage via select_related/prefetch.

    Output:
        str: Prompt instructing the LLM to provide issues with references and fixes.
    """
    msg = f"""
DJANGO ORM THREAT ANALYSIS REQUEST

Function Context:
- ORM Purpose: {function_explanation}
- File Location: {file_path}
- ORM Context: {orm_context}
- ORM Threats to Evaluate: {', '.join(list_of_orm_threats)}

Django ORM Source Code to Analyze:
{function_body}

Please perform a comprehensive Django ORM security analysis focusing on the specified threats and provide detailed findings with ORM-specific attack vector analysis, potential ORM impact, and remediation guidance specific to Django ORM vulnerabilities and secure ORM development practices.
"""

    return msg
