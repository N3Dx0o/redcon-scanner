from db import get_orm, Project, Finding, Confirmation, AIModel
from db.models import SeverityLevel, FindingStatus, ProjectStatus
from typing import Annotated, List, Dict, Any, Optional
from datetime import datetime



async def report_confirmation(
    finding_id: Annotated[int, "The ID of the finding to be validated. Should be a valid finding ID that exists in the database."],
    model_id: Annotated[int, "The ID of the model (Settings) used to validate the finding. Should be a valid model ID that exists in the database."],
    justification: Annotated[str, "A detailed, evidence-based justification for the validation decision. Should reference specific code, explain reasoning, and cite security best practices."],
    evidence_analysis: Annotated[str, "Detailed analysis of the evidence supporting or refuting the vulnerability. Include specific code examples, file paths, and technical details that were examined."],
    exploit_feasibility: Annotated[str, "Assessment of how realistically exploitable this vulnerability is. Consider attack vectors, prerequisites, complexity, and potential impact if successfully exploited."],
    is_remote_attack: Annotated[bool, "Whether the vulnerability is a remote attack or not."],
    false_positive: Annotated[str, "Validation decision - set to 'true' or 'false_positive' if the finding is NOT a genuine security vulnerability, or 'false' or 'confirmed' if the vulnerability IS real and exploitable."]
):
    """
    Records the validation decision for a security finding after thorough analysis.

    This function is the final step in the vulnerability validation process. Use it to officially 
    confirm whether a reported security finding is a genuine vulnerability or a false positive.
    The validation should be based on thorough code analysis, exploit feasibility assessment, 
    and evidence examination. response should be formated in markdown.

    WHEN TO USE:
    - After completing thorough analysis of the reported vulnerability
    - When you have sufficient evidence to make a definitive validation decision
    - After examining the actual code, attack vectors, and potential mitigations

    VALIDATION PROCESS:
    1. Analyze the code context and implementation details
    2. Assess realistic exploitability and attack scenarios  
    3. Check for existing security controls or mitigations
    4. Make a final determination: CONFIRMED or FALSE_POSITIVE

    Args:
        finding_id: The unique database ID of the security finding being validated
        model_id: The unique database ID of the AI model performing the validation  
        justification: Comprehensive explanation of your validation decision with technical details
        evidence_analysis: Specific evidence from code analysis (file paths, code snippets, technical details)
        exploit_feasibility: Realistic assessment of exploitability (attack vectors, complexity, prerequisites)
        is_remotet_attack: Whether the vulnerability is a remote attack or not.
        false_positive: Your final decision - 'true'/'false_positive' for false positives, 'false'/'confirmed' for real vulnerabilities

    EXAMPLE USAGE:
        # For a FALSE POSITIVE (not a real vulnerability):
        await report_confirmation(
            finding_id=123,
            model_id=1,
            justification="The reported SQL injection is not exploitable because the application uses parameterized queries throughout the codebase.",
            evidence_analysis="Examined database.py lines 45-67. All SQL queries use prepared statements with proper parameter binding. No string concatenation found.",
            exploit_feasibility="Not exploitable - input is properly sanitized before database interaction. No direct SQL construction occurs.",
            is_remote_attack=False,
            false_positive="true"
        )

        # For a CONFIRMED vulnerability:
        await report_confirmation(
            finding_id=124, 
            model_id=1,
            justification="Confirmed XSS vulnerability due to unescaped user input being directly rendered in HTML output.",
            evidence_analysis="File user_profile.py line 89 directly inserts user.bio into HTML template without escaping. Tested with <script> tags.",
            exploit_feasibility="Highly exploitable - any authenticated user can inject JavaScript that executes in other users' browsers.",
            is_remote_attack=True,
            false_positive="false"
        )
    """
    try:
        # Use the ORM to add a confirmation record for the finding
        orm = get_orm()
        with orm.get_session() as session:
            # Fetch the finding by ID
            finding = session.query(Finding).filter(Finding.id == finding_id).first()
            if not finding:
                raise ValueError(f"Finding with ID {finding_id} does not exist.")

            # Fetch the model by ID
            model = session.query(AIModel).filter(AIModel.id == model_id).first()
            if not model:
                raise ValueError(f"Model with ID {model_id} does not exist.")

            false_positive_str = false_positive.lower()
            if false_positive_str == "true" or false_positive_str == "false_positive":
                false_positive = True
            elif false_positive_str == "false" or false_positive_str == "confirmed":
                false_positive = False

            final_justification = f"""
            Justification: {justification}
            Evidence Analysis: {evidence_analysis}
            Exploit Feasibility: {exploit_feasibility}
            is Remote Attack: {is_remote_attack}
            """
            # Use the imported Confirmation object directly
            confirmation = Confirmation(
                finding_id=finding_id,
                model_id=model_id,
                justification=justification,
                evidence_analysis=evidence_analysis,
                exploit_feasibility=exploit_feasibility,
                is_remote_attack=is_remote_attack,
                false_positive=false_positive
            )
            session.add(confirmation)
            session.commit()
    except Exception as e:
        print(f"Error reporting confirmation: {e}")


async def get_findings_by_file_path(
    file_path: Annotated[str, "The full relative path of the file containing the finding (e.g., 'app/controllers/user_controller.py', 'src/main/java/com/example/UserService.java')"],
) -> list[str]:
    """
    Get findings by file path and return a list of strings with title and description.
    Each string is of the form 'finding title: finding description'.
    """
    orm = get_orm()
    findings_list = []
    with orm.get_session() as session:
        findings = orm.filter_by(session, Finding, file_path=file_path)
        for finding in findings:
            findings_list.append(f"{finding.title}: {finding.description}")
    return findings_list

async def add_finding_to_database(
    title: Annotated[str, "The title of the finding - should be concise and descriptive of the security issue (e.g., 'SQL Injection in user authentication', 'XSS vulnerability in comment system')"], 
    description: Annotated[str, "Detailed description of the finding including the vulnerability type, affected code, potential impact, and how it could be exploited. Should provide enough context for developers to understand the issue."], 
    file_path: Annotated[str, "The full relative path of the file containing the finding (e.g., 'app/controllers/user_controller.py', 'src/main/java/com/example/UserService.java')"], 
    severity: Annotated[int, "The severity level of the finding on a scale of 1-10 where: 1-2=Low (minimal impact), 3-4=Medium (moderate impact), 5-6=High (significant impact), 7-8=Critical (severe impact), 9-10=Critical (catastrophic impact)"],
    recommendation: Annotated[str, "Specific actionable recommendations for fixing the vulnerability including code examples, best practices, and secure alternatives. Should provide clear remediation steps."],
    project_id: Annotated[int, "The unique identifier of the project this finding belongs to. Must be a valid project ID that exists in the database."],
) -> str:
    """
    Report a security finding to the database.
    
    This function creates a new finding record in the database with the provided details.
    It validates the severity level and ensures the project exists before saving.
    
    Args:
        title: Concise title describing the security issue
        description: Detailed explanation of the vulnerability 
        file_path: Full path to the affected file
        severity: Severity rating from 1 (low) to 10 (critical)
        recommendation: Actionable remediation guidance
        project_id: ID of the associated project
        
    Returns:
        str: Success message with finding ID or error message
        
    Example:
        result = await add_finding_to_database(
            title="SQL Injection in login function",
            description="The login function uses string concatenation to build SQL queries, making it vulnerable to SQL injection attacks...",
            file_path="app/auth/login.py", 
            severity=8,
            recommendation="Use parameterized queries or prepared statements instead of string concatenation...",
            project_id=123
        )
    """
    try:
        orm = get_orm()
        
        # Map severity integer to enum
        severity_mapping = {
            1: "info", 2: "low", 
            3: "low", 4: "medium",
            5: "medium", 6: "high", 
            7: "high", 8: "critical",
            9: "critical", 10: "critical"
        }
        
        severity_enum = severity_mapping.get(severity, "medium")
        
        with orm.get_session() as session:
            # Verify project exists
            project = orm.get_by_id(session, Project, project_id)
            if not project:
                return f"Error: Project with ID {project_id} not found"

            # ── Deduplication: reject if same file already has a very similar title ──
            existing = session.query(Finding).filter(
                Finding.project_id == project_id
            ).all()
            title_lower = title.lower().strip()
            # Normalize file path for comparison (strip leading path separators)
            file_basename = file_path.replace('\\', '/').split('/')[-1].lower()
            for ef in existing:
                ef_title_lower = ef.title.lower().strip()
                ef_basename = ef.file_path.replace('\\', '/').split('/')[-1].lower()
                # Duplicate if: titles share >60% of words AND same base filename
                title_words = set(title_lower.split())
                ef_words = set(ef_title_lower.split())
                if title_words and ef_words:
                    overlap = len(title_words & ef_words) / max(len(title_words), len(ef_words))
                    if overlap > 0.6 and file_basename == ef_basename:
                        msg = f"[SKIPPED] Duplicate finding detected — '{title}' is too similar to existing finding '{ef.title}' (ID {ef.id}) in {ef.file_path}. Skipping."
                        print(msg)
                        return msg

            # Create the finding
            finding_data = {
                'title': title,
                'description': description,
                'file_path': file_path,
                'severity': severity_enum,
                'recommendation': recommendation,
                'project_id': project_id,
                'status': 'open'
            }

            finding = orm.create(session, Finding, **finding_data)

            msg = f"[SUCCESS] Successfully created finding '{title}' with ID {finding.id} for project '{project.name}'"
            print(msg)
            return msg
            
    except Exception as e:
        msg = f"Error reporting finding: {str(e)}"
        print(f"[ERROR] {msg}")
        return msg

# ============================================================================
# PROJECT MANAGEMENT FUNCTIONS
# ============================================================================

async def create_project(
    name: Annotated[str, "The name of the project (e.g., 'Web Application Security Scan', 'Mobile App Analysis')"],
    description: Annotated[str, "Detailed description of the project including its purpose, technology stack, and scope"],
    zip_file_path: Annotated[str, "Path to the uploaded zip file containing the project code"],
    base_path: Annotated[str, "Base path within the zip file where the main code is located"],
) -> str:
    """
    Create a new project in the database.
    
    Args:
        name: Project name
        description: Project description
        zip_file_path: Path to the project zip file
        base_path: Base path within the zip file
        
    Returns:
        str: Success message with project ID or error message
    """
    try:
        orm = get_orm()
        with orm.get_session() as session:
            project_data = {
                'name': name,
                'description': description,
                'zip_file_path': zip_file_path,
                'base_path': base_path,
                'status': ProjectStatus.ACTIVE
            }
            
            project = orm.create(session, Project, **project_data)
            msg = f"[SUCCESS] Successfully created project '{name}' with ID {project.id}"
            print(msg)
            return msg
            
    except Exception as e:
        msg = f"Error creating project: {str(e)}"
        print(f"[ERROR] {msg}")
        return msg

async def get_project(
    project_id: Annotated[int, "The unique identifier of the project to retrieve"],
    include_findings: Annotated[bool, "Whether to include findings in the response"] = False
) -> Dict[str, Any]:
    """
    Get project details by ID.
    
    Args:
        project_id: Project ID
        include_findings: Whether to include findings data
        
    Returns:
        Dict containing project information
    """
    try:
        orm = get_orm()
        with orm.get_session() as session:
            relations = ['findings'] if include_findings else []
            project = orm.get_by_id_with_relations(session, Project, project_id, relations)
            
            if not project:
                return {"error": f"Project with ID {project_id} not found"}
            
            result = {
                "id": project.id,
                "name": project.name,
                "description": project.description,
                "zip_file_path": project.zip_file_path,
                "base_path": project.base_path,
                "status": project.status.value,
                "created_at": project.created_at.isoformat(),
                "updated_at": project.updated_at.isoformat(),
                "last_scanned_at": project.last_scanned_at.isoformat() if project.last_scanned_at else None,
                "last_modified_at": project.last_modified_at.isoformat() if project.last_modified_at else None
            }
            
            if include_findings:
                result["findings"] = [
                    {
                        "id": finding.id,
                        "title": finding.title,
                        "severity": finding.severity.value,
                        "status": finding.status.value,
                        "file_path": finding.file_path
                    }
                    for finding in project.findings
                ]
            
            return result
            
    except Exception as e:
        return {"error": f"Error retrieving project: {str(e)}"}

async def list_projects(
    status: Annotated[Optional[str], "Filter by project status (active, inactive, archived, scanning)"] = None,
    limit: Annotated[int, "Maximum number of projects to return"] = 50
) -> List[Dict[str, Any]]:
    """
    List all projects with optional filtering.
    
    Args:
        status: Optional status filter
        limit: Maximum number of projects to return
        
    Returns:
        List of project dictionaries
    """
    try:
        orm = get_orm()
        with orm.get_session() as session:
            if status:
                projects = orm.filter_by(session, Project, status=status)
            else:
                projects = orm.get_all(session, Project, limit=limit)
            
            return [
                {
                    "id": project.id,
                    "name": project.name,
                    "description": project.description,
                    "status": project.status.value,
                    "created_at": project.created_at.isoformat(),
                    "last_scanned_at": project.last_scanned_at.isoformat() if project.last_scanned_at else None
                }
                for project in projects
            ]
            
    except Exception as e:
        return [{"error": f"Error listing projects: {str(e)}"}]

async def update_project_status(
    project_id: Annotated[int, "The unique identifier of the project to update"],
    status: Annotated[str, "New status for the project (active, inactive, archived, scanning)"]
) -> str:
    """
    Update project status.
    
    Args:
        project_id: Project ID
        status: New status
        
    Returns:
        str: Success or error message
    """
    try:
        orm = get_orm()
        with orm.get_session() as session:
            project = orm.get_by_id(session, Project, project_id)
            if not project:
                return f"Error: Project with ID {project_id} not found"
            
            # Validate status
            valid_statuses = [s.value for s in ProjectStatus]
            if status not in valid_statuses:
                return f"Error: Invalid status '{status}'. Valid statuses: {valid_statuses}"
            
            orm.update(session, project, status=ProjectStatus(status))
            return f"[SUCCESS] Successfully updated project '{project.name}' status to '{status}'"
            
    except Exception as e:
        return f"Error updating project status: {str(e)}"

# ============================================================================
# FINDING MANAGEMENT FUNCTIONS
# ============================================================================

async def search_findings(
    query: Annotated[str, "Search term to look for in finding titles and descriptions"],
    project_id: Annotated[Optional[int], "Optional project ID to limit search scope"] = None,
    severity: Annotated[Optional[str], "Optional severity filter (critical, high, medium, low, info)"] = None,
    status: Annotated[Optional[str], "Optional status filter (open, in_progress, resolved, false_positive, ignored)"] = None
) -> List[Dict[str, Any]]:
    """
    Search findings by query with optional filters.
    
    Args:
        query: Search term
        project_id: Optional project filter
        severity: Optional severity filter
        status: Optional status filter
        
    Returns:
        List of matching findings
    """
    try:
        orm = get_orm()
        with orm.get_session() as session:
            findings = orm.search_findings(session, query, project_id)
            
            # Apply additional filters
            if severity:
                findings = [f for f in findings if f.severity.value == severity]
            if status:
                findings = [f for f in findings if f.status.value == status]
            
            return [
                {
                    "id": finding.id,
                    "title": finding.title,
                    "description": finding.description,
                    "file_path": finding.file_path,
                    "severity": finding.severity.value,
                    "status": finding.status.value,
                    "project_id": finding.project_id,
                    "created_at": finding.created_at.isoformat(),
                    "recommendation": finding.recommendation
                }
                for finding in findings
            ]
            
    except Exception as e:
        return [{"error": f"Error searching findings: {str(e)}"}]

async def get_findings_by_severity(
    severity: Annotated[str, "Severity level to filter by (critical, high, medium, low, info)"],
    project_id: Annotated[Optional[int], "Optional project ID to limit scope"] = None
) -> List[Dict[str, Any]]:
    """
    Get findings filtered by severity level.
    
    Args:
        severity: Severity level to filter by
        project_id: Optional project filter
        
    Returns:
        List of findings with specified severity
    """
    try:
        orm = get_orm()
        with orm.get_session() as session:
            if project_id:
                findings = orm.get_project_findings(session, project_id, severity)
            else:
                findings = orm.filter_by(session, Finding, severity=severity)
            
            return [
                {
                    "id": finding.id,
                    "title": finding.title,
                    "description": finding.description,
                    "file_path": finding.file_path,
                    "severity": finding.severity.value,
                    "status": finding.status.value,
                    "project_id": finding.project_id,
                    "created_at": finding.created_at.isoformat()
                }
                for finding in findings
            ]
            
    except Exception as e:
        return [{"error": f"Error getting findings by severity: {str(e)}"}]

async def update_finding_status(
    finding_id: Annotated[int, "The unique identifier of the finding to update"],
    status: Annotated[str, "New status for the finding (open, in_progress, resolved, false_positive, ignored)"]
) -> str:
    """
    Update finding status.
    
    Args:
        finding_id: Finding ID
        status: New status
        
    Returns:
        str: Success or error message
    """
    try:
        orm = get_orm()
        with orm.get_session() as session:
            finding = orm.get_by_id(session, Finding, finding_id)
            if not finding:
                return f"Error: Finding with ID {finding_id} not found"
            
            # Validate status
            valid_statuses = [s.value for s in FindingStatus]
            if status not in valid_statuses:
                return f"Error: Invalid status '{status}'. Valid statuses: {valid_statuses}"
            
            update_data = {"status": FindingStatus(status)}
            if status == "resolved":
                update_data["resolved_at"] = datetime.utcnow()
            
            orm.update(session, finding, **update_data)
            return f"[SUCCESS] Successfully updated finding '{finding.title}' status to '{status}'"
            
    except Exception as e:
        return f"Error updating finding status: {str(e)}"

async def get_finding_details(
    finding_id: Annotated[int, "The unique identifier of the finding to retrieve"]
) -> Dict[str, Any]:
    """
    Get detailed information about a specific finding.
    
    Args:
        finding_id: Finding ID
        
    Returns:
        Dict containing detailed finding information
    """
    try:
        orm = get_orm()
        with orm.get_session() as session:
            finding = orm.get_by_id_with_relations(session, Finding, finding_id, ['project', 'confirmations'])
            
            if not finding:
                return {"error": f"Finding with ID {finding_id} not found"}
            
            return {
                "id": finding.id,
                "title": finding.title,
                "description": finding.description,
                "file_path": finding.file_path,
                "severity": finding.severity.value,
                "status": finding.status.value,
                "recommendation": finding.recommendation,
                "impacted_files": finding.impacted_files,
                "project_id": finding.project_id,
                "project_name": finding.project.name if finding.project else None,
                "created_at": finding.created_at.isoformat(),
                "updated_at": finding.updated_at.isoformat(),
                "resolved_at": finding.resolved_at.isoformat() if finding.resolved_at else None,
                "confirmations": [
                    {
                        "id": conf.id,
                        "justification": conf.justification,
                        "false_positive": conf.false_positive,
                        "model_id": conf.model_id,
                        "created_at": conf.created_at.isoformat()
                    }
                    for conf in finding.confirmations
                ]
            }
            
    except Exception as e:
        return {"error": f"Error retrieving finding details: {str(e)}"}

# ============================================================================
# AGENT MANAGEMENT FUNCTIONS
# ============================================================================

async def create_agent(
    name: Annotated[str, "Name of the agent (e.g., 'Security Scanner', 'Code Reviewer')"],
    description: Annotated[str, "Description of what the agent does and its capabilities"],
    system_prompt: Annotated[str, "System prompt that defines the agent's behavior and role"],
    task_prompt: Annotated[str, "Task-specific prompt that guides the agent's analysis approach"]
) -> str:
    """
    Create a new agent in the database.
    
    Args:
        name: Agent name
        description: Agent description
        system_prompt: System prompt for the agent
        task_prompt: Task-specific prompt
        
    Returns:
        str: Success message with agent ID or error message
    """
    try:
        orm = get_orm()
        with orm.get_session() as session:
            agent_data = {
                'name': name,
                'description': description,
                'system_prompt': system_prompt,
                'task_prompt': task_prompt,
                'is_active': True
            }
            
            agent = orm.create(session, Agent, **agent_data)
            msg = f"[SUCCESS] Successfully created agent '{name}' with ID {agent.id}"
            print(msg)
            return msg
            
    except Exception as e:
        msg = f"Error creating agent: {str(e)}"
        print(f"[ERROR] {msg}")
        return msg

async def get_agent(
    agent_id: Annotated[int, "The unique identifier of the agent to retrieve"]
) -> Dict[str, Any]:
    """
    Get agent details by ID.
    
    Args:
        agent_id: Agent ID
        
    Returns:
        Dict containing agent information
    """
    try:
        orm = get_orm()
        with orm.get_session() as session:
            agent = orm.get_by_id_with_relations(session, Agent, agent_id, ['projects'])
            
            if not agent:
                return {"error": f"Agent with ID {agent_id} not found"}
            
            return {
                "id": agent.id,
                "name": agent.name,
                "description": agent.description,
                "system_prompt": agent.system_prompt,
                "task_prompt": agent.task_prompt,
                "is_active": agent.is_active,
                "created_at": agent.created_at.isoformat(),
                "updated_at": agent.updated_at.isoformat(),
                "projects": [
                    {
                        "id": project.id,
                        "name": project.name,
                        "status": project.status.value
                    }
                    for project in agent.projects
                ]
            }
            
    except Exception as e:
        return {"error": f"Error retrieving agent: {str(e)}"}

async def list_agents(
    active_only: Annotated[bool, "Whether to return only active agents"] = True
) -> List[Dict[str, Any]]:
    """
    List all agents with optional filtering.
    
    Args:
        active_only: Whether to return only active agents
        
    Returns:
        List of agent dictionaries
    """
    try:
        orm = get_orm()
        with orm.get_session() as session:
            if active_only:
                agents = orm.get_active_agents(session)
            else:
                agents = orm.get_all(session, Agent)
            
            return [
                {
                    "id": agent.id,
                    "name": agent.name,
                    "description": agent.description,
                    "is_active": agent.is_active,
                    "created_at": agent.created_at.isoformat()
                }
                for agent in agents
            ]
            
    except Exception as e:
        return [{"error": f"Error listing agents: {str(e)}"}]

async def assign_agent_to_project(
    agent_id: Annotated[int, "The unique identifier of the agent to assign"],
    project_id: Annotated[int, "The unique identifier of the project to assign the agent to"]
) -> str:
    """
    Assign an agent to a project.
    
    Args:
        agent_id: Agent ID
        project_id: Project ID
        
    Returns:
        str: Success or error message
    """
    try:
        orm = get_orm()
        with orm.get_session() as session:
            agent = orm.get_by_id(session, Agent, agent_id)
            project = orm.get_by_id(session, Project, project_id)
            
            if not agent:
                return f"Error: Agent with ID {agent_id} not found"
            if not project:
                return f"Error: Project with ID {project_id} not found"
            
            # Check if already assigned
            if project in agent.projects:
                return f"Agent '{agent.name}' is already assigned to project '{project.name}'"
            
            # Add the relationship
            agent.projects.append(project)
            session.flush()
            
            return f"[SUCCESS] Successfully assigned agent '{agent.name}' to project '{project.name}'"
            
    except Exception as e:
        return f"Error assigning agent to project: {str(e)}"

# ============================================================================
# SETTINGS/MODEL MANAGEMENT FUNCTIONS
# ============================================================================

async def create_model_setting(
    model_name: Annotated[str, "Name of the AI model (e.g., 'gpt-4', 'claude-3-sonnet')"],
    vendor: Annotated[str, "Vendor/provider of the model (e.g., 'openai', 'anthropic', 'google')"],
    api_key: Annotated[str, "API key for accessing the model"]
) -> str:
    """
    Create a new model setting in the database.
    
    Args:
        model_name: Model name
        vendor: Model vendor
        api_key: API key
        
    Returns:
        str: Success message with setting ID or error message
    """
    try:
        orm = get_orm()
        with orm.get_session() as session:
            setting_data = {
                'model_name': model_name,
                'vendor': vendor,
                'api_key': api_key,
                'is_active': True
            }
            
            setting = orm.create(session, Settings, **setting_data)
            msg = f"[SUCCESS] Successfully created model setting '{model_name}' with ID {setting.id}"
            print(msg)
            return msg
            
    except Exception as e:
        msg = f"Error creating model setting: {str(e)}"
        print(f"[ERROR] {msg}")
        return msg

async def get_active_models() -> List[Dict[str, Any]]:
    """
    Get all active AI models.
    
    Returns:
        List of active model settings
    """
    try:
        orm = get_orm()
        with orm.get_session() as session:
            models = orm.get_active_models(session)
            
            return [
                {
                    "id": model.id,
                    "model_name": model.model_name,
                    "vendor": model.vendor,
                    "is_active": model.is_active,
                    "created_at": model.created_at.isoformat()
                }
                for model in models
            ]
            
    except Exception as e:
        return [{"error": f"Error getting active models: {str(e)}"}]

async def toggle_model_status(
    model_id: Annotated[int, "The unique identifier of the model setting to toggle"],
    is_active: Annotated[bool, "Whether to activate (True) or deactivate (False) the model"]
) -> str:
    """
    Toggle model active status.
    
    Args:
        model_id: Model setting ID
        is_active: New active status
        
    Returns:
        str: Success or error message
    """
    try:
        orm = get_orm()
        with orm.get_session() as session:
            model = orm.get_by_id(session, Settings, model_id)
            if not model:
                return f"Error: Model with ID {model_id} not found"
            
            orm.update(session, model, is_active=is_active)
            status = "activated" if is_active else "deactivated"
            return f"[SUCCESS] Successfully {status} model '{model.model_name}'"
            
    except Exception as e:
        return f"Error toggling model status: {str(e)}"

# ============================================================================
# ANALYTICS AND REPORTING FUNCTIONS
# ============================================================================

async def get_project_statistics(
    project_id: Annotated[int, "The unique identifier of the project to get statistics for"]
) -> Dict[str, Any]:
    """
    Get comprehensive statistics for a project.
    
    Args:
        project_id: Project ID
        
    Returns:
        Dict containing project statistics
    """
    try:
        orm = get_orm()
        with orm.get_session() as session:
            # Get basic project info
            project = orm.get_by_id(session, Project, project_id)
            if not project:
                return {"error": f"Project with ID {project_id} not found"}
            
            # Get statistics
            stats = orm.get_project_stats(session, project_id)
            
            # Get findings by severity
            findings_by_severity = {}
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                count = orm.count(session, Finding, project_id=project_id, severity=severity)
                findings_by_severity[severity] = count
            
            # Get findings by status
            findings_by_status = {}
            for status in ['open', 'in_progress', 'resolved', 'false_positive', 'ignored']:
                count = orm.count(session, Finding, project_id=project_id, status=status)
                findings_by_status[status] = count
            
            return {
                "project": {
                    "id": project.id,
                    "name": project.name,
                    "status": project.status.value,
                    "created_at": project.created_at.isoformat(),
                    "last_scanned_at": project.last_scanned_at.isoformat() if project.last_scanned_at else None
                },
                "statistics": stats,
                "findings_by_severity": findings_by_severity,
                "findings_by_status": findings_by_status
            }
            
    except Exception as e:
        return {"error": f"Error getting project statistics: {str(e)}"}

async def get_global_statistics() -> Dict[str, Any]:
    """
    Get global statistics across all projects.
    
    Returns:
        Dict containing global statistics
    """
    try:
        orm = get_orm()
        with orm.get_session() as session:
            stats = orm.get_global_stats(session)
            
            # Get additional detailed stats
            total_findings_by_severity = {}
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                count = orm.count(session, Finding, severity=severity)
                total_findings_by_severity[severity] = count
            
            total_findings_by_status = {}
            for status in ['open', 'in_progress', 'resolved', 'false_positive', 'ignored']:
                count = orm.count(session, Finding, status=status)
                total_findings_by_status[status] = count
            
            active_projects = orm.count(session, Project, status='active')
            active_agents = orm.count(session, Agent, is_active=True)
            active_models = orm.count(session, Settings, is_active=True)
            
            return {
                **stats,
                "active_projects": active_projects,
                "active_agents": active_agents,
                "active_models": active_models,
                "findings_by_severity": total_findings_by_severity,
                "findings_by_status": total_findings_by_status
            }
            
    except Exception as e:
        return {"error": f"Error getting global statistics: {str(e)}"}

async def get_findings_summary(
    project_id: Annotated[Optional[int], "Optional project ID to limit summary scope"] = None
) -> Dict[str, Any]:
    """
    Get a summary of findings with key metrics.
    
    Args:
        project_id: Optional project filter
        
    Returns:
        Dict containing findings summary
    """
    try:
        orm = get_orm()
        with orm.get_session() as session:
            # Base query
            if project_id:
                base_query = session.query(Finding).filter(Finding.project_id == project_id)
            else:
                base_query = session.query(Finding)
            
            # Get counts
            total_findings = base_query.count()
            open_findings = base_query.filter(Finding.status == 'open').count()
            critical_findings = base_query.filter(Finding.severity == 'critical').count()
            high_findings = base_query.filter(Finding.severity == 'high').count()
            
            # Get recent findings (last 7 days)
            from datetime import datetime, timedelta
            week_ago = datetime.utcnow() - timedelta(days=7)
            recent_findings = base_query.filter(Finding.created_at >= week_ago).count()
            
            # Get top file paths with most findings
            from sqlalchemy import func
            top_files = base_query.with_entities(
                Finding.file_path, 
                func.count(Finding.id).label('count')
            ).group_by(Finding.file_path).order_by(func.count(Finding.id).desc()).limit(10).all()
            
            return {
                "total_findings": total_findings,
                "open_findings": open_findings,
                "critical_findings": critical_findings,
                "high_findings": high_findings,
                "recent_findings": recent_findings,
                "resolution_rate": round((total_findings - open_findings) / total_findings * 100, 2) if total_findings > 0 else 0,
                "top_files": [{"file_path": file_path, "count": count} for file_path, count in top_files]
            }
            
    except Exception as e:
        return {"error": f"Error getting findings summary: {str(e)}"}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

async def health_check() -> Dict[str, Any]:
    """
    Check database connectivity and return health status.
    
    Returns:
        Dict containing health check results
    """
    try:
        orm = get_orm()
        is_healthy = orm.health_check()
        
        if is_healthy:
            # Get basic counts
            with orm.get_session() as session:
                project_count = orm.count(session, Project)
                finding_count = orm.count(session, Finding)
                agent_count = orm.count(session, Agent)
                model_count = orm.count(session, Settings)
            
            return {
                "status": "healthy",
                "database_connected": True,
                "counts": {
                    "projects": project_count,
                    "findings": finding_count,
                    "agents": agent_count,
                    "models": model_count
                }
            }
        else:
            return {
                "status": "unhealthy",
                "database_connected": False,
                "error": "Database connection failed"
            }
            
    except Exception as e:
        return {
            "status": "unhealthy",
            "database_connected": False,
            "error": str(e)
        }

async def bulk_update_finding_status(
    finding_ids: Annotated[List[int], "List of finding IDs to update"],
    status: Annotated[str, "New status for all findings (open, in_progress, resolved, false_positive, ignored)"]
) -> str:
    """
    Update status for multiple findings at once.
    
    Args:
        finding_ids: List of finding IDs
        status: New status for all findings
        
    Returns:
        str: Success message with count of updated findings
    """
    try:
        orm = get_orm()
        with orm.get_session() as session:
            # Validate status
            valid_statuses = [s.value for s in FindingStatus]
            if status not in valid_statuses:
                return f"Error: Invalid status '{status}'. Valid statuses: {valid_statuses}"
            
            updated_count = 0
            update_data = {"status": FindingStatus(status)}
            if status == "resolved":
                update_data["resolved_at"] = datetime.utcnow()
            
            for finding_id in finding_ids:
                finding = orm.get_by_id(session, Finding, finding_id)
                if finding:
                    orm.update(session, finding, **update_data)
                    updated_count += 1
            
            return f"[SUCCESS] Successfully updated {updated_count} out of {len(finding_ids)} findings to status '{status}'"
            
    except Exception as e:
        return f"Error bulk updating findings: {str(e)}"

async def export_project_data(
    project_id: Annotated[int, "The unique identifier of the project to export"]
) -> Dict[str, Any]:
    """
    Export all data for a project including findings, agents, and models.
    
    Args:
        project_id: Project ID to export
        
    Returns:
        Dict containing all project data
    """
    try:
        orm = get_orm()
        with orm.get_session() as session:
            # Get project with all relations
            project = orm.get_by_id_with_relations(session, Project, project_id, ['findings', 'agents', 'models'])
            
            if not project:
                return {"error": f"Project with ID {project_id} not found"}
            
            # Get all findings for the project
            findings = orm.get_project_findings(session, project_id)
            
            export_data = {
                "project": {
                    "id": project.id,
                    "name": project.name,
                    "description": project.description,
                    "zip_file_path": project.zip_file_path,
                    "base_path": project.base_path,
                    "status": project.status.value,
                    "created_at": project.created_at.isoformat(),
                    "updated_at": project.updated_at.isoformat(),
                    "last_scanned_at": project.last_scanned_at.isoformat() if project.last_scanned_at else None
                },
                "findings": [
                    {
                        "id": finding.id,
                        "title": finding.title,
                        "description": finding.description,
                        "file_path": finding.file_path,
                        "severity": finding.severity.value,
                        "status": finding.status.value,
                        "recommendation": finding.recommendation,
                        "impacted_files": finding.impacted_files,
                        "created_at": finding.created_at.isoformat(),
                        "updated_at": finding.updated_at.isoformat(),
                        "resolved_at": finding.resolved_at.isoformat() if finding.resolved_at else None
                    }
                    for finding in findings
                ],
                "agents": [
                    {
                        "id": agent.id,
                        "name": agent.name,
                        "description": agent.description,
                        "is_active": agent.is_active
                    }
                    for agent in project.agents
                ],
                "models": [
                    {
                        "id": model.id,
                        "model_name": model.model_name,
                        "vendor": model.vendor,
                        "is_active": model.is_active
                    }
                    for model in project.models
                ],
                "export_timestamp": datetime.utcnow().isoformat()
            }
            
            return export_data
            
    except Exception as e:
        return {"error": f"Error exporting project data: {str(e)}"}
