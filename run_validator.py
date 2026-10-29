import sentry_sdk
from sentry_sdk.integrations.logging import LoggingIntegration
import logging as base_logging

# Disable SQLAlchemy engine INFO logs - MUST be before any db imports
# Comprehensive list to disable all SQLAlchemy logging
base_logging.getLogger('sqlalchemy.engine').setLevel(base_logging.WARNING)
base_logging.getLogger('sqlalchemy.pool').setLevel(base_logging.WARNING)
base_logging.getLogger('sqlalchemy.dialects').setLevel(base_logging.WARNING)
base_logging.getLogger('sqlalchemy').setLevel(base_logging.WARNING)
base_logging.getLogger('sqlalchemy.orm').setLevel(base_logging.WARNING)
base_logging.getLogger('sqlalchemy.engine.Engine').setLevel(base_logging.WARNING)

# Initialize Sentry SDK - only capture exceptions and error/critical logs
sentry_logging = LoggingIntegration(
    level=base_logging.ERROR,        # Capture ERROR and CRITICAL logs
    event_level=base_logging.ERROR   # Send events for ERROR and CRITICAL only
)

sentry_sdk.init(
    dsn="https://ff3ab07a2406ded2fd4a81daaaba30dc@o4510286572879872.ingest.de.sentry.io/4510286576418896",
    send_default_pii=True,
    integrations=[sentry_logging],
    # Only capture exceptions (not debug/info logs)
    traces_sample_rate=0.0,  # Disable performance monitoring
    # Only capture exceptions and error/critical logs, not debug/info/warning
    before_send=lambda event, hint: (
        event if (
            hint.get('exc_info') or  # Exceptions
            (event.get('level') in ('error', 'fatal', 'critical'))  # Error/Critical logs
        ) else None
    ),
)


from db import get_orm, Project, Finding, Confirmation, AIModel, SeverityLevel
from sqlalchemy import case
import argparse
import os
import asyncio
import sys
import traceback
import json

from typing import Annotated

from nerve.models import Configuration
from nerve.runtime import logging as nerve_logging, state
from nerve.runtime import flow
from nerve.runtime.agent import Agent as NerveAgent
from nerve.runtime.flow import Flow
# Shuffle findings to process in random order
import random

from utils.ai_models_utils import init_models_env, format_model_name_for_litellm, create_model_agent, model_completion_options

# ============================================================================
# MONKEY-PATCHES FOR NERVE LIBRARY
# ============================================================================

# Override IS_ACTIVE to always be False and prevent Flow from changing it
flow.IS_ACTIVE = False

_original_flow_init = Flow.__init__

def _patched_flow_init(self, *args, **kwargs):
    """Patched Flow.__init__ that doesn't set IS_ACTIVE to True"""
    _original_flow_init(self, *args, **kwargs)
    flow.IS_ACTIVE = False

Flow.__init__ = _patched_flow_init

# Monkey-patch nerve_logging.init to fix the format parameter bug
try:
    from loguru import logger as loguru_logger
    import litellm
    
    _original_nerve_logging_init = nerve_logging.init
    
    def _patched_nerve_logging_init(
        log_path=None,
        level="INFO",
        litellm_debug=False,
        litellm_tracing=None,
        target=None,
    ):
        """Patched nerve_logging.init that fixes the format parameter bug"""
        import pathlib
        
        if target is None:
            target = sys.stderr
        
        if level != "DEBUG":
            loguru_logger.remove()
            loguru_logger.add(
                target,
                colorize=True,
                format="<level>[{time:MM-DD-YY HH:mm:ss}] {level}</level> {message}",
                level=level,
            )
        
        if not litellm_debug:
            # https://github.com/BerriAI/litellm/issues/4825
            litellm.suppress_debug_info = True
        
        if litellm_tracing:
            litellm.callbacks = [litellm_tracing]  # type: ignore
        
        if log_path:
            # Fix: Use a proper format string instead of the built-in format function
            if isinstance(log_path, pathlib.Path):
                log_path = str(log_path)
            loguru_logger.add(
                log_path,
                format="<level>[{time:MM-DD-YY HH:mm:ss}] {level}</level> {message}",
                level=level
            )
        
        from nerve.runtime.logging import log_event_to_terminal
        state.add_event_listener(log_event_to_terminal)
    
    nerve_logging.init = _patched_nerve_logging_init
except ImportError:
    pass  # loguru or litellm not available, skip patching

# ============================================================================
# CONSTANTS
# ============================================================================

MAX_STEPS = 100
MAX_COST = 5
TIMEOUT = 30000
PROJECT_ID = None
MODEL_ID = None



from db.models import Finding, Confirmation
from db import get_orm

from ai_tools.reporting_tools import report_confirmation

filesystem_server_path = "mcp_servers/file_system_validate.py"

# Use the same Python executable that's running this script (cross-platform)
filesystem_server_command = sys.executable


import typing as t
import signal
import threading
import warnings

def mark_task_complete(
    reason: t.Annotated[
        str | None, "Optional reason explaining why the vulnerability validation process is fully complete."
    ] = None,
) -> None:
    """
    Notify the agent runtime that the vulnerability triage/validation process
    for the entire project is complete and all findings have been handled.

    This function MUST only be invoked after:
    - The specific finding has been thoroughly analyzed, confirmed, or marked as a false positive.
    - The confirmation report is persisted in the database as required.
    - the report_confirmation tool has been called to report the confirmation.

    Args:
        reason (str | None): Optionally provide a summary reason of completion, such as
                             all findings reviewed, X confirmed, Y dismissed, final status, etc.

    Returns:
        None

    Caution:
        - Only call when the agent can guarantee full project completion.
        - This communicates to the agent runtime and state tracker that
          no further work remains and enables end-of-task actions (logging, hooks, reporting).
    """
    # Inform the Nerve agent runtime that all validation work is done for this session/project.
    state.set_task_complete(reason)

def update_cost_on_interrupt(orm):
    try:
        with orm.get_session() as session:
            projects = session.query(Project).filter_by(id=PROJECT_ID).all()
            for project in projects:
                if hasattr(state, '_usage') and state._usage and hasattr(state._usage, 'cost'):
                    # Handle None values properly
                    current_cost = state._usage.cost
                    if current_cost is not None:
                        if project.cost is None:
                            project.cost = 0
                        project.cost += current_cost
                        # Reset the usage cost to 0 after updating
                        state._usage.cost = 0
                        session.commit()
                        print(f"Updated project cost: +{current_cost:.4f}, total: {project.cost:.4f}")

    except Exception as e:
        print(f"Error updating project cost: {e}")


async def cleanup_agent(agent):
    """Properly cleanup agent and its MCP connections"""
    try:
        # Try to close the agent if it has a close method
        if hasattr(agent, 'close'):
            if asyncio.iscoroutinefunction(agent.close):
                await agent.close()
            else:
                agent.close()
    except SystemExit:
        # MCP client may raise SystemExit during cleanup - this is expected
        pass
    except Exception as e:
        # Ignore other cleanup errors - they're harmless
        pass


def get_default_validation_questions() -> list[str]:
    """
    Return a comprehensive set of default validation questions to use when
    the judge fails to generate specific questions.
    """
    return [
        "Can an attacker control the input that reaches the vulnerable code path, and through what entry point (API endpoint, form field, file upload, etc.)?",
        "What input validation, sanitization, or encoding functions exist between the user input and the vulnerable sink?",
        "Is authentication and/or authorization required to reach the vulnerable code, and can these controls be bypassed?",
        "Are there framework-level protections (ORM for SQL, templating for XSS, CSRF tokens, etc.) that would prevent exploitation?",
        "Is the vulnerable code actually reachable in production, or is it dead code, behind feature flags, or admin-only functionality?",
        "What would a realistic attack scenario look like, including prerequisites, attacker capabilities, and expected impact?",
        "Are there compensating controls elsewhere in the application (WAF, rate limiting, monitoring) that would detect or prevent this attack?",
    ]


async def judge_finding(finding: Finding, target_file_full_path: str, model: AIModel) -> list[str]:
    """
    Analyze a finding before validation and determine what questions/queries need to be answered
    to properly validate the finding.
    
    This function acts as a judge that reads the finding details and decides what information
    is needed to validate it effectively. It should be called BEFORE starting the validation process.
    
    Args:
        finding: The Finding object to analyze
        target_file_full_path: The full path to the target file
        model: The AI model to use for analysis
        
    Returns:
        A list of questions/queries (as strings) that should be answered during validation
        to properly assess whether the finding is a false positive or genuine vulnerability.
    """
    import litellm
    from litellm import completion
    
    # Format model name for LiteLLM (handles Ollama and other vendors)
    formatted_model_name = format_model_name_for_litellm(model)
    
    # Prepare finding details
    finding_details = f"""
Finding ID: {finding.id}
Title: {finding.title}
Severity: {finding.severity.value if hasattr(finding.severity, 'value') else finding.severity}
Status: {finding.status.value if hasattr(finding.status, 'value') else finding.status}
File Path: {finding.file_path}
Target File Full Path: {target_file_full_path}

Description:
{finding.description}

Recommendation:
{finding.recommendation or 'No recommendation provided'}
"""
    
    judge_prompt = f"""You are a Principal Security Engineer acting as a validation judge. Your task is to generate precise, targeted questions that will determine whether a reported security finding is genuine or a false positive.

## YOUR OBJECTIVE
Analyze the finding below and produce a focused list of investigation questions. These questions will guide a security analyst in gathering the exact evidence needed to make a definitive determination.

## QUESTION CATEGORIES TO COVER

### 1. SOURCE & SINK ANALYSIS
- Where does attacker-controlled input originate?
- How does data flow from source to the vulnerable sink?
- Are there transformations, sanitizations, or validations along the path?

### 2. EXPLOITABILITY ASSESSMENT
- What preconditions must exist for exploitation?
- Is the vulnerable code path reachable in normal application flow?
- What privileges/authentication levels are required?
- Can the attack be performed remotely or only locally?

### 3. MITIGATION DETECTION
- Are there input validation mechanisms (allowlists, denylists, regex filters)?
- Are there output encoding/escaping mechanisms?
- Are there framework-level protections (CSRF tokens, CSP, prepared statements)?
- Are there architectural controls (WAF, sandboxing, rate limiting)?

### 4. CONTEXTUAL FACTORS
- Is this pattern intentional by design (e.g., admin-only functionality)?
- Does the business logic prevent the attack scenario?
- Are there compensating controls elsewhere in the codebase?
- What is the realistic attack surface and threat model?

### 5. CODE VERIFICATION
- What specific functions/methods need to be traced?
- What imports, dependencies, or configurations affect this code?
- Are there related files that implement security controls?

## OUTPUT FORMAT
Return ONLY a valid JSON array of 5-8 specific, actionable questions. Each question must:
- Target a specific piece of evidence
- Be answerable by examining code or configuration
- Contribute to the exploit/false-positive determination

Example:
["Does the `sanitize_input()` function on line 45 of utils.py properly escape the characters used in this attack vector?",
 "Is the vulnerable endpoint `/api/execute` protected by authentication middleware?",
 "Can user input reach the `eval()` call without passing through the validation layer in middleware.py?",
 "What Content-Security-Policy headers are set that might prevent script execution?",
 "Is this functionality only accessible to admin users based on the route definitions?"]

---

## FINDING TO ANALYZE
{finding_details}

Generate your JSON array of validation questions:"""

    try:
        options = model_completion_options(model)
        options.setdefault("timeout", 30)
        response = completion(
            **options,
            messages=[
                {"role": "system", "content": "You are a security analysis judge. Return only valid JSON arrays of question strings."},
                {"role": "user", "content": judge_prompt}
            ],
        )
        # Extract response content
        response_text = response.choices[0].message.content if response.choices else None
        if response_text is None:
            response_text = ""
        
        # Try to parse as JSON
        # Clean the response - might have markdown code blocks
        if response_text and "```json" in response_text:
            response_text = response_text.split("```json")[1].split("```")[0].strip()
        elif response_text and "```" in response_text:
            response_text = response_text.split("```")[1].split("```")[0].strip()
        
        # If response_text is empty or None, use defaults
        if not response_text:
            print("⚠️ Judge returned empty response, using defaults")
            return get_default_validation_questions()
        
        questions = json.loads(response_text)
        
        if isinstance(questions, list) and len(questions) > 0:
            print(f"\n✓ Judge generated {len(questions)} validation questions:")
            for idx, q in enumerate(questions, 1):
                print(f"  {idx}. {q}")
            return questions
        else:
            print("⚠️ Judge did not return a valid list of questions, using defaults")
            return get_default_validation_questions()
            
    except json.JSONDecodeError as e:
        print(f"⚠️ Failed to parse judge response as JSON: {e}")
        print(f"Response was: {response_text[:200] if response_text else 'empty'}...")
        return get_default_validation_questions()
    except Exception as e:
        print(f"⚠️ Error calling judge function: {e}")
        import traceback
        traceback.print_exc()
        return get_default_validation_questions()


BASE_PROMPT = """
# ROLE: Principal Application Security Engineer - Vulnerability Validator

You are a battle-tested security engineer with 15+ years of experience in vulnerability research, code auditing, and penetration testing. Your expertise spans web applications, APIs, cryptography, smart contracts, and infrastructure security.

## CORE MANDATE
Perform rigorous, evidence-based validation of security findings. Your goal is to determine with high confidence whether each finding represents a **genuine exploitable vulnerability** or a **false positive**.

**DEFAULT STANCE**: Treat every finding as a potential false positive until you gather sufficient evidence to prove otherwise. However, remain objective—if evidence confirms exploitability, acknowledge it.

---

## VALIDATION METHODOLOGY

### PHASE 1: RECONNAISSANCE
1. **Read the VALIDATION QUESTIONS** provided in the task—these were generated by a security judge specifically for this finding
2. **Understand the vulnerability class** (e.g., SQLi, XSS, IDOR, RCE, crypto weakness)
3. **Locate the vulnerable code** using the file path provided
4. **Map the attack surface** by identifying entry points and data flows

### PHASE 2: DEEP CODE ANALYSIS
Perform systematic code review to answer each validation question:

**Source-to-Sink Tracing**
- Trace attacker-controlled input from entry point to vulnerable sink
- Document every function call, transformation, and validation along the path
- Identify all code paths that could reach the vulnerability

**Mitigation Hunting**
- Search for input validation (sanitization, encoding, type checking)
- Look for framework-level protections (ORM, templating, CSRF tokens)
- Check for security headers, middleware, and configuration hardening
- Examine authentication/authorization checks guarding the vulnerable code

**Context Analysis**
- Determine if the code is reachable in production (dead code elimination)
- Check if functionality is admin-only or requires special privileges
- Assess if the vulnerable pattern is intentional by design

### PHASE 3: EXPLOITABILITY ASSESSMENT
For each potential attack vector, evaluate:

| Factor | Question |
|--------|----------|
| **Reachability** | Can an attacker actually reach this code path? |
| **Controllability** | Can an attacker control the vulnerable input? |
| **Preconditions** | What conditions must exist for exploitation? |
| **Attack Complexity** | How difficult is the attack to execute? |
| **Authentication** | What access level is required? |
| **Impact** | What's the realistic damage if exploited? |

### PHASE 4: VERDICT & REPORTING
After thorough analysis, make your determination and document it.

---

## REPORT STRUCTURE (MANDATORY FIELDS)

You MUST call `report_confirmation` with these fields:

### 1. `justification` (Markdown supported)
Write a clear, evidence-based explanation of your verdict:
- State your conclusion upfront (confirmed vulnerability or false positive)
- Reference specific code files, line numbers, and function names
- Explain which validation questions you answered and how
- Describe the evidence that led to your conclusion

### 2. `evidence_analysis` (Markdown supported)
Provide detailed technical analysis:
- Include relevant code snippets you examined
- Document the data flow path (source → transformations → sink)
- List all mitigations found (or explicitly state none were found)
- Reference specific files and line numbers throughout
- Answer each validation question with supporting evidence

### 3. `exploit_feasibility` (Markdown supported)
Assess realistic exploitability:
- **If exploitable**: Describe the attack scenario, prerequisites, and impact
- **If not exploitable**: Explain exactly why (mitigations, unreachable code, etc.)
- Rate complexity: trivial / moderate / complex / theoretical only
- Describe what an attacker would need (access level, knowledge, tools)

### 4. `is_remote_attack` (Boolean)
- `true` = Exploitable remotely over the network
- `false` = Requires local access or physical presence

### 5. `false_positive` (Boolean)
- `true` = Not a real vulnerability (mitigated, unreachable, or by design)
- `false` = Confirmed exploitable vulnerability

---

## DECISION FRAMEWORK

**Mark as FALSE POSITIVE (`false_positive=true`) when:**
- Input is properly sanitized/validated before reaching the sink
- Framework-level protections prevent exploitation
- The vulnerable code path is unreachable in practice
- Authentication/authorization prevents attacker access
- The pattern is intentional and secure by design
- Compensating controls elsewhere neutralize the risk

**Mark as CONFIRMED VULNERABILITY (`false_positive=false`) when:**
- Attacker-controlled input reaches the sink without adequate sanitization
- No effective mitigations exist along the data flow path
- The attack is realistically executable (not just theoretical)
- You can articulate a concrete attack scenario

---

## QUALITY STANDARDS

**DO:**
- Provide specific file paths, line numbers, and code references
- Answer every validation question explicitly
- Support conclusions with concrete evidence from the codebase
- Consider the full context (business logic, threat model, architecture)
- Use markdown formatting for readability

**DON'T:**
- Make claims without examining the actual code
- Leave any report field empty or vague
- Assume mitigations exist without verifying them
- Ignore edge cases or alternative attack vectors
- Rush to judgment—thoroughness over speed

---

## WORKFLOW REMINDER

1. Read the finding details and validation questions
2. Use filesystem tools to examine the vulnerable file and related code
3. Trace data flows and hunt for mitigations
4. Answer each validation question with evidence
5. Make your determination based on the totality of evidence
6. Call `report_confirmation` with a complete, well-structured report
7. Call `mark_task_complete` to finalize

Begin your analysis now.
"""

def generate_task_prompt(finding: Finding, model_id: int, target_file_full_path: str, validation_questions: list[str] = None):
    questions_section = ""
    if validation_questions:
        questions_section = "\n## VALIDATION QUESTIONS\nA security judge has determined these specific questions must be answered to validate this finding:\n\n"
        for idx, question in enumerate(validation_questions, 1):
            questions_section += f"{idx}. {question}\n"
        questions_section += "\n**You MUST address each question above with specific evidence from the codebase.**\n"
    
    severity_value = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
    
    return f"""
# VULNERABILITY VALIDATION TASK

## FINDING DETAILS

| Field | Value |
|-------|-------|
| **Title** | {finding.title} |
| **Severity** | {severity_value} |
| **File Path** | `{finding.file_path}` |
| **Full Path** | `{target_file_full_path}` |
| **Finding ID** | {finding.id} |
| **Model ID** | {model_id} |

### Description
{finding.description}

### Recommended Fix
{finding.recommendation or 'No recommendation provided'}

---
{questions_section}
## YOUR TASK

### Step 1: Initial Code Review
- Open and examine `{target_file_full_path}`
- Locate the vulnerable code pattern described above
- Understand the context and purpose of the code

### Step 2: Data Flow Analysis
- **Trace Upstream**: Where does the data/input come from? What transformations occur?
- **Trace Downstream**: Where does the data go? What operations are performed?
- **Identify Entry Points**: How can an attacker reach this code?

### Step 3: Mitigation Hunt
Search for security controls that might prevent exploitation:
- Input validation/sanitization functions
- Output encoding/escaping
- Authentication/authorization checks
- Framework-level protections
- Security middleware or interceptors
- Configuration-based hardening

### Step 4: Exploitability Assessment
Evaluate whether the vulnerability is practically exploitable:
- Is the code path reachable by an attacker?
- Can attacker-controlled input reach the vulnerable sink?
- What preconditions are required?
- Are there compensating controls?

### Step 5: Report Your Findings
Call `report_confirmation` with:
- `finding_id`: {finding.id}
- `model_id`: {model_id}
- `false_positive`: true/false based on your analysis
- `is_remote_attack`: true/false
- `justification`: Your verdict with evidence
- `evidence_analysis`: Detailed technical findings
- `exploit_feasibility`: Attack scenario assessment

### Step 6: Complete the Task
Call `mark_task_complete` when finished.

---

**IMPORTANT REMINDERS:**
- Use the filesystem tools to read and explore code files
- Be thorough—examine related files, imports, and dependencies
- Document specific file paths and line numbers in your report
- Answer ALL validation questions with evidence
- Default to false_positive=true unless exploitation is clearly demonstrated
"""


async def validate_finding(finding: Finding, project: Project, model: AIModel, orm):
    """Validate a single finding"""
    global PROJECT_ID, MODEL_ID
    PROJECT_ID = project.id
    MODEL_ID = model.id
    
    # Format model name for LiteLLM (handles Ollama and other vendors)
    formatted_model_name = format_model_name_for_litellm(model)
    print(f"\n{'='*80}")
    print(f"Validating finding {finding.id} with model {formatted_model_name}")
    print(f"Project ID: {PROJECT_ID}")
    print(f"Model ID: {MODEL_ID}")
    print(f"Project Name: {project.name}")
    print(f"Project Base Path: {project.base_path}")
    print(f"Finding Title: {finding.title}")
    print(f"Finding Status: {finding.status}")
    print(f"Finding Severity: {finding.severity}")
    print(f"Finding File Path: {finding.file_path}")
    print(f"{'='*80}\n")
    import os

    target_file_full_path = os.path.join(project.base_path, finding.file_path)

    import glob

    # Validate if the file is accessible
    if not os.path.isfile(target_file_full_path) or not os.access(target_file_full_path, os.R_OK):
        print(f"✗ WARNING: Target file does not exist or is not accessible: {target_file_full_path}")
        # Try to find candidate files by matching filename and extension in all subdirs of the base path
        file_basename = os.path.basename(finding.file_path)
        file_ext = os.path.splitext(file_basename)[1]
        # Search all files with same name and extension recursively from project.base_path
        search_pattern = os.path.join(project.base_path, '**', file_basename)
        candidate_files = glob.glob(search_pattern, recursive=True)
        # Filter by extension, if needed (in case of accidental naming issues)
        candidate_files = [f for f in candidate_files if f.endswith(file_ext) and os.path.isfile(f) and os.access(f, os.R_OK)]

        if candidate_files:
            print(f"✓ Found candidate files matching '{file_basename}' in subdirectories:")
            for idx, cand in enumerate(candidate_files, 1):
                print(f"    [{idx}] {cand}")
            # For now, use the first candidate (could add logic here if you want manual selection)
            target_file_full_path = candidate_files[0]
            print(f"✓ Using file: {target_file_full_path}")
        else:
            print(f"✗ ERROR: Could not find any readable file matching '{file_basename}' (ext: '{file_ext}') in {project.base_path} or its subdirectories.")
            return


    print(f"✓ Located and can access file: {target_file_full_path}")

    # Step 1: Judge the finding to determine what questions need to be answered
    print(f"\n{'='*80}")
    print("STEP 1: Judging finding to determine validation questions...")
    print(f"{'='*80}\n")
    validation_questions = await judge_finding(finding, target_file_full_path, model)
    
    print(f"\n{'='*80}")
    print("STEP 2: Starting validation with judge's questions...")
    print(f"{'='*80}\n")
    print(f"Validation Questions: {validation_questions}")



    try:
        agent = await create_model_agent(model,
            formatted_model_name,
            Configuration(
                agent=BASE_PROMPT,
                task=generate_task_prompt(finding, model.id, target_file_full_path, validation_questions),
                mcp={'vulnerability-validate-filesystem-server': Configuration.MCPServer(
                    command=filesystem_server_command,
                    args=[filesystem_server_path, project.base_path]
                )},
                tools=[report_confirmation, mark_task_complete],
            ),
        )
        try:
            await agent.run(
                start_state={
                    "project_base_path": project.base_path, 
                    "finding_name": finding.title,
                    "finding_description": finding.description,
                    "finding_recommendation": finding.recommendation,
                    "finding_status": finding.status,
                    "finding_severity": finding.severity,
                    "finding_file_path": finding.file_path,
                    "model_id": model.id,
                    "finding_id": finding.id,
                    "model_name": model.model_name,
                    "validation_questions": validation_questions},
                max_steps=10000, max_cost=5, timeout=30000)
        finally:
            # Cleanup agent resources
            await cleanup_agent(agent)
            # Give a small delay for subprocess cleanup
            await asyncio.sleep(0.1)

        update_cost_on_interrupt(orm)
        print(f"✓ Successfully validated finding {finding.id}")
    except Exception as e:
        update_cost_on_interrupt(orm)
        print(f"✗ Error validating finding {finding.id}: {e}")
        traceback.print_exc()





def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Security Finding Validator')
    parser.add_argument('--project-id', '-p', type=int, help='The ID of the project - validates all findings for this project')
    parser.add_argument('--finding-id', '-f', type=int, help='The ID of the finding to validate')
    parser.add_argument('--model-id', '-m', type=int, required=True, help='The ID of the model to use for validation')
    
    args = parser.parse_args()
    
    # Require either project-id OR finding-id, but not both
    if args.project_id is None and args.finding_id is None:
        parser.error("Either --project-id or --finding-id must be provided")
    if args.project_id is not None and args.finding_id is not None:
        parser.error("Cannot specify both --project-id and --finding-id at the same time")
    
    return args

async def main():
    """Validate findings - either all findings for a project or a single finding"""
    try:
        args = parse_arguments()
        # Set database name in environment
        orm = get_orm()
        
        # Setup log file path based on validation mode
        from pathlib import Path
        project_root = Path(__file__).parent.resolve()
        logs_dir = project_root / 'logs'
        logs_dir.mkdir(parents=True, exist_ok=True)
        
        if args.finding_id is not None:
            # Single finding validation
            log_path = logs_dir / f'validate_{args.finding_id}_{args.model_id}.log'
        else:
            # Bulk project validation
            log_path = logs_dir / f'bulk_validate_{args.project_id}_{args.model_id}.log'
        
        # Delete existing log file if present
        if log_path.exists():
            try:
                log_path.unlink()
                print(f"Deleted existing log file: {log_path}")
            except Exception as e:
                print(f"Warning: Could not delete existing log file: {e}")
        
        # Initialize nerve logging with log file path
        nerve_logging.init(log_path=str(log_path), level="INFO")
        print(f"Logging to: {log_path}")
        
        # Use database session to query data
        with orm.get_session() as session:
            # Get the model
            model = session.query(AIModel).filter_by(id=args.model_id).one()
            init_models_env([model])
            
            findings_to_validate = []
            project = None
            
            # Determine which findings to validate
            if args.finding_id is not None:
                # Single finding mode
                finding = session.query(Finding).filter_by(id=args.finding_id).one()
                findings_to_validate.append(finding)
                # Load project for single finding
                project = finding.project
            else:
                # Project mode - get all findings for the project, sorted by severity (critical first)
                project = session.query(Project).filter_by(id=args.project_id).one()
                
                # Define severity priority order: critical=1, high=2, medium=3, low=4, info=5
                severity_order = case(
                    (Finding.severity == SeverityLevel.CRITICAL, 1),
                    (Finding.severity == SeverityLevel.HIGH, 2),
                    (Finding.severity == SeverityLevel.MEDIUM, 3),
                    (Finding.severity == SeverityLevel.LOW, 4),
                    (Finding.severity == SeverityLevel.INFO, 5),
                    else_=6  # fallback for any unexpected values
                )
                
                findings_to_validate = session.query(Finding).filter_by(
                    project_id=project.id
                ).order_by(severity_order).all()
                print(f"Found {len(findings_to_validate)} findings to validate for project {project.id}")
                print(f"Sorted by severity: critical first, then high, medium, low, info")
            
            if not findings_to_validate:
                print("No findings to validate.")
                return
            
            # Track validation statistics
            skipped_count = 0
            validated_count = 0
            
            # Validate each finding
            for finding in findings_to_validate:
                # Check if this finding has already been validated by this model
                existing_confirmation = session.query(Confirmation).filter_by(
                    finding_id=finding.id,
                    model_id=model.id
                ).first()
                
                if existing_confirmation:
                    skipped_count += 1
                    print(f"⏭️  Skipping finding {finding.id} - already validated by model {model.model_name} (ID: {model.id})")
                    print(f"   Previous validation: false_positive={existing_confirmation.false_positive}, "
                          f"is_remote_attack={existing_confirmation.is_remote_attack}")
                    continue
                
                await validate_finding(finding, project, model, orm)
                validated_count += 1
                
                # Commit after each finding
                session.commit()
            
            print(f"\n✓ Validation complete.")
            print(f"   Total findings: {len(findings_to_validate)}")
            print(f"   Validated: {validated_count}")
            print(f"   Skipped (already validated): {skipped_count}")
        
    except Exception as e:
        print(f"Error during validation: {e}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    # Suppress asyncio cleanup warnings - these are harmless
    warnings.filterwarnings("ignore", category=RuntimeWarning, message=".*Event loop is closed.*")
    warnings.filterwarnings("ignore", category=RuntimeWarning, message=".*no running event loop.*")
    
    # Suppress asyncio logger warnings
    base_logging.getLogger('asyncio').setLevel(base_logging.ERROR)
    
    try:
        # Use a custom event loop runner that handles SystemExit gracefully
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(main())
        finally:
            # Manually close async generators before closing the loop
            # This prevents SystemExit from being raised during automatic shutdown
            exit_code = 0
            try:
                # Get all pending tasks
                pending = [task for task in asyncio.all_tasks(loop) if not task.done()]
                if pending:
                    # Cancel all pending tasks
                    for task in pending:
                        task.cancel()
                    # Wait for them to complete cancellation
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                
                # Give async generators time to finish before closing
                # This prevents "aclose(): asynchronous generator is already running" errors
                try:
                    # Wait a small amount for any running generators to finish
                    loop.run_until_complete(asyncio.sleep(0.1))
                except Exception:
                    pass
                
                # Now shutdown async generators manually
                # Catch RuntimeError for async generators that are still running
                # and SystemExit that may be raised by MCP client cleanup
                try:
                    loop.run_until_complete(loop.shutdown_asyncgens())
                except RuntimeError as e:
                    # Handle "aclose(): asynchronous generator is already running" error
                    if "async generator is already running" in str(e):
                        # Ignore this error - it's harmless during shutdown
                        pass
                    else:
                        # Re-raise other RuntimeErrors
                        raise
                except SystemExit as e:
                    # MCP client cleanup may raise SystemExit - convert to exit code
                    if e.code is not None:
                        exit_code = e.code
                    # Don't re-raise - we'll exit normally
            except SystemExit as e:
                # MCP client cleanup may raise SystemExit - convert to exit code
                if e.code is not None:
                    exit_code = e.code
            except RuntimeError as e:
                # Handle "aclose(): asynchronous generator is already running" error
                if "async generator is already running" in str(e):
                    # Ignore this error - it's harmless during shutdown
                    pass
                else:
                    # Re-raise other RuntimeErrors
                    raise
            except Exception:
                # Ignore other errors during shutdown
                pass
            finally:
                try:
                    loop.close()
                except Exception:
                    # Ignore errors during loop close
                    pass
        
        # Give a small delay for final cleanup
        import time
        time.sleep(0.2)
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n=== VALIDATION INTERRUPTED BY USER ===")
        sys.exit(0)
    except SystemExit as e:
        # Handle SystemExit from MCP client cleanup - convert to normal exit
        sys.exit(e.code if e.code is not None else 0)
    except Exception as e:
        print(f"Fatal error: {e}")
        traceback.print_exc()
        sys.exit(1)



