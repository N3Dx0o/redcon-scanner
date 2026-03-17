# -*- coding: utf-8 -*-
"""
Security Code Scanner
Main script for running security vulnerability scans on codebases using AI models.
"""

# ============================================================================
# IMPORTS
# ============================================================================

# Standard Library
import argparse
import asyncio
import fnmatch
import json
import logging
import os
import random
import shutil
import signal
import sys
import threading
import time
import traceback
import typing as t
import uuid
import warnings
import zipfile
from pathlib import Path

# Third-party
import sentry_sdk
from litellm import RateLimitError
from loguru import logger as loguru_logger
from sentry_sdk.integrations.logging import LoggingIntegration

# Nerve AI Framework
from nerve.models import Configuration
from nerve.runtime import flow
from nerve.runtime import logging as nerve_logging
from nerve.runtime import state
from nerve.runtime.agent import Agent as NerveAgent
from nerve.runtime.flow import Flow

# Local Imports
from ai_tools.reporting_tools import *
from ai_tools.threat_modeling import *
from ai_tools.threat_modeling import validate_finding_before_db
from db import get_orm, Project, AIModel, Finding, ProjectStatus
from db.orm import T
from threat_modeling_tools import *
from utils.ai_models_utils import init_models_env, format_model_name_for_litellm
from utils.project_utils import filter_target_dirs

# ============================================================================
# SENTRY INITIALIZATION
# ============================================================================

sentry_logging = LoggingIntegration(
    level=logging.ERROR,
    event_level=logging.ERROR
)

sentry_sdk.init(
    dsn=os.getenv("SENTRY_DSN", ""),
    send_default_pii=False,
    integrations=[sentry_logging],
    traces_sample_rate=0.0,
    before_send=lambda event, hint: (
        event if (
            hint.get('exc_info') or
            (event.get('level') in ('error', 'fatal', 'critical'))
        ) else None
    ),
)

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

# Disable SQLAlchemy engine INFO logs - MUST be before any db imports
logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy.pool').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy.dialects').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy.orm').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy.engine.Engine').setLevel(logging.WARNING)

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
    
    import litellm
    if litellm_debug:
        litellm._turn_on_debug()  # type: ignore
    else:
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

# ============================================================================
# CONSTANTS
# ============================================================================

MAX_STEPS = 1000
MAX_COST = 30
TIMEOUT = 30000


# ============================================================================
# GLOBAL VARIABLES
# ============================================================================

PROJECT_ID: int | None = None
MODEL_ID: int | None = None
shutdown_requested: bool = False

# ============================================================================
# PATH SETUP
# ============================================================================

_script_dir = Path(__file__).parent.resolve()
filesystem_server_path = str(_script_dir / "mcp_servers" / "file_system_tools.py")
filesystem_server_command = sys.executable

# Create logs directory if it doesn't exist
logs_dir = _script_dir / "logs"
if not logs_dir.exists():
    logs_dir.mkdir(parents=True, exist_ok=True)
    print(f"Created logs directory: {logs_dir}")

# ============================================================================
# PROMPT GENERATION FUNCTIONS
# ============================================================================

def get_system_prompt() -> str:
    """Get the system prompt for the security analysis agent"""
    return """
You are a world-class application security and threat modeling expert with 15+ years of experience in offensive security, secure code review, and vulnerability research. Your task is to critically analyze each provided file for real, actionable, reproducible security vulnerabilities.

CRITICAL TOOL USAGE RULES — READ CAREFULLY:
- Threat analysis tools (e.g. python_web_threats, javascript_general_threats, etc.) return a STRUCTURED ANALYSIS CONTEXT for YOU to reason over. They do NOT perform the analysis themselves.
- Call each threat tool EXACTLY ONCE per file/function. After receiving the tool result, YOU must perform the security reasoning and determine whether a vulnerability exists.
- NEVER call the same threat tool more than once for the same file or function. This wastes budget and produces no new information.
- After calling a threat tool and completing your analysis:
  1. If a vulnerability is confirmed → call validate_finding_before_db, then call add_finding_to_database.
  2. If no vulnerability → move on to the next file or function immediately.
- Do NOT loop back and re-call threat tools repeatedly. One call per function, then act on the result.

Your workflow for EACH file:
1. Read the file with read_file.
2. Call get_findings_by_file_path to check for existing findings — skip files that already have findings.
3. Choose the single most appropriate threat tool for the code type and call it ONCE.
4. Using YOUR OWN security expertise, analyze whether the code has real, exploitable vulnerabilities.
5. For each confirmed vulnerability: call validate_finding_before_db → then add_finding_to_database.
6. Move to the next file. Do not revisit completed files.
7. After ALL files are processed: call mark_task_complete.

REMEDIATION QUALITY STANDARDS — Your recommendations MUST be:
- Specific to the exact vulnerable code (reference the actual variable names, function names, line logic).
- Include a concrete code fix example (even pseudocode) showing the secure pattern.
- Reference the relevant security standard or CWE where applicable (e.g., CWE-79 for XSS, CWE-89 for SQLi).
- Be actionable in under 30 minutes for a developer familiar with the codebase.
- NOT generic advice like "validate inputs" — always explain WHAT to validate and HOW.

FINDING QUALITY STANDARDS:
- Title: "VulnType in SpecificFunction/Endpoint" (e.g., "Open Redirect in /home route via redirect_url parameter")
- Description: (1) What the vulnerability is, (2) Where exactly it exists (file + function + parameter), (3) How an attacker exploits it, (4) What data/system is at risk.
- Severity: Base on CVSS-like reasoning — consider exploitability (remote vs local, auth required), impact (data breach, RCE, DoS).

DEDUPLICATION: Always call get_findings_by_file_path before analyzing. If a similar finding already exists for that file, do NOT add another one for the same vulnerability class.

Only report vulnerabilities confirmed in this specific codebase. Do NOT report hypothetical or generic issues. Prioritize accuracy, exploitability, and developer-actionable output.
    """


def get_vulnerability_scan_prompt(available_tools: list[str]) -> str:
    """Get the vulnerability scan prompt with available tools"""
    return f"""
You are an advanced application security analyst tasked with performing a thorough vulnerability assessment of a codebase.
Your primary goal is to detect real, actionable, and reproducible security vulnerabilities, not hypothetical issues or false positives.

Available threat analysis tools (use each at most ONCE per file/function):
{chr(10).join(available_tools)}

STRICT WORKFLOW — follow this exactly for every file:
Step 1. explore_directory / read_file — discover and read each source file.
Step 2. get_findings_by_file_path — check for duplicates before analyzing.
Step 3. Call ONE appropriate threat tool for the file (e.g. python_web_threats for Flask/Django code). Pass the function body and relevant context. Call it ONCE and STOP.
Step 4. YOU analyze the tool's structured output using your own security expertise. Decide: is there a real, exploitable vulnerability?
Step 5a. If YES → call validate_finding_before_db (confirm the finding is grounded in the actual code path), then call add_finding_to_database with full details (title, description, file_path, severity 1-10, recommendation, project_id).
Step 5b. If NO → immediately proceed to the next file. Do not retry the threat tool.
Step 6. Repeat Steps 1-5 for every remaining file and subdirectory.
Step 7. When ALL files are analyzed → call mark_task_complete with a summary.

CRITICAL RULES:
- NEVER call the same threat tool twice on the same file or function. One call = one analysis.
- NEVER skip add_finding_to_database for a confirmed vulnerability.
- NEVER call mark_task_complete before processing every file.
- Severity guide: 1-2=Info, 3-4=Low, 5-6=Medium, 7-8=High, 9-10=Critical.

Your responses will be evaluated for accuracy, critical thinking, and relevance. Prioritize accuracy and the minimization of false positives.
    """


# ============================================================================
# TASK MANAGEMENT FUNCTIONS
# ============================================================================

def mark_task_complete(
    reason: t.Annotated[
        str | None, "Optional reason why the task is complete or report of conclusive information."
    ] = None,
) -> None:
    """
    Mark the security scanning task as complete.
    
    This function should only be called when:
    - All files in the target directory have been processed
    - All subdirectories have been recursively scanned
    - All security findings have been properly analyzed and reported to the database
    - The complete scan results have been documented
    
    Args:
        reason: Optional detailed reason explaining why the task is complete,
                including summary of files processed, findings discovered, and 
                reporting status. Should confirm all scanning objectives met.
    """
    state.set_task_complete(reason)


# ============================================================================
# COMMAND LINE ARGUMENT PARSING
# ============================================================================

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Security Code Scanner')
    parser.add_argument('--project-id', '-p', type=int, required=True,
                        help='Project ID for which to run the scan (required)')
    
    # Create a mutually exclusive group for model selection
    model_group = parser.add_mutually_exclusive_group(required=True)
    model_group.add_argument('--model-id', '-m', type=int,
                             help='AI Model ID to use for the scan')
    model_group.add_argument('--model-name', '-n', type=str,
                             help='AI Model name to use for the scan')
    
    return parser.parse_args()


# ============================================================================
# SIGNAL HANDLING
# ============================================================================

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    global shutdown_requested
    if not shutdown_requested:
        print(f"\n\n=== RECEIVED SIGNAL {signum} ===")
        print("Initiating graceful shutdown...")
        shutdown_requested = True
        cleanup_thread = threading.Thread(target=cleanup_resources)
        cleanup_thread.daemon = True
        cleanup_thread.start()
    else:
        print("\n=== FORCE EXIT REQUESTED ===")
        sys.exit(1)


def setup_signal_handlers():
    """Setup signal handlers for graceful shutdown"""
    if sys.platform != "win32":
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    else:
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)


# ============================================================================
# COST MANAGEMENT
# ============================================================================

def update_cost_on_interrupt(orm):
    """Update project cost when scan is interrupted"""
    try:
        with orm.get_session() as session:
            projects = session.query(Project).filter_by(id=PROJECT_ID).all()
            for project in projects:
                if hasattr(state, '_usage') and state._usage and hasattr(state._usage, 'cost'):
                    current_cost = state._usage.cost
                    if current_cost is not None:
                        if project.cost is None:
                            project.cost = 0
                        project.cost += current_cost
                        state._usage.cost = 0
                        session.commit()
                        print(f"Updated project cost: +{current_cost:.4f}, total: {project.cost:.4f}")
    except Exception as e:
        print(f"Error updating project cost: {e}")


# ============================================================================
# CLEANUP FUNCTIONS
# ============================================================================

def cleanup_resources():
    """Clean up resources and handle final cost update"""
    global shutdown_requested
    if not shutdown_requested:
        return
    
    try:
        orm = get_orm()
        update_cost_on_interrupt(orm)
    except Exception as e:
        print(f"Error during cleanup: {e}")
    
    # Give a moment for async cleanup
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(asyncio.sleep(0.1))
    except Exception:
        pass


async def cleanup_agent(agent):
    """Properly cleanup agent and its MCP connections"""
    try:
        if hasattr(agent, 'close'):
            if asyncio.iscoroutinefunction(agent.close):
                await agent.close()
            else:
                agent.close()
    except SystemExit:
        # MCP client may raise SystemExit during cleanup - this is expected
        pass
    except Exception:
        # Ignore other cleanup errors - they're harmless
        pass




# ============================================================================
# MAIN SCAN FUNCTION
# ============================================================================

async def main() -> int:
    """
    Main async function to run the security scan.
    
    Returns:
        Exit code (0 for success, non-zero for errors)
    """
    global shutdown_requested, PROJECT_ID, MODEL_ID
    
    # Setup signal handlers
    setup_signal_handlers()
    
    # Parse arguments
    args = parse_arguments()
    
    # Check if shutdown was requested during argument parsing
    if shutdown_requested:
        print("\n=== SHUTDOWN REQUESTED BEFORE START ===")
        return 0
    
    # Set environment variables
    os.environ['PROJECT_ID'] = str(args.project_id)
    PROJECT_ID = int(args.project_id)
    
    # Determine model selection method
    model_selection_method = None
    if args.model_id is not None:
        MODEL_ID = int(args.model_id)
        os.environ['MODEL_ID'] = str(MODEL_ID)
        model_selection_method = 'id'
    elif args.model_name is not None:
        MODEL_ID = None
        os.environ['MODEL_NAME'] = args.model_name
        model_selection_method = 'name'
    
    orm = get_orm()
    
    # Check if shutdown was requested after database setup
    if shutdown_requested:
        print("\n=== SHUTDOWN REQUESTED AFTER DATABASE SETUP ===")
        return 0
    
    try:
        # Initialize logging
        log_path = str(_script_dir / "logs" / f"scan_{PROJECT_ID}_{MODEL_ID}.log")
        
        # Delete log file if it exists before creating a new one
        log_file_path = Path(log_path)
        if log_file_path.exists():
            try:
                log_file_path.unlink()
                print(f"Deleted existing log file: {log_path}")
            except Exception as e:
                print(f"Warning: Could not delete existing log file: {e}")
        
        nerve_logging.init(log_path=log_path, level="INFO")
        
        # Use database session to query data
        with orm.get_session() as session:
            # Fetch the model using either ID or name
            if model_selection_method == 'id':
                model = session.query(AIModel).filter_by(id=MODEL_ID).one()
            elif model_selection_method == 'name':
                model = session.query(AIModel).filter_by(model_name=args.model_name).one()
                MODEL_ID = model.id
                os.environ['MODEL_ID'] = str(MODEL_ID)
            else:
                raise ValueError("Invalid model selection method")
            
            project = session.query(Project).filter_by(id=PROJECT_ID).one()
            init_models_env([model])
        
            excluded_dirs = project.excluded_dirs or []
            included_dirs = project.included_dirs or []
            base_path = project.base_path
            threat_models = project.threat_models or []
            full_base_path = Path(base_path).resolve()
            
            # Get project max cost
            try:
                project_max_cost = float(project.max_cost)
            except (TypeError, ValueError, AttributeError):
                project_max_cost = 50.0

            # Check if project's max_cost has already been exceeded
            if hasattr(project, "cost"):
                try:
                    current_cost = float(project.cost)
                except (TypeError, ValueError, AttributeError):
                    current_cost = 0.0
                if current_cost >= project_max_cost:
                    print(f"\n=== MAX COST EXCEEDED: Current cost ({current_cost}) >= Maximum allowed cost ({project_max_cost}). Aborting scan. ===")
                    return 0

            # Compute all candidate targets
            target_dirs = filter_target_dirs(base_path, excluded_dirs, included_dirs)
            random.shuffle(target_dirs)
            
            # Build threat models list
            threat_models_list = []
            for threat_model in threat_models:
                threat_models_list.append(globals().get(threat_model))
            threat_models_list = list(set(threat_models_list))
            random.shuffle(threat_models_list)
            # Fixed tools always included (6 tools)
            fixed_tools = [
                business_logic_threats,
                parameters_possible_threats,
                add_finding_to_database,
                get_findings_by_file_path,
                validate_finding_before_db,
                mark_task_complete
            ]
            # OpenAI limit is 128 tools. Reserve 6 for MCP server + 6 fixed = 116 max threat model tools
            MAX_THREAT_TOOLS = 116
            if len(threat_models_list) > MAX_THREAT_TOOLS:
                print(f"[WARNING] Capping threat models from {len(threat_models_list)} to {MAX_THREAT_TOOLS} to stay within API tool limit")
                threat_models_list = threat_models_list[:MAX_THREAT_TOOLS]
            # Build tools list
            all_tools = threat_models_list + fixed_tools
            all_tools_names = [tool.__name__ for tool in threat_models_list]

            # Check if shutdown was requested before starting the main loop
            if shutdown_requested:
                print("\n=== SHUTDOWN REQUESTED BEFORE MAIN LOOP ===")
                return 0

            # Process each target directory
            for i, target in enumerate(target_dirs, 1):
                print(f"\n=== PROCESSING TARGET {i}/{len(target_dirs)}: {target} ===")
                
                if shutdown_requested:
                    print("\n=== SHUTDOWN REQUESTED - STOPPING SCAN ===")
                    break
                
                try:
                    # Format model name for LiteLLM (handles Ollama and other vendors)
                    formatted_model_name = format_model_name_for_litellm(model)
                    print(f"Creating agent for target: {target} with model: {formatted_model_name}")
                    target_absolute_path = full_base_path / target
                    
                    # Verify MCP server file exists
                    if not Path(filesystem_server_path).exists():
                        print(f"ERROR: MCP server file not found: {filesystem_server_path}")
                        print(f"  Current working directory: {os.getcwd()}")
                        continue
                    
                    # Verify target directory exists
                    if not target_absolute_path.exists():
                        print(f"WARNING: Target directory does not exist: {target_absolute_path}")
                        print(f"  Skipping target: {target}")
                        continue

                    # Create agent
                    
                    try:
                        agent = await NerveAgent.create(
                            formatted_model_name,
                            Configuration(
                                agent=get_system_prompt(),
                                task=get_vulnerability_scan_prompt(all_tools_names) + " DB Related Information: Project ID: " + str(project.id),
                                mcp={'filesystem_server': Configuration.MCPServer(
                                    command=filesystem_server_command,
                                    args=[filesystem_server_path, str(target_absolute_path)]
                                )},
                                tools=all_tools,
                            ),
                        )
                    except RuntimeError as e:
                        if "generator didn't yield" in str(e):
                            print(f"ERROR: MCP server connection failed for target: {target}")
                            print(f"  This usually means the MCP server process failed to start or communicate.")
                            print(f"  MCP server: {filesystem_server_path}")
                            print(f"  Target path: {target_absolute_path}")
                            print(f"  Command: {filesystem_server_command}")
                            print(f"  Error: {e}")
                            continue
                        else:
                            raise
                    
                    # Create agent task
                    agent_task = asyncio.create_task(agent.run(
                        start_state={
                            "target_file": target,
                            "available_tools": all_tools_names,
                            "target_path": target,
                            "project_base_path": base_path,
                            "project_id": project.id,
                            "base_model": formatted_model_name
                        },
                        max_steps=10000,
                        max_cost=project_max_cost,
                        timeout=10000
                    ))
                    update_cost_on_interrupt(orm)
                    
                    # Run agent with shutdown monitoring
                    try:
                        if shutdown_requested:
                            print(f"\n=== SHUTDOWN REQUESTED - SKIPPING TARGET: {target} ===")
                            await cleanup_agent(agent)
                            break
                        
                        # Create a background task to monitor for shutdown
                        async def monitor_shutdown():
                            while not agent_task.done() and not shutdown_requested:
                                await asyncio.sleep(2.0)
                            if shutdown_requested and not agent_task.done():
                                print(f"\n=== CANCELLING AGENT FOR TARGET: {target} ===")
                                agent_task.cancel()
                        
                        monitor_task = asyncio.create_task(monitor_shutdown())
                        
                        try:
                            print(f"Starting agent for target: {target}")
                            await agent_task
                            print(f"Agent completed for target: {target}")
                        finally:
                            monitor_task.cancel()
                            try:
                                await monitor_task
                            except asyncio.CancelledError:
                                pass
                            await cleanup_agent(agent)
                            await asyncio.sleep(0.1)
                        
                    except asyncio.CancelledError:
                        print(f"\n=== AGENT CANCELLED FOR TARGET: {target} ===")
                        await cleanup_agent(agent)
                        raise
                    except Exception as e:
                        print(f"Error in agent for target {target}: {e}")
                        await cleanup_agent(agent)
                        continue
                    
                    if not shutdown_requested:
                        update_cost_on_interrupt(orm)
                        
                except asyncio.CancelledError:
                    print(f"\n=== AGENT CANCELLED FOR TARGET: {target} ===")
                    update_cost_on_interrupt(orm)
                    break
                except Exception as e:
                    import traceback as tb
                    tb.print_exc()
                    print(f"Error processing target {target}: {e}")
                    update_cost_on_interrupt(orm)
                    continue
            
            print(f"Total targets processed: {i}")

    except KeyboardInterrupt:
        update_cost_on_interrupt(orm)
        print("\n\n=== SCAN INTERRUPTED BY USER ===")
        print("Exiting gracefully...")
        return 0
    except asyncio.CancelledError:
        update_cost_on_interrupt(orm)
        print("\n\n=== SCAN CANCELLED ===")
        print("Exiting gracefully...")
        return 0
    except SystemExit as e:
        update_cost_on_interrupt(orm)
        print(f"\n\n=== SYSTEM EXIT (Code: {e.code}) ===")
        print("Exiting gracefully...")
        return e.code if e.code is not None else 0
    except Exception as e:
        update_cost_on_interrupt(orm)
        print(f"Error during database scan: {e}")
        import traceback as tb
        tb.print_exc()
        return 1


# ============================================================================
# MAIN EXECUTION
# ============================================================================

if __name__ == "__main__":
    # Suppress asyncio cleanup warnings
    warnings.filterwarnings("ignore", category=RuntimeWarning, message=".*Event loop is closed.*")
    warnings.filterwarnings("ignore", category=RuntimeWarning, message=".*no running event loop.*")
    
    # Suppress asyncio logger warnings
    logging.getLogger('asyncio').setLevel(logging.ERROR)
    
    exit_code = 0
    try:
        # Use a custom event loop runner that handles SystemExit gracefully
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            exit_code = loop.run_until_complete(main())
        finally:
            # Manually close async generators before closing the loop
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
                try:
                    loop.run_until_complete(asyncio.sleep(0.1))
                except Exception:
                    pass
                
                # Now shutdown async generators manually
                try:
                    loop.run_until_complete(loop.shutdown_asyncgens())
                except RuntimeError as e:
                    if "async generator is already running" in str(e):
                        pass
                    else:
                        raise
                except SystemExit as e:
                    if e.code is not None:
                        exit_code = e.code
            except SystemExit as e:
                if e.code is not None:
                    exit_code = e.code
            except RuntimeError as e:
                if "async generator is already running" in str(e):
                    pass
                else:
                    raise
            except Exception:
                pass
            finally:
                try:
                    loop.close()
                except Exception:
                    pass
        
        # Give a small delay for final cleanup
        time.sleep(0.2)
        cleanup_resources()
        sys.exit(exit_code)
        
    except KeyboardInterrupt:
        print("\n\n=== FINAL KEYBOARD INTERRUPT ===")
        cleanup_resources()
        sys.exit(0)
    except SystemExit as e:
        cleanup_resources()
        raise
    except Exception as e:
        print(f"Fatal error: {e}")
        import traceback as tb
        tb.print_exc()
        cleanup_resources()
        sys.exit(1)
