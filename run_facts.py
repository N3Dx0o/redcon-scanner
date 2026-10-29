# -*- coding: utf-8 -*-
"""
Codebase Fact Gatherer
Main script for collecting facts about codebases using AI agents.
Runs one agent per fact type to systematically gather knowledge about the codebase.
"""

# ============================================================================
# IMPORTS
# ============================================================================

# Standard Library
import argparse
import asyncio
import logging
import os
import signal
import sys
import threading
import time
import warnings
from pathlib import Path

# Third-party
import sentry_sdk
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
from ai_tools.facts_tools import (
    create_architecture_fact,
    create_attack_surface_fact,
    create_dependency_fact,
    create_data_flow_fact,
    create_access_control_fact,
    create_crypto_fact,
    create_validation_fact,
    create_dangerous_function_fact,
    create_state_logic_fact,
    create_external_interaction_fact,
    create_threat_model_fact,
    get_project_facts,
    get_facts_summary,
)
from db import get_orm, Project, AIModel
from db.models import FactType
from utils.ai_models_utils import init_models_env, format_model_name_for_litellm, create_model_agent, model_completion_options

# ============================================================================
# SENTRY INITIALIZATION
# ============================================================================

sentry_logging = LoggingIntegration(
    level=logging.ERROR,
    event_level=logging.ERROR
)

sentry_sdk.init(
    dsn="https://ff3ab07a2406ded2fd4a81daaaba30dc@o4510286572879872.ingest.de.sentry.io/4510286576418896",
    send_default_pii=True,
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

logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy.pool').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy.dialects').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy.orm').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy.engine.Engine').setLevel(logging.WARNING)

# ============================================================================
# MONKEY-PATCHES FOR NERVE LIBRARY
# ============================================================================

flow.IS_ACTIVE = False

_original_flow_init = Flow.__init__

def _patched_flow_init(self, *args, **kwargs):
    """Patched Flow.__init__ that doesn't set IS_ACTIVE to True"""
    _original_flow_init(self, *args, **kwargs)
    flow.IS_ACTIVE = False

Flow.__init__ = _patched_flow_init

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
        litellm._turn_on_debug()
    else:
        litellm.suppress_debug_info = True
    
    if litellm_tracing:
        litellm.callbacks = [litellm_tracing]
    
    if log_path:
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

MAX_STEPS = 500
MAX_COST = 10
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

logs_dir = _script_dir / "logs"
if not logs_dir.exists():
    logs_dir.mkdir(parents=True, exist_ok=True)
    print(f"Created logs directory: {logs_dir}")

# ============================================================================
# FACT TYPE CONFIGURATIONS
# ============================================================================

FACT_TYPE_CONFIGS = {
    FactType.ARCHITECTURE: {
        "name": "Architecture",
        "tool": create_architecture_fact,
        "description": "System architecture, components, services, and their relationships",
        "prompt": """Analyze the codebase structure and identify architectural patterns.

Focus on:
- Overall architecture style (monolithic, microservices, serverless, etc.)
- Main components and their responsibilities
- Service boundaries and communication patterns
- Layer structure (presentation, business logic, data access)
- Design patterns in use (MVC, Repository, Factory, etc.)
- Module organization and dependency structure

For each significant architectural discovery, create a fact using the create_architecture_fact tool."""
    },
    FactType.ATTACK_SURFACE: {
        "name": "Attack Surface",
        "tool": create_attack_surface_fact,
        "description": "Entry points, exposed endpoints, APIs, and potential attack vectors",
        "prompt": """Identify all entry points and exposed interfaces in the codebase.

Focus on:
- HTTP/REST API endpoints and their methods
- WebSocket connections and handlers
- GraphQL endpoints and schemas
- File upload handlers
- Authentication endpoints
- Admin interfaces and panels
- Public-facing functions and services
- External integrations and webhooks

For each attack surface element, create a fact using the create_attack_surface_fact tool."""
    },
    FactType.DEPENDENCY: {
        "name": "Dependencies",
        "tool": create_dependency_fact,
        "description": "Third-party libraries, packages, frameworks, and their versions",
        "prompt": """Analyze the project dependencies and third-party libraries.

Focus on:
- Package manifest files (package.json, requirements.txt, Cargo.toml, etc.)
- Direct vs transitive dependencies
- Version constraints and pinning
- Known vulnerable packages
- Outdated or unmaintained dependencies
- Security-critical libraries (crypto, auth, etc.)
- Framework versions and their security implications

For each significant dependency, create a fact using the create_dependency_fact tool."""
    },
    FactType.DATA_FLOW: {
        "name": "Data Flow",
        "tool": create_data_flow_fact,
        "description": "How data moves through the system, storage, and transformations",
        "prompt": """Trace how data flows through the application.

Focus on:
- User input sources and how they're processed
- Data transformation and validation points
- Database interactions and queries
- Session and state management
- Caching mechanisms
- Data serialization/deserialization
- File I/O operations
- API request/response handling
- Logging and what data is logged

For each data flow pattern, create a fact using the create_data_flow_fact tool."""
    },
    FactType.ACCESS_CONTROL: {
        "name": "Access Control",
        "tool": create_access_control_fact,
        "description": "Authentication and authorization mechanisms",
        "prompt": """Analyze authentication and authorization implementations.

Focus on:
- Authentication mechanisms (JWT, sessions, OAuth, API keys)
- Authorization models (RBAC, ABAC, ACL)
- Permission checks and enforcement points
- Role definitions and hierarchies
- Session management
- Password policies
- Multi-factor authentication
- Token handling and validation
- Protected routes and resources

For each access control mechanism found, create a fact using the create_access_control_fact tool."""
    },
    FactType.DANGEROUS_FUNCTION: {
        "name": "Dangerous Functions",
        "tool": create_dangerous_function_fact,
        "description": "Usage of dangerous functions and unsafe patterns",
        "prompt": """Identify dangerous function usage and unsafe coding patterns.

Focus on:
- eval(), exec() and dynamic code execution
- Shell command execution (subprocess, os.system)
- Deserialization of untrusted data (pickle, yaml.load)
- Unsafe type coercion
- Direct SQL query construction
- innerHTML and DOM manipulation
- File path manipulation
- Memory unsafe operations
- Deprecated or insecure APIs

For each dangerous function usage, create a fact using the create_dangerous_function_fact tool."""
    },
    FactType.VALIDATION: {
        "name": "Input Validation",
        "tool": create_validation_fact,
        "description": "Input validation and sanitization practices",
        "prompt": """Examine input validation and sanitization throughout the codebase.

Focus on:
- Input validation libraries and frameworks
- Validation patterns (whitelist vs blacklist)
- Sanitization functions and their usage
- Type checking and coercion
- Size/length limits
- Format validation (email, URL, etc.)
- SQL query construction
- HTML/template rendering
- Command execution

For each validation pattern or gap, create a fact using the create_validation_fact tool."""
    },
    FactType.CRYPTO: {
        "name": "Cryptography",
        "tool": create_crypto_fact,
        "description": "Cryptographic implementations, algorithms, and key management",
        "prompt": """Identify all cryptographic implementations and practices.

Focus on:
- Encryption algorithms in use (AES, RSA, etc.)
- Hashing functions (SHA, MD5, bcrypt, etc.)
- Key generation and management
- Certificate handling
- TLS/SSL configurations
- Token generation (JWT, session tokens)
- Random number generation
- Password storage mechanisms
- Cryptographic libraries used

For each cryptographic implementation, create a fact using the create_crypto_fact tool."""
    },
    FactType.STATE_LOGIC: {
        "name": "State & Business Logic",
        "tool": create_state_logic_fact,
        "description": "State management and business logic that could have security implications",
        "prompt": """Analyze state management and business logic flows.

Focus on:
- State machines and their transitions
- Business rule implementations
- Transaction handling
- Race condition potential
- Concurrency patterns
- Workflow processes
- Order of operations dependencies
- Error state handling
- Rollback mechanisms

For each state/business logic pattern, create a fact using the create_state_logic_fact tool."""
    },
    FactType.EXTERNAL_INTERACTION: {
        "name": "External Interactions",
        "tool": create_external_interaction_fact,
        "description": "External service integrations, APIs, and network communications",
        "prompt": """Identify all external service integrations and communications.

Focus on:
- Third-party API integrations
- Database connections
- Message queue interactions
- Cloud service usage (AWS, GCP, Azure)
- Email services
- Payment gateways
- OAuth providers
- Webhook endpoints
- External file storage

For each external interaction, create a fact using the create_external_interaction_fact tool."""
    },
    FactType.THREAT_MODEL: {
        "name": "Threat Model",
        "tool": create_threat_model_fact,
        "description": "Identified threats, trust boundaries, and security assumptions",
        "prompt": """Develop threat model insights for the codebase.

Focus on:
- Trust boundaries between components
- High-value assets and their protection
- Potential threat actors and their capabilities
- Attack vectors and entry points
- Security assumptions in the code
- STRIDE threats (Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation of Privilege)
- Risk areas requiring attention
- Missing security controls

For each threat model insight, create a fact using the create_threat_model_fact tool."""
    },
}

# ============================================================================
# PROMPT GENERATION FUNCTIONS
# ============================================================================

def get_system_prompt() -> str:
    """Get the system prompt for the fact gathering agent"""
    return """You are an expert code analyst specializing in understanding and documenting codebases.
Your task is to thoroughly explore and analyze a codebase to gather specific types of facts.

You will use filesystem tools to:
- List directories and understand project structure
- Read files to understand implementations
- Search for patterns and specific code constructs

Your analysis should be:
- Thorough: Explore all relevant parts of the codebase
- Accurate: Only report what you actually find in the code
- Specific: Include file paths, line numbers, and concrete details
- Contextual: Explain the significance of each finding

Always provide evidence from the code for each fact you report.
Use the appropriate fact creation tool to record each discovery.
"""


def get_fact_gathering_prompt(fact_type: FactType, config: dict, project_id: int) -> str:
    """Get the task prompt for gathering a specific type of facts"""
    return f"""Your task is to gather {config['name']} facts from this codebase.

FACT TYPE: {fact_type.value}
DESCRIPTION: {config['description']}

INSTRUCTIONS:
{config['prompt']}

IMPORTANT:
- Use the filesystem tools (list_directory, read_file, search) to explore the codebase
- Look in all relevant directories and files
- Be thorough but focused on {config['name']} related information
- Create a fact for each significant discovery using the appropriate tool
- Project ID for creating facts: {project_id}

When you have thoroughly explored the codebase for {config['name']} facts, call mark_task_complete with a summary of what you found.
"""


# ============================================================================
# TASK MANAGEMENT FUNCTIONS
# ============================================================================

def mark_task_complete(reason: str | None = None) -> None:
    """
    Mark the fact gathering task as complete.
    
    Args:
        reason: Summary of facts gathered and areas explored.
    """
    state.set_task_complete(reason)


# ============================================================================
# COMMAND LINE ARGUMENT PARSING
# ============================================================================

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Codebase Fact Gatherer')
    parser.add_argument('--project-id', '-p', type=int, required=True,
                        help='Project ID for which to gather facts (required)')
    
    model_group = parser.add_mutually_exclusive_group(required=True)
    model_group.add_argument('--model-id', '-m', type=int,
                             help='AI Model ID to use for fact gathering')
    model_group.add_argument('--model-name', '-n', type=str,
                             help='AI Model name to use for fact gathering')
    
    parser.add_argument('--fact-types', '-f', type=str, nargs='+',
                        help='Specific fact types to gather (default: all)',
                        choices=[ft.value for ft in FactType])
    
    parser.add_argument('--max-cost', type=float, default=50.0,
                        help='Maximum cost limit for the entire run (default: 50.0)')
    
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
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


# ============================================================================
# COST MANAGEMENT
# ============================================================================

def update_cost(orm):
    """Update project cost"""
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
        update_cost(orm)
    except Exception as e:
        print(f"Error during cleanup: {e}")


async def cleanup_agent(agent):
    """Properly cleanup agent and its MCP connections"""
    try:
        if hasattr(agent, 'close'):
            if asyncio.iscoroutinefunction(agent.close):
                await agent.close()
            else:
                agent.close()
    except SystemExit:
        pass
    except Exception:
        pass


# ============================================================================
# MAIN FACT GATHERING FUNCTION
# ============================================================================

async def gather_facts_for_type(
    fact_type: FactType,
    config: dict,
    project: Project,
    model: AIModel,
    formatted_model_name: str,
    orm
) -> bool:
    """
    Run an agent to gather facts of a specific type.
    
    Returns:
        True if successful, False otherwise
    """
    global shutdown_requested
    
    print(f"\n{'='*60}")
    print(f"GATHERING {config['name'].upper()} FACTS")
    print(f"{'='*60}")
    
    if shutdown_requested:
        print("Shutdown requested, skipping...")
        return False
    
    try:
        base_path = Path(project.base_path).resolve()
        
        if not Path(filesystem_server_path).exists():
            print(f"ERROR: MCP server file not found: {filesystem_server_path}")
            return False
        
        if not base_path.exists():
            print(f"ERROR: Project path does not exist: {base_path}")
            return False
        
        # Build tools list for this fact type
        tools = [mark_task_complete, get_project_facts, get_facts_summary]
        
        # Add the specific fact creation tool if available
        if config.get("tool"):
            tools.append(config["tool"])
        
        # Create agent
        try:
            agent = await create_model_agent(model,
                formatted_model_name,
                Configuration(
                    agent=get_system_prompt(),
                    task=get_fact_gathering_prompt(fact_type, config, project.id),
                    mcp={'filesystem_server': Configuration.MCPServer(
                        command=filesystem_server_command,
                        args=[filesystem_server_path, str(base_path)]
                    )},
                    tools=tools,
                ),
            )
        except RuntimeError as e:
            if "generator didn't yield" in str(e):
                print(f"ERROR: MCP server connection failed: {e}")
                return False
            raise
        
        # Create agent task
        agent_task = asyncio.create_task(agent.run(
            start_state={
                "fact_type": fact_type.value,
                "project_id": project.id,
                "project_name": project.name,
                "base_path": str(base_path),
            },
            max_steps=MAX_STEPS,
            max_cost=MAX_COST,
            timeout=TIMEOUT
        ))
        
        # Monitor for shutdown
        async def monitor_shutdown():
            while not agent_task.done() and not shutdown_requested:
                await asyncio.sleep(2.0)
            if shutdown_requested and not agent_task.done():
                print(f"\n=== CANCELLING {config['name']} AGENT ===")
                agent_task.cancel()
        
        monitor_task = asyncio.create_task(monitor_shutdown())
        
        try:
            await agent_task
            print(f"Completed gathering {config['name']} facts")
        finally:
            monitor_task.cancel()
            try:
                await monitor_task
            except asyncio.CancelledError:
                pass
            await cleanup_agent(agent)
            await asyncio.sleep(0.1)
        
        update_cost(orm)
        return True
        
    except asyncio.CancelledError:
        print(f"\n=== {config['name'].upper()} AGENT CANCELLED ===")
        return False
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"Error gathering {config['name']} facts: {e}")
        return False


async def main() -> int:
    """
    Main async function to run the fact gathering process.
    
    Returns:
        Exit code (0 for success, non-zero for errors)
    """
    global shutdown_requested, PROJECT_ID, MODEL_ID
    
    setup_signal_handlers()
    args = parse_arguments()
    
    if shutdown_requested:
        print("\n=== SHUTDOWN REQUESTED BEFORE START ===")
        return 0
    
    os.environ['PROJECT_ID'] = str(args.project_id)
    PROJECT_ID = int(args.project_id)
    
    # Determine model selection method
    if args.model_id is not None:
        MODEL_ID = int(args.model_id)
        os.environ['MODEL_ID'] = str(MODEL_ID)
        model_selection_method = 'id'
    else:
        MODEL_ID = None
        os.environ['MODEL_NAME'] = args.model_name
        model_selection_method = 'name'
    
    orm = get_orm()
    
    if shutdown_requested:
        return 0
    
    try:
        # Initialize logging
        log_path = str(_script_dir / "logs" / f"facts_{PROJECT_ID}_{MODEL_ID or args.model_name}.log")
        log_file_path = Path(log_path)
        if log_file_path.exists():
            try:
                log_file_path.unlink()
            except Exception as e:
                print(f"Warning: Could not delete existing log file: {e}")
        
        nerve_logging.init(log_path=log_path, level="INFO")
        
        with orm.get_session() as session:
            # Fetch the model
            if model_selection_method == 'id':
                model = session.query(AIModel).filter_by(id=MODEL_ID).one()
            else:
                model = session.query(AIModel).filter_by(model_name=args.model_name).one()
                MODEL_ID = model.id
                os.environ['MODEL_ID'] = str(MODEL_ID)
            
            project = session.query(Project).filter_by(id=PROJECT_ID).one()
            init_models_env([model])
            
            # Check cost limit
            max_cost = args.max_cost
            if hasattr(project, "cost") and project.cost:
                current_cost = float(project.cost)
                if current_cost >= max_cost:
                    print(f"\n=== MAX COST EXCEEDED: {current_cost} >= {max_cost} ===")
                    return 0
            
            # Determine which fact types to gather
            if args.fact_types:
                fact_types = [FactType(ft) for ft in args.fact_types]
            else:
                fact_types = list(FactType)
            
            formatted_model_name = format_model_name_for_litellm(model)
            
            print(f"\n{'='*60}")
            print(f"CODEBASE FACT GATHERER")
            print(f"{'='*60}")
            print(f"Project: {project.name} (ID: {project.id})")
            print(f"Model: {formatted_model_name}")
            print(f"Base Path: {project.base_path}")
            print(f"Fact Types: {[ft.value for ft in fact_types]}")
            print(f"Max Cost: ${max_cost}")
            print(f"{'='*60}\n")
            
            # Process each fact type
            successful = 0
            failed = 0
            
            for i, fact_type in enumerate(fact_types, 1):
                if shutdown_requested:
                    print("\n=== SHUTDOWN REQUESTED - STOPPING ===")
                    break
                
                config = FACT_TYPE_CONFIGS.get(fact_type)
                if not config:
                    print(f"No config for fact type: {fact_type.value}, skipping...")
                    continue
                
                print(f"\n[{i}/{len(fact_types)}] Processing {config['name']}...")
                
                success = await gather_facts_for_type(
                    fact_type=fact_type,
                    config=config,
                    project=project,
                    model=model,
                    formatted_model_name=formatted_model_name,
                    orm=orm
                )
                
                if success:
                    successful += 1
                else:
                    failed += 1
                
                # Check cost after each fact type
                session.refresh(project)
                if project.cost and project.cost >= max_cost:
                    print(f"\n=== MAX COST REACHED: ${project.cost:.2f} ===")
                    break
            
            print(f"\n{'='*60}")
            print(f"FACT GATHERING COMPLETE")
            print(f"{'='*60}")
            print(f"Successful: {successful}")
            print(f"Failed: {failed}")
            print(f"Total Cost: ${project.cost or 0:.4f}")
            print(f"{'='*60}\n")
            
            return 0
            
    except KeyboardInterrupt:
        update_cost(orm)
        print("\n\n=== INTERRUPTED BY USER ===")
        return 0
    except asyncio.CancelledError:
        update_cost(orm)
        print("\n\n=== CANCELLED ===")
        return 0
    except SystemExit as e:
        update_cost(orm)
        return e.code if e.code is not None else 0
    except Exception as e:
        update_cost(orm)
        import traceback
        traceback.print_exc()
        print(f"Error during fact gathering: {e}")
        return 1


# ============================================================================
# MAIN EXECUTION
# ============================================================================

if __name__ == "__main__":
    warnings.filterwarnings("ignore", category=RuntimeWarning, message=".*Event loop is closed.*")
    warnings.filterwarnings("ignore", category=RuntimeWarning, message=".*no running event loop.*")
    logging.getLogger('asyncio').setLevel(logging.ERROR)
    
    exit_code = 0
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            exit_code = loop.run_until_complete(main())
        finally:
            try:
                pending = [task for task in asyncio.all_tasks(loop) if not task.done()]
                if pending:
                    for task in pending:
                        task.cancel()
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                
                try:
                    loop.run_until_complete(asyncio.sleep(0.1))
                except Exception:
                    pass
                
                try:
                    loop.run_until_complete(loop.shutdown_asyncgens())
                except RuntimeError as e:
                    if "async generator is already running" not in str(e):
                        raise
                except SystemExit as e:
                    if e.code is not None:
                        exit_code = e.code
            except SystemExit as e:
                if e.code is not None:
                    exit_code = e.code
            except RuntimeError as e:
                if "async generator is already running" not in str(e):
                    raise
            except Exception:
                pass
            finally:
                try:
                    loop.close()
                except Exception:
                    pass
        
        time.sleep(0.2)
        cleanup_resources()
        sys.exit(exit_code)
        
    except KeyboardInterrupt:
        print("\n\n=== FINAL KEYBOARD INTERRUPT ===")
        cleanup_resources()
        sys.exit(0)
    except SystemExit:
        cleanup_resources()
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"Fatal error: {e}")
        cleanup_resources()
        sys.exit(1)
