#!/usr/bin/env python3
"""
Startup script for the Security Scanner web application
"""

import sentry_sdk
from sentry_sdk.integrations.logging import LoggingIntegration
import logging

# Initialize Sentry SDK - only capture exceptions and error/critical logs
sentry_logging = LoggingIntegration(
    level=logging.ERROR,        # Capture ERROR and CRITICAL logs
    event_level=logging.ERROR   # Send events for ERROR and CRITICAL only
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

# Disable SQLAlchemy engine INFO logs - MUST be before any db imports
# Comprehensive list to disable all SQLAlchemy logging
logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy.pool').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy.dialects').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy.orm').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy.engine.Engine').setLevel(logging.WARNING)

import os
import json
import argparse
import sys
import platform

from app import app
from utils.flask_helpers import initialize_database
from db import get_orm
from db.models import AIModel, Project, InputType, ProjectStatus


# ============================================================================
# API KEY CONFIGURATION
# Users must set their own API keys via environment variables
# Example: export OPENAI_API_KEY="sk-your-key-here"
# ============================================================================

def validate_api_keys():
    """Validate that required API keys are set in environment variables"""
    required_keys = {
        'OPENAI_API_KEY': 'OpenAI API key (required for AI analysis)'
    }
    
    missing_keys = []
    for key, description in required_keys.items():
        if not os.getenv(key):
            missing_keys.append(f"  - {key}: {description}")
    
    if missing_keys:
        print("\n" + "="*70)
        print("ERROR: Required API keys are not set!")
        print("="*70)
        print("\nMissing environment variables:")
        for key in missing_keys:
            print(key)
        print("\nPlease set your API keys before running the application:")
        print("\n  export OPENAI_API_KEY='sk-your-key-here'")
        print("\nOr add them to your shell profile (~/.bashrc, ~/.zshrc, etc.)")
        print("="*70 + "\n")
        sys.exit(1)

# Validate API keys on startup
validate_api_keys()




def create_ai_models(database_name):
    """Create AI models from environment variables and Ollama using centralized utilities"""
    try:
        from utils.ai_models_utils import discover_and_add_models_for_vendor, discover_and_add_ollama_models, AI_KEYS_MAPPING
        
        orm = get_orm(environment='development', database_name=database_name)
        
        with orm.get_session() as session:
            # Check which vendors have API keys set
            available_vendors = []
            for vendor, env_var in AI_KEYS_MAPPING.items():
                api_key = os.getenv(env_var)
                if api_key:
                    available_vendors.append((vendor, api_key))
            
            # Discover and add models for each vendor
            total_successful = []
            total_failed = []
            
            # Add models from vendors with API keys
            for vendor, api_key in available_vendors:
                result = discover_and_add_models_for_vendor(orm, session, vendor, api_key)
                
                if result.get('error'):
                    print(f"[WARNING] Error for vendor {vendor}: {result['error']}")
                
                if result.get('successful_models'):
                    total_successful.extend(result['successful_models'])
                    print(f"[SUCCESS] Added {len(result['successful_models'])} model(s) for vendor {vendor}")
                
                if result.get('failed_models'):
                    total_failed.extend(result['failed_models'])
                    print(f"[WARNING] Failed to add {len(result['failed_models'])} model(s) for vendor {vendor}")
            
            # Discover and add Ollama models (if Ollama is running)
            # Check for custom Ollama base URL from environment variable
            ollama_base_url = os.getenv('OLLAMA_BASE_URL', 'http://192.168.1.10:11434/')
            ollama_result = discover_and_add_ollama_models(orm, session, ollama_base_url=ollama_base_url)
            
            if ollama_result.get('error'):
                # Only print warning if we expected Ollama to be available
                # Silently skip if Ollama is just not running
                pass
            elif ollama_result.get('successful_models'):
                total_successful.extend(ollama_result['successful_models'])
                print(f"[SUCCESS] Added {len(ollama_result['successful_models'])} Ollama model(s)")
            
            if ollama_result.get('failed_models'):
                total_failed.extend(ollama_result['failed_models'])
                print(f"[WARNING] Failed to add {len(ollama_result['failed_models'])} Ollama model(s)")
            
            # Report overall results
            if total_successful:
                print(f"[SUCCESS] Created {len(total_successful)} AI model configurations total")
            
            if total_failed:
                print(f"[WARNING] Skipped {len(total_failed)} models due to errors")
            
            if not available_vendors and not ollama_result.get('successful_models'):
                print("[INFO] No API keys found in environment variables and Ollama is not available")
            
    except Exception as e:
        print(f"[ERROR] Error creating AI models: {e}")
        import traceback
        traceback.print_exc()

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Security Scanner Web Application')
    parser.add_argument('--port', '-p', type=int, default=5000, 
                       help='Port to bind the web server to (default: 5000)')
    parser.add_argument('--database', '-d', type=str, default='dev.db',
                       help='Database file name (default: dev.db)')
    parser.add_argument('--host', type=str, default='127.0.0.1',
                       help='Host to bind the web server to (default: 127.0.0.1)')
    return parser.parse_args()

if __name__ == '__main__':
    # Parse command line arguments
    args = parse_arguments()
    
    # Ensure we're in the right directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    # Create necessary directories
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('uploads', exist_ok=True)
    os.makedirs('codebases', exist_ok=True)
    
    # If OS is Linux, bind to localhost only for security
    bind_host = args.host
    if platform.system() == 'Linux':
        bind_host = '127.0.0.1'
        print("Linux detected: Binding to localhost only for security")
    
    print(f"Starting Security Scanner Web Application")
    print(f"Database: {args.database}")
    print(f"Web interface: http://{bind_host}:{args.port}")
    
    # Set database name in environment
    os.environ['DB_DATABASE'] = args.database
    
    # Initialize database
    initialize_database(args.database)
    
    # Create AI models from environment variables
    create_ai_models(args.database)
    
    # Run the Flask app
    app.run(debug=False, host=bind_host, port=args.port)