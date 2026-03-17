"""API endpoints"""
from flask_login import login_required, current_user
from flask import request, jsonify
from routes import api_bp
from utils.flask_helpers import get_orm_instance
from db.models import AIModel, Finding, FindingStatus, Project
from utils.tools_utils import list_tools
from utils.project_utils import validate_git_url, is_zip_file
from werkzeug.utils import secure_filename
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


@api_bp.route('/ai-models', methods=['GET', 'POST'])
@login_required
def api_ai_models():
    """Get available AI models or add new AI model"""
    if request.method == 'GET':
        try:
            orm = get_orm_instance()
            with orm.get_session() as session:
                models = orm.get_all(session, AIModel)
                return jsonify({'models': [{
                    'id': m.id, 
                    'model_name': m.model_name, 
                    'vendor': m.vendor,
                    'api_key_suffix': m.api_key[-4:] if m.api_key and len(m.api_key) >= 4 else '****'
                } for m in models]})
        except Exception as e:
            logger.error(f"Error getting AI models: {e}")
            return jsonify({'models': []})
    
    elif request.method == 'POST':
        """Add AI models for a vendor - automatically discovers and adds all suitable models"""
        try:
            data = request.get_json()
            if not data or not data.get('vendor') or not data.get('api_key'):
                return jsonify({'success': False, 'error': 'Missing required fields: vendor and api_key are required'})
            
            vendor = data['vendor']
            api_key = data['api_key']
            
            orm = get_orm_instance()
            with orm.get_session() as session:
                # Use centralized utility to discover and add all suitable models
                from utils.ai_models_utils import discover_and_add_models_for_vendor
                
                result = discover_and_add_models_for_vendor(orm, session, vendor, api_key)
                
                if result.get('error'):
                    return jsonify({
                        'success': False, 
                        'error': result['error'],
                        'successful_models': result['successful_models'],
                        'failed_models': result['failed_models']
                    })
                
                # Return success with list of added models
                return jsonify({
                    'success': True, 
                    'message': f"Successfully added {len(result['successful_models'])} model(s) for vendor {vendor}",
                    'successful_models': result['successful_models'],
                    'failed_models': result['failed_models'],
                    'total_added': len(result['successful_models'])
                })
        except Exception as e:
            logger.error(f"Error adding AI models: {e}")
            return jsonify({'success': False, 'error': str(e)})


@api_bp.route('/ai-models/<int:model_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def api_ai_model_by_id(model_id):
    """Get, update or delete specific AI model"""
    try:
        orm = get_orm_instance()
        with orm.get_session() as session:
            model = orm.get_by_id(session, AIModel, model_id)
            if not model:
                return jsonify({'success': False, 'error': 'Model not found'})
            
            if request.method == 'GET':
                """Get AI model data"""
                # Only admins may retrieve the full API key; others see only last 4 chars
                if current_user.is_admin:
                    exposed_key = model.api_key
                else:
                    k = model.api_key or ""
                    exposed_key = ("*" * (len(k) - 4) + k[-4:]) if len(k) >= 4 else "****"
                return jsonify({
                    'success': True, 
                    'model': {
                        'id': model.id, 
                        'model_name': model.model_name, 
                        'vendor': model.vendor,
                        'api_key': exposed_key,
                        'created_at': model.created_at.isoformat() if model.created_at else None
                    }
                })
            
            elif request.method == 'PUT':
                # IDOR fix: only admins may update AI model records
                if not current_user.is_admin:
                    return jsonify({'success': False, 'error': 'Forbidden: admin access required'}), 403
                """Update AI model"""
                data = request.get_json()
                if not data:
                    return jsonify({'success': False, 'error': 'No data provided'})
                
                # Update fields if provided
                if 'model_name' in data:
                    model.model_name = data['model_name']
                if 'vendor' in data:
                    model.vendor = data['vendor']
                if 'api_key' in data:
                    model.api_key = data['api_key']
                
                orm.update(session, model)
                return jsonify({'success': True, 'model': {'id': model.id, 'model_name': model.model_name, 'vendor': model.vendor}})
            
            elif request.method == 'DELETE':
                # IDOR fix: only admins may delete AI model records
                if not current_user.is_admin:
                    return jsonify({'success': False, 'error': 'Forbidden: admin access required'}), 403
                """Delete AI model"""
                orm.delete(session, model)
                return jsonify({'success': True})
                
    except Exception as e:
        logger.error(f"Error with AI model {model_id}: {e}")
        return jsonify({'success': False, 'error': str(e)})


@api_bp.route('/ai-models/delete-all', methods=['DELETE'])
@login_required
def api_delete_all_ai_models():
    """Delete all AI models from the database"""
    if not current_user.is_admin:
        return jsonify({"success": False, "error": "Forbidden: admin access required"}), 403
    try:
        orm = get_orm_instance()
        with orm.get_session() as session:
            # Get count before deletion
            count = orm.count(session, AIModel)
            
            # Delete all models using bulk delete
            # The context manager will commit the transaction
            session.query(AIModel).delete()
            
            return jsonify({
                'success': True,
                'message': f'Successfully deleted {count} model(s)',
                'deleted_count': count
            })
                
    except Exception as e:
        logger.error(f"Error deleting all AI models: {e}")
        return jsonify({'success': False, 'error': str(e)})


@api_bp.route('/projects', methods=['GET'])
@login_required
def api_list_projects():
    """API endpoint to list all projects"""
    try:
        orm = get_orm_instance()
        with orm.get_session() as session:
            if current_user.is_admin:
                projects = orm.get_all(session, Project)
            else:
                projects = session.query(Project).filter(Project.owner_id == current_user.id).all()
            projects_list = [{
                'id': p.id,
                'name': p.name,
                'status': p.status.value if hasattr(p.status, 'value') else str(p.status),
                'base_path': p.base_path,
                'input_type': p.input_type.value if hasattr(p.input_type, 'value') else str(p.input_type),
                'last_scanned_at': p.last_scanned_at.isoformat() if p.last_scanned_at else None,
                'created_at': p.created_at.isoformat() if p.created_at else None,
                'updated_at': p.updated_at.isoformat() if p.updated_at else None,
            } for p in projects]
            
            return jsonify({
                'success': True,
                'projects': projects_list,
                'total': len(projects_list)
            })
    except Exception as e:
        logger.error(f"Error listing projects: {e}")
        logger.error(f'Internal error: {e}', exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@api_bp.route('/projects/<int:project_id>', methods=['GET'])
@login_required
def api_get_project(project_id):
    """API endpoint to get a single project by ID"""
    try:
        orm = get_orm_instance()
        with orm.get_session() as session:
            project = orm.get_by_id(session, Project, project_id)
            if not project:
                return jsonify({'success': False, 'error': 'Project not found'}), 404
            
            project_dict = {
                'id': project.id,
                'name': project.name,
                'status': project.status.value if hasattr(project.status, 'value') else str(project.status),
                # base_path omitted
                'input_type': project.input_type.value if hasattr(project.input_type, 'value') else str(project.input_type),
                'last_scanned_at': project.last_scanned_at.isoformat() if project.last_scanned_at else None,
                'created_at': project.created_at.isoformat() if project.created_at else None,
                'updated_at': project.updated_at.isoformat() if project.updated_at else None,
            }
            
            return jsonify({
                'success': True,
                'project': project_dict
            })
    except Exception as e:
        logger.error(f"Error getting project: {e}")
        logger.error(f'Internal error: {e}', exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@api_bp.route('/threat-models')
@login_required
def api_threat_models():
    """Get available threat models with categorization"""
    try:
        from utils.tools_utils import get_tools_by_category, get_all_tools_metadata
        
        tools = list_tools()
        tools_metadata = get_all_tools_metadata()
        tools_by_category = get_tools_by_category()
        
        # Create a mapping of tool names to their metadata
        tools_map = {tool['name']: tool for tool in tools_metadata}
        
        # Organize tools by category for better UX
        categorized = {}
        for category, category_tools in tools_by_category.items():
            categorized[category] = [
                {
                    'name': tool['name'],
                    'display_name': tool['display_name'],
                    'subcategory': tool.get('subcategory', 'General')
                }
                for tool in category_tools
            ]
        
        # Get list of available categories
        available_categories = sorted(categorized.keys())
        
        return jsonify({
            'tools': tools,  # Keep for backward compatibility
            'categorized': categorized,  # New grouped structure
            'tools_metadata': tools_map,  # Full metadata for each tool
            'categories': available_categories  # List of available categories for dynamic button generation
        })
    except Exception as e:
        logger.error(f"Error getting threat models: {e}")
        return jsonify({'tools': [], 'categorized': {}, 'tools_metadata': {}})


@api_bp.route('/project-directories', methods=['POST'])
@login_required
def api_get_project_directories():
    """Get directory structure for a project after cloning/unzipping as a tree"""
    try:
        data = request.get_json()
        if not data or not data.get('project_path'):
            return jsonify({'success': False, 'error': 'Project path is required'})
        
        project_path = data['project_path']

        # Security: restrict to allowed base directories only (prevent path traversal)
        import pathlib
        ALLOWED_BASES = [
            os.path.realpath('/var/www/scanner/codebases'),
            os.path.realpath('/var/www/scanner/uploads'),
            os.path.realpath('/tmp'),
        ]
        try:
            real_path = os.path.realpath(project_path)
        except Exception:
            return jsonify({'success': False, 'error': 'Invalid path'})

        if not any(real_path.startswith(base + os.sep) or real_path == base for base in ALLOWED_BASES):
            logger.warning(f'Path traversal attempt blocked: {project_path} -> {real_path}')
            return jsonify({'success': False, 'error': 'Access denied: path outside allowed directories'})

        if not os.path.exists(real_path):
            return jsonify({'success': False, 'error': 'Project path does not exist'})
        project_path = real_path
        
        def build_directory_tree(root_path, max_depth=20, current_depth=0):
            """Recursively build directory tree structure"""
            if current_depth >= max_depth:
                return None
            
            tree = {
                'name': os.path.basename(root_path),
                'path': os.path.relpath(root_path, project_path),
                'full_path': root_path,
                'children': [],
                'is_dir': True
            }
            
            try:
                items = sorted(os.listdir(root_path))
                for item in items:
                    item_path = os.path.join(root_path, item)
                    if os.path.isdir(item_path):
                        # Only skip hidden directories and very common build/cache directories
                        # Don't skip too many directories - let users decide what to exclude
                        if not item.startswith('.') and item not in ['node_modules', '__pycache__']:
                            child = build_directory_tree(item_path, max_depth, current_depth + 1)
                            if child:
                                tree['children'].append(child)
            except PermissionError:
                pass
            
            # Always return the tree node, even if it has no children
            return tree
        
        directory_tree = build_directory_tree(project_path)
        
        return jsonify({'success': True, 'tree': directory_tree})
    
    except Exception as e:
        logger.error(f"Error getting project directories: {e}")
        return jsonify({'success': False, 'error': str(e)})


@api_bp.route('/findings', methods=['GET'])
@login_required
def api_list_findings():
    """API endpoint to list findings with filtering"""
    try:
        orm = get_orm_instance()
        with orm.get_session() as session:
            # Get filter parameters
            project_id = request.args.get('project_id', type=int)
            severity = request.args.get('severity')
            status = request.args.get('status')
            search = request.args.get('search')
            file_path = request.args.get('file_path')
            limit = request.args.get('limit', 100, type=int)
            offset = request.args.get('offset', 0, type=int)
            
            # Build query
            query = session.query(Finding)
            
            # Multi-tenancy: filter by project owner unless admin
            if not current_user.is_admin:
                query = query.join(Project, Finding.project_id == Project.id).filter(Project.owner_id == current_user.id)
            
            # Apply filters
            if project_id:
                query = query.filter(Finding.project_id == project_id)
            if severity:
                try:
                    query = query.filter(Finding.severity == SeverityLevel(severity.lower()))
                except ValueError:
                    return jsonify({
                        'success': False,
                        'error': f'Invalid severity: {severity}',
                        'valid_values': [s.value for s in SeverityLevel]
                    }), 400
            if status:
                try:
                    query = query.filter(Finding.status == FindingStatus(status.lower()))
                except ValueError:
                    return jsonify({
                        'success': False,
                        'error': f'Invalid status: {status}',
                        'valid_values': [s.value for s in FindingStatus]
                    }), 400
            if search:
                query = query.filter(
                    Finding.title.ilike(f'%{search}%') |
                    Finding.description.ilike(f'%{search}%')
                )
            if file_path:
                query = query.filter(Finding.file_path.ilike(f'%{file_path}%'))
            
            # Get total count
            total = query.count()
            
            # Apply pagination and ordering
            findings = query.order_by(Finding.created_at.desc()).offset(offset).limit(limit).all()
            
            # Convert to dictionaries
            findings_list = [{
                'id': f.id,
                'title': f.title,
                'description': f.description,
                'recommendation': f.recommendation,
                'severity': f.severity.value if hasattr(f.severity, 'value') else f.severity,
                'status': f.status.value if hasattr(f.status, 'value') else f.status,
                'file_path': f.file_path,
                'impacted_files': f.impacted_files,
                'project_id': f.project_id,
                'resolved_at': f.resolved_at.isoformat() if f.resolved_at else None,
                'created_at': f.created_at.isoformat() if f.created_at else None,
                'updated_at': f.updated_at.isoformat() if f.updated_at else None,
            } for f in findings]
            
            return jsonify({
                'success': True,
                'findings': findings_list,
                'total': total,
                'limit': limit,
                'offset': offset
            })
    
    except Exception as e:
        logger.error(f"Error listing findings: {e}")
        logger.error(f'Internal error: {e}', exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@api_bp.route('/findings/<int:finding_id>', methods=['GET'])
@login_required
def api_get_finding(finding_id):
    """API endpoint to get a single finding by ID"""
    try:
        orm = get_orm_instance()
        with orm.get_session() as session:
            finding = orm.get_by_id(session, Finding, finding_id)
            if not finding:
                return jsonify({'success': False, 'error': 'Finding not found'}), 404
            if not current_user.is_admin and finding.project and finding.project.owner_id != current_user.id:
                return jsonify({'success': False, 'error': 'Access denied'}), 403
            
            # Convert to dictionary
            finding_dict = {
                'id': finding.id,
                'title': finding.title,
                'description': finding.description,
                'recommendation': finding.recommendation,
                'severity': finding.severity.value if hasattr(finding.severity, 'value') else finding.severity,
                'status': finding.status.value if hasattr(finding.status, 'value') else finding.status,
                'file_path': finding.file_path,
                'impacted_files': finding.impacted_files,
                'project_id': finding.project_id,
                'resolved_at': finding.resolved_at.isoformat() if finding.resolved_at else None,
                'created_at': finding.created_at.isoformat() if finding.created_at else None,
                'updated_at': finding.updated_at.isoformat() if finding.updated_at else None,
            }
            
            return jsonify({
                'success': True,
                'finding': finding_dict
            })
    
    except Exception as e:
        logger.error(f"Error getting finding: {e}")
        logger.error(f'Internal error: {e}', exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@api_bp.route('/findings/<int:finding_id>/status', methods=['PUT'])
@login_required
def api_update_finding_status(finding_id):
    """API endpoint to update finding status"""
    try:
        orm = get_orm_instance()
        with orm.get_session() as session:
            finding = orm.get_by_id(session, Finding, finding_id)
            if not finding:
                return jsonify({'success': False, 'error': 'Finding not found'})
            
            data = request.get_json()
            new_status = data.get('status')
            
            if new_status not in [status.value for status in FindingStatus]:
                return jsonify({'success': False, 'error': 'Invalid status'})
            
            finding.status = FindingStatus(new_status)
            if new_status == 'resolved':
                finding.resolved_at = datetime.utcnow()
            
            session.commit()
            return jsonify({'success': True})
    
    except Exception as e:
        logger.error(f"Error updating finding status: {e}")
        return jsonify({'success': False, 'error': str(e)})


@api_bp.route('/findings/<int:finding_id>', methods=['DELETE'])
@login_required
def api_delete_finding(finding_id):
    """API endpoint to delete a finding"""
    try:
        orm = get_orm_instance()
        with orm.get_session() as session:
            finding = orm.get_by_id(session, Finding, finding_id)
            if not finding:
                return jsonify({'success': False, 'error': 'Finding not found'})
            
            orm.delete(session, finding)
            return jsonify({'success': True})
    
    except Exception as e:
        logger.error(f"Error deleting finding: {e}")
        return jsonify({'success': False, 'error': str(e)})


@api_bp.route('/test-model-connection', methods=['POST'])
@login_required
def test_model_connection():
    """Test API connection for a specific AI model using LiteLLM.
    Accepts model_id only — API key is fetched server-side from DB, never from client."""
    try:
        import litellm
        from litellm import completion
        from utils.ai_models_utils import format_model_name_for_litellm

        data = request.get_json()
        model_id = data.get('model_id')

        if not model_id:
            return jsonify({'success': False, 'error': 'model_id is required'})

        # Fetch model + API key from DB — never trust client-supplied keys
        from utils.flask_helpers import get_orm_instance
        from db.models import AIModel
        orm = get_orm_instance()
        with orm.get_session() as session:
            model_obj = orm.get_by_id(session, AIModel, model_id)
            if not model_obj:
                return jsonify({'success': False, 'error': 'Model not found'})
            model_name = model_obj.model_name
            vendor = model_obj.vendor
            api_key = model_obj.api_key or ''

        if vendor.lower() != 'ollama' and not api_key:
            return jsonify({'success': False, 'error': 'No API key stored for this model'})
        
        # Create a simple object for formatting (mimics AIModel structure)
        class TempModel:
            def __init__(self, model_name, vendor):
                self.model_name = model_name
                self.vendor = vendor
        
        temp_model = TempModel(model_name, vendor)
        
        # Format model name using the helper function
        full_model_name = format_model_name_for_litellm(temp_model)
        
        # Handle Ollama separately (no API key needed)
        if vendor.lower() == 'ollama':
            # Set OLLAMA_API_BASE for LiteLLM if OLLAMA_BASE_URL is configured
            ollama_base_url = os.getenv('OLLAMA_BASE_URL', 'http://192.168.1.10:11434/')
            original_ollama_base = os.environ.get('OLLAMA_API_BASE')
            os.environ['OLLAMA_API_BASE'] = ollama_base_url
            
            try:
                # Test with a simple completion
                response = completion(
                    model=full_model_name,
                    messages=[{"role": "user", "content": "Hello, this is a test message. Please respond with 'Connection successful!'"}],
                    max_tokens=100,
                    timeout=1000
                )
                
                # Extract response content
                if response and response.choices:
                    response_text = response.choices[0].message.content
                    return jsonify({
                        'success': True, 
                        'message': 'Connection successful!',
                        'response': response_text,
                        'model_used': full_model_name,
                        'model_name': model_name
                    })
                else:
                    return jsonify({'success': False, 'error': 'No response received from model'})
                    
            except Exception as e:
                return jsonify({'success': False, 'error': f'Ollama connection failed: {str(e)}. Make sure Ollama is running at {ollama_base_url}'})
            
            finally:
                # Restore original OLLAMA_API_BASE
                if original_ollama_base:
                    os.environ['OLLAMA_API_BASE'] = original_ollama_base
                else:
                    os.environ.pop('OLLAMA_API_BASE', None)
        
        else:
            # Handle other vendors that require API keys
            # Map vendor to environment variable name
            from utils.ai_models_utils import AI_KEYS_MAPPING
            
            env_var = AI_KEYS_MAPPING.get(vendor.lower())
            if not env_var:
                return jsonify({'success': False, 'error': f'Unsupported vendor: {vendor}'})
            
            # Set the API key in environment
            original_key = os.environ.get(env_var)
            os.environ[env_var] = api_key
            
            try:
                # Test with a simple completion
                response = completion(
                    model=full_model_name,
                    messages=[{"role": "user", "content": "Hello, this is a test message. Please respond with 'Connection successful!'"}],
                    max_tokens=10,
                    timeout=10
                )
                
                # Extract response content
                if response and response.choices:
                    response_text = response.choices[0].message.content
                    return jsonify({
                        'success': True, 
                        'message': 'Connection successful!',
                        'response': response_text,
                        'model_used': full_model_name,
                        'model_name': model_name
                    })
                else:
                    return jsonify({'success': False, 'error': 'No response received from model'})
                    
            except Exception as e:
                return jsonify({'success': False, 'error': f'API call failed: {str(e)}'})
            
            finally:
                # Restore original API key
                if original_key:
                    os.environ[env_var] = original_key
                else:
                    os.environ.pop(env_var, None)
                
    except Exception as e:
        logger.error(f"Error testing model connection: {e}")
        return jsonify({'success': False, 'error': f'Test failed: {str(e)}'})


@api_bp.route('/validate-api-key', methods=['POST'])
@login_required
def validate_api_key_endpoint():
    """Validate API key format without making expensive API calls (cheap validation)"""
    try:
        data = request.get_json()
        vendor = data.get('vendor')
        api_key = data.get('api_key')
        
        if not vendor or not api_key:
            return jsonify({'success': False, 'error': 'Missing required fields: vendor and api_key are required'})
        
        # Import the validation function from centralized utils
        from utils.ai_models_utils import validate_api_key
        
        is_valid = validate_api_key(vendor, api_key)
        
        if is_valid:
            return jsonify({
                'success': True,
                'message': 'API key format is valid',
                'validation_type': 'format_check'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'API key format is invalid for this vendor',
                'validation_type': 'format_check'
            })
                
    except Exception as e:
        logger.error(f"Error validating API key: {e}")
        return jsonify({'success': False, 'error': f'Validation failed: {str(e)}'})


@api_bp.route('/findings/<int:finding_id>/check-confirmation/<int:model_id>', methods=['GET'])
@login_required
def api_check_confirmation_exists(finding_id, model_id):
    """Check if a confirmation already exists for a finding and model combination"""
    try:
        from db.models import Confirmation
        
        orm = get_orm_instance()
        with orm.get_session() as session:
            # Check if finding exists
            finding = orm.get_by_id(session, Finding, finding_id)
            if not finding:
                return jsonify({'success': False, 'error': 'Finding not found'})
            
            # Check if model exists
            model = orm.get_by_id(session, AIModel, model_id)
            if not model:
                return jsonify({'success': False, 'error': 'Model not found'})
            
            # Check if confirmation exists
            confirmation = session.query(Confirmation).filter_by(
                finding_id=finding_id,
                model_id=model_id
            ).first()
            
            if confirmation:
                return jsonify({
                    'success': True,
                    'exists': True,
                    'confirmation': {
                        'id': confirmation.id,
                        'false_positive': confirmation.false_positive,
                        'is_remote_attack': confirmation.is_remote_attack,
                        'created_at': confirmation.created_at.isoformat() if confirmation.created_at else None
                    }
                })
            else:
                return jsonify({
                    'success': True,
                    'exists': False
                })
    
    except Exception as e:
        logger.error(f"Error checking confirmation: {e}")
        return jsonify({'success': False, 'error': str(e)})


@api_bp.route('/findings/<int:finding_id>/start-validation', methods=['POST'])
@login_required
def api_start_validation(finding_id):
    """Start validation for a finding in background"""
    try:
        import subprocess
        import sys
        import psutil
        import shlex
        from pathlib import Path
        import re
        
        data = request.get_json()
        model_id = data.get('model_id')
        
        if not model_id:
            return jsonify({'success': False, 'error': 'Model ID is required'}), 400
        
        orm = get_orm_instance()
        with orm.get_session() as session:
            finding = orm.get_by_id(session, Finding, finding_id)
            if not finding:
                return jsonify({'success': False, 'error': 'Finding not found'}), 404
            
            model = orm.get_by_id(session, AIModel, model_id)
            if not model:
                return jsonify({'success': False, 'error': 'AI Model not found'}), 404
            
            # Get project for cost checking
            project = finding.project
            
            # Check if project's max_cost has already been exceeded
            try:
                project_max_cost = float(project.max_cost) if project.max_cost else 50.0
            except (TypeError, ValueError, AttributeError):
                project_max_cost = 50.0
            
            current_cost = 0.0
            if hasattr(project, "cost") and project.cost is not None:
                try:
                    current_cost = float(project.cost)
                except (TypeError, ValueError, AttributeError):
                    current_cost = 0.0
            
            if current_cost >= project_max_cost:
                return jsonify({
                    'success': False,
                    'error': f'Cannot start validation: Maximum cost limit exceeded. Current cost (${current_cost:.2f}) >= Maximum allowed cost (${project_max_cost:.2f}). Please increase the maximum cost limit in project settings to continue.'
                }), 400
            
            # Build the command
            base_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(base_dir)
            run_validator_forever_path = os.path.join(project_root, 'scripts', 'run_validator_forever.py')
            
            # Detect virtual environment Python path (cross-platform)
            if sys.platform == 'win32':
                # Windows: venv/Scripts/python.exe or env/Scripts/python.exe
                env_python = os.path.join(project_root, 'venv', 'Scripts', 'python.exe')
                if not os.path.exists(env_python):
                    env_python = os.path.join(project_root, 'env', 'Scripts', 'python.exe')
            else:
                # Unix-like: venv/bin/python or env/bin/python
                env_python = os.path.join(project_root, 'venv', 'bin', 'python')
                if not os.path.exists(env_python):
                    env_python = os.path.join(project_root, 'env', 'bin', 'python')
            
            # Use system python if venv python doesn't exist
            if not os.path.exists(env_python):
                # Try alternative names
                if sys.platform == 'win32':
                    # Try python.exe, python3.exe, or just python
                    for py_name in ['python.exe', 'python3.exe', 'python']:
                        try:
                            result = subprocess.run([py_name, '--version'], 
                                                  capture_output=True, timeout=1)
                            if result.returncode == 0:
                                env_python = py_name
                                break
                        except (subprocess.TimeoutExpired, FileNotFoundError):
                            continue
                    else:
                        env_python = 'python'
                else:
                    env_python = 'python3'
            
            # Verify paths exist
            if not os.path.exists(run_validator_forever_path):
                return jsonify({
                    'success': False,
                    'error': f'run_validator_forever.py not found at: {run_validator_forever_path}'
                }), 500
            
            # Build the base command with proper path quoting (cross-platform)
            if sys.platform == 'win32':
                # Windows: use list format for subprocess, no shell quoting needed
                base_command_parts = [env_python, run_validator_forever_path, '--finding-id', str(finding_id), '--model-id', str(model_id)]
                base_command = ' '.join(f'"{part}"' if ' ' in part else part for part in base_command_parts)
            else:
                # Unix-like: use shlex.quote for shell safety
                quoted_python = shlex.quote(env_python)
                quoted_script = shlex.quote(run_validator_forever_path)
                base_command = f'{quoted_python} {quoted_script} --finding-id {finding_id} --model-id {model_id}'
            
            # Log the command that will be executed
            logger.info(f"Preparing to execute validation command: {base_command}")
            logger.info(f"Python path: {env_python} (exists: {os.path.exists(env_python)})")
            logger.info(f"Script path: {run_validator_forever_path} (exists: {os.path.exists(run_validator_forever_path)})")
            
            # Check if process is already running - must match both finding_id and model_id
            running_process = None
            log_file = os.path.join(project_root, 'logs', f'validate_{finding_id}_{model_id}.log')
            
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
                try:
                    cmdline = proc.info.get('cmdline', [])
                    if not cmdline:
                        continue
                    
                    # Check if this is a run_validator_forever.py or run_validator.py process
                    has_run_validator_forever = any('run_validator_forever.py' in str(arg) for arg in cmdline)
                    has_run_validator = any('run_validator.py' in str(arg) for arg in cmdline)
                    if not (has_run_validator_forever or has_run_validator):
                        continue
                    
                    # Build command line string for matching
                    cmdline_str = ' '.join(str(arg) for arg in cmdline)
                    
                    # Must match both finding-id and model-id exactly
                    finding_match = f'--finding-id {finding_id}' in cmdline_str or f'--finding-id={finding_id}' in cmdline_str or f'-f {finding_id}' in cmdline_str
                    model_match = f'--model-id {model_id}' in cmdline_str or f'--model-id={model_id}' in cmdline_str or f'-m {model_id}' in cmdline_str
                    
                    if finding_match and model_match:
                        running_process = proc
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            if running_process:
                # Get output from log file if it exists
                output_lines = []
                try:
                    output_lines.append('Validation process is currently running...')
                    output_lines.append(f'Process ID: {running_process.info["pid"]}')
                    import datetime
                    start_time = datetime.datetime.fromtimestamp(running_process.info.get('create_time', 0))
                    output_lines.append(f'Started: {start_time.strftime("%Y-%m-%d %H:%M:%S")}')
                    
                    # Try to read last few lines from log file
                    if os.path.exists(log_file):
                        try:
                            with open(log_file, 'r') as f:
                                lines = f.readlines()
                                if lines:
                                    output_lines.append('\n--- Last 10 lines from log ---')
                                    output_lines.extend(lines[-10:])
                        except Exception:
                            pass
                except Exception as e:
                    output_lines = ['Validation is already running']
                
                return jsonify({
                    'success': True,
                    'already_running': True,
                    'output': '\n'.join(output_lines)
                })
            
            # Start the validation in background
            try:
                # Create log file directory if it doesn't exist
                log_dir = os.path.dirname(log_file)
                if log_dir and not os.path.exists(log_dir):
                    os.makedirs(log_dir, exist_ok=True)
                
                # Log the command that will be executed BEFORE executing
                logger.info(f"=== VALIDATION COMMAND PREVIEW ===")
                logger.info(f"Base command: {base_command}")
                logger.info(f"Working directory: {project_root} (exists: {os.path.exists(project_root)})")
                logger.info(f"Log file: {log_file}")
                
                # Start the process (cross-platform)
                # Build command list
                cmd_list = [env_python, run_validator_forever_path, '--finding-id', str(finding_id), '--model-id', str(model_id)]
                
                logger.info(f"Final command to execute: {base_command}")
                logger.info(f"=== EXECUTING COMMAND NOW ===")
                
                # Open log file for writing
                log_handle = open(log_file, 'a', encoding='utf-8')
                
                if sys.platform == 'win32':
                    # Windows - use detached process
                    process = subprocess.Popen(
                        cmd_list,
                        cwd=project_root,
                        stdout=log_handle,
                        stderr=subprocess.STDOUT,
                        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS,
                        close_fds=False  # Windows doesn't support close_fds=True
                    )
                else:
                    # Unix-like system - use start_new_session to detach from parent
                    process = subprocess.Popen(
                        cmd_list,
                        cwd=project_root,
                        stdout=log_handle,
                        stderr=subprocess.STDOUT,
                        start_new_session=True,  # Detach from parent process
                        close_fds=True
                    )
                
                log_handle.close()
                
                # Get the actual PID from the background process (may need to wait a moment)
                import time
                time.sleep(0.1)  # Brief wait to let process start
                
                # Try to get the actual PID of the run_validator_forever.py process
                actual_pid = None
                try:
                    # The process we started is the shell, find the actual python process
                    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                        try:
                            cmdline = proc.info.get('cmdline', [])
                            if cmdline and any('run_validator_forever.py' in str(arg) for arg in cmdline):
                                cmdline_str = ' '.join(str(arg) for arg in cmdline)
                                if f'--finding-id {finding_id}' in cmdline_str and f'--model-id {model_id}' in cmdline_str:
                                    actual_pid = proc.info['pid']
                                    break
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                except Exception:
                    pass
                
                logger.info(f"Process started. Shell PID: {process.pid}, Run Validator Forever PID: {actual_pid}")
                
                # Build display command (the actual command that runs)
                display_command = base_command
                
                return jsonify({
                    'success': True,
                    'already_running': False,
                    'message': 'Validation started successfully',
                    'command': display_command,
                    'base_command': base_command,
                    'log_file': log_file,
                    'pid': actual_pid or process.pid,
                    'finding_id': finding_id,
                    'model_id': model_id
                })
            except Exception as e:
                logger.error(f"Error starting validation: {e}")
                return jsonify({
                    'success': False,
                    'error': f'Failed to start validation: {str(e)}'
                }), 500
                
    except Exception as e:
        logger.error(f"Error in start_validation: {e}")
        return jsonify({
            'success': False,
            'error': f'Error starting validation: {str(e)}'
        }), 500


@api_bp.route('/projects/<int:project_id>/start-bulk-validation', methods=['POST'])
@login_required
def api_start_bulk_validation(project_id):
    """Start validation for all unconfirmed findings in a project"""
    try:
        import subprocess
        import sys
        import psutil
        import shlex
        from pathlib import Path
        import re
        
        data = request.get_json()
        model_id = data.get('model_id')
        
        if not model_id:
            return jsonify({'success': False, 'error': 'Model ID is required'}), 400
        
        orm = get_orm_instance()
        with orm.get_session() as session:
            # Get project and model
            project = session.query(Project).filter_by(id=project_id).first()
            if not project:
                return jsonify({'success': False, 'error': 'Project not found'}), 404
                
            model = session.query(AIModel).filter_by(id=model_id).first()
            if not model:
                return jsonify({'success': False, 'error': 'Model not found'}), 404
            
            # Count findings that need validation (don't have confirmation from this model)
            from db.models import Finding, Confirmation
            from sqlalchemy import and_, not_, exists
            
            # Subquery to find findings that already have confirmation from this model
            confirmed_finding_ids = session.query(Confirmation.finding_id).filter(
                Confirmation.model_id == model_id
            ).subquery()
            
            # Count unconfirmed findings for this project
            unconfirmed_count = session.query(Finding).filter(
                and_(
                    Finding.project_id == project_id,
                    ~Finding.id.in_(confirmed_finding_ids)
                )
            ).count()
            
            total_findings = session.query(Finding).filter_by(project_id=project_id).count()
            
            if unconfirmed_count == 0:
                return jsonify({
                    'success': False, 
                    'error': f'All {total_findings} findings have already been validated by this model'
                }), 400
            
            # Check if project max cost is set and if we're already over
            if project.max_cost is not None and project.cost is not None:
                if project.cost >= project.max_cost:
                    return jsonify({
                        'success': False,
                        'error': f'Project has reached maximum cost limit (${project.max_cost:.2f})'
                    }), 400
            
            # Build command for run_validator_forever.py with --project-id
            project_root = Path(__file__).parent.parent.resolve()
            scripts_dir = project_root / 'scripts'
            
            # Check for virtual environment
            if sys.platform == 'win32':
                env_python = project_root / 'env' / 'Scripts' / 'python.exe'
            else:
                env_python = project_root / 'env' / 'bin' / 'python3'
            
            python_executable = str(env_python) if env_python.exists() else sys.executable
            
            # Build command
            script_path = scripts_dir / 'run_validator_forever.py'
            command = [
                python_executable,
                str(script_path),
                '--project-id', str(project_id),
                '--model-id', str(model_id)
            ]
            
            # Log file path for bulk validation
            log_file = project_root / 'logs' / f'bulk_validate_{project_id}_{model_id}.log'
            log_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Check if bulk validation is already running for this project+model
            for proc in psutil.process_iter(['pid', 'cmdline']):
                try:
                    cmdline = proc.info.get('cmdline')
                    if cmdline:
                        cmdline_str = ' '.join(cmdline)
                        if 'run_validator' in cmdline_str:
                            if f'--project-id' in cmdline_str and str(project_id) in cmdline_str:
                                if f'--model-id' in cmdline_str and str(model_id) in cmdline_str:
                                    return jsonify({
                                        'success': False,
                                        'already_running': True,
                                        'error': f'Bulk validation already running for this project with this model',
                                        'pid': proc.info['pid']
                                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            # Start the process in background
            try:
                with open(log_file, 'w') as f:
                    f.write(f"Starting bulk validation for project {project_id} with model {model_id}\n")
                    f.write(f"Findings to validate: {unconfirmed_count} out of {total_findings}\n")
                    f.write(f"Command: {' '.join(command)}\n")
                    f.write("-" * 80 + "\n")
                
                # Open log file for appending
                log_handle = open(log_file, 'a')
                
                # Start subprocess
                if sys.platform == 'win32':
                    process = subprocess.Popen(
                        command,
                        stdout=log_handle,
                        stderr=subprocess.STDOUT,
                        cwd=str(project_root),
                        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
                    )
                else:
                    process = subprocess.Popen(
                        command,
                        stdout=log_handle,
                        stderr=subprocess.STDOUT,
                        cwd=str(project_root),
                        start_new_session=True
                    )
                
                # Get actual child PID
                actual_pid = None
                time.sleep(0.5)
                for proc in psutil.process_iter(['pid', 'cmdline', 'ppid']):
                    try:
                        cmdline = proc.info.get('cmdline')
                        if cmdline and 'run_validator.py' in ' '.join(cmdline):
                            if f'--project-id' in ' '.join(cmdline) and str(project_id) in ' '.join(cmdline):
                                actual_pid = proc.info['pid']
                                break
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                # Format display command
                display_command = f"python run_validator.py --project-id {project_id} --model-id {model_id}"
                
                return jsonify({
                    'success': True,
                    'message': f'Bulk validation started for {unconfirmed_count} findings',
                    'command': display_command,
                    'log_file': str(log_file),
                    'pid': actual_pid or process.pid,
                    'project_id': project_id,
                    'model_id': model_id,
                    'unconfirmed_count': unconfirmed_count,
                    'total_findings': total_findings
                })
                
            except Exception as e:
                logger.error(f"Error starting bulk validation: {e}")
                return jsonify({
                    'success': False,
                    'error': f'Failed to start bulk validation: {str(e)}'
                }), 500
                
    except Exception as e:
        logger.error(f"Error in start_bulk_validation: {e}")
        return jsonify({
            'success': False,
            'error': f'Error starting bulk validation: {str(e)}'
        }), 500



@api_bp.route('/projects/<int:project_id>/scan-complete', methods=['POST'])
@login_required
def api_scan_complete(project_id):
    """Notify scan completion - called by scan subprocess"""
    try:
        orm = get_orm_instance()
        with orm.get_session() as session:
            project = orm.get_by_id(session, Project, project_id)
            if not project:
                return jsonify({'success': False, 'error': 'Project not found'}), 404

            # Get owner user for notifications
            if project.owner_id:
                from db.models import User
                owner = session.query(User).filter_by(id=project.owner_id).first()
                if owner and owner.email and owner.notify_scan_complete:
                    from utils.email_notifications import notify_scan_complete
                    findings = project.findings or []
                    total = len(findings)
                    critical = sum(1 for f in findings if hasattr(f.severity, 'value') and f.severity.value == 'critical')
                    try:
                        notify_scan_complete(owner.email, project.name, total, critical, project_id)
                    except Exception as notify_err:
                        logger.warning(f'Scan complete notification failed: {notify_err}')

            return jsonify({'success': True, 'message': 'Scan complete notification processed'})
    except Exception as e:
        logger.error(f'Error in scan_complete endpoint: {e}')
        logger.error(f'Internal error: {e}', exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500
