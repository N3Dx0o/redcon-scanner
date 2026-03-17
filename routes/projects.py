"""Project-related routes"""
from flask_login import login_required, current_user
from flask import render_template, request, redirect, url_for, flash, jsonify
from routes import projects_bp
from utils.flask_helpers import get_orm_instance
from db.models import Project, AIModel, InputType, ProjectStatus, Fact, FactType
from utils.project_utils import (
    clone_git_repository, extract_zip_file, clone_git_repository_temp,
    extract_zip_file_temp, validate_git_url, is_zip_file, filter_target_dirs
)
from utils.git_utils import get_git_info, is_git_repository, checkout_branch, get_all_branches
from werkzeug.utils import secure_filename
import os
import sys
import uuid
import shutil
import logging
import subprocess
import shlex
import re
import psutil

logger = logging.getLogger(__name__)


@projects_bp.route('/projects/onboard', methods=['GET', 'POST'])
@login_required
def project_onboarding():
    """New project onboarding flow"""
    if request.method == 'GET':
        return render_template('project_onboarding.html')
    
    try:
        orm = get_orm_instance()
        with orm.get_session() as session:
            # Get form data
            project_name = request.form.get('project_name')
            input_type = request.form.get('input_type')
            status = request.form.get('status', 'active')
            max_cost = request.form.get('max_cost')
            ai_models = request.form.getlist('ai_models')
            threat_models = request.form.getlist('threat_models')
            
            # Validate required fields
            if not project_name:
                return jsonify({'success': False, 'error': 'Project name is required'})
            
            # This is the final project creation
            # Process from scratch for final creation
            base_path = None
            zip_file_path = None
            git_link = None
            
            if input_type == 'zip_file':
                if 'zip_file' not in request.files:
                    return jsonify({'success': False, 'error': 'No file uploaded'})
                
                file = request.files['zip_file']
                if file.filename == '':
                    return jsonify({'success': False, 'error': 'No file selected'})
                
                if file and is_zip_file(file.filename):
                    # Save uploaded file
                    filename = secure_filename(file.filename)
                    upload_dir = 'uploads'
                    os.makedirs(upload_dir, exist_ok=True)
                    zip_file_path = os.path.join(upload_dir, filename)
                    file.save(zip_file_path)
                    
                    # Extract zip file
                    extract_dir = os.path.join('codebases', str(uuid.uuid4())[:6])
                    os.makedirs(extract_dir, exist_ok=True)
                    base_path = extract_zip_file(zip_file_path, extract_dir)
                else:
                    return jsonify({'success': False, 'error': 'Invalid file type'})
            
            elif input_type == 'git_link':
                git_url = request.form.get('git_url')
                if not git_url:
                    return jsonify({'success': False, 'error': 'Git URL is required'})
                
                if not validate_git_url(git_url):
                    return jsonify({'success': False, 'error': 'Invalid Git URL'})
                
                # Clone repository
                extract_dir = os.path.join('codebases', str(uuid.uuid4())[:6])
                os.makedirs(extract_dir, exist_ok=True)
                base_path = clone_git_repository(git_url, extract_dir)
                git_link = git_url
                
                if not base_path:
                    return jsonify({'success': False, 'error': 'Failed to process project source'})
            
            # Create project
            try:
                project_data = {
                    'name': project_name,
                    'base_path': base_path,
                    'zip_file_path': zip_file_path,
                    'git_link': git_link,
                    'input_type': InputType(input_type),
                    'status': ProjectStatus(status),
                    'max_cost': float(max_cost) if max_cost else None,
                    'excluded_dirs': [],
                    'threat_models': threat_models
                }
                
                project = orm.create(session, Project, **project_data)
                project.owner_id = current_user.id
                
                # Associate AI models
                if ai_models:
                    ai_model_objects = []
                    for model_id in ai_models:
                        model = orm.get_by_id(session, AIModel, int(model_id))
                        if model:
                            ai_model_objects.append(model)
                    
                    if ai_model_objects:
                        project.ai_models = ai_model_objects
                
                return jsonify({'success': True, 'project_id': project.id})
                
            except Exception as project_error:
                # Clean up temporary directories if project creation fails
                try:
                    if base_path and os.path.exists(base_path):
                        shutil.rmtree(base_path)
                        logger.info(f"Cleaned up temporary directory: {base_path}")
                except Exception as cleanup_error:
                    logger.warning(f"Failed to clean up temporary directory {base_path}: {cleanup_error}")
                
                # Re-raise the original project creation error
                raise project_error
    
    except Exception as e:
        logger.error(f"Error in project onboarding: {e}")
        return jsonify({'success': False, 'error': str(e)})


def calculate_confirmation_insights(findings):
    """
    Calculate confirmation insights for a list of findings.
    
    Returns dict with:
    - confirmed_bugs: Findings where ALL confirmations agree it's a real vulnerability
    - confirmed_false_positives: Findings where ALL confirmations agree it's a false positive
    - conflicting: Findings where confirmations have mixed results
    - pending_validation: Findings with no confirmations
    - total_confirmations: Total number of confirmations across all findings
    - models_used: Set of unique model IDs that provided confirmations
    """
    insights = {
        'confirmed_bugs': 0,           # All models agree: real bug
        'confirmed_false_positives': 0, # All models agree: false positive
        'conflicting': 0,              # Models disagree
        'pending_validation': 0,       # No confirmations yet
        'total_confirmations': 0,
        'models_used': set(),
        'findings_detail': []          # Detailed info per finding
    }
    
    for finding in findings:
        confirmations = getattr(finding, 'confirmations', [])
        
        if not confirmations:
            insights['pending_validation'] += 1
            insights['findings_detail'].append({
                'finding_id': finding.id,
                'title': finding.title,
                'severity': finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                'status': 'pending',
                'confirmation_count': 0,
                'false_positive_votes': 0,
                'real_bug_votes': 0
            })
        else:
            insights['total_confirmations'] += len(confirmations)
            
            false_positive_votes = sum(1 for c in confirmations if c.false_positive)
            real_bug_votes = len(confirmations) - false_positive_votes
            
            for c in confirmations:
                insights['models_used'].add(c.model_id)
            
            # Determine consensus
            if false_positive_votes == len(confirmations):
                # All agree it's false positive
                insights['confirmed_false_positives'] += 1
                status = 'false_positive'
            elif real_bug_votes == len(confirmations):
                # All agree it's a real bug
                insights['confirmed_bugs'] += 1
                status = 'confirmed_bug'
            else:
                # Mixed results
                insights['conflicting'] += 1
                status = 'conflicting'
            
            insights['findings_detail'].append({
                'finding_id': finding.id,
                'title': finding.title,
                'severity': finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                'status': status,
                'confirmation_count': len(confirmations),
                'false_positive_votes': false_positive_votes,
                'real_bug_votes': real_bug_votes
            })
    
    # Convert set to count
    insights['unique_models_count'] = len(insights['models_used'])
    insights['models_used'] = list(insights['models_used'])
    
    return insights


@projects_bp.route('/projects/<int:project_id>')
@login_required
def view_project(project_id):
    """View project details (with analytics that require nested eager load of models)."""
    try:
        from sqlalchemy.orm import joinedload
        from db.models import Finding, Confirmation
        
        orm = get_orm_instance()
        with orm.get_session() as session:
            # Eager load findings, their confirmed_models, and confirmations
            project = session.query(Project) \
                .options(joinedload(Project.findings).joinedload(Finding.confirmed_models)) \
                .options(joinedload(Project.findings).joinedload(Finding.confirmations).joinedload(Confirmation.model)) \
                .options(joinedload(Project.ai_models)) \
                .options(joinedload(Project.facts)) \
                .filter(Project.id == project_id).first()
            if not project:
                flash('Project not found', 'error')
                return redirect(url_for('home.index'))
            # Ownership check (multi-tenancy)
            if project.owner_id is not None and project.owner_id != current_user.id and not current_user.is_admin:
                from flask import abort
                return abort(403)
            stats = orm.get_project_stats(session, project_id)
            findings = project.findings or []
            per_model = {}
            file_counts = {}
            severity_counts = {}
            for finding in findings:
                fp = finding.file_path
                if fp:
                    file_counts[fp] = file_counts.get(fp, 0) + 1
                sev = getattr(finding.severity, 'value', str(finding.severity))
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                for m in getattr(finding, 'confirmed_models', []):
                    mid = m.id
                    if mid not in per_model:
                        per_model[mid] = {
                            'model_name': m.model_name,
                            'vendor': m.vendor,
                            'severities': {},
                            'total': 0
                        }
                    per_model[mid]['total'] += 1
                    per_model[mid]['severities'][sev] = per_model[mid]['severities'].get(sev, 0) + 1
            top_files = sorted(file_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            analytics = {
                'by_model': list(per_model.values()),
                'severity_counts': severity_counts,
                'file_counts': file_counts,
                'top_files': top_files,
            }
            
            # Calculate confirmation insights
            confirmation_insights = calculate_confirmation_insights(findings)
            
            # Get filtered target directories for scanning
            filtered_dirs = []
            try:
                if project.base_path and os.path.exists(project.base_path):
                    excluded_dirs = project.excluded_dirs or []
                    included_dirs = project.included_dirs or []
                    filtered_dirs = filter_target_dirs(project.base_path, excluded_dirs, included_dirs)
                    filtered_dirs.sort()  # Sort for better display
            except Exception as e:
                logger.warning(f"Error getting filtered directories: {e}")
                filtered_dirs = []
            
            # Group facts by type
            facts_by_type = {}
            all_facts = project.facts or []
            for fact in all_facts:
                fact_type_value = fact.type.value if hasattr(fact.type, 'value') else str(fact.type)
                if fact_type_value not in facts_by_type:
                    facts_by_type[fact_type_value] = []
                facts_by_type[fact_type_value].append(fact)
            
            # Sort facts within each type by created_at (newest first)
            for fact_type in facts_by_type:
                facts_by_type[fact_type].sort(key=lambda f: f.created_at, reverse=True)
            
            # Define fact type metadata for display
            fact_type_meta = {
                'architecture': {'icon': 'bi-diagram-3', 'color': 'primary', 'label': 'Architecture'},
                'attack_surface': {'icon': 'bi-bullseye', 'color': 'danger', 'label': 'Attack Surface'},
                'dependency': {'icon': 'bi-box-seam', 'color': 'warning', 'label': 'Dependencies'},
                'data_flow': {'icon': 'bi-arrow-left-right', 'color': 'info', 'label': 'Data Flow'},
                'access_control': {'icon': 'bi-key', 'color': 'success', 'label': 'Access Control'},
                'dangerous_function': {'icon': 'bi-exclamation-triangle', 'color': 'danger', 'label': 'Dangerous Functions'},
                'validation': {'icon': 'bi-check-circle', 'color': 'warning', 'label': 'Validation'},
                'cryptography': {'icon': 'bi-shield-lock', 'color': 'info', 'label': 'Cryptography'},
                'state_logic': {'icon': 'bi-gear', 'color': 'secondary', 'label': 'State & Logic'},
                'external_interaction': {'icon': 'bi-cloud-arrow-up-down', 'color': 'primary', 'label': 'External Interactions'},
                'threat_model': {'icon': 'bi-shield-exclamation', 'color': 'danger', 'label': 'Threat Model'},
            }
            
            # Compute fact insights
            total_fact_types = len(fact_type_meta)
            covered_types = len(facts_by_type)
            coverage_pct = int((covered_types / total_fact_types) * 100) if total_fact_types > 0 else 0
            
            # Security-critical facts (attack surface, dangerous functions, cryptography)
            security_critical_types = ['attack_surface', 'dangerous_function', 'cryptography', 'validation']
            security_facts_count = sum(len(facts_by_type.get(t, [])) for t in security_critical_types)
            
            # Get latest fact timestamp
            latest_fact = None
            if all_facts:
                latest_fact = max(all_facts, key=lambda f: f.created_at)
            
            fact_insights = {
                'total': len(all_facts),
                'covered_types': covered_types,
                'total_types': total_fact_types,
                'coverage_pct': coverage_pct,
                'security_critical_count': security_facts_count,
                'latest_fact': latest_fact,
                'type_counts': {t: len(facts) for t, facts in facts_by_type.items()},
            }
            
            # Get git information if this is a git project
            git_info = None
            if project.base_path and os.path.exists(project.base_path):
                if is_git_repository(project.base_path):
                    git_info = get_git_info(project.base_path)
                    if git_info:
                        logger.info(f"Git info for project {project_id}: branch={git_info.get('current_branch')}, commit={git_info.get('commit_hash_short')}")
            
            return render_template('project_detail.html', 
                                 project=project, 
                                 stats=stats, 
                                 analytics=analytics, 
                                 filtered_dirs=filtered_dirs,
                                 confirmation_insights=confirmation_insights,
                                 facts_by_type=facts_by_type,
                                 fact_type_meta=fact_type_meta,
                                 total_facts=len(all_facts),
                                 fact_insights=fact_insights,
                                 git_info=git_info)
    except Exception as e:
        logger.error(f"Error viewing project: {e}")
        flash('Error loading project', 'error')
        return redirect(url_for('home.index'))


@projects_bp.route('/projects/<int:project_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_project(project_id):
    """Edit project"""
    try:
        orm = get_orm_instance()
        with orm.get_session() as session:
            project = orm.get_by_id_with_relations(session, Project, project_id, ['ai_models'])
            if not project:
                flash('Project not found', 'error')
                return redirect(url_for('home.index'))
            
            # Ownership check (multi-tenancy)
            if project.owner_id is not None and project.owner_id != current_user.id and not current_user.is_admin:
                from flask import abort
                return abort(403)
            if request.method == 'POST':
                # Handle git branch change if requested
                git_branch = request.form.get('git_branch')
                if git_branch and project.base_path and is_git_repository(project.base_path):
                    git_info = get_git_info(project.base_path)
                    current_branch = git_info.get('current_branch') if git_info else None
                    
                    # Only checkout if branch is different
                    if current_branch and git_branch != current_branch:
                        success, message = checkout_branch(project.base_path, git_branch)
                        if success:
                            flash(message, 'success')
                            logger.info(f"Switched branch for project {project_id} to {git_branch}")
                        else:
                            flash(f"Failed to switch branch: {message}", 'error')
                            logger.error(f"Failed to switch branch for project {project_id}: {message}")
                
                # Update project
                project.name = request.form.get('name', project.name)
                project.status = ProjectStatus(request.form.get('status', project.status.value))
                
                # Update max cost
                max_cost = request.form.get('max_cost')
                project.max_cost = float(max_cost) if max_cost else None
                
                # Update included directories
                included_dirs = request.form.get('included_dirs', '')
                if included_dirs:
                    # Split by comma and filter out empty strings
                    project.included_dirs = [d.strip() for d in included_dirs.split(',') if d.strip()]
                else:
                    # Empty string means user cleared all selections
                    project.included_dirs = []
                
                # Update excluded directories
                # The hidden input is always initialized with current excluded_dirs on page load
                # If it's empty, it means user cleared all selections (which is valid)
                excluded_dirs = request.form.get('excluded_dirs', '')
                if excluded_dirs:
                    # Split by comma and filter out empty strings
                    project.excluded_dirs = [d.strip() for d in excluded_dirs.split(',') if d.strip()]
                else:
                    # Empty string means user cleared all selections
                    project.excluded_dirs = []
                
                # Update AI models
                ai_models = request.form.getlist('ai_models')
                if ai_models:
                    ai_model_objects = []
                    for model_id in ai_models:
                        model = orm.get_by_id(session, AIModel, int(model_id))
                        if model:
                            ai_model_objects.append(model)
                    project.ai_models = ai_model_objects
                else:
                    project.ai_models = []
                
                # Update threat models
                threat_models = request.form.getlist('threat_models')
                project.threat_models = threat_models
                
                session.commit()
                flash('Project updated successfully', 'success')
                return redirect(url_for('projects.view_project', project_id=project_id))
            
            # Get git info for GET request
            git_info = None
            if project.base_path and os.path.exists(project.base_path):
                if is_git_repository(project.base_path):
                    git_info = get_git_info(project.base_path)
            
            return render_template('edit_project.html', project=project, git_info=git_info)
    except Exception as e:
        logger.error(f"Error editing project: {e}")
        flash('Error editing project', 'error')
        return redirect(url_for('home.index'))


@projects_bp.route('/projects/<int:project_id>/delete', methods=['POST'])
@login_required
def delete_project(project_id):
    """Delete project and all associated codebase files"""
    try:
        orm = get_orm_instance()
        with orm.get_session() as session:
            project = orm.get_by_id(session, Project, project_id)
            if not project:
                flash('Project not found', 'error')
                return redirect(url_for('home.index'))
            if project.owner_id is not None and project.owner_id != current_user.id and not current_user.is_admin:
                flash('Access denied', 'error')
                return redirect(url_for('home.index'))
            
            # Delete codebase files (base_path contains the extracted/cloned codebase)
            if project.base_path and os.path.exists(project.base_path):
                try:
                    shutil.rmtree(project.base_path)
                    logger.info(f"Deleted codebase directory: {project.base_path}")
                    
                    # Try to clean up parent directory if it's empty
                    parent_dir = os.path.dirname(project.base_path)
                    if parent_dir and parent_dir != '.' and os.path.exists(parent_dir):
                        try:
                            # Check if parent directory is empty
                            if not os.listdir(parent_dir):
                                os.rmdir(parent_dir)
                                logger.info(f"Cleaned up empty parent directory: {parent_dir}")
                        except OSError:
                            # Parent directory not empty or other error - ignore
                            pass
                except Exception as e:
                    logger.warning(f"Error deleting codebase directory {project.base_path}: {e}")
            
            # Delete uploaded zip file if it exists
            if project.zip_file_path and os.path.exists(project.zip_file_path):
                try:
                    os.remove(project.zip_file_path)
                    logger.info(f"Deleted zip file: {project.zip_file_path}")
                except Exception as e:
                    logger.warning(f"Error deleting zip file {project.zip_file_path}: {e}")
            
            # Delete project from database
            orm.delete(session, project)
            flash('Project deleted successfully', 'success')
    
    except Exception as e:
        logger.error(f"Error deleting project: {e}")
        flash('Error deleting project', 'error')
    
    return redirect(url_for('home.index'))


@projects_bp.route('/projects/<int:project_id>/resync', methods=['POST'])
@login_required
def resync_project(project_id):
    """Resync a git project by removing it and re-cloning"""
    try:
        orm = get_orm_instance()
        with orm.get_session() as session:
            project = orm.get_by_id(session, Project, project_id)
            if not project:
                return jsonify({'success': False, 'error': 'Project not found'}), 404
            
            # Only allow resync for git projects
            if project.owner_id is not None and project.owner_id != current_user.id and not current_user.is_admin:
                return jsonify({'success': False, 'error': 'Access denied'}), 403
            if not project.git_link or project.input_type != InputType.GIT_LINK:
                return jsonify({'success': False, 'error': 'Resync is only available for git projects'}), 400
            
            # Validate git URL
            if not validate_git_url(project.git_link):
                return jsonify({'success': False, 'error': 'Invalid git URL'}), 400
            
            # Store the old base_path and parent directory for cleanup
            old_base_path = project.base_path
            old_parent_dir = os.path.dirname(old_base_path) if old_base_path else None
            
            # Delete the old codebase directory
            if old_base_path and os.path.exists(old_base_path):
                try:
                    shutil.rmtree(old_base_path)
                    logger.info(f"Deleted old codebase directory: {old_base_path}")
                    
                    # Try to clean up parent directory if it's empty
                    if old_parent_dir and old_parent_dir != '.' and os.path.exists(old_parent_dir):
                        try:
                            if not os.listdir(old_parent_dir):
                                os.rmdir(old_parent_dir)
                                logger.info(f"Cleaned up empty parent directory: {old_parent_dir}")
                        except OSError:
                            # Parent directory not empty or other error - ignore
                            pass
                except Exception as e:
                    logger.warning(f"Error deleting old codebase directory {old_base_path}: {e}")
                    # Continue with resync even if deletion fails
            
            # Re-clone the repository
            try:
                # Use the same parent directory structure as original onboarding
                extract_dir = os.path.join('codebases', str(uuid.uuid4())[:6])
                os.makedirs(extract_dir, exist_ok=True)
                new_base_path = clone_git_repository(project.git_link, extract_dir)
                
                if not new_base_path:
                    return jsonify({'success': False, 'error': 'Failed to clone repository'}), 500
                
                # Update project with new base_path
                project.base_path = new_base_path
                session.commit()
                
                logger.info(f"Successfully resynced project {project_id}: {project.name}")
                return jsonify({
                    'success': True,
                    'message': 'Project resynced successfully',
                    'new_base_path': new_base_path
                })
                
            except Exception as clone_error:
                logger.error(f"Error cloning repository during resync: {clone_error}")
                return jsonify({
                    'success': False,
                    'error': f'Failed to clone repository: {str(clone_error)}'
                }), 500
                
    except Exception as e:
        logger.error(f"Error resyncing project: {e}")
        return jsonify({
            'success': False,
            'error': f'Error resyncing project: {str(e)}'
        }), 500


@projects_bp.route('/projects/<int:project_id>/start-scan', methods=['POST'])
@login_required
def start_scan(project_id):
    """Start a security scan for a project"""
    try:
        data = request.get_json()
        model_id = data.get('model_id')
        
        if not model_id:
            return jsonify({'success': False, 'error': 'Model ID is required'}), 400

        # Block scan if no AI models exist at all
        _orm_check = get_orm_instance()
        with _orm_check.get_session() as _sess:
            from db.models import AIModel as _AIModel
            _model_count = _sess.query(_AIModel).count()
        if _model_count == 0:
            return jsonify({
                'success': False,
                'error': 'No AI models configured. Please add an API key in AI Models settings before scanning.'
            }), 400
        
        orm = get_orm_instance()
        with orm.get_session() as session:
            project = orm.get_by_id(session, Project, project_id)
            if not project:
                return jsonify({'success': False, 'error': 'Project not found'}), 404
            # Ownership check (multi-tenancy)
            if project.owner_id is not None and project.owner_id != current_user.id and not current_user.is_admin:
                return jsonify({'success': False, 'error': 'Access denied'}), 403
            
            model = orm.get_by_id(session, AIModel, model_id)
            if not model:
                return jsonify({'success': False, 'error': 'AI Model not found'}), 404
            
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
                    'error': f'Cannot start scan: Maximum cost limit exceeded. Current cost (${current_cost:.2f}) >= Maximum allowed cost (${project_max_cost:.2f}). Please increase the maximum cost limit in project settings to continue scanning.'
                }), 400
            
            # Build the command
            base_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(base_dir)
            run_forever_path = os.path.join(project_root, 'scripts', 'run_forever.py')
            
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
            if not os.path.exists(run_forever_path):
                return jsonify({
                    'success': False,
                    'error': f'run_forever.py not found at: {run_forever_path}'
                }), 500
            
            # Build the base command with proper path quoting (cross-platform)
            if sys.platform == 'win32':
                # Windows: use list format for subprocess, no shell quoting needed
                base_command_parts = [env_python, run_forever_path, '--project-id', str(project_id), '--model-id', str(model_id)]
                base_command = ' '.join(f'"{part}"' if ' ' in part else part for part in base_command_parts)
            else:
                # Unix-like: use shlex.quote for shell safety
                quoted_python = shlex.quote(env_python)
                quoted_script = shlex.quote(run_forever_path)
                base_command = f'{quoted_python} {quoted_script} --project-id {project_id} --model-id {model_id}'
            
            # Log the command that will be executed
            logger.info(f"Preparing to execute scan command: {base_command}")
            logger.info(f"Python path: {env_python} (exists: {os.path.exists(env_python)})")
            logger.info(f"Script path: {run_forever_path} (exists: {os.path.exists(run_forever_path)})")
            
            # Check if process is already running - must match both project_id and model_id
            # Check for both run_forever.py and run_scan.py (since run_forever.py spawns run_scan.py)
            running_process = None
            log_file = os.path.join(project_root, 'logs', f'scan_{project_id}_{model_id}.log')
            
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
                try:
                    cmdline = proc.info.get('cmdline', [])
                    if not cmdline:
                        continue
                    
                    # Check if this is a run_forever.py or run_scan.py process
                    has_run_forever = any('run_forever.py' in str(arg) for arg in cmdline)
                    has_run_scan = any('run_scan.py' in str(arg) for arg in cmdline)
                    if not (has_run_forever or has_run_scan):
                        continue
                    
                    # Build command line string for matching
                    cmdline_str = ' '.join(str(arg) for arg in cmdline)
                    
                    # Must match both project-id and model-id exactly
                    project_match = f'--project-id {project_id}' in cmdline_str
                    model_match = f'--model-id {model_id}' in cmdline_str
                    
                    if project_match and model_match:
                        running_process = proc
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            if running_process:
                # Get output from log file if it exists
                output_lines = []
                try:
                    output_lines.append('Scan process is currently running...')
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
                    output_lines = ['Scan is already running']
                
                return jsonify({
                    'success': True,
                    'already_running': True,
                    'output': '\n'.join(output_lines)
                })
            
            # Start the scan in background
            try:
                # Create log file directory if it doesn't exist
                log_dir = os.path.dirname(log_file)
                if log_dir and not os.path.exists(log_dir):
                    os.makedirs(log_dir, exist_ok=True)
                
                # Log the command that will be executed BEFORE executing
                logger.info(f"=== SCAN COMMAND PREVIEW ===")
                logger.info(f"Base command: {base_command}")
                logger.info(f"Working directory: {project_root} (exists: {os.path.exists(project_root)})")
                logger.info(f"Log file: {log_file}")
                
                # Start the process (cross-platform)
                # Build command list
                cmd_list = [env_python, run_forever_path, '--project-id', str(project_id), '--model-id', str(model_id)]
                
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
                
                # Try to get the actual PID of the run_forever.py process
                actual_pid = None
                try:
                    # The process we started is the shell, find the actual python process
                    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                        try:
                            cmdline = proc.info.get('cmdline', [])
                            if cmdline and any('run_forever.py' in str(arg) for arg in cmdline):
                                cmdline_str = ' '.join(str(arg) for arg in cmdline)
                                if f'--project-id {project_id}' in cmdline_str and f'--model-id {model_id}' in cmdline_str:
                                    actual_pid = proc.info['pid']
                                    break
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                except Exception:
                    pass
                
                logger.info(f"Process started. Shell PID: {process.pid}, Run Forever PID: {actual_pid}")
                
                # Build display command (the actual command that runs)
                display_command = base_command
                
                return jsonify({
                    'success': True,
                    'already_running': False,
                    'message': 'Scan started successfully',
                    'command': display_command,
                    'base_command': base_command,
                    'log_file': log_file,
                    'pid': actual_pid or process.pid
                })
            except Exception as e:
                logger.error(f"Error starting scan: {e}")
                return jsonify({
                    'success': False,
                    'error': f'Failed to start scan: {str(e)}'
                }), 500
                
    except Exception as e:
        logger.error(f"Error in start_scan: {e}")
        return jsonify({
            'success': False,
            'error': f'Error starting scan: {str(e)}'
        }), 500

