"""Status page routes - shows running scan processes"""
from flask_login import login_required, current_user
from flask import render_template, jsonify, abort
from routes import status_bp
from utils.flask_helpers import get_orm_instance
from db.models import Project, AIModel
import psutil
import logging
import re
import datetime
import os
from pathlib import Path

logger = logging.getLogger(__name__)


@status_bp.route('/status')
@login_required
def status_page():
    """Display status of running scan and validation processes"""
    try:
        orm = get_orm_instance()
        running_scans = []
        running_validations = []
        
        # Find all processes running run_scan.py or run_validator.py
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time', 'status']):
            try:
                cmdline = proc.info.get('cmdline', [])
                if not cmdline:
                    continue
                
                # Build command line string
                cmdline_str = ' '.join(str(arg) for arg in cmdline)
                
                # Check if this is a run_scan.py process
                if 'run_scan.py' in cmdline_str:
                
                    # Parse project-id and model-id from command line
                    project_id = None
                    model_id = None
                    
                    # Try to find --project-id or -p
                    project_match = re.search(r'--project-id\s+(\d+)|-p\s+(\d+)', cmdline_str)
                    if project_match:
                        project_id = int(project_match.group(1) or project_match.group(2))
                    
                    # Try to find --model-id or -m
                    model_match = re.search(r'--model-id\s+(\d+)|-m\s+(\d+)', cmdline_str)
                    if model_match:
                        model_id = int(model_match.group(1) or model_match.group(2))
                    
                    # Get process info
                    pid = proc.info['pid']
                    create_time = proc.info.get('create_time', 0)
                    start_time = datetime.datetime.fromtimestamp(create_time) if create_time else None
                    status = proc.info.get('status', 'unknown')
                    
                    # Calculate runtime
                    runtime_hours = None
                    if start_time:
                        runtime_hours = (datetime.datetime.now() - start_time).total_seconds() / 3600
                    
                    # Get project and model names from database
                    project_name = None
                    model_name = None
                    vendor = None
                    
                    if project_id:
                        with orm.get_session() as session:
                            project = orm.get_by_id(session, Project, project_id)
                            if project:
                                project_name = project.name
                    
                    if model_id:
                        with orm.get_session() as session:
                            model = orm.get_by_id(session, AIModel, model_id)
                            if model:
                                model_name = model.model_name
                                vendor = model.vendor
                    
                    running_scans.append({
                        'pid': pid,
                        'project_id': project_id,
                        'project_name': project_name or f'Project {project_id}' if project_id else 'Unknown',
                        'model_id': model_id,
                        'model_name': model_name or f'Model {model_id}' if model_id else 'Unknown',
                        'vendor': vendor or 'Unknown',
                        'start_time': start_time,
                        'runtime_hours': runtime_hours,
                        'status': status,
                        'cmdline': cmdline_str[:200] + '...' if len(cmdline_str) > 200 else cmdline_str,
                        'process_type': 'scan'
                    })
                
                # Check if this is a run_validator.py process
                elif 'run_validator.py' in cmdline_str:
                    # Parse finding-id, project-id and model-id from command line
                    finding_id = None
                    project_id = None
                    model_id = None
                    is_bulk = False  # True if this is a bulk project validation
                    
                    # Try to find --finding-id or -f (single finding mode)
                    finding_match = re.search(r'--finding-id\s+(\d+)|-f\s+(\d+)', cmdline_str)
                    if finding_match:
                        finding_id = int(finding_match.group(1) or finding_match.group(2))
                    
                    # Try to find --project-id or -p (bulk validation mode)
                    project_match = re.search(r'--project-id\s+(\d+)|-p\s+(\d+)', cmdline_str)
                    if project_match:
                        project_id = int(project_match.group(1) or project_match.group(2))
                        is_bulk = True
                    
                    # Try to find --model-id or -m
                    model_match = re.search(r'--model-id\s+(\d+)|-m\s+(\d+)', cmdline_str)
                    if model_match:
                        model_id = int(model_match.group(1) or model_match.group(2))
                    
                    # Get process info
                    pid = proc.info['pid']
                    create_time = proc.info.get('create_time', 0)
                    start_time = datetime.datetime.fromtimestamp(create_time) if create_time else None
                    status = proc.info.get('status', 'unknown')
                    
                    # Calculate runtime
                    runtime_hours = None
                    if start_time:
                        runtime_hours = (datetime.datetime.now() - start_time).total_seconds() / 3600
                    
                    # Get finding, project and model names from database
                    from db.models import Finding
                    finding_title = None
                    project_name = None
                    model_name = None
                    vendor = None
                    
                    # Handle single finding validation
                    if finding_id:
                        with orm.get_session() as session:
                            finding = orm.get_by_id(session, Finding, finding_id)
                            if finding:
                                finding_title = finding.title
                                project_name = finding.project.name if finding.project else None
                                project_id = finding.project_id
                    
                    # Handle bulk project validation
                    elif project_id and is_bulk:
                        with orm.get_session() as session:
                            project = orm.get_by_id(session, Project, project_id)
                            if project:
                                project_name = project.name
                                # Count remaining unconfirmed findings
                                from db.models import Confirmation
                                total_findings = session.query(Finding).filter_by(project_id=project_id).count()
                                confirmed_count = session.query(Confirmation).join(Finding).filter(
                                    Finding.project_id == project_id,
                                    Confirmation.model_id == model_id
                                ).count() if model_id else 0
                                finding_title = f'Bulk: {total_findings - confirmed_count} remaining of {total_findings}'
                    
                    if model_id:
                        with orm.get_session() as session:
                            model = orm.get_by_id(session, AIModel, model_id)
                            if model:
                                model_name = model.model_name
                                vendor = model.vendor
                    
                    running_validations.append({
                        'pid': pid,
                        'finding_id': finding_id,
                        'finding_title': finding_title or (f'Finding {finding_id}' if finding_id else 'Unknown'),
                        'project_id': project_id,
                        'project_name': project_name or 'Unknown',
                        'model_id': model_id,
                        'model_name': model_name or (f'Model {model_id}' if model_id else 'Unknown'),
                        'vendor': vendor or 'Unknown',
                        'start_time': start_time,
                        'runtime_hours': runtime_hours,
                        'status': status,
                        'cmdline': cmdline_str[:200] + '...' if len(cmdline_str) > 200 else cmdline_str,
                        'process_type': 'bulk_validation' if is_bulk else 'validation',
                        'is_bulk': is_bulk
                    })
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                logger.warning(f"Error processing process: {e}")
                continue
        
        # Sort by start time (newest first)
        running_scans.sort(key=lambda x: x['start_time'] if x['start_time'] else datetime.datetime.min, reverse=True)
        running_validations.sort(key=lambda x: x['start_time'] if x['start_time'] else datetime.datetime.min, reverse=True)
        
        return render_template('status.html', 
                             running_scans=running_scans,
                             running_validations=running_validations,
                             scan_count=len(running_scans),
                             validation_count=len(running_validations),
                             total_count=len(running_scans) + len(running_validations))
    
    except Exception as e:
        logger.error(f"Error in status_page route: {e}")
        return render_template('status.html', 
                             running_scans=[],
                             running_validations=[],
                             scan_count=0,
                             validation_count=0,
                             total_count=0,
                             error=str(e))


@status_bp.route('/status/kill/<int:pid>', methods=['POST'])
@login_required
def kill_process(pid):
    """Kill a running scan or validation process by PID"""
    if not current_user.is_admin:
        return jsonify({"success": False, "error": "Admin access required"}), 403
    try:
        # Verify the process exists and is a run_scan.py or run_validator.py process
        try:
            proc = psutil.Process(pid)
            cmdline = proc.cmdline()
            cmdline_str = ' '.join(str(arg) for arg in cmdline)
            
            # Verify it's a run_scan.py or run_validator.py process
            is_scan = 'run_scan.py' in cmdline_str
            is_validation = 'run_validator.py' in cmdline_str
            
            if not (is_scan or is_validation):
                return jsonify({
                    'success': False,
                    'error': 'Process is not a run_scan.py or run_validator.py process'
                }), 400
            
            # Get process info before killing
            project_id = None
            model_id = None
            finding_id = None
            
            # For scan processes
            if is_scan:
                project_match = re.search(r'--project-id\s+(\d+)|-p\s+(\d+)', cmdline_str)
                if project_match:
                    project_id = int(project_match.group(1) or project_match.group(2))
                
                model_match = re.search(r'--model-id\s+(\d+)|-m\s+(\d+)', cmdline_str)
                if model_match:
                    model_id = int(model_match.group(1) or model_match.group(2))
            
            # For validation processes (single finding or bulk project)
            elif is_validation:
                # Check for single finding validation
                finding_match = re.search(r'--finding-id\s+(\d+)|-f\s+(\d+)', cmdline_str)
                if finding_match:
                    finding_id = int(finding_match.group(1) or finding_match.group(2))
                
                # Check for bulk project validation
                project_match = re.search(r'--project-id\s+(\d+)|-p\s+(\d+)', cmdline_str)
                if project_match:
                    project_id = int(project_match.group(1) or project_match.group(2))
                
                model_match = re.search(r'--model-id\s+(\d+)|-m\s+(\d+)', cmdline_str)
                if model_match:
                    model_id = int(model_match.group(1) or model_match.group(2))
            
            # Try to find and kill any matching run_forever.py or run_validator_forever.py processes
            killed_forever_processes = []
            
            # For scan processes, kill run_forever.py
            if is_scan and project_id and model_id:
                for forever_proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                    try:
                        forever_cmdline = forever_proc.info.get('cmdline', [])
                        if not forever_cmdline:
                            continue
                        
                        forever_cmdline_str = ' '.join(str(arg) for arg in forever_cmdline)
                        
                        # Check if this is a run_forever.py process
                        if 'run_forever.py' not in forever_cmdline_str:
                            continue
                        
                        # Check if it matches the same project-id and model-id
                        forever_project_match = re.search(r'--project-id\s+(\d+)', forever_cmdline_str)
                        forever_model_match = re.search(r'--model-id\s+(\d+)', forever_cmdline_str)
                        
                        forever_project_id = None
                        forever_model_id = None
                        
                        if forever_project_match:
                            forever_project_id = int(forever_project_match.group(1))
                        if forever_model_match:
                            forever_model_id = int(forever_model_match.group(1))
                        
                        # If both match, kill this process
                        if forever_project_id == project_id and forever_model_id == model_id:
                            forever_pid = forever_proc.info['pid']
                            try:
                                forever_proc.terminate()
                                try:
                                    forever_proc.wait(timeout=5)
                                    logger.info(f"run_forever.py process {forever_pid} terminated gracefully")
                                    killed_forever_processes.append({
                                        'pid': forever_pid,
                                        'script': 'run_forever.py',
                                        'status': 'terminated'
                                    })
                                except psutil.TimeoutExpired:
                                    forever_proc.kill()
                                    forever_proc.wait(timeout=2)
                                    logger.info(f"run_forever.py process {forever_pid} force killed")
                                    killed_forever_processes.append({
                                        'pid': forever_pid,
                                        'script': 'run_forever.py',
                                        'status': 'force killed'
                                    })
                            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                                logger.warning(f"Could not kill run_forever.py process {forever_pid}: {e}")
                                continue
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
                    except Exception as e:
                        logger.warning(f"Error checking run_forever.py process: {e}")
                        continue
            
            # For validation processes, kill run_validator_forever.py
            # Handle both single finding (--finding-id) and bulk project (--project-id) modes
            elif is_validation and model_id and (finding_id or project_id):
                for forever_proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                    try:
                        forever_cmdline = forever_proc.info.get('cmdline', [])
                        if not forever_cmdline:
                            continue
                        
                        forever_cmdline_str = ' '.join(str(arg) for arg in forever_cmdline)
                        
                        # Check if this is a run_validator_forever.py process
                        if 'run_validator_forever.py' not in forever_cmdline_str:
                            continue
                        
                        # Check for matching finding-id or project-id and model-id
                        forever_finding_match = re.search(r'--finding-id\s+(\d+)', forever_cmdline_str)
                        forever_project_match = re.search(r'--project-id\s+(\d+)', forever_cmdline_str)
                        forever_model_match = re.search(r'--model-id\s+(\d+)', forever_cmdline_str)
                        
                        forever_finding_id = int(forever_finding_match.group(1)) if forever_finding_match else None
                        forever_project_id = int(forever_project_match.group(1)) if forever_project_match else None
                        forever_model_id = int(forever_model_match.group(1)) if forever_model_match else None
                        
                        # Check if this matches our target process
                        matches = False
                        if finding_id and forever_finding_id == finding_id and forever_model_id == model_id:
                            matches = True  # Single finding validation match
                        elif project_id and forever_project_id == project_id and forever_model_id == model_id:
                            matches = True  # Bulk project validation match
                        
                        if matches:
                            forever_pid = forever_proc.info['pid']
                            try:
                                forever_proc.terminate()
                                try:
                                    forever_proc.wait(timeout=5)
                                    logger.info(f"run_validator_forever.py process {forever_pid} terminated gracefully")
                                    killed_forever_processes.append({
                                        'pid': forever_pid,
                                        'script': 'run_validator_forever.py',
                                        'status': 'terminated'
                                    })
                                except psutil.TimeoutExpired:
                                    forever_proc.kill()
                                    forever_proc.wait(timeout=2)
                                    logger.info(f"run_validator_forever.py process {forever_pid} force killed")
                                    killed_forever_processes.append({
                                        'pid': forever_pid,
                                        'script': 'run_validator_forever.py',
                                        'status': 'force killed'
                                    })
                            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                                logger.warning(f"Could not kill run_validator_forever.py process {forever_pid}: {e}")
                                continue
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
                    except Exception as e:
                        logger.warning(f"Error checking run_validator_forever.py process: {e}")
                        continue
            
            # Now kill the run_scan.py or run_validator.py process
            # Try graceful shutdown first (SIGTERM)
            try:
                proc.terminate()
                # Wait up to 5 seconds for graceful shutdown
                try:
                    proc.wait(timeout=5)
                    logger.info(f"Process {pid} terminated gracefully")
                    message = f'Process {pid} terminated successfully'
                    if killed_forever_processes:
                        forever_details = ', '.join(f"{p['script']} (PID {p['pid']})" for p in killed_forever_processes)
                        message += f'. Also killed run_forever processes: {forever_details}'
                    
                    # Delete log file based on process type
                    log_deleted = False
                    current_file = Path(__file__).resolve()
                    project_root = current_file.parent.parent
                    
                    if is_scan and project_id and model_id:
                        try:
                            log_file = project_root / "logs" / f"scan_{project_id}_{model_id}.log"
                            if log_file.exists():
                                log_file.unlink()
                                log_deleted = True
                                logger.info(f"Deleted log file: {log_file}")
                        except Exception as e:
                            logger.warning(f"Could not delete log file: {e}")
                    elif is_validation and finding_id and model_id:
                        try:
                            log_file = project_root / "logs" / f"validate_{finding_id}_{model_id}.log"
                            if log_file.exists():
                                log_file.unlink()
                                log_deleted = True
                                logger.info(f"Deleted log file: {log_file}")
                        except Exception as e:
                            logger.warning(f"Could not delete log file: {e}")
                    
                    return jsonify({
                        'success': True,
                        'message': message,
                        'pid': pid,
                        'project_id': project_id,
                        'finding_id': finding_id,
                        'model_id': model_id,
                        'killed_forever_processes': killed_forever_processes,
                        'log_deleted': log_deleted
                    })
                except psutil.TimeoutExpired:
                    # Process didn't terminate gracefully, force kill
                    logger.warning(f"Process {pid} did not terminate gracefully, forcing kill")
                    proc.kill()
                    proc.wait(timeout=2)
                    message = f'Process {pid} force killed'
                    if killed_forever_processes:
                        forever_details = ', '.join(f"{p['script']} (PID {p['pid']})" for p in killed_forever_processes)
                        message += f'. Also killed run_forever processes: {forever_details}'
                    
                    # Delete log file based on process type
                    log_deleted = False
                    current_file = Path(__file__).resolve()
                    project_root = current_file.parent.parent
                    
                    if is_scan and project_id and model_id:
                        try:
                            log_file = project_root / "logs" / f"scan_{project_id}_{model_id}.log"
                            if log_file.exists():
                                log_file.unlink()
                                log_deleted = True
                                logger.info(f"Deleted log file: {log_file}")
                        except Exception as e:
                            logger.warning(f"Could not delete log file: {e}")
                    elif is_validation and finding_id and model_id:
                        try:
                            log_file = project_root / "logs" / f"validate_{finding_id}_{model_id}.log"
                            if log_file.exists():
                                log_file.unlink()
                                log_deleted = True
                                logger.info(f"Deleted log file: {log_file}")
                        except Exception as e:
                            logger.warning(f"Could not delete log file: {e}")
                    
                    return jsonify({
                        'success': True,
                        'message': message,
                        'pid': pid,
                        'project_id': project_id,
                        'finding_id': finding_id,
                        'model_id': model_id,
                        'killed_forever_processes': killed_forever_processes,
                        'log_deleted': log_deleted
                    })
            except psutil.NoSuchProcess:
                # Process already terminated
                # Still try to delete log file based on process type
                log_deleted = False
                current_file = Path(__file__).resolve()
                project_root = current_file.parent.parent
                
                if is_scan and project_id and model_id:
                    try:
                        log_file = project_root / "logs" / f"scan_{project_id}_{model_id}.log"
                        if log_file.exists():
                            log_file.unlink()
                            log_deleted = True
                            logger.info(f"Deleted log file: {log_file}")
                    except Exception as e:
                        logger.warning(f"Could not delete log file: {e}")
                elif is_validation and finding_id and model_id:
                    try:
                        log_file = project_root / "logs" / f"validate_{finding_id}_{model_id}.log"
                        if log_file.exists():
                            log_file.unlink()
                            log_deleted = True
                            logger.info(f"Deleted log file: {log_file}")
                    except Exception as e:
                        logger.warning(f"Could not delete log file: {e}")
                
                return jsonify({
                    'success': True,
                    'message': f'Process {pid} was already terminated',
                    'pid': pid,
                    'log_deleted': log_deleted
                })
            except psutil.AccessDenied:
                return jsonify({
                    'success': False,
                    'error': f'Permission denied: Cannot kill process {pid}'
                }), 403
                
        except psutil.NoSuchProcess:
            return jsonify({
                'success': False,
                'error': f'Process {pid} not found'
            }), 404
        except psutil.AccessDenied:
            return jsonify({
                'success': False,
                'error': f'Permission denied: Cannot access process {pid}'
            }), 403
            
    except Exception as e:
        logger.error(f"Error killing process {pid}: {e}")
        return jsonify({
            'success': False,
            'error': f'Error killing process: {str(e)}'
        }), 500


@status_bp.route('/status/logs/scan/<int:project_id>/<int:model_id>')
@login_required
def view_scan_logs(project_id, model_id):
    """View scan log file for a specific project and model"""
    try:
        # Get the script directory (same as run_scan.py uses)
        # We need to find the project root directory
        current_file = Path(__file__).resolve()
        # Go up from routes/status.py to project root
        project_root = current_file.parent.parent
        
        # Build log file path
        log_file = project_root / "logs" / f"scan_{project_id}_{model_id}.log"
        
        # Check if log file exists
        if not log_file.exists():
            abort(404, description=f"Scan log file not found for project {project_id} and model {model_id}")
        
        # Read the log file content
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                log_content = f.read()
        except UnicodeDecodeError:
            # Try with different encoding if UTF-8 fails
            with open(log_file, 'r', encoding='latin-1') as f:
                log_content = f.read()
        
        # Get project and model names from database
        orm = get_orm_instance()
        project_name = None
        model_name = None
        
        with orm.get_session() as session:
            project = orm.get_by_id(session, Project, project_id)
            if project:
                project_name = project.name
            
            model = orm.get_by_id(session, AIModel, model_id)
            if model:
                model_name = model.model_name
        
        # Get file stats
        file_stats = os.stat(log_file)
        file_size = file_stats.st_size
        modified_time = datetime.datetime.fromtimestamp(file_stats.st_mtime)
        
        return render_template('view_logs.html',
                             log_content=log_content,
                             project_id=project_id,
                             project_name=project_name or f'Project {project_id}',
                             model_id=model_id,
                             model_name=model_name or f'Model {model_id}',
                             file_size=file_size,
                             modified_time=modified_time,
                             log_file=str(log_file))
    
    except Exception as e:
        logger.error(f"Error viewing scan logs for project {project_id}, model {model_id}: {e}")
        abort(500, description=f"Error reading log file: {str(e)}")


@status_bp.route('/status/logs/validate/<int:finding_id>/<int:model_id>')
@login_required
def view_validation_logs(finding_id, model_id):
    """View validation log file for a specific finding and model"""
    try:
        from db.models import Finding
        
        # Get the script directory
        current_file = Path(__file__).resolve()
        # Go up from routes/status.py to project root
        project_root = current_file.parent.parent
        
        # Build log file path
        log_file = project_root / "logs" / f"validate_{finding_id}_{model_id}.log"
        
        # Check if log file exists
        if not log_file.exists():
            abort(404, description=f"Validation log file not found for finding {finding_id} and model {model_id}")
        
        # Read the log file content
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                log_content = f.read()
        except UnicodeDecodeError:
            # Try with different encoding if UTF-8 fails
            with open(log_file, 'r', encoding='latin-1') as f:
                log_content = f.read()
        
        # Get finding, project and model names from database
        orm = get_orm_instance()
        finding_title = None
        project_name = None
        model_name = None
        
        with orm.get_session() as session:
            finding = orm.get_by_id(session, Finding, finding_id)
            if finding:
                finding_title = finding.title
                if finding.project:
                    project_name = finding.project.name
            
            model = orm.get_by_id(session, AIModel, model_id)
            if model:
                model_name = model.model_name
        
        # Get file stats
        file_stats = os.stat(log_file)
        file_size = file_stats.st_size
        modified_time = datetime.datetime.fromtimestamp(file_stats.st_mtime)
        
        return render_template('view_logs.html',
                             log_content=log_content,
                             finding_id=finding_id,
                             finding_title=finding_title or f'Finding {finding_id}',
                             project_name=project_name or 'Unknown',
                             model_id=model_id,
                             model_name=model_name or f'Model {model_id}',
                             file_size=file_size,
                             modified_time=modified_time,
                             log_file=str(log_file),
                             log_type='validation')
    
    except Exception as e:
        logger.error(f"Error viewing validation logs for finding {finding_id}, model {model_id}: {e}")
        abort(500, description=f"Error reading log file: {str(e)}")

