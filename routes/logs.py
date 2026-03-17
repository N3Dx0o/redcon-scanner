"""Logs aggregation routes - view all log files in one place"""
from flask_login import login_required, current_user
from flask import render_template, jsonify, request, Response
from routes import logs_bp
from pathlib import Path
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


def get_project_root():
    """Get the project root directory"""
    return Path(__file__).parent.parent.resolve()


def parse_log_filename(filename):
    """Parse log filename to extract metadata"""
    info = {
        'type': 'unknown',
        'type_label': 'Unknown',
        'type_color': 'secondary',
        'project_id': None,
        'model_id': None,
        'finding_id': None,
    }
    
    name = filename.replace('.log', '')
    
    if name.startswith('scan_'):
        # scan_{project_id}_{model_id}.log
        parts = name.split('_')
        if len(parts) >= 3:
            info['type'] = 'scan'
            info['type_label'] = 'Scan'
            info['type_color'] = 'primary'
            try:
                info['project_id'] = int(parts[1])
                info['model_id'] = int(parts[2])
            except (ValueError, IndexError):
                pass
                
    elif name.startswith('validate_'):
        # validate_{finding_id}_{model_id}.log
        parts = name.split('_')
        if len(parts) >= 3:
            info['type'] = 'validate'
            info['type_label'] = 'Validation'
            info['type_color'] = 'info'
            try:
                info['finding_id'] = int(parts[1])
                info['model_id'] = int(parts[2])
            except (ValueError, IndexError):
                pass
                
    elif name.startswith('bulk_validate_'):
        # bulk_validate_{project_id}_{model_id}.log
        parts = name.split('_')
        if len(parts) >= 4:
            info['type'] = 'bulk_validate'
            info['type_label'] = 'Bulk Validation'
            info['type_color'] = 'warning'
            try:
                info['project_id'] = int(parts[2])
                info['model_id'] = int(parts[3])
            except (ValueError, IndexError):
                pass
                
    elif name == 'output':
        info['type'] = 'output'
        info['type_label'] = 'System Output'
        info['type_color'] = 'success'
        
    elif name == 'error':
        info['type'] = 'error'
        info['type_label'] = 'System Errors'
        info['type_color'] = 'danger'
    
    return info


def get_all_log_files():
    """Gather all log files from various locations"""
    project_root = get_project_root()
    logs_dir = project_root / 'logs'
    
    log_files = []
    
    # Get logs from logs/ directory
    if logs_dir.exists():
        for log_file in logs_dir.glob('*.log'):
            try:
                stat = log_file.stat()
                file_info = parse_log_filename(log_file.name)
                log_files.append({
                    'name': log_file.name,
                    'path': str(log_file.relative_to(project_root)),
                    'full_path': str(log_file),
                    'size': stat.st_size,
                    'size_human': format_file_size(stat.st_size),
                    'modified': datetime.fromtimestamp(stat.st_mtime),
                    'modified_human': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                    **file_info
                })
            except Exception as e:
                logger.warning(f"Error reading log file {log_file}: {e}")
    
    # Get root-level logs (output.log, error.log)
    for log_name in ['output.log', 'error.log']:
        log_file = project_root / log_name
        if log_file.exists():
            try:
                stat = log_file.stat()
                file_info = parse_log_filename(log_file.name)
                log_files.append({
                    'name': log_file.name,
                    'path': log_name,
                    'full_path': str(log_file),
                    'size': stat.st_size,
                    'size_human': format_file_size(stat.st_size),
                    'modified': datetime.fromtimestamp(stat.st_mtime),
                    'modified_human': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                    **file_info
                })
            except Exception as e:
                logger.warning(f"Error reading log file {log_file}: {e}")
    
    # Sort by modified time (newest first)
    log_files.sort(key=lambda x: x['modified'], reverse=True)
    
    return log_files


def format_file_size(size_bytes):
    """Format file size in human readable format"""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"


@logs_bp.route('/logs')
@login_required
def logs_page():
    """Main logs aggregation page"""
    try:
        log_files = get_all_log_files()
        
        # Calculate stats
        total_size = sum(f['size'] for f in log_files)
        type_counts = {}
        for f in log_files:
            t = f['type_label']
            type_counts[t] = type_counts.get(t, 0) + 1
        
        return render_template('logs.html',
                             log_files=log_files,
                             total_files=len(log_files),
                             total_size=format_file_size(total_size),
                             type_counts=type_counts)
    except Exception as e:
        logger.error(f"Error in logs_page: {e}")
        return render_template('logs.html',
                             log_files=[],
                             total_files=0,
                             total_size='0 B',
                             type_counts={},
                             error=str(e))


@logs_bp.route('/logs/view/<path:log_path>')
@login_required
def view_log(log_path):
    if not current_user.is_admin:
        return jsonify({'success': False, 'error': 'Admin access required'}), 403
    """View contents of a specific log file"""
    try:
        project_root = get_project_root()
        
        # Security: ensure path is within project
        full_path = (project_root / log_path).resolve()
        if not str(full_path).startswith(str(project_root)):
            return jsonify({'success': False, 'error': 'Invalid path'}), 400
        
        if not full_path.exists():
            return jsonify({'success': False, 'error': 'File not found'}), 404
        
        # Only allow viewing .log files
        if full_path.suffix != '.log':
            return jsonify({'success': False, 'error': 'Can only view .log files'}), 400
        
        # Get tail parameter (default to last 500 lines)
        tail_lines = min(request.args.get('tail', 500, type=int), 10_000)
        
        # Read file content
        try:
            with open(full_path, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
                
            total_lines = len(lines)
            
            if tail_lines > 0 and total_lines > tail_lines:
                content = ''.join(lines[-tail_lines:])
                truncated = True
            else:
                content = ''.join(lines)
                truncated = False
            
            stat = full_path.stat()
            
            return jsonify({
                'success': True,
                'content': content,
                'total_lines': total_lines,
                'displayed_lines': min(tail_lines, total_lines) if tail_lines > 0 else total_lines,
                'truncated': truncated,
                'size': format_file_size(stat.st_size),
                'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            })
            
        except Exception as e:
            return jsonify({'success': False, 'error': f'Error reading file: {str(e)}'}), 500
            
    except Exception as e:
        logger.error(f"Error viewing log: {e}")
        logger.error(f'Internal error: {e}', exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@logs_bp.route('/logs/download/<path:log_path>')
@login_required
def download_log(log_path):
    if not current_user.is_admin:
        return jsonify({'success': False, 'error': 'Admin access required'}), 403
    """Download a specific log file"""
    try:
        project_root = get_project_root()
        
        # Security: ensure path is within project
        full_path = (project_root / log_path).resolve()
        if not str(full_path).startswith(str(project_root)):
            return jsonify({'success': False, 'error': 'Invalid path'}), 400
        
        if not full_path.exists():
            return jsonify({'success': False, 'error': 'File not found'}), 404
        
        # Only allow downloading .log files
        if full_path.suffix != '.log':
            return jsonify({'success': False, 'error': 'Can only download .log files'}), 400
        
        with open(full_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        
        response = Response(content, mimetype='text/plain')
        response.headers['Content-Disposition'] = f'attachment; filename="{full_path.name}"'
        return response
        
    except Exception as e:
        logger.error(f"Error downloading log: {e}")
        logger.error(f'Internal error: {e}', exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@logs_bp.route('/logs/delete/<path:log_path>', methods=['POST'])
@login_required
def delete_log(log_path):
    """Delete a specific log file"""
    if not current_user.is_admin:
        return jsonify({"success": False, "error": "Admin access required"}), 403
    try:
        project_root = get_project_root()
        
        # Security: ensure path is within project
        full_path = (project_root / log_path).resolve()
        if not str(full_path).startswith(str(project_root)):
            return jsonify({'success': False, 'error': 'Invalid path'}), 400
        
        if not full_path.exists():
            return jsonify({'success': False, 'error': 'File not found'}), 404
        
        # Only allow deleting .log files
        if not full_path.suffix == '.log':
            return jsonify({'success': False, 'error': 'Can only delete .log files'}), 400
        
        full_path.unlink()
        logger.info(f"Deleted log file: {log_path}")
        
        return jsonify({'success': True, 'message': f'Deleted {full_path.name}'})
        
    except Exception as e:
        logger.error(f"Error deleting log: {e}")
        logger.error(f'Internal error: {e}', exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@logs_bp.route('/logs/clear-all', methods=['POST'])
@login_required
def clear_all_logs():
    """Delete all log files"""
    if not current_user.is_admin:
        return jsonify({"success": False, "error": "Admin access required"}), 403
    try:
        project_root = get_project_root()
        logs_dir = project_root / 'logs'
        
        deleted_count = 0
        errors = []
        
        # Delete logs from logs/ directory
        if logs_dir.exists():
            for log_file in logs_dir.glob('*.log'):
                try:
                    log_file.unlink()
                    deleted_count += 1
                except Exception as e:
                    errors.append(f"{log_file.name}: {str(e)}")
        
        # Delete root-level logs
        for log_name in ['output.log', 'error.log']:
            log_file = project_root / log_name
            if log_file.exists():
                try:
                    log_file.unlink()
                    deleted_count += 1
                except Exception as e:
                    errors.append(f"{log_name}: {str(e)}")
        
        if errors:
            return jsonify({
                'success': True,
                'message': f'Deleted {deleted_count} files with {len(errors)} errors',
                'errors': errors
            })
        
        return jsonify({
            'success': True,
            'message': f'Deleted {deleted_count} log files'
        })
        
    except Exception as e:
        logger.error(f"Error clearing logs: {e}")
        logger.error(f'Internal error: {e}', exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500


@logs_bp.route('/api/logs/list')
@login_required
def api_list_logs():
    """API endpoint to get list of log files (for auto-refresh)"""
    try:
        log_files = get_all_log_files()
        
        # Convert datetime to string for JSON
        for f in log_files:
            f['modified'] = f['modified'].isoformat()
        
        return jsonify({
            'success': True,
            'files': log_files,
            'count': len(log_files)
        })
    except Exception as e:
        logger.error(f'Internal error: {e}', exc_info=True)
        return jsonify({'success': False, 'error': 'An internal error occurred'}), 500

