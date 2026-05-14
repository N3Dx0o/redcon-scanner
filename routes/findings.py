"""Findings-related routes"""
from flask_login import login_required, current_user
from flask import render_template, request, redirect, url_for, flash, jsonify
from routes import findings_bp
from utils.flask_helpers import get_orm_instance
from db.models import Finding, Confirmation, FindingStatus, Project, SeverityLevel
from sqlalchemy import exists, func, not_
from sqlalchemy.orm import joinedload
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


def get_finding_validation_status(finding):
    """
    Determine the validation status of a finding based on its confirmations.
    Returns: 'confirmed_bug', 'false_positive', 'conflicting', 'pending'
    """
    if not finding.confirmations:
        return 'pending'
    
    bugs = sum(1 for c in finding.confirmations if not c.false_positive)
    fps = sum(1 for c in finding.confirmations if c.false_positive)
    
    if bugs > 0 and fps > 0:
        return 'conflicting'
    elif bugs > 0:
        return 'confirmed_bug'
    elif fps > 0:
        return 'false_positive'
    return 'pending'


def calculate_findings_insights(findings):
    """Calculate validation insights for a list of findings"""
    insights = {
        'confirmed_bugs': 0,
        'false_positives': 0,
        'conflicting': 0,
        'pending': 0,
        'with_remote_attack': 0,
        'total_confirmations': 0
    }
    
    for finding in findings:
        status = get_finding_validation_status(finding)
        if status == 'confirmed_bug':
            insights['confirmed_bugs'] += 1
        elif status == 'false_positive':
            insights['false_positives'] += 1
        elif status == 'conflicting':
            insights['conflicting'] += 1
        else:
            insights['pending'] += 1
        
        # Count remote attacks
        if finding.confirmations:
            insights['total_confirmations'] += len(finding.confirmations)
            if any(c.is_remote_attack for c in finding.confirmations):
                insights['with_remote_attack'] += 1
    
    return insights


@findings_bp.route('/findings')
@login_required
def findings_list():
    """List all findings with filtering and search"""
    try:
        orm = get_orm_instance()
        with orm.get_session() as session:
            # Get filter parameters
            severity = request.args.get('severity')
            status = request.args.get('status')
            project_id = request.args.get('project_id')
            search = request.args.get('search')
            file_path = request.args.get('file_path')
            date_from = request.args.get('date_from')
            date_to = request.args.get('date_to')
            
            # Confirmation filters
            with_confirmations = request.args.get('with_confirmations', '').lower() == 'true'
            without_confirmations = request.args.get('without_confirmations', '').lower() == 'true'
            confirmation_count = request.args.get('confirmation_count')
            
            # Validation status filters
            validation_status = request.args.get('validation_status')  # confirmed_bug, false_positive, conflicting, pending
            remote_attack = request.args.get('remote_attack', '').lower() == 'true'
            not_remote_attack = request.args.get('not_remote_attack', '').lower() == 'true'
            unanimous_only = request.args.get('unanimous_only', '').lower() == 'true'
            
            # Build query with relationships
            query = session.query(Finding).join(Finding.project).options(
                joinedload(Finding.project), 
                joinedload(Finding.confirmations).joinedload(Confirmation.model)
            )

            # Scope to current user's projects (admins see all)
            if not current_user.is_admin:
                query = query.filter(Project.owner_id == current_user.id)
            
            # Basic filters
            if severity:
                query = query.filter(Finding.severity == severity)
            if status:
                query = query.filter(Finding.status == status)
            if project_id:
                query = query.filter(Finding.project_id == project_id)
            if search:
                query = query.filter(
                    Finding.title.ilike(f'%{search}%') | 
                    Finding.description.ilike(f'%{search}%')
                )
            if file_path:
                query = query.filter(Finding.file_path.ilike(f'%{file_path}%'))
            
            # Date range filters
            if date_from:
                try:
                    from_date = datetime.strptime(date_from, '%Y-%m-%d')
                    query = query.filter(Finding.created_at >= from_date)
                except ValueError:
                    pass
            if date_to:
                try:
                    to_date = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
                    query = query.filter(Finding.created_at < to_date)
                except ValueError:
                    pass
            
            # Confirmation existence filters
            if with_confirmations:
                query = query.filter(
                    exists().where(Confirmation.finding_id == Finding.id)
                )
            if without_confirmations:
                query = query.filter(
                    not_(exists().where(Confirmation.finding_id == Finding.id))
                )
            
            findings = query.order_by(Finding.created_at.desc()).all()
            
            # Post-process filters that require confirmation data analysis
            filtered_findings = []
            for finding in findings:
                include = True
                finding.validation_status = get_finding_validation_status(finding)
                
                # Validation status filter
                if validation_status and finding.validation_status != validation_status:
                    include = False
                
                # Confirmation count filter
                if confirmation_count and include:
                    count = len(finding.confirmations) if finding.confirmations else 0
                    if confirmation_count == '0' and count != 0:
                        include = False
                    elif confirmation_count == '1' and count != 1:
                        include = False
                    elif confirmation_count == '2' and count != 2:
                        include = False
                    elif confirmation_count == '3+' and count < 3:
                        include = False
                
                # Remote attack filters
                if include and finding.confirmations:
                    has_remote = any(c.is_remote_attack for c in finding.confirmations)
                    if remote_attack and not has_remote:
                        include = False
                    if not_remote_attack and has_remote:
                        include = False
                elif include and (remote_attack or not_remote_attack):
                    # No confirmations - can't determine remote attack status
                    if remote_attack:
                        include = False
                
                # Unanimous filter - only include if all confirmations agree
                if unanimous_only and include and finding.confirmations:
                    if len(finding.confirmations) >= 2:
                        all_bug = all(not c.false_positive for c in finding.confirmations)
                        all_fp = all(c.false_positive for c in finding.confirmations)
                        if not (all_bug or all_fp):
                            include = False
                
                if include:
                    filtered_findings.append(finding)
            
            findings = filtered_findings
            
            # Calculate insights
            insights = calculate_findings_insights(findings)
            
            # Get all findings for global insights (unfiltered count)
            all_q = session.query(Finding).join(Finding.project).options(joinedload(Finding.confirmations))
            if not current_user.is_admin:
                all_q = all_q.filter(Project.owner_id == current_user.id)
            all_findings = all_q.all()
            global_insights = calculate_findings_insights(all_findings)

            if current_user.is_admin:
                projects = orm.get_all(session, Project)
            else:
                projects = session.query(Project).filter(Project.owner_id == current_user.id).all()
            
            # Get unique file paths for autocomplete
            file_paths = session.query(Finding.file_path).distinct().all()
            unique_file_paths = sorted(set(fp[0] for fp in file_paths if fp[0]))
            
            return render_template('findings_list.html', 
                                 findings=findings, 
                                 projects=projects,
                                 findings_count=len(findings),
                                 insights=insights,
                                 global_insights=global_insights,
                                 unique_file_paths=unique_file_paths,
                                 # Pass current filter values to preserve state
                                 current_filters={
                                     'severity': severity,
                                     'status': status,
                                     'project_id': project_id,
                                     'search': search,
                                     'file_path': file_path,
                                     'date_from': date_from,
                                     'date_to': date_to,
                                     'with_confirmations': with_confirmations,
                                     'without_confirmations': without_confirmations,
                                     'confirmation_count': confirmation_count,
                                     'validation_status': validation_status,
                                     'remote_attack': remote_attack,
                                     'not_remote_attack': not_remote_attack,
                                     'unanimous_only': unanimous_only
                                 })
    except Exception as e:
        logger.error(f"Error listing findings: {e}")
        flash('Error loading findings', 'error')
        return render_template('findings_list.html', findings=[], projects=[], findings_count=0,
                             insights={}, global_insights={}, unique_file_paths=[], current_filters={})


@findings_bp.route('/findings/navigate')
@login_required
def findings_navigate():
    """Navigate through findings one at a time for focused analysis"""
    try:
        orm = get_orm_instance()
        with orm.get_session() as session:
            # Get filter parameters
            severity = request.args.get('severity')
            status = request.args.get('status')
            project_id = request.args.get('project_id')
            file_path = request.args.get('file_path')
            
            # Build query with relationships
            query = session.query(Finding).join(Finding.project).options(joinedload(Finding.project))

            # Scope to current user's projects
            if not current_user.is_admin:
                query = query.filter(Project.owner_id == current_user.id)

            if severity:
                query = query.filter(Finding.severity == severity)
            if status:
                query = query.filter(Finding.status == status)
            if project_id:
                query = query.filter(Finding.project_id == project_id)
            if file_path:
                query = query.filter(Finding.file_path.ilike(f"%{file_path}%"))
            
            findings = query.order_by(Finding.created_at.desc()).all()
            
            if not findings:
                if current_user.is_admin:
                    projects = orm.get_all(session, Project)
                else:
                    projects = session.query(Project).filter(Project.owner_id == current_user.id).all()
                return render_template('findings_navigate.html', 
                                     findings=[], 
                                     current_finding=None, 
                                     current_index=0,
                                     projects=projects,
                                     selected_severity=severity,
                                     selected_status=status,
                                     selected_project_id=project_id,
                                     selected_file_path=file_path)
            
            # Get current index from URL parameter
            current_index = int(request.args.get('index', 0))
            if current_index >= len(findings):
                current_index = 0
            elif current_index < 0:
                current_index = len(findings) - 1
            
            current_finding = findings[current_index]
            
            # Load confirmations with their model relationships for the current finding
            confirmations = session.query(Confirmation)\
                .options(joinedload(Confirmation.model))\
                .filter_by(finding_id=current_finding.id)\
                .all()
            
            current_finding.confirmations = confirmations
            
            # Get all projects for filter dropdown
            if current_user.is_admin:
                projects = orm.get_all(session, Project)
            else:
                projects = session.query(Project).filter(Project.owner_id == current_user.id).all()

            return render_template('findings_navigate.html', 
                                 findings=findings, 
                                 current_finding=current_finding, 
                                 current_index=current_index,
                                 projects=projects,
                                 selected_severity=severity,
                                 selected_status=status,
                                 selected_project_id=project_id,
                                 selected_file_path=file_path)
    except Exception as e:
        logger.error(f"Error in findings navigate: {e}")
        flash('Error loading findings', 'error')
        orm = get_orm_instance()
        with orm.get_session() as session:
            projects = orm.get_all(session, Project)
        return render_template('findings_navigate.html', 
                             findings=[], 
                             current_finding=None, 
                             current_index=0,
                             projects=projects,
                             selected_severity=None,
                             selected_status=None,
                             selected_project_id=None,
                             selected_file_path=None)


@findings_bp.route('/findings/<int:finding_id>')
@login_required
def finding_detail(finding_id):
    """View finding details"""
    try:
        orm = get_orm_instance()
        with orm.get_session() as session:
            # Load finding with project relationship
            finding = orm.get_by_id_with_relations(session, Finding, finding_id, ['project'])
            if not finding:
                flash('Finding not found', 'error')
                return redirect(url_for('findings.findings_list'))
            # Security: ensure user owns the project this finding belongs to
            if not current_user.is_admin and finding.project and finding.project.owner_id != current_user.id:
                flash('Access denied', 'error')
                return redirect(url_for('findings.findings_list'))
            
            # Load confirmations with their model relationships
            confirmations = session.query(Confirmation)\
                .options(joinedload(Confirmation.model))\
                .filter_by(finding_id=finding_id)\
                .all()
            
            finding.confirmations = confirmations
            
            return render_template('finding_detail.html', finding=finding)
    except Exception as e:
        logger.error(f"Error viewing finding: {e}")
        flash('Error loading finding', 'error')
        return redirect(url_for('findings.findings_list'))

