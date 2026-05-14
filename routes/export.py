"""Export routes for PDF generation"""
from flask_login import login_required, current_user
from flask import render_template, request, flash, redirect, url_for, Response
from routes import export_bp
from utils.flask_helpers import get_orm_instance, IS_WINDOWS, HTML, pdfkit
from db.models import Project, Finding, Confirmation, SeverityLevel, FindingStatus
from sqlalchemy.orm import joinedload
from datetime import datetime
from collections import Counter
import os
import logging
import platform
import re

logger = logging.getLogger(__name__)


@export_bp.route('/export', methods=['GET'])
@login_required
def export_page():
    """Export page with filters to generate PDF report from HTML"""
    try:
        orm = get_orm_instance()
        with orm.get_session() as session:
            if current_user.is_admin:
                projects = orm.get_all(session, Project)
            else:
                projects = session.query(Project).filter(Project.owner_id == current_user.id).all()
            return render_template('export.html', projects=projects, is_windows=platform.system().lower().startswith('win'))
    except Exception as e:
        logger.error(f"Error loading export page: {e}")
        flash('Error loading export page', 'error')
        return render_template('export.html', projects=[])


@export_bp.route('/export/pdf', methods=['POST'])
@login_required
def export_pdf():
    """Generate a PDF report of findings based on filters using HTML to PDF"""
    try:
        if IS_WINDOWS:
            flash('PDF export is only available on non-Windows systems.', 'error')
            return redirect(url_for('export.export_page'))
        from sqlalchemy.orm import joinedload
        orm = get_orm_instance()
        with orm.get_session() as session:
            severity = request.form.get('severity')
            status = request.form.get('status')
            project_id = request.form.get('project_id')
            search = request.form.get('search')

            query = session.query(Finding).join(Finding.project).options(
                joinedload(Finding.project),
                joinedload(Finding.confirmations).joinedload(Confirmation.model)
            )
            # Scope to current user's projects
            if not current_user.is_admin:
                query = query.filter(Project.owner_id == current_user.id)
            if severity:
                query = query.filter(Finding.severity == severity)
            if status:
                query = query.filter(Finding.status == status)
            if project_id:
                # Security: verify the requested project belongs to this user
                proj_check = session.query(Project).filter(Project.id == project_id).first()
                if proj_check and (current_user.is_admin or proj_check.owner_id == current_user.id):
                    query = query.filter(Finding.project_id == project_id)
                elif proj_check:
                    # Silently ignore unauthorized project filter
                    pass
            if search:
                query = query.filter(
                    Finding.title.ilike(f"%{search}%") |
                    Finding.description.ilike(f"%{search}%")
                )

            findings = query.order_by(Finding.created_at.desc()).all()

            # Calculate statistics
            total_findings = len(findings)
            severity_counts = Counter()
            status_counts = Counter()
            confirmed_count = 0
            false_positive_count = 0
            remote_attack_count = 0
            project_names = set()
            project_ids = set()
            earliest_date = None
            latest_date = None
            
            for finding in findings:
                sev = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
                severity_counts[sev] += 1
                
                stat = finding.status.value if hasattr(finding.status, 'value') else str(finding.status)
                status_counts[stat] += 1
                
                if finding.project:
                    project_names.add(finding.project.name)
                    project_ids.add(finding.project_id)
                
                if finding.created_at:
                    if earliest_date is None or finding.created_at < earliest_date:
                        earliest_date = finding.created_at
                    if latest_date is None or finding.created_at > latest_date:
                        latest_date = finding.created_at
                
                # Count confirmations
                for confirmation in finding.confirmations:
                    if not confirmation.false_positive:
                        confirmed_count += 1
                    else:
                        false_positive_count += 1
                    if confirmation.is_remote_attack:
                        remote_attack_count += 1
            
            # Calculate financial statistics
            total_project_cost = 0.0
            cost_per_finding = 0.0
            
            if project_ids:
                # Get the projects for cost calculation
                projects_query = session.query(Project).filter(Project.id.in_(project_ids))
                for proj in projects_query:
                    if proj.cost is not None:
                        total_project_cost += proj.cost
                
                # Calculate cost per finding
                if total_findings > 0 and total_project_cost > 0:
                    cost_per_finding = total_project_cost / total_findings

            # Calculate max values for charts
            max_severity_count = max(severity_counts.values()) if severity_counts else 1
            max_status_count = max(status_counts.values()) if status_counts else 1

            # Group findings by project for the list view
            grouped_findings = {}
            for finding in findings:
                project_name = finding.project.name if finding.project else 'N/A'
                if project_name not in grouped_findings:
                    grouped_findings[project_name] = []
                grouped_findings[project_name].append(finding)
            
            # Sort projects and their findings
            sorted_grouped_findings = {k: grouped_findings[k] for k in sorted(grouped_findings.keys())}

            # Render HTML template for the report
            html_content = render_template(
                'report_export.html',
                findings=findings,
                grouped_findings=sorted_grouped_findings,
                filters={
                    'severity': severity,
                    'status': status,
                    'project_id': project_id,
                    'search': search
                },
                generated_at=datetime.utcnow(),
                statistics={
                    'total_findings': total_findings,
                    'severity_counts': dict(severity_counts),
                    'status_counts': dict(status_counts),
                    'confirmed_count': confirmed_count,
                    'false_positive_count': false_positive_count,
                    'remote_attack_count': remote_attack_count,
                    'project_count': len(project_names),
                    'project_names': sorted(list(project_names)),
                    'earliest_date': earliest_date,
                    'latest_date': latest_date,
                    'max_severity_count': max_severity_count,
                    'max_status_count': max_status_count,
                    'total_project_cost': total_project_cost,
                    'cost_per_finding': cost_per_finding
                }
            )

            # Convert HTML to PDF (WeasyPrint -> fallback to wkhtmltopdf/pdfkit on Windows)
            try:
                pdf_bytes = HTML(string=html_content, base_url=request.url_root).write_pdf()
            except Exception:
                if pdfkit is None:
                    raise
                wkhtml_path = os.getenv('WKHTMLTOPDF_PATH')
                config = pdfkit.configuration(wkhtmltopdf=wkhtml_path) if wkhtml_path else None
                pdf_bytes = pdfkit.from_string(html_content, False, configuration=config)  # returns bytes

            # Generate filename based on project selection
            if project_id:
                # Get the project name for the filename
                project = session.query(Project).filter(Project.id == project_id).first()
                if project:
                    # Sanitize project name for filename (remove special chars, replace spaces with underscores)
                    safe_name = re.sub(r'[^\w\s-]', '', project.name)
                    safe_name = re.sub(r'[-\s]+', '_', safe_name).strip('_')
                    filename = f"{safe_name}_findings_report.pdf"
                else:
                    filename = f"security_findings_report_{datetime.utcnow().strftime('%Y%m%d')}.pdf"
            else:
                # Multiple projects or no filter
                filename = f"security_findings_report_{datetime.utcnow().strftime('%Y%m%d')}.pdf"
            
            headers = {'Content-Type': 'application/pdf', 'Content-Disposition': f'attachment; filename="{filename}"'}
            return Response(pdf_bytes, headers=headers)
    except Exception as e:
        logger.error(f"Error generating PDF: {e}")
        flash('Failed to generate PDF report', 'error')
        return redirect(url_for('export.export_page'))

