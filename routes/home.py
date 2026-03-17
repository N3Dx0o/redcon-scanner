"""Home page routes"""
from flask_login import login_required, current_user
from flask import render_template, flash
from routes import home_bp
from utils.flask_helpers import get_orm_instance
from db.models import Project, Finding, FindingStatus, SeverityLevel, Confirmation
from sqlalchemy.orm import joinedload
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)


def calculate_project_confirmation_stats(findings):
    """
    Calculate quick confirmation stats for a project's findings.
    Returns a dict with counts for display on dashboard.
    """
    stats = {
        'confirmed_bugs': 0,
        'confirmed_false_positives': 0,
        'conflicting': 0,
        'pending': 0,
        'total_confirmations': 0
    }
    
    for finding in findings:
        confirmations = getattr(finding, 'confirmations', [])
        
        if not confirmations:
            stats['pending'] += 1
        else:
            stats['total_confirmations'] += len(confirmations)
            false_positive_votes = sum(1 for c in confirmations if c.false_positive)
            real_bug_votes = len(confirmations) - false_positive_votes
            
            if false_positive_votes == len(confirmations):
                stats['confirmed_false_positives'] += 1
            elif real_bug_votes == len(confirmations):
                stats['confirmed_bugs'] += 1
            else:
                stats['conflicting'] += 1
    
    return stats


@home_bp.route('/')
@login_required
def index():
    """Home page — landing for guests, dashboard for logged-in users"""
    # Authenticated users go to dashboard; unauthenticated hit login_view (auth.login)
    # The before_request in app.py handles / -> /welcome for guests before this fires
    try:
        orm = get_orm_instance()
        with orm.get_session() as session:
            # Eager load findings with confirmations for insights
            # Filter by owner unless admin (multi-tenancy)
            base_q = session.query(Project) \
                .options(joinedload(Project.findings).joinedload(Finding.confirmations)) \
                .options(joinedload(Project.ai_models))
            if current_user.is_admin:
                projects = base_q.all()
            else:
                projects = base_q.filter(Project.owner_id == current_user.id).all()
            findings = orm.get_all(session, Finding)
            
            # Calculate global stats
            findings_count = len(findings)
            total_cost = sum(project.cost or 0 for project in projects)
            cost_per_finding = (total_cost / findings_count) if findings_count > 0 else 0
            
            # Calculate detailed stats per project
            project_stats = []
            for project in projects:
                project_findings = project.findings
                
                # Status breakdown
                status_counts = defaultdict(int)
                for finding in project_findings:
                    status_counts[finding.status.value] += 1
                
                # Severity breakdown
                severity_counts = defaultdict(int)
                for finding in project_findings:
                    severity_counts[finding.severity.value] += 1
                
                # Calculate totals
                total_findings = len(project_findings)
                open_count = status_counts.get('open', 0)
                in_progress_count = status_counts.get('in_progress', 0)
                resolved_count = status_counts.get('resolved', 0)
                false_positive_count = status_counts.get('false_positive', 0)
                ignored_count = status_counts.get('ignored', 0)
                
                # Critical/High severity counts
                critical_count = severity_counts.get('critical', 0)
                high_count = severity_counts.get('high', 0)
                medium_count = severity_counts.get('medium', 0)
                low_count = severity_counts.get('low', 0)
                info_count = severity_counts.get('info', 0)
                
                # Calculate confirmation insights for this project
                confirmation_stats = calculate_project_confirmation_stats(project_findings)
                
                project_stats.append({
                    'project': project,
                    'total_findings': total_findings,
                    'open_count': open_count,
                    'in_progress_count': in_progress_count,
                    'resolved_count': resolved_count,
                    'false_positive_count': false_positive_count,
                    'ignored_count': ignored_count,
                    'critical_count': critical_count,
                    'high_count': high_count,
                    'medium_count': medium_count,
                    'low_count': low_count,
                    'info_count': info_count,
                    'status_counts': dict(status_counts),
                    'severity_counts': dict(severity_counts),
                    # Confirmation insights
                    'confirmed_bugs': confirmation_stats['confirmed_bugs'],
                    'confirmed_false_positives': confirmation_stats['confirmed_false_positives'],
                    'conflicting': confirmation_stats['conflicting'],
                    'pending_validation': confirmation_stats['pending'],
                    'total_confirmations': confirmation_stats['total_confirmations']
                })
            
            # Calculate global statistics for charts
            global_status_counts = defaultdict(int)
            global_severity_counts = defaultdict(int)
            for finding in findings:
                global_status_counts[finding.status.value] += 1
                global_severity_counts[finding.severity.value] += 1
            
            # Calculate additional statistics for dashboard cards
            total_open_issues = global_status_counts.get('open', 0)
            total_in_progress = global_status_counts.get('in_progress', 0)
            total_resolved = global_status_counts.get('resolved', 0)
            total_critical = global_severity_counts.get('critical', 0)
            total_high = global_severity_counts.get('high', 0)
            
            # Count projects by status
            active_projects = sum(1 for p in projects if p.status.value == 'active')
            scanning_projects = sum(1 for p in projects if p.status.value == 'scanning')
            archived_projects = sum(1 for p in projects if p.status.value == 'archived')
            
            # Count total AI models used
            total_ai_models = sum(len(project.ai_models) for project in projects)
            
            # Calculate global confirmation stats
            global_confirmed_bugs = sum(ps['confirmed_bugs'] for ps in project_stats)
            global_false_positives = sum(ps['confirmed_false_positives'] for ps in project_stats)
            global_conflicting = sum(ps['conflicting'] for ps in project_stats)
            global_pending = sum(ps['pending_validation'] for ps in project_stats)
            global_total_confirmations = sum(ps['total_confirmations'] for ps in project_stats)
            
            return render_template('index.html', 
                                 projects=projects,
                                 project_stats=project_stats,
                                 findings_count=findings_count,
                                 total_cost=total_cost,
                                 cost_per_finding=cost_per_finding,
                                 project_count=len(projects),
                                 global_status_counts=dict(global_status_counts),
                                 global_severity_counts=dict(global_severity_counts),
                                 total_open_issues=total_open_issues,
                                 total_in_progress=total_in_progress,
                                 total_resolved=total_resolved,
                                 total_critical=total_critical,
                                 total_high=total_high,
                                 active_projects=active_projects,
                                 scanning_projects=scanning_projects,
                                 archived_projects=archived_projects,
                                 total_ai_models=total_ai_models,
                                 # Global confirmation insights
                                 global_confirmed_bugs=global_confirmed_bugs,
                                 global_false_positives=global_false_positives,
                                 global_conflicting=global_conflicting,
                                 global_pending=global_pending,
                                 global_total_confirmations=global_total_confirmations)
    except Exception as e:
        logger.error(f"Error in index route: {e}")
        flash('Error loading projects', 'error')
        return render_template('index.html', 
                             projects=[], 
                             project_stats=[],
                             findings_count=0, 
                             total_cost=0, 
                             cost_per_finding=0, 
                             project_count=0,
                             global_status_counts={},
                             global_severity_counts={},
                             total_open_issues=0,
                             total_in_progress=0,
                             total_resolved=0,
                             total_critical=0,
                             total_high=0,
                             active_projects=0,
                             scanning_projects=0,
                             archived_projects=0,
                             total_ai_models=0,
                             global_confirmed_bugs=0,
                             global_false_positives=0,
                             global_conflicting=0,
                             global_pending=0,
                             global_total_confirmations=0)



@home_bp.route('/welcome')
def landing():
    """Public landing / marketing page - no auth required"""
    from flask import render_template as _rt
    return _rt('landing.html')
