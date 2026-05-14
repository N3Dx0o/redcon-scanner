"""
auto_scheduler.py — Background scheduler for automatic project rescans.

Security design:
  - Runs entirely server-side; no external input can trigger a scan.
  - Validates project existence, ownership, and AI model before launching.
  - Checks for already-running scan process before starting a new one.
  - All subprocess args are integer IDs (no user-supplied strings in command).
  - Logs every action to logs/auto_scan_scheduler.log.
  - Scheduler is a singleton; calling init_scheduler() twice is a no-op.
"""

import os
import sys
import logging
import subprocess
import psutil
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

logger = logging.getLogger(__name__)

_scheduler = None   # singleton

# ── Schedule interval → timedelta ────────────────────────────────────────────
_SCHEDULE_DELTAS = {
    'hourly':  timedelta(hours=1),
    'daily':   timedelta(days=1),
    'weekly':  timedelta(weeks=1),
    'monthly': timedelta(days=30),
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def _project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def _venv_python() -> str:
    root = _project_root()
    for rel in ['venv/bin/python', 'env/bin/python']:
        p = os.path.join(root, rel)
        if os.path.exists(p):
            return p
    return 'python3'

def _is_scan_running(project_id: int, model_id: int) -> bool:
    """Return True if run_forever.py or run_scan.py is already running for this project+model."""
    target_project = f'--project-id {project_id}'
    target_model   = f'--model-id {model_id}'
    for proc in psutil.process_iter(['cmdline']):
        try:
            cmdline = proc.info.get('cmdline') or []
            if not cmdline:
                continue
            has_scan = any('run_forever.py' in a or 'run_scan.py' in a for a in cmdline)
            if not has_scan:
                continue
            joined = ' '.join(str(a) for a in cmdline)
            if target_project in joined and target_model in joined:
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return False

def _is_any_scan_running(project_id: int) -> bool:
    """Return True if ANY scan is running for this project (regardless of model)."""
    target = f'--project-id {project_id}'
    for proc in psutil.process_iter(['cmdline']):
        try:
            cmdline = proc.info.get('cmdline') or []
            if not cmdline:
                continue
            has_scan = any('run_forever.py' in a or 'run_scan.py' in a for a in cmdline)
            if not has_scan:
                continue
            if target in ' '.join(str(a) for a in cmdline):
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return False

# ── Core job function ─────────────────────────────────────────────────────────

def _run_due_scans():
    """Called every 10 minutes. Finds projects due for auto-scan and starts them."""
    try:
        from utils.flask_helpers import get_orm_instance
        from db.models import Project, AIModel, ProjectStatus

        orm  = get_orm_instance()
        now  = datetime.utcnow()

        with orm.get_session() as session:
            # Find all projects with an active schedule whose next_scan_at has passed
            due = (
                session.query(Project)
                .filter(
                    Project.scan_schedule.isnot(None),
                    Project.scan_schedule != 'none',
                    Project.next_scan_at.isnot(None),
                    Project.next_scan_at <= now,
                    Project.auto_scan_model_id.isnot(None),
                )
                .all()
            )

            if not due:
                return

            logger.info(f"[AutoScan] {len(due)} project(s) due for auto-scan")

            root         = _project_root()
            env_python   = _venv_python()
            run_forever  = os.path.join(root, 'scripts', 'run_forever.py')

            if not os.path.exists(run_forever):
                logger.error(f"[AutoScan] run_forever.py not found at {run_forever}")
                return

            for project in due:
                pid  = project.id
                mid  = project.auto_scan_model_id
                name = project.name

                # ── Safety: skip if already scanning ──────────────────────
                if _is_any_scan_running(pid):
                    logger.info(f"[AutoScan] Project {pid} ({name}): scan already running, skipping")
                    # Still advance next_scan_at so we don't hammer it every 10 min
                    _advance_next_scan(session, project, now)
                    continue

                # ── Safety: verify project status ──────────────────────────
                if project.status == ProjectStatus.SCANNING:
                    logger.info(f"[AutoScan] Project {pid} ({name}): status=SCANNING, skipping")
                    _advance_next_scan(session, project, now)
                    continue

                # ── Safety: verify AI model still exists ───────────────────
                model = session.query(AIModel).filter_by(id=mid).first()
                if not model:
                    logger.warning(f"[AutoScan] Project {pid} ({name}): model {mid} not found, disabling schedule")
                    project.scan_schedule    = None
                    project.next_scan_at     = None
                    project.auto_scan_model_id = None
                    continue

                # ── Launch scan subprocess ─────────────────────────────────
                log_dir  = os.path.join(root, 'logs')
                os.makedirs(log_dir, exist_ok=True)
                log_file = os.path.join(log_dir, f'auto_scan_{pid}_{mid}.log')

                cmd = [env_python, run_forever, '--project-id', str(pid), '--model-id', str(mid)]

                try:
                    with open(log_file, 'a', encoding='utf-8') as lf:
                        lf.write(f"\n\n=== AUTO SCAN STARTED {now.isoformat()} ===\n")
                    log_handle = open(log_file, 'a', encoding='utf-8')

                    proc = subprocess.Popen(
                        cmd,
                        cwd=root,
                        stdout=log_handle,
                        stderr=subprocess.STDOUT,
                        start_new_session=True,
                        close_fds=True,
                    )
                    logger.info(f"[AutoScan] Project {pid} ({name}): started PID {proc.pid} with model {mid}")
                except Exception as e:
                    logger.error(f"[AutoScan] Project {pid} ({name}): failed to start — {e}")
                    continue

                # Advance next_scan_at
                _advance_next_scan(session, project, now)

    except Exception as e:
        logger.exception(f"[AutoScan] Unexpected error in scheduler job: {e}")


def _advance_next_scan(session, project, now: datetime):
    """Push next_scan_at forward by the schedule interval."""
    delta = _SCHEDULE_DELTAS.get(project.scan_schedule)
    if delta:
        # Advance from now (not from old next_scan_at) to avoid pile-up
        project.next_scan_at = now + delta
        try:
            session.flush()
        except Exception as e:
            logger.warning(f"[AutoScan] Could not flush next_scan_at for project {project.id}: {e}")


# ── Public API ────────────────────────────────────────────────────────────────

def init_scheduler(app):
    """Start the background scheduler. Safe to call multiple times (no-op if running)."""
    global _scheduler
    if _scheduler and _scheduler.running:
        return

    _scheduler = BackgroundScheduler(
        job_defaults={'coalesce': True, 'max_instances': 1},
        timezone='UTC',
    )
    _scheduler.add_job(
        func=_run_due_scans,
        trigger=IntervalTrigger(minutes=10),
        id='auto_scan_job',
        name='Auto Scan Scheduler',
        replace_existing=True,
    )
    _scheduler.start()
    logger.info("[AutoScan] Background scheduler started (runs every 10 minutes)")

    # Graceful shutdown when Flask exits
    import atexit
    atexit.register(lambda: _scheduler.shutdown(wait=False))


def set_project_schedule(project_id: int, schedule: str, model_id: int, actor_user_id: int) -> dict:
    """
    Set or update the auto-scan schedule for a project.
    Returns {'success': True} or {'success': False, 'error': '...'}.

    Security: validates ownership before updating.
    """
    valid_schedules = ('none', 'hourly', 'daily', 'weekly', 'monthly')
    if schedule not in valid_schedules:
        return {'success': False, 'error': f'Invalid schedule. Must be one of: {", ".join(valid_schedules)}'}

    try:
        from utils.flask_helpers import get_orm_instance
        from db.models import Project, AIModel, User

        orm = get_orm_instance()
        with orm.get_session() as session:
            project = session.query(Project).filter_by(id=project_id).first()
            if not project:
                return {'success': False, 'error': 'Project not found'}

            # Ownership / admin check
            actor = session.query(User).filter_by(id=actor_user_id).first()
            if not actor:
                return {'success': False, 'error': 'Actor not found'}
            if project.owner_id is not None and project.owner_id != actor_user_id and not actor.is_admin:
                return {'success': False, 'error': 'Access denied'}

            if schedule == 'none':
                project.scan_schedule      = None
                project.next_scan_at       = None
                project.auto_scan_model_id = None
                logger.info(f"[AutoScan] Project {project_id}: schedule disabled by user {actor_user_id}")
                return {'success': True, 'message': 'Auto-scan disabled'}

            # Verify AI model exists and user has access to it
            model = session.query(AIModel).filter_by(id=model_id).first()
            if not model:
                return {'success': False, 'error': 'AI model not found'}

            delta = _SCHEDULE_DELTAS.get(schedule)
            if not delta:
                return {'success': False, 'error': 'Unknown schedule interval'}

            project.scan_schedule      = schedule
            project.auto_scan_model_id = model_id
            project.next_scan_at       = datetime.utcnow() + delta

            logger.info(
                f"[AutoScan] Project {project_id}: schedule set to '{schedule}' "
                f"with model {model_id} by user {actor_user_id}. "
                f"Next scan at {project.next_scan_at.isoformat()}"
            )
            return {
                'success': True,
                'message': f'Auto-scan scheduled: {schedule}',
                'next_scan_at': project.next_scan_at.isoformat(),
            }

    except Exception as e:
        logger.exception(f"[AutoScan] set_project_schedule error: {e}")
        return {'success': False, 'error': str(e)}
