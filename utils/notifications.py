"""utils/notifications.py — Create and fetch in-app notifications."""
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


def _get_session():
    from utils.flask_helpers import get_orm_instance
    return get_orm_instance()


def create_notification(user_id: int, notif_type: str, title: str,
                        message: str = None, project_id: int = None, link: str = None):
    """Insert a notification row. Silently ignores errors so it never breaks scan flow."""
    try:
        from utils.flask_helpers import get_orm_instance
        from db.models import Notification, NotificationType
        orm = get_orm_instance()
        with orm.get_session() as session:
            n = Notification(
                user_id=user_id,
                project_id=project_id,
                type=NotificationType(notif_type),
                title=title,
                message=message,
                is_read=False,
                link=link,
            )
            session.add(n)
            session.flush()
            logger.info(f"[Notif] Created '{notif_type}' for user {user_id}: {title}")
    except Exception as e:
        logger.warning(f"[Notif] Failed to create notification: {e}")


def notify_scan_started(project_id: int, project_name: str, owner_id: int):
    create_notification(
        user_id=owner_id,
        notif_type='scan_started',
        title=f'Scan started — {project_name}',
        message='AI agents are now scanning your codebase for vulnerabilities.',
        project_id=project_id,
        link=f'/projects/{project_id}',
    )


def notify_scan_complete(project_id: int, project_name: str, owner_id: int,
                         total: int, critical: int):
    sev = f'{critical} critical' if critical else f'{total} findings'
    create_notification(
        user_id=owner_id,
        notif_type='scan_complete',
        title=f'Scan complete — {project_name}',
        message=f'Found {total} issue(s). {sev}.' if total else 'No issues found.',
        project_id=project_id,
        link=f'/projects/{project_id}',
    )


def notify_auto_scan_started(project_id: int, project_name: str, owner_id: int):
    create_notification(
        user_id=owner_id,
        notif_type='auto_scan',
        title=f'Auto-scan started — {project_name}',
        message='Scheduled auto-scan has begun.',
        project_id=project_id,
        link=f'/projects/{project_id}',
    )
