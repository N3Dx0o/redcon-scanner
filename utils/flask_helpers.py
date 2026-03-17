"""Shared Flask helper functions and utilities"""
import os
import logging
import platform

logger = logging.getLogger(__name__)

# Platform detection
IS_WINDOWS = platform.system().lower().startswith('win')

# PDF dependencies
if not IS_WINDOWS:
    from weasyprint import HTML
else:
    HTML = None  # type: ignore

try:
    import pdfkit  # type: ignore
except Exception:  # pragma: no cover
    pdfkit = None  # type: ignore


def get_orm_instance():
    """Get ORM instance"""
    from db import get_orm
    return get_orm(environment='development', database_name=os.getenv('DB_DATABASE', 'scanner.db'))


def initialize_database(database_name):
    """Initialize database with tables"""
    try:
        from db import get_orm
        orm = get_orm(environment='development', database_name=database_name)
        orm.create_tables()
        logger.info(f"Database initialized: {database_name}")
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        raise

