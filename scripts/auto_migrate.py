#!/usr/bin/env python3
"""
Auto-migration script for SQLite database
This script automatically detects missing columns and adds them to existing tables.
It's designed to be standalone and can be run without any dependencies.
"""

import sentry_sdk
from sentry_sdk.integrations.logging import LoggingIntegration
import logging

# Initialize Sentry SDK - only capture exceptions and error/critical logs
sentry_logging = LoggingIntegration(
    level=logging.ERROR,        # Capture ERROR and CRITICAL logs
    event_level=logging.ERROR   # Send events for ERROR and CRITICAL only
)

sentry_sdk.init(
    dsn="https://ff3ab07a2406ded2fd4a81daaaba30dc@o4510286572879872.ingest.de.sentry.io/4510286576418896",
    send_default_pii=True,
    integrations=[sentry_logging],
    # Only capture exceptions (not debug/info logs)
    traces_sample_rate=0.0,  # Disable performance monitoring
    # Only capture exceptions and error/critical logs, not debug/info/warning
    before_send=lambda event, hint: (
        event if (
            hint.get('exc_info') or  # Exceptions
            (event.get('level') in ('error', 'fatal', 'critical'))  # Error/Critical logs
        ) else None
    ),
)

import sqlite3
import sys
import os
from typing import Dict, List, Tuple, Optional

# Disable SQLAlchemy engine INFO logs - MUST be before any db imports
# Comprehensive list to disable all SQLAlchemy logging
logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy.pool').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy.dialects').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy.orm').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy.engine.Engine').setLevel(logging.WARNING)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Database schema definition based on models.py
EXPECTED_SCHEMA = {
    'ai_models': {
        'id': 'INTEGER PRIMARY KEY',
        'model_name': 'VARCHAR(255) NOT NULL',
        'vendor': 'VARCHAR(255) NOT NULL',
        'api_key': 'VARCHAR(1000) NOT NULL',
        'created_at': 'DATETIME NOT NULL',
        'updated_at': 'DATETIME NOT NULL',
    },
    'projects': {
        'id': 'INTEGER PRIMARY KEY',
        'name': 'VARCHAR(255) NOT NULL',
        'zip_file_path': 'VARCHAR(1000)',
        'base_path': 'VARCHAR(1000) NOT NULL',
        'cost': 'REAL',
        'git_link': 'VARCHAR(1000)',
        'excluded_dirs': 'TEXT',  # JSON
        'included_dirs': 'TEXT',  # JSON
        'max_cost': 'REAL',
        'input_type': 'VARCHAR(255) NOT NULL',
        'threat_models': 'TEXT',  # JSON
        'status': 'VARCHAR(255) NOT NULL',
        'last_scanned_at': 'DATETIME',
        'last_modified_at': 'DATETIME',
        'created_at': 'DATETIME NOT NULL',
        'updated_at': 'DATETIME NOT NULL',
    },
    'findings': {
        'id': 'INTEGER PRIMARY KEY',
        'file_path': 'VARCHAR(1000) NOT NULL',
        'title': 'VARCHAR(500) NOT NULL',
        'description': 'TEXT NOT NULL',
        'recommendation': 'TEXT',
        'severity': 'VARCHAR(255) NOT NULL',
        'status': 'VARCHAR(255) NOT NULL',
        'impacted_files': 'TEXT',  # JSON
        'project_id': 'INTEGER NOT NULL',
        'resolved_at': 'DATETIME',
        'created_at': 'DATETIME NOT NULL',
        'updated_at': 'DATETIME NOT NULL',
    },
    'confirmations': {
        'id': 'INTEGER PRIMARY KEY',
        'justification': 'TEXT NOT NULL',
        'evidence_analysis': 'TEXT NOT NULL',
        'exploit_feasibility': 'TEXT NOT NULL',
        'is_remote_attack': 'INTEGER NOT NULL',
        'false_positive': 'INTEGER NOT NULL',
        'finding_id': 'INTEGER NOT NULL',
        'model_id': 'INTEGER NOT NULL',
        'created_at': 'DATETIME NOT NULL',
        'updated_at': 'DATETIME NOT NULL',
    },
    'finding_models': {
        'finding_id': 'INTEGER PRIMARY KEY',
        'model_id': 'INTEGER PRIMARY KEY',
    },
    'project_models': {
        'project_id': 'INTEGER PRIMARY KEY',
        'model_id': 'INTEGER PRIMARY KEY',
    },
    'tasks': {
        'id': 'INTEGER PRIMARY KEY',
        'task_type': 'VARCHAR(255) NOT NULL',
        'tools': 'TEXT',  # JSON
        'status': 'VARCHAR(255) NOT NULL',
        'cost': 'REAL',
        'cmd': 'VARCHAR(1000)',
        'model_id': 'INTEGER NOT NULL',
        'created_at': 'DATETIME NOT NULL',
        'updated_at': 'DATETIME NOT NULL',
    },
    'facts': {
        'id': 'INTEGER PRIMARY KEY',
        'content': 'TEXT NOT NULL',
        'type': 'VARCHAR(255) NOT NULL',  # FactType enum
        'project_id': 'INTEGER NOT NULL',
        'created_at': 'DATETIME NOT NULL',
        'updated_at': 'DATETIME NOT NULL',
    },
}

# Foreign key constraints
FOREIGN_KEYS = {
    'findings': [('project_id', 'projects', 'id')],
    'confirmations': [
        ('finding_id', 'findings', 'id'),
        ('model_id', 'ai_models', 'id'),
    ],
    'finding_models': [
        ('finding_id', 'findings', 'id'),
        ('model_id', 'ai_models', 'id'),
    ],
    'project_models': [
        ('project_id', 'projects', 'id'),
        ('model_id', 'ai_models', 'id'),
    ],
    'tasks': [
        ('model_id', 'ai_models', 'id'),
    ],
    'facts': [
        ('project_id', 'projects', 'id'),
    ],
}


def get_existing_schema(db_path: str) -> Dict[str, Dict[str, str]]:
    """Get the current schema from the database"""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    schema = {}
    
    # Get all table names
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]
    
    for table_name in tables:
        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = {}
        for row in cursor.fetchall():
            columns[row[1]] = row[2]  # name -> type
        schema[table_name] = columns
    
    conn.close()
    return schema


def get_sqlite_type(model_type: str, nullable: bool = True) -> str:
    """Convert SQLAlchemy type to SQLite type"""
    nullable_str = '' if nullable else ' NOT NULL'
    
    if 'INTEGER' in model_type.upper():
        return 'INTEGER' + nullable_str
    elif 'VARCHAR' in model_type.upper() or 'STRING' in model_type.upper():
        if '(' in model_type:
            return model_type + nullable_str
        return 'VARCHAR(255)' + nullable_str
    elif 'TEXT' in model_type.upper():
        return 'TEXT' + nullable_str
    elif 'REAL' in model_type.upper() or 'FLOAT' in model_type.upper():
        return 'REAL' + nullable_str
    elif 'DATETIME' in model_type.upper() or 'TIMESTAMP' in model_type.upper():
        return 'DATETIME' + nullable_str
    elif 'BOOLEAN' in model_type.upper():
        return 'INTEGER' + nullable_str
    else:
        return 'TEXT' + nullable_str


def add_column(conn: sqlite3.Connection, table_name: str, column_name: str, column_type: str) -> bool:
    """Add a column to a table if it doesn't exist"""
    try:
        # Check if column already exists
        cursor = conn.cursor()
        cursor.execute(f"PRAGMA table_info({table_name})")
        existing_columns = [row[1] for row in cursor.fetchall()]
        
        if column_name in existing_columns:
            logger.info(f"Column {table_name}.{column_name} already exists, skipping")
            return False
        
        # Add the column
        sql = f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"
        logger.info(f"Adding column: {sql}")
        cursor.execute(sql)
        conn.commit()
        logger.info(f"Successfully added column {table_name}.{column_name}")
        return True
        
    except Exception as e:
        logger.error(f"Error adding column {table_name}.{column_name}: {e}")
        conn.rollback()
        return False


def create_table(conn: sqlite3.Connection, table_name: str, columns: Dict[str, str]) -> bool:
    """Create a table if it doesn't exist"""
    try:
        # Build the CREATE TABLE statement
        column_defs = []
        for col_name, col_type in columns.items():
            column_defs.append(f"{col_name} {col_type}")
        
        sql = f"CREATE TABLE IF NOT EXISTS {table_name} ({', '.join(column_defs)})"
        logger.info(f"Creating table: {table_name}")
        conn.execute(sql)
        conn.commit()
        logger.info(f"Successfully created table {table_name}")
        return True
        
    except Exception as e:
        logger.error(f"Error creating table {table_name}: {e}")
        conn.rollback()
        return False


def create_index(conn: sqlite3.Connection, table_name: str, column_name: str, unique: bool = False) -> bool:
    """Create an index if it doesn't exist"""
    try:
        index_name = f"idx_{table_name}_{column_name}"
        unique_str = "UNIQUE" if unique else ""
        sql = f"CREATE {unique_str} INDEX IF NOT EXISTS {index_name} ON {table_name}({column_name})"
        logger.debug(f"Creating index: {sql}")
        conn.execute(sql)
        conn.commit()
        return True
    except Exception as e:
        logger.debug(f"Index {index_name} may already exist: {e}")
        return False


def migrate_database(db_path: str) -> bool:
    """Migrate the database to match the expected schema"""
    logger.info(f"Starting migration for database: {db_path}")
    
    if not os.path.exists(db_path):
        logger.error(f"Database file not found: {db_path}")
        return False
    
    conn = sqlite3.connect(db_path)
    existing_schema = get_existing_schema(db_path)
    
    changes_made = False
    
    try:
        # Process each table
        for table_name, expected_columns in EXPECTED_SCHEMA.items():
            if table_name not in existing_schema:
                # Table doesn't exist, create it
                logger.info(f"Table {table_name} does not exist, creating...")
                if create_table(conn, table_name, expected_columns):
                    changes_made = True
                    existing_schema[table_name] = expected_columns
            else:
                # Table exists, check for missing columns
                existing_columns = existing_schema[table_name]
                
                for col_name, col_type in expected_columns.items():
                    if col_name not in existing_columns:
                        logger.info(f"Column {table_name}.{col_name} is missing, adding...")
                        nullable_col_type = col_type if 'NOT NULL' in col_type else col_type
                        if add_column(conn, table_name, col_name, nullable_col_type):
                            changes_made = True
        
        # Create indexes for primary columns
        index_configs = {
            'ai_models': ['id', 'model_name', 'vendor', 'created_at'],
            'projects': ['id', 'name', 'input_type', 'status', 'created_at', 'last_scanned_at'],
            'findings': ['id', 'file_path', 'title', 'severity', 'status', 'project_id', 'created_at'],
            'confirmations': ['id', 'finding_id', 'model_id', 'is_remote_attack', 'false_positive', 'created_at'],
            'tasks': ['id', 'task_type', 'status', 'model_id', 'created_at'],
            'facts': ['id', 'type', 'project_id', 'created_at'],
        }
        
        for table_name, index_columns in index_configs.items():
            if table_name in existing_schema or table_name in EXPECTED_SCHEMA:
                for col in index_columns:
                    create_index(conn, table_name, col)
        
        conn.close()
        
        if changes_made:
            logger.info("Migration completed successfully with changes made")
        else:
            logger.info("Migration completed - no changes needed")
        
        return True
        
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        conn.rollback()
        conn.close()
        return False


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Auto-migrate SQLite database schema')
    parser.add_argument(
        '--db',
        type=str,
        default='dev.db',
        help='Path to SQLite database file (default: dev.db)'
    )
    parser.add_argument(
        '--all',
        action='store_true',
        help='Migrate all databases (dev.db, dev_mpc.db, dev_chia.db, etc.)'
    )
    
    args = parser.parse_args()
    
    if args.all:
        # Find all .db files in current directory
        db_files = [f for f in os.listdir('.') if f.endswith('.db')]
        logger.info(f"Found {len(db_files)} database files: {db_files}")
        
        for db_file in db_files:
            logger.info(f"\n{'='*50}")
            logger.info(f"Migrating {db_file}")
            logger.info(f"{'='*50}")
            migrate_database(db_file)
    else:
        migrate_database(args.db)


if __name__ == '__main__':
    main()

