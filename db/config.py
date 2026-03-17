from typing import Dict, Any, Optional, Union
from sqlalchemy import create_engine, Engine, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool, QueuePool
from sqlalchemy.exc import SQLAlchemyError
import os
import logging
from enum import Enum

# Disable SQLAlchemy engine INFO logs globally - comprehensive list
logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy.pool').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy.dialects').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy.orm').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy.engine.Engine').setLevel(logging.WARNING)

class DatabaseType(str, Enum):
    SQLITE = "sqlite"

class DatabaseConfig:
    """Database configuration class supporting SQLite only"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.db_type = DatabaseType(config.get('type', 'sqlite').lower())
        self.engine = None
        self.SessionLocal = None
        self.logger = logging.getLogger('DB')
        self.logger.setLevel(logging.ERROR)
        # Validate database type
        if self.db_type not in DatabaseType:
            raise ValueError(f"Unsupported database type: {self.db_type}. Supported types: {list(DatabaseType)}")
        
    def get_connection_string(self) -> str:
        """Generate SQLite connection string with proper validation and encoding"""
        try:
            database_path = self.config.get('database', 'app.db')
            # Handle absolute and relative paths
            if not os.path.isabs(database_path):
                database_path = os.path.abspath(database_path)
            # Add encoding parameter to SQLite connection string
            return f"sqlite:///{database_path}?charset=utf8"
                
        except Exception as e:
            self.logger.error(f"Failed to build connection string: {e}")
            raise
    
    
    def create_engine(self) -> Engine:
        """Create SQLAlchemy engine with SQLite-specific settings and error handling"""
        try:
            connection_string = self.get_connection_string()
            self.logger.info(f"Creating SQLite engine")
            
            engine_kwargs = {
                'echo': self.config.get('echo', False),
                'pool_pre_ping': self.config.get('pool_pre_ping', True),
                'poolclass': StaticPool,
                'connect_args': {
                    'check_same_thread': False,
                    'timeout': 30  # 30 second timeout for SQLite
                }
            }
            
            # Ensure directory exists for SQLite database
            db_path = self.config.get('database', 'app.db')
            if not os.path.isabs(db_path):
                db_path = os.path.abspath(db_path)
            db_dir = os.path.dirname(db_path)
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir, exist_ok=True)
            
            self.engine = create_engine(connection_string, **engine_kwargs)
            
            # Test connection
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            
            self.logger.info(f"Successfully connected to SQLite database")
            return self.engine
            
        except SQLAlchemyError as e:
            self.logger.error(f"SQLite connection failed: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error during engine creation: {e}")
            raise
    
    def create_session_factory(self) -> sessionmaker:
        """Create session factory with error handling"""
        try:
            if not self.engine:
                self.create_engine()
            
            self.SessionLocal = sessionmaker(
                autocommit=False,
                autoflush=False,
                bind=self.engine,
                expire_on_commit=False  # Prevent lazy loading issues
            )
            
            self.logger.info("Session factory created successfully")
            return self.SessionLocal
            
        except Exception as e:
            self.logger.error(f"Failed to create session factory: {e}")
            raise

# Default configurations for different environments
DEFAULT_CONFIGS = {
    'development': {
        'type': 'sqlite',
        'database': 'dev.db',
        'echo': False,
        'pool_pre_ping': True
    },
    'testing': {
        'type': 'sqlite',
        'database': ':memory:',
        'echo': False,
        'pool_pre_ping': False
    },
    'production': {
        'type': 'sqlite',
        'database': 'app.db',
        'echo': False,
        'pool_pre_ping': True
    }
}

def get_config_from_env() -> Dict[str, Any]:
    """Get SQLite database configuration from environment variables"""
    config = {
        'type': 'sqlite',
        'database': os.getenv('DB_DATABASE', 'dev.db'),
        'echo': os.getenv('DB_ECHO', 'false').lower() == 'true',
        'pool_pre_ping': os.getenv('DB_POOL_PRE_PING', 'true').lower() == 'true',
    }
    
    return config
