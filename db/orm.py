from typing import Any, Dict, List, Optional, Type, TypeVar, Union
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy import create_engine, Engine, text
from sqlalchemy.exc import SQLAlchemyError
from contextlib import contextmanager
import logging
from datetime import datetime
import re

# Disable SQLAlchemy engine INFO logs globally - comprehensive list
logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy.pool').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy.dialects').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy.orm').setLevel(logging.WARNING)
logging.getLogger('sqlalchemy.engine.Engine').setLevel(logging.WARNING)

from .config import DatabaseConfig, get_config_from_env, DEFAULT_CONFIGS
from .models import Base, AIModel, Finding, Project, Confirmation, User

# Type variable for model classes
T = TypeVar('T', bound=Base)

class DatabaseORM:
    """Dynamic ORM class supporting multiple databases"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, environment: str = 'development', database_name: Optional[str] = None):
        """
        Initialize ORM with database configuration
        
        Args:
            config: Database configuration dictionary
            environment: Environment name (development, testing, production)
            database_name: Custom database name to override default
        """
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.ERROR)
        # Use provided config, environment config, or environment variables
        if config:
            self.config = DatabaseConfig(config)
        elif environment in DEFAULT_CONFIGS:
            # Override database name if provided
            env_config = DEFAULT_CONFIGS[environment].copy()
            if database_name:
                env_config['database'] = database_name
            self.config = DatabaseConfig(env_config)
        else:
            env_config = get_config_from_env()
            if database_name:
                env_config['database'] = database_name
            self.config = DatabaseConfig(env_config)
        
        self.engine: Optional[Engine] = None
        self.SessionLocal: Optional[sessionmaker] = None
        self._initialize()
    
    def _initialize(self):
        """Initialize database connection and session factory"""
        try:
            self.engine = self.config.create_engine()
            self.SessionLocal = self.config.create_session_factory()
            self.logger.info(f"Database initialized successfully: {self.config.db_type}")
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
            raise
    
    def create_tables(self):
        """Create all tables in the database"""
        try:
            Base.metadata.create_all(bind=self.engine)
            self.logger.info("Database tables created successfully")
        except Exception as e:
            self.logger.error(f"Failed to create tables: {e}")
            raise
    
    def drop_tables(self):
        """Drop all tables in the database"""
        try:
            Base.metadata.drop_all(bind=self.engine)
            self.logger.info("Database tables dropped successfully")
        except Exception as e:
            self.logger.error(f"Failed to drop tables: {e}")
            raise
    
    @contextmanager
    def get_session(self):
        """Context manager for database sessions"""
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            self.logger.error(f"Database session error: {e}")
            raise
        finally:
            session.close()
    
    def get_session_direct(self) -> Session:
        """Get a database session directly (caller responsible for closing)"""
        return self.SessionLocal()
    
    # Generic CRUD operations
    def create(self, session: Session, model_class: Type[T], **kwargs) -> T:
        """Create a new record"""
        try:
            instance = model_class(**kwargs)
            session.add(instance)
            session.flush()  # Get the ID without committing
            return instance
        except Exception as e:
            self.logger.error(f"Failed to create {model_class.__name__}: {e}")
            raise
    
    def get_by_id(self, session: Session, model_class: Type[T], record_id: int) -> Optional[T]:
        """Get record by ID"""
        try:
            return session.query(model_class).filter(model_class.id == record_id).first()
        except Exception as e:
            self.logger.error(f"Failed to get {model_class.__name__} by ID {record_id}: {e}")
            raise
    
    
    def get_all(self, session: Session, model_class: Type[T], limit: Optional[int] = None, offset: int = 0) -> List[T]:
        """Get all records with optional pagination"""
        try:
            query = session.query(model_class).offset(offset)
            if limit:
                query = query.limit(limit)
            return query.all()
        except Exception as e:
            self.logger.error(f"Failed to get all {model_class.__name__}: {e}")
            raise

    def get_all_with_relations(self, session: Session, model_class: Type[T], relations: List[str], limit: Optional[int] = None, offset: int = 0) -> List[T]:
        """Get all records with specified relations loaded"""
        try:
            from sqlalchemy.orm import joinedload
            query = session.query(model_class)
            
            # Add joinedload for each relation
            for relation in relations:
                if hasattr(model_class, relation):
                    query = query.options(joinedload(getattr(model_class, relation)))
            
            query = query.offset(offset)
            if limit:
                query = query.limit(limit)
            return query.all()
        except Exception as e:
            self.logger.error(f"Failed to get all {model_class.__name__} with relations: {e}")
            raise

    def get_by_id_with_relations(self, session: Session, model_class: Type[T], record_id: int, relations: List[str]) -> Optional[T]:
        """Get a record by ID with specified relations loaded"""
        try:
            from sqlalchemy.orm import joinedload
            query = session.query(model_class).filter(model_class.id == record_id)
            
            # Add joinedload for each relation
            for relation in relations:
                if hasattr(model_class, relation):
                    query = query.options(joinedload(getattr(model_class, relation)))
            
            return query.first()
        except Exception as e:
            self.logger.error(f"Failed to get {model_class.__name__} by ID with relations: {e}")
            raise
    
    def update(self, session: Session, instance: T, **kwargs) -> T:
        """Update an existing record"""
        try:
            for key, value in kwargs.items():
                if hasattr(instance, key):
                    setattr(instance, key, value)
            # updated_at is automatically handled by TimestampMixin
            session.flush()
            return instance
        except Exception as e:
            self.logger.error(f"Failed to update {instance.__class__.__name__}: {e}")
            raise
    
    def delete(self, session: Session, instance: T) -> bool:
        """Delete a record"""
        try:
            session.delete(instance)
            session.flush()
            return True
        except Exception as e:
            self.logger.error(f"Failed to delete {instance.__class__.__name__}: {e}")
            raise
    
    def delete_by_id(self, session: Session, model_class: Type[T], record_id: int) -> bool:
        """Delete record by ID"""
        try:
            instance = self.get_by_id(session, model_class, record_id)
            if instance:
                return self.delete(session, instance)
            return False
        except Exception as e:
            self.logger.error(f"Failed to delete {model_class.__name__} by ID {record_id}: {e}")
            raise
    
    # Query methods
    def filter_by(self, session: Session, model_class: Type[T], **filters) -> List[T]:
        """Filter records by given criteria"""
        try:
            return session.query(model_class).filter_by(**filters).all()
        except Exception as e:
            self.logger.error(f"Failed to filter {model_class.__name__}: {e}")
            raise
    
    def filter_one(self, session: Session, model_class: Type[T], **filters) -> Optional[T]:
        """Get first record matching criteria"""
        try:
            return session.query(model_class).filter_by(**filters).first()
        except Exception as e:
            self.logger.error(f"Failed to filter one {model_class.__name__}: {e}")
            raise
    
    def count(self, session: Session, model_class: Type[T], **filters) -> int:
        """Count records matching criteria"""
        try:
            query = session.query(model_class)
            if filters:
                query = query.filter_by(**filters)
            return query.count()
        except Exception as e:
            self.logger.error(f"Failed to count {model_class.__name__}: {e}")
            raise
    
    # Specific model methods
    def get_active_models(self, session: Session) -> List[AIModel]:
        """Get all active AI models"""
        return self.filter_by(session, AIModel, is_active=True)
    
    def get_active_agents(self, session: Session) -> List[AIModel]:
        """Get all active AI models (agents functionality replaced by AI models)"""
        return self.filter_by(session, AIModel, is_active=True)
    
    def get_project_findings(self, session: Session, project_id: int, severity: Optional[str] = None) -> List[Finding]:
        """Get findings for a specific project"""
        try:
            query = session.query(Finding).filter(Finding.project_id == project_id)
            if severity:
                query = query.filter(Finding.severity == severity)
            return query.all()
        except Exception as e:
            self.logger.error(f"Failed to get project findings: {e}")
            raise
    
    def get_findings_by_status(self, session: Session, status: str) -> List[Finding]:
        """Get findings by status"""
        try:
            return session.query(Finding).filter(Finding.status == status).all()
        except Exception as e:
            self.logger.error(f"Failed to get findings by status: {e}")
            raise
    
    def get_projects_by_status(self, session: Session, status: str) -> List[Project]:
        """Get projects by status"""
        try:
            return session.query(Project).filter(Project.status == status).all()
        except Exception as e:
            self.logger.error(f"Failed to get projects by status: {e}")
            raise
    
    def search_findings(self, session: Session, query: str, project_id: Optional[int] = None) -> List[Finding]:
        """Search findings by title or description"""
        try:
            search_query = session.query(Finding).filter(
                Finding.title.ilike(f"%{query}%") | 
                Finding.description.ilike(f"%{query}%")
            )
            if project_id:
                search_query = search_query.filter(Finding.project_id == project_id)
            return search_query.all()
        except Exception as e:
            self.logger.error(f"Failed to search findings: {e}")
            raise
    
    # Statistics methods
    def get_project_stats(self, session: Session, project_id: int) -> Dict[str, Any]:
        """Get statistics for a project"""
        try:
            total_findings = session.query(Finding).filter(Finding.project_id == project_id).count()
            open_findings = session.query(Finding).filter(
                Finding.project_id == project_id, 
                Finding.status == 'open'
            ).count()
            critical_findings = session.query(Finding).filter(
                Finding.project_id == project_id, 
                Finding.severity == 'critical'
            ).count()
            high_findings = session.query(Finding).filter(
                Finding.project_id == project_id, 
                Finding.severity == 'high'
            ).count()
            
            return {
                'total_findings': total_findings,
                'open_findings': open_findings,
                'critical_findings': critical_findings,
                'high_findings': high_findings,
                'resolved_findings': total_findings - open_findings
            }
        except Exception as e:
            self.logger.error(f"Failed to get project stats: {e}")
            raise
    
    def get_global_stats(self, session: Session) -> Dict[str, Any]:
        """Get global statistics"""
        try:
            total_projects = session.query(Project).count()
            total_findings = session.query(Finding).count()
            total_models = session.query(AIModel).count()
            total_agents = session.query(AIModel).count()
            
            return {
                'total_projects': total_projects,
                'total_findings': total_findings,
                'total_models': total_models,
                'total_agents': total_agents
            }
        except Exception as e:
            self.logger.error(f"Failed to get global stats: {e}")
            raise
    
    # Health check
    def health_check(self) -> bool:
        """Check database connectivity"""
        try:
            with self.get_session() as session:
                session.execute(text("SELECT 1"))
            return True
        except Exception as e:
            self.logger.error(f"Database health check failed: {e}")
            return False
    
    # Raw SQL execution
    def execute_raw_sql(self, session: Session, sql: str, params: Optional[Dict] = None) -> Any:
        """Execute raw SQL query"""
        try:
            result = session.execute(text(sql), params or {})
            return result
        except Exception as e:
            self.logger.error(f"Failed to execute raw SQL: {e}")
            raise

def get_orm(config: Optional[Dict[str, Any]] = None, environment: str = 'development', database_name: Optional[str] = None) -> DatabaseORM:
    """Create a new ORM instance with the specified configuration"""
    # If no config provided, use environment variables
    if config is None and database_name is None:
        config = get_config_from_env()
    return DatabaseORM(config, environment, database_name)
