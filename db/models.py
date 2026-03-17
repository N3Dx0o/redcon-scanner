from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Table, JSON, Boolean, Float, Enum as SQLEnum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
from enum import Enum
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import uuid

Base = declarative_base()


class User(Base, UserMixin):
    """User account for dashboard authentication."""
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(80), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(512), nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login_at = Column(DateTime, nullable=True)
    api_key = Column(String(64), unique=True, nullable=True, index=True)
    notify_scan_complete = Column(Boolean, default=True, nullable=False)
    notify_critical_findings = Column(Boolean, default=True, nullable=False)
    onboarding_complete = Column(Boolean, default=False, nullable=False)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


class TimestampMixin:
    """Mixin class for created_at and updated_at timestamps"""
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class FindingStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    IGNORED = "ignored"

class ProjectStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SCANNED = "scanned"
    ARCHIVED = "archived"
    SCANNING = "scanning"

class InputType(str, Enum):
    ZIP_FILE = "zip_file"
    GIT_LINK = "git_link"

class TaskType(str, Enum):
    VALIDATE = "validate"
    SCAN = "scan"

class TaskStatus(str, Enum):
    PENDING = "pending"
    EXECUTED = "executed"

# Association table for many-to-many relationship between findings and models
finding_models = Table(
    'finding_models',
    Base.metadata,
    Column('finding_id', Integer, ForeignKey('findings.id'), primary_key=True),
    Column('model_id', Integer, ForeignKey('ai_models.id'), primary_key=True)
)

# Association table for many-to-many relationship between projects and models
project_models = Table(
    'project_models',
    Base.metadata,
    Column('project_id', Integer, ForeignKey('projects.id'), primary_key=True),
    Column('model_id', Integer, ForeignKey('ai_models.id'), primary_key=True)
)




class AIModel(Base, TimestampMixin):
    __tablename__ = 'ai_models'
    
    id = Column(Integer, primary_key=True, index=True)
    model_name = Column(String(255), nullable=False, index=True)
    vendor = Column(String(255), nullable=False, index=True)
    api_key = Column(String(1000), nullable=False)  # Increased length for longer keys
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    
    # Relationships
    findings = relationship("Finding", secondary=finding_models, back_populates="confirmed_models")
    projects = relationship("Project", secondary=project_models, back_populates="ai_models")
    confirmations = relationship("Confirmation", back_populates="model", cascade="all, delete-orphan")
    tasks = relationship("Task", back_populates="model", cascade="all, delete-orphan")


class Finding(Base, TimestampMixin):
    __tablename__ = 'findings'
    
    id = Column(Integer, primary_key=True, index=True)
    file_path = Column(String(1000), nullable=False, index=True)
    title = Column(String(500), nullable=False, index=True)
    description = Column(Text, nullable=False)
    recommendation = Column(Text, nullable=True)
    
    # Severity and status
    severity = Column(SQLEnum(SeverityLevel), default=SeverityLevel.MEDIUM, nullable=False, index=True)
    status = Column(SQLEnum(FindingStatus), default=FindingStatus.OPEN, nullable=False, index=True)
        
    # JSON field to store list of impacted files with their line numbers
    impacted_files = Column(JSON, nullable=True)  # Format: [{"file_path": "path/to/file.py", "lines": [10, 15, 20], "code": "snippet"}]
    
    # Foreign key to project
    project_id = Column(Integer, ForeignKey('projects.id'), nullable=False, index=True)
    
    # Additional timestamp for resolution
    resolved_at = Column(DateTime, nullable=True)
    
    # Relationships
    project = relationship("Project", back_populates="findings")
    confirmed_models = relationship("AIModel", secondary=finding_models, back_populates="findings")
    confirmations = relationship("Confirmation", back_populates="finding", cascade="all, delete-orphan")

class Confirmation(Base, TimestampMixin):
    __tablename__ = 'confirmations'
    
    id = Column(Integer, primary_key=True, index=True)
    justification = Column(Text, nullable=False)
    evidence_analysis = Column(Text, nullable=False)
    exploit_feasibility = Column(Text, nullable=False)
    is_remote_attack = Column(Boolean, nullable=False, index=True)
    false_positive = Column(Boolean, nullable=False, index=True)
    
    # Foreign keys
    finding_id = Column(Integer, ForeignKey('findings.id'), nullable=False, index=True)
    model_id = Column(Integer, ForeignKey('ai_models.id'), nullable=False, index=True)
    
    # Relationships
    finding = relationship("Finding", back_populates="confirmations")
    model = relationship("AIModel", back_populates="confirmations")


class Task(Base, TimestampMixin):
    __tablename__ = 'tasks'
    
    id = Column(Integer, primary_key=True, index=True)
    task_type = Column(SQLEnum(TaskType), nullable=False, index=True)
    tools = Column(JSON, nullable=True)  # Array of tool names as strings
    status = Column(SQLEnum(TaskStatus), default=TaskStatus.PENDING, nullable=False, index=True)
    cost = Column(Float, nullable=True)
    cmd = Column(String(1000), nullable=True)
    
    # Foreign key to AI model
    model_id = Column(Integer, ForeignKey('ai_models.id'), nullable=False, index=True)
    
    # Relationships
    model = relationship("AIModel", back_populates="tasks")




class Project(Base, TimestampMixin):
    __tablename__ = 'projects'
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    zip_file_path = Column(String(1000), nullable=True)  # Made nullable since we now have input_type
    base_path = Column(String(1000), nullable=False)
    cost = Column(Float, nullable=True)
    
    # New fields
    git_link = Column(String(1000), nullable=True)
    excluded_dirs = Column(JSON, nullable=True)  # Array of directory paths to exclude
    included_dirs = Column(JSON, nullable=True)  # Array of directory paths to include
    max_cost = Column(Float, nullable=True)
    input_type = Column(SQLEnum(InputType), nullable=False, default=InputType.ZIP_FILE, index=True)
    threat_models = Column(JSON, nullable=True)  # Array of threat model names as strings
    
    # Project metadata
    status = Column(SQLEnum(ProjectStatus), default=ProjectStatus.ACTIVE, nullable=False, index=True)
    
    # Additional timestamps
    last_scanned_at = Column(DateTime, nullable=True, index=True)
    last_modified_at = Column(DateTime, nullable=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    
    # Relationships
    findings = relationship("Finding", back_populates="project", cascade="all, delete-orphan")
    ai_models = relationship("AIModel", secondary=project_models, back_populates="projects")
    facts = relationship("Fact", back_populates="project", cascade="all, delete-orphan")


class FactType(str, Enum):
    ARCHITECTURE = "architecture"
    ATTACK_SURFACE = "attack_surface"
    DEPENDENCY = "dependency"
    DATA_FLOW = "data_flow"
    ACCESS_CONTROL = "access_control"
    DANGEROUS_FUNCTION = "dangerous_function"
    VALIDATION = "validation"
    CRYPTO = "cryptography"
    STATE_LOGIC = "state_logic"
    EXTERNAL_INTERACTION = "external_interaction"
    THREAT_MODEL = "threat_model"

class Fact(Base, TimestampMixin):
#     {
#   "type": "dependency",
#   "content": "The project uses express@4.17.1 which has known vulnerabilities in body-parser."
# }

# {
#   "type": "attack_surface",
#   "content": "POST /api/v2/subscribe/{streamId} allows WebSocket frames from unauthorized sources."
# }

    __tablename__ = 'facts'
    
    id = Column(Integer, primary_key=True, index=True)

    
    content = Column(Text, nullable=False)
    type = Column(SQLEnum(FactType), nullable=False, index=True)

    # Relationships
    project_id = Column(Integer, ForeignKey('projects.id'), nullable=False, index=True)
    project = relationship("Project", back_populates="facts")
