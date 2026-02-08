"""
Database configuration and models for security policy analysis.

Provides SQLAlchemy ORM models for:
- Policy storage and versioning
- Analysis job tracking
- Result caching
- Audit logs
"""

from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, JSON, Boolean, Text, ForeignKey, UniqueConstraint, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import os
from typing import Optional

# Database configuration
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://user:password@localhost:5432/security_analysis"
)

# Create engine and session factory
engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for all models
Base = declarative_base()


class ServiceAccount(Base):
    """Represents an AWS/Azure/GCP service account for policy extraction."""
    __tablename__ = "service_accounts"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, index=True)
    provider = Column(String(50))  # aws, azure, gcp
    source_type = Column(String(50))  # arn, managed_identity, service_account
    credentials_json = Column(JSON)  # Encrypted in production
    created_at = Column(DateTime, default=datetime.utcnow)
    last_sync = Column(DateTime, nullable=True)
    
    # Relationships
    policies = relationship("Policy", back_populates="account")
    analysis_jobs = relationship("AnalysisJob", back_populates="account")
    
    __table_args__ = (
        Index('ix_provider_source', 'provider', 'source_type'),
    )


class Policy(Base):
    """Represents a security policy (IAM, firewall, etc)."""
    __tablename__ = "policies"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), index=True)
    policy_type = Column(String(50))  # iam, firewall, network, rbac
    provider = Column(String(50))  # aws, azure, gcp, generic
    version = Column(Integer, default=1)
    
    # Policy content
    principal = Column(String(500))  # User/role/service
    resource = Column(String(500))  # Target resource
    actions = Column(JSON)  # List of allowed actions
    conditions = Column(JSON, nullable=True)  # Condition block
    
    # Metadata
    account_id = Column(Integer, ForeignKey('service_accounts.id'))
    source_arn = Column(String(500))  # Original ARN/identifier
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    account = relationship("ServiceAccount", back_populates="policies")
    paths = relationship("AttackPath", back_populates="policy")
    
    __table_args__ = (
        UniqueConstraint('policy_type', 'source_arn', 'version', name='policy_version_unique'),
        Index('ix_provider_type', 'provider', 'policy_type'),
        Index('ix_principal_resource', 'principal', 'resource'),
    )


class AnalysisJob(Base):
    """Represents a path analysis job."""
    __tablename__ = "analysis_jobs"
    
    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(String(50), unique=True, index=True)  # UUIDv4
    
    # Job parameters
    source_node = Column(String(255))
    target_node = Column(String(255))
    context = Column(JSON)  # Execution context (IP, time, etc)
    max_depth = Column(Integer, default=5)
    
    # Account for traceability
    account_id = Column(Integer, ForeignKey('service_accounts.id'), nullable=True)
    
    # Results
    status = Column(String(20), default="pending")  # pending, running, completed, failed
    total_paths_found = Column(Integer, default=0)
    paths_pruned = Column(Integer, default=0)
    evaluation_time_ms = Column(Float)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    
    # Relationships
    account = relationship("ServiceAccount", back_populates="analysis_jobs")
    paths = relationship("AttackPath", back_populates="job")
    
    __table_args__ = (
        Index('ix_status_created', 'status', 'created_at'),
    )


class AttackPath(Base):
    """Represents a discovered attack path."""
    __tablename__ = "attack_paths"
    
    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(Integer, ForeignKey('analysis_jobs.id'))
    
    # Path data
    path_nodes = Column(JSON)  # List of nodes in order
    path_length = Column(Integer)
    risk_score = Column(Float)  # 0-100
    
    # Explanation
    explanation = Column(JSON)  # List of step explanations
    
    # First policy involved
    first_policy_id = Column(Integer, ForeignKey('policies.id'), nullable=True)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    job = relationship("AnalysisJob", back_populates="paths")
    policy = relationship("Policy", back_populates="paths")
    
    __table_args__ = (
        Index('ix_job_score', 'job_id', 'risk_score'),
    )


class PolicyChange(Base):
    """Audit log for policy changes."""
    __tablename__ = "policy_changes"
    
    id = Column(Integer, primary_key=True, index=True)
    policy_id = Column(Integer, ForeignKey('policies.id'))
    
    # Change details
    change_type = Column(String(20))  # added, modified, deleted
    old_value = Column(JSON, nullable=True)
    new_value = Column(JSON, nullable=True)
    
    # Metadata
    changed_at = Column(DateTime, default=datetime.utcnow, index=True)
    changed_by = Column(String(255), default="system")
    reason = Column(String(255), nullable=True)
    
    __table_args__ = (
        Index('ix_policy_changed', 'policy_id', 'changed_at'),
    )


class AnalysisCache(Base):
    """Cache for analysis results to speed up repeated queries."""
    __tablename__ = "analysis_cache"
    
    id = Column(Integer, primary_key=True, index=True)
    cache_key = Column(String(255), unique=True, index=True)
    
    # Cached data
    result = Column(JSON)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, index=True)
    hit_count = Column(Integer, default=0)
    
    __table_args__ = (
        Index('ix_expires', 'expires_at'),
    )


def init_db():
    """Initialize database tables."""
    Base.metadata.create_all(bind=engine)
    print("Database initialized successfully!")


def get_db():
    """Get database session for dependency injection."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


if __name__ == "__main__":
    init_db()
