"""
SQLAlchemy ORM models for Argus.

Defines the database schema for scans, findings, IAM entities, and AWS accounts.
"""

import enum
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all models."""

    pass


class ScanType(str, enum.Enum):
    """Type of security scan."""

    IAC = "iac"
    AWS_CLOUD = "aws_cloud"
    SECRET = "secret"
    IAM = "iam"


class ScanStatus(str, enum.Enum):
    """Status of a scan."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(str, enum.Enum):
    """Severity level of a finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, enum.Enum):
    """Status of a finding."""

    OPEN = "open"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


class IAMEntityType(str, enum.Enum):
    """Type of IAM entity."""

    USER = "user"
    ROLE = "role"
    GROUP = "group"


class Scan(Base):
    """Represents a security scan execution."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_type: Mapped[ScanType] = mapped_column(Enum(ScanType), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False
    )
    
    # Target information
    target_info: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    
    # AWS account if applicable
    aws_account_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("aws_accounts.id"), nullable=True
    )
    
    # Timing
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Results summary
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    info_count: Mapped[int] = mapped_column(Integer, default=0)
    
    # Error info if failed
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Relationships
    findings: Mapped[list["Finding"]] = relationship(
        "Finding", back_populates="scan", cascade="all, delete-orphan"
    )
    aws_account: Mapped[Optional["AWSAccount"]] = relationship(
        "AWSAccount", back_populates="scans"
    )

    __table_args__ = (
        Index("idx_scans_type", "scan_type"),
        Index("idx_scans_status", "status"),
        Index("idx_scans_created_at", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<Scan(id={self.id}, type={self.scan_type}, status={self.status})>"


class Finding(Base):
    """Represents a security finding from a scan."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id"), nullable=False)
    
    # Finding identification
    rule_id: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), nullable=False)
    status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus), default=FindingStatus.OPEN, nullable=False
    )
    
    # Finding details
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    suggestion: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    # Resource information
    resource_id: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    resource_type: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    resource_arn: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    
    # Location (for code-based findings)
    file_path: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    line_number: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    commit_hash: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    
    # Additional metadata
    metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    
    # Confidence score for secret detection
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
    
    # Relationships
    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")

    __table_args__ = (
        Index("idx_findings_scan_id", "scan_id"),
        Index("idx_findings_severity", "severity"),
        Index("idx_findings_status", "status"),
        Index("idx_findings_rule_id", "rule_id"),
        Index("idx_findings_resource_type", "resource_type"),
    )

    def __repr__(self) -> str:
        return f"<Finding(id={self.id}, rule={self.rule_id}, severity={self.severity})>"


class IAMEntity(Base):
    """Represents an AWS IAM entity (User, Role, or Group)."""

    __tablename__ = "iam_entities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    aws_account_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("aws_accounts.id"), nullable=False
    )
    
    # Entity identification
    entity_type: Mapped[IAMEntityType] = mapped_column(Enum(IAMEntityType), nullable=False)
    entity_name: Mapped[str] = mapped_column(String(255), nullable=False)
    arn: Mapped[str] = mapped_column(String(1000), nullable=False, unique=True)
    
    # Entity details
    path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    created_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Policy information stored as JSONB
    inline_policies: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    attached_policies: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    
    # For users: access key info
    access_keys: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    mfa_enabled: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    password_enabled: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    last_used: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # For roles: trust policy
    trust_policy: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    
    # Group memberships (for users)
    groups: Mapped[list[str]] = mapped_column(JSONB, default=list)
    
    # Neo4j sync tracking
    neo4j_synced: Mapped[bool] = mapped_column(Boolean, default=False)
    neo4j_synced_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
    
    # Relationships
    aws_account: Mapped["AWSAccount"] = relationship("AWSAccount", back_populates="iam_entities")

    __table_args__ = (
        Index("idx_iam_entities_account_id", "aws_account_id"),
        Index("idx_iam_entities_type", "entity_type"),
        Index("idx_iam_entities_name", "entity_name"),
    )

    def __repr__(self) -> str:
        return f"<IAMEntity(type={self.entity_type}, name={self.entity_name})>"


class AWSAccount(Base):
    """Represents an AWS account configuration."""

    __tablename__ = "aws_accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    account_id: Mapped[str] = mapped_column(String(12), nullable=False, unique=True)
    account_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    account_alias: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    
    # Authentication configuration (encrypted in practice)
    profile_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    assume_role_arn: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    external_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    
    # Account status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_scanned_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Organization info
    organization_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    organizational_unit: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
    
    # Relationships
    scans: Mapped[list["Scan"]] = relationship("Scan", back_populates="aws_account")
    iam_entities: Mapped[list["IAMEntity"]] = relationship(
        "IAMEntity", back_populates="aws_account", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("idx_aws_accounts_account_id", "account_id"),
        Index("idx_aws_accounts_organization", "organization_id"),
    )

    def __repr__(self) -> str:
        return f"<AWSAccount(id={self.account_id}, name={self.account_name})>"
