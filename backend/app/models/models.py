"""
Database Models - SQLAlchemy 2.0 async ORM models
Covers: Organizations, Users, Domains (whitelist), Scans, Findings, Reports, AuditLogs
"""
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import (
    Boolean, DateTime, Float, ForeignKey, Integer, JSON,
    String, Text, Enum as SAEnum, Index
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
import enum


def utcnow():
    return datetime.now(timezone.utc)


def new_uuid():
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


# ── Enums ─────────────────────────────────────────────────────────────────────

class UserRole(str, enum.Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanProfile(str, enum.Enum):
    FULL_OWASP = "full_owasp"
    QUICK = "quick"
    API_SECURITY = "api_security"
    AUTH_DEEP = "auth_deep"
    PASSIVE_ONLY = "passive_only"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, enum.Enum):
    OPEN = "open"
    IN_REVIEW = "in_review"
    ACCEPTED = "accepted"
    FIXED = "fixed"
    FALSE_POSITIVE = "false_positive"


class DomainStatus(str, enum.Enum):
    PENDING = "pending"
    VERIFIED = "verified"
    REVOKED = "revoked"


# ── Models ────────────────────────────────────────────────────────────────────

class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    plan: Mapped[str] = mapped_column(String(50), default="enterprise")
    max_scans_per_month: Mapped[int] = mapped_column(Integer, default=100)
    max_concurrent_scans: Mapped[int] = mapped_column(Integer, default=3)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    users: Mapped[List["User"]] = relationship("User", back_populates="organization", cascade="all, delete-orphan")
    domains: Mapped[List["WhitelistedDomain"]] = relationship("WhitelistedDomain", back_populates="organization", cascade="all, delete-orphan")
    scans: Mapped[List["Scan"]] = relationship("Scan", back_populates="organization", cascade="all, delete-orphan")


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(SAEnum(UserRole), default=UserRole.VIEWER)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    organization: Mapped["Organization"] = relationship("Organization", back_populates="users")
    scans: Mapped[List["Scan"]] = relationship("Scan", back_populates="initiated_by_user")
    audit_logs: Mapped[List["AuditLog"]] = relationship("AuditLog", back_populates="user")

    __table_args__ = (Index("ix_users_email", "email"), Index("ix_users_org_id", "org_id"))


class WhitelistedDomain(Base):
    """Only domains in this table can be scanned. Prevents unauthorized scanning."""
    __tablename__ = "whitelisted_domains"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    domain: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[DomainStatus] = mapped_column(SAEnum(DomainStatus), default=DomainStatus.PENDING)
    verification_token: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    added_by: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    organization: Mapped["Organization"] = relationship("Organization", back_populates="domains")

    __table_args__ = (Index("ix_domains_org_domain", "org_id", "domain"),)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    initiated_by: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    target_domain: Mapped[str] = mapped_column(String(500), nullable=False)
    profile: Mapped[ScanProfile] = mapped_column(SAEnum(ScanProfile), default=ScanProfile.FULL_OWASP)
    status: Mapped[ScanStatus] = mapped_column(SAEnum(ScanStatus), default=ScanStatus.QUEUED)

    # Config
    enabled_modules: Mapped[dict] = mapped_column(JSON, default=dict)
    scan_options: Mapped[dict] = mapped_column(JSON, default=dict)

    # Results summary
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    urls_crawled: Mapped[int] = mapped_column(Integer, default=0)
    total_requests: Mapped[int] = mapped_column(Integer, default=0)
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    info_count: Mapped[int] = mapped_column(Integer, default=0)

    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    organization: Mapped["Organization"] = relationship("Organization", back_populates="scans")
    initiated_by_user: Mapped["User"] = relationship("User", back_populates="scans")
    findings: Mapped[List["Finding"]] = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    reports: Mapped[List["Report"]] = relationship("Report", back_populates="scan", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_scans_org_id", "org_id"),
        Index("ix_scans_status", "status"),
        Index("ix_scans_target_domain", "target_domain"),
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)

    # Classification
    owasp_category: Mapped[str] = mapped_column(String(10), nullable=False)   # A01–A10
    owasp_name: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[Severity] = mapped_column(SAEnum(Severity), nullable=False)
    status: Mapped[FindingStatus] = mapped_column(SAEnum(FindingStatus), default=FindingStatus.OPEN)

    # Location
    affected_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    affected_parameter: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    http_method: Mapped[str] = mapped_column(String(10), default="GET")

    # Risk scoring: Risk = severity_weight × confidence × exposure
    severity_weight: Mapped[float] = mapped_column(Float, default=5.0)   # 1–10
    confidence: Mapped[float] = mapped_column(Float, default=0.8)         # 0.0–1.0
    exposure: Mapped[float] = mapped_column(Float, default=1.0)           # 0.0–1.0 (public=1.0)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)         # computed
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Evidence (non-destructive, safe)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    # e.g. {"request_snippet": "...", "response_pattern": "...", "parameter": "id", "error_signature": "..."}

    # Remediation
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    references: Mapped[list] = mapped_column(JSON, default=list)
    cve_ids: Mapped[list] = mapped_column(JSON, default=list)

    # False positive tracking
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    fp_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")

    __table_args__ = (
        Index("ix_findings_scan_id", "scan_id"),
        Index("ix_findings_severity", "severity"),
        Index("ix_findings_owasp", "owasp_category"),
    )


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    generated_by: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    format: Mapped[str] = mapped_column(String(10), nullable=False)  # html, json, pdf
    file_path: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    file_size_bytes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="reports")


class AuditLog(Base):
    """Immutable audit trail of all platform actions."""
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"), nullable=False)
    user_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    resource_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    user: Mapped[Optional["User"]] = relationship("User", back_populates="audit_logs")

    __table_args__ = (
        Index("ix_audit_org_id", "org_id"),
        Index("ix_audit_action", "action"),
        Index("ix_audit_created_at", "created_at"),
    )


class PasswordResetToken(Base):
    """One-time password reset tokens — expire after 30 min, single use."""

    __tablename__ = "password_reset_tokens"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=new_uuid
    )

    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    token_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False
    )

    used: Mapped[bool] = mapped_column(
        Boolean,
        default=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utcnow
    )

    user: Mapped["User"] = relationship(
        "User",
        backref="reset_tokens"
    )