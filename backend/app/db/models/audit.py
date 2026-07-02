from datetime import datetime

from sqlalchemy import DateTime, Index, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AuditLog(Base):
    """Immutable trail of security-relevant events (logins, authz decisions, admin changes)."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    tenant_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    event: Mapped[str] = mapped_column(String(64), nullable=False)      # e.g. "login.success"
    method: Mapped[str | None] = mapped_column(String(32), nullable=True)  # authn method used
    detail: Mapped[str | None] = mapped_column(String(512), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    outcome: Mapped[str] = mapped_column(String(16), default="success", nullable=False)

    __table_args__ = (Index("ix_audit_event_ts", "event", "timestamp"),)
