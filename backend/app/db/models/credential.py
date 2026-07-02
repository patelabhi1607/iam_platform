"""Non-password credentials: API keys, personal access tokens, server sessions."""
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin


class ApiKey(Base, TimestampMixin):
    """Machine credential. The raw key is shown once; only its hash is stored."""

    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    prefix: Mapped[str] = mapped_column(String(12), index=True, nullable=False)  # for display/lookup
    hashed_key: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    # Space-separated scopes limiting what the key can do (e.g. "document:read metrics:read")
    scopes: Mapped[str] = mapped_column(Text, default="", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class PersonalAccessToken(Base, TimestampMixin):
    """User-owned token acting on the user's behalf (like a GitHub PAT)."""

    __tablename__ = "personal_access_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    prefix: Mapped[str] = mapped_column(String(12), index=True, nullable=False)
    hashed_token: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    scopes: Mapped[str] = mapped_column(Text, default="", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
