"""
Federated identity models.

- SocialIdentity: links a local user to an external IdP account (Google/GitHub/SAML).
- OAuthClient: a third-party app registered against THIS platform acting as an
  OAuth2 provider (authorization_code + PKCE, client_credentials, device_code).
"""
from sqlalchemy import Boolean, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin


class SocialIdentity(Base, TimestampMixin):
    __tablename__ = "social_identities"
    __table_args__ = (
        UniqueConstraint("provider", "subject", name="uq_social_provider_subject"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)   # google | github | saml
    subject: Mapped[str] = mapped_column(String(255), nullable=False)   # external user id
    email: Mapped[str | None] = mapped_column(String(320), nullable=True)


class OAuthClient(Base, TimestampMixin):
    __tablename__ = "oauth_clients"

    id: Mapped[int] = mapped_column(primary_key=True)
    client_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    # Confidential clients have a secret; public clients (SPAs/native) rely on PKCE.
    client_secret_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    redirect_uris: Mapped[str] = mapped_column(Text, default="", nullable=False)      # space-separated
    allowed_scopes: Mapped[str] = mapped_column(Text, default="", nullable=False)     # space-separated
    grant_types: Mapped[str] = mapped_column(
        Text, default="authorization_code refresh_token", nullable=False
    )
    is_confidential: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
