"""
RBAC with fine-grained permissions and role hierarchy.

- Permission: an atomic capability, named "resource:action" (e.g. "document:read").
- Role: a named bundle of permissions, scoped to a tenant, optionally inheriting
  from a parent role (hierarchy).
- Membership: links a user to a tenant with one role (the user's role in that org).
"""
from sqlalchemy import ForeignKey, String, Table, Column, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin

# Role ↔ Permission many-to-many
role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column("role_id", ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    Column("permission_id", ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True),
)


class Permission(Base, TimestampMixin):
    __tablename__ = "permissions"

    id: Mapped[int] = mapped_column(primary_key=True)
    # "resource:action", e.g. "document:read", "user:invite", "*:*" for superadmin
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(256), nullable=True)


class Role(Base, TimestampMixin):
    __tablename__ = "roles"
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_role_tenant_name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str | None] = mapped_column(String(256), nullable=True)
    # Role hierarchy — a role inherits all permissions of its parent (transitively).
    parent_id: Mapped[int | None] = mapped_column(
        ForeignKey("roles.id", ondelete="SET NULL"), nullable=True
    )
    # System roles (owner/admin/member/viewer) are seeded and cannot be deleted.
    is_system: Mapped[bool] = mapped_column(default=False, nullable=False)

    permissions: Mapped[list[Permission]] = relationship(
        secondary=role_permissions, lazy="selectin"
    )
    parent: Mapped["Role | None"] = relationship(remote_side=[id], lazy="selectin")


class Membership(Base, TimestampMixin):
    """A user's membership in a tenant, carrying their role in that tenant."""

    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("user_id", "tenant_id", name="uq_membership_user_tenant"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=False
    )
    role_id: Mapped[int] = mapped_column(
        ForeignKey("roles.id", ondelete="RESTRICT"), nullable=False
    )

    role: Mapped[Role] = relationship(lazy="selectin")
