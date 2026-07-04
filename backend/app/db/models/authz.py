"""
Models for the advanced authorization models:

- Doc            : a demo protected resource (has an owner + attributes for ABAC)
- AclEntry       : explicit per-resource grant to a subject (ACL)
- RelationTuple  : Zanzibar-style (object, relation, subject) edge (ReBAC)
- AbacPolicy     : an attribute/condition policy evaluated by the ABAC engine
"""
from sqlalchemy import ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin


class Doc(Base, TimestampMixin):
    __tablename__ = "docs"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(Integer, index=True, nullable=False)
    owner_id: Mapped[int] = mapped_column(Integer, index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    # ABAC attributes, e.g. {"classification": "secret", "department": "eng"}
    classification: Mapped[str] = mapped_column(String(32), default="internal", nullable=False)
    attributes: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)


class AclEntry(Base, TimestampMixin):
    """Direct grant: subject `subject` may `permission` on object `resource`."""

    __tablename__ = "acl_entries"

    id: Mapped[int] = mapped_column(primary_key=True)
    resource: Mapped[str] = mapped_column(String(128), index=True, nullable=False)  # "doc:42"
    subject: Mapped[str] = mapped_column(String(128), index=True, nullable=False)   # "user:5"
    permission: Mapped[str] = mapped_column(String(64), nullable=False)             # "read"

    __table_args__ = (Index("ix_acl_lookup", "resource", "subject", "permission"),)


class RelationTuple(Base, TimestampMixin):
    """
    Zanzibar edge: object#relation@subject.
      ("doc:42", "editor", "user:5")             — user 5 is an editor of doc 42
      ("group:eng", "member", "user:5")          — user 5 is a member of group eng
      ("doc:42", "viewer", "group:eng#member")   — members of eng can view doc 42
    """

    __tablename__ = "relation_tuples"

    id: Mapped[int] = mapped_column(primary_key=True)
    object: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    relation: Mapped[str] = mapped_column(String(64), nullable=False)
    subject: Mapped[str] = mapped_column(String(160), index=True, nullable=False)

    __table_args__ = (Index("ix_rel_lookup", "object", "relation"),)


class AbacPolicy(Base, TimestampMixin):
    """
    An attribute-based policy. `condition` is a small JSON rule tree evaluated
    against a context {subject, resource, action, env}. `effect` is allow|deny.
    """

    __tablename__ = "abac_policies"

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(Integer, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    effect: Mapped[str] = mapped_column(String(8), default="allow", nullable=False)  # allow|deny
    action: Mapped[str] = mapped_column(String(64), default="*", nullable=False)     # "read" or "*"
    condition: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
