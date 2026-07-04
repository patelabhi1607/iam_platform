"""Access Control Lists — explicit per-resource grants to a subject."""
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.authz import AclEntry


async def has_acl_grant(db: AsyncSession, resource: str, subject: str, permission: str) -> bool:
    row = (
        await db.execute(
            select(AclEntry.id).where(
                AclEntry.resource == resource,
                AclEntry.subject == subject,
                AclEntry.permission.in_([permission, "*"]),
            )
        )
    ).first()
    return row is not None
