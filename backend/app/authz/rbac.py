"""RBAC resolution — expand a user's role (with hierarchy) into effective permissions."""
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.rbac import Membership, Role


async def resolve_permissions(db: AsyncSession, user_id: int, tenant_id: int) -> set[str]:
    """
    Return the set of permission names the user effectively has in the tenant.
    Walks the role hierarchy so a role inherits every ancestor's permissions.
    """
    membership = (
        await db.execute(
            select(Membership).where(
                Membership.user_id == user_id, Membership.tenant_id == tenant_id
            )
        )
    ).scalar_one_or_none()
    if membership is None:
        return set()

    perms: set[str] = set()
    role: Role | None = membership.role
    seen: set[int] = set()
    # Climb the parent chain. We fetch each ancestor explicitly by id rather than
    # walking role.parent — async SQLAlchemy can't lazy-load relationships beyond
    # the first eagerly-loaded level, and the chain can be arbitrarily deep.
    while role is not None and role.id not in seen:
        seen.add(role.id)
        for p in role.permissions:
            perms.add(p.name)
        role = await db.get(Role, role.parent_id) if role.parent_id else None
    return perms


async def get_membership(db: AsyncSession, user_id: int, tenant_id: int) -> Membership | None:
    return (
        await db.execute(
            select(Membership).where(
                Membership.user_id == user_id, Membership.tenant_id == tenant_id
            )
        )
    ).scalar_one_or_none()
