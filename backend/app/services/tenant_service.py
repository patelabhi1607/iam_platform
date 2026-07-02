"""Tenant provisioning — creates a tenant with its system roles and an owner."""
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.authz.catalog import OWNER_ROLE, PERMISSIONS, SYSTEM_ROLES
from app.db.models.rbac import Membership, Permission, Role
from app.db.models.tenant import Tenant


async def ensure_permissions(db: AsyncSession) -> dict[str, Permission]:
    """Make sure every catalog permission exists; return name→Permission."""
    existing = {p.name: p for p in (await db.execute(select(Permission))).scalars().all()}
    for name, desc in PERMISSIONS.items():
        if name not in existing:
            p = Permission(name=name, description=desc)
            db.add(p)
            existing[name] = p
    await db.flush()
    return existing


async def create_tenant_with_roles(db: AsyncSession, slug: str, name: str) -> Tenant:
    tenant = Tenant(slug=slug, name=name)
    db.add(tenant)
    await db.flush()

    perms = await ensure_permissions(db)
    created: dict[str, Role] = {}
    # Roles are ordered parent-last in the catalog, so resolve parents by name.
    for role_name, parent_name, perm_names in SYSTEM_ROLES:
        role = Role(
            tenant_id=tenant.id,
            name=role_name,
            is_system=True,
            parent_id=created[parent_name].id if parent_name else None,
        )
        role.permissions = [perms[pn] for pn in perm_names]
        db.add(role)
        await db.flush()
        created[role_name] = role
    return tenant


async def add_member(db: AsyncSession, user_id: int, tenant_id: int, role_name: str) -> Membership:
    role = (
        await db.execute(
            select(Role).where(Role.tenant_id == tenant_id, Role.name == role_name)
        )
    ).scalar_one()
    m = Membership(user_id=user_id, tenant_id=tenant_id, role_id=role.id)
    db.add(m)
    await db.flush()
    return m


async def make_owner(db: AsyncSession, user_id: int, tenant_id: int) -> Membership:
    return await add_member(db, user_id, tenant_id, OWNER_ROLE)
