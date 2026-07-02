from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import CurrentPrincipal
from app.db.models.rbac import Membership, Role
from app.db.models.tenant import Tenant
from app.db.session import get_db
from app.schemas.core import CreateTenantRequest, TenantResponse
from app.services import tenant_service

router = APIRouter(prefix="/tenants", tags=["tenants"])
Db = Annotated[AsyncSession, Depends(get_db)]


@router.get("", response_model=list[TenantResponse])
async def my_tenants(principal: CurrentPrincipal, db: Db):
    """Tenants the current user belongs to (multi-tenancy)."""
    if principal.user_id is None:
        return []
    rows = (
        await db.execute(
            select(Tenant).join(Membership, Membership.tenant_id == Tenant.id)
            .where(Membership.user_id == principal.user_id)
        )
    ).scalars().all()
    return rows


@router.post("", response_model=TenantResponse, status_code=201)
async def create_tenant(body: CreateTenantRequest, principal: CurrentPrincipal, db: Db):
    """Any authenticated user can create a tenant and becomes its owner."""
    tenant = await tenant_service.create_tenant_with_roles(db, body.slug, body.name)
    await tenant_service.make_owner(db, principal.user_id, tenant.id)
    return tenant
