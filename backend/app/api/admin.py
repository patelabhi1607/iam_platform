"""Tenant-scoped RBAC administration: roles, permissions, members."""
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import CurrentPrincipal, require_permission
from app.db.models.rbac import Membership, Permission, Role
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.core import (
    AssignRoleRequest,
    CreateRoleRequest,
    MemberResponse,
    MessageResponse,
    PermissionResponse,
    RoleResponse,
    UpdateRolePermissionsRequest,
)

router = APIRouter(prefix="/admin", tags=["admin-rbac"])
Db = Annotated[AsyncSession, Depends(get_db)]


def _role_out(r: Role) -> RoleResponse:
    return RoleResponse(
        id=r.id, name=r.name, description=r.description, parent_id=r.parent_id,
        is_system=r.is_system, permissions=sorted(p.name for p in r.permissions),
    )


@router.get("/permissions", response_model=list[PermissionResponse],
            dependencies=[Depends(require_permission("role:read"))])
async def list_permissions(db: Db):
    return (await db.execute(select(Permission).order_by(Permission.name))).scalars().all()


@router.get("/roles", response_model=list[RoleResponse],
            dependencies=[Depends(require_permission("role:read"))])
async def list_roles(principal: CurrentPrincipal, db: Db):
    roles = (
        await db.execute(select(Role).where(Role.tenant_id == principal.tenant_id))
    ).scalars().all()
    return [_role_out(r) for r in roles]


@router.post("/roles", response_model=RoleResponse, status_code=201,
             dependencies=[Depends(require_permission("role:manage"))])
async def create_role(body: CreateRoleRequest, principal: CurrentPrincipal, db: Db):
    perms = (
        await db.execute(select(Permission).where(Permission.name.in_(body.permissions)))
    ).scalars().all()
    role = Role(
        tenant_id=principal.tenant_id, name=body.name, description=body.description,
        parent_id=body.parent_id,
    )
    role.permissions = list(perms)
    db.add(role)
    await db.flush()
    await db.refresh(role)
    return _role_out(role)


@router.put("/roles/{role_id}/permissions", response_model=RoleResponse,
            dependencies=[Depends(require_permission("role:manage"))])
async def set_role_permissions(
    role_id: int, body: UpdateRolePermissionsRequest, principal: CurrentPrincipal, db: Db
):
    role = await db.get(Role, role_id)
    if role is None or role.tenant_id != principal.tenant_id:
        raise HTTPException(404, "Role not found")
    if role.is_system:
        raise HTTPException(400, "Cannot modify a system role")
    perms = (
        await db.execute(select(Permission).where(Permission.name.in_(body.permissions)))
    ).scalars().all()
    role.permissions = list(perms)
    await db.flush()
    await db.refresh(role)
    return _role_out(role)


@router.delete("/roles/{role_id}", status_code=204,
               dependencies=[Depends(require_permission("role:manage"))])
async def delete_role(role_id: int, principal: CurrentPrincipal, db: Db):
    role = await db.get(Role, role_id)
    if role is None or role.tenant_id != principal.tenant_id:
        raise HTTPException(404, "Role not found")
    if role.is_system:
        raise HTTPException(400, "Cannot delete a system role")
    await db.delete(role)


@router.get("/members", response_model=list[MemberResponse],
            dependencies=[Depends(require_permission("member:read"))])
async def list_members(principal: CurrentPrincipal, db: Db):
    rows = (
        await db.execute(
            select(Membership, User, Role)
            .join(User, User.id == Membership.user_id)
            .join(Role, Role.id == Membership.role_id)
            .where(Membership.tenant_id == principal.tenant_id)
        )
    ).all()
    return [MemberResponse(user_id=u.id, email=u.email, role=r.name) for _, u, r in rows]


@router.put("/members/{user_id}/role", response_model=MemberResponse,
            dependencies=[Depends(require_permission("role:manage"))])
async def assign_role(user_id: int, body: AssignRoleRequest, principal: CurrentPrincipal, db: Db):
    membership = (
        await db.execute(
            select(Membership).where(
                Membership.user_id == user_id, Membership.tenant_id == principal.tenant_id
            )
        )
    ).scalar_one_or_none()
    if membership is None:
        raise HTTPException(404, "Membership not found")
    role = (
        await db.execute(
            select(Role).where(Role.tenant_id == principal.tenant_id, Role.name == body.role_name)
        )
    ).scalar_one_or_none()
    if role is None:
        raise HTTPException(404, "Role not found")
    membership.role_id = role.id
    await db.flush()
    user = await db.get(User, user_id)
    return MemberResponse(user_id=user_id, email=user.email, role=role.name)
