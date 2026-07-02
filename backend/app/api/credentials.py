from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import CurrentPrincipal, require_permission
from app.db.models.credential import ApiKey, PersonalAccessToken
from app.db.session import get_db
from app.schemas.core import (
    ApiKeyCreatedResponse,
    ApiKeyResponse,
    CreateApiKeyRequest,
    CreatePatRequest,
    PatCreatedResponse,
)
from app.services import credential_service

router = APIRouter(tags=["credentials"])
Db = Annotated[AsyncSession, Depends(get_db)]


# ── API keys (tenant machine credentials) ────────────────────────────────────

@router.post("/api-keys", response_model=ApiKeyCreatedResponse, status_code=201,
             dependencies=[Depends(require_permission("apikey:manage"))])
async def create_api_key(body: CreateApiKeyRequest, principal: CurrentPrincipal, db: Db):
    key, raw = await credential_service.create_api_key(
        db, principal.tenant_id, body.name, " ".join(body.scopes)
    )
    return ApiKeyCreatedResponse(
        id=key.id, name=key.name, prefix=key.prefix, scopes=key.scopes,
        is_active=key.is_active, created_at=key.created_at, api_key=raw,
    )


@router.get("/api-keys", response_model=list[ApiKeyResponse],
            dependencies=[Depends(require_permission("apikey:manage"))])
async def list_api_keys(principal: CurrentPrincipal, db: Db):
    return (
        await db.execute(select(ApiKey).where(ApiKey.tenant_id == principal.tenant_id))
    ).scalars().all()


@router.delete("/api-keys/{key_id}", status_code=204,
               dependencies=[Depends(require_permission("apikey:manage"))])
async def revoke_api_key(key_id: int, principal: CurrentPrincipal, db: Db):
    key = await db.get(ApiKey, key_id)
    if key is None or key.tenant_id != principal.tenant_id:
        raise HTTPException(404, "API key not found")
    key.is_active = False


# ── Personal access tokens (user credentials) ────────────────────────────────

@router.post("/pats", response_model=PatCreatedResponse, status_code=201)
async def create_pat(body: CreatePatRequest, principal: CurrentPrincipal, db: Db):
    if principal.user_id is None:
        raise HTTPException(400, "Only user principals can create PATs")
    pat, raw = await credential_service.create_pat(
        db, principal.user_id, body.name, " ".join(body.scopes)
    )
    return PatCreatedResponse(id=pat.id, name=pat.name, prefix=pat.prefix, token=raw)


@router.get("/pats")
async def list_pats(principal: CurrentPrincipal, db: Db):
    if principal.user_id is None:
        return []
    rows = (
        await db.execute(
            select(PersonalAccessToken).where(PersonalAccessToken.user_id == principal.user_id)
        )
    ).scalars().all()
    return [
        {"id": p.id, "name": p.name, "prefix": p.prefix, "scopes": p.scopes, "is_active": p.is_active}
        for p in rows
    ]


@router.delete("/pats/{pat_id}", status_code=204)
async def revoke_pat(pat_id: int, principal: CurrentPrincipal, db: Db):
    pat = await db.get(PersonalAccessToken, pat_id)
    if pat is None or pat.user_id != principal.user_id:
        raise HTTPException(404, "PAT not found")
    pat.is_active = False
