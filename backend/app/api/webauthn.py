"""WebAuthn / passkey registration and login endpoints."""
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import CurrentPrincipal
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.core import TokenPair
from app.services import auth_service, webauthn_service

router = APIRouter(prefix="/webauthn", tags=["webauthn"])
Db = Annotated[AsyncSession, Depends(get_db)]


# ── Registration (authenticated user adds a passkey) ─────────────────────────

@router.post("/register/begin")
async def register_begin(principal: CurrentPrincipal, db: Db):
    if principal.user_id is None:
        raise HTTPException(400, "Passkeys apply to user accounts only")
    user = await db.get(User, principal.user_id)
    return await webauthn_service.registration_options(user)


@router.post("/register/complete")
async def register_complete(
    principal: CurrentPrincipal, db: Db, credential: Annotated[dict[str, Any], Body()]
):
    user = await db.get(User, principal.user_id)
    try:
        await webauthn_service.verify_registration(db, user, credential)
    except Exception as e:
        raise HTTPException(400, f"Registration failed: {e}")
    return {"message": "Passkey registered"}


# ── Authentication (login with a passkey) ────────────────────────────────────

@router.post("/authenticate/begin")
async def authenticate_begin(db: Db, email: Annotated[str, Body(embed=True)]):
    return await webauthn_service.authentication_options(db, email)


@router.post("/authenticate/complete", response_model=TokenPair)
async def authenticate_complete(
    db: Db,
    email: Annotated[str, Body()],
    credential: Annotated[dict[str, Any], Body()],
):
    try:
        user = await webauthn_service.verify_authentication(db, email, credential)
    except Exception as e:
        raise HTTPException(401, f"Authentication failed: {e}")
    tenant_id = await auth_service.resolve_or_create_tenant(db, user)
    return await auth_service.issue_token_pair(user, tenant_id, mfa_satisfied=True)
