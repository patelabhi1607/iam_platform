"""TOTP 2FA enrollment and recovery-code management (requires an authenticated user)."""
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import CurrentPrincipal
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.core import (
    MessageResponse,
    MfaEnrollBeginResponse,
    MfaEnrollConfirmRequest,
    RecoveryCodesResponse,
)
from app.services import mfa_service

router = APIRouter(prefix="/mfa", tags=["mfa"])
Db = Annotated[AsyncSession, Depends(get_db)]


async def _user(principal: CurrentPrincipal, db: AsyncSession) -> User:
    if principal.user_id is None:
        raise HTTPException(400, "MFA applies to user accounts only")
    return await db.get(User, principal.user_id)


@router.post("/enroll/begin", response_model=MfaEnrollBeginResponse)
async def enroll_begin(principal: CurrentPrincipal, db: Db):
    user = await _user(principal, db)
    secret, uri = await mfa_service.begin_enrollment(db, user)
    return MfaEnrollBeginResponse(secret=secret, otpauth_uri=uri)


@router.post("/enroll/confirm", response_model=RecoveryCodesResponse)
async def enroll_confirm(body: MfaEnrollConfirmRequest, principal: CurrentPrincipal, db: Db):
    user = await _user(principal, db)
    try:
        codes = await mfa_service.confirm_enrollment(db, user, body.code)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return RecoveryCodesResponse(recovery_codes=codes)


@router.post("/disable", response_model=MessageResponse)
async def disable(principal: CurrentPrincipal, db: Db):
    user = await _user(principal, db)
    await mfa_service.disable_mfa(db, user)
    return MessageResponse(message="MFA disabled")


@router.post("/recovery-codes/regenerate", response_model=RecoveryCodesResponse)
async def regenerate(principal: CurrentPrincipal, db: Db):
    user = await _user(principal, db)
    if not user.mfa_enabled:
        raise HTTPException(400, "Enable MFA first")
    return RecoveryCodesResponse(recovery_codes=await mfa_service.regenerate_recovery_codes(db, user))
