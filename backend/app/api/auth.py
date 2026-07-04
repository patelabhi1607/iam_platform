from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.deps import CurrentPrincipal, get_access_token_claims_optional
from app.db.models.rbac import Membership
from app.db.session import get_db
from app.schemas.core import (
    LoginChallenge,
    LoginRequest,
    LogoutRequest,
    MessageResponse,
    MfaVerifyRequest,
    RefreshRequest,
    RegisterRequest,
    TokenPair,
    UserResponse,
)
from app.services import auth_service, tenant_service
from app.services.auth_service import AuthError

router = APIRouter(prefix="/auth", tags=["auth"])
Db = Annotated[AsyncSession, Depends(get_db)]


def _raise(e: AuthError):
    raise HTTPException(status_code=e.status_code, detail=e.message)


async def _first_tenant(db: AsyncSession, user_id: int) -> int | None:
    m = (
        await db.execute(select(Membership).where(Membership.user_id == user_id).limit(1))
    ).scalar_one_or_none()
    return m.tenant_id if m else None


@router.post("/register", response_model=UserResponse, status_code=201)
async def register(body: RegisterRequest, db: Db):
    try:
        user = await auth_service.register(db, body.email, body.password, body.full_name)
    except AuthError as e:
        _raise(e)
    # Optionally create a tenant and make the new user its owner.
    if body.tenant_name:
        slug = body.tenant_name.lower().replace(" ", "-")[:64]
        tenant = await tenant_service.create_tenant_with_roles(db, slug, body.tenant_name)
        await tenant_service.make_owner(db, user.id, tenant.id)
    return user


@router.post("/login", response_model=TokenPair | LoginChallenge)
async def login(body: LoginRequest, db: Db):
    try:
        user = await auth_service.verify_credentials(db, body.email, body.password)
    except AuthError as e:
        _raise(e)
    tenant_id = body.tenant_id or await _first_tenant(db, user.id)
    if tenant_id is None:
        raise HTTPException(400, "User has no tenant; register with a tenant_name first")
    # If MFA is enabled, don't hand out tokens yet — issue a challenge instead.
    if user.mfa_enabled:
        return LoginChallenge(mfa_token=auth_service.create_mfa_challenge(user, tenant_id))
    return await auth_service.issue_token_pair(user, tenant_id)


@router.post("/mfa/verify", response_model=TokenPair)
async def mfa_verify(body: MfaVerifyRequest, db: Db):
    from app.core.security import decode_jwt
    from app.db.models.user import User
    from app.services import mfa_service

    try:
        claims = decode_jwt(body.mfa_token, expected_type="mfa")
    except ValueError:
        raise HTTPException(401, "Invalid or expired MFA challenge")
    user = await db.get(User, int(claims["sub"]))
    if user is None or not user.is_active:
        raise HTTPException(401, "Invalid MFA challenge")

    # Accept either a TOTP code or a one-time recovery code.
    ok = bool(user.totp_secret and mfa_service.verify_totp(user.totp_secret, body.code))
    if not ok:
        ok = await mfa_service.consume_recovery_code(db, user, body.code)
    if not ok:
        raise HTTPException(401, "Invalid MFA code")
    return await auth_service.issue_token_pair(user, int(claims["tid"]), mfa_satisfied=True)


@router.post("/step-up", response_model=MessageResponse)
async def step_up(
    principal: CurrentPrincipal,
    db: Db,
    password: str | None = None,
    totp_code: str | None = None,
):
    """
    Re-verify identity for sensitive actions. Marks a short-lived step-up in Redis
    that require_step_up() checks. Accepts the account password or a TOTP code.
    """
    from app.core.config import get_settings
    from app.core.redis_client import get_redis
    from app.core.security import verify_password
    from app.db.models.user import User
    from app.services import mfa_service

    if principal.user_id is None:
        raise HTTPException(400, "Step-up applies to user accounts only")
    user = await db.get(User, principal.user_id)
    ok = False
    if password and user.hashed_password:
        ok = verify_password(password, user.hashed_password)
    if not ok and totp_code and user.totp_secret:
        ok = mfa_service.verify_totp(user.totp_secret, totp_code)
    if not ok:
        raise HTTPException(401, "Step-up verification failed")
    settings = get_settings()
    await get_redis().set(f"stepup:{user.id}", "1", ex=settings.step_up_ttl_seconds)
    return MessageResponse(message="Step-up verified")


@router.post("/refresh", response_model=TokenPair)
async def refresh(body: RefreshRequest, db: Db):
    try:
        return await auth_service.refresh_tokens(db, body.refresh_token)
    except AuthError as e:
        _raise(e)


@router.post("/logout", response_model=MessageResponse)
async def logout(
    body: LogoutRequest,
    claims: Annotated[dict | None, Depends(get_access_token_claims_optional)],
):
    jti = claims.get("jti") if claims else None
    exp = claims.get("exp") if claims else None
    await auth_service.logout_jwt(body.refresh_token, jti, exp)
    return MessageResponse(message="Logged out")


# ── Server-side session login (cookie-based) ─────────────────────────────────

@router.post("/session/login", response_model=MessageResponse)
async def session_login(body: LoginRequest, response: Response, db: Db):
    try:
        user = await auth_service.verify_credentials(db, body.email, body.password)
    except AuthError as e:
        _raise(e)
    tenant_id = body.tenant_id or await _first_tenant(db, user.id)
    if tenant_id is None:
        raise HTTPException(400, "User has no tenant")
    sid = await auth_service.create_session(user, tenant_id)
    settings = get_settings()
    response.set_cookie(
        settings.session_cookie_name, sid, httponly=True, samesite="lax",
        max_age=settings.session_ttl_seconds,
    )
    return MessageResponse(message="Session established")


@router.post("/session/logout", response_model=MessageResponse)
async def session_logout(request: Request, response: Response):
    settings = get_settings()
    sid = request.cookies.get(settings.session_cookie_name)
    if sid:
        await auth_service.destroy_session(sid)
        response.delete_cookie(settings.session_cookie_name)
    return MessageResponse(message="Session ended")
