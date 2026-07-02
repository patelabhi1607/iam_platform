from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.deps import get_access_token_claims_optional
from app.db.models.rbac import Membership
from app.db.session import get_db
from app.schemas.core import (
    LoginRequest,
    LogoutRequest,
    MessageResponse,
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


@router.post("/login", response_model=TokenPair)
async def login(body: LoginRequest, db: Db):
    try:
        user = await auth_service.verify_credentials(db, body.email, body.password)
    except AuthError as e:
        _raise(e)
    tenant_id = body.tenant_id or await _first_tenant(db, user.id)
    if tenant_id is None:
        raise HTTPException(400, "User has no tenant; register with a tenant_name first")
    return await auth_service.issue_token_pair(user, tenant_id)


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
