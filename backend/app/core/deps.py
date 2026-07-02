"""
Authentication resolution + authorization guards.

resolve_principal() inspects the request and tries, in order:
  1. Authorization: Bearer <jwt access token>
  2. Authorization: Bearer <PAT>          (prefix iamp_)
  3. X-API-Key: <api key>                 (prefix iamk_)
  4. Authorization: Basic <base64>        (email:password)
  5. Session cookie
Whichever succeeds yields a Principal with resolved RBAC permissions.
"""
import base64
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.authz.rbac import resolve_permissions
from app.core.config import get_settings
from app.core.principal import Principal
from app.core.redis_client import get_redis
from app.core.security import decode_jwt
from app.db.models.user import User
from app.db.session import get_db
from app.services import auth_service, credential_service

_UNAUTH = HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")


async def _principal_for_user(
    db: AsyncSession, user: User, tenant_id: int, method: str, mfa_satisfied: bool = True,
    scopes: set[str] | None = None,
) -> Principal:
    perms = await resolve_permissions(db, user.id, tenant_id)
    return Principal(
        kind="user",
        auth_method=method,
        user_id=user.id,
        tenant_id=tenant_id,
        is_superuser=user.is_superuser,
        permissions=perms,
        scopes=scopes or set(),
        mfa_satisfied=mfa_satisfied,
    )


async def resolve_principal(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Principal:
    auth = request.headers.get("Authorization", "")
    api_key = request.headers.get("X-API-Key")

    # 3. API key (machine) — tenant-scoped, carries scopes as permissions.
    if api_key:
        key = await credential_service.verify_api_key(db, api_key)
        if key is None:
            raise _UNAUTH
        scopes = set(key.scopes.split()) if key.scopes else set()
        return Principal(
            kind="api_key", auth_method="api_key", tenant_id=key.tenant_id,
            permissions=scopes, scopes=scopes,
        )

    if auth.startswith("Bearer "):
        token = auth[7:]
        # 2. PAT
        if token.startswith(credential_service.PAT_PREFIX):
            pat = await credential_service.verify_pat(db, token)
            if pat is None:
                raise _UNAUTH
            user = await db.get(User, pat.user_id)
            if user is None or not user.is_active:
                raise _UNAUTH
            # PAT acts for the user; its scopes narrow the user's permissions.
            # (tenant chosen via X-Tenant-Id header, else the user's first membership)
            tid = await _tenant_from_request(request, db, user.id)
            scopes = set(pat.scopes.split()) if pat.scopes else set()
            return await _principal_for_user(db, user, tid, "pat", scopes=scopes)
        # 1. JWT access token
        try:
            payload = decode_jwt(token, expected_type="access")
        except ValueError:
            raise _UNAUTH
        if payload.get("jti") and await get_redis().exists(f"bl:{payload['jti']}"):
            raise _UNAUTH
        user = await db.get(User, int(payload["sub"]))
        if user is None or not user.is_active or payload.get("tv") != user.token_version:
            raise _UNAUTH
        return await _principal_for_user(
            db, user, int(payload["tid"]), "jwt", mfa_satisfied=payload.get("mfa", True)
        )

    # 4. HTTP Basic
    if auth.startswith("Basic "):
        try:
            decoded = base64.b64decode(auth[6:]).decode()
            email, _, password = decoded.partition(":")
        except Exception:
            raise _UNAUTH
        try:
            user = await auth_service.verify_credentials(db, email, password)
        except auth_service.AuthError:
            raise _UNAUTH
        tid = await _tenant_from_request(request, db, user.id)
        return await _principal_for_user(db, user, tid, "basic")

    # 5. Session cookie
    sid = request.cookies.get(get_settings().session_cookie_name)
    if sid:
        sess = await auth_service.read_session(sid)
        if sess:
            user = await db.get(User, int(sess["uid"]))
            if user and user.is_active and sess.get("tv") == user.token_version:
                return await _principal_for_user(db, user, int(sess["tid"]), "session")

    raise _UNAUTH


async def _tenant_from_request(request: Request, db: AsyncSession, user_id: int) -> int:
    from app.authz.rbac import get_membership
    from app.db.models.rbac import Membership

    header = request.headers.get("X-Tenant-Id")
    if header and header.isdigit():
        if await get_membership(db, user_id, int(header)):
            return int(header)
        raise HTTPException(403, "Not a member of the requested tenant")
    m = (
        await db.execute(select(Membership).where(Membership.user_id == user_id).limit(1))
    ).scalar_one_or_none()
    if m is None:
        raise HTTPException(403, "User has no tenant membership")
    return m.tenant_id


CurrentPrincipal = Annotated[Principal, Depends(resolve_principal)]


def require_permission(permission: str):
    """Guard: the principal must hold `permission` in the active tenant."""

    async def guard(principal: CurrentPrincipal) -> Principal:
        if not principal.has_permission(permission):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail=f"Missing required permission: {permission}",
            )
        return principal

    return guard


def require_mfa():
    async def guard(principal: CurrentPrincipal) -> Principal:
        if not principal.mfa_satisfied:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail="MFA required")
        return principal

    return guard


async def get_access_token_claims_optional(request: Request) -> dict | None:
    """Best-effort decode of the access token (used by logout to blocklist it)."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    try:
        return decode_jwt(auth[7:], expected_type="access")
    except ValueError:
        return None
