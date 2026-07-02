"""Password authentication, JWT issuance with refresh rotation, and sessions."""
import json
import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.redis_client import get_redis
from app.core.security import (
    create_jwt,
    decode_jwt,
    hash_password,
    new_opaque_token,
    verify_password,
)
from app.db.models.user import User

logger = logging.getLogger(__name__)


class AuthError(Exception):
    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        self.message = message
        super().__init__(message)


# ── Registration ──────────────────────────────────────────────────────────────

async def register(db: AsyncSession, email: str, password: str, full_name: str | None = None) -> User:
    if (await db.execute(select(User).where(User.email == email))).scalar_one_or_none():
        raise AuthError(409, "An account with this email already exists")
    user = User(email=email, hashed_password=hash_password(password), full_name=full_name)
    db.add(user)
    await db.flush()
    await db.refresh(user)
    return user


async def verify_credentials(db: AsyncSession, email: str, password: str) -> User:
    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if user is None:
        verify_password(password, "$argon2id$v=19$m=65536,t=3,p=4$" + "a" * 22 + "$" + "b" * 43)
        raise AuthError(401, "Invalid email or password")
    if user.hashed_password is None or not verify_password(password, user.hashed_password):
        raise AuthError(401, "Invalid email or password")
    if not user.is_active:
        raise AuthError(403, "Account is disabled")
    return user


# ── JWT pair (access + refresh) with rotation + reuse detection ───────────────

async def issue_token_pair(user: User, tenant_id: int, mfa_satisfied: bool = True) -> dict:
    settings = get_settings()
    access, _, _ = create_jwt(
        str(user.id), "access", settings.access_token_ttl_seconds,
        claims={"tid": tenant_id, "tv": user.token_version, "mfa": mfa_satisfied},
    )
    refresh, jti, _ = create_jwt(
        str(user.id), "refresh", settings.refresh_token_ttl_seconds,
        claims={"tid": tenant_id, "tv": user.token_version},
    )
    await get_redis().set(f"rt:{user.id}:{jti}", "1", ex=settings.refresh_token_ttl_seconds)
    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "bearer",
        "expires_in": settings.access_token_ttl_seconds,
    }


async def refresh_tokens(db: AsyncSession, refresh_token: str) -> dict:
    try:
        payload = decode_jwt(refresh_token, expected_type="refresh")
    except ValueError as exc:
        raise AuthError(401, "Invalid refresh token") from exc

    uid, jti, tid, tv = payload["sub"], payload["jti"], payload["tid"], payload.get("tv", -1)
    redis = get_redis()
    user = (await db.execute(select(User).where(User.id == int(uid)))).scalar_one_or_none()
    if user is None or not user.is_active or tv != user.token_version:
        raise AuthError(401, "Refresh token has been revoked")

    key = f"rt:{uid}:{jti}"
    if not await redis.exists(key):
        # Reuse of a rotated token → revoke every session for this user.
        logger.warning("Refresh reuse detected for user %s", uid)
        user.token_version += 1
        await db.flush()
        cursor = 0
        while True:
            cursor, keys = await redis.scan(cursor, match=f"rt:{uid}:*", count=100)
            if keys:
                await redis.delete(*keys)
            if cursor == 0:
                break
        raise AuthError(401, "Refresh token reuse detected; all sessions revoked")

    await redis.delete(key)
    return await issue_token_pair(user, int(tid))


async def logout_jwt(refresh_token: str, access_jti: str | None, access_exp: int | None) -> None:
    redis = get_redis()
    try:
        p = decode_jwt(refresh_token, expected_type="refresh")
        await redis.delete(f"rt:{p['sub']}:{p['jti']}")
    except ValueError:
        pass
    if access_jti and access_exp:
        import time
        await redis.set(f"bl:{access_jti}", "1", ex=max(1, access_exp - int(time.time())))


# ── Server-side sessions (opaque id in a cookie, state in Redis) ──────────────

async def create_session(user: User, tenant_id: int) -> str:
    settings = get_settings()
    sid = new_opaque_token()
    data = json.dumps({"uid": user.id, "tid": tenant_id, "tv": user.token_version})
    await get_redis().set(f"sess:{sid}", data, ex=settings.session_ttl_seconds)
    return sid


async def read_session(sid: str) -> dict | None:
    raw = await get_redis().get(f"sess:{sid}")
    return json.loads(raw) if raw else None


async def destroy_session(sid: str) -> None:
    await get_redis().delete(f"sess:{sid}")
