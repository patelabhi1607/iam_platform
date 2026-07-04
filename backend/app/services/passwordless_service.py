"""Passwordless authentication: email/SMS OTP codes and magic links."""
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.redis_client import get_redis
from app.core.security import hash_secret, new_numeric_otp, new_opaque_token
from app.db.models.user import User
from app.providers import messaging


async def _get_or_create_user(db: AsyncSession, email: str) -> User:
    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if user is None:
        # Passwordless sign-up: create a password-less account.
        user = User(email=email, hashed_password=None, is_verified=False)
        db.add(user)
        await db.flush()
    return user


# ── One-time codes (email or SMS) ─────────────────────────────────────────────

async def request_otp(db: AsyncSession, email: str, channel: str = "email") -> None:
    settings = get_settings()
    await _get_or_create_user(db, email)
    code = new_numeric_otp(6)
    await get_redis().set(f"otp:{email}", hash_secret(code), ex=settings.otp_ttl_seconds)
    if channel == "sms":
        await messaging.send_sms(email, f"Your verification code is {code}")
    else:
        await messaging.send_email(email, "Your login code", f"Your verification code is {code}")


async def verify_otp(db: AsyncSession, email: str, code: str) -> User:
    redis = get_redis()
    stored = await redis.get(f"otp:{email}")
    if stored is None or stored != hash_secret(code):
        raise ValueError("Invalid or expired code")
    await redis.delete(f"otp:{email}")  # single use
    user = (await db.execute(select(User).where(User.email == email))).scalar_one()
    user.is_verified = True
    await db.flush()
    return user


# ── Magic links ───────────────────────────────────────────────────────────────

async def request_magic_link(db: AsyncSession, email: str) -> str:
    settings = get_settings()
    await _get_or_create_user(db, email)
    token = new_opaque_token(32)
    await get_redis().set(f"magic:{hash_secret(token)}", email, ex=settings.magic_link_ttl_seconds)
    link = f"{settings.webauthn_origin}/#magic={token}"
    await messaging.send_email(email, "Your magic sign-in link", f"Click to sign in: {link}")
    return token  # returned for dev; in prod only the email carries it


async def consume_magic_link(db: AsyncSession, token: str) -> User:
    redis = get_redis()
    key = f"magic:{hash_secret(token)}"
    email = await redis.get(key)
    if email is None:
        raise ValueError("Invalid or expired magic link")
    await redis.delete(key)  # single use
    user = (await db.execute(select(User).where(User.email == email))).scalar_one()
    user.is_verified = True
    await db.flush()
    return user
