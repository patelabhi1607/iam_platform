"""
Social login — this platform acting as an OAuth2/OIDC *client* of Google/GitHub.

Mock mode (default): the "provider" is simulated locally so the whole flow runs
with no external accounts. Real mode uses the configured client_id/secret and hits
the real provider endpoints (kept behind the same interface).
"""
import json

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.redis_client import get_redis
from app.core.security import new_opaque_token
from app.db.models.oauth import SocialIdentity
from app.db.models.user import User

SUPPORTED = {"google", "github"}

_REAL_ENDPOINTS = {
    "google": {
        "authorize": "https://accounts.google.com/o/oauth2/v2/auth",
        "token": "https://oauth2.googleapis.com/token",
        "userinfo": "https://openidconnect.googleapis.com/v1/userinfo",
        "scope": "openid email profile",
    },
    "github": {
        "authorize": "https://github.com/login/oauth/authorize",
        "token": "https://github.com/login/oauth/access_token",
        "userinfo": "https://api.github.com/user",
        "scope": "read:user user:email",
    },
}


def _is_mock(provider: str) -> bool:
    s = get_settings()
    if s.provider_mode != "real":
        return True
    creds = {
        "google": (s.google_client_id, s.google_client_secret),
        "github": (s.github_client_id, s.github_client_secret),
    }[provider]
    return not all(creds)


async def start_login(provider: str) -> str:
    if provider not in SUPPORTED:
        raise ValueError("Unsupported provider")
    s = get_settings()
    state = new_opaque_token(16)
    await get_redis().set(f"soc_state:{state}", provider, ex=600)

    if _is_mock(provider):
        # Point the browser at our own mock consent screen.
        return f"{s.webauthn_origin.replace('8080', '8000')}/auth/oauth/{provider}/mock-authorize?state={state}"

    ep = _REAL_ENDPOINTS[provider]
    cid = s.google_client_id if provider == "google" else s.github_client_id
    redirect = f"{s.webauthn_origin.replace('8080', '8000')}/auth/oauth/{provider}/callback"
    return (
        f"{ep['authorize']}?response_type=code&client_id={cid}"
        f"&redirect_uri={redirect}&scope={ep['scope'].replace(' ', '%20')}&state={state}"
    )


async def mock_authorize(provider: str, state: str) -> str:
    """Simulate the external IdP granting consent; returns a code bound to a profile."""
    code = new_opaque_token(16)
    profile = {
        "subject": f"{provider}-sub-001",
        "email": f"{provider}.user@example.com",
        "name": f"{provider.title()} Demo User",
    }
    await get_redis().set(
        f"soc_code:{code}", json.dumps({"provider": provider, "profile": profile}), ex=120
    )
    return code


async def _exchange_real(provider: str, code: str) -> dict:
    s = get_settings()
    ep = _REAL_ENDPOINTS[provider]
    cid = s.google_client_id if provider == "google" else s.github_client_id
    secret = s.google_client_secret if provider == "google" else s.github_client_secret
    redirect = f"{s.webauthn_origin.replace('8080', '8000')}/auth/oauth/{provider}/callback"
    async with httpx.AsyncClient() as client:
        tok = await client.post(
            ep["token"],
            data={
                "grant_type": "authorization_code", "code": code, "client_id": cid,
                "client_secret": secret, "redirect_uri": redirect,
            },
            headers={"Accept": "application/json"},
        )
        access = tok.json()["access_token"]
        info = await client.get(ep["userinfo"], headers={"Authorization": f"Bearer {access}"})
        data = info.json()
    return {
        "subject": str(data.get("sub") or data.get("id")),
        "email": data.get("email"),
        "name": data.get("name") or data.get("login"),
    }


async def complete_login(db: AsyncSession, provider: str, code: str, state: str) -> User:
    redis = get_redis()
    if await redis.get(f"soc_state:{state}") != provider:
        raise ValueError("Invalid or expired state")  # CSRF protection
    await redis.delete(f"soc_state:{state}")

    if _is_mock(provider):
        raw = await redis.get(f"soc_code:{code}")
        if raw is None:
            raise ValueError("Invalid code")
        profile = json.loads(raw)["profile"]
        await redis.delete(f"soc_code:{code}")
    else:
        profile = await _exchange_real(provider, code)

    return await _upsert_user(db, provider, profile)


async def _upsert_user(db: AsyncSession, provider: str, profile: dict) -> User:
    identity = (
        await db.execute(
            select(SocialIdentity).where(
                SocialIdentity.provider == provider, SocialIdentity.subject == profile["subject"]
            )
        )
    ).scalar_one_or_none()
    if identity:
        return await db.get(User, identity.user_id)

    # Link to an existing local account by email, or create a new one.
    user = None
    if profile.get("email"):
        user = (
            await db.execute(select(User).where(User.email == profile["email"]))
        ).scalar_one_or_none()
    if user is None:
        user = User(
            email=profile.get("email") or f"{profile['subject']}@{provider}.local",
            hashed_password=None, full_name=profile.get("name"), is_verified=True,
        )
        db.add(user)
        await db.flush()
    db.add(SocialIdentity(
        user_id=user.id, provider=provider, subject=profile["subject"], email=profile.get("email")
    ))
    await db.flush()
    return user
