"""API key and Personal Access Token issuance/verification."""
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_secret, new_opaque_token
from app.db.models.credential import ApiKey, PersonalAccessToken

API_KEY_PREFIX = "iamk_"
PAT_PREFIX = "iamp_"


def _split(raw: str) -> str:
    return raw[:12]


async def create_api_key(
    db: AsyncSession, tenant_id: int, name: str, scopes: str, expires_at: datetime | None = None
) -> tuple[ApiKey, str]:
    raw = API_KEY_PREFIX + new_opaque_token(24)
    key = ApiKey(
        tenant_id=tenant_id,
        name=name,
        prefix=_split(raw),
        hashed_key=hash_secret(raw),
        scopes=scopes,
        expires_at=expires_at,
    )
    db.add(key)
    await db.flush()
    await db.refresh(key)
    return key, raw  # raw shown once, never stored


async def verify_api_key(db: AsyncSession, raw: str) -> ApiKey | None:
    key = (
        await db.execute(select(ApiKey).where(ApiKey.hashed_key == hash_secret(raw)))
    ).scalar_one_or_none()
    if key is None or not key.is_active:
        return None
    if key.expires_at and key.expires_at < datetime.now(timezone.utc):
        return None
    key.last_used_at = datetime.now(timezone.utc)
    return key


async def create_pat(
    db: AsyncSession, user_id: int, name: str, scopes: str, expires_at: datetime | None = None
) -> tuple[PersonalAccessToken, str]:
    raw = PAT_PREFIX + new_opaque_token(24)
    pat = PersonalAccessToken(
        user_id=user_id,
        name=name,
        prefix=_split(raw),
        hashed_token=hash_secret(raw),
        scopes=scopes,
        expires_at=expires_at,
    )
    db.add(pat)
    await db.flush()
    await db.refresh(pat)
    return pat, raw


async def verify_pat(db: AsyncSession, raw: str) -> PersonalAccessToken | None:
    pat = (
        await db.execute(
            select(PersonalAccessToken).where(PersonalAccessToken.hashed_token == hash_secret(raw))
        )
    ).scalar_one_or_none()
    if pat is None or not pat.is_active:
        return None
    if pat.expires_at and pat.expires_at < datetime.now(timezone.utc):
        return None
    pat.last_used_at = datetime.now(timezone.utc)
    return pat
