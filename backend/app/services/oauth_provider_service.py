"""
This platform acting as an OAuth2 Authorization Server (IdP).

Grants: authorization_code (+ PKCE), client_credentials, device_code.
Codes and device sessions live in Redis (short-lived, single-use). Issued access
tokens are JWTs that our own resolve_principal() can consume — full circle.
"""
import base64
import hashlib
import json

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.redis_client import get_redis
from app.core.security import create_jwt, hash_secret, new_numeric_otp, new_opaque_token
from app.db.models.oauth import OAuthClient
from app.db.models.user import User


class OAuthError(Exception):
    def __init__(self, error: str, description: str = "") -> None:
        self.error = error
        self.description = description
        super().__init__(description or error)


async def register_client(
    db: AsyncSession, name: str, redirect_uris: list[str], scopes: list[str],
    grant_types: list[str], confidential: bool = True,
) -> tuple[OAuthClient, str | None]:
    client_id = "cid_" + new_opaque_token(12)
    secret = None
    secret_hash = None
    if confidential:
        secret = "csec_" + new_opaque_token(24)
        secret_hash = hash_secret(secret)
    client = OAuthClient(
        client_id=client_id, client_secret_hash=secret_hash, name=name,
        redirect_uris=" ".join(redirect_uris), allowed_scopes=" ".join(scopes),
        grant_types=" ".join(grant_types), is_confidential=confidential,
    )
    db.add(client)
    await db.flush()
    return client, secret


async def _client(db: AsyncSession, client_id: str) -> OAuthClient:
    c = (
        await db.execute(select(OAuthClient).where(OAuthClient.client_id == client_id))
    ).scalar_one_or_none()
    if c is None:
        raise OAuthError("invalid_client", "Unknown client")
    return c


def _verify_pkce(verifier: str, challenge: str, method: str) -> bool:
    if method == "S256":
        digest = hashlib.sha256(verifier.encode()).digest()
        computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        return computed == challenge
    return verifier == challenge  # "plain"


# ── Authorization code (+ PKCE) ───────────────────────────────────────────────

async def issue_auth_code(
    db: AsyncSession, client_id: str, user: User, tenant_id: int, scope: str,
    redirect_uri: str, code_challenge: str | None, code_challenge_method: str,
) -> str:
    client = await _client(db, client_id)
    if redirect_uri not in client.redirect_uris.split():
        raise OAuthError("invalid_request", "redirect_uri not registered")
    code = new_opaque_token(24)
    await get_redis().set(
        f"oauth_code:{code}",
        json.dumps({
            "client_id": client_id, "user_id": user.id, "tenant_id": tenant_id,
            "scope": scope, "redirect_uri": redirect_uri,
            "code_challenge": code_challenge, "code_challenge_method": code_challenge_method,
            "tv": user.token_version,
        }),
        ex=get_settings().oauth_code_ttl_seconds,
    )
    return code


async def exchange_code(
    db: AsyncSession, client_id: str, client_secret: str | None, code: str,
    redirect_uri: str, code_verifier: str | None,
) -> dict:
    client = await _client(db, client_id)
    redis = get_redis()
    raw = await redis.get(f"oauth_code:{code}")
    if raw is None:
        raise OAuthError("invalid_grant", "Invalid or expired code")
    await redis.delete(f"oauth_code:{code}")  # single-use
    data = json.loads(raw)

    if data["client_id"] != client_id or data["redirect_uri"] != redirect_uri:
        raise OAuthError("invalid_grant", "Code/client/redirect mismatch")
    # Confidential clients authenticate with a secret; public clients must use PKCE.
    if client.is_confidential:
        if not client_secret or hash_secret(client_secret) != client.client_secret_hash:
            raise OAuthError("invalid_client", "Bad client secret")
    if data["code_challenge"]:
        if not code_verifier or not _verify_pkce(
            code_verifier, data["code_challenge"], data["code_challenge_method"]
        ):
            raise OAuthError("invalid_grant", "PKCE verification failed")

    return _issue_access(str(data["user_id"]), data["tenant_id"], data["scope"], data["tv"])


# ── Client credentials (machine-to-machine) ──────────────────────────────────

async def client_credentials(db: AsyncSession, client_id: str, client_secret: str, scope: str) -> dict:
    client = await _client(db, client_id)
    if "client_credentials" not in client.grant_types.split():
        raise OAuthError("unauthorized_client", "Grant not allowed")
    if not client_secret or hash_secret(client_secret) != client.client_secret_hash:
        raise OAuthError("invalid_client", "Bad client secret")
    allowed = set(client.allowed_scopes.split())
    granted = " ".join(s for s in scope.split() if s in allowed) if scope else client.allowed_scopes
    token, _, exp = create_jwt(
        client_id, "access", get_settings().access_token_ttl_seconds,
        claims={"scope": granted, "client": client_id, "sub_type": "client"},
    )
    return {"access_token": token, "token_type": "bearer",
            "expires_in": get_settings().access_token_ttl_seconds, "scope": granted}


# ── Device authorization flow ─────────────────────────────────────────────────

async def device_code(db: AsyncSession, client_id: str, scope: str) -> dict:
    await _client(db, client_id)
    settings = get_settings()
    device = new_opaque_token(24)
    user_code = f"{new_numeric_otp(4)}-{new_numeric_otp(4)}"
    await get_redis().set(
        f"device:{device}",
        json.dumps({"client_id": client_id, "scope": scope, "status": "pending",
                    "user_code": user_code}),
        ex=settings.device_code_ttl_seconds,
    )
    await get_redis().set(f"ucode:{user_code}", device, ex=settings.device_code_ttl_seconds)
    verify_uri = f"{settings.webauthn_origin.replace('8080', '8000')}/oauth/device"
    return {
        "device_code": device, "user_code": user_code,
        "verification_uri": verify_uri, "interval": 2,
        "expires_in": settings.device_code_ttl_seconds,
    }


async def approve_device(user: User, tenant_id: int, user_code: str) -> None:
    redis = get_redis()
    device = await redis.get(f"ucode:{user_code}")
    if device is None:
        raise OAuthError("invalid_grant", "Unknown or expired user code")
    raw = await redis.get(f"device:{device}")
    data = json.loads(raw)
    data.update({"status": "approved", "user_id": user.id, "tenant_id": tenant_id,
                 "tv": user.token_version})
    await redis.set(f"device:{device}", json.dumps(data), ex=get_settings().device_code_ttl_seconds)


async def poll_device(device_code_val: str) -> dict:
    raw = await get_redis().get(f"device:{device_code_val}")
    if raw is None:
        raise OAuthError("expired_token", "Device code expired")
    data = json.loads(raw)
    if data["status"] != "approved":
        raise OAuthError("authorization_pending", "Not yet approved")
    await get_redis().delete(f"device:{device_code_val}")
    return _issue_access(str(data["user_id"]), data["tenant_id"], data["scope"], data["tv"])


# ── Introspection ─────────────────────────────────────────────────────────────

def introspect(token: str) -> dict:
    from app.core.security import decode_jwt
    try:
        claims = decode_jwt(token)
    except ValueError:
        return {"active": False}
    return {"active": True, "sub": claims.get("sub"), "scope": claims.get("scope"),
            "exp": claims.get("exp"), "client_id": claims.get("client"),
            "token_type": claims.get("type")}


def _issue_access(sub: str, tenant_id: int, scope: str, tv: int) -> dict:
    settings = get_settings()
    token, _, _ = create_jwt(
        sub, "access", settings.access_token_ttl_seconds,
        claims={"tid": tenant_id, "tv": tv, "scope": scope, "mfa": True},
    )
    refresh, jti, _ = create_jwt(
        sub, "refresh", settings.refresh_token_ttl_seconds, claims={"tid": tenant_id, "tv": tv},
    )
    return {"access_token": token, "refresh_token": refresh, "token_type": "bearer",
            "expires_in": settings.access_token_ttl_seconds, "scope": scope}
