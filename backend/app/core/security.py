"""Cryptographic primitives: password hashing, token signing, secure randomness."""
import hashlib
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import get_settings

# Argon2 is the modern default (memory-hard); bcrypt kept for verifying legacy hashes.
_pwd = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")


def hash_password(plain: str) -> str:
    return _pwd.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return _pwd.verify(plain, hashed)


def needs_rehash(hashed: str) -> bool:
    return _pwd.needs_update(hashed)


# ── Opaque secrets (API keys, PATs, session ids, OTP codes) ──────────────────

def new_opaque_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def hash_secret(secret: str) -> str:
    """SHA-256 for high-entropy secrets (API keys/PATs) — fast, one-way lookup."""
    return hashlib.sha256(secret.encode()).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return secrets.compare_digest(a, b)


def new_numeric_otp(digits: int = 6) -> str:
    return "".join(secrets.choice("0123456789") for _ in range(digits))


# ── JWT ──────────────────────────────────────────────────────────────────────

def _now() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def create_jwt(
    subject: str,
    token_type: str,
    ttl_seconds: int,
    claims: dict[str, Any] | None = None,
) -> tuple[str, str, int]:
    """Return (token, jti, exp)."""
    settings = get_settings()
    now = _now()
    exp = now + ttl_seconds
    jti = str(uuid.uuid4())
    payload: dict[str, Any] = {
        "sub": subject,
        "type": token_type,
        "jti": jti,
        "iat": now,
        "exp": exp,
    }
    if claims:
        payload.update(claims)
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return token, jti, exp


def decode_jwt(token: str, expected_type: str | None = None) -> dict[str, Any]:
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except JWTError as exc:
        raise ValueError(f"invalid token: {exc}") from exc
    if expected_type is not None and payload.get("type") != expected_type:
        raise ValueError(f"wrong token type: expected {expected_type}")
    return payload
