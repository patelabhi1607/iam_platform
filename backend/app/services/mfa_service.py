"""TOTP-based 2FA enrollment/verification and one-time recovery codes."""
import pyotp
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import hash_secret, new_opaque_token
from app.db.models.mfa import RecoveryCode
from app.db.models.user import User


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, email: str) -> str:
    """otpauth:// URI — encode into a QR for Google Authenticator / Authy / 1Password."""
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=get_settings().totp_issuer)


def verify_totp(secret: str, code: str) -> bool:
    # valid_window=1 tolerates ~30s of clock drift between server and phone.
    return pyotp.TOTP(secret).verify(code, valid_window=1)


async def begin_enrollment(db: AsyncSession, user: User) -> tuple[str, str]:
    """Generate (but don't yet enable) a TOTP secret. Returns (secret, otpauth_uri)."""
    secret = generate_totp_secret()
    user.totp_secret = secret  # stored; mfa_enabled stays False until confirmed
    await db.flush()
    return secret, provisioning_uri(secret, user.email)


async def confirm_enrollment(db: AsyncSession, user: User, code: str) -> list[str]:
    """Verify the first code, enable MFA, and return fresh recovery codes."""
    if not user.totp_secret or not verify_totp(user.totp_secret, code):
        raise ValueError("Invalid TOTP code")
    user.mfa_enabled = True
    await db.flush()
    return await regenerate_recovery_codes(db, user)


async def disable_mfa(db: AsyncSession, user: User) -> None:
    user.mfa_enabled = False
    user.totp_secret = None
    await db.flush()
    for rc in (
        await db.execute(select(RecoveryCode).where(RecoveryCode.user_id == user.id))
    ).scalars().all():
        await db.delete(rc)


async def regenerate_recovery_codes(db: AsyncSession, user: User, count: int = 10) -> list[str]:
    # Wipe old codes, mint new ones. Plaintext returned once; only hashes stored.
    for rc in (
        await db.execute(select(RecoveryCode).where(RecoveryCode.user_id == user.id))
    ).scalars().all():
        await db.delete(rc)
    codes: list[str] = []
    for _ in range(count):
        code = new_opaque_token(6)[:10]
        codes.append(code)
        db.add(RecoveryCode(user_id=user.id, code_hash=hash_secret(code)))
    await db.flush()
    return codes


async def consume_recovery_code(db: AsyncSession, user: User, code: str) -> bool:
    rc = (
        await db.execute(
            select(RecoveryCode).where(
                RecoveryCode.user_id == user.id,
                RecoveryCode.code_hash == hash_secret(code),
                RecoveryCode.used_at.is_(None),
            )
        )
    ).scalar_one_or_none()
    if rc is None:
        return False
    from datetime import datetime, timezone
    rc.used_at = datetime.now(timezone.utc)
    await db.flush()
    return True
