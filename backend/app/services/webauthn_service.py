"""
WebAuthn / passkeys (FIDO2) using py_webauthn.

Registration and authentication each are two-step: the server issues a random
challenge, the browser's authenticator signs it, and the server verifies the
signature. Challenges are single-use and stored in Redis.
"""
import json

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from app.core.config import get_settings
from app.core.redis_client import get_redis
from app.db.models.mfa import WebAuthnCredential
from app.db.models.user import User


def _rp():
    s = get_settings()
    return s.webauthn_rp_id, s.webauthn_rp_name, s.webauthn_origin


async def registration_options(user: User) -> dict:
    rp_id, rp_name, _ = _rp()
    opts = generate_registration_options(
        rp_id=rp_id,
        rp_name=rp_name,
        user_id=str(user.id).encode(),
        user_name=user.email,
        user_display_name=user.full_name or user.email,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    await get_redis().set(
        f"wa:reg:{user.id}", bytes_to_base64url(opts.challenge), ex=300
    )
    return json.loads(options_to_json(opts))


async def verify_registration(db: AsyncSession, user: User, credential: dict) -> WebAuthnCredential:
    rp_id, _, origin = _rp()
    stored = await get_redis().get(f"wa:reg:{user.id}")
    if stored is None:
        raise ValueError("No pending registration challenge")
    verification = verify_registration_response(
        credential=json.dumps(credential),
        expected_challenge=base64url_to_bytes(stored),
        expected_rp_id=rp_id,
        expected_origin=origin,
    )
    await get_redis().delete(f"wa:reg:{user.id}")
    cred = WebAuthnCredential(
        user_id=user.id,
        credential_id=bytes_to_base64url(verification.credential_id),
        public_key=verification.credential_public_key,
        sign_count=verification.sign_count,
    )
    db.add(cred)
    await db.flush()
    return cred


async def authentication_options(db: AsyncSession, email: str) -> dict:
    rp_id, _, _ = _rp()
    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    allow = []
    if user:
        creds = (
            await db.execute(select(WebAuthnCredential).where(WebAuthnCredential.user_id == user.id))
        ).scalars().all()
        allow = [
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(c.credential_id)) for c in creds
        ]
    opts = generate_authentication_options(
        rp_id=rp_id, allow_credentials=allow,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    # Key the challenge by email (user may not be resolved until completion).
    await get_redis().set(f"wa:auth:{email}", bytes_to_base64url(opts.challenge), ex=300)
    return json.loads(options_to_json(opts))


async def verify_authentication(db: AsyncSession, email: str, credential: dict) -> User:
    rp_id, _, origin = _rp()
    stored = await get_redis().get(f"wa:auth:{email}")
    if stored is None:
        raise ValueError("No pending authentication challenge")

    cred_id = credential.get("id") or credential.get("rawId")
    row = (
        await db.execute(
            select(WebAuthnCredential).where(WebAuthnCredential.credential_id == cred_id)
        )
    ).scalar_one_or_none()
    if row is None:
        raise ValueError("Unknown passkey")

    verification = verify_authentication_response(
        credential=json.dumps(credential),
        expected_challenge=base64url_to_bytes(stored),
        expected_rp_id=rp_id,
        expected_origin=origin,
        credential_public_key=row.public_key,
        credential_current_sign_count=row.sign_count,
    )
    row.sign_count = verification.new_sign_count  # replay protection
    await get_redis().delete(f"wa:auth:{email}")
    user = await db.get(User, row.user_id)
    if user is None or not user.is_active:
        raise ValueError("Account unavailable")
    await db.flush()
    return user
