"""
SAML 2.0 SP-initiated SSO (simplified).

Mock mode ships a built-in IdP that issues a signed-shaped assertion so the whole
SP flow runs with no external IdP. Real mode would verify the IdP's XML signature
(e.g. via python3-saml) — the parse/attribute-extraction here is the same shape.
"""
import base64
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.redis_client import get_redis
from app.core.security import new_opaque_token
from app.db.models.oauth import SocialIdentity
from app.db.models.user import User

_NS = {"saml": "urn:oasis:names:tc:SAML:2.0:assertion"}


async def start_login() -> tuple[str, str]:
    """Return (idp_url, relay_state). SP-initiated: browser goes to the IdP."""
    relay = new_opaque_token(16)
    await get_redis().set(f"saml_relay:{relay}", "1", ex=600)
    origin = get_settings().webauthn_origin.replace("8080", "8000")
    return f"{origin}/auth/saml/mock-idp?RelayState={relay}", relay


def build_mock_assertion(email: str, name: str = "SAML User") -> str:
    """A minimal SAML assertion (base64). Real IdPs additionally sign this XML."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    xml = f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" IssueInstant="{now}">
  <saml:Issuer>urn:iam-platform:mock-idp</saml:Issuer>
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{email}</saml:NameID>
    </saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="email"><saml:AttributeValue>{email}</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="displayName"><saml:AttributeValue>{name}</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"""
    return base64.b64encode(xml.encode()).decode()


def parse_assertion(saml_response_b64: str) -> dict:
    xml = base64.b64decode(saml_response_b64).decode()
    root = ET.fromstring(xml)
    name_id = root.find(".//saml:Subject/saml:NameID", _NS)
    if name_id is None or not name_id.text:
        raise ValueError("SAML assertion missing NameID")
    email = name_id.text.strip()
    display = email
    for attr in root.findall(".//saml:Attribute", _NS):
        if attr.get("Name") == "displayName":
            val = attr.find("saml:AttributeValue", _NS)
            if val is not None and val.text:
                display = val.text.strip()
    return {"subject": email, "email": email, "name": display}


async def complete_login(db: AsyncSession, saml_response_b64: str, relay_state: str) -> User:
    if await get_redis().get(f"saml_relay:{relay_state}") is None:
        raise ValueError("Invalid or expired RelayState")
    await get_redis().delete(f"saml_relay:{relay_state}")
    profile = parse_assertion(saml_response_b64)

    identity = (
        await db.execute(
            select(SocialIdentity).where(
                SocialIdentity.provider == "saml", SocialIdentity.subject == profile["subject"]
            )
        )
    ).scalar_one_or_none()
    if identity:
        return await db.get(User, identity.user_id)

    user = (
        await db.execute(select(User).where(User.email == profile["email"]))
    ).scalar_one_or_none()
    if user is None:
        user = User(email=profile["email"], hashed_password=None,
                    full_name=profile["name"], is_verified=True)
        db.add(user)
        await db.flush()
    db.add(SocialIdentity(user_id=user.id, provider="saml",
                          subject=profile["subject"], email=profile["email"]))
    await db.flush()
    return user
