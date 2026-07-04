"""SAML 2.0 SP-initiated SSO (mockable IdP)."""
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.schemas.core import TokenPair
from app.services import auth_service, saml_service

router = APIRouter(prefix="/auth/saml", tags=["saml"])
Db = Annotated[AsyncSession, Depends(get_db)]


@router.get("/login")
async def login():
    """SP-initiated — returns the IdP URL to send the user to."""
    idp_url, relay = await saml_service.start_login()
    return {"idp_url": idp_url, "relay_state": relay}


@router.get("/mock-idp", response_class=HTMLResponse)
async def mock_idp(RelayState: str, email: str = "saml.user@example.com"):
    """Built-in mock IdP: renders a tiny form that POSTs a SAMLResponse to our ACS."""
    saml_response = saml_service.build_mock_assertion(email)
    return f"""
    <html><body style="font-family:sans-serif;background:#0d1117;color:#e6edf3;padding:40px">
      <h2>Mock SAML IdP</h2>
      <p>Signing in <b>{email}</b></p>
      <form method="POST" action="/auth/saml/acs">
        <input type="hidden" name="SAMLResponse" value="{saml_response}"/>
        <input type="hidden" name="RelayState" value="{RelayState}"/>
        <button type="submit" style="padding:10px 16px">Continue to Service Provider</button>
      </form>
    </body></html>
    """


@router.post("/acs")
async def assertion_consumer_service(
    db: Db,
    SAMLResponse: Annotated[str, Form()],
    RelayState: Annotated[str, Form()],
):
    """Assertion Consumer Service — verifies the assertion and logs the user in."""
    try:
        user = await saml_service.complete_login(db, SAMLResponse, RelayState)
    except ValueError as e:
        raise HTTPException(400, str(e))
    tenant_id = await auth_service.resolve_or_create_tenant(db, user)
    tokens = await auth_service.issue_token_pair(user, tenant_id, mfa_satisfied=True)
    return TokenPair(**tokens)
