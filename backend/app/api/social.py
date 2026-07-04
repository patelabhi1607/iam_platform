"""Social login (OAuth2 client for Google/GitHub, mockable)."""
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.schemas.core import TokenPair
from app.services import auth_service, social_service

router = APIRouter(prefix="/auth/oauth", tags=["social-login"])
Db = Annotated[AsyncSession, Depends(get_db)]


@router.get("/{provider}/authorize")
async def authorize(provider: str):
    """Step 1 — get the URL to send the user to (real IdP, or our mock consent)."""
    try:
        url = await social_service.start_login(provider)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"authorization_url": url}


@router.get("/{provider}/mock-authorize")
async def mock_authorize(provider: str, state: str):
    """Mock IdP — simulates consent, then redirects back to our callback with a code."""
    code = await social_service.mock_authorize(provider, state)
    return RedirectResponse(url=f"/auth/oauth/{provider}/callback?code={code}&state={state}")


@router.get("/{provider}/callback", response_model=TokenPair)
async def callback(provider: str, code: str, state: str, db: Db):
    """Step 2 — exchange the code, upsert the user, and issue our own tokens."""
    try:
        user = await social_service.complete_login(db, provider, code, state)
    except ValueError as e:
        raise HTTPException(400, str(e))
    tenant_id = await auth_service.resolve_or_create_tenant(db, user)
    return await auth_service.issue_token_pair(user, tenant_id, mfa_satisfied=True)
