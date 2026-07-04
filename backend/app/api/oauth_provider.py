"""OAuth2 Authorization Server endpoints (this platform as an IdP)."""
from typing import Annotated

from fastapi import APIRouter, Body, Depends, Form, HTTPException
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import CurrentPrincipal
from app.db.models.user import User
from app.db.session import get_db
from app.services import oauth_provider_service as oauth
from app.services.oauth_provider_service import OAuthError

router = APIRouter(prefix="/oauth", tags=["oauth-provider"])
Db = Annotated[AsyncSession, Depends(get_db)]


def _oauth_err(e: OAuthError, status: int = 400):
    return JSONResponse(status_code=status, content={"error": e.error, "error_description": e.description})


# ── Client registration ───────────────────────────────────────────────────────

@router.post("/clients", status_code=201)
async def register_client(
    principal: CurrentPrincipal,
    db: Db,
    name: Annotated[str, Body()],
    redirect_uris: Annotated[list[str], Body()] = ["http://localhost:8080/callback"],
    scopes: Annotated[list[str], Body()] = ["document:read"],
    grant_types: Annotated[list[str], Body()] = ["authorization_code", "refresh_token"],
    confidential: Annotated[bool, Body()] = True,
):
    client, secret = await oauth.register_client(db, name, redirect_uris, scopes, grant_types, confidential)
    return {"client_id": client.client_id, "client_secret": secret,
            "redirect_uris": redirect_uris, "grant_types": grant_types}


# ── Authorization endpoint (user consents; must be authenticated) ────────────

@router.get("/authorize")
async def authorize(
    principal: CurrentPrincipal,
    db: Db,
    client_id: str,
    redirect_uri: str,
    scope: str = "",
    state: str = "",
    response_type: str = "code",
    code_challenge: str | None = None,
    code_challenge_method: str = "S256",
):
    if response_type != "code":
        raise HTTPException(400, "Only response_type=code is supported")
    if principal.user_id is None:
        raise HTTPException(401, "Must be an authenticated user to authorize")
    user = await db.get(User, principal.user_id)
    try:
        code = await oauth.issue_auth_code(
            db, client_id, user, principal.tenant_id, scope, redirect_uri,
            code_challenge, code_challenge_method,
        )
    except OAuthError as e:
        return _oauth_err(e)
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(url=f"{redirect_uri}{sep}code={code}&state={state}")


# ── Token endpoint (form-encoded, per spec) ──────────────────────────────────

@router.post("/token")
async def token(
    db: Db,
    grant_type: Annotated[str, Form()],
    code: Annotated[str | None, Form()] = None,
    redirect_uri: Annotated[str | None, Form()] = None,
    client_id: Annotated[str | None, Form()] = None,
    client_secret: Annotated[str | None, Form()] = None,
    code_verifier: Annotated[str | None, Form()] = None,
    scope: Annotated[str, Form()] = "",
    device_code: Annotated[str | None, Form()] = None,
):
    try:
        if grant_type == "authorization_code":
            return await oauth.exchange_code(db, client_id, client_secret, code, redirect_uri, code_verifier)
        if grant_type == "client_credentials":
            return await oauth.client_credentials(db, client_id, client_secret, scope)
        if grant_type == "urn:ietf:params:oauth:grant-type:device_code":
            return await oauth.poll_device(device_code)
        raise HTTPException(400, "Unsupported grant_type")
    except OAuthError as e:
        return _oauth_err(e)


# ── Device authorization flow ─────────────────────────────────────────────────

@router.post("/device/code")
async def device_code(db: Db, client_id: Annotated[str, Form()], scope: Annotated[str, Form()] = ""):
    try:
        return await oauth.device_code(db, client_id, scope)
    except OAuthError as e:
        return _oauth_err(e)


@router.post("/device/approve")
async def device_approve(principal: CurrentPrincipal, db: Db, user_code: Annotated[str, Body(embed=True)]):
    if principal.user_id is None:
        raise HTTPException(401, "Must be an authenticated user")
    user = await db.get(User, principal.user_id)
    try:
        await oauth.approve_device(user, principal.tenant_id, user_code)
    except OAuthError as e:
        return _oauth_err(e)
    return {"message": "Device approved — it can now retrieve its token"}


# ── Token introspection ───────────────────────────────────────────────────────

@router.post("/introspect")
async def introspect(token: Annotated[str, Form()]):
    return oauth.introspect(token)
