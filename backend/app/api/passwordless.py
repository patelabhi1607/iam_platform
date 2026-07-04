"""Passwordless login: email/SMS OTP and magic links."""
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.providers import messaging
from app.schemas.core import (
    MagicConsumeRequest,
    MagicRequest,
    MessageResponse,
    OtpRequest,
    OtpVerifyRequest,
    TokenPair,
)
from app.services import auth_service, passwordless_service

router = APIRouter(prefix="/auth", tags=["passwordless"])
Db = Annotated[AsyncSession, Depends(get_db)]


@router.post("/otp/request", response_model=MessageResponse)
async def otp_request(body: OtpRequest, db: Db):
    await passwordless_service.request_otp(db, body.email, body.channel)
    # Generic response — never reveal whether the address exists.
    return MessageResponse(message=f"If the account exists, a code was sent via {body.channel}.")


@router.post("/otp/verify", response_model=TokenPair)
async def otp_verify(body: OtpVerifyRequest, db: Db):
    try:
        user = await passwordless_service.verify_otp(db, body.email, body.code)
    except ValueError as e:
        raise HTTPException(401, str(e))
    tenant_id = await auth_service.resolve_or_create_tenant(db, user)
    return await auth_service.issue_token_pair(user, tenant_id)


@router.post("/magic/request", response_model=MessageResponse)
async def magic_request(body: MagicRequest, db: Db):
    await passwordless_service.request_magic_link(db, body.email)
    return MessageResponse(message="If the account exists, a sign-in link was emailed.")


@router.post("/magic/consume", response_model=TokenPair)
async def magic_consume(body: MagicConsumeRequest, db: Db):
    try:
        user = await passwordless_service.consume_magic_link(db, body.token)
    except ValueError as e:
        raise HTTPException(401, str(e))
    tenant_id = await auth_service.resolve_or_create_tenant(db, user)
    return await auth_service.issue_token_pair(user, tenant_id)


# ── Dev helper: read the mock outbox so the demo UI can show OTP/magic messages ─

@router.get("/dev/outbox")
async def dev_outbox(email: str, channel: str = "email"):
    body = await messaging.peek_outbox(channel, email)
    return {"channel": channel, "to": email, "message": body}
