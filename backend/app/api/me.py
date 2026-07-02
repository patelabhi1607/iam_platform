from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import CurrentPrincipal, resolve_principal
from app.core.principal import Principal
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.core import UserResponse, WhoAmI

router = APIRouter(tags=["me"])
Db = Annotated[AsyncSession, Depends(get_db)]


@router.get("/me", response_model=UserResponse)
async def me(principal: CurrentPrincipal, db: Db):
    if principal.user_id is None:
        # Machine principal (API key) — synthesize a minimal identity.
        return UserResponse(
            id=0, email="machine@apikey", full_name=None, is_active=True,
            is_verified=True, is_superuser=False, mfa_enabled=False,
        )
    return await db.get(User, principal.user_id)


@router.get("/whoami", response_model=WhoAmI)
async def whoami(principal: CurrentPrincipal):
    """Shows exactly how you authenticated and what you can do — great for demos."""
    return WhoAmI(
        kind=principal.kind,
        auth_method=principal.auth_method,
        user_id=principal.user_id,
        tenant_id=principal.tenant_id,
        is_superuser=principal.is_superuser,
        permissions=sorted(principal.permissions),
        scopes=sorted(principal.scopes),
        mfa_satisfied=principal.mfa_satisfied,
    )
