"""
Seed a demo tenant with one user per role, so you can log in as owner/admin/
member/viewer and watch RBAC differ. Idempotent.
"""
import logging

from sqlalchemy import select

from app.core.security import hash_password
from app.db.models.tenant import Tenant
from app.db.models.user import User
from app.db.session import get_session_factory
from app.services import tenant_service

logger = logging.getLogger(__name__)

DEMO_USERS = [
    ("owner@example.com", "owner"),
    ("admin@example.com", "admin"),
    ("member@example.com", "member"),
    ("viewer@example.com", "viewer"),
]
PASSWORD = "password123"


async def seed_demo() -> None:
    try:
        async with get_session_factory()() as db:
            existing = (
                await db.execute(select(Tenant).where(Tenant.slug == "acme"))
            ).scalar_one_or_none()
            if existing:
                return

            tenant = await tenant_service.create_tenant_with_roles(db, "acme", "Acme Inc")
            for email, role_name in DEMO_USERS:
                user = (
                    await db.execute(select(User).where(User.email == email))
                ).scalar_one_or_none()
                if user is None:
                    user = User(
                        email=email, hashed_password=hash_password(PASSWORD),
                        is_verified=True, full_name=email.split("@")[0].title(),
                    )
                    db.add(user)
                    await db.flush()
                await tenant_service.add_member(db, user.id, tenant.id, role_name)
            await db.commit()
            logger.info("Seeded demo tenant 'acme' with owner/admin/member/viewer users")
    except Exception:
        logger.exception("Failed to seed demo data — continuing")
