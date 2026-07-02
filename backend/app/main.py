import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.core.redis_client import close_redis, init_redis
from app.db.seed import seed_demo
from app.db.session import close_db

logging.basicConfig(level=get_settings().log_level)
logger = logging.getLogger(__name__)


async def _create_tables() -> None:
    # This project evolves across phases; create tables from metadata at startup
    # rather than maintaining a migration per phase. (Alembic can be layered on later.)
    from app.db.models import Base  # noqa: F401 — ensures all models are registered
    from app.db.session import get_engine

    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_redis()
    await _create_tables()
    await seed_demo()
    logger.info("IAM Platform started")
    yield
    await close_redis()
    await close_db()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="IAM Platform",
        description="Comprehensive identity & access management — all authN methods, all authZ models",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.get_cors_origins(),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    from app.api.health import router as health
    from app.api.auth import router as auth
    from app.api.me import router as me
    from app.api.tenants import router as tenants
    from app.api.admin import router as admin
    from app.api.credentials import router as credentials
    from app.api.resources import router as resources

    for r in (health, auth, me, tenants, admin, credentials, resources):
        app.include_router(r)
    return app


app = create_app()
