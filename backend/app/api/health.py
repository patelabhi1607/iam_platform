from fastapi import APIRouter
from sqlalchemy import text

from app.core.redis_client import get_redis
from app.db.session import get_session_factory

router = APIRouter(tags=["health"])


@router.get("/health")
async def health():
    s = {"api": "ok", "redis": "unknown", "postgres": "unknown"}
    try:
        await get_redis().ping()
        s["redis"] = "ok"
    except Exception as e:
        s["redis"] = f"error: {e}"
    try:
        async with get_session_factory()() as sess:
            await sess.execute(text("SELECT 1"))
        s["postgres"] = "ok"
    except Exception as e:
        s["postgres"] = f"error: {e}"
    s["status"] = "ok" if all(v == "ok" for v in s.values()) else "degraded"
    return s
