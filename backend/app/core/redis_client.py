import redis.asyncio as aioredis
from redis.asyncio import ConnectionPool

from app.core.config import get_settings

_pool: ConnectionPool | None = None


async def init_redis() -> None:
    global _pool
    _pool = ConnectionPool.from_url(get_settings().redis_url, decode_responses=True)
    await aioredis.Redis(connection_pool=_pool).ping()


def get_redis() -> aioredis.Redis:
    if _pool is None:
        raise RuntimeError("Redis not initialized")
    return aioredis.Redis(connection_pool=_pool)


async def close_redis() -> None:
    global _pool
    if _pool:
        await _pool.disconnect()
        _pool = None
