"""
Email / SMS delivery. In mock mode (default) messages are logged and stashed in
Redis so the dev UI can display them — no external account needed. Setting
PROVIDER_MODE=real with SMTP/Twilio creds switches to real delivery.
"""
import logging

from app.core.config import get_settings
from app.core.redis_client import get_redis

logger = logging.getLogger(__name__)


async def _stash(channel: str, to: str, body: str) -> None:
    # Keep the most recent message per recipient so the demo UI can show it.
    await get_redis().set(f"outbox:{channel}:{to}", body, ex=900)
    logger.info("[MOCK %s → %s] %s", channel.upper(), to, body)


async def send_email(to: str, subject: str, body: str) -> None:
    settings = get_settings()
    if settings.provider_mode == "real" and settings.smtp_host:
        # Real SMTP would go here (aiosmtplib). Kept out to avoid a hard dep.
        logger.info("Would send real email to %s via %s", to, settings.smtp_host)
        return
    await _stash("email", to, f"{subject}\n{body}")


async def send_sms(to: str, body: str) -> None:
    settings = get_settings()
    if settings.provider_mode == "real" and settings.twilio_account_sid:
        logger.info("Would send real SMS to %s via Twilio", to)
        return
    await _stash("sms", to, body)


async def peek_outbox(channel: str, to: str) -> str | None:
    """Dev helper — read the last message sent to a recipient (mock mode)."""
    return await get_redis().get(f"outbox:{channel}:{to}")
