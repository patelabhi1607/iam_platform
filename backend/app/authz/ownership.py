"""Row-level ownership — the creator/owner of a resource may act on it."""
from app.db.models.authz import Doc


def is_owner(doc: Doc, user_id: int | None) -> bool:
    return user_id is not None and doc.owner_id == user_id
