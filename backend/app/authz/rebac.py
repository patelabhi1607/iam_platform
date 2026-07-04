"""
ReBAC — relationship-based access control, Google Zanzibar style.

Access is decided by whether a *path* of relationship tuples connects the subject
to the object with the required relation. Two Zanzibar features are implemented:

  1. Relation implication (userset rewrite): an `owner` is also an `editor` is also
     a `viewer`. So checking `viewer` succeeds if the user is owner/editor/viewer.
  2. Userset subjects (group nesting): a tuple's subject can be another
     object#relation, e.g. (doc:42, viewer, group:eng#member). We recurse into it.
"""
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.authz import RelationTuple

# A more-privileged relation implies the less-privileged ones.
RELATION_IMPLICATIONS: dict[str, list[str]] = {
    "viewer": ["viewer", "editor", "owner"],
    "editor": ["editor", "owner"],
    "owner": ["owner"],
    "member": ["member"],
}

# Map a coarse permission/action to the relation it requires.
PERMISSION_TO_RELATION = {
    "read": "viewer",
    "write": "editor",
    "share": "editor",
    "delete": "owner",
}


async def check(
    db: AsyncSession, obj: str, relation: str, subject: str, depth: int = 0
) -> bool:
    if depth > 10:  # cycle / runaway guard
        return False

    for rel in RELATION_IMPLICATIONS.get(relation, [relation]):
        tuples = (
            await db.execute(
                select(RelationTuple).where(
                    RelationTuple.object == obj, RelationTuple.relation == rel
                )
            )
        ).scalars().all()
        for t in tuples:
            if t.subject == subject:
                return True
            if "#" in t.subject:
                # Userset subject like "group:eng#member" — recurse.
                uset_obj, uset_rel = t.subject.split("#", 1)
                if await check(db, uset_obj, uset_rel, subject, depth + 1):
                    return True
    return False


async def check_permission(db: AsyncSession, obj: str, permission: str, subject: str) -> bool:
    relation = PERMISSION_TO_RELATION.get(permission)
    if relation is None:
        return False
    return await check(db, obj, relation, subject)
