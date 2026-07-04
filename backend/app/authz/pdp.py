"""
Policy Decision Point — the single place that answers "can this principal do this
action on this resource?" by combining every authorization model:

  1. Superuser        → allow
  2. ABAC deny policy → deny (explicit deny overrides everything below)
  3. Ownership        → allow if the principal owns the resource
  4. ACL              → allow on an explicit per-resource grant
  5. ReBAC            → allow if a relationship path grants the relation
  6. ABAC allow       → allow if an allow-policy's condition holds
  7. RBAC             → allow on the coarse tenant permission (document:<action>)
  8. default          → deny
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.authz import abac, acl, rebac
from app.authz.ownership import is_owner
from app.core.principal import Principal
from app.db.models.authz import AbacPolicy, Doc


@dataclass
class Decision:
    allowed: bool
    reason: str
    model: str
    trace: list[str] = field(default_factory=list)


def _build_context(principal: Principal, doc: Doc, action: str) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "subject": {
            "user_id": principal.user_id,
            "permissions": sorted(principal.permissions),
            "clearance": None,  # could come from user attributes in a fuller model
        },
        "resource": {
            "owner_id": doc.owner_id,
            "classification": doc.classification,
            "tenant_id": doc.tenant_id,
            "attributes": doc.attributes or {},
        },
        "action": action,
        "env": {"hour": now.hour, "weekday": now.weekday()},
    }


async def authorize(db: AsyncSession, principal: Principal, action: str, doc: Doc) -> Decision:
    trace: list[str] = []
    subject = f"user:{principal.user_id}"
    resource = f"doc:{doc.id}"

    if principal.is_superuser:
        return Decision(True, "superuser bypass", "superuser", trace)

    ctx = _build_context(principal, doc, action)

    # ABAC policies (deny-overrides). Highest priority first.
    policies = (
        await db.execute(
            select(AbacPolicy)
            .where(AbacPolicy.tenant_id == doc.tenant_id)
            .order_by(AbacPolicy.priority.desc())
        )
    ).scalars().all()
    abac_allow = False
    for p in policies:
        if p.action not in (action, "*"):
            continue
        if abac.evaluate(p.condition, ctx):
            trace.append(f"abac:{p.name}={p.effect}")
            if p.effect == "deny":
                return Decision(False, f"denied by ABAC policy '{p.name}'", "abac", trace)
            abac_allow = True

    if is_owner(doc, principal.user_id):
        trace.append("ownership:owner")
        return Decision(True, "principal owns the resource", "ownership", trace)

    if await acl.has_acl_grant(db, resource, subject, action):
        trace.append("acl:grant")
        return Decision(True, "explicit ACL grant", "acl", trace)

    if await rebac.check_permission(db, resource, action, subject):
        trace.append("rebac:relation")
        return Decision(True, "relationship path grants access", "rebac", trace)

    if abac_allow:
        return Decision(True, "allowed by ABAC policy", "abac", trace)

    if principal.has_permission(f"document:{action}"):
        trace.append("rbac:permission")
        return Decision(True, f"RBAC permission document:{action}", "rbac", trace)

    return Decision(False, "no matching grant", "default-deny", trace)
