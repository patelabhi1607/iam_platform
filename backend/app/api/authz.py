"""
Advanced authorization: create resources, run the PDP (ownership/ACL/ReBAC/ABAC),
and manage the grant stores. The /check endpoint returns the full decision trace
so you can see WHICH model granted or denied access.
"""
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.authz import pdp
from app.core.deps import CurrentPrincipal, require_permission
from app.db.models.authz import AbacPolicy, AclEntry, Doc, RelationTuple
from app.db.session import get_db
from app.schemas.authz import (
    AbacPolicyRequest,
    AbacPolicyResponse,
    AclGrantRequest,
    CheckRequest,
    CreateDocRequest,
    DecisionResponse,
    DocResponse,
    RelationRequest,
)
from app.schemas.core import MessageResponse

router = APIRouter(tags=["authz-advanced"])
Db = Annotated[AsyncSession, Depends(get_db)]
# ACL/ReBAC/ABAC administration reuses the RBAC role-management permission.
ManageAuthz = Depends(require_permission("role:manage"))


# ── Resources ─────────────────────────────────────────────────────────────────

@router.post("/docs", response_model=DocResponse, status_code=201)
async def create_doc(body: CreateDocRequest, principal: CurrentPrincipal, db: Db):
    doc = Doc(
        tenant_id=principal.tenant_id, owner_id=principal.user_id or 0,
        title=body.title, classification=body.classification, attributes=body.attributes,
    )
    db.add(doc)
    await db.flush()
    await db.refresh(doc)
    return doc


@router.get("/docs", response_model=list[DocResponse])
async def list_docs(principal: CurrentPrincipal, db: Db):
    return (
        await db.execute(select(Doc).where(Doc.tenant_id == principal.tenant_id))
    ).scalars().all()


@router.post("/docs/{doc_id}/check", response_model=DecisionResponse)
async def check_access(doc_id: int, body: CheckRequest, principal: CurrentPrincipal, db: Db):
    """Run the PDP and return the decision + trace (does not enforce — for demos)."""
    doc = await db.get(Doc, doc_id)
    if doc is None or doc.tenant_id != principal.tenant_id:
        raise HTTPException(404, "Doc not found")
    decision = await pdp.authorize(db, principal, body.action, doc)
    return DecisionResponse(
        allowed=decision.allowed, reason=decision.reason,
        model=decision.model, trace=decision.trace,
    )


@router.get("/docs/{doc_id}", response_model=DocResponse)
async def read_doc(doc_id: int, principal: CurrentPrincipal, db: Db):
    """Enforced read — the PDP must allow 'read', else 403."""
    doc = await db.get(Doc, doc_id)
    if doc is None or doc.tenant_id != principal.tenant_id:
        raise HTTPException(404, "Doc not found")
    decision = await pdp.authorize(db, principal, "read", doc)
    if not decision.allowed:
        raise HTTPException(403, detail=f"Access denied: {decision.reason}")
    return doc


# ── ACL management ────────────────────────────────────────────────────────────

@router.post("/authz/acl", response_model=MessageResponse, dependencies=[ManageAuthz])
async def add_acl(body: AclGrantRequest, db: Db):
    db.add(AclEntry(resource=body.resource, subject=body.subject, permission=body.permission))
    await db.flush()
    return MessageResponse(message=f"Granted {body.permission} on {body.resource} to {body.subject}")


@router.get("/authz/acl", dependencies=[ManageAuthz])
async def list_acl(db: Db):
    rows = (await db.execute(select(AclEntry))).scalars().all()
    return [{"id": r.id, "resource": r.resource, "subject": r.subject, "permission": r.permission} for r in rows]


# ── ReBAC relation tuples ─────────────────────────────────────────────────────

@router.post("/authz/relations", response_model=MessageResponse, dependencies=[ManageAuthz])
async def add_relation(body: RelationRequest, db: Db):
    db.add(RelationTuple(object=body.object, relation=body.relation, subject=body.subject))
    await db.flush()
    return MessageResponse(message=f"{body.object}#{body.relation}@{body.subject}")


@router.get("/authz/relations", dependencies=[ManageAuthz])
async def list_relations(db: Db):
    rows = (await db.execute(select(RelationTuple))).scalars().all()
    return [{"id": r.id, "object": r.object, "relation": r.relation, "subject": r.subject} for r in rows]


# ── ABAC policies ─────────────────────────────────────────────────────────────

@router.post("/authz/policies", response_model=AbacPolicyResponse, status_code=201, dependencies=[ManageAuthz])
async def add_policy(body: AbacPolicyRequest, principal: CurrentPrincipal, db: Db):
    policy = AbacPolicy(tenant_id=principal.tenant_id, **body.model_dump())
    db.add(policy)
    await db.flush()
    await db.refresh(policy)
    return policy


@router.get("/authz/policies", response_model=list[AbacPolicyResponse], dependencies=[ManageAuthz])
async def list_policies(principal: CurrentPrincipal, db: Db):
    return (
        await db.execute(select(AbacPolicy).where(AbacPolicy.tenant_id == principal.tenant_id))
    ).scalars().all()


@router.delete("/authz/policies/{policy_id}", status_code=204, dependencies=[ManageAuthz])
async def delete_policy(policy_id: int, db: Db):
    p = await db.get(AbacPolicy, policy_id)
    if p:
        await db.delete(p)
