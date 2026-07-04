from typing import Any

from pydantic import BaseModel, Field


class CreateDocRequest(BaseModel):
    title: str = Field(min_length=1, max_length=256)
    classification: str = "internal"  # public | internal | secret
    attributes: dict[str, Any] = {}


class DocResponse(BaseModel):
    id: int
    tenant_id: int
    owner_id: int
    title: str
    classification: str
    attributes: dict[str, Any]
    model_config = {"from_attributes": True}


class CheckRequest(BaseModel):
    action: str = "read"


class DecisionResponse(BaseModel):
    allowed: bool
    reason: str
    model: str
    trace: list[str]


class AclGrantRequest(BaseModel):
    resource: str        # "doc:42"
    subject: str         # "user:5"
    permission: str      # "read"


class RelationRequest(BaseModel):
    object: str          # "doc:42" or "group:eng"
    relation: str        # "viewer" | "editor" | "owner" | "member"
    subject: str         # "user:5" or "group:eng#member"


class AbacPolicyRequest(BaseModel):
    name: str
    effect: str = "allow"   # allow | deny
    action: str = "*"
    condition: dict[str, Any] = {}
    priority: int = 0
    description: str | None = None


class AbacPolicyResponse(AbacPolicyRequest):
    id: int
    model_config = {"from_attributes": True}
