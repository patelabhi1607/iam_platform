from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


# ── Auth ──────────────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    full_name: str | None = None
    tenant_name: str | None = None  # if given, create a tenant and make user its owner


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    tenant_id: int | None = None


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


class MessageResponse(BaseModel):
    message: str


# ── Identity ──────────────────────────────────────────────────────────────────

class UserResponse(BaseModel):
    id: int
    email: EmailStr
    full_name: str | None
    is_active: bool
    is_verified: bool
    is_superuser: bool
    mfa_enabled: bool
    model_config = {"from_attributes": True}


class WhoAmI(BaseModel):
    kind: str
    auth_method: str
    user_id: int | None
    tenant_id: int | None
    is_superuser: bool
    permissions: list[str]
    scopes: list[str]
    mfa_satisfied: bool


# ── Tenants / RBAC ────────────────────────────────────────────────────────────

class TenantResponse(BaseModel):
    id: int
    slug: str
    name: str
    is_active: bool
    model_config = {"from_attributes": True}


class CreateTenantRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    slug: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9-]+$")


class PermissionResponse(BaseModel):
    id: int
    name: str
    description: str | None
    model_config = {"from_attributes": True}


class RoleResponse(BaseModel):
    id: int
    name: str
    description: str | None
    parent_id: int | None
    is_system: bool
    permissions: list[str]


class CreateRoleRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    description: str | None = None
    parent_id: int | None = None
    permissions: list[str] = []


class UpdateRolePermissionsRequest(BaseModel):
    permissions: list[str]


class InviteMemberRequest(BaseModel):
    email: EmailStr
    role_name: str = "member"


class AssignRoleRequest(BaseModel):
    role_name: str


class MemberResponse(BaseModel):
    user_id: int
    email: EmailStr
    role: str


# ── Credentials ───────────────────────────────────────────────────────────────

class CreateApiKeyRequest(BaseModel):
    name: str
    scopes: list[str] = []


class ApiKeyResponse(BaseModel):
    id: int
    name: str
    prefix: str
    scopes: str
    is_active: bool
    created_at: datetime
    model_config = {"from_attributes": True}


class ApiKeyCreatedResponse(ApiKeyResponse):
    api_key: str  # shown once


class CreatePatRequest(BaseModel):
    name: str
    scopes: list[str] = []


class PatCreatedResponse(BaseModel):
    id: int
    name: str
    prefix: str
    token: str  # shown once
