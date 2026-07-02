"""
A Principal is the unified representation of "who is making this request",
regardless of which authentication method was used (password/JWT, session,
API key, PAT, OAuth token, passkey, ...).

Every authN method produces a Principal; every authZ check consumes one.
"""
from dataclasses import dataclass, field


@dataclass
class Principal:
    kind: str                       # "user" | "api_key" | "pat" | "service"
    auth_method: str                # "jwt" | "session" | "api_key" | "pat" | "basic" | ...
    user_id: int | None = None
    tenant_id: int | None = None
    is_superuser: bool = False

    # Effective RBAC permissions (role + inherited parents + wildcards expanded).
    permissions: set[str] = field(default_factory=set)
    # Token/key scopes — an upper bound that intersects with permissions.
    scopes: set[str] = field(default_factory=set)

    # MFA / step-up state (for sensitive-action gating).
    mfa_satisfied: bool = True
    step_up_at: int | None = None

    def has_permission(self, required: str) -> bool:
        """
        True if the principal holds `required` (e.g. "document:read").
        Superusers pass everything. Wildcards are honored on the granted side:
        "*:*", "document:*", and "*:read" all match "document:read".
        If the principal carries scopes (token-based auth), the permission must
        ALSO be within scope — scopes can only narrow, never widen.
        """
        if self.is_superuser:
            return True
        if not _match_any(self.permissions, required):
            return False
        if self.scopes and not _match_any(self.scopes, required):
            return False
        return True


def _match_any(granted: set[str], required: str) -> bool:
    if required in granted or "*:*" in granted or "*" in granted:
        return True
    res, _, act = required.partition(":")
    return (
        f"{res}:*" in granted
        or f"*:{act}" in granted
    )
