"""
The permission catalog and the built-in system roles with hierarchy.

Role hierarchy (each inherits the one below):
    owner  →  admin  →  member  →  viewer
"""

# Every fine-grained permission the platform understands.
PERMISSIONS: dict[str, str] = {
    "document:read": "View documents",
    "document:write": "Create and edit documents",
    "document:delete": "Delete documents",
    "document:share": "Share documents with others",
    "member:read": "View members",
    "member:invite": "Invite members",
    "member:remove": "Remove members",
    "role:read": "View roles",
    "role:manage": "Create/edit/delete roles and assignments",
    "apikey:manage": "Create and revoke API keys",
    "tenant:manage": "Manage tenant settings",
    "audit:read": "Read the audit log",
}

# System roles: (name, parent_name_or_None, [direct permissions]).
# Effective permissions accumulate up the parent chain.
SYSTEM_ROLES: list[tuple[str, str | None, list[str]]] = [
    ("viewer", None, ["document:read", "member:read", "role:read"]),
    ("member", "viewer", ["document:write", "document:share"]),
    (
        "admin",
        "member",
        [
            "document:delete",
            "member:invite",
            "member:remove",
            "role:manage",
            "apikey:manage",
            "audit:read",
        ],
    ),
    ("owner", "admin", ["tenant:manage"]),
]

DEFAULT_ROLE = "member"
OWNER_ROLE = "owner"
