# IAM Platform

A comprehensive identity & access management system covering **every major
authentication method** and **every major authorization model** behind one clean
architecture. FastAPI + PostgreSQL + Redis, with a React + TypeScript frontend,
fully containerized.

> **The core idea:** every authentication method resolves to a single
> **`Principal`** (who you are + which tenant + what you can do), and every
> authorization model feeds a single **Policy Decision Point (PDP)**. That
> decoupling is what lets the platform support this much variety without the code
> collapsing into spaghetti — adding a new method is one new file that returns a
> `Principal`.

---

## Quick Start

```bash
cp .env.example .env
docker compose up --build
```

| Service | URL |
|---|---|
| **Web UI** | http://localhost:8080 |
| Backend API | http://localhost:8000 |
| API docs (Swagger) | http://localhost:8000/docs |

Demo users (all password `password123`) in the seeded **acme** tenant:
`owner@`, `admin@`, `member@`, `viewer@example.com` — each with a different role so
you can watch authorization differ.

---

## Authentication — every method

All of these produce the same `Principal`, so the rest of the system never cares
how you logged in.

| Category | Methods |
|---|---|
| **Credential** | Email + password (**Argon2**, bcrypt fallback), HTTP Basic |
| **Token** | JWT access + refresh with **rotation & reuse detection**, server-side sessions (Redis cookie), API keys (hashed, scoped), Personal Access Tokens (scoped) |
| **MFA / step-up** | **TOTP** authenticator 2FA, one-time **recovery codes**, step-up re-auth for sensitive actions |
| **Passwordless** | Email / SMS **OTP**, **magic links** (single-use) |
| **Modern** | **WebAuthn / passkeys** (FIDO2) |
| **Federated (client)** | **Sign in with Google / GitHub** (OAuth2 / OIDC) |
| **Federated (provider)** | This app **as an OAuth2 IdP**: authorization code + **PKCE**, client credentials, **device flow**, token introspection |
| **Enterprise SSO** | **SAML 2.0** SP-initiated |

External providers (Google/GitHub/SMS/SAML) run in **mock mode** by default — the
full flows work with zero external accounts. Set `PROVIDER_MODE=real` and supply
credentials in `.env` to hit the real endpoints; the code path is identical.

### JWT rotation & reuse detection

Each refresh issues a brand-new pair and invalidates the old refresh token. If a
rotated (already-used) token is replayed, the platform detects the reuse and
**revokes every session for that user** by bumping their `token_version`.

---

## Authorization — every model

A single **Policy Decision Point** answers *"can this principal do this action on
this resource?"* by combining all models with **deny-overrides**:

```
superuser → ABAC deny → ownership → ACL → ReBAC → ABAC allow → RBAC → default deny
```

| Model | What it does |
|---|---|
| **RBAC** | Roles → fine-grained permissions, **role hierarchy with inheritance** (owner ⊃ admin ⊃ member ⊃ viewer), wildcard matching |
| **Multi-tenancy** | Every resource and role scoped to a tenant; a user can hold different roles in different tenants |
| **Ownership** | Row-level — the creator/owner of a resource may act on it |
| **ACL** | Explicit per-resource grants: `(resource, subject, permission)` |
| **ReBAC** | Zanzibar-style relationship tuples with relation implication (owner ⊃ editor ⊃ viewer) and **group nesting** (recursive userset expansion) |
| **ABAC** | JSON policy engine over `{subject, resource, action, env}`; allow **and** deny policies with priority |

`POST /docs/{id}/check` returns the decision **plus which model decided and a
trace** — try it in the Authorization Playground in the UI.

---

## Architecture

```
iam_platform/
├── backend/                 FastAPI + PostgreSQL + Redis
│   └── app/
│       ├── core/            config, security (Argon2 + JWT), Principal, deps (auth resolution + guards)
│       ├── db/models/       tenant, user, rbac, credential, mfa, oauth, authz, audit
│       ├── authn/…          (methods live in services/)
│       ├── authz/           rbac, ownership, acl, rebac, abac, catalog, pdp
│       ├── services/        auth, mfa, passwordless, webauthn, social, oauth_provider, saml, tenant, credential
│       ├── providers/       mockable email / SMS
│       └── api/             auth, me, tenants, admin, credentials, mfa, passwordless,
│                            webauthn, social, oauth_provider, saml, authz, resources, health
├── frontend/                React + TypeScript (Vite → nginx)
└── docker-compose.yml       backend + frontend + postgres + redis
```

Tables are created from SQLAlchemy metadata at startup (the schema evolves across
phases); Alembic can be layered on for production migrations.

---

## Key Endpoints (selection)

```
# Core auth
POST /auth/register  /auth/login  /auth/refresh  /auth/logout
POST /auth/mfa/verify            exchange MFA challenge for tokens
POST /auth/step-up               re-verify for sensitive actions

# Passwordless
POST /auth/otp/request  /auth/otp/verify
POST /auth/magic/request  /auth/magic/consume

# MFA
POST /mfa/enroll/begin  /mfa/enroll/confirm  /mfa/disable

# WebAuthn
POST /webauthn/register/begin|complete   /webauthn/authenticate/begin|complete

# Federated
GET  /auth/oauth/{provider}/authorize|callback     social login (Google/GitHub)
GET  /auth/saml/login    POST /auth/saml/acs        SAML SSO
POST /oauth/authorize  /oauth/token  /oauth/device/code  /oauth/introspect   OAuth2 provider

# Identity / RBAC / tenancy
GET  /me   /whoami
GET/POST  /tenants
GET/POST/PUT/DELETE  /admin/roles  /admin/permissions  /admin/members

# Credentials
POST/GET/DELETE  /api-keys   /pats

# Advanced authorization
POST /docs   GET /docs   POST /docs/{id}/check
POST/GET  /authz/acl  /authz/relations  /authz/policies
```

Full interactive reference at `/docs`.

---

## Tech Stack

- **FastAPI** — async web framework
- **python-jose** — JWT; **passlib + argon2/bcrypt** — password hashing
- **pyotp** — TOTP; **py_webauthn** — passkeys/FIDO2
- **PostgreSQL + SQLAlchemy 2 (async)** — data; **Redis** — sessions, token
  blocklist, OTP/magic/challenge/device stores
- **React + TypeScript + Vite** — frontend, served by nginx
- **Docker Compose** — backend + frontend + postgres + redis

---

## Configuration (`.env`)

| Variable | Purpose |
|---|---|
| `JWT_SECRET` | Signing key for JWTs (use a long random string in prod) |
| `PROVIDER_MODE` | `mock` (default) or `real` — external IdP/SMS behavior |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Real Google OAuth (optional) |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | Real GitHub OAuth (optional) |
| `WEBAUTHN_RP_ID` / `WEBAUTHN_ORIGIN` | Passkey relying-party settings |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | Database |

---

## Running Tests

```bash
cd backend
pip install -r requirements.txt
pytest -m unit -v          # fast, no containers
pytest -m integration -v   # spins up real Redis + Postgres via testcontainers
```

---

## Status

Built in four phases, all complete:

- **Phase 1** — core authN (password, JWT, sessions, API keys, PATs, Basic) + RBAC + multi-tenancy
- **Phase 2** — MFA & passwordless (TOTP, recovery codes, OTP, magic links, WebAuthn, step-up)
- **Phase 3** — federated identity (OAuth2 social login, OAuth2 provider with PKCE/device, SAML)
- **Phase 4** — advanced authorization (ABAC + policy engine, ReBAC, ACLs, ownership, unified PDP)
