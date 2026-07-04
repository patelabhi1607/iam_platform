# IAM Platform

Comprehensive identity & access management: **every authentication method** and
**every authorization model**, built with FastAPI + PostgreSQL + Redis and a
React + TypeScript frontend. Built in phases.

## Phase 1 ✅ — core authN + RBAC + multi-tenancy

**Authentication methods** (all resolve to a unified `Principal`):
- Email + password (Argon2, bcrypt fallback)
- JWT access + refresh with rotation & reuse detection
- Server-side sessions (Redis-backed cookie)
- API keys (hashed, scoped, tenant machine credentials)
- Personal Access Tokens (user-owned, scoped)
- HTTP Basic auth

**Authorization** — RBAC with fine-grained permissions, **role hierarchy**
(owner → admin → member → viewer, inheriting permissions), wildcard matching,
scope narrowing for token/key auth, and **multi-tenancy** (everything scoped to a tenant).

## Quick Start
```bash
cp .env.example .env
docker compose up --build
```
UI: http://localhost:8080 · API: http://localhost:8000/docs

Demo users (all password `password123`): `owner@`, `admin@`, `member@`, `viewer@example.com`

## Roadmap
- Phase 2 ✅ — MFA/passwordless: TOTP authenticator, email/SMS OTP, magic links, recovery codes, WebAuthn/passkeys, step-up auth
- Phase 3: Federated — OAuth2 social login (Google/GitHub), OAuth2 provider (auth code + PKCE, client credentials, device), SAML
- Phase 4: Advanced authZ — ABAC + policy engine, ReBAC (Zanzibar), ACLs, row-level ownership
