import { useCallback, useEffect, useState } from "react";
import { api, tokens, type ActionResult, type WhoAmI } from "./api";
import { MfaPanel } from "./components/MfaPanel";
import { PasswordlessLogin } from "./components/PasswordlessLogin";
import { AuthzPlayground } from "./components/AuthzPlayground";

const DEMO_USERS = [
  { email: "owner@example.com", role: "owner" },
  { email: "admin@example.com", role: "admin" },
  { email: "member@example.com", role: "member" },
  { email: "viewer@example.com", role: "viewer" },
];

const ACTIONS = [
  { label: "Read documents", method: "GET", path: "/documents", perm: "document:read" },
  { label: "Create document", method: "POST", path: "/documents", perm: "document:write" },
  { label: "Share document", method: "POST", path: "/documents/1/share", perm: "document:share" },
  { label: "Delete document", method: "DELETE", path: "/documents/1", perm: "document:delete" },
];

export function App() {
  const [who, setWho] = useState<WhoAmI | null>(null);
  const [results, setResults] = useState<Record<string, ActionResult>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    if (!tokens.access) {
      setWho(null);
      return;
    }
    try {
      setWho(await api.whoami());
    } catch {
      tokens.clear();
      setWho(null);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [mfaCode, setMfaCode] = useState("");

  async function login(email: string) {
    setError(null);
    setBusy(true);
    setResults({});
    try {
      const res = await api.loginMaybeChallenge(email, "password123");
      if (res.mfa) {
        setMfaToken(res.token!); // account has 2FA — ask for a code
      } else {
        await refresh();
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Login failed");
    } finally {
      setBusy(false);
    }
  }

  async function submitMfa() {
    setError(null);
    try {
      await api.mfaVerifyChallenge(mfaToken!, mfaCode);
      setMfaToken(null);
      setMfaCode("");
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "MFA failed");
    }
  }

  function logout() {
    tokens.clear();
    setWho(null);
    setResults({});
  }

  async function tryAction(a: (typeof ACTIONS)[number]) {
    const res = await api.tryAction(a.method, a.path);
    setResults((prev) => ({ ...prev, [a.label]: res }));
  }

  return (
    <div className="wrap">
      <h1>IAM Platform <span className="tag">RBAC</span></h1>
      <p className="subtitle">
        Log in as different roles and watch role-based access control allow or deny
        each action. Owner → admin → member → viewer (role hierarchy with inherited
        permissions). All passwords: <code>password123</code>.
      </p>

      {error && <div className="msg error">{error}</div>}

      {!who ? (
        <>
          <div className="panel">
            <h2>Log in as a demo role</h2>
            <div className="row" style={{ flexWrap: "wrap", gap: 10 }}>
              {DEMO_USERS.map((u) => (
                <button key={u.email} disabled={busy} onClick={() => login(u.email)}>
                  {u.role}
                </button>
              ))}
            </div>
            {mfaToken && (
              <div style={{ marginTop: 16 }}>
                <div className="msg ok">This account has 2FA — enter your authenticator or recovery code.</div>
                <input placeholder="TOTP or recovery code" value={mfaCode} onChange={(e) => setMfaCode(e.target.value)} />
                <button onClick={submitMfa}>Verify</button>
              </div>
            )}
          </div>
          <div className="panel">
            <h2>Federated login (mock providers)</h2>
            <div className="row" style={{ flexWrap: "wrap", gap: 10 }}>
              <button className="secondary" onClick={async () => { await api.socialLogin("google"); await refresh(); }}>
                Continue with Google
              </button>
              <button className="secondary" onClick={async () => { await api.socialLogin("github"); await refresh(); }}>
                Continue with GitHub
              </button>
              <button className="secondary" onClick={() => { window.location.href = "http://localhost:8000/auth/saml/login"; }}>
                SSO (SAML) — API
              </button>
            </div>
            <p className="hint">Mock OAuth/SAML — no external accounts needed. Also try the OAuth2 provider + device flow via the API docs.</p>
          </div>
          <PasswordlessLogin onAuthed={refresh} />
        </>
      ) : (
        <>
          <div className="panel">
            <h2>Authenticated</h2>
            <div className="kv"><span className="k">Auth method</span><span>{who.auth_method}</span></div>
            <div className="kv"><span className="k">User ID</span><span>{who.user_id}</span></div>
            <div className="kv"><span className="k">Tenant ID</span><span>{who.tenant_id}</span></div>
            <div className="kv">
              <span className="k">Effective permissions ({who.permissions.length})</span>
              <span style={{ textAlign: "right", fontSize: 12, fontFamily: "monospace" }}>
                {who.permissions.join(", ") || "none"}
              </span>
            </div>
            <div style={{ marginTop: 16 }}>
              <button className="danger" onClick={logout}>Log out</button>
            </div>
          </div>

          <AuthzPlayground />

          <MfaPanel />

          <div className="panel">
            <h2>Try actions (RBAC enforced per endpoint)</h2>
            {ACTIONS.map((a) => {
              const res = results[a.label];
              return (
                <div key={a.label} style={{ marginBottom: 12 }}>
                  <div className="row" style={{ justifyContent: "space-between" }}>
                    <div>
                      <button className="secondary small" onClick={() => tryAction(a)}>
                        {a.method} {a.label}
                      </button>
                      <code style={{ marginLeft: 10, fontSize: 12, color: "var(--muted)" }}>
                        needs {a.perm}
                      </code>
                    </div>
                    {res && (
                      <span className={"badge-role " + (res.ok ? "member" : "")}
                        style={{ color: res.ok ? "var(--green)" : "var(--red)" }}>
                        {res.status} {res.ok ? "ALLOWED" : "DENIED"}
                      </span>
                    )}
                  </div>
                  {res && <div className="hint" style={{ marginTop: 4 }}>{res.message}</div>}
                </div>
              );
            })}
          </div>
        </>
      )}

      <div className="footer">
        <a href={api ? "http://localhost:8000/docs" : "#"} target="_blank" rel="noreferrer">API Docs</a>
      </div>
    </div>
  );
}
