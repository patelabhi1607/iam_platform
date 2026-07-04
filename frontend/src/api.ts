export const API_URL: string =
  (import.meta.env.VITE_API_URL as string | undefined) ?? "http://localhost:8000";

const ACCESS = "iam_access";
const REFRESH = "iam_refresh";

export const tokens = {
  get access() {
    return localStorage.getItem(ACCESS);
  },
  set(a: string, r: string) {
    localStorage.setItem(ACCESS, a);
    localStorage.setItem(REFRESH, r);
  },
  clear() {
    localStorage.removeItem(ACCESS);
    localStorage.removeItem(REFRESH);
  },
};

export interface WhoAmI {
  kind: string;
  auth_method: string;
  user_id: number | null;
  tenant_id: number | null;
  is_superuser: boolean;
  permissions: string[];
  scopes: string[];
  mfa_satisfied: boolean;
}

export interface ActionResult {
  ok: boolean;
  status: number;
  message: string;
}

async function req(path: string, opts: { method?: string; body?: unknown; auth?: boolean } = {}) {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (opts.auth && tokens.access) headers["Authorization"] = `Bearer ${tokens.access}`;
  const resp = await fetch(API_URL + path, {
    method: opts.method ?? "GET",
    headers,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  return resp;
}

export const api = {
  async login(email: string, password: string): Promise<void> {
    const r = await req("/auth/login", { method: "POST", body: { email, password } });
    if (!r.ok) throw new Error((await r.json()).detail ?? "Login failed");
    const d = await r.json();
    tokens.set(d.access_token, d.refresh_token);
  },

  async whoami(): Promise<WhoAmI> {
    const r = await req("/whoami", { auth: true });
    if (!r.ok) throw new Error("Not authenticated");
    return r.json();
  },

  async tryAction(method: string, path: string): Promise<ActionResult> {
    const r = await req(path, { method, auth: true });
    let message = r.statusText;
    try {
      const data = await r.json();
      message = data.message ?? data.detail ?? message;
    } catch {
      /* non-JSON response */
    }
    return { ok: r.ok, status: r.status, message };
  },

  // ── MFA (TOTP) ──────────────────────────────────────────────────────────
  async mfaBegin(): Promise<{ secret: string; otpauth_uri: string }> {
    const r = await req("/mfa/enroll/begin", { method: "POST", auth: true });
    if (!r.ok) throw new Error("Enroll failed");
    return r.json();
  },
  async mfaConfirm(code: string): Promise<string[]> {
    const r = await req("/mfa/enroll/confirm", { method: "POST", body: { code }, auth: true });
    if (!r.ok) throw new Error((await r.json()).detail ?? "Invalid code");
    return (await r.json()).recovery_codes;
  },
  async mfaDisable(): Promise<void> {
    await req("/mfa/disable", { method: "POST", auth: true });
  },

  // ── Passwordless (email OTP) ───────────────────────────────────────────
  async otpRequest(email: string): Promise<void> {
    await req("/auth/otp/request", { method: "POST", body: { email, channel: "email" } });
  },
  async otpPeek(email: string): Promise<string> {
    const r = await req(`/auth/dev/outbox?email=${encodeURIComponent(email)}&channel=email`);
    return (await r.json()).message ?? "";
  },
  async otpVerify(email: string, code: string): Promise<void> {
    const r = await req("/auth/otp/verify", { method: "POST", body: { email, code } });
    if (!r.ok) throw new Error((await r.json()).detail ?? "Invalid code");
    const d = await r.json();
    tokens.set(d.access_token, d.refresh_token);
  },

  // ── MFA challenge (when password login returns mfa_required) ────────────
  async loginMaybeChallenge(email: string, password: string): Promise<{ mfa: boolean; token?: string }> {
    const r = await req("/auth/login", { method: "POST", body: { email, password } });
    if (!r.ok) throw new Error((await r.json()).detail ?? "Login failed");
    const d = await r.json();
    if (d.mfa_required) return { mfa: true, token: d.mfa_token };
    tokens.set(d.access_token, d.refresh_token);
    return { mfa: false };
  },
  async mfaVerifyChallenge(mfa_token: string, code: string): Promise<void> {
    const r = await req("/auth/mfa/verify", { method: "POST", body: { mfa_token, code } });
    if (!r.ok) throw new Error((await r.json()).detail ?? "Invalid MFA code");
    const d = await r.json();
    tokens.set(d.access_token, d.refresh_token);
  },

  // ── Advanced authorization (PDP) ────────────────────────────────────────
  async createDoc(title: string, classification: string): Promise<{ id: number; title: string; classification: string }> {
    const r = await req("/docs", { method: "POST", body: { title, classification }, auth: true });
    if (!r.ok) throw new Error("Create failed");
    return r.json();
  },
  async listDocs(): Promise<Array<{ id: number; title: string; classification: string; owner_id: number }>> {
    const r = await req("/docs", { auth: true });
    return r.ok ? r.json() : [];
  },
  async checkAccess(docId: number, action: string): Promise<{ allowed: boolean; reason: string; model: string; trace: string[] }> {
    const r = await req(`/docs/${docId}/check`, { method: "POST", body: { action }, auth: true });
    return r.json();
  },

  // ── Social login (mock provider: the whole flow completes over fetch) ────
  async socialLogin(provider: "google" | "github"): Promise<void> {
    const start = await req(`/auth/oauth/${provider}/authorize`);
    const { authorization_url } = await start.json();
    // In mock mode the provider redirects straight through to our callback,
    // which returns the token pair as JSON (fetch follows the redirects).
    const r = await fetch(authorization_url);
    if (!r.ok) throw new Error(`${provider} login failed`);
    const d = await r.json();
    tokens.set(d.access_token, d.refresh_token);
  },
};
