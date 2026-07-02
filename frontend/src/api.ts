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
};
