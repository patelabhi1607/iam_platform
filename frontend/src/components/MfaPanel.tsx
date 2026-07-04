import { useState } from "react";
import { api } from "../api";

export function MfaPanel() {
  const [secret, setSecret] = useState<string | null>(null);
  const [uri, setUri] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [recovery, setRecovery] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function begin() {
    setError(null);
    try {
      const r = await api.mfaBegin();
      setSecret(r.secret);
      setUri(r.otpauth_uri);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed");
    }
  }

  async function confirm() {
    setError(null);
    try {
      setRecovery(await api.mfaConfirm(code));
      setSecret(null);
      setUri(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed");
    }
  }

  return (
    <div className="panel">
      <h2>MFA — TOTP Authenticator</h2>
      {error && <div className="msg error">{error}</div>}

      {!secret && !recovery && (
        <button className="secondary" onClick={begin}>Enable 2FA</button>
      )}

      {secret && (
        <>
          <p className="hint">
            Add this secret to Google Authenticator / Authy (manual entry), then enter
            the 6-digit code to confirm.
          </p>
          <div className="token-box">Secret: {secret}</div>
          <div className="token-box">{uri}</div>
          <input placeholder="6-digit code" value={code} onChange={(e) => setCode(e.target.value)} />
          <button onClick={confirm}>Confirm & Enable</button>
        </>
      )}

      {recovery && (
        <>
          <div className="msg ok">2FA enabled. Save these one-time recovery codes:</div>
          <div className="token-box" style={{ lineHeight: 1.8 }}>
            {recovery.map((c) => (
              <div key={c}>{c}</div>
            ))}
          </div>
          <button className="danger small" onClick={async () => { await api.mfaDisable(); setRecovery(null); }}>
            Disable MFA
          </button>
        </>
      )}
    </div>
  );
}
