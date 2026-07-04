import { useState } from "react";
import { api } from "../api";

// Email OTP passwordless login. In mock mode we can peek the delivered code so
// the demo works without a real mailbox.
export function PasswordlessLogin({ onAuthed }: { onAuthed: () => void }) {
  const [email, setEmail] = useState("passwordless@example.com");
  const [code, setCode] = useState("");
  const [sent, setSent] = useState(false);
  const [peeked, setPeeked] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function request() {
    setError(null);
    await api.otpRequest(email);
    setSent(true);
    // Dev convenience: show the mock-delivered message.
    setPeeked(await api.otpPeek(email));
  }

  async function verify() {
    setError(null);
    try {
      await api.otpVerify(email, code);
      onAuthed();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed");
    }
  }

  return (
    <div className="panel">
      <h2>Passwordless — Email OTP</h2>
      {error && <div className="msg error">{error}</div>}
      <label>Email</label>
      <input value={email} onChange={(e) => setEmail(e.target.value)} type="email" />
      {!sent ? (
        <button className="secondary" onClick={request}>Send code</button>
      ) : (
        <>
          {peeked && <div className="msg ok">Mock inbox: {peeked}</div>}
          <label>6-digit code</label>
          <input value={code} onChange={(e) => setCode(e.target.value)} />
          <button onClick={verify}>Verify & Sign in</button>
        </>
      )}
    </div>
  );
}
