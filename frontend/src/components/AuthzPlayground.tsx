import { useCallback, useEffect, useState } from "react";
import { api } from "../api";

type Doc = { id: number; title: string; classification: string; owner_id: number };
type Decision = { allowed: boolean; reason: string; model: string; trace: string[] };

const ACTIONS = ["read", "write", "share", "delete"];

export function AuthzPlayground() {
  const [docs, setDocs] = useState<Doc[]>([]);
  const [title, setTitle] = useState("My Document");
  const [classification, setClassification] = useState("internal");
  const [results, setResults] = useState<Record<string, Decision>>({});

  const load = useCallback(async () => setDocs(await api.listDocs()), []);
  useEffect(() => { load(); }, [load]);

  async function create() {
    await api.createDoc(title, classification);
    await load();
  }

  async function check(docId: number, action: string) {
    const d = await api.checkAccess(docId, action);
    setResults((p) => ({ ...p, [`${docId}:${action}`]: d }));
  }

  return (
    <div className="panel">
      <h2>Authorization Playground (PDP: RBAC · Ownership · ACL · ReBAC · ABAC)</h2>
      <div className="row" style={{ gap: 10, alignItems: "flex-end" }}>
        <div style={{ flex: 2 }}>
          <label>Title</label>
          <input value={title} onChange={(e) => setTitle(e.target.value)} />
        </div>
        <div style={{ flex: 1 }}>
          <label>Classification</label>
          <select value={classification} onChange={(e) => setClassification(e.target.value)}>
            <option>public</option>
            <option>internal</option>
            <option>secret</option>
          </select>
        </div>
        <button onClick={create}>Create doc</button>
      </div>

      <p className="hint">
        Create a doc, then check an action. The result shows WHICH model decided.
        Manage ACL grants, ReBAC relations, and ABAC policies via the API (see docs).
      </p>

      {docs.map((d) => (
        <div key={d.id} style={{ borderTop: "1px solid var(--border)", paddingTop: 10, marginTop: 10 }}>
          <div className="row" style={{ justifyContent: "space-between" }}>
            <b>doc:{d.id} — {d.title}</b>
            <span className="badge-role" style={{ background: "var(--panel-2)" }}>{d.classification}</span>
          </div>
          <div className="row" style={{ flexWrap: "wrap", gap: 6, marginTop: 6 }}>
            {ACTIONS.map((a) => {
              const r = results[`${d.id}:${a}`];
              return (
                <div key={a} style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                  <button className="secondary small" onClick={() => check(d.id, a)}>{a}</button>
                  {r && (
                    <span style={{ fontSize: 11, color: r.allowed ? "var(--green)" : "var(--red)" }}>
                      {r.allowed ? "✓" : "✗"} {r.model}
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}
