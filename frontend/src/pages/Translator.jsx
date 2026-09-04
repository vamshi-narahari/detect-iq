import { useState } from "react";
import { ArrowRight, Copy } from "lucide-react";
import { translateQuery } from "../lib/api";

const SIEMS = ["splunk", "crowdstrike", "logscale", "sentinel", "qradar", "chronicle", "tanium", "panther", "sumologic", "elastic"];

export default function Translator() {
  const [query, setQuery] = useState("");
  const [from, setFrom] = useState("splunk");
  const [to, setTo] = useState("sentinel");
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function translate() {
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const data = await translateQuery(query, from, to);
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{ maxWidth: 900 }}>
      <h1 style={{ fontSize: 20, margin: "0 0 4px 0" }}>Query Translator</h1>
      <p style={{ color: "var(--text-muted)", fontSize: 13, margin: "0 0 20px 0", maxWidth: "70ch" }}>
        Convert a detection query from one SIEM's syntax to another. Useful when migrating a rule or
        deploying the same logic across platforms — always review the result, some constructs don't map 1:1.
      </p>

      <div className="panel" style={{ padding: 20, marginBottom: 16 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
          <select className="input" value={from} onChange={(e) => setFrom(e.target.value)} style={{ maxWidth: 200 }}>
            {SIEMS.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <ArrowRight size={16} color="var(--text-muted)" />
          <select className="input" value={to} onChange={(e) => setTo(e.target.value)} style={{ maxWidth: 200 }}>
            {SIEMS.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
        <textarea
          className="input"
          rows={8}
          style={{ fontFamily: "var(--mono)", fontSize: 12.5, marginBottom: 12 }}
          placeholder={`Paste a ${from} query...`}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        {error && <div style={{ color: "var(--red)", fontSize: 12.5, marginBottom: 10 }}>{error}</div>}
        <button className="btn btn-primary" onClick={translate} disabled={busy || !query}>
          {busy ? "Translating…" : "Translate"}
        </button>
      </div>

      {result && (
        <div className="panel" style={{ padding: 20 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
            <div className="mono" style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase" }}>{to}</div>
            <button className="btn" onClick={() => navigator.clipboard.writeText(result.translated)}>
              <Copy size={12} style={{ marginRight: 6, verticalAlign: -1 }} />Copy
            </button>
          </div>
          <pre className="mono" style={{ fontSize: 12.5, background: "var(--panel-2)", padding: 14, borderRadius: "var(--radius-sm)", whiteSpace: "pre-wrap", marginBottom: result.notes ? 14 : 0 }}>{result.translated}</pre>
          {result.notes && (
            <div style={{ fontSize: 12.5, color: "var(--amber)" }}>{result.notes}</div>
          )}
        </div>
      )}
    </div>
  );
}
