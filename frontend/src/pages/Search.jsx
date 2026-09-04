import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Search as SearchIcon } from "lucide-react";
import { supabase } from "../lib/supabase";

const SIEMS = ["splunk", "crowdstrike", "logscale", "sentinel", "qradar", "chronicle"];

export default function SearchPage() {
  const navigate = useNavigate();
  const [scope, setScope] = useState("all");
  const [query, setQuery] = useState("");
  const [results, setResults] = useState(null);
  const [busy, setBusy] = useState(false);
  const [statusByProvider, setStatusByProvider] = useState({});

  useEffect(() => {
    supabase.from("integrations").select("*").then(({ data }) => {
      const map = {};
      (data || []).forEach((i) => { map[i.provider] = i.status; });
      setStatusByProvider(map);
    });
  }, []);

  async function runSearch() {
    setBusy(true);
    let q = supabase.from("detections").select("*").limit(50);
    if (query) q = q.or(`name.ilike.%${query}%,query.ilike.%${query}%,technique_id.ilike.%${query}%`);
    if (scope !== "all") q = q.eq("tool", scope);
    const { data } = await q;
    setResults(data || []);
    setBusy(false);
  }

  return (
    <div>
      <h1 style={{ fontSize: 20, margin: "0 0 4px 0" }}>Search</h1>
      <p style={{ color: "var(--text-muted)", fontSize: 13, margin: "0 0 20px 0", maxWidth: "70ch" }}>
        One box, this source or all. Hits come back normalized so you can correlate and open the Editor.
      </p>

      <div className="panel" style={{ padding: 16, marginBottom: 16 }}>
        <div style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
          <button className="btn" style={scope === "all" ? { borderColor: "var(--cyan)", color: "var(--cyan)" } : {}} onClick={() => setScope("all")}>
            All sources
          </button>
          {SIEMS.map((s) => {
            const connected = statusByProvider[s] === "connected";
            return (
              <button
                key={s}
                className="btn"
                style={scope === s ? { borderColor: "var(--cyan)", color: "var(--cyan)" } : {}}
                onClick={() => setScope(s)}
              >
                {s} <span style={{ marginLeft: 6, fontSize: 10, color: connected ? "var(--cyan)" : "var(--text-dim)" }}>{connected ? "●" : "○"}</span>
              </button>
            );
          })}
        </div>
        <p style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 12 }}>
          This searches your detection library directly. A filled dot means that SIEM is connected
          in Settings → Integrations; live query execution against it lands once that connector is wired.
        </p>
        <div style={{ display: "flex", gap: 8 }}>
          <div style={{ flex: 1, display: "flex", alignItems: "center", gap: 8, background: "var(--panel-2)", border: "1px solid var(--border)", borderRadius: "var(--radius)", padding: "8px 12px" }}>
            <SearchIcon size={14} />
            <input
              style={{ flex: 1, background: "transparent", border: "none", outline: "none", color: "var(--text)", fontSize: 13 }}
              placeholder="EncodedCommand, T1110, or any query text…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && runSearch()}
            />
          </div>
          <button className="btn btn-primary" onClick={runSearch} disabled={busy}>{busy ? "Searching…" : "Search"}</button>
        </div>
      </div>

      {results && (
        <div className="panel">
          <div className="panel-head">{results.length} result{results.length !== 1 ? "s" : ""}</div>
          {results.length === 0 && <div style={{ padding: 16, fontSize: 13, color: "var(--text-muted)" }}>No matches.</div>}
          {results.map((r) => (
            <div
              key={r.id}
              className="hoverable"
              onClick={() => navigate(`/editor?id=${r.id}`)}
              style={{ display: "flex", gap: 12, padding: "10px 16px", borderBottom: "1px solid var(--border)", fontSize: 13, alignItems: "center", cursor: "pointer" }}
            >
              <span style={{ flex: 1 }}>{r.name}</span>
              <span className="mono" style={{ color: "var(--text-muted)" }}>{r.tool}</span>
              <span className="badge">{r.technique_id || "no mitre"}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
