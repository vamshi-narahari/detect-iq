import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { supabase } from "../lib/supabase";

// The 14 canonical MITRE ATT&CK Enterprise tactics, in kill-chain order.
const TACTICS = [
  "Reconnaissance", "Resource Development", "Initial Access", "Execution",
  "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
  "Discovery", "Lateral Movement", "Collection", "Command and Control",
  "Exfiltration", "Impact",
];

export default function Coverage() {
  const navigate = useNavigate();
  const [detections, setDetections] = useState([]);

  useEffect(() => {
    supabase.from("detections").select("tactic,severity,status").then(({ data }) => setDetections(data || []));
  }, []);

  const counts = TACTICS.map((tactic) => ({
    tactic,
    count: detections.filter((d) => (d.tactic || "").toLowerCase() === tactic.toLowerCase()).length,
    production: detections.filter((d) => (d.tactic || "").toLowerCase() === tactic.toLowerCase() && d.status === "active").length,
  }));
  const maxCount = Math.max(1, ...counts.map((c) => c.count));

  function intensity(count) {
    if (count === 0) return "var(--panel-2)";
    const pct = Math.min(1, count / maxCount);
    return `rgba(79, 209, 197, ${0.15 + pct * 0.65})`;
  }

  return (
    <div>
      <h1 style={{ fontSize: 20, margin: "0 0 4px 0" }}>MITRE ATT&CK Coverage</h1>
      <p style={{ color: "var(--text-muted)", fontSize: 13, margin: "0 0 20px 0", maxWidth: "70ch" }}>
        Detection count per tactic, matched against each detection's tagged tactic. Darker means more
        coverage. Click a tactic to see its detections in the Library.
      </p>

      <div className="panel" style={{ padding: 20, marginBottom: 20 }}>
        <div style={{ display: "grid", gridTemplateColumns: `repeat(${TACTICS.length}, 1fr)`, gap: 6 }}>
          {counts.map((c) => (
            <div
              key={c.tactic}
              onClick={() => navigate(`/library?tactic=${encodeURIComponent(c.tactic)}`)}
              style={{
                background: intensity(c.count), borderRadius: "var(--radius-sm)", padding: "14px 6px",
                textAlign: "center", cursor: "pointer", border: "1px solid var(--border)",
              }}
              title={`${c.tactic}: ${c.count} detection(s)`}
            >
              <div className="mono" style={{ fontSize: 18, fontWeight: 700 }}>{c.count}</div>
            </div>
          ))}
        </div>
        <div style={{ display: "grid", gridTemplateColumns: `repeat(${TACTICS.length}, 1fr)`, gap: 6, marginTop: 8 }}>
          {counts.map((c) => (
            <div key={c.tactic} style={{ fontSize: 10, color: "var(--text-muted)", textAlign: "center", lineHeight: 1.3 }}>{c.tactic}</div>
          ))}
        </div>
      </div>

      <div className="panel">
        <div className="panel-head" style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr", gap: 12 }}>
          <span>Tactic</span><span>Detections</span><span>In production</span>
        </div>
        {counts.map((c) => (
          <div key={c.tactic} className="hoverable" onClick={() => navigate(`/library?tactic=${encodeURIComponent(c.tactic)}`)} style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr", gap: 12, padding: "10px 16px", borderBottom: "1px solid var(--border)", fontSize: 13, cursor: "pointer" }}>
            <span>{c.tactic}</span>
            <span className="mono">{c.count}</span>
            <span className="mono" style={{ color: c.production ? "var(--cyan)" : "var(--text-muted)" }}>{c.production}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
