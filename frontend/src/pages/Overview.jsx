import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { supabase } from "../lib/supabase";

export default function Overview() {
  const navigate = useNavigate();
  const [detections, setDetections] = useState([]);
  const [runs, setRuns] = useState([]);
  const [suppressions, setSuppressions] = useState([]);
  const [packs, setPacks] = useState([]);

  useEffect(() => {
    supabase.from("detections").select("*").then(({ data }) => setDetections(data || []));
    supabase.from("validation_runs").select("*").then(({ data }) => setRuns(data || []));
    supabase.from("suppression_rules").select("*").then(({ data }) => setSuppressions(data || []));
    supabase.from("packs").select("*").then(({ data }) => setPacks(data || []));
  }, []);

  const production = detections.filter((d) => d.status === "active");
  const failingRuns = runs.filter((r) => r.status === "failed").length;
  const openRuns = runs.filter((r) => r.status === "queued" || r.status === "running").length;
  const coveredTechniques = new Set(detections.map((d) => d.technique_id).filter(Boolean));
  const packTechniques = new Set(packs.flatMap((p) => p.techniques || []));
  const gaps = [...packTechniques].filter((t) => !coveredTechniques.has(t)).length;

  const tacticCounts = detections.reduce((acc, d) => {
    if (!d.tactic) return acc;
    acc[d.tactic] = (acc[d.tactic] || 0) + 1;
    return acc;
  }, {});
  const maxTactic = Math.max(1, ...Object.values(tacticCounts));

  const stats = [
    { label: "IN PRODUCTION", value: String(production.length).padStart(2, "0"), tone: "cyan", to: "/library" },
    { label: "TOTAL IN LIBRARY", value: String(detections.length).padStart(2, "0"), tone: "cyan", to: "/library" },
    { label: "OPEN VALIDATIONS", value: String(openRuns).padStart(2, "0"), note: failingRuns ? `${failingRuns} failing` : "none failing", tone: openRuns ? "amber" : "cyan", to: "/library" },
    { label: "COVERAGE GAPS", value: String(gaps).padStart(2, "0"), tone: gaps ? "amber" : "cyan", to: "/packs" },
  ];

  return (
    <div>
      <section className="panel" style={{ padding: "26px 28px", marginBottom: 20, display: "flex", alignItems: "center", gap: 28, overflow: "hidden", position: "relative" }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="mono" style={{ fontSize: 11, color: "var(--cyan)", letterSpacing: "0.08em", marginBottom: 8 }}>DETECTIQ · LIVE</div>
          <h1 style={{ fontSize: 22, margin: "0 0 8px 0", fontWeight: 600 }}>Signal is measured against the threshold you set</h1>
          <p style={{ fontSize: 13, color: "var(--text-muted)", margin: "0 0 16px 0", maxWidth: "52ch", lineHeight: 1.6 }}>
            Every detection tracks its own noise over time. When the signal crosses the line, it fires
            — and you can see exactly why, tune it, and ship it.
          </p>
          <div style={{ display: "flex", gap: 10 }}>
            <Link to="/builder" className="btn btn-primary" style={{ textDecoration: "none" }}>Build a detection</Link>
            <Link to="/leads" className="btn" style={{ textDecoration: "none" }}>Ask a hunt question</Link>
          </div>
        </div>
        <Waveform />
      </section>

      <section style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginBottom: 20 }}>
        {stats.map((s) => (
          <div className="panel hoverable" key={s.label} onClick={() => navigate(s.to)} style={{ padding: "16px 18px", cursor: "pointer" }}>
            <div className="mono" style={{ fontSize: 10.5, letterSpacing: "0.06em", color: "var(--text-muted)", marginBottom: 10 }}>{s.label}</div>
            <div className="mono" style={{ fontSize: 28, fontVariantNumeric: "tabular-nums", marginBottom: 4 }}>{s.value}</div>
            {s.note && <div style={{ fontSize: 11.5, color: `var(--${s.tone})` }}>{s.note}</div>}
          </div>
        ))}
      </section>

      <div style={{ display: "grid", gridTemplateColumns: "1.3fr 1fr", gap: 16 }}>
        <section className="panel">
          <div className="panel-head">In production</div>
          {production.length === 0 && (
            <div style={{ padding: 16, fontSize: 13, color: "var(--text-muted)" }}>
              Nothing deployed to production yet. Mark a detection's status as "active" in the Editor once validated.
            </div>
          )}
          {production.map((d) => (
            <div key={d.id} className="hoverable" onClick={() => navigate(`/editor?id=${d.id}`)} style={{ display: "flex", alignItems: "center", gap: 12, padding: "11px 16px", borderBottom: "1px solid var(--border)", fontSize: 13, cursor: "pointer" }}>
              <span style={{ flex: 1 }}>{d.name}</span>
              <span className="mono" style={{ color: "var(--text-muted)", fontSize: 11.5 }}>{d.tool}</span>
              <span className="badge" data-tone={d.severity === "critical" || d.severity === "high" ? "red" : "amber"}>{d.severity || "—"}</span>
            </div>
          ))}
        </section>

        <section className="panel">
          <div className="panel-head">Coverage by tactic</div>
          {Object.keys(tacticCounts).length === 0 && (
            <div style={{ padding: 16, fontSize: 13, color: "var(--text-muted)" }}>No detections tagged with a tactic yet.</div>
          )}
          {Object.entries(tacticCounts).sort((a, b) => b[1] - a[1]).map(([tactic, count]) => (
            <div key={tactic} className="hoverable" onClick={() => navigate(`/library?tactic=${encodeURIComponent(tactic)}`)} style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 16px", borderBottom: "1px solid var(--border)", fontSize: 12.5, cursor: "pointer" }}>
              <div style={{ width: 130, flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{tactic}</div>
              <div style={{ flex: 1, height: 5, background: "var(--panel-2)", borderRadius: 3, overflow: "hidden" }}>
                <div style={{ height: "100%", background: "linear-gradient(90deg, var(--cyan), #7fe8de)", width: `${(count / maxTactic) * 100}%` }} />
              </div>
              <div className="mono" style={{ fontSize: 11, color: "var(--text-muted)", width: 18, textAlign: "right" }}>{count}</div>
            </div>
          ))}
        </section>
      </div>
    </div>
  );
}

function Waveform() {
  return (
    <div style={{ width: 260, height: 76, flexShrink: 0 }} aria-hidden="true">
      <style>{`
        .diq-wave-path {
          fill: none; stroke: var(--cyan); stroke-width: 2; stroke-linecap: round; stroke-linejoin: round;
          stroke-dasharray: 340; stroke-dashoffset: 340; animation: diq-draw 3.4s ease-in-out infinite;
          filter: drop-shadow(0 0 6px rgba(79,209,197,0.5));
        }
        .diq-threshold { stroke: var(--amber); stroke-width: 1; stroke-dasharray: 3 4; opacity: 0.7; }
        .diq-pulse { fill: var(--amber); animation: diq-pulse 3.4s ease-in-out infinite; filter: drop-shadow(0 0 5px rgba(242,169,59,0.7)); }
        @keyframes diq-draw { 0% { stroke-dashoffset: 340; } 60% { stroke-dashoffset: 0; } 100% { stroke-dashoffset: -340; } }
        @keyframes diq-pulse {
          0%, 55% { opacity: 0; transform: scale(0.6); transform-origin: 150px 22px; }
          62% { opacity: 1; transform: scale(1.5); transform-origin: 150px 22px; }
          75%, 100% { opacity: 0; transform: scale(0.6); transform-origin: 150px 22px; }
        }
        @media (prefers-reduced-motion: reduce) { .diq-wave-path, .diq-pulse { animation: none; stroke-dashoffset: 0; opacity: 0.9; } }
      `}</style>
      <svg viewBox="0 0 220 64" width="100%" height="100%">
        <line x1="0" y1="22" x2="220" y2="22" className="diq-threshold" />
        <path className="diq-wave-path" d="M0,40 C15,40 20,44 30,44 C40,44 45,20 55,20 C65,20 68,48 78,48 C88,48 92,10 105,10 C118,10 122,50 135,50 C148,50 150,22 165,22 C180,22 185,30 200,30 C210,30 215,26 220,26" />
        <circle cx="150" cy="22" r="4" className="diq-pulse" />
      </svg>
    </div>
  );
}
