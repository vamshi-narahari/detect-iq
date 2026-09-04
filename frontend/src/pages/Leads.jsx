import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { supabase } from "../lib/supabase";
import { generateDetection } from "../lib/api";

const TELEMETRY_SOURCES = [
  { name: "Windows Security", index: 'index=windows sourcetype="WinEventLog:Security"', keyword: "index=windows" },
  { name: "Okta", index: 'index=okta sourcetype="OktaIM2:log"', keyword: "index=okta" },
  { name: "Microsoft 365", index: 'index=o365 sourcetype="o365:management:activity"', keyword: "index=o365" },
  { name: "Entra / Azure AD", index: 'index=azure sourcetype="azure:auditlogs"', keyword: "index=azure" },
  { name: "AWS CloudTrail", index: "index=aws sourcetype=aws:cloudtrail", keyword: "index=aws" },
  { name: "Zscaler / Proxy", index: 'index=proxy sourcetype="zscalernss-web"', keyword: "index=proxy" },
  { name: "DNS", index: 'index=dns sourcetype="infoblox:dns"', keyword: "index=dns" },
];

export default function Leads() {
  const navigate = useNavigate();
  const [tab, setTab] = useState("telemetry");
  const [question, setQuestion] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [detections, setDetections] = useState([]);
  const [packs, setPacks] = useState([]);

  useEffect(() => {
    supabase.from("detections").select("tool,technique_id,query").then(({ data }) => setDetections(data || []));
    supabase.from("packs").select("*").then(({ data }) => setPacks(data || []));
  }, []);

  const coveredTechniques = new Set(detections.map((d) => d.technique_id).filter(Boolean));
  const gapTechniques = [...new Set(packs.flatMap((p) => p.techniques || []))].filter((t) => !coveredTechniques.has(t));

  function sourceIsCovered(keyword) {
    return detections.some((d) => (d.query || "").toLowerCase().includes(keyword));
  }

  async function openInBuilder() {
    if (!question) return;
    setBusy(true);
    setError("");
    try {
      const result = await generateDetection(question, "splunk");
      const { data: userData } = await supabase.auth.getUser();
      const { data } = await supabase
        .from("detections")
        .insert({
          user_id: userData.user.id,
          name: result.name,
          query: result.query,
          tool: "splunk",
          tactic: result.tactic,
          technique_id: result.technique_id,
          severity: result.severity,
          description: [result.summary, result.tuning_notes].filter(Boolean).join("\n\n"),
          status: "draft",
          source: "ai",
        })
        .select()
        .single();
      if (data) navigate(`/editor?id=${data.id}`);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <h1 style={{ fontSize: 20, margin: "0 0 4px 0" }}>Leads</h1>
      <p style={{ color: "var(--text-muted)", fontSize: 13, margin: "0 0 20px 0", maxWidth: "70ch" }}>
        Hunt and IR start from a question, the telemetry you already have, or a coverage gap.
      </p>

      <div className="panel" style={{ padding: 16, marginBottom: 20 }}>
        <div className="mono" style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 8, textTransform: "uppercase" }}>
          Ask a hunt question
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <input
            className="input"
            placeholder="Who is launching encoded PowerShell from Word on our Windows endpoints this week?"
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
          />
          <button className="btn btn-primary" onClick={openInBuilder} disabled={busy || !question} style={{ whiteSpace: "nowrap" }}>
            {busy ? "Working…" : "Open in builder"}
          </button>
        </div>
        {error && <div style={{ color: "var(--red)", fontSize: 12.5, marginTop: 8 }}>{error}</div>}
      </div>

      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        <button className="btn" style={tab === "telemetry" ? { borderColor: "var(--cyan)", color: "var(--cyan)" } : {}} onClick={() => setTab("telemetry")}>
          Your telemetry · {TELEMETRY_SOURCES.length}
        </button>
        <button className="btn" style={tab === "gaps" ? { borderColor: "var(--cyan)", color: "var(--cyan)" } : {}} onClick={() => setTab("gaps")}>
          Coverage gaps · {gapTechniques.length}
        </button>
      </div>

      {tab === "telemetry" && (
        <div className="panel">
          <div className="panel-head" style={{ display: "grid", gridTemplateColumns: "1fr 2fr 1fr", gap: 12 }}>
            <span>Source</span><span>Index / sourcetype</span><span>Coverage</span>
          </div>
          {TELEMETRY_SOURCES.map((s) => (
            <div key={s.name} style={{ display: "grid", gridTemplateColumns: "1fr 2fr 1fr", gap: 12, padding: "10px 16px", borderBottom: "1px solid var(--border)", fontSize: 13, alignItems: "center" }}>
              <span>{s.name}</span>
              <span className="mono" style={{ fontSize: 12, color: "var(--text-muted)" }}>{s.index}</span>
              <span className="badge" data-tone={sourceIsCovered(s.keyword) ? "cyan" : undefined}>
                {sourceIsCovered(s.keyword) ? "in library" : "not in library"}
              </span>
            </div>
          ))}
        </div>
      )}

      {tab === "gaps" && (
        <div className="panel">
          {gapTechniques.length === 0 && (
            <div style={{ padding: 16, fontSize: 13, color: "var(--text-muted)" }}>
              No gaps — every technique in your Packs has at least one detection. Add packs to track more.
            </div>
          )}
          {gapTechniques.map((t) => (
            <div key={t} style={{ display: "flex", alignItems: "center", gap: 12, padding: "10px 16px", borderBottom: "1px solid var(--border)", fontSize: 13 }}>
              <span className="mono">{t}</span>
              <span style={{ flex: 1, color: "var(--text-muted)" }}>No detection covers this technique yet</span>
              <button
                className="btn"
                onClick={() => { setQuestion(`Detect ${t}`); setTab("telemetry"); }}
              >
                Draft with AI
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
