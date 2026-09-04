import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Sparkles, PenLine } from "lucide-react";
import { supabase } from "../lib/supabase";
import { generateDetection } from "../lib/api";

const SIEMS = ["splunk", "crowdstrike", "logscale", "sentinel", "qradar", "chronicle", "tanium", "panther", "sumologic", "elastic"];

export default function Builder() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [mode, setMode] = useState(null); // null | 'ai' | 'manual'
  const [technique, setTechnique] = useState("");
  const [siem, setSiem] = useState("splunk");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const ask = params.get("ask");
    if (ask) {
      setTechnique(ask);
      setMode("ai");
    }
  }, [params]);

  async function createManual() {
    const { data: userData } = await supabase.auth.getUser();
    const { data } = await supabase
      .from("detections")
      .insert({ user_id: userData.user.id, name: "Untitled detection", query: "", tool: "splunk", status: "draft", source: "manual" })
      .select()
      .single();
    if (data) navigate(`/editor?id=${data.id}`);
  }

  async function createWithAi() {
    setBusy(true);
    setError("");
    try {
      const result = await generateDetection(technique, siem);
      const { data: userData } = await supabase.auth.getUser();
      const { data } = await supabase
        .from("detections")
        .insert({
          user_id: userData.user.id,
          name: result.name,
          query: result.query,
          tool: siem,
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
    <div style={{ maxWidth: 900 }}>
      <h1 style={{ fontSize: 20, margin: "0 0 4px 0" }}>Detection Builder</h1>
      <p style={{ color: "var(--text-muted)", fontSize: 13, margin: "0 0 20px 0", maxWidth: "70ch" }}>
        AI or manual — both compile into the same detection record, editable afterward in the Editor.
      </p>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 20 }}>
        <div
          className="panel"
          style={{ padding: 20, cursor: "pointer", borderColor: mode === "ai" ? "var(--cyan)" : undefined }}
          onClick={() => setMode("ai")}
        >
          <Sparkles size={18} color="var(--cyan)" style={{ marginBottom: 10 }} />
          <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 6 }}>AI assist</div>
          <div style={{ fontSize: 12.5, color: "var(--text-muted)" }}>
            Describe the technique or behavior — drafts query, MITRE tagging, severity, and tuning notes.
          </div>
        </div>
        <div
          className="panel"
          style={{ padding: 20, cursor: "pointer", borderColor: mode === "manual" ? "var(--cyan)" : undefined }}
          onClick={() => setMode("manual")}
        >
          <PenLine size={18} color="var(--amber)" style={{ marginBottom: 10 }} />
          <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 6 }}>Manual</div>
          <div style={{ fontSize: 12.5, color: "var(--text-muted)" }}>
            Fill in every field yourself — name, query, MITRE tagging, severity, notes.
          </div>
        </div>
      </div>

      {mode === "ai" && (
        <div className="panel" style={{ padding: 20 }}>
          <div style={{ display: "grid", gap: 12 }}>
            <textarea
              className="input"
              rows={4}
              placeholder="e.g. password spraying against O365 from a single external IP"
              value={technique}
              onChange={(e) => setTechnique(e.target.value)}
            />
            <select className="input" value={siem} onChange={(e) => setSiem(e.target.value)}>
              {SIEMS.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
            {error && <div style={{ color: "var(--red)", fontSize: 12.5 }}>{error}</div>}
            <button className="btn btn-primary" onClick={createWithAi} disabled={busy || !technique} style={{ justifySelf: "start" }}>
              {busy ? "Generating…" : "Generate detection"}
            </button>
          </div>
        </div>
      )}

      {mode === "manual" && (
        <div className="panel" style={{ padding: 20 }}>
          <p style={{ color: "var(--text-muted)", fontSize: 13, marginBottom: 16 }}>
            Creates a blank detection and opens it in the Editor.
          </p>
          <button className="btn btn-primary" onClick={createManual}>Create blank detection</button>
        </div>
      )}
    </div>
  );
}
