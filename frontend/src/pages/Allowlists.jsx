import { useEffect, useState } from "react";
import { supabase } from "../lib/supabase";

const DESTINATIONS = ["all", "splunk", "crowdstrike", "logscale", "sentinel", "databricks"];
const OPS = ["equals", "contains", "cidr"];

export default function Allowlists() {
  const [rules, setRules] = useState([]);
  const [detections, setDetections] = useState([]);
  const [form, setForm] = useState({ scope: "global", detection_id: "", field: "", op: "equals", value: "", reason: "", destination: "all" });

  async function load() {
    const { data: r } = await supabase.from("suppression_rules").select("*, detections(name)").order("created_at", { ascending: false });
    const { data: d } = await supabase.from("detections").select("id,name");
    setRules(r || []);
    setDetections(d || []);
  }
  useEffect(() => { load(); }, []);

  async function addRule() {
    if (!form.field || !form.value) return;
    const { data: userData } = await supabase.auth.getUser();
    const payload = {
      user_id: userData.user.id,
      scope: form.scope,
      detection_id: form.scope === "detection" ? form.detection_id || null : null,
      field: form.field,
      op: form.op,
      value: form.value,
      reason: form.reason,
      destination: form.destination,
    };
    await supabase.from("suppression_rules").insert(payload);
    setForm({ scope: "global", detection_id: "", field: "", op: "equals", value: "", reason: "", destination: "all" });
    load();
  }

  async function remove(id) {
    await supabase.from("suppression_rules").delete().eq("id", id);
    load();
  }

  return (
    <div>
      <h1 style={{ fontSize: 20, margin: "0 0 4px 0" }}>Allowlists</h1>
      <p style={{ color: "var(--text-muted)", fontSize: 13, margin: "0 0 20px 0", maxWidth: "75ch" }}>
        Global entries apply to every detection. Detection-scoped entries compile into that rule only.
        Destination scopes a row to one SIEM or all. Expired rows stop applying.
      </p>

      <div className="panel" style={{ padding: 16, marginBottom: 20 }}>
        <div className="mono" style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 10, textTransform: "uppercase" }}>Add exception</div>
        <div style={{ display: "grid", gridTemplateColumns: form.scope === "detection" ? "1fr 1.4fr 1fr 1fr 1.2fr" : "1fr 1fr 1fr 1.2fr", gap: 8, marginBottom: 8 }}>
          <select className="input" value={form.scope} onChange={(e) => setForm({ ...form, scope: e.target.value })}>
            <option value="global">global</option>
            <option value="detection">detection</option>
          </select>
          {form.scope === "detection" && (
            <select className="input" value={form.detection_id} onChange={(e) => setForm({ ...form, detection_id: e.target.value })}>
              <option value="">Select detection…</option>
              {detections.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
            </select>
          )}
          <input className="input" placeholder="field (e.g. user)" value={form.field} onChange={(e) => setForm({ ...form, field: e.target.value })} />
          <select className="input" value={form.op} onChange={(e) => setForm({ ...form, op: e.target.value })}>
            {OPS.map((o) => <option key={o} value={o}>{o}</option>)}
          </select>
          <input className="input" placeholder="value" value={form.value} onChange={(e) => setForm({ ...form, value: e.target.value })} />
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr auto", gap: 8 }}>
          <input className="input" placeholder="Reason (required)" value={form.reason} onChange={(e) => setForm({ ...form, reason: e.target.value })} />
          <select className="input" value={form.destination} onChange={(e) => setForm({ ...form, destination: e.target.value })}>
            {DESTINATIONS.map((d) => <option key={d} value={d}>{d === "all" ? "all destinations" : d}</option>)}
          </select>
          <button className="btn btn-primary" onClick={addRule}>Add allowlist</button>
        </div>
      </div>

      <div className="panel">
        <div className="panel-head" style={{ display: "grid", gridTemplateColumns: "0.8fr 1.4fr 0.8fr 0.8fr 0.6fr 0.8fr 1.4fr 80px", gap: 10 }}>
          <span>Scope</span><span>Detection</span><span>Destination</span><span>Field</span><span>Op</span><span>Value</span><span>Reason</span><span></span>
        </div>
        {rules.length === 0 && <div style={{ padding: 24, textAlign: "center", color: "var(--text-muted)", fontSize: 13 }}>No allowlist rules yet.</div>}
        {rules.map((r) => (
          <div key={r.id} style={{ display: "grid", gridTemplateColumns: "0.8fr 1.4fr 0.8fr 0.8fr 0.6fr 0.8fr 1.4fr 80px", gap: 10, padding: "10px 16px", borderBottom: "1px solid var(--border)", fontSize: 12.5, alignItems: "center" }}>
            <span className="badge">{r.scope}</span>
            <span style={{ color: "var(--text-muted)" }}>{r.detections?.name || "—"}</span>
            <span>{r.destination}</span>
            <span className="mono">{r.field}</span>
            <span style={{ color: "var(--text-muted)" }}>{r.op}</span>
            <span className="mono">{r.value}</span>
            <span style={{ color: "var(--text-muted)" }}>{r.reason || "—"}</span>
            <button className="btn" onClick={() => remove(r.id)} style={{ fontSize: 11, padding: "4px 8px" }}>Remove</button>
          </div>
        ))}
      </div>
    </div>
  );
}
