import { useEffect, useState } from "react";
import { supabase } from "../lib/supabase";

const TYPES = ["host", "service_account", "cloud_resource", "other"];
const CRITICALITY = ["low", "medium", "high", "critical"];

export default function Assets() {
  const [assets, setAssets] = useState([]);
  const [form, setForm] = useState({ name: "", type: "host", owner: "", criticality: "medium", tags: "", notes: "" });

  async function load() {
    const { data } = await supabase.from("assets").select("*").order("created_at", { ascending: false });
    setAssets(data || []);
  }
  useEffect(() => { load(); }, []);

  async function save() {
    if (!form.name) return;
    const { data: userData } = await supabase.auth.getUser();
    const tags = form.tags.split(",").map((t) => t.trim()).filter(Boolean);
    await supabase.from("assets").insert({ ...form, tags, user_id: userData.user.id });
    setForm({ name: "", type: "host", owner: "", criticality: "medium", tags: "", notes: "" });
    load();
  }

  async function remove(id) {
    await supabase.from("assets").delete().eq("id", id);
    load();
  }

  return (
    <div>
      <h1 style={{ fontSize: 20, margin: "0 0 4px 0" }}>Assets</h1>
      <p style={{ color: "var(--text-muted)", fontSize: 13, margin: "0 0 20px 0", maxWidth: "70ch" }}>
        Your asset inventory — hosts, service accounts, cloud resources. This is what the
        <code style={{ margin: "0 4px" }}>detectiq_enrich_asset</code>
        macro and detection enrichment lookups reference, kept separate from Macros since it's data you
        maintain continuously, not detection logic.
      </p>

      <div className="panel" style={{ padding: 16, marginBottom: 20 }}>
        <div className="mono" style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 10, textTransform: "uppercase" }}>Add asset</div>
        <div style={{ display: "grid", gridTemplateColumns: "1.5fr 1fr 1fr 1fr", gap: 8, marginBottom: 8 }}>
          <input className="input" placeholder="Name (hostname, account, resource id)" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          <select className="input" value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value })}>
            {TYPES.map((t) => <option key={t} value={t}>{t.replace("_", " ")}</option>)}
          </select>
          <input className="input" placeholder="Owner" value={form.owner} onChange={(e) => setForm({ ...form, owner: e.target.value })} />
          <select className="input" value={form.criticality} onChange={(e) => setForm({ ...form, criticality: e.target.value })}>
            {CRITICALITY.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
        </div>
        <input className="input" placeholder="Tags, comma separated" value={form.tags} onChange={(e) => setForm({ ...form, tags: e.target.value })} style={{ marginBottom: 8 }} />
        <textarea className="input" rows={2} placeholder="Notes" value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} style={{ marginBottom: 8 }} />
        <button className="btn btn-primary" onClick={save} disabled={!form.name}>Add asset</button>
      </div>

      <div className="panel">
        <div className="panel-head" style={{ display: "grid", gridTemplateColumns: "1.5fr 1fr 1fr 1fr 1.5fr 60px", gap: 12 }}>
          <span>Name</span><span>Type</span><span>Owner</span><span>Criticality</span><span>Tags</span><span></span>
        </div>
        {assets.length === 0 && <div style={{ padding: 24, textAlign: "center", color: "var(--text-muted)", fontSize: 13 }}>No assets yet.</div>}
        {assets.map((a) => (
          <div key={a.id} style={{ display: "grid", gridTemplateColumns: "1.5fr 1fr 1fr 1fr 1.5fr 60px", gap: 12, padding: "10px 16px", borderBottom: "1px solid var(--border)", fontSize: 13, alignItems: "center" }}>
            <span>{a.name}</span>
            <span style={{ color: "var(--text-muted)" }}>{a.type.replace("_", " ")}</span>
            <span style={{ color: "var(--text-muted)" }}>{a.owner || "—"}</span>
            <span className="badge" data-tone={a.criticality === "critical" || a.criticality === "high" ? "red" : "amber"}>{a.criticality}</span>
            <span style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
              {(a.tags || []).map((t) => <span key={t} className="badge">{t}</span>)}
            </span>
            <button className="btn" onClick={() => remove(a.id)} style={{ fontSize: 11, padding: "4px 8px" }}>Remove</button>
          </div>
        ))}
      </div>
    </div>
  );
}
