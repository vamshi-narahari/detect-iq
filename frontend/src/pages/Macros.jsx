import { useEffect, useState } from "react";
import { supabase } from "../lib/supabase";

const KINDS = ["allowlist", "enrich", "emit", "parse", "normalize"];

export default function Macros() {
  const [macros, setMacros] = useState([]);
  const [form, setForm] = useState({ name: "", kind: "allowlist", description: "", query_body: "" });

  async function load() {
    const { data } = await supabase.from("macros").select("*").order("is_system", { ascending: false }).order("name");
    setMacros(data || []);
  }
  useEffect(() => { load(); }, []);

  async function save() {
    if (!form.name) return;
    const { data: userData } = await supabase.auth.getUser();
    await supabase.from("macros").insert({ ...form, user_id: userData.user.id, is_system: false });
    setForm({ name: "", kind: "allowlist", description: "", query_body: "" });
    load();
  }

  return (
    <div>
      <h1 style={{ fontSize: 20, margin: "0 0 4px 0" }}>Macros</h1>
      <p style={{ color: "var(--text-muted)", fontSize: 13, margin: "0 0 20px 0", maxWidth: "70ch" }}>
        Shared parse / normalize / allowlist / enrich / emit building blocks. System macros ship with
        DetectIQ; yours are editable.
      </p>

      <div className="panel" style={{ padding: 16, marginBottom: 20 }}>
        <div className="mono" style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 10, textTransform: "uppercase" }}>New custom macro</div>
        <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 10, marginBottom: 10 }}>
          <input className="input" placeholder="detectiq_allow_jump_hosts" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          <select className="input" value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })}>
            {KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
          </select>
        </div>
        <input className="input" placeholder="Description" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} style={{ marginBottom: 10 }} />
        <textarea className="input" rows={3} placeholder="Query body" value={form.query_body} onChange={(e) => setForm({ ...form, query_body: e.target.value })} style={{ marginBottom: 10, fontFamily: "var(--mono)", fontSize: 12.5 }} />
        <button className="btn btn-primary" onClick={save} disabled={!form.name}>Save macro</button>
      </div>

      <div className="panel">
        <div className="panel-head" style={{ display: "grid", gridTemplateColumns: "0.8fr 1.4fr 2fr 0.6fr", gap: 12 }}>
          <span>Kind</span><span>Name</span><span>Description</span><span></span>
        </div>
        {macros.map((m) => (
          <div key={m.id} style={{ display: "grid", gridTemplateColumns: "0.8fr 1.4fr 2fr 0.6fr", gap: 12, padding: "10px 16px", borderBottom: "1px solid var(--border)", fontSize: 13, alignItems: "center" }}>
            <span className="badge">{m.kind}</span>
            <span className="mono">{m.name}</span>
            <span style={{ color: "var(--text-muted)" }}>{m.description}</span>
            <span style={{ fontSize: 11, color: "var(--text-muted)" }}>{m.is_system ? "system" : "custom"}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
