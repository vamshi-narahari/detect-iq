import { useEffect, useState } from "react";
import { Plus } from "lucide-react";
import { supabase } from "../lib/supabase";

export default function Packs() {
  const [packs, setPacks] = useState([]);
  const [detections, setDetections] = useState([]);
  const [showNew, setShowNew] = useState(false);
  const [form, setForm] = useState({ name: "", description: "", techniques: "" });
  const [expanded, setExpanded] = useState(null);

  async function load() {
    const { data: p } = await supabase.from("packs").select("*").order("created_at", { ascending: false });
    const { data: d } = await supabase.from("detections").select("technique_id");
    setPacks(p || []);
    setDetections(d || []);
  }
  useEffect(() => { load(); }, []);

  const coveredTechniques = new Set(detections.map((d) => d.technique_id).filter(Boolean));

  function coverage(pack) {
    const techniques = pack.techniques || [];
    const covered = techniques.filter((t) => coveredTechniques.has(t)).length;
    return { covered, total: techniques.length, pct: techniques.length ? Math.round((covered / techniques.length) * 100) : 0 };
  }

  async function createPack() {
    const { data: userData } = await supabase.auth.getUser();
    const techniques = form.techniques.split(",").map((t) => t.trim()).filter(Boolean);
    const { data } = await supabase
      .from("packs")
      .insert({ user_id: userData.user.id, name: form.name, description: form.description, techniques })
      .select()
      .single();
    setShowNew(false);
    setForm({ name: "", description: "", techniques: "" });
    await load();
    if (data) setExpanded(data.id);
  }

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 20 }}>
        <div>
          <h1 style={{ fontSize: 20, margin: "0 0 4px 0" }}>Packs</h1>
          <p style={{ color: "var(--text-muted)", fontSize: 13, margin: 0, maxWidth: "70ch" }}>
            Packs of ATT&CK techniques you want correlated coverage on. A pack doesn't run itself —
            draft a detection from a gap, then it counts toward this pack's coverage.
          </p>
        </div>
        <button className="btn btn-primary" onClick={() => setShowNew(true)}><Plus size={14} /> New pack</button>
      </div>

      {showNew && (
        <div className="panel" style={{ padding: 16, marginBottom: 16, display: "grid", gap: 10 }}>
          <input className="input" placeholder="Pack name (e.g. Credential Access)" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          <input className="input" placeholder="Description" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
          <input className="input" placeholder="Technique IDs, comma separated (e.g. T1110, T1110.003, T1558)" value={form.techniques} onChange={(e) => setForm({ ...form, techniques: e.target.value })} />
          <div style={{ display: "flex", gap: 8 }}>
            <button className="btn btn-primary" onClick={createPack} disabled={!form.name}>Create pack</button>
            <button className="btn" onClick={() => setShowNew(false)}>Cancel</button>
          </div>
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12 }}>
        {packs.map((pack) => {
          const c = coverage(pack);
          return (
            <div className="panel" key={pack.id} style={{ padding: 16, cursor: "pointer" }} onClick={() => setExpanded(expanded === pack.id ? null : pack.id)}>
              <div style={{ fontSize: 14.5, fontWeight: 600, marginBottom: 4 }}>{pack.name}</div>
              <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 12, minHeight: 32 }}>{pack.description}</div>
              <div style={{ height: 5, background: "var(--panel-2)", borderRadius: 3, overflow: "hidden", marginBottom: 8 }}>
                <div style={{ height: "100%", background: c.pct === 100 ? "var(--cyan)" : "var(--amber)", width: `${c.pct}%` }} />
              </div>
              <div className="mono" style={{ fontSize: 11.5, color: "var(--text-muted)" }}>
                {c.covered}/{c.total} techniques · {c.pct}%
              </div>
            </div>
          );
        })}
      </div>

      {packs.length === 0 && !showNew && (
        <div className="panel" style={{ padding: 24, textAlign: "center", color: "var(--text-muted)", fontSize: 13 }}>
          No packs yet. Create one to start tracking coverage across a group of techniques.
        </div>
      )}

      {expanded && (
        <div className="panel" style={{ marginTop: 16 }}>
          <div className="panel-head">Techniques</div>
          {(packs.find((p) => p.id === expanded)?.techniques || []).map((t) => (
            <div key={t} style={{ display: "flex", gap: 12, padding: "10px 16px", borderBottom: "1px solid var(--border)", fontSize: 13 }}>
              <span className="mono">{t}</span>
              <span className="badge" data-tone={coveredTechniques.has(t) ? "cyan" : "amber"} style={{ marginLeft: "auto" }}>
                {coveredTechniques.has(t) ? "covered" : "gap"}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
