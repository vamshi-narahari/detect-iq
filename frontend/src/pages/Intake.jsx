import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { supabase } from "../lib/supabase";

const STATUSES = ["open", "building", "review", "done"];

export default function Intake() {
  const navigate = useNavigate();
  const [requests, setRequests] = useState([]);
  const [filter, setFilter] = useState("open");
  const [sourceFilter, setSourceFilter] = useState("all");
  const [form, setForm] = useState({ title: "", notes: "", priority: "high", technique_id: "" });

  async function load() {
    const { data } = await supabase.from("intake_requests").select("*").order("created_at", { ascending: false });
    setRequests(data || []);
  }
  useEffect(() => { load(); }, []);

  const counts = {
    open: requests.filter((r) => r.status === "open").length,
    building: requests.filter((r) => r.status === "building").length,
    review: requests.filter((r) => r.status === "review").length,
    noDetection: requests.filter((r) => !r.detection_id).length,
  };

  const visible = requests.filter(
    (r) => (filter === "all" || r.status === filter) && (sourceFilter === "all" || r.source === sourceFilter)
  );

  async function createRequest() {
    if (!form.title) return;
    const { data: userData } = await supabase.auth.getUser();
    await supabase.from("intake_requests").insert({ ...form, user_id: userData.user.id, source: "manual" });
    setForm({ title: "", notes: "", priority: "high", technique_id: "" });
    load();
  }

  async function buildDetection(request) {
    await supabase.from("intake_requests").update({ status: "building" }).eq("id", request.id);
    navigate(`/builder?ask=${encodeURIComponent(request.title)}`);
  }

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 20 }}>
        <div>
          <h1 style={{ fontSize: 20, margin: "0 0 4px 0" }}>Intake</h1>
          <p style={{ color: "var(--text-muted)", fontSize: 13, margin: 0, maxWidth: "70ch" }}>
            New detection requests — no rule exists yet. Pull from Jira or Outlook, open a ticket manually, or start from a Leads gap.
          </p>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <span className="badge" data-tone="cyan" title="Point a Jira/Outlook/Teams/Webex automation at POST /api/webhook/intake/:provider">
            webhook intake available
          </span>
        </div>
      </div>

      <div className="panel" style={{ padding: "10px 14px", marginBottom: 16, fontSize: 12, color: "var(--text-muted)" }}>
        Auto-create tickets from Jira, Outlook, Teams, or Webex by pointing an automation/flow at
        <code style={{ margin: "0 4px" }}>POST /api/webhook/intake/:provider</code>
        with header <code>x-webhook-secret</code>. See <code>backend/.env.example</code> for setup.
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginBottom: 20 }}>
        <div className="panel" style={{ padding: 14 }}>
          <div className="mono" style={{ fontSize: 10.5, color: "var(--text-muted)", marginBottom: 8 }}>OPEN</div>
          <div className="mono" style={{ fontSize: 24 }}>{counts.open}</div>
        </div>
        <div className="panel" style={{ padding: 14 }}>
          <div className="mono" style={{ fontSize: 10.5, color: "var(--text-muted)", marginBottom: 8 }}>BUILDING</div>
          <div className="mono" style={{ fontSize: 24 }}>{counts.building}</div>
        </div>
        <div className="panel" style={{ padding: 14 }}>
          <div className="mono" style={{ fontSize: 10.5, color: "var(--text-muted)", marginBottom: 8 }}>IN REVIEW</div>
          <div className="mono" style={{ fontSize: 24 }}>{counts.review}</div>
        </div>
        <div className="panel" style={{ padding: 14 }}>
          <div className="mono" style={{ fontSize: 10.5, color: "var(--text-muted)", marginBottom: 8 }}>NO DETECTION YET</div>
          <div className="mono" style={{ fontSize: 24 }}>{counts.noDetection}</div>
        </div>
      </div>

      <div className="panel" style={{ padding: 16, marginBottom: 16 }}>
        <div className="mono" style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 10, textTransform: "uppercase" }}>New request</div>
        <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr", gap: 8, marginBottom: 8 }}>
          <input className="input" placeholder="What should we detect?" value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} />
          <select className="input" value={form.priority} onChange={(e) => setForm({ ...form, priority: e.target.value })}>
            {["low", "medium", "high", "critical"].map((p) => <option key={p} value={p}>{p}</option>)}
          </select>
          <input className="input" placeholder="MITRE (optional)" value={form.technique_id} onChange={(e) => setForm({ ...form, technique_id: e.target.value })} />
        </div>
        <textarea className="input" rows={2} placeholder="Notes from IR or Hunt" value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} style={{ marginBottom: 8 }} />
        <button className="btn btn-primary" onClick={createRequest} disabled={!form.title}>Open ticket</button>
      </div>

      <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
        {["open", "building", "review", "done", "all"].map((f) => (
          <button key={f} className="btn" style={filter === f ? { borderColor: "var(--cyan)", color: "var(--cyan)" } : {}} onClick={() => setFilter(f)}>{f}</button>
        ))}
        <span style={{ width: 1, background: "var(--border)" }} />
        {["all", "manual", "jira", "outlook", "teams", "webex", "gap", "builder"].map((s) => (
          <button key={s} className="btn" style={sourceFilter === s ? { borderColor: "var(--amber)", color: "var(--amber)" } : {}} onClick={() => setSourceFilter(s)}>{s}</button>
        ))}
      </div>

      <div className="panel">
        <div className="panel-head" style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr 1fr 100px", gap: 12 }}>
          <span>Ticket</span><span>Priority</span><span>Source</span><span>Status</span><span></span>
        </div>
        {visible.length === 0 && (
          <div style={{ padding: 24, textAlign: "center", color: "var(--text-muted)", fontSize: 13 }}>
            No tickets in this filter. Open one above, or file a gap from Leads.
          </div>
        )}
        {visible.map((r) => (
          <div key={r.id} style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr 1fr 100px", gap: 12, padding: "12px 16px", borderBottom: "1px solid var(--border)", fontSize: 13, alignItems: "center" }}>
            <span>{r.title}</span>
            <span className="badge" data-tone={r.priority === "critical" || r.priority === "high" ? "red" : "amber"}>{r.priority}</span>
            <span style={{ color: "var(--text-muted)" }}>{r.source}</span>
            <span className="badge" data-tone={r.status === "done" ? "cyan" : undefined}>{r.status}</span>
            {!r.detection_id && <button className="btn" onClick={() => buildDetection(r)} style={{ fontSize: 12 }}>Build</button>}
          </div>
        ))}
      </div>
    </div>
  );
}
