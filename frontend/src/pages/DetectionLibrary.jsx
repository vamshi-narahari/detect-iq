import { useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { X, Plus } from "lucide-react";
import { supabase } from "../lib/supabase";

const SIEMS = ["all", "splunk", "crowdstrike", "logscale", "sentinel", "qradar", "chronicle", "tanium", "panther", "sumologic", "elastic"];

export default function DetectionLibrary() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const tacticFilter = params.get("tactic") || "";
  const [detections, setDetections] = useState([]);
  const [filter, setFilter] = useState("all");
  const [query, setQuery] = useState("");

  useEffect(() => {
    supabase.from("detections").select("*").order("created_at", { ascending: false }).then(({ data }) => setDetections(data || []));
  }, []);

  const visible = detections.filter(
    (d) =>
      (filter === "all" || d.tool === filter) &&
      d.name.toLowerCase().includes(query.toLowerCase()) &&
      (!tacticFilter || d.tactic === tacticFilter)
  );

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 20 }}>
        <div>
          <h1 style={{ fontSize: 20, margin: "0 0 4px 0" }}>Detection Library</h1>
          <p style={{ color: "var(--text-muted)", fontSize: 13, margin: 0, maxWidth: "70ch" }}>
            Browse and inspect every detection — click through to the Editor for logic, schedule,
            validation, tuning, and enrichment.
          </p>
        </div>
        <Link to="/builder" className="btn btn-primary" style={{ textDecoration: "none", whiteSpace: "nowrap" }}>
          <Plus size={14} style={{ marginRight: 6, verticalAlign: -2 }} />
          New detection
        </Link>
      </div>

      <div style={{ display: "flex", gap: 12, marginBottom: 16, alignItems: "center" }}>
        <input className="input" placeholder="Filter by name..." value={query} onChange={(e) => setQuery(e.target.value)} style={{ maxWidth: 280 }} />
        <select className="input" value={filter} onChange={(e) => setFilter(e.target.value)} style={{ maxWidth: 180 }}>
          {SIEMS.map((s) => <option key={s} value={s}>{s === "all" ? "All SIEMs" : s}</option>)}
        </select>
        {tacticFilter && (
          <button className="badge" data-tone="cyan" style={{ cursor: "pointer", border: "1px solid rgba(79,209,197,0.4)" }} onClick={() => setParams({})}>
            {tacticFilter} <X size={11} style={{ marginLeft: 4, verticalAlign: -1 }} />
          </button>
        )}
      </div>

      <div className="panel">
        <div className="panel-head" style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr 1fr 1fr 80px", gap: 12 }}>
          <span>Name</span><span>SIEM</span><span>Tactic</span><span>Severity</span><span>Validation</span><span>Status</span>
        </div>
        {visible.length === 0 && (
          <div style={{ padding: 24, textAlign: "center", color: "var(--text-muted)", fontSize: 13 }}>
            Nothing here yet. Use the Builder to create one manually or with AI assist.
          </div>
        )}
        {visible.map((d) => (
          <div
            key={d.id}
            onClick={() => navigate(`/editor?id=${d.id}`)}
            className="hoverable"
            style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr 1fr 1fr 80px", gap: 12, padding: "12px 16px", borderBottom: "1px solid var(--border)", fontSize: 13, cursor: "pointer", alignItems: "center" }}
          >
            <span>{d.name}</span>
            <span className="mono" style={{ color: "var(--text-muted)" }}>{d.tool}</span>
            <span style={{ color: "var(--text-muted)" }}>{d.tactic || "—"}</span>
            <span className="badge" data-tone={d.severity === "critical" || d.severity === "high" ? "red" : "amber"}>{d.severity || "—"}</span>
            <span className="badge" data-tone={d.validation_status && d.validation_status !== "unvalidated" ? "cyan" : undefined}>
              {d.validation_status === "unvalidated" || !d.validation_status ? "unvalidated" : d.validation_status.replace("_", " ")}
            </span>
            <span className="badge" data-tone={d.status === "active" ? "cyan" : undefined}>{d.status}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
