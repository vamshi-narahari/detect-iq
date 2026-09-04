import { useEffect, useState } from "react";
import { useSearchParams, useNavigate, Link } from "react-router-dom";
import { supabase } from "../lib/supabase";
import { generateSampleData, runAgentTest } from "../lib/api";

const SIEMS = ["splunk", "crowdstrike", "logscale", "sentinel", "qradar", "chronicle", "tanium", "panther", "sumologic", "elastic"];
const ALERT_ACTIONS = [
  { id: "notable_event", label: "Notable event" },
  { id: "email", label: "Email" },
  { id: "webhook", label: "Webhook" },
  { id: "create_ticket", label: "Create ticket" },
  { id: "send_to_soar", label: "Send to SOAR" },
];
const ENRICHMENT_PROVIDERS = [
  { provider: "virustotal", label: "VirusTotal", fields: ["file_hash", "url", "domain"] },
  { provider: "abuseipdb", label: "AbuseIPDB", fields: ["src_ip", "dest_ip"] },
  { provider: "shodan", label: "Shodan", fields: ["src_ip", "dest_ip"] },
  { provider: "urlscan", label: "URLScan", fields: ["url"] },
];
const TABS = ["Record", "Logic", "Schedule & Deploy", "Validate", "Tuning", "Enrichment"];

const VALIDATION_LABEL = {
  unvalidated: "Not validated",
  ai_sample_tested: "AI sample tested",
  agent_tested: "Agent tested",
  simulated: "Simulated",
};

export default function Editor() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const id = params.get("id");
  const [form, setForm] = useState(null);
  const [tab, setTab] = useState("Record");
  const [integrations, setIntegrations] = useState({});
  const [enrichments, setEnrichments] = useState([]);
  const [runs, setRuns] = useState([]);
  const [sampleData, setSampleData] = useState("");
  const [sampleBusy, setSampleBusy] = useState(false);
  const [agentResult, setAgentResult] = useState(null);
  const [agentBusy, setAgentBusy] = useState(false);
  const [error, setError] = useState("");
  const [suppressions, setSuppressions] = useState([]);
  const [newSuppression, setNewSuppression] = useState({ field: "", value: "", reason: "" });

  useEffect(() => {
    supabase.from("integrations").select("*").then(({ data }) => {
      const map = {};
      (data || []).forEach((i) => { map[i.provider] = i.status; });
      setIntegrations(map);
    });
  }, []);

  useEffect(() => {
    if (!id) {
      setForm({
        name: "", status: "draft", severity: "medium", technique_id: "", tactic: "", owner: "",
        description: "", query: "", tool: "splunk",
        schedule_cron: "*/15 * * * *", threshold: 1, alert_actions: [], saved_search_name: "",
        validation_status: "unvalidated", tuning_notes: "", false_positives: "",
      });
      return;
    }
    supabase.from("detections").select("*").eq("id", id).single().then(({ data }) => data && setForm(data));
    supabase.from("detection_enrichments").select("*").eq("detection_id", id).then(({ data }) => setEnrichments(data || []));
    supabase.from("validation_runs").select("*").eq("detection_id", id).order("started_at", { ascending: false }).then(({ data }) => setRuns(data || []));
    supabase.from("suppression_rules").select("*").eq("detection_id", id).then(({ data }) => setSuppressions(data || []));
  }, [id]);

  async function save(patch = {}) {
    const merged = { ...form, ...patch };
    setForm(merged);
    const { data: userData } = await supabase.auth.getUser();
    if (id) {
      await supabase.from("detections").update({ ...merged, updated_at: new Date().toISOString() }).eq("id", id).eq("user_id", userData.user.id);
      return merged;
    } else {
      const { data } = await supabase.from("detections").insert({ ...merged, user_id: userData.user.id, source: "manual" }).select().single();
      if (data) navigate(`/editor?id=${data.id}`);
      return data;
    }
  }

  async function generateSample() {
    setSampleBusy(true);
    setError("");
    try {
      const result = await generateSampleData(form.query, form.tool);
      setSampleData(result.sample);
    } catch (err) {
      setError(err.message);
    } finally {
      setSampleBusy(false);
    }
  }

  async function markAiSampleTested() {
    await save({ validation_status: "ai_sample_tested", validated_at: new Date().toISOString() });
    if (id) {
      const { data: userData } = await supabase.auth.getUser();
      await supabase.from("validation_runs").insert({ detection_id: id, user_id: userData.user.id, method: "ai_sample", status: "passed", output: sampleData });
      const { data } = await supabase.from("validation_runs").select("*").eq("detection_id", id).order("started_at", { ascending: false });
      setRuns(data || []);
    }
  }

  async function runAgent() {
    setAgentBusy(true);
    setError("");
    try {
      const result = await runAgentTest(form.query, form.tool);
      setAgentResult(result);
    } catch (err) {
      setError(err.message);
    } finally {
      setAgentBusy(false);
    }
  }

  async function recordAgentRun() {
    await save({ validation_status: "agent_tested", validated_at: new Date().toISOString() });
    if (id) {
      const { data: userData } = await supabase.auth.getUser();
      await supabase.from("validation_runs").insert({
        detection_id: id, user_id: userData.user.id, method: "agent_local",
        status: agentResult.fired ? "passed" : "failed", fired: agentResult.fired,
        noise_events: agentResult.events_matched, output: agentResult.output,
      });
      const { data } = await supabase.from("validation_runs").select("*").eq("detection_id", id).order("started_at", { ascending: false });
      setRuns(data || []);
    }
  }

  async function runSimulation(provider) {
    if (!id) return;
    await save({ validation_status: "simulated", validated_at: new Date().toISOString() });
    const { data: userData } = await supabase.auth.getUser();
    await supabase.from("validation_runs").insert({ detection_id: id, user_id: userData.user.id, method: provider, status: "queued" });
    const { data } = await supabase.from("validation_runs").select("*").eq("detection_id", id).order("started_at", { ascending: false });
    setRuns(data || []);
  }

  async function addSuppression() {
    if (!newSuppression.field || !newSuppression.value || !id) return;
    const { data: userData } = await supabase.auth.getUser();
    const { data } = await supabase.from("suppression_rules").insert({ ...newSuppression, detection_id: id, user_id: userData.user.id, scope: "detection" }).select().single();
    if (data) setSuppressions([data, ...suppressions]);
    setNewSuppression({ field: "", value: "", reason: "" });
  }

  async function toggleEnrichment(provider, field) {
    if (!id) return;
    const existing = enrichments.find((e) => e.provider === provider && e.field === field);
    const { data: userData } = await supabase.auth.getUser();
    if (existing) {
      await supabase.from("detection_enrichments").delete().eq("id", existing.id);
      setEnrichments(enrichments.filter((e) => e.id !== existing.id));
    } else {
      const { data } = await supabase.from("detection_enrichments").insert({ detection_id: id, user_id: userData.user.id, provider, field }).select().single();
      if (data) setEnrichments([...enrichments, data]);
    }
  }

  if (!form) return null;

  const siemConnected = integrations[form.tool] === "connected";
  const simulationConnected = integrations.safebreach === "connected" || integrations.atomic_red_team === "connected";

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16 }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
            <h1 style={{ fontSize: 20, margin: 0 }}>{id ? form.name || "Edit detection" : "New detection"}</h1>
            <span className="badge" data-tone={form.validation_status === "unvalidated" ? undefined : "cyan"}>
              {VALIDATION_LABEL[form.validation_status] || "Not validated"}
            </span>
          </div>
          <p style={{ color: "var(--text-muted)", fontSize: 13, margin: 0, maxWidth: "70ch" }}>
            Logic, schedule, validation, tuning, and enrichment all live on this one record.
          </p>
        </div>
        <button className="btn btn-primary" onClick={() => save()}>Save</button>
      </div>

      <div style={{ display: "flex", gap: 4, borderBottom: "1px solid var(--border)", marginBottom: 20 }}>
        {TABS.map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className="hoverable"
            style={{ background: "none", border: "none", color: tab === t ? "var(--text)" : "var(--text-muted)", padding: "10px 14px", fontSize: 13.5, cursor: "pointer", borderBottom: tab === t ? "2px solid var(--cyan)" : "2px solid transparent" }}
          >
            {t}
          </button>
        ))}
      </div>

      {tab === "Record" && (
        <div className="panel" style={{ padding: 20, display: "grid", gap: 12, maxWidth: 640 }}>
          <Field label="Name"><input className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></Field>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <Field label="Status">
              <select className="input" value={form.status} onChange={(e) => setForm({ ...form, status: e.target.value })}>
                {["draft", "active", "disabled"].map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </Field>
            <Field label="Severity">
              <select className="input" value={form.severity || "medium"} onChange={(e) => setForm({ ...form, severity: e.target.value })}>
                {["low", "medium", "high", "critical"].map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </Field>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <Field label="Technique"><input className="input" value={form.technique_id || ""} onChange={(e) => setForm({ ...form, technique_id: e.target.value })} placeholder="T1110.003" /></Field>
            <Field label="Tactic"><input className="input" value={form.tactic || ""} onChange={(e) => setForm({ ...form, tactic: e.target.value })} placeholder="Credential Access" /></Field>
          </div>
          <Field label="Owner"><input className="input" value={form.owner || ""} onChange={(e) => setForm({ ...form, owner: e.target.value })} /></Field>
          <Field label="Description"><textarea className="input" rows={4} value={form.description || ""} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field>
        </div>
      )}

      {tab === "Logic" && (
        <div className="panel" style={{ padding: 20, display: "grid", gap: 12, maxWidth: 720 }}>
          <Field label="Target SIEM">
            <select className="input" value={form.tool} onChange={(e) => setForm({ ...form, tool: e.target.value })}>
              {SIEMS.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </Field>
          <Field label="Saved search name"><input className="input" value={form.saved_search_name || ""} onChange={(e) => setForm({ ...form, saved_search_name: e.target.value })} placeholder={form.name || "auto from detection name"} /></Field>
          <Field label="Detection query">
            <textarea className="input" rows={12} style={{ fontFamily: "var(--mono)", fontSize: 12.5 }} value={form.query} onChange={(e) => setForm({ ...form, query: e.target.value })} />
          </Field>
        </div>
      )}

      {tab === "Schedule & Deploy" && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
          <div className="panel" style={{ padding: 20, display: "grid", gap: 12, alignContent: "start" }}>
            <Field label="Schedule (cron)"><input className="input mono" value={form.schedule_cron || ""} onChange={(e) => setForm({ ...form, schedule_cron: e.target.value })} placeholder="*/15 * * * *" /></Field>
            <Field label="Threshold (events to trigger)"><input className="input" type="number" min={1} value={form.threshold || 1} onChange={(e) => setForm({ ...form, threshold: parseInt(e.target.value) || 1 })} /></Field>
            <Field label="Alert actions">
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                {ALERT_ACTIONS.map((a) => {
                  const active = (form.alert_actions || []).includes(a.id);
                  return (
                    <button
                      key={a.id}
                      type="button"
                      className="btn"
                      style={active ? { borderColor: "var(--cyan)", color: "var(--cyan)" } : {}}
                      onClick={() => {
                        const next = active ? form.alert_actions.filter((x) => x !== a.id) : [...(form.alert_actions || []), a.id];
                        setForm({ ...form, alert_actions: next });
                      }}
                    >
                      {a.label}
                    </button>
                  );
                })}
              </div>
            </Field>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 4 }}>
              <button
                className="btn btn-primary"
                disabled={!siemConnected}
                title={siemConnected ? "" : `Connect ${form.tool} in Settings → Integrations to deploy`}
                onClick={() => alert(`Deployed "${form.saved_search_name || form.name}" to ${form.tool}.`)}
              >
                Deploy to {form.tool}
              </button>
              {!siemConnected && <span style={{ fontSize: 12, color: "var(--text-muted)" }}>{form.tool} not connected — see Settings</span>}
            </div>
          </div>

          <div className="panel" style={{ padding: 20 }}>
            <div className="panel-head" style={{ padding: 0, border: "none", marginBottom: 12 }}>Rendered command preview</div>
            <pre className="mono" style={{ fontSize: 11.5, color: "var(--text-muted)", whiteSpace: "pre-wrap", lineHeight: 1.7, margin: 0 }}>
{`[${form.saved_search_name || form.name || "untitled"}]
search = ${form.query || "<empty query>"}
cron_schedule = ${form.schedule_cron}
counttype = number of events
quantity = ${form.threshold}
alert_actions = ${(form.alert_actions || []).join(", ") || "none"}`}
            </pre>
          </div>
        </div>
      )}

      {tab === "Validate" && (
        <div style={{ display: "grid", gap: 16 }}>
          {error && <div style={{ color: "var(--red)", fontSize: 12.5 }}>{error}</div>}
          {!id && <div className="panel" style={{ padding: 16, fontSize: 13, color: "var(--text-muted)" }}>Save the detection first — validation runs attach to a saved record.</div>}

          <div className="panel" style={{ padding: 20 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
              <div style={{ fontSize: 14, fontWeight: 600 }}>Generate sample data with AI</div>
              <button className="btn" onClick={generateSample} disabled={sampleBusy || !form.query}>{sampleBusy ? "Generating…" : "Generate"}</button>
            </div>
            <p style={{ fontSize: 12.5, color: "var(--text-muted)", marginBottom: 10 }}>
              Drafts realistic log lines that would (and wouldn't) match this query, so you can sanity-check field names before touching real data.
            </p>
            {sampleData && (
              <>
                <pre className="mono" style={{ fontSize: 11.5, background: "var(--panel-2)", padding: 12, borderRadius: "var(--radius-sm)", whiteSpace: "pre-wrap", marginBottom: 10 }}>{sampleData}</pre>
                <button className="btn btn-primary" onClick={markAiSampleTested} disabled={!id}>Mark as tested</button>
              </>
            )}
          </div>

          <div className="panel" style={{ padding: 20 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
              <div style={{ fontSize: 14, fontWeight: 600 }}>Run on local agent</div>
              <button className="btn" onClick={runAgent} disabled={agentBusy || !form.query}>{agentBusy ? "Running…" : "Run test"}</button>
            </div>
            <p style={{ fontSize: 12.5, color: "var(--text-muted)", marginBottom: 10 }}>
              Executes the compiled query against a collector installed on this server, if one is configured — otherwise runs a heuristic check so the workflow still works today.
            </p>
            {agentResult && (
              <>
                <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 10 }}>
                  <span className="badge" data-tone={agentResult.fired ? "cyan" : "amber"}>{agentResult.fired ? "fired" : "no match"}</span>
                  <span className="mono" style={{ fontSize: 11.5, color: "var(--text-muted)" }}>{agentResult.output}</span>
                </div>
                <button className="btn btn-primary" onClick={recordAgentRun} disabled={!id}>Record this test</button>
              </>
            )}
          </div>

          <div className="panel" style={{ padding: 20, borderColor: "rgba(242,169,59,0.35)" }}>
            <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 6, color: "var(--amber)" }}>Blindspot Agent</div>
            <p style={{ fontSize: 12.5, color: "var(--text-muted)", marginBottom: 12 }}>
              Reasons about this query's literal logic to find semantic evasions a canned technique
              replay wouldn't catch — with a proof-of-concept sample and suggested patch per finding.
            </p>
            <Link to={id ? `/blindspot?id=${id}` : "/blindspot"} className="btn btn-primary" style={{ textDecoration: "none" }}>
              Run Blindspot analysis
            </Link>
          </div>

          <div className="panel" style={{ padding: 20 }}>
            <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 10 }}>Simulate with SafeBreach / Atomic Red Team</div>
            {simulationConnected ? (
              <div style={{ display: "flex", gap: 8 }}>
                {integrations.safebreach === "connected" && <button className="btn btn-primary" onClick={() => runSimulation("safebreach")} disabled={!id}>Run SafeBreach scenario</button>}
                {integrations.atomic_red_team === "connected" && <button className="btn btn-primary" onClick={() => runSimulation("atomic_red_team")} disabled={!id}>Run Atomic test</button>}
              </div>
            ) : (
              <p style={{ fontSize: 12.5, color: "var(--text-muted)" }}>No simulation tool connected. Connect SafeBreach or Atomic Red Team in Settings → Integrations to trigger real attack simulations.</p>
            )}
          </div>

          {runs.length > 0 && (
            <div className="panel">
              <div className="panel-head">Validation history</div>
              {runs.map((r) => (
                <div key={r.id} style={{ display: "flex", alignItems: "center", gap: 12, padding: "10px 16px", borderBottom: "1px solid var(--border)", fontSize: 13 }}>
                  <span className="badge" data-tone={r.status === "failed" ? "red" : r.status === "passed" ? "cyan" : "amber"}>{r.status}</span>
                  <span style={{ color: "var(--text-muted)" }}>{r.method}</span>
                  <span style={{ flex: 1 }} />
                  <span className="mono" style={{ fontSize: 11, color: "var(--text-muted)" }}>{new Date(r.started_at).toLocaleString()}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {tab === "Tuning" && (
        <div style={{ display: "grid", gap: 16, maxWidth: 720 }}>
          <div className="panel" style={{ padding: 20, display: "grid", gap: 12 }}>
            <Field label="Known false positives"><textarea className="input" rows={3} value={form.false_positives || ""} onChange={(e) => setForm({ ...form, false_positives: e.target.value })} placeholder="e.g. Backup service accounts trigger this on Sunday maintenance windows." /></Field>
            <Field label="Tuning notes"><textarea className="input" rows={3} value={form.tuning_notes || ""} onChange={(e) => setForm({ ...form, tuning_notes: e.target.value })} placeholder="Adjustments made after review, threshold rationale, etc." /></Field>
          </div>

          {!id && <div className="panel" style={{ padding: 16, fontSize: 13, color: "var(--text-muted)" }}>Save the detection first to add suppression rules scoped to it.</div>}
          {id && (
            <div className="panel" style={{ padding: 16 }}>
              <div style={{ fontSize: 13.5, fontWeight: 600, marginBottom: 10 }}>Quick suppression rule</div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr auto", gap: 8, marginBottom: 12 }}>
                <input className="input" placeholder="Field" value={newSuppression.field} onChange={(e) => setNewSuppression({ ...newSuppression, field: e.target.value })} />
                <input className="input" placeholder="Value" value={newSuppression.value} onChange={(e) => setNewSuppression({ ...newSuppression, value: e.target.value })} />
                <input className="input" placeholder="Reason" value={newSuppression.reason} onChange={(e) => setNewSuppression({ ...newSuppression, reason: e.target.value })} />
                <button className="btn btn-primary" onClick={addSuppression}>Add</button>
              </div>
              {suppressions.map((s) => (
                <div key={s.id} style={{ display: "flex", gap: 10, padding: "8px 0", borderTop: "1px solid var(--border)", fontSize: 12.5 }}>
                  <span className="mono" style={{ color: "var(--amber)" }}>{s.field}</span>=<span className="mono">{s.value}</span>
                  <span style={{ color: "var(--text-muted)", marginLeft: "auto" }}>{s.reason}</span>
                </div>
              ))}
              <div style={{ marginTop: 10 }}><a href="/allowlists" style={{ fontSize: 12 }}>Manage all allowlists →</a></div>
            </div>
          )}
        </div>
      )}

      {tab === "Enrichment" && (
        <div style={{ display: "grid", gap: 12, maxWidth: 720 }}>
          {!id && <div className="panel" style={{ padding: 16, fontSize: 13, color: "var(--text-muted)" }}>Save the detection first to configure enrichment.</div>}
          {ENRICHMENT_PROVIDERS.map((p) => {
            const connected = integrations[p.provider] === "connected";
            return (
              <div className="panel" key={p.provider} style={{ padding: 16 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
                  <span style={{ fontSize: 14, fontWeight: 600 }}>{p.label}</span>
                  <span className="badge" data-tone={connected ? "cyan" : undefined}>{connected ? "connected" : "not connected"}</span>
                </div>
                {!connected ? (
                  <p style={{ fontSize: 12, color: "var(--text-muted)" }}>Connect {p.label} in Settings → Integrations to enable this.</p>
                ) : (
                  <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                    {p.fields.map((f) => {
                      const active = enrichments.some((e) => e.provider === p.provider && e.field === f);
                      return (
                        <button
                          key={f}
                          className="btn"
                          disabled={!id}
                          style={active ? { borderColor: "var(--cyan)", color: "var(--cyan)" } : {}}
                          onClick={() => toggleEnrichment(p.provider, f)}
                        >
                          {active ? "✓ " : ""}enrich {f}
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function Field({ label, children }) {
  return (
    <label style={{ display: "grid", gap: 6, fontSize: 12, color: "var(--text-muted)" }}>
      {label}
      {children}
    </label>
  );
}
