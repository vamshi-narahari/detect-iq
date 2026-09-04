import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Crosshair, Copy, Check, X } from "lucide-react";
import { supabase } from "../lib/supabase";
import { runBlindspotAnalysis, runBlindspotScan } from "../lib/api";

const SIEMS = ["splunk", "crowdstrike", "logscale", "sentinel", "qradar", "chronicle", "tanium", "panther", "sumologic", "elastic"];
const MAX_BATCH = 10;

export default function Blindspot() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [mode, setMode] = useState("single"); // 'single' | 'batch'

  const [detections, setDetections] = useState([]);
  const [selectedId, setSelectedId] = useState("");
  const [name, setName] = useState("");
  const [query, setQuery] = useState("");
  const [tool, setTool] = useState("splunk");
  const [result, setResult] = useState(null); // ephemeral, ad-hoc queries only
  const [findings, setFindings] = useState([]); // persisted, when a real detection is selected
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const [batchSelected, setBatchSelected] = useState([]);
  const [batchResults, setBatchResults] = useState(null);
  const [batchBusy, setBatchBusy] = useState(false);

  useEffect(() => {
    supabase.from("detections").select("id,name,query,tool").order("created_at", { ascending: false }).then(({ data }) => {
      setDetections(data || []);
      const preselect = params.get("id");
      if (preselect && data) {
        const d = data.find((x) => x.id === preselect);
        if (d) selectDetection(d.id, data);
      }
    });
  }, [params]);

  function selectDetection(id, list = detections) {
    setSelectedId(id);
    setResult(null);
    const d = list.find((x) => x.id === id);
    if (d) {
      setName(d.name);
      setQuery(d.query || "");
      setTool(d.tool || "splunk");
      loadFindings(id);
    }
  }

  async function loadFindings(detectionId) {
    const { data } = await supabase.from("blindspot_findings").select("*").eq("detection_id", detectionId).order("created_at", { ascending: false });
    setFindings(data || []);
  }

  async function run() {
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const data = await runBlindspotAnalysis(query, tool, name, selectedId || undefined);
      if (selectedId) {
        await loadFindings(selectedId);
      } else {
        setResult(data);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function updateFinding(id, patch) {
    await supabase.from("blindspot_findings").update(patch).eq("id", id);
    setFindings(findings.map((f) => (f.id === id ? { ...f, ...patch } : f)));
  }

  async function fileAsTicket(finding) {
    const { data: userData } = await supabase.auth.getUser();
    const priority = finding.severity === "critical" || finding.severity === "high" ? "high" : finding.severity === "low" ? "low" : "medium";
    await supabase.from("intake_requests").insert({
      user_id: userData.user.id,
      title: `Fix blind spot: ${finding.name}`,
      notes: `${finding.description}\n\nEvasion sample:\n${finding.evasion_sample}\n\nSuggested patch:\n${finding.suggested_patch}`,
      priority,
      source: "gap",
      detection_id: selectedId || null,
    });
    updateFinding(finding.id, { status: "patched" }); // treat "filed" as tracked/handled for list purposes
  }

  function toggleBatch(id) {
    setBatchSelected(batchSelected.includes(id) ? batchSelected.filter((x) => x !== id) : [...batchSelected, id].slice(0, MAX_BATCH));
  }

  async function runBatch() {
    setBatchBusy(true);
    setError("");
    setBatchResults(null);
    try {
      const data = await runBlindspotScan(batchSelected);
      setBatchResults(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setBatchBusy(false);
    }
  }

  const severityRank = { critical: 3, high: 2, medium: 1, low: 0 };
  const sortedBatchResults = batchResults?.results
    ? [...batchResults.results].sort((a, b) => {
        const score = (r) => (r.blindspots || []).reduce((s, f) => s + (severityRank[f.severity] ?? 1), 0);
        return score(b) - score(a);
      })
    : [];

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
        <Crosshair size={20} color="var(--amber)" />
        <h1 style={{ fontSize: 20, margin: 0 }}>Blindspot Agent</h1>
      </div>
      <p style={{ color: "var(--text-muted)", fontSize: 13, margin: "0 0 16px 0", maxWidth: "72ch" }}>
        Not a canned attack-technique replay — this reads a detection's actual query logic and reasons
        like an attacker who has studied it: which specific check would they slip past, and how. This
        is AI-reasoned analysis, not execution against a live SIEM — review the reasoning before trusting it blindly.
      </p>

      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        <button className="btn" style={mode === "single" ? { borderColor: "var(--cyan)", color: "var(--cyan)" } : {}} onClick={() => setMode("single")}>Single detection</button>
        <button className="btn" style={mode === "batch" ? { borderColor: "var(--cyan)", color: "var(--cyan)" } : {}} onClick={() => setMode("batch")}>Batch scan</button>
      </div>

      {error && <div style={{ color: "var(--red)", fontSize: 12.5, marginBottom: 12 }}>{error}</div>}

      {mode === "single" && (
        <>
          <div className="panel" style={{ padding: 20, marginBottom: 20 }}>
            <div style={{ display: "grid", gap: 12 }}>
              <label style={{ display: "grid", gap: 6, fontSize: 12, color: "var(--text-muted)" }}>
                Analyze an existing detection (optional — findings only persist for a real detection)
                <select className="input" value={selectedId} onChange={(e) => selectDetection(e.target.value)}>
                  <option value="">— paste a query manually instead —</option>
                  {detections.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
                </select>
              </label>

              <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 12 }}>
                <label style={{ display: "grid", gap: 6, fontSize: 12, color: "var(--text-muted)" }}>
                  Detection name
                  <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="Optional, helps the agent's reasoning" disabled={!!selectedId} />
                </label>
                <label style={{ display: "grid", gap: 6, fontSize: 12, color: "var(--text-muted)" }}>
                  Target SIEM
                  <select className="input" value={tool} onChange={(e) => setTool(e.target.value)} disabled={!!selectedId}>
                    {SIEMS.map((s) => <option key={s} value={s}>{s}</option>)}
                  </select>
                </label>
              </div>

              <label style={{ display: "grid", gap: 6, fontSize: 12, color: "var(--text-muted)" }}>
                Detection query
                <textarea
                  className="input"
                  rows={8}
                  style={{ fontFamily: "var(--mono)", fontSize: 12.5 }}
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  disabled={!!selectedId}
                  placeholder="Paste the real detection logic — the agent reads this literally, field by field."
                />
              </label>

              <button className="btn btn-primary" onClick={run} disabled={busy || !query} style={{ justifySelf: "start" }}>
                {busy ? "Reasoning through the logic…" : "Find blind spots"}
              </button>
            </div>
          </div>

          {/* Ephemeral results for ad-hoc pasted queries */}
          {result && (
            <div style={{ marginBottom: 16 }}>
              {result.overall_assessment && (
                <div className="panel" style={{ padding: 16, marginBottom: 16, fontSize: 13, color: "var(--text-muted)" }}>{result.overall_assessment}</div>
              )}
              {(result.blindspots || []).length === 0 && (
                <div className="panel" style={{ padding: 20, textAlign: "center", color: "var(--cyan)", fontSize: 13 }}>
                  No genuine blind spots found.
                </div>
              )}
              <div style={{ display: "grid", gap: 12 }}>
                {(result.blindspots || []).map((b, i) => <FindingCard key={i} finding={b} />)}
              </div>
            </div>
          )}

          {/* Persisted, trackable findings for a real detection */}
          {selectedId && (
            <div>
              <div className="panel-head" style={{ padding: 0, border: "none", marginBottom: 10 }}>
                Tracked findings ({findings.filter((f) => f.status === "open").length} open)
              </div>
              {findings.length === 0 && <div className="panel" style={{ padding: 20, textAlign: "center", color: "var(--text-muted)", fontSize: 13 }}>No findings yet — run the agent above.</div>}
              <div style={{ display: "grid", gap: 12 }}>
                {findings.map((f) => (
                  <FindingCard
                    key={f.id}
                    finding={f}
                    onDismiss={() => updateFinding(f.id, { status: "dismissed", dismissal_reason: "Reviewed — accepted risk" })}
                    onMarkPatched={() => updateFinding(f.id, { status: "patched" })}
                    onFileTicket={() => fileAsTicket(f)}
                    onOpenEditor={() => navigate(`/editor?id=${selectedId}`)}
                  />
                ))}
              </div>
            </div>
          )}
        </>
      )}

      {mode === "batch" && (
        <div>
          <div className="panel" style={{ padding: 16, marginBottom: 16 }}>
            <p style={{ fontSize: 12.5, color: "var(--text-muted)", marginBottom: 12 }}>
              Select up to {MAX_BATCH} detections. Each one is a separate real AI call — a batch of {batchSelected.length || "N"} costs {batchSelected.length || "N"} calls against your daily budget, not one.
            </p>
            <div style={{ maxHeight: 240, overflowY: "auto", marginBottom: 12 }}>
              {detections.map((d) => (
                <label key={d.id} style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 0", fontSize: 13 }}>
                  <input type="checkbox" checked={batchSelected.includes(d.id)} onChange={() => toggleBatch(d.id)} disabled={!batchSelected.includes(d.id) && batchSelected.length >= MAX_BATCH} />
                  {d.name} <span className="mono" style={{ color: "var(--text-muted)", fontSize: 11 }}>({d.tool})</span>
                </label>
              ))}
            </div>
            <button className="btn btn-primary" onClick={runBatch} disabled={batchBusy || batchSelected.length === 0}>
              {batchBusy ? "Scanning…" : `Scan ${batchSelected.length} detection${batchSelected.length === 1 ? "" : "s"}`}
            </button>
          </div>

          {batchResults && (
            <div>
              <p style={{ fontSize: 12.5, color: "var(--text-muted)", marginBottom: 12 }}>
                Scanned {batchResults.scanned} of {batchResults.requested}
                {batchResults.budget_exhausted && " — stopped early, daily AI budget was reached"}. Ranked by severity, weakest first.
              </p>
              <div style={{ display: "grid", gap: 16 }}>
                {sortedBatchResults.map((r) => (
                  <div key={r.detection_id} className="panel" style={{ padding: 16 }}>
                    <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 10 }}>{r.name}</div>
                    {(r.blindspots || []).length === 0 ? (
                      <div style={{ fontSize: 12.5, color: "var(--cyan)" }}>No genuine blind spots found.</div>
                    ) : (
                      <div style={{ display: "grid", gap: 10 }}>
                        {r.blindspots.map((b, i) => <FindingCard key={i} finding={b} compact />)}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

const SEVERITY_TONE = { critical: "red", high: "red", medium: "amber", low: undefined };

function FindingCard({ finding, onDismiss, onMarkPatched, onFileTicket, onOpenEditor, compact }) {
  const [copiedSample, setCopiedSample] = useState(false);
  const [copiedPatch, setCopiedPatch] = useState(false);

  function copy(text, setFlag) {
    navigator.clipboard.writeText(text);
    setFlag(true);
    setTimeout(() => setFlag(false), 1500);
  }

  const dismissed = finding.status === "dismissed";

  return (
    <div className="panel" style={{ padding: compact ? 14 : 18, opacity: dismissed ? 0.55 : 1 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 6 }}>
        <div style={{ fontSize: 14.5, fontWeight: 600, color: "var(--amber)" }}>{finding.name}</div>
        <div style={{ display: "flex", gap: 6 }}>
          {finding.severity && <span className="badge" data-tone={SEVERITY_TONE[finding.severity]}>{finding.severity}</span>}
          {finding.status && finding.status !== "open" && <span className="badge" data-tone="cyan">{finding.status}</span>}
        </div>
      </div>
      <div style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 14 }}>{finding.description}</div>

      <div style={{ marginBottom: 12 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
          <span className="mono" style={{ fontSize: 10.5, color: "var(--text-muted)", textTransform: "uppercase" }}>Proof-of-concept evasion</span>
          <button className="btn" onClick={() => copy(finding.evasion_sample, setCopiedSample)} style={{ padding: "3px 8px", fontSize: 11 }}>
            {copiedSample ? <Check size={11} /> : <Copy size={11} />}
          </button>
        </div>
        <pre className="mono" style={{ fontSize: 12, background: "var(--panel-2)", padding: 12, borderRadius: "var(--radius-sm)", whiteSpace: "pre-wrap", margin: 0 }}>{finding.evasion_sample}</pre>
      </div>

      <div style={{ marginBottom: onDismiss ? 14 : 0 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
          <span className="mono" style={{ fontSize: 10.5, color: "var(--text-muted)", textTransform: "uppercase" }}>Suggested patch</span>
          <button className="btn" onClick={() => copy(finding.suggested_patch, setCopiedPatch)} style={{ padding: "3px 8px", fontSize: 11 }}>
            {copiedPatch ? <Check size={11} /> : <Copy size={11} />}
          </button>
        </div>
        <pre className="mono" style={{ fontSize: 12, background: "var(--panel-2)", padding: 12, borderRadius: "var(--radius-sm)", whiteSpace: "pre-wrap", margin: 0 }}>{finding.suggested_patch}</pre>
      </div>

      {onDismiss && !dismissed && (
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <button className="btn" onClick={onOpenEditor}>Open in Editor</button>
          <button className="btn" onClick={onFileTicket}>File as ticket</button>
          <button className="btn" onClick={onMarkPatched}>Mark patched</button>
          <button className="btn" onClick={onDismiss}><X size={12} style={{ marginRight: 4, verticalAlign: -2 }} />Dismiss</button>
        </div>
      )}
    </div>
  );
}
