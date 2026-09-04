import { useEffect, useState } from "react";
import { useAuth } from "../context/AuthContext";
import { supabase } from "../lib/supabase";

const TIMEZONES = ["UTC", "America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles", "Europe/London", "Europe/Berlin", "Asia/Kolkata", "Asia/Singapore", "Australia/Sydney"];

function initials(email) {
  if (!email) return "?";
  return email.split("@")[0].slice(0, 2).toUpperCase();
}

const CATALOG = [
  { provider: "splunk", category: "siem", label: "Splunk" },
  { provider: "crowdstrike", category: "siem", label: "CrowdStrike" },
  { provider: "logscale", category: "siem", label: "Falcon LogScale" },
  { provider: "sentinel", category: "siem", label: "Microsoft Sentinel" },
  { provider: "databricks", category: "siem", label: "Databricks" },
  { provider: "safebreach", category: "simulation", label: "SafeBreach" },
  { provider: "atomic_red_team", category: "simulation", label: "Atomic Red Team" },
  { provider: "jira", category: "ticketing", label: "Jira" },
  { provider: "outlook", category: "ticketing", label: "Outlook" },
  { provider: "teams", category: "ticketing", label: "Microsoft Teams" },
  { provider: "webex", category: "ticketing", label: "Webex" },
  { provider: "virustotal", category: "enrichment", label: "VirusTotal" },
  { provider: "abuseipdb", category: "enrichment", label: "AbuseIPDB" },
  { provider: "shodan", category: "enrichment", label: "Shodan" },
  { provider: "urlscan", category: "enrichment", label: "URLScan" },
];

const CATEGORY_LABELS = { siem: "SIEM connectors", simulation: "Simulation & validation", ticketing: "Ticketing & chat", enrichment: "Alert enrichment" };

export default function Settings() {
  const { user, profile, signOut, refreshProfile } = useAuth();
  const [statusByProvider, setStatusByProvider] = useState({});
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState("");

  useEffect(() => {
    supabase.from("integrations").select("*").then(({ data }) => {
      const map = {};
      (data || []).forEach((i) => { map[i.provider] = i.status; });
      setStatusByProvider(map);
    });
  }, []);

  async function uploadAvatar(e) {
    const file = e.target.files?.[0];
    if (!file || !user) return;
    setUploading(true);
    setUploadError("");
    try {
      const path = `${user.id}/avatar.${file.name.split(".").pop()}`;
      const { error: uploadErr } = await supabase.storage.from("avatars").upload(path, file, { upsert: true });
      if (uploadErr) throw uploadErr;
      const { data: pub } = supabase.storage.from("avatars").getPublicUrl(path);
      await supabase.from("profiles").update({ avatar_url: pub.publicUrl, updated_at: new Date().toISOString() }).eq("id", user.id);
      refreshProfile();
    } catch (err) {
      setUploadError(err.message || "Upload failed — make sure the 'avatars' storage bucket exists and is public.");
    } finally {
      setUploading(false);
    }
  }

  async function updateTimezone(tz) {
    await supabase.from("profiles").update({ timezone: tz, updated_at: new Date().toISOString() }).eq("id", user.id);
    refreshProfile();
  }

  async function toggle(provider, category) {
    const { data: userData } = await supabase.auth.getUser();
    const current = statusByProvider[provider] || "disconnected";
    const next = current === "connected" ? "disconnected" : "connected";
    await supabase
      .from("integrations")
      .upsert({ user_id: userData.user.id, provider, category, status: next }, { onConflict: "user_id,provider" });
    setStatusByProvider({ ...statusByProvider, [provider]: next });
  }

  const byCategory = CATALOG.reduce((acc, c) => {
    (acc[c.category] ||= []).push(c);
    return acc;
  }, {});

  return (
    <div style={{ maxWidth: 720 }}>
      <h1 style={{ fontSize: 20, margin: "0 0 4px 0" }}>Settings</h1>
      <p style={{ color: "var(--text-muted)", fontSize: 13, margin: "0 0 20px 0" }}>
        Accounts first, then every SIEM, simulation platform, and ticketing source DetectIQ talks to.
      </p>

      <div className="panel" style={{ padding: 20, marginBottom: 20 }}>
        <div className="panel-head" style={{ padding: 0, border: "none", marginBottom: 14 }}>Profile</div>
        <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 14 }}>
          {profile?.avatar_url ? (
            <img src={profile.avatar_url} alt="" style={{ width: 56, height: 56, borderRadius: "50%", objectFit: "cover" }} />
          ) : (
            <div style={{ width: 56, height: 56, borderRadius: "50%", background: "linear-gradient(135deg, var(--cyan), var(--amber))", display: "flex", alignItems: "center", justifyContent: "center", fontFamily: "var(--mono)", fontWeight: 700, color: "#06141a", fontSize: 18 }}>
              {initials(user?.email)}
            </div>
          )}
          <div>
            <label className="btn" style={{ cursor: "pointer", display: "inline-block" }}>
              {uploading ? "Uploading…" : "Change photo"}
              <input type="file" accept="image/*" onChange={uploadAvatar} disabled={uploading} style={{ display: "none" }} />
            </label>
            {uploadError && <div style={{ color: "var(--red)", fontSize: 11.5, marginTop: 6, maxWidth: 320 }}>{uploadError}</div>}
          </div>
        </div>
        <div style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 14 }}>{user?.email}</div>
        <label style={{ display: "grid", gap: 6, fontSize: 12, color: "var(--text-muted)", maxWidth: 280, marginBottom: 16 }}>
          Time zone
          <select className="input" value={profile?.timezone || "UTC"} onChange={(e) => updateTimezone(e.target.value)}>
            {TIMEZONES.map((tz) => <option key={tz} value={tz}>{tz}</option>)}
          </select>
        </label>
        <button className="btn" onClick={signOut}>Sign out</button>
      </div>

      {Object.entries(byCategory).map(([category, items]) => (
        <div key={category} style={{ marginBottom: 20 }}>
          <div className="mono" style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 10, textTransform: "uppercase" }}>
            {CATEGORY_LABELS[category]}
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            {items.map((c) => {
              const status = statusByProvider[c.provider] || "disconnected";
              return (
                <div key={c.provider} className="panel" style={{ padding: 14, display: "flex", alignItems: "center", gap: 10 }}>
                  <span style={{ flex: 1, fontSize: 13.5 }}>{c.label}</span>
                  <span className="badge" data-tone={status === "connected" ? "cyan" : undefined}>{status}</span>
                  <button className="btn" onClick={() => toggle(c.provider, c.category)} style={{ fontSize: 12 }}>
                    {status === "connected" ? "Disconnect" : "Connect"}
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      ))}

      <div className="panel" style={{ padding: 20 }}>
        <div className="panel-head" style={{ padding: 0, border: "none", marginBottom: 12 }}>AI provider</div>
        <p style={{ fontSize: 13, color: "var(--text-muted)" }}>
          AI generation runs through either AWS Bedrock or the direct Anthropic API, configured
          server-side — whichever key is set in the backend env. Demo instances cap AI runs per day —
          see <code>DEMO_MODE</code> / <code>DEMO_DAILY_AI_LIMIT</code> in the backend environment.
        </p>
      </div>

      <div className="panel" style={{ padding: 20, marginTop: 20 }}>
        <div className="panel-head" style={{ padding: 0, border: "none", marginBottom: 12 }}>Intake webhook</div>
        <p style={{ fontSize: 13, color: "var(--text-muted)" }}>
          Point a Jira Automation rule, Power Automate flow, or Webex webhook at
          <code style={{ margin: "0 4px" }}>POST /api/webhook/intake/&lt;provider&gt;</code>
          with header <code>X-Webhook-Secret</code> and body <code>{"{ title, notes, priority }"}</code> to
          auto-create Intake tickets. Set <code>INTAKE_WEBHOOK_SECRET</code> and{" "}
          <code>INTAKE_OWNER_USER_ID</code> in the backend env to enable it — off by default.
        </p>
      </div>
    </div>
  );
}
