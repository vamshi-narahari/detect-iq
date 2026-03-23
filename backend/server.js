require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");
const { BedrockRuntimeClient, InvokeModelCommand } = require("@aws-sdk/client-bedrock-runtime");
const { createClient } = require("redis");
const crypto = require("crypto");
const { createClient: createSupabaseClient } = require("@supabase/supabase-js");
const supabase = createSupabaseClient(
  "https://gckbdtcguptlfulzekzx.supabase.co",
  process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY
);

const PORT = process.env.PORT || 3001;
const app = express();
app.set("trust proxy", 1); // Trust Cloudflare proxy
const startTime = Date.now();

// ── Redis client ──────────────────────────────────────────────────────────────
const redis = createClient({ url: process.env.REDIS_URL || "redis://127.0.0.1:6379" });
redis.connect().then(() => console.log("Redis connected")).catch(e => console.error("Redis error:", e));

// ── Security headers ──────────────────────────────────────────────────────────
app.use(helmet());
app.use(morgan("combined"));

// ── CORS ──────────────────────────────────────────────────────────────────────
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",").map(o => o.trim());

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    callback(new Error("CORS: origin not allowed"));
  },
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type"],
}));

app.use(express.json({ limit: "50kb" }));

// ── Rate limiters ─────────────────────────────────────────────────────────────
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 100,
  standardHeaders: true, legacyHeaders: false,
  message: { error: "Too many requests, please try again in 15 minutes." },
});
const claudeLimiter = rateLimit({
  windowMs: 60 * 1000, max: 20,
  standardHeaders: true, legacyHeaders: false,
  message: { error: "AI rate limit reached. Please wait a moment." },
});
app.use(globalLimiter);

// ── Bedrock clients ───────────────────────────────────────────────────────────
const bedrockConfig = {
  region: process.env.AWS_REGION || "us-east-1",
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
};
const bedrock = new BedrockRuntimeClient(bedrockConfig);

// Model IDs
const SONNET = process.env.BEDROCK_MODEL_ID || "us.anthropic.claude-sonnet-4-6";
const HAIKU = "us.anthropic.claude-sonnet-4-6";

// ── Smart model router ────────────────────────────────────────────────────────
// Detect if this is a heavy ADS/simulation call or a lighter call
function selectModel(system, messages, max_tokens) { return SONNET; }

// ── Input sanitization ────────────────────────────────────────────────────────
function sanitizeString(val, maxLen = 10000) {
  if (typeof val !== "string") return "";
  return val.slice(0, maxLen).replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
}
function sanitizeMessages(messages) {
  if (!Array.isArray(messages)) return null;
  if (messages.length > 50) return null;
  return messages.map(m => {
    if (!m || typeof m !== "object") return null;
    const role = ["user", "assistant"].includes(m.role) ? m.role : null;
    if (!role) return null;
    const content = typeof m.content === "string" ? sanitizeString(m.content, 20000) : null;
    if (content === null) return null;
    return { role, content };
  }).filter(Boolean);
}

// ── Cache helpers ─────────────────────────────────────────────────────────────
function cacheKey(messages, system, model) {
  const hash = crypto.createHash("sha256")
    .update(JSON.stringify({ messages, system, model }))
    .digest("hex").slice(0, 32);
  return "detectiq:claude:" + hash;
}

// Cache TTLs by call type (seconds)
function cacheTTL(system, messages) {
  const combined = (system + JSON.stringify(messages)).toLowerCase();
  if (combined.includes("attack detection strategy")) return 3600 * 6;  // ADS: 6 hours
  if (combined.includes("translate")) return 3600 * 24;                 // Translation: 24 hours
  if (combined.includes("explain")) return 3600 * 12;                   // Explainer: 12 hours
  if (combined.includes("apt profile") || combined.includes("apt intel")) return 3600 * 2; // APT: 2 hours
  if (combined.includes("kill chain")) return 3600 * 4;                 // Kill chain: 4 hours
  return 3600; // Default: 1 hour
}

// ── /api/claude ───────────────────────────────────────────────────────────────
app.post("/api/claude", claudeLimiter, async (req, res) => {
  try {
    const { messages, system, max_tokens } = req.body;

    const sanitized = sanitizeMessages(messages);
    if (!sanitized || sanitized.length === 0) {
      return res.status(400).json({ error: "Invalid or missing messages array." });
    }

    const safeSystem = sanitizeString(system || "", 5000);
    const safeTokens = Math.min(Math.max(parseInt(max_tokens) || 1000, 1), 6000);

    // Select model based on call type
    const modelId = selectModel(safeSystem, sanitized, safeTokens);

    // Reduce tokens for Haiku calls (it's faster and cheaper)
    const effectiveTokens = Math.min(safeTokens, 4000);

    // Check cache
    const key = cacheKey(sanitized, safeSystem, modelId);
    let cached = null;
    try { cached = await redis.get(key); } catch {}

    if (cached) {
      console.log(`Cache HIT [${modelId.includes("haiku") ? "haiku" : "sonnet"}] ${key.slice(-8)}`);
      return res.json({ text: cached, cached: true });
    }

    console.log(`Cache MISS — calling ${modelId.includes("haiku") ? "Haiku" : "Sonnet"} (${effectiveTokens} tokens)`);

    const command = new InvokeModelCommand({
      modelId,
      contentType: "application/json",
      accept: "application/json",
      body: JSON.stringify({
        anthropic_version: "bedrock-2023-05-31",
        max_tokens: effectiveTokens,
        system: safeSystem,
        messages: sanitized,
      }),
    });

    const response = await bedrock.send(command);
    const result = JSON.parse(Buffer.from(response.body));
    const text = result.content?.[0]?.text || "";

    // Cache the result
    const ttl = cacheTTL(safeSystem, sanitized);
    try { await redis.setEx(key, ttl, text); } catch {}

    res.json({ text, model: modelId.includes("haiku") ? "haiku" : "sonnet" });
  } catch (err) {
    console.error("Claude error:", err.message);
    res.status(500).json({ error: "AI service error. Please try again." });
  }
});

// ── /api/kev ──────────────────────────────────────────────────────────────────
let kevCache = null;
let kevCacheTime = 0;

app.get("/api/kev", async (req, res) => {
  try {
    if (kevCache && Date.now() - kevCacheTime < 3600000) return res.json(kevCache);
    const https = require("https");
    const data = await new Promise((resolve, reject) => {
      https.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", r => {
        let body = "";
        r.on("data", chunk => body += chunk);
        r.on("end", () => { try { resolve(JSON.parse(body)); } catch(e) { reject(e); } });
        r.on("error", reject);
      }).on("error", reject);
    });
    kevCache = data;
    kevCacheTime = Date.now();
    res.json(data);
  } catch (err) {
    console.error("KEV fetch error:", err.message);
    res.status(500).json({ error: "Failed to fetch KEV data." });
  }
});

// ── /api/autopilot/run ───────────────────────────────────────────────────────
app.post("/api/autopilot/run", claudeLimiter, async (req, res) => {
  try {
    const { lastKevIds = [], siemTool = "splunk", userId } = req.body;
    if (!userId) return res.status(400).json({ error: "userId required." });

    // Fetch KEV data (uses cache if fresh)
    let kevData = kevCache;
    if (!kevData || Date.now() - kevCacheTime > 3600000) {
      const https = require("https");
      kevData = await new Promise((resolve, reject) => {
        https.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", r => {
          let body = "";
          r.on("data", chunk => body += chunk);
          r.on("end", () => { try { resolve(JSON.parse(body)); } catch(e) { reject(e); } });
          r.on("error", reject);
        }).on("error", reject);
      });
      kevCache = kevData;
      kevCacheTime = Date.now();
    }

    const allVulns = kevData?.vulnerabilities || [];

    // Find new entries not seen before
    const newVulns = lastKevIds.length === 0
      ? allVulns.slice(0, 3) // First run — draft detections for 3 most recent
      : allVulns.filter(v => !lastKevIds.includes(v.cveID)).slice(0, 5);

    if (newVulns.length === 0) {
      return res.json({ newCount: 0, drafts: [], allIds: allVulns.map(v => v.cveID).slice(0, 100) });
    }

    const drafts = [];
    for (const vuln of newVulns) {
      try {
        const prompt = `You are a detection engineer. Generate a detection for this vulnerability.

CVE: ${vuln.cveID}
Vendor/Product: ${vuln.vendorProject} - ${vuln.product}
Vulnerability: ${vuln.vulnerabilityName}
Description: ${vuln.shortDescription}
Target SIEM: ${siemTool.toUpperCase()}

Respond ONLY with valid JSON, no markdown, no explanation:
{
  "detection_name": "short rule name",
  "detection_query": "full SIEM query",
  "detection_tactic": "one MITRE tactic",
  "detection_severity": "Critical|High|Medium|Low",
  "detection_summary": "one sentence explaining what this detects"
}`;

        const command = new InvokeModelCommand({
          modelId: SONNET,
          contentType: "application/json",
          accept: "application/json",
          body: JSON.stringify({
            anthropic_version: "bedrock-2023-05-31",
            max_tokens: 1000,
            system: "You are an expert detection engineer. Always respond with valid JSON only.",
            messages: [{ role: "user", content: prompt }],
          }),
        });

        const response = await bedrock.send(command);
        const result = JSON.parse(Buffer.from(response.body));
        const text = result.content?.[0]?.text || "";

        let parsed;
        try {
          const clean = text.replace(/```json|```/g, "").trim();
          parsed = JSON.parse(clean);
        } catch {
          parsed = {
            detection_name: `Detect ${vuln.cveID} - ${vuln.vendorProject}`,
            detection_query: `// Query generation failed for ${vuln.cveID}`,
            detection_tactic: "Initial Access",
            detection_severity: "High",
            detection_summary: vuln.shortDescription
          };
        }

        drafts.push({
          cve_id: vuln.cveID,
          vendor_project: `${vuln.vendorProject} - ${vuln.product}`,
          vulnerability_name: vuln.vulnerabilityName,
          date_added: vuln.dateAdded,
          siem_tool: siemTool,
          ...parsed
        });
      } catch (err) {
        console.error(`Autopilot draft error for ${vuln.cveID}:`, err.message);
      }
    }

    const allIds = allVulns.map(v => v.cveID).slice(0, 100);
    res.json({ newCount: newVulns.length, drafts, allIds });
  } catch (err) {
    console.error("Autopilot run error:", err.message);
    res.status(500).json({ error: "Autopilot run failed." });
  }
});

// ── /api/cache/stats ──────────────────────────────────────────────────────────
app.get("/api/cache/stats", async (req, res) => {
  try {
    const keys = await redis.keys("detectiq:claude:*");
    const info = await redis.info("memory");
    const memMatch = info.match(/used_memory_human:(.+)/);
    res.json({
      cached_responses: keys.length,
      memory_used: memMatch ? memMatch[1].trim() : "unknown",
      kev_cached: !!kevCache,
      kev_age_min: kevCacheTime ? Math.floor((Date.now() - kevCacheTime) / 60000) : null,
    });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

// ── /api/cache/clear ──────────────────────────────────────────────────────────
app.post("/api/cache/clear", async (req, res) => {
  try {
    const keys = await redis.keys("detectiq:claude:*");
    if (keys.length > 0) await redis.del(keys);
    res.json({ cleared: keys.length });
  } catch(err) {
    res.status(500).json({ error: err.message });
  }
});

// ── /api/health ───────────────────────────────────────────────────────────────
app.get("/api/health", async (req, res) => {
  const mem = process.memoryUsage();
  let redisStatus = "disconnected";
  let cachedCount = 0;
  try {
    await redis.ping();
    redisStatus = "connected";
    const keys = await redis.keys("detectiq:claude:*");
    cachedCount = keys.length;
  } catch {}

  res.json({
    status: "ok",
    uptime_seconds: Math.floor((Date.now() - startTime) / 1000),
    models: { heavy: "sonnet-4-6", light: "haiku-4-5" },
    redis: { status: redisStatus, cached_responses: cachedCount },
    memory: {
      rss_mb: (mem.rss / 1024 / 1024).toFixed(1),
      heap_used_mb: (mem.heapUsed / 1024 / 1024).toFixed(1),
    },
    kev_cache_age_min: kevCacheTime ? Math.floor((Date.now() - kevCacheTime) / 60000) : null,
    ts: new Date().toISOString(),
  });
});

app.get("/health", (req, res) => res.redirect("/api/health"));
// ── /api/send-reset-email ────────────────────────────────────────────────────
app.post("/api/send-reset-email", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || !email.includes("@")) {
      return res.status(400).json({ error: "Valid email required." });
    }
    const RESEND_KEY = process.env.RESEND_API_KEY;
    if (!RESEND_KEY) {
      return res.status(500).json({ error: "Email service not configured." });
    }
    // Generate reset link via Supabase admin
    let resetLink = "https://detect-iq.com";
    try {
      const linkResult = await supabase.auth.admin.generateLink({
        type: "recovery",
        email: email,
        options: { redirectTo: "https://detect-iq.com" }
      });
      if (linkResult?.data?.properties?.hashed_token) {
        resetLink = `https://detect-iq.com/#access_token=${linkResult.data.properties.hashed_token}&type=recovery`;
      }
    } catch(e) { /* fallback to generic link */ }

    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { "Authorization": `Bearer ${RESEND_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        from: "noreply@detect-iq.com",
        to: [email],
        subject: "Reset your DetectIQ password",
        html: `<div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px"><h2 style="color:#00d4ff">Reset your password</h2><p>Click the button below to reset your DetectIQ password.</p><a href="${resetLink}" style="display:inline-block;margin:20px 0;padding:12px 28px;background:#00d4ff;color:#05080f;border-radius:7px;font-weight:700;text-decoration:none">Reset Password</a><p style="color:#666;font-size:13px">If you didn't request this, you can safely ignore this email.</p></div>`
      })
    });
    if (!response.ok) {
      const errText = await response.text();
      throw new Error("Resend error: " + errText);
    }
    res.json({ success: true, message: "Password reset email sent." });
  } catch(err) {
    console.error("Send reset email error:", err.message);
    res.status(500).json({ error: "Failed to send reset email." });
  }
});

// ── /api/mitre/techniques ─────────────────────────────────────────────────────
const MITRE_CACHE_KEY = "mitre:enterprise:v1";
const MITRE_CTI_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json";
const MITRE_TTL = 7 * 24 * 3600;
const TACTIC_MAP = {
  "initial-access":"Initial Access","execution":"Execution","persistence":"Persistence",
  "privilege-escalation":"Privilege Escalation","defense-evasion":"Defense Evasion",
  "credential-access":"Credential Access","discovery":"Discovery",
  "lateral-movement":"Lateral Movement","collection":"Collection",
  "command-and-control":"Command and Control","exfiltration":"Exfiltration",
  "impact":"Impact","reconnaissance":"Reconnaissance","resource-development":"Resource Development"
};
async function loadMitreTechniques() {
  try {
    const cached = await redis.get(MITRE_CACHE_KEY);
    if (cached) { console.log("[MITRE] Serving from cache."); return JSON.parse(cached); }
  } catch(e) {}
  console.log("[MITRE] Fetching ATT&CK STIX data (~50MB)...");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 60000);
  const res = await fetch(MITRE_CTI_URL, { signal: controller.signal });
  clearTimeout(timer);
  if (!res.ok) throw new Error("MITRE fetch failed: " + res.status);
  const bundle = await res.json();
  const techniques = bundle.objects
    .filter(o => o.type === "attack-pattern" && !o.revoked && !o.x_mitre_deprecated)
    .reduce((arr, t) => {
      const ref = (t.external_references || []).find(r => r.source_name === "mitre-attack");
      const tid = ref?.external_id || "";
      if (!tid || tid.includes(".")) return arr;
      const tactics = (t.kill_chain_phases || [])
        .filter(p => p.kill_chain_name === "mitre-attack")
        .map(p => TACTIC_MAP[p.phase_name] || p.phase_name);
      arr.push({
        id: tid.toLowerCase(), technique: tid, name: t.name,
        description: (t.description || "").replace(/\(Citation:[^)]+\)/g,"").trim().split("\n")[0].slice(0,400),
        tactic: tactics[0] || "Unknown", url: ref?.url || ""
      });
      return arr;
    }, [])
    .sort((a, b) => a.technique.localeCompare(b.technique));
  console.log(`[MITRE] Cached ${techniques.length} techniques.`);
  await redis.set(MITRE_CACHE_KEY, JSON.stringify(techniques), { EX: MITRE_TTL }).catch(() => {});
  return techniques;
}
app.get("/api/mitre/techniques", async (req, res) => {
  try {
    const techniques = await loadMitreTechniques();
    res.json({ techniques, count: techniques.length });
  } catch(err) {
    console.error("[MITRE] Error:", err.message);
    res.status(500).json({ error: "MITRE data unavailable: " + err.message });
  }
});
setTimeout(() => loadMitreTechniques().catch(e => console.error("[MITRE] Warm failed:", e.message)), 10000);

// ── /api/siem/push/* — server-side proxy to avoid browser CORS issues ─────────
app.post("/api/siem/push/splunk", express.json(), async (req, res) => {
  const { url, token, name, query, severity, description } = req.body;
  if (!url || !token) return res.status(400).json({ error: "url and token required" });
  try {
    const target = url.replace(/\/$/, "") + "/services/saved/searches";
    const body = new URLSearchParams({
      name, search: query, description: description || "",
      "alert.severity": severity === "Critical" ? "5" : severity === "High" ? "4" : severity === "Medium" ? "3" : "2",
      "alert_type": "number", "alert.suppress": "0",
      "dispatch.earliest_time": "-15m", "dispatch.latest_time": "now",
      "is_scheduled": "1", "cron_schedule": "*/15 * * * *",
    });
    const r = await fetch(target, {
      method: "POST",
      headers: { "Authorization": "Bearer " + token, "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    const text = await r.text();
    if (r.ok || r.status === 201) {
      res.json({ success: true, message: "Detection '" + name + "' pushed to Splunk as a scheduled saved search (runs every 15 min)." });
    } else {
      res.status(400).json({ error: "Splunk returned " + r.status + ". Check your management URL (port 8089) and token. " + text.slice(0, 200) });
    }
  } catch (e) {
    res.status(500).json({ error: "Could not reach Splunk: " + e.message + ". Ensure the URL is reachable from the server." });
  }
});

app.post("/api/siem/push/elastic", express.json(), async (req, res) => {
  const { url, token, name, query, severity, description, tactic, queryType } = req.body;
  if (!url || !token) return res.status(400).json({ error: "url and token required" });
  try {
    const target = url.replace(/\/$/, "") + "/api/detection_engine/rules";
    const payload = {
      type: "eql", name, description: description || name,
      severity: (severity || "medium").toLowerCase(),
      risk_score: severity === "Critical" ? 99 : severity === "High" ? 73 : severity === "Medium" ? 47 : 21,
      query, enabled: false,
      tags: [tactic, queryType].filter(Boolean),
      interval: "5m", from: "now-6m",
    };
    const r = await fetch(target, {
      method: "POST",
      headers: { "Authorization": "ApiKey " + token, "Content-Type": "application/json", "kbn-xsrf": "true" },
      body: JSON.stringify(payload),
    });
    const text = await r.text();
    if (r.ok) {
      res.json({ success: true, message: "Rule '" + name + "' pushed to Elastic Security (disabled — review and enable in Detection Rules)." });
    } else {
      res.status(400).json({ error: "Elastic returned " + r.status + ". Check Kibana URL and API key (Base64 of id:api_key). " + text.slice(0, 200) });
    }
  } catch (e) {
    res.status(500).json({ error: "Could not reach Elastic/Kibana: " + e.message });
  }
});

app.post("/api/siem/push/soar", express.json(), async (req, res) => {
  const { url, token, payload } = req.body;
  if (!url) return res.status(400).json({ error: "url required" });
  try {
    const headers = { "Content-Type": "application/json" };
    if (token) headers["Authorization"] = "Bearer " + token;
    const r = await fetch(url, { method: "POST", headers, body: JSON.stringify(payload) });
    if (r.ok) {
      res.json({ success: true, message: "Payload delivered to SOAR webhook successfully." });
    } else {
      res.status(400).json({ error: "SOAR returned " + r.status + ". Verify the webhook URL and any required auth headers." });
    }
  } catch (e) {
    res.status(500).json({ error: "Could not reach SOAR webhook: " + e.message });
  }
});

// ── /api/github/push ──────────────────────────────────────────────────────────
app.post("/api/github/push", express.json(), async (req, res) => {
  const { token, repo, owner, detection } = req.body;
  if (!token || !repo || !owner || !detection) {
    return res.status(400).json({ error: "token, repo, owner, and detection are required." });
  }
  try {
    const { name, query, tactic, severity, queryType, tool, threat } = detection;
    const ext = queryType === "SPL" || tool === "splunk" ? "spl"
      : queryType === "KQL" || tool === "sentinel" || tool === "qradar" ? "kql"
      : queryType === "EQL" || tool === "elastic" ? "eql"
      : "sql";
    const safeName = (name || "detection").replace(/[^a-zA-Z0-9_\-\s]/g, "").replace(/\s+/g, "-").toLowerCase();
    const safeTactic = (tactic || "general").replace(/[^a-zA-Z0-9_\-\s]/g, "").replace(/\s+/g, "-").toLowerCase();
    const filePath = `detections/${safeTactic}/${safeName}.${ext}`;
    const fileContent = `# Detection: ${name}
# Tactic: ${tactic || "Unknown"}
# Severity: ${severity || "Medium"}
# Platform: ${queryType || tool || "Unknown"}
# Threat: ${threat || ""}
# Generated by DetectIQ

${query}`;
    const contentBase64 = Buffer.from(fileContent).toString("base64");
    const apiBase = `https://api.github.com/repos/${owner}/${repo}/contents/${filePath}`;
    const headers = {
      "Authorization": "Bearer " + token,
      "Accept": "application/vnd.github+json",
      "Content-Type": "application/json",
      "X-GitHub-Api-Version": "2022-11-28",
    };
    // Check if file exists to get sha for update
    let sha;
    try {
      const getRes = await fetch(apiBase, { headers });
      if (getRes.ok) {
        const existing = await getRes.json();
        sha = existing.sha;
      }
    } catch {}
    const putBody = { message: "Add detection: " + name, content: contentBase64 };
    if (sha) putBody.sha = sha;
    const putRes = await fetch(apiBase, { method: "PUT", headers, body: JSON.stringify(putBody) });
    const putData = await putRes.json();
    if (putRes.ok) {
      const url = putData.content?.html_url || `https://github.com/${owner}/${repo}/blob/main/${filePath}`;
      res.json({ success: true, url });
    } else {
      res.status(400).json({ error: putData.message || "GitHub push failed." });
    }
  } catch (e) {
    res.status(500).json({ error: "GitHub push error: " + e.message });
  }
});

// ── /api/sigma/export ─────────────────────────────────────────────────────────
app.post("/api/sigma/export", claudeLimiter, express.json(), async (req, res) => {
  const { detection } = req.body;
  if (!detection) return res.status(400).json({ error: "detection required." });
  try {
    const { name, query, tactic, technique, severity, queryType, tool, threat } = detection;
    const prompt = `Convert this ${queryType || tool || "SIEM"} query to Sigma YAML format. Include title, status: experimental, description, logsource, detection, falsepositives, and level fields. Return ONLY the YAML, no explanation, no markdown fences.

Detection name: ${name}
Tactic: ${tactic || ""}
Technique: ${technique || ""}
Severity: ${severity || "medium"}
Threat/Description: ${threat || ""}
Query:
${query}`;
    const command = new InvokeModelCommand({
      modelId: SONNET,
      contentType: "application/json",
      accept: "application/json",
      body: JSON.stringify({
        anthropic_version: "bedrock-2023-05-31",
        max_tokens: 2000,
        system: "You are an expert detection engineer specializing in Sigma rules. Always return valid YAML only.",
        messages: [{ role: "user", content: prompt }],
      }),
    });
    const response = await bedrock.send(command);
    const result = JSON.parse(Buffer.from(response.body));
    let sigma = result.content?.[0]?.text || "";
    // Strip markdown fences if model adds them
    sigma = sigma.replace(/^```[a-z]*\n?/i, "").replace(/\n?```$/i, "").trim();
    res.json({ sigma });
  } catch (e) {
    res.status(500).json({ error: "Sigma export failed: " + e.message });
  }
});

// ── /api/auth/welcome-email ───────────────────────────────────────────────────
app.post("/api/auth/welcome-email", express.json(), async (req, res) => {
  const { email, name } = req.body;
  if (!email || !email.includes("@")) {
    return res.status(400).json({ error: "Valid email required." });
  }
  const RESEND_KEY = process.env.RESEND_API_KEY;
  if (!RESEND_KEY) {
    return res.status(500).json({ error: "Email service not configured." });
  }
  try {
    const displayName = name || email.split("@")[0];
    const html = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#05080f;font-family:'Segoe UI',Arial,sans-serif;color:#e2e8f0">
  <div style="max-width:560px;margin:0 auto;padding:48px 32px">
    <div style="margin-bottom:32px">
      <span style="font-size:28px;font-weight:900;letter-spacing:-0.02em"><span style="color:#00d4ff">DETECT</span><span style="color:#e2e8f0">IQ</span></span>
    </div>
    <h1 style="font-size:24px;font-weight:700;color:#e2e8f0;margin:0 0 12px">Welcome to DetectIQ, ${displayName}!</h1>
    <p style="font-size:15px;color:#94a3b8;line-height:1.7;margin:0 0 28px">
      You're now part of the next generation of detection engineering. DetectIQ puts AI-powered threat detection directly in your hands.
    </p>

    <div style="background:#0c1220;border:1px solid #1e293b;border-radius:12px;padding:24px;margin-bottom:24px">
      <div style="font-size:11px;font-weight:700;color:#00d4ff;letter-spacing:0.12em;margin-bottom:16px">WHAT YOU CAN DO</div>
      <div style="display:flex;flex-direction:column;gap:14px">
        <div>
          <div style="font-weight:700;color:#e2e8f0;margin-bottom:4px">🔨 Detection Builder</div>
          <div style="font-size:13px;color:#94a3b8;line-height:1.6">Describe a threat in plain English and get production-ready SIEM queries for Splunk, Sentinel, Elastic, and 7 other platforms instantly.</div>
        </div>
        <div>
          <div style="font-weight:700;color:#e2e8f0;margin-bottom:4px">🔄 Query Translator</div>
          <div style="font-size:13px;color:#94a3b8;line-height:1.6">Convert your existing detections between any SIEM platforms with a single click. Migrate from Splunk to Elastic or Sentinel with ease.</div>
        </div>
        <div>
          <div style="font-weight:700;color:#e2e8f0;margin-bottom:4px">🤖 Autopilot</div>
          <div style="font-size:13px;color:#94a3b8;line-height:1.6">Automatically draft detections for the latest CISA KEV entries as they drop. Stay ahead of emerging threats without manual effort.</div>
        </div>
      </div>
    </div>

    <a href="https://detect-iq.com" style="display:inline-block;padding:14px 32px;background:#00d4ff;color:#05080f;border-radius:8px;font-weight:700;font-size:14px;text-decoration:none;margin-bottom:28px">
      Open DetectIQ →
    </a>

    <p style="font-size:12px;color:#475569;line-height:1.6;border-top:1px solid #1e293b;padding-top:20px;margin:0">
      You're receiving this because you signed up at detect-iq.com. Questions? Reply to this email.
    </p>
  </div>
</body>
</html>`;
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { "Authorization": `Bearer ${RESEND_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        from: "DetectIQ <noreply@detect-iq.com>",
        to: [email],
        subject: "Welcome to DetectIQ",
        html,
      }),
    });
    if (!response.ok) {
      const errText = await response.text();
      throw new Error("Resend error: " + errText);
    }
    res.json({ success: true });
  } catch (e) {
    console.error("Welcome email error:", e.message);
    res.status(500).json({ error: "Failed to send welcome email." });
  }
});

app.use((req, res) => res.status(404).json({ error: "Not found." }));
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err.message);
  res.status(500).json({ error: "Internal server error." });
});

// ── Autopilot background cron (every 3 days) ─────────────────────────────────
const AUTOPILOT_INTERVAL_MS = 24 * 60 * 60 * 1000; // daily
const AUTOPILOT_SIEM_DEFAULT = "splunk";

async function fetchKEVData() {
  if (kevCache && Date.now() - kevCacheTime < 3600000) return kevCache;
  const https = require("https");
  const data = await new Promise((resolve, reject) => {
    https.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", r => {
      let body = "";
      r.on("data", chunk => body += chunk);
      r.on("end", () => { try { resolve(JSON.parse(body)); } catch(e) { reject(e); } });
      r.on("error", reject);
    }).on("error", reject);
  });
  kevCache = data; kevCacheTime = Date.now();
  return data;
}

async function runAutopilotCron() {
  console.log("[Autopilot] Starting scheduled KEV scan...");
  try {
    // Get last seen KEV IDs from Redis
    let lastIdsRaw = null;
    try { lastIdsRaw = await redis.get("autopilot:last_kev_ids"); } catch {}
    const lastIds = lastIdsRaw ? JSON.parse(lastIdsRaw) : [];

    const kevData = await fetchKEVData();
    const allVulns = kevData?.vulnerabilities || [];
    const allIds = allVulns.map(v => v.cveID);

    // Find new entries
    const newVulns = lastIds.length === 0
      ? allVulns.slice(0, 3)
      : allVulns.filter(v => !lastIds.includes(v.cveID)).slice(0, 5);

    if (newVulns.length === 0) {
      console.log("[Autopilot] No new KEV entries found.");
      await redis.set("autopilot:last_run", new Date().toISOString());
      return;
    }

    console.log("[Autopilot] Found " + newVulns.length + " new KEV entries. Drafting detections...");

    // Get all users with autopilot enabled from Supabase
    const { data: settings } = await supabase
      .from("autopilot_settings")
      .select("user_id, siem_tool, enabled")
      .eq("enabled", true);

    const users = settings || [];
    if (users.length === 0) {
      console.log("[Autopilot] No users with autopilot enabled.");
    }

    // Group users by SIEM tool so we generate one query per SIEM (not one per user)
    const siemGroups = {};
    for (const u of users) {
      const siem = u.siem_tool || AUTOPILOT_SIEM_DEFAULT;
      if (!siemGroups[siem]) siemGroups[siem] = [];
      siemGroups[siem].push(u);
    }
    if (users.length === 0) {
      // Still track KEV IDs even with no users
      siemGroups[AUTOPILOT_SIEM_DEFAULT] = [];
    }

    const draftsCreated = {};  // cveID -> count of drafts saved

    // Draft detections — one AI call per (vuln x SIEM) combination
    for (const vuln of newVulns) {
      for (const [siemTool, siemUsers] of Object.entries(siemGroups)) {
        try {
          const prompt = `You are a detection engineer. Generate a detection for this vulnerability.

CVE: ${vuln.cveID}
Vendor/Product: ${vuln.vendorProject} - ${vuln.product}
Vulnerability: ${vuln.vulnerabilityName}
Description: ${vuln.shortDescription}
Target SIEM: ${siemTool.toUpperCase()}

Respond ONLY with valid JSON, no markdown:
{
  "detection_name": "short descriptive rule name",
  "detection_query": "full ${siemTool.toUpperCase()} query for this CVE",
  "detection_tactic": "one MITRE tactic",
  "detection_severity": "Critical|High|Medium|Low",
  "detection_summary": "one sentence explaining what this detects"
}`;

          const command = new InvokeModelCommand({
            modelId: SONNET,
            contentType: "application/json",
            accept: "application/json",
            body: JSON.stringify({
              anthropic_version: "bedrock-2023-05-31",
              max_tokens: 1000,
              system: "You are an expert detection engineer. Always respond with valid JSON only.",
              messages: [{ role: "user", content: prompt }],
            }),
          });

          const response = await bedrock.send(command);
          const result = JSON.parse(Buffer.from(response.body));
          const text = result.content?.[0]?.text || "";
          let parsed;
          try {
            parsed = JSON.parse(text.replace(/```json|```/g, "").trim());
          } catch {
            parsed = {
              detection_name: "Detect " + vuln.cveID + " - " + vuln.vendorProject,
              detection_query: "// Auto-generation failed for " + vuln.cveID,
              detection_tactic: "Initial Access",
              detection_severity: "High",
              detection_summary: vuln.shortDescription
            };
          }

          // Save draft for each user with this SIEM
          for (const u of siemUsers) {
            await supabase.from("autopilot_drafts").insert([{
              user_id: u.user_id,
              cve_id: vuln.cveID,
              vendor_project: vuln.vendorProject + " - " + vuln.product,
              vulnerability_name: vuln.vulnerabilityName,
              date_added: vuln.dateAdded,
              siem_tool: siemTool,
              detection_name: parsed.detection_name,
              detection_query: parsed.detection_query,
              detection_tactic: parsed.detection_tactic,
              detection_severity: parsed.detection_severity,
              detection_summary: parsed.detection_summary,
              status: "pending",
              created_at: new Date().toISOString(),
            }]);
            draftsCreated[u.user_id] = (draftsCreated[u.user_id] || 0) + 1;
          }
          console.log("[Autopilot] Drafted detection for " + vuln.cveID + " (" + siemTool + ")");
        } catch(err) {
          console.error("[Autopilot] Error drafting " + vuln.cveID + " for " + siemTool + ":", err.message);
        }
      }
    }

    // Send email notification to each user with new drafts
    const RESEND_KEY = process.env.RESEND_API_KEY;
    if (RESEND_KEY && users.length > 0) {
      // Get user emails from Supabase auth
      for (const u of users) {
        const count = draftsCreated[u.user_id] || 0;
        if (count === 0) continue;
        try {
          const { data: profile } = await supabase.auth.admin.getUserById(u.user_id);
          const email = profile?.user?.email;
          if (!email) continue;
          await fetch("https://api.resend.com/emails", {
            method: "POST",
            headers: { "Authorization": "Bearer " + RESEND_KEY, "Content-Type": "application/json" },
            body: JSON.stringify({
              from: "DetectIQ Autopilot <noreply@detect-iq.com>",
              to: email,
              subject: count + " new detection draft" + (count > 1 ? "s" : "") + " from Autopilot",
              html: `<div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:32px;background:#05080f;color:#dce8f0">
                <h2 style="color:#00d4ff;margin-bottom:8px">DetectIQ Autopilot</h2>
                <p style="color:#7a8a9a;margin-bottom:24px">${count} new detection draft${count > 1 ? "s have" : " has"} been generated from the latest CISA KEV entries.</p>
                <div style="background:#0a0e1a;border:1px solid #1e2d45;border-radius:8px;padding:16px;margin-bottom:24px">
                  <p style="margin:0;font-size:13px;color:#7a8a9a">New CVEs detected:</p>
                  <ul style="margin:8px 0 0;padding-left:20px;color:#dce8f0;font-size:13px">
                    ${newVulns.map(v => `<li style="margin-bottom:4px"><strong>${v.cveID}</strong> — ${v.vulnerabilityName}</li>`).join("")}
                  </ul>
                </div>
                <a href="https://detect-iq.com/autopilot" style="display:inline-block;padding:12px 28px;background:#00d4ff;color:#05080f;border-radius:7px;font-weight:700;text-decoration:none;font-size:14px">Review Drafts</a>
                <p style="color:#3a4a5a;font-size:11px;margin-top:24px">You received this because Autopilot is enabled on your account. Disable it anytime in Settings.</p>
              </div>`
            })
          });
          console.log("[Autopilot] Email sent to", email);
        } catch(emailErr) {
          console.error("[Autopilot] Email error for", u.user_id, emailErr.message);
        }
      }
    }

    // Update last seen IDs in Redis
    try {
      await redis.set("autopilot:last_kev_ids", JSON.stringify(allIds.slice(0, 200)));
      await redis.set("autopilot:last_run", new Date().toISOString());
    } catch {}

    console.log("[Autopilot] Cron complete. " + newVulns.length + " CVEs × " + Object.keys(siemGroups).length + " SIEMs → " + users.length + " users.");
  } catch(err) {
    console.error("[Autopilot] Cron error:", err.message);
  }
}

// Run once on startup after 60s delay, then every 3 days
setTimeout(() => {
  runAutopilotCron();
  setInterval(runAutopilotCron, AUTOPILOT_INTERVAL_MS);
}, 60000);


app.listen(PORT, "127.0.0.1", () => console.log(`DetectIQ API running on 127.0.0.1:${PORT}`));
