require("dotenv").config();
const express = require("express");
const compression = require("compression");
const yaml = require("js-yaml");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");
const { RedisStore } = require("rate-limit-redis");
const { Queue, Worker, QueueEvents } = require("bullmq");
const { BedrockRuntimeClient, InvokeModelCommand, InvokeModelWithResponseStreamCommand } = require("@aws-sdk/client-bedrock-runtime");
const { createClient } = require("redis");
const crypto = require("crypto");
const { jsonrepair } = require("jsonrepair");
const { createClient: createSupabaseClient } = require("@supabase/supabase-js");
const supabase = createSupabaseClient(
  "https://gckbdtcguptlfulzekzx.supabase.co",
  process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY
);

// ── SIEM Push Audit Logger ────────────────────────────────────────────────────
async function logSiemPush({ userId, detectionId, detectionName, platform, status, message, ipAddress }) {
  try {
    await supabase.from("siem_push_audit").insert([{
      user_id: userId || null,
      detection_id: detectionId || null,
      detection_name: detectionName || null,
      platform,
      status,
      message: message?.slice(0, 500) || null,
      ip_address: ipAddress || null,
    }]);
  } catch(e) { console.error("[AUDIT] Log failed:", e.message); }
}

const PORT = process.env.PORT || 3001;
const app = express();
app.set("trust proxy", 1); // Trust Cloudflare proxy
const startTime = Date.now();

// ── Redis client ──────────────────────────────────────────────────────────────
const REDIS_URL = process.env.REDIS_URL || "redis://127.0.0.1:6379";
const redis = createClient({ url: REDIS_URL });
redis.connect().then(() => console.log("Redis connected")).catch(e => console.error("Redis error:", e));

// ── BullMQ job queue (async processing for heavy AI calls) ─────────────────────
const redisConnection = { url: REDIS_URL };
const aiQueue = new Queue("ai-jobs", { connection: redisConnection });
const queueEvents = new QueueEvents("ai-jobs", { connection: redisConnection });
const jobResults = new Map(); // in-memory store for job results (TTL managed separately)

const aiWorker = new Worker("ai-jobs", async (job) => {
  const { type, payload } = job.data;

  if (type === "ml-enhance") {
    const { name, query, queryType, tactic, severity, threat } = payload;
    const querySnippet = (query || "").slice(0, 600);
    const prompt = `You are an expert detection engineer specializing in machine learning, UBA, and risk-based alerting for SIEM platforms.

Detection Name: ${name}
Query Type: ${queryType || "SPL"}
Tactic: ${tactic || "Unknown"}
Severity: ${severity || "Medium"}
Threat: ${(threat || "").slice(0, 200)}
Original Query (excerpt):
${querySnippet}

Generate concise ML/UBA/RBA enhancements. Keep all queries to 1-3 lines. Keep all text fields to 1 sentence max. Return ONLY valid JSON:
{
  "ml_approach": "one sentence, max 15 words",
  "ml_query": "1-3 line ${queryType||"SPL"} query using eventstats/streamstats z-score or stdev",
  "ml_explanation": "one sentence explaining the ML logic",
  "uba_pattern": "one sentence describing the behavior pattern",
  "uba_query": "1-3 line ${queryType||"SPL"} query baselining per user/host",
  "risk_modifier_rule": "compact Splunk ES risk modifier: eval risk_score, risk_object, risk_object_type then collect into risk index",
  "risk_score": 60,
  "risk_factors": ["6 words max", "6 words max"],
  "anomaly_threshold": "one line threshold, e.g. z_score >= 3",
  "baseline_window": "e.g. 30d rolling"
}`;
    const resp = await bedrock.send(new InvokeModelCommand({
      modelId: SONNET,
      body: JSON.stringify({ anthropic_version:"bedrock-2023-05-31", max_tokens:6000,
        system:"Expert detection engineer. Return ONLY valid JSON, no markdown, no code fences.",
        messages:[{role:"user",content:prompt}] }),
      contentType:"application/json", accept:"application/json"
    }));
    const raw = JSON.parse(new TextDecoder().decode(resp.body)).content[0].text;
    const m = raw.match(/\{[\s\S]*\}/);
    if (!m) throw new Error("No JSON in response");
    return JSON.parse(require("jsonrepair").jsonrepair(m[0]));
  }

  if (type === "workflow") {
    const { name, query, queryType, tactic, severity, threat, mitre_id } = payload;
    const prompt = `You are a SOAR engineer designing an automated response workflow for a security detection.

Detection: ${name}
MITRE ID: ${mitre_id || "unknown"}
Tactic: ${tactic || "Unknown"}
Severity: ${severity || "Medium"}
Threat: ${(threat||"").slice(0,150)}
Query Type: ${queryType}

Design a complete automated response workflow. Return ONLY valid JSON with keys: workflow_name, description, steps (array), edges (array), xsoar_pseudocode, tines_description, key_integrations.`;
    const resp = await bedrock.send(new InvokeModelCommand({
      modelId: SONNET,
      body: JSON.stringify({ anthropic_version:"bedrock-2023-05-31", max_tokens:6000,
        system:"You are a SOAR engineer. Return ONLY valid JSON, no markdown, no code fences.",
        messages:[{role:"user",content:prompt}] }),
      contentType:"application/json", accept:"application/json"
    }));
    const raw = JSON.parse(new TextDecoder().decode(resp.body)).content[0].text;
    const m = raw.match(/\{[\s\S]*\}/);
    if (!m) throw new Error("No JSON in workflow response");
    return JSON.parse(require("jsonrepair").jsonrepair(m[0]));
  }

  throw new Error(`Unknown job type: ${type}`);
}, { connection: redisConnection, concurrency: 3 });

aiWorker.on("completed", (job, result) => {
  jobResults.set(job.id, { status: "done", result });
  setTimeout(() => jobResults.delete(job.id), 10 * 60 * 1000); // cleanup after 10min
});
aiWorker.on("failed", (job, err) => {
  jobResults.set(job.id, { status: "error", error: err.message });
  setTimeout(() => jobResults.delete(job.id), 5 * 60 * 1000);
});

// ── Compression (gzip ~70% bandwidth reduction) ───────────────────────────────
app.use(compression({ threshold: 1024 }));

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

app.use(express.json({ limit: "500kb" }));

// ── Rate limiters (Redis-backed — persists across restarts, works multi-instance) ──
const redisStore = (prefix) => new RedisStore({
  sendCommand: (...args) => redis.sendCommand(args),
  prefix,
});

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 60,
  standardHeaders: true, legacyHeaders: false,
  store: redisStore("rl:global:"),
  message: { error: "Too many requests, please try again in 15 minutes." },
  skip: (req) => req.path === "/api/health" || req.path === "/health",
});
const claudeLimiter = rateLimit({
  windowMs: 60 * 1000, max: 5,
  standardHeaders: true, legacyHeaders: false,
  store: redisStore("rl:claude:"),
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
const HAIKU = "us.anthropic.claude-haiku-4-5";

// ── Startup env-var validation ────────────────────────────────────────────────
const REQUIRED_ENV = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"];
const WARN_ENV = ["SUPABASE_SERVICE_ROLE_KEY", "REDIS_URL", "RESEND_API_KEY", "WEBHOOK_SECRET"];
const missingRequired = REQUIRED_ENV.filter(k => !process.env[k]);
if (missingRequired.length) {
  console.error("[STARTUP] FATAL — missing required env vars:", missingRequired.join(", "));
  process.exit(1);
}
WARN_ENV.forEach(k => { if (!process.env[k]) console.warn("[STARTUP] WARN — missing optional env var:", k); });

const IS_PROD = process.env.NODE_ENV === "production";
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || "";

// ── HMAC webhook signature verifier ───────────────────────────────────────────
function verifyWebhookSignature(req, res, next) {
  if (!WEBHOOK_SECRET) return next();
  const sig = req.headers["x-detectiq-signature"] || "";
  const body = JSON.stringify(req.body);
  const expected = "sha256=" + crypto.createHmac("sha256", WEBHOOK_SECRET).update(body).digest("hex");
  const match = sig.length === expected.length && crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
  if (!match) return res.status(401).json({ error: "Invalid webhook signature" });
  next();
}

// ── Safe error message helper ─────────────────────────────────────────────────
function safeError(e, fallback = "Internal server error") {
  if (IS_PROD) return fallback;
  return e?.message || fallback;
}

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

// ── /api/claude/stream ────────────────────────────────────────────────────────
app.post("/api/claude/stream", claudeLimiter, async (req, res) => {
  try {
    const { messages, system, max_tokens } = req.body;
    const sanitized = sanitizeMessages(messages);
    if (!sanitized || sanitized.length === 0) {
      return res.status(400).json({ error: "Invalid or missing messages array." });
    }
    const safeSystem = sanitizeString(system || "", 5000);
    const safeTokens = Math.min(Math.max(parseInt(max_tokens) || 1000, 1), 6000);

    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.flushHeaders();

    const command = new InvokeModelWithResponseStreamCommand({
      modelId: SONNET,
      contentType: "application/json",
      accept: "application/json",
      body: JSON.stringify({
        anthropic_version: "bedrock-2023-05-31",
        max_tokens: safeTokens,
        system: safeSystem,
        messages: sanitized,
      }),
    });

    const response = await bedrock.send(command);
    let fullText = "";

    for await (const event of response.body) {
      if (event.chunk?.bytes) {
        const decoded = JSON.parse(Buffer.from(event.chunk.bytes));
        if (decoded.type === "content_block_delta" && decoded.delta?.type === "text_delta") {
          const text = decoded.delta.text;
          fullText += text;
          res.write(`data: ${JSON.stringify({ text })}\n\n`);
        }
      }
    }

    res.write(`data: ${JSON.stringify({ done: true, fullText })}\n\n`);
    res.end();
  } catch (err) {
    console.error("Stream error:", err.message);
    try { res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`); res.end(); } catch {}
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

// ── /api/autopilot/run-source — TTP / Actor / Ransomware ─────────────────────
app.post("/api/autopilot/run-source", claudeLimiter, express.json(), async (req, res) => {
  const { sourceType, items, siemTool = "splunk", userId } = req.body;
  if (!userId) return res.status(400).json({ error: "userId required." });
  if (!items || items.length === 0) return res.status(400).json({ error: "No items provided." });
  const drafts = [];
  for (const item of items.slice(0, 5)) {
    let prompt;
    if (sourceType === "ttp") {
      prompt = `You are a detection engineer. Generate a ${siemTool.toUpperCase()} detection for MITRE ATT&CK.

Technique: ${item.id} — ${item.name}
Tactic: ${item.tactic}

Return ONLY valid JSON:
{
  "detection_name": "short descriptive rule name",
  "detection_query": "complete ${siemTool.toUpperCase()} query ready to deploy",
  "detection_tactic": "${item.tactic}",
  "detection_severity": "Critical|High|Medium|Low",
  "detection_summary": "one sentence explaining what this detects",
  "key_indicators": ["indicator1","indicator2","indicator3"]
}`;
    } else {
      prompt = `You are a detection engineer. Generate a ${siemTool.toUpperCase()} detection for threat actor activity.

Threat Actor / Group: ${item.actor_name}
Technique: ${item.ttp_id} — ${item.technique_name}
Tactic: ${item.tactic}
Source type: ${sourceType}

Return ONLY valid JSON:
{
  "detection_name": "short rule name referencing the actor/technique",
  "detection_query": "complete ${siemTool.toUpperCase()} query ready to deploy",
  "detection_tactic": "${item.tactic}",
  "detection_severity": "Critical",
  "detection_summary": "one sentence explaining what this detects for this specific threat actor",
  "key_indicators": ["indicator1","indicator2","indicator3"]
}`;
    }
    try {
      const resp = await bedrock.send(new InvokeModelCommand({ modelId: SONNET, contentType:"application/json", accept:"application/json",
        body: JSON.stringify({ anthropic_version:"bedrock-2023-05-31", max_tokens:1500, system:"Expert detection engineer. Return ONLY valid JSON.", messages:[{role:"user",content:prompt}] }) }));
      const text = JSON.parse(new TextDecoder().decode(resp.body)).content[0].text;
      let parsed;
      try { parsed = JSON.parse(jsonrepair(text.replace(/```json|```/g,"").trim())); }
      catch { parsed = { detection_name:`Detect ${item.id||item.ttp_id} - ${item.name||item.technique_name}`, detection_query:`// Generation failed for ${item.id||item.ttp_id}`, detection_tactic:item.tactic, detection_severity:"High", detection_summary:item.name||item.technique_name, key_indicators:[] }; }
      drafts.push({
        source_type: sourceType,
        draft_id: `${sourceType}-${(item.id||item.ttp_id||"").replace(/\./g,"_")}-${(item.actor_name||"").replace(/\s/g,"_")}`,
        ttp_id: item.id || item.ttp_id,
        technique_name: item.name || item.technique_name,
        actor_name: item.actor_name || null,
        siem_tool: siemTool,
        ...parsed
      });
    } catch(e) { console.error("Autopilot source draft error:", e.message); }
  }
  res.json({ drafts, count: drafts.length });
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

// ── /api/jobs/:id — poll async job result ────────────────────────────────────
app.get("/api/jobs/:id", async (req, res) => {
  const id = req.params.id;
  const local = jobResults.get(id);
  if (local) return res.json(local);
  // Job may still be queued/active — check BullMQ
  try {
    const job = await aiQueue.getJob(id);
    if (!job) return res.status(404).json({ error: "Job not found" });
    const state = await job.getState();
    if (state === "completed") return res.json({ status: "done", result: job.returnvalue });
    if (state === "failed") return res.status(500).json({ status: "error", error: job.failedReason });
    return res.json({ status: state }); // waiting, active, delayed
  } catch(e) {
    res.status(500).json({ error: e.message });
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

// ── /api/siem/data-requirements — AI analysis of detection data needs ────────
app.post("/api/siem/data-requirements", express.json(), async (req, res) => {
  const { name, query, queryType, tactic, severity, platform } = req.body;
  if (!query) return res.status(400).json({ error: "query required" });

  const platformPrompts = {
    elastic: `You are a detection engineering expert for Elastic Security. Analyze this ${queryType||"KQL"} detection query and return ONLY this JSON:
{
  "index_patterns": ["Elastic index patterns needed, e.g. logs-endpoint.events.*, winlogbeat-*, filebeat-*"],
  "data_streams": ["Elastic data streams, e.g. logs-endpoint.events.process-*"],
  "required_fields": [{"field": "field_name", "ecs_mapping": "ECS equivalent or null", "description": "what it is"}],
  "ecs_categories": ["ECS event categories, e.g. process, network, authentication, file"],
  "integrations": ["Elastic Agent integrations needed, e.g. endpoint, windows, system, network_traffic"],
  "beats": ["Beats modules needed, e.g. winlogbeat, filebeat, auditbeat, packetbeat"],
  "normalization_steps": ["step 1", "step 2"],
  "data_sources": ["specific log sources needed"],
  "notes": "important caveats about data availability or ECS mapping gaps"
}`,
    soar: `You are a detection engineering expert. Analyze this detection and return ONLY this JSON describing what data a SOAR platform needs to process it:
{
  "required_fields": [{"field": "field_name", "description": "what it is", "example": "example value"}],
  "recommended_playbook_actions": ["action 1 e.g. Enrich IP with VirusTotal", "action 2"],
  "data_sources": ["specific log sources needed"],
  "triage_checklist": ["check 1", "check 2"],
  "escalation_criteria": ["when to escalate e.g. risk_score > 2"],
  "false_positive_filters": ["common FP scenario 1", "common FP scenario 2"],
  "notes": "important caveats for SOAR automation"
}`,
    splunk: `You are a detection engineering expert for Splunk. Analyze this ${queryType||"SPL"} detection query and return ONLY this JSON:
{
  "indexes": ["Splunk index names referenced or recommended, e.g. windows, main, sysmon"],
  "sourcetypes": ["sourcetypes referenced or needed"],
  "required_fields": [{"field": "field_name", "cim_mapping": "CIM equivalent or null", "description": "what it is"}],
  "cim_datamodels": ["CIM data models needed, e.g. Endpoint, Network_Traffic, Authentication"],
  "normalization_steps": ["step 1", "step 2"],
  "data_sources": ["specific log sources needed, e.g. Windows Security Event Log, IIS logs"],
  "ta_recommendations": ["Splunk TA names that provide this data, e.g. Splunk_TA_windows"],
  "notes": "important caveats about data availability or common gaps"
}`
  };

  const systemPrompt = platformPrompts[platform] || platformPrompts.splunk;
  const prompt = `${systemPrompt}

Detection: ${name}
Tactic: ${tactic||"Unknown"}
Severity: ${severity||"Unknown"}
Query:
${query}`;
  try {
    const result = await callClaude([{ role: "user", content: prompt }], "Detection engineering data requirements analyst. Return only valid JSON.", 1000);
    const m = result.match(/\{[\s\S]*\}/);
    if (!m) return res.status(500).json({ error: "Could not parse AI response" });
    res.json(JSON.parse(m[0]));
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── /api/siem/push/* — server-side proxy to avoid browser CORS issues ─────────
app.post("/api/siem/push/splunk", express.json(), async (req, res) => {
  const { url, token, authMode, username, password, name, query, severity, description } = req.body;
  if (!url) return res.status(400).json({ error: "url required" });
  if (authMode === "basic" && (!username || !password)) return res.status(400).json({ error: "username and password required" });
  if (authMode !== "basic" && !token) return res.status(400).json({ error: "token required" });
  try {
    const target = url.replace(/\/$/, "") + "/services/saved/searches";
    const bodyStr = new URLSearchParams({
      name, search: query || "", description: description || "",
      "alert.severity": severity === "Critical" ? "5" : severity === "High" ? "4" : severity === "Medium" ? "3" : "2",
      "alert_type": "number of events", "alert_comparator": "greater than", "alert_threshold": "0",
      "dispatch.earliest_time": "-15m", "dispatch.latest_time": "now",
      "is_scheduled": "1", "cron_schedule": "*/15 * * * *",
    }).toString();
    const authHeader = authMode === "basic"
      ? "Basic " + Buffer.from(`${username}:${password}`).toString("base64")
      : "Bearer " + token;
    // Use https.request with rejectUnauthorized:false so on-prem self-signed certs work
    const https = require("https");
    const parsed = new URL(target);
    const statusCode = await new Promise((resolve, reject) => {
      const opts = {
        hostname: parsed.hostname, port: parsed.port || 8089,
        path: parsed.pathname + parsed.search, method: "POST",
        headers: { "Authorization": authHeader, "Content-Type": "application/x-www-form-urlencoded", "Content-Length": Buffer.byteLength(bodyStr) },
        rejectUnauthorized: false,
      };
      const r = https.request(opts, resp => { resolve(resp.statusCode); resp.resume(); });
      r.on("error", reject);
      r.write(bodyStr); r.end();
    });
    if (statusCode === 201 || statusCode === 200 || statusCode === 409) {
      const msg = statusCode === 409 ? "Saved search already exists in Splunk." : `Detection '${name}' pushed to Splunk as a scheduled saved search.`;
      logSiemPush({ userId: req.body.userId, detectionName: name, platform: "splunk", status: "success", message: msg, ipAddress: req.ip });
      res.json({ success: true, message: msg });
    } else {
      logSiemPush({ userId: req.body.userId, detectionName: name, platform: "splunk", status: "failure", message: "Splunk returned " + statusCode, ipAddress: req.ip });
      res.status(400).json({ error: `Splunk returned ${statusCode}. Check URL (port 8089), credentials, and that the management port is accessible.` });
    }
  } catch (e) {
    res.status(500).json({ error: "Could not reach Splunk: " + e.message });
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
      logSiemPush({ userId: req.body.userId, detectionName: req.body.name, platform: "elastic", status: "success", message: "Detection rule created in Kibana", ipAddress: req.ip });
      res.json({ success: true, message: "Rule '" + name + "' pushed to Elastic Security (disabled — review and enable in Detection Rules)." });
    } else {
      logSiemPush({ userId: req.body.userId, detectionName: req.body.name, platform: "elastic", status: "failure", message: "Elastic returned " + r.status, ipAddress: req.ip });
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
      logSiemPush({ userId: req.body.userId, detectionName: req.body.name, platform: "soar", status: "success", message: "Payload delivered to SOAR", ipAddress: req.ip });
      res.json({ success: true, message: "Payload delivered to SOAR webhook successfully." });
    } else {
      logSiemPush({ userId: req.body.userId, detectionName: req.body.name, platform: "soar", status: "failure", message: "SOAR returned " + r.status, ipAddress: req.ip });
      res.status(400).json({ error: "SOAR returned " + r.status + ". Verify the webhook URL and any required auth headers." });
    }
  } catch (e) {
    res.status(500).json({ error: "Could not reach SOAR webhook: " + e.message });
  }
});

// ── /api/siem/push/sentinel ───────────────────────────────────────────────────
app.post("/api/siem/push/sentinel", express.json(), async (req, res) => {
  const { url, token, name, query, severity, description, tactic, queryType } = req.body;
  if (!url || !token) return res.status(400).json({ error: "url and token required" });
  try {
    const sevMap = { Critical: "High", High: "High", Medium: "Medium", Low: "Low", Informational: "Informational" };
    const sentinelSev = sevMap[severity] || "Medium";
    const ruleId = name.replace(/[^a-zA-Z0-9-]/g, "-").toLowerCase().slice(0, 60) + "-" + Date.now().toString(36);
    const target = `${url.replace(/\/$/, "")}/providers/Microsoft.SecurityInsights/alertRules/${ruleId}?api-version=2023-02-01`;
    const payload = {
      kind: "Scheduled",
      properties: {
        displayName: name,
        description: description || name,
        severity: sentinelSev,
        query: query,
        queryFrequency: "PT1H",
        queryPeriod: "P1D",
        triggerOperator: "GreaterThan",
        triggerThreshold: 0,
        enabled: true,
        suppressionEnabled: false,
        tactics: tactic ? [tactic.replace(/\s+/g, "")] : [],
      },
    };
    const r = await fetch(target, {
      method: "PUT",
      headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const text = await r.text();
    if (r.ok || r.status === 201) {
      res.json({ success: true, message: "Scheduled Analytics Rule '" + name + "' created in Microsoft Sentinel." });
    } else {
      res.status(400).json({ error: "Sentinel returned " + r.status + ". Check workspace URL and Bearer token. " + text.slice(0, 300) });
    }
  } catch (e) {
    res.status(500).json({ error: "Could not reach Sentinel API: " + e.message });
  }
});

// ── /api/siem/push/qradar ─────────────────────────────────────────────────────
app.post("/api/siem/push/qradar", express.json(), async (req, res) => {
  const { url, token, name, query, severity, description, tactic } = req.body;
  if (!url || !token) return res.status(400).json({ error: "url and token required" });
  try {
    const target = `${url.replace(/\/$/, "")}/api/ariel/saved_searches`;
    const payload = { name, description: description || name, aql: query };
    const r = await fetch(target, {
      method: "POST",
      headers: { "SEC": token, "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify(payload),
    });
    const text = await r.text();
    if (r.ok || r.status === 201) {
      res.json({ success: true, message: "Saved search '" + name + "' created in QRadar Ariel." });
    } else {
      res.status(400).json({ error: "QRadar returned " + r.status + ". Check base URL and SEC token. " + text.slice(0, 300) });
    }
  } catch (e) {
    res.status(500).json({ error: "Could not reach QRadar: " + e.message });
  }
});

// ── /api/siem/push/chronicle ──────────────────────────────────────────────────
app.post("/api/siem/push/chronicle", express.json(), async (req, res) => {
  const { name, query, severity, tactic } = req.body;
  if (!name || !query) return res.status(400).json({ error: "name and query required" });
  function generateYaraL(name, query, severity, tactic) {
    const ruleName = name.replace(/[^a-zA-Z0-9_]/g, "_").toLowerCase();
    const sevComment = severity ? severity.toUpperCase() : "MEDIUM";
    const tacticComment = tactic || "Unknown";
    return `rule ${ruleName} {
  meta:
    author = "DetectIQ"
    description = "${name}"
    severity = "${sevComment}"
    tactic = "${tacticComment}"
    reference = "https://detect-iq.com"

  events:
    // Query context: ${query.split("\n")[0].slice(0, 120)}
    $e.metadata.event_type = "PROCESS_LAUNCH"

  condition:
    $e
}`;
  }
  const rule = generateYaraL(name, query, severity, tactic);
  res.json({ success: true, message: "Chronicle YARA-L rule generated. Copy it into Chronicle > Detection Engine > Rules.", rule });
});

// ── /api/siem/push/crowdstrike ────────────────────────────────────────────────
app.post("/api/siem/push/crowdstrike", express.json(), async (req, res) => {
  const { name, query, severity, tactic, description } = req.body;
  if (!name || !query) return res.status(400).json({ error: "name and query required" });
  const sevMap = { Critical: "Critical", High: "High", Medium: "Medium", Low: "Low" };
  const sevValue = sevMap[severity] || "Medium";
  const ruleName = (name || "detection").replace(/[^a-zA-Z0-9_\-\s]/g, "").replace(/\s+/g, "_").toLowerCase();
  const ruleText = `// CrowdStrike Falcon Custom IOA Rule
// Name: ${name}
// Tactic: ${tactic || "Unknown"}
// Severity: ${sevValue}
// Description: ${description || name}
// Generated by DetectIQ
//
// Deploy: Falcon Console > Endpoint Security > Custom IOA Rules > New Rule Group
// Paste the FQL expression below into the field appropriate for your event type.
//
// FQL Detection Query:
${query}`;
  const ruleJson = JSON.stringify({
    ruletype_name: "Process Creation",
    name,
    description: description || `${tactic || "Unknown"} — Severity: ${sevValue}`,
    pattern_severity: sevValue,
    enabled: true,
    field_values: [
      { name: "CommandLine", type: "excludable", values: [{ label: "include", value: query.split("\n").find(l => l.trim()) || "" }] }
    ]
  }, null, 2);
  res.json({ success: true, message: "CrowdStrike FQL rule generated. Import via Falcon Custom IOA Rules.", rule: ruleText, ruleJson });
});

// ── /api/siem/push/logscale ───────────────────────────────────────────────────
app.post("/api/siem/push/logscale", express.json(), async (req, res) => {
  const { url, token, repo, name, query, description } = req.body;
  if (!url || !token || !repo) return res.status(400).json({ error: "url, token, and repo required" });
  try {
    const target = `${url.replace(/\/$/, "")}/api/v1/repositories/${encodeURIComponent(repo)}/saved-queries`;
    const payload = { name, queryString: query, description: description || name, start: "1h", end: "now", isLive: false };
    const r = await fetch(target, {
      method: "POST",
      headers: { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const text = await r.text();
    if (r.ok || r.status === 201) {
      res.json({ success: true, message: `Saved query '${name}' created in LogScale repository '${repo}'.` });
    } else {
      res.status(400).json({ error: `LogScale returned ${r.status}. Check URL, token, and repository name. ${text.slice(0, 200)}` });
    }
  } catch (e) {
    res.status(500).json({ error: "Could not reach LogScale: " + e.message });
  }
});

// ── /api/siem/push/tanium ─────────────────────────────────────────────────────
app.post("/api/siem/push/tanium", express.json(), async (req, res) => {
  const { name, query, severity, tactic, description } = req.body;
  if (!name || !query) return res.status(400).json({ error: "name and query required" });
  const signal = {
    name,
    description: description || name,
    source_guid: `detectiq-${Date.now()}`,
    platforms: ["Windows"],
    mitreAttack: { technique: tactic || "Unknown", url: "" },
    severity: severity || "Medium",
    query: { expression: query, platforms: ["Windows"] },
    created: new Date().toISOString(),
    author: "DetectIQ",
  };
  const ruleText = `// Tanium Signal
// Name: ${name}
// Severity: ${severity || "Medium"}
// Tactic: ${tactic || "Unknown"}
// Generated by DetectIQ
//
// Signal Expression:
${query}

// Deploy: Tanium Console > Threat Response > Signals > Import
// Or POST to Tanium REST API: /plugin/products/threat-response/api/v1/signals`;
  res.json({ success: true, message: "Tanium Signal generated. Import via Threat Response > Signals.", rule: ruleText, signalJson: JSON.stringify(signal, null, 2) });
});

// ── /api/siem/push/panther ────────────────────────────────────────────────────
app.post("/api/siem/push/panther", claudeLimiter, express.json(), async (req, res) => {
  const { detection } = req.body;
  if (!detection) return res.status(400).json({ error: "detection required." });
  try {
    const { name, query, tactic, technique, severity, queryType, threat } = detection;
    const prompt = `Convert this ${queryType || "SIEM"} detection to a Panther Python rule.

Detection name: ${name}
Tactic: ${tactic || ""}
Technique: ${technique || ""}
Severity: ${severity || "medium"}
Threat/Description: ${threat || ""}
Query:
${query}

Return ONLY a complete Python file with:
- rule(event) function returning True when the detection fires
- title(event) function returning a descriptive string
- severity() function returning "CRITICAL", "HIGH", "MEDIUM", or "LOW"
- MITRE ATT&CK tags in a comment header
No explanation, no markdown fences.`;
    const command = new InvokeModelCommand({
      modelId: SONNET,
      contentType: "application/json",
      accept: "application/json",
      body: JSON.stringify({
        anthropic_version: "bedrock-2023-05-31",
        max_tokens: 4000,
        system: "You are an expert detection engineer specializing in Panther Python rules. Always return valid Python only.",
        messages: [{ role: "user", content: prompt }],
      }),
    });
    const response = await bedrock.send(command);
    const result = JSON.parse(Buffer.from(response.body));
    let python = result.content?.[0]?.text || "";
    python = python.replace(/^```[a-z]*\n?/i, "").replace(/\n?```$/i, "").trim();
    res.json({ success: true, rule: python });
  } catch (e) {
    res.status(500).json({ error: "Panther rule generation failed: " + e.message });
  }
});

// ── /api/siem/push/sumo ───────────────────────────────────────────────────────
app.post("/api/siem/push/sumo", express.json(), async (req, res) => {
  const { url, accessId, accessKey, name, query, description } = req.body;
  if (!url || !accessId || !accessKey) return res.status(400).json({ error: "url, accessId, and accessKey required" });
  try {
    const target = `${url.replace(/\/$/, "")}/api/v1/savedSearchesWithSchedule`;
    const payload = {
      type: "SavedSearchWithScheduleSyncDefinition",
      name,
      description: description || name,
      search: { queryText: query, defaultTimeRange: "-15m", queryParameters: [], parsingMode: "AutoParse" },
      searchSchedule: {
        cronExpression: "0/15 * * * ?",
        displayableTimeRange: "-15m",
        parseableTimeRange: { type: "BeginBoundedTimeRange", from: { type: "RelativeTimeRangeBoundary", relativeTime: "-15m" }, to: null },
        timeZone: "UTC",
        threshold: { thresholdType: "group", operator: "gt", count: 0 },
        notification: { taskType: "EmailSearchNotificationSyncDefinition", toList: [], subjectTemplate: `[DetectIQ] ${name} Fired`, includeQuery: true, includeResultSet: true, includeHistogram: false, includeCsvAttachment: false },
        scheduleType: "15Minutes",
        muteErrorEmails: false,
      },
    };
    const auth = "Basic " + Buffer.from(`${accessId}:${accessKey}`).toString("base64");
    const r = await fetch(target, {
      method: "POST",
      headers: { "Authorization": auth, "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const text = await r.text();
    if (r.ok || r.status === 200 || r.status === 201) {
      res.json({ success: true, message: `Scheduled saved search '${name}' created in Sumo Logic (runs every 15 min).` });
    } else {
      res.status(400).json({ error: `Sumo Logic returned ${r.status}. Check your API endpoint (e.g. api.us2.sumologic.com) and access keys. ${text.slice(0, 300)}` });
    }
  } catch (e) {
    res.status(500).json({ error: "Could not reach Sumo Logic: " + e.message });
  }
});

// ── /api/detection/quality-score ──────────────────────────────────────────────
app.post("/api/detection/quality-score", claudeLimiter, express.json(), async (req, res) => {
  const { name, query, queryType, tactic, severity, description } = req.body;
  if (!name || !query) return res.status(400).json({ error: "name and query required" });
  const prompt = `Score this ${queryType||"detection"} rule. Be brief — max 8 words per note.

Name: ${name} | Tactic: ${tactic||"?"} | Severity: ${severity||"?"}
Query: ${(query||"").slice(0,300)}

Return ONLY valid JSON:
{
  "overall": 78,
  "breakdown": {
    "query_quality": { "score": 85, "notes": "8 words max" },
    "fp_risk": { "score": 70, "notes": "8 words max" },
    "coverage": { "score": 80, "notes": "8 words max" },
    "mitre_alignment": { "score": 75, "notes": "8 words max" },
    "data_requirements": { "score": 82, "notes": "8 words max" }
  },
  "strengths": ["max 6 words", "max 6 words"],
  "weaknesses": ["max 6 words"],
  "recommendations": ["max 10 words", "max 10 words"]
}`;
  try {
    const command = new InvokeModelCommand({
      modelId: SONNET,
      contentType: "application/json",
      accept: "application/json",
      body: JSON.stringify({
        anthropic_version: "bedrock-2023-05-31",
        max_tokens: 5000,
        system: "You are an expert detection engineer. Return only valid JSON, no markdown.",
        messages: [{ role: "user", content: prompt }],
      }),
    });
    const response = await bedrock.send(command);
    const result = JSON.parse(Buffer.from(response.body));
    const text = result.content?.[0]?.text || "";
    const m = text.match(/\{[\s\S]*\}/);
    if (!m) return res.status(500).json({ error: "Could not parse AI response" });
    res.json(JSON.parse(require("jsonrepair").jsonrepair(m[0])));
  } catch (e) {
    res.status(500).json({ error: "Quality score failed: " + e.message });
  }
});

// ── /api/teams/invite ─────────────────────────────────────────────────────────
app.post("/api/teams/invite", express.json(), async (req, res) => {
  const { inviterUserId, inviterEmail, inviteeEmail, teamName } = req.body;
  if (!inviteeEmail || !inviteeEmail.includes("@")) return res.status(400).json({ error: "Valid invitee email required." });
  const token = Buffer.from(JSON.stringify({ inviterUserId, inviteeEmail, teamName, ts: Date.now() })).toString("base64");
  const inviteLink = `https://detect-iq.com?invite=${token}`;
  const RESEND_KEY = process.env.RESEND_API_KEY;
  if (RESEND_KEY) {
    try {
      await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: { "Authorization": `Bearer ${RESEND_KEY}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          from: "DetectIQ <noreply@detect-iq.com>",
          to: [inviteeEmail],
          subject: `You've been invited to ${teamName || "a team"} on DetectIQ`,
          html: `<div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px"><h2 style="color:#00d4ff">You've been invited to DetectIQ</h2><p>${inviterEmail || "A colleague"} has invited you to join <strong>${teamName || "their team"}</strong> on DetectIQ.</p><a href="${inviteLink}" style="display:inline-block;margin:20px 0;padding:12px 28px;background:#00d4ff;color:#05080f;border-radius:7px;font-weight:700;text-decoration:none">Accept Invitation</a><p style="color:#666;font-size:13px">If you didn't expect this invitation, you can safely ignore this email.</p></div>`
        })
      });
    } catch(e) { console.error("Invite email error:", e.message); }
  }
  res.json({ success: true, token });
});

// ── /api/teams/accept ─────────────────────────────────────────────────────────
app.post("/api/teams/accept", express.json(), async (req, res) => {
  const { token, userId } = req.body;
  if (!token) return res.status(400).json({ error: "token required" });
  try {
    const decoded = JSON.parse(Buffer.from(token, "base64").toString("utf8"));
    const { inviterUserId, inviteeEmail, teamName } = decoded;
    res.json({ success: true, inviterUserId, inviteeEmail, teamName });
  } catch(e) {
    res.status(400).json({ error: "Invalid invite token." });
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
        max_tokens: 4000,
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

// GET /api/detections?userId=xxx
app.get("/api/detections", async (req, res) => {
  const { userId } = req.query;
  if (!userId) return res.status(400).json({ error: "userId required." });
  try {
    const { data, error } = await supabase.from("detections").select("*").eq("user_id", userId).order("created_at", { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    res.json({ detections: data || [], count: (data || []).length });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/detections/bulk-import
app.post("/api/detections/bulk-import", express.json(), async (req, res) => {
  const { userId, detections: dets } = req.body || {};
  if (!userId) return res.status(400).json({ error: "userId required." });
  if (!Array.isArray(dets)) return res.status(400).json({ error: "detections must be an array." });
  if (dets.length > 50) return res.status(400).json({ error: "Maximum 50 detections per import." });
  try {
    const rows = dets.map(d => ({
      user_id: userId,
      name: d.name || "Untitled",
      query: d.query || "",
      tool: d.tool || d.queryType || "splunk",
      tactic: d.tactic || "Unknown",
      severity: d.severity || "Medium",
      description: d.threat || d.description || "",
      tags: d.tags || [],
      score: d.score || 0,
    }));
    const { data, error } = await supabase.from("detections").insert(rows).select();
    if (error) return res.status(500).json({ error: error.message });
    res.json({ imported: (data || []).length, detections: data || [] });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/detections/version
app.post("/api/detections/version", express.json(), async (req, res) => {
  const { detectionId, userId, query, name, notes } = req.body || {};
  if (!detectionId || !userId) return res.status(400).json({ error: "detectionId and userId required." });
  try {
    const { error } = await supabase.from("detection_versions").insert([{
      detection_id: detectionId,
      user_id: userId,
      query: query || "",
      name: name || "",
      notes: notes || "",
      created_at: new Date().toISOString(),
    }]);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/detections/versions/:detectionId
app.get("/api/detections/versions/:detectionId", async (req, res) => {
  const { detectionId } = req.params;
  try {
    const { data, error } = await supabase.from("detection_versions").select("*").eq("detection_id", detectionId).order("created_at", { ascending: false }).limit(20);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ versions: data || [] });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── /api/detection/test ───────────────────────────────────────────────────────
app.post("/api/detection/test", claudeLimiter, express.json(), async (req, res) => {
  const { name, query, queryType, tool, tactic, severity, threat } = req.body;
  if (!query) return res.status(400).json({ error: "query required" });
  const prompt = `You are a detection engineer testing a SIEM detection rule against simulated attack logs.

Detection Rule:
Name: ${name}
Platform: ${queryType || tool || "Unknown"}
Tactic: ${tactic || "Unknown"}
Severity: ${severity || "Medium"}
Query:
${query.slice(0, 800)}

Generate a realistic test scenario and return ONLY this JSON:
{
  "verdict": "MATCH" or "NO_MATCH" or "PARTIAL_MATCH",
  "confidence": 85,
  "test_logs": [
    {
      "log": "exact realistic log line in the correct SIEM format",
      "matches": true,
      "reason": "which part of the query matched this log"
    },
    {
      "log": "another realistic log line",
      "matches": false,
      "reason": "why this log does NOT trigger the detection"
    }
  ],
  "true_positive_scenario": "specific attack scenario that would trigger this detection",
  "false_positive_scenario": "common benign activity that might also trigger this",
  "coverage_gaps": ["attack variation 1 this would miss", "attack variation 2 this would miss"],
  "tuning_suggestion": "one specific field or condition to add to reduce false positives",
  "estimated_fp_rate": "Low/Medium/High",
  "data_sources_required": ["log source 1", "log source 2"]
}`;
  try {
    const command = new InvokeModelCommand({
      modelId: SONNET,
      contentType: "application/json",
      accept: "application/json",
      body: JSON.stringify({
        anthropic_version: "bedrock-2023-05-31",
        max_tokens: 4000,
        system: "You are an expert detection engineer. Return ONLY valid JSON.",
        messages: [{ role: "user", content: prompt }],
      }),
    });
    const response = await bedrock.send(command);
    const result = JSON.parse(Buffer.from(response.body));
    const text = result.content?.[0]?.text || "";
    const m = text.match(/\{[\s\S]*\}/);
    if (!m) return res.status(500).json({ error: "Could not parse test result" });
    const parsed = JSON.parse(jsonrepair(m[0]));
    parsed.passed = parsed.verdict === "MATCH" || parsed.verdict === "PARTIAL_MATCH";
    parsed.summary = parsed.verdict === "MATCH" ? "Detection logic matched the simulated attack logs."
      : parsed.verdict === "PARTIAL_MATCH" ? "Detection partially matched — review coverage gaps below."
      : "Detection did not match simulated logs — review tuning suggestions.";
    res.json(parsed);
  } catch (e) {
    console.error("detection/test error:", e);
    res.status(500).json({ error: "Detection test failed: " + e.message });
  }
});

// ── /api/siem/audit ───────────────────────────────────────────────────────────
app.get("/api/siem/audit", async (req, res) => {
  const { userId, limit = 50 } = req.query;
  if (!userId) return res.status(400).json({ error: "userId required" });
  try {
    const { data, error } = await supabase
      .from("siem_push_audit")
      .select("*")
      .eq("user_id", userId)
      .order("created_at", { ascending: false })
      .limit(Math.min(parseInt(limit) || 50, 200));
    if (error) throw error;
    res.json({ audit: data || [], count: (data || []).length });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── /api/community/share ──────────────────────────────────────────────────────
app.post("/api/community/share", express.json(), async (req, res) => {
  const { detection, userId, authorName } = req.body;
  if (!detection || !userId) return res.status(400).json({ error: "detection and userId required" });
  try {
    const { data, error } = await supabase.from("community_detections").upsert([{
      detection_id: detection.id,
      user_id: userId,
      author_name: authorName || "Anonymous",
      name: detection.name,
      query: detection.query,
      tool: detection.tool,
      query_type: detection.queryType,
      tactic: detection.tactic,
      severity: detection.severity,
      threat: detection.threat || "",
      tags: detection.tags || [],
      score: detection.score || 0,
      is_public: true,
      updated_at: new Date().toISOString(),
    }], { onConflict: "detection_id" }).select().single();
    if (error) throw error;
    res.json({ success: true, id: data.id });
  } catch(e) {
    res.status(500).json({ error: "Share failed: " + e.message });
  }
});

// ── /api/community/unshare ────────────────────────────────────────────────────
app.post("/api/community/unshare", express.json(), async (req, res) => {
  const { detectionId, userId } = req.body;
  if (!detectionId || !userId) return res.status(400).json({ error: "detectionId and userId required" });
  try {
    await supabase.from("community_detections").update({ is_public: false }).eq("detection_id", detectionId).eq("user_id", userId);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── /api/community/list ───────────────────────────────────────────────────────
app.get("/api/community/list", async (req, res) => {
  const { tactic, tool, sort = "stars", limit = 30, search } = req.query;
  try {
    let q = supabase.from("community_detections").select("*").eq("is_public", true);
    if (tactic && tactic !== "All") q = q.eq("tactic", tactic);
    if (tool && tool !== "All") q = q.eq("tool", tool);
    if (search) q = q.ilike("name", "%" + search + "%");
    q = q.order(sort === "new" ? "created_at" : "stars", { ascending: false }).limit(Math.min(parseInt(limit) || 30, 100));
    const { data, error } = await q;
    if (error) throw error;
    res.json({ detections: data || [], count: (data || []).length });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── /api/community/star ───────────────────────────────────────────────────────
app.post("/api/community/star", express.json(), async (req, res) => {
  const { id } = req.body;
  if (!id) return res.status(400).json({ error: "id required" });
  try {
    await supabase.rpc("increment_stars", { row_id: id }).catch(() =>
      supabase.from("community_detections").select("stars").eq("id", id).single()
        .then(({ data }) => supabase.from("community_detections").update({ stars: (data?.stars || 0) + 1 }).eq("id", id))
    );
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── /api/community/clone ──────────────────────────────────────────────────────
app.post("/api/community/clone", express.json(), async (req, res) => {
  const { id, userId } = req.body;
  if (!id || !userId) return res.status(400).json({ error: "id and userId required" });
  try {
    const { data: src, error: fetchErr } = await supabase.from("community_detections").select("*").eq("id", id).single();
    if (fetchErr || !src) return res.status(404).json({ error: "Detection not found" });
    await supabase.from("community_detections").update({ clone_count: (src.clone_count || 0) + 1 }).eq("id", id);
    const newDet = { user_id: userId, name: src.name, query: src.query, tool: src.tool, tactic: src.tactic, severity: src.severity, description: src.threat || src.name, tags: src.tags || [], score: src.score || 0 };
    const { data: inserted, error: insertErr } = await supabase.from("detections").insert([newDet]).select().single();
    if (insertErr) throw insertErr;
    res.json({ success: true, detection: inserted });
  } catch(e) { res.status(500).json({ error: "Clone failed: " + e.message }); }
});

// ── Atomic Red Team ───────────────────────────────────────────────────────────
const ATOMIC_TECHNIQUES = [
  "T1059.001","T1059.003","T1059.005","T1059.006","T1059.007",
  "T1547.001","T1053.005","T1136.001","T1543.003",
  "T1055.001","T1055.012","T1548.002","T1134.001",
  "T1070.001","T1070.004","T1036.005","T1562.001","T1027.001",
  "T1003.001","T1003.002","T1110.001","T1110.003","T1552.001","T1558.003",
  "T1082","T1083","T1087.001","T1087.002","T1069.001","T1057","T1018",
  "T1021.001","T1021.002","T1021.006","T1550.002",
  "T1005","T1056.001","T1113","T1114.001",
  "T1071.001","T1095","T1105",
  "T1041","T1048.003",
  "T1486","T1490","T1489","T1529",
  "T1566.001","T1566.002","T1190","T1078.002",
];
const ATOMIC_TACTIC_MAP = {
  "T1059":"Execution","T1547":"Persistence","T1053":"Persistence","T1136":"Persistence","T1543":"Persistence",
  "T1055":"Privilege Escalation","T1548":"Privilege Escalation","T1134":"Privilege Escalation",
  "T1070":"Defense Evasion","T1036":"Defense Evasion","T1562":"Defense Evasion","T1027":"Defense Evasion",
  "T1003":"Credential Access","T1110":"Credential Access","T1552":"Credential Access","T1558":"Credential Access",
  "T1082":"Discovery","T1083":"Discovery","T1087":"Discovery","T1069":"Discovery","T1057":"Discovery","T1018":"Discovery",
  "T1021":"Lateral Movement","T1550":"Lateral Movement",
  "T1005":"Collection","T1056":"Collection","T1113":"Collection","T1114":"Collection",
  "T1071":"Command and Control","T1095":"Command and Control","T1105":"Command and Control",
  "T1041":"Exfiltration","T1048":"Exfiltration",
  "T1486":"Impact","T1490":"Impact","T1489":"Impact","T1529":"Impact",
  "T1566":"Initial Access","T1190":"Initial Access","T1078":"Initial Access",
};
let atomicCache = null;
let atomicCacheTime = 0;
const ATOMIC_CACHE_TTL = 24 * 60 * 60 * 1000;

async function fetchAtomicTests() {
  if (atomicCache && Date.now() - atomicCacheTime < ATOMIC_CACHE_TTL) return atomicCache;
  const results = [];
  await Promise.allSettled(ATOMIC_TECHNIQUES.map(async (tid) => {
    try {
      const url = `https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/${tid}/${tid}.yaml`;
      const res = await fetch(url, { signal: AbortSignal.timeout(8000) });
      if (!res.ok) return;
      const text = await res.text();
      const doc = yaml.load(text);
      if (!doc?.atomic_tests) return;
      const base = tid.split(".")[0];
      const tactic = ATOMIC_TACTIC_MAP[base] || "Other";
      doc.atomic_tests.slice(0, 3).forEach((test, i) => {
        const cmd = test.executor?.command || test.executor?.steps || "";
        const cleanup = test.executor?.cleanup_command || "";
        const args = test.input_arguments || {};

        // Resolve #{variable} placeholders with default values
        function resolveCmd(str) {
          if (typeof str !== "string") return "";
          return str.replace(/#\{(\w+)\}/g, (_, key) => {
            return args[key]?.default !== undefined ? String(args[key].default) : `<${key}>`;
          });
        }

        const rawCmd = typeof cmd === "string" ? cmd.trim().slice(0, 800) : "";
        const resolvedCmd = resolveCmd(rawCmd);

        results.push({
          id: `${tid}-${i}`,
          technique_id: tid,
          technique_name: doc.display_name || tid,
          tactic,
          test_name: test.name,
          description: (test.description||"").trim().slice(0, 400),
          platforms: test.supported_platforms || [],
          executor_name: test.executor?.name || "manual",
          command: rawCmd,
          resolved_command: resolvedCmd !== rawCmd ? resolvedCmd.slice(0, 800) : null,
          cleanup_command: typeof cleanup === "string" ? resolveCmd(cleanup).trim().slice(0, 400) : null,
          input_args: Object.entries(args).slice(0, 6).map(([k,v])=>({
            name: k,
            description: v.description || "",
            default: v.default !== undefined ? String(v.default).slice(0, 100) : "",
            type: v.type || "string",
          })),
          elevation_required: test.executor?.elevation_required || false,
        });
      });
    } catch {}
  }));
  atomicCache = results.sort((a, b) => a.tactic.localeCompare(b.tactic));
  atomicCacheTime = Date.now();
  return atomicCache;
}

app.get("/api/atomic-tests", async (req, res) => {
  try {
    const all = await fetchAtomicTests();
    const { tactic, platform, search, limit = 200 } = req.query;
    let filtered = all;
    if (tactic && tactic !== "All") filtered = filtered.filter(t => t.tactic === tactic);
    if (platform && platform !== "All") filtered = filtered.filter(t => t.platforms.includes(platform.toLowerCase()));
    if (search) {
      const q = search.toLowerCase();
      filtered = filtered.filter(t =>
        t.technique_id.toLowerCase().includes(q) ||
        t.technique_name.toLowerCase().includes(q) ||
        t.test_name.toLowerCase().includes(q) ||
        t.description.toLowerCase().includes(q)
      );
    }
    res.json({ tests: filtered.slice(0, Number(limit)), total: filtered.length });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Atomic: AI Simulate ───────────────────────────────────────────────────────
app.post("/api/atomic/simulate", claudeLimiter, express.json(), async (req, res) => {
  const { technique_id, technique_name, test_name, description, command, executor_name, platforms } = req.body;
  if (!technique_id || !command) return res.status(400).json({ error: "Missing required fields" });
  const prompt = `You are a cybersecurity expert simulating what happens when an attacker runs an Atomic Red Team test.

Technique: ${technique_id} - ${technique_name}
Test: ${test_name}
Platform: ${(platforms||[]).join(", ")}
Executor: ${executor_name}
Command:
${command}

Simulate this test. Be concise. CRITICAL: Return ONLY raw JSON, no markdown, no backslashes in strings, use forward slashes for paths, no quotes inside string values.

{
  "what_happens": "1 sentence: what this command does",
  "process_tree": ["parent -> child (key args only)"],
  "event_logs": [{"event_id": "4688", "source": "Security", "description": "brief", "key_fields": {"ProcessName": "x.exe", "CommandLine": "short"}}],
  "artifacts": ["one short artifact per item"],
  "detection_signals": ["EventID=4688 AND CommandLine contains x"],
  "cleanup_result": "one sentence"
}`;

  try {
    const resp = await bedrock.send(new InvokeModelCommand({
      modelId: SONNET,
      body: JSON.stringify({ anthropic_version:"bedrock-2023-05-31", max_tokens:2000, messages:[{role:"user",content:prompt}] }),
      contentType:"application/json", accept:"application/json"
    }));
    const raw = JSON.parse(new TextDecoder().decode(resp.body)).content[0].text;
    const m = raw.match(/\{[\s\S]*\}/);
    if (!m) return res.status(500).json({ error: "Could not parse simulation" });
    let parsed;
    try {
      parsed = JSON.parse(jsonrepair(m[0]));
    } catch(parseErr) {
      console.error("[simulate] JSON repair failed:", parseErr.message, m[0].slice(0, 300));
      return res.status(500).json({ error: "Simulation returned invalid JSON: " + parseErr.message });
    }
    res.json(parsed);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Atomic: Agent Job Queue ───────────────────────────────────────────────────
const atomicJobs = new Map(); // jobId → job object

app.post("/api/atomic/jobs", express.json(), async (req, res) => {
  const { test_id, command, cleanup_command, executor_name, platform, agent_key } = req.body;
  if (!command || !agent_key) return res.status(400).json({ error: "Missing command or agent_key" });
  const jobId = crypto.randomUUID();
  const job = {
    id: jobId, test_id, command, cleanup_command: cleanup_command||null,
    executor_name: executor_name||"powershell", platform: platform||"windows",
    agent_key, status: "pending", created_at: Date.now(),
    output: null, cleanup_output: null, error: null, completed_at: null
  };
  atomicJobs.set(jobId, job);
  // Auto-expire jobs after 30 min
  setTimeout(() => atomicJobs.delete(jobId), 30 * 60 * 1000);
  res.json({ job_id: jobId, status: "pending" });
});

// Agent polls this — returns oldest pending job for this key
app.get("/api/atomic/jobs/pending", (req, res) => {
  const { agent_key } = req.query;
  if (!agent_key) return res.status(400).json({ error: "Missing agent_key" });
  const job = [...atomicJobs.values()].find(j => j.agent_key === agent_key && j.status === "pending");
  if (!job) return res.json({ job: null });
  job.status = "running";
  res.json({ job });
});

// Agent posts results
app.post("/api/atomic/jobs/:id/result", express.json(), (req, res) => {
  const job = atomicJobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: "Job not found" });
  job.output = req.body.output || "";
  job.cleanup_output = req.body.cleanup_output || null;
  job.error = req.body.error || null;
  job.status = req.body.error ? "failed" : "completed";
  job.completed_at = Date.now();
  res.json({ ok: true });
});

// Frontend polls job status
app.get("/api/atomic/jobs/:id", (req, res) => {
  const job = atomicJobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: "Job not found" });
  res.json({ job_id: job.id, status: job.status, output: job.output, cleanup_output: job.cleanup_output, error: job.error, completed_at: job.completed_at });
});

// ── Agent script download ─────────────────────────────────────────────────────
app.get("/api/atomic/agent-script", (req, res) => {
  const { platform, key } = req.query;
  if (!key) return res.status(400).json({ error: "Missing agent key" });
  const apiBase = `${req.protocol}://${req.get("host")}`;

  if (platform === "windows") {
    res.setHeader("Content-Type", "text/plain");
    res.setHeader("Content-Disposition", 'attachment; filename="detectiq-agent.ps1"');
    res.send(`# DetectIQ Agent Script - Windows PowerShell
# Agent Key: ${key}
# This script polls DetectIQ for pending test jobs, executes them, and posts results back.

$AgentKey = "${key}"
$ApiBase = "${apiBase}"
$PollInterval = 10  # seconds between polls

Write-Host "[DetectIQ Agent] Starting. Agent key: $AgentKey" -ForegroundColor Cyan

while ($true) {
    try {
        $resp = Invoke-RestMethod -Uri "$ApiBase/api/atomic/jobs/pending?agent_key=$AgentKey" -Method GET -ErrorAction Stop

        if ($resp.job_id) {
            $JobId = $resp.job_id
            $Command = $resp.command
            $Cleanup = $resp.cleanup_command

            Write-Host "[DetectIQ Agent] Got job $JobId" -ForegroundColor Yellow
            Write-Host "[DetectIQ Agent] Command: $Command"

            $Output = ""
            $CleanupOutput = ""
            $Error = $null

            try {
                $Output = Invoke-Expression $Command 2>&1 | Out-String
                Write-Host "[DetectIQ Agent] Output: $Output"
            } catch {
                $Error = $_.Exception.Message
                Write-Host "[DetectIQ Agent] Error: $Error" -ForegroundColor Red
            }

            if ($Cleanup) {
                try {
                    $CleanupOutput = Invoke-Expression $Cleanup 2>&1 | Out-String
                    Write-Host "[DetectIQ Agent] Cleanup output: $CleanupOutput"
                } catch {
                    $CleanupOutput = "Cleanup error: $($_.Exception.Message)"
                }
            }

            $Body = @{ output = $Output; cleanup_output = $CleanupOutput; error = $Error } | ConvertTo-Json
            Invoke-RestMethod -Uri "$ApiBase/api/atomic/jobs/$JobId/result" -Method POST -Body $Body -ContentType "application/json" | Out-Null
            Write-Host "[DetectIQ Agent] Posted result for job $JobId" -ForegroundColor Green
        }
    } catch {
        # No pending jobs or network error, continue polling
    }

    Start-Sleep -Seconds $PollInterval
}
`);
  } else {
    // Linux / macOS bash
    res.setHeader("Content-Type", "text/plain");
    res.setHeader("Content-Disposition", 'attachment; filename="detectiq-agent.sh"');
    res.send(`#!/bin/bash
# DetectIQ Agent Script - Linux/macOS Bash
# Agent Key: ${key}
# This script polls DetectIQ for pending test jobs, executes them, and posts results back.

AGENT_KEY="${key}"
API_BASE="${apiBase}"
POLL_INTERVAL=10

echo "[DetectIQ Agent] Starting. Agent key: $AGENT_KEY"

while true; do
    RESP=$(curl -sf "$API_BASE/api/atomic/jobs/pending?agent_key=$AGENT_KEY" 2>/dev/null)

    if [ -n "$RESP" ]; then
        JOB_ID=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('job_id',''))" 2>/dev/null)
        COMMAND=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('command',''))" 2>/dev/null)
        CLEANUP=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('cleanup_command',''))" 2>/dev/null)

        if [ -n "$JOB_ID" ]; then
            echo "[DetectIQ Agent] Got job: $JOB_ID"
            echo "[DetectIQ Agent] Command: $COMMAND"

            OUTPUT=$(eval "$COMMAND" 2>&1) && ERROR="" || ERROR="Exit code $?"
            echo "[DetectIQ Agent] Output: $OUTPUT"

            CLEANUP_OUTPUT=""
            if [ -n "$CLEANUP" ]; then
                CLEANUP_OUTPUT=$(eval "$CLEANUP" 2>&1)
                echo "[DetectIQ Agent] Cleanup: $CLEANUP_OUTPUT"
            fi

            PAYLOAD=$(python3 -c "
import json, sys
print(json.dumps({'output': sys.argv[1], 'cleanup_output': sys.argv[2], 'error': sys.argv[3]}))
" "$OUTPUT" "$CLEANUP_OUTPUT" "$ERROR")

            curl -sf -X POST "$API_BASE/api/atomic/jobs/$JOB_ID/result" \
                -H "Content-Type: application/json" \
                -d "$PAYLOAD" > /dev/null

            echo "[DetectIQ Agent] Posted result for job $JOB_ID"
        fi
    fi

    sleep $POLL_INTERVAL
done
`);
  }
});

// ── ML / UBA / Risk-Based Alerting Enhancement (async via job queue) ──────────
app.post("/api/detection/ml-enhance", claudeLimiter, express.json(), async (req, res) => {
  const { name, query, queryType, tactic, severity, threat } = req.body;
  if (!name || !query) return res.status(400).json({ error: "name and query required" });
  try {
    const job = await aiQueue.add("ml-enhance", { type: "ml-enhance", payload: { name, query, queryType, tactic, severity, threat } });
    res.json({ jobId: job.id });
  } catch(e) {
    console.error("[ml-enhance] Queue error:", e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── Automated Response Workflow Generator (async via job queue) ───────────────
app.post("/api/detection/workflow", claudeLimiter, express.json(), async (req, res) => {
  const { name, query, queryType, tactic, severity, threat, mitre_id } = req.body;
  if (!name) return res.status(400).json({ error: "name required" });
  try {
    const job = await aiQueue.add("workflow", { type: "workflow", payload: { name, query, queryType, tactic, severity, threat, mitre_id } });
    res.json({ jobId: job.id });
  } catch(e) {
    console.error("[workflow] Queue error:", e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── Blast Radius Estimator ────────────────────────────────────────────────────
app.post("/api/detection/blast-radius", claudeLimiter, express.json(), async (req, res) => {
  const { name, query, queryType, tactic, severity } = req.body;
  if (!name || !query) return res.status(400).json({ error: "name and query required" });
  const prompt = `You are a detection engineering expert. Estimate how often this detection would fire across enterprise environments of different sizes based on its query logic and MITRE tactic.

Detection: ${name}
Query Type: ${queryType || "SPL"}
Tactic: ${tactic || "Unknown"}
Severity: ${severity || "Medium"}
Query (excerpt): ${(query||"").slice(0,400)}

Return ONLY valid JSON:
{
  "estimates": [
    {"org_size": 500, "endpoints": "~500 endpoints", "daily_alerts": 8, "fp_rate": "~25%", "noise_level": "Low", "recommendation": "Safe to deploy as-is"},
    {"org_size": 1000, "endpoints": "~1000 endpoints", "daily_alerts": 18, "fp_rate": "~28%", "noise_level": "Medium", "recommendation": "Add 2-3 exclusions first"},
    {"org_size": 5000, "endpoints": "~5000 endpoints", "daily_alerts": 85, "fp_rate": "~32%", "noise_level": "High", "recommendation": "Tune before deploying — risk of alert fatigue"},
    {"org_size": 10000, "endpoints": "~10000 endpoints", "daily_alerts": 170, "fp_rate": "~35%", "noise_level": "Very High", "recommendation": "Must tune — will overwhelm SOC queue"}
  ],
  "top_log_sources": ["Windows Security Event Log", "Sysmon"],
  "peak_hours": "Business hours 9am-6pm local",
  "tuning_recommendation": "one specific exclusion to cut noise by ~40%",
  "alert_fatigue_risk": "Medium",
  "benchmark": "Similar ${tactic} detections typically generate 15-40 alerts/day per 1000 endpoints",
  "cost_estimate": "At $0.003/alert for analyst triage, ~$X/month at 1000 endpoints"
}`;
  try {
    const resp = await bedrock.send(new InvokeModelCommand({ modelId: SONNET, contentType:"application/json", accept:"application/json",
      body: JSON.stringify({ anthropic_version:"bedrock-2023-05-31", max_tokens:2000, system:"Detection engineering expert. Return ONLY valid JSON.", messages:[{role:"user",content:prompt}] }) }));
    const raw = JSON.parse(new TextDecoder().decode(resp.body)).content[0].text;
    const m = raw.match(/\{[\s\S]*\}/); if(!m) return res.status(500).json({error:"No JSON in response"});
    res.json(JSON.parse(jsonrepair(m[0])));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── False Positive Estimator ──────────────────────────────────────────────────
app.post("/api/detection/false-positives", claudeLimiter, express.json(), async (req, res) => {
  const { name, query, queryType, tactic } = req.body;
  if (!name || !query) return res.status(400).json({ error: "name and query required" });
  const prompt = `You are a detection engineering expert. Analyze this detection query for realistic false positive scenarios in enterprise environments.

Detection: ${name}
Query Type: ${queryType || "SPL"}
Tactic: ${tactic || "Unknown"}
Query: ${(query||"").slice(0,500)}

Return ONLY valid JSON:
{
  "scenarios": [
    {
      "title": "IT Admin Legitimate Activity",
      "description": "System admins regularly run this for maintenance",
      "likelihood": "High",
      "affected_roles": "IT, SysAdmins, Helpdesk",
      "exclusion_query": "NOT (user IN ('svcaccount','admin') AND process_name='expected.exe')"
    }
  ],
  "overall_fp_rate": "~30%",
  "exclusion_template": "full ready-to-paste exclusion block for the ${queryType||"SPL"} query",
  "recommended_whitelist_fields": ["user", "dest", "process_name"],
  "tuning_priority": "High",
  "safe_to_deploy": false,
  "deploy_recommendation": "Add exclusions for IT admin accounts before deploying"
}`;
  try {
    const resp = await bedrock.send(new InvokeModelCommand({ modelId: SONNET, contentType:"application/json", accept:"application/json",
      body: JSON.stringify({ anthropic_version:"bedrock-2023-05-31", max_tokens:4000, system:"Detection engineering expert. Return ONLY valid JSON.", messages:[{role:"user",content:prompt}] }) }));
    const raw = JSON.parse(new TextDecoder().decode(resp.body)).content[0].text;
    const m = raw.match(/\{[\s\S]*\}/); if(!m) return res.status(500).json({error:"No JSON in response"});
    res.json(JSON.parse(jsonrepair(m[0])));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Honeytoken / Canary Generator ─────────────────────────────────────────────
app.post("/api/detection/honeytoken", claudeLimiter, express.json(), async (req, res) => {
  const { name, query, queryType, tactic, threat } = req.body;
  if (!name) return res.status(400).json({ error: "name required" });
  const prompt = `You are a deception security expert. Design honeytoken and canary traps that pair with this detection to catch attackers with 100% confidence.

Detection: ${name}
Tactic: ${tactic || "Unknown"}
Threat: ${(threat||"").slice(0,150)}
Query Type: ${queryType || "SPL"}

Design 3-4 honeytokens suited for this tactic. Return ONLY valid JSON:
{
  "tokens": [
    {
      "type": "Honey Credentials",
      "name": "svc_detectiq_honey01",
      "description": "Fake service account — any authentication attempt is malicious",
      "deployment_cmd": "net user svc_detectiq_honey01 'P@ssw0rd!Fake' /add /domain",
      "detection_query": "${queryType||"SPL"} query to detect access to this token",
      "alert_confidence": "100%",
      "platform": "Active Directory"
    }
  ],
  "canarytoken_types": ["DNS token", "HTTP token", "AWS key token"],
  "canarytoken_url": "https://canarytokens.org/generate",
  "deployment_guide": "Step-by-step: where to place each token in a ${tactic} attack path",
  "coverage_benefit": "Adds near-zero-FP tripwires across the ${tactic} attack chain"
}`;
  try {
    const resp = await bedrock.send(new InvokeModelCommand({ modelId: SONNET, contentType:"application/json", accept:"application/json",
      body: JSON.stringify({ anthropic_version:"bedrock-2023-05-31", max_tokens:4000, system:"Deception security expert. Return ONLY valid JSON.", messages:[{role:"user",content:prompt}] }) }));
    const raw = JSON.parse(new TextDecoder().decode(resp.body)).content[0].text;
    const m = raw.match(/\{[\s\S]*\}/); if(!m) return res.status(500).json({error:"No JSON in response"});
    res.json(JSON.parse(jsonrepair(m[0])));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── DNS Sinkhole Generator ────────────────────────────────────────────────────
app.post("/api/detection/dns-sinkhole", claudeLimiter, express.json(), async (req, res) => {
  const { name, query, threat, tactic } = req.body;
  if (!name) return res.status(400).json({ error: "name required" });
  const prompt = `You are a DNS security expert. Based on this detection context, infer likely C2/malicious domains and generate complete DNS sinkhole configurations.

Detection: ${name}
Tactic: ${tactic || "Unknown"}
Threat context: ${(threat||"").slice(0,200)}
Query context: ${(query||"").slice(0,300)}

Extract or infer 3-5 example malicious domains this detection would cover, then generate configs. Return ONLY valid JSON:
{
  "inferred_domains": ["c2.example-malware.com", "update.evil-actor.net"],
  "pihole_blocklist": "0.0.0.0 c2.example-malware.com\\n0.0.0.0 update.evil-actor.net",
  "bind9_rpz": "; RPZ zone file for BIND9\\n$TTL 60\\n@ IN SOA localhost. root.localhost. 1 1h 15m 30d 2m\\n@ IN NS localhost.\\nc2.example-malware.com IN CNAME .\\nupdate.evil-actor.net IN CNAME .",
  "windows_dns_rpz": "Add-DnsServerZone -Name 'block.local' -ReplicationScope Domain\\nAdd-DnsServerResourceRecord -ZoneName 'block.local' -Name 'c2.example-malware.com' -A -IPv4Address '0.0.0.0'",
  "unbound_conf": "local-zone: 'c2.example-malware.com' always_nxdomain\\nlocal-zone: 'update.evil-actor.net' always_nxdomain",
  "sinkhole_ip": "0.0.0.0",
  "sinkhole_detection_query": "SPL/KQL query: detect DNS queries resolving to sinkhole IP 0.0.0.0 — guaranteed malicious",
  "deployment_steps": ["1. Choose sinkhole IP (0.0.0.0 or internal honeypot)", "2. Configure your DNS server with the RPZ zone", "3. Add detection query to SIEM"],
  "ioc_feed_sources": ["abuse.ch", "URLhaus", "Feodo Tracker"]
}`;
  try {
    const resp = await bedrock.send(new InvokeModelCommand({ modelId: SONNET, contentType:"application/json", accept:"application/json",
      body: JSON.stringify({ anthropic_version:"bedrock-2023-05-31", max_tokens:4000, system:"DNS security expert. Return ONLY valid JSON.", messages:[{role:"user",content:prompt}] }) }));
    const raw = JSON.parse(new TextDecoder().decode(resp.body)).content[0].text;
    const m = raw.match(/\{[\s\S]*\}/); if(!m) return res.status(500).json({error:"No JSON in response"});
    res.json(JSON.parse(jsonrepair(m[0])));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── LOTL Coverage Generator ───────────────────────────────────────────────────
app.post("/api/detection/lotl-coverage", claudeLimiter, express.json(), async (req, res) => {
  const { name, tactic, queryType } = req.body;
  if (!tactic) return res.status(400).json({ error: "tactic required" });
  const prompt = `You are a detection expert specializing in Living-off-the-Land (LOTL) attacks. List all relevant LOLBins and LOLBas tools for this MITRE tactic and generate a ${queryType||"SPL"} detection query for each.

MITRE Tactic: ${tactic}
Detection context: ${name || "General"}
Query Type: ${queryType || "SPL"}

Return 8-12 LOLBins relevant to this tactic. Return ONLY valid JSON:
{
  "lolbins": [
    {
      "name": "certutil.exe",
      "risk": "High",
      "abuse": "Download malware, decode base64 payloads, bypass proxy",
      "mitre_techniques": ["T1105", "T1140"],
      "query": "${queryType||"SPL"} detection query (1-3 lines)",
      "prevalence": "Very Common — seen in 70% of campaigns"
    }
  ],
  "coverage_gap_summary": "X of Y LOTL binaries have no detections in most environments",
  "priority_order": ["certutil.exe", "mshta.exe", "regsvr32.exe"],
  "quick_win": "Detecting these 3 LOLBins covers 60% of LOTL-based ${tactic} attacks",
  "reference": "https://lolbas-project.github.io/"
}`;
  try {
    const resp = await bedrock.send(new InvokeModelCommand({ modelId: SONNET, contentType:"application/json", accept:"application/json",
      body: JSON.stringify({ anthropic_version:"bedrock-2023-05-31", max_tokens:3000, system:"LOTL detection expert. Return ONLY valid JSON.", messages:[{role:"user",content:prompt}] }) }));
    const raw = JSON.parse(new TextDecoder().decode(resp.body)).content[0].text;
    const m = raw.match(/\{[\s\S]*\}/); if(!m) return res.status(500).json({error:"No JSON in response"});
    res.json(JSON.parse(jsonrepair(m[0])));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Detection Chain / Correlation Generator ───────────────────────────────────
app.post("/api/detection/chain", claudeLimiter, express.json(), async (req, res) => {
  const { nameA, queryA, nameB, queryB, queryType, correlField, timeWindowMin, platform } = req.body;
  if (!nameA || !nameB) return res.status(400).json({ error: "nameA and nameB required" });
  const prompt = `You are a SIEM correlation expert. Generate a correlation rule that triggers when Detection A fires within ${timeWindowMin||15} minutes of Detection B for the same ${correlField||"host"}, indicating a multi-stage attack.

Detection A (early stage): ${nameA}
Detection A query: ${(queryA||"").slice(0,250)}

Detection B (later stage): ${nameB}
Detection B query: ${(queryB||"").slice(0,250)}

Correlation field: ${correlField||"host"}
Time window: ${timeWindowMin||15} minutes
Primary platform: ${platform||"Splunk"}

Return ONLY valid JSON:
{
  "correlation_name": "CHAIN: ${nameA} → ${nameB}",
  "description": "one sentence explaining the multi-stage attack pattern",
  "attack_narrative": "2-3 sentences explaining what the chained detections mean together",
  "risk_score": 95,
  "severity": "Critical",
  "splunk_correlation": "Splunk ES correlation SPL query using transaction or join",
  "elastic_query": "Elastic EQL sequence query",
  "sentinel_kql": "Microsoft Sentinel KQL query using sequence",
  "chronicle_udm": "Google Chronicle YARA-L 2.0 rule",
  "recommended_response": "immediate action to take when this fires",
  "mitre_techniques": ["T1xxx", "T1xxx"]
}`;
  try {
    const resp = await bedrock.send(new InvokeModelCommand({ modelId: SONNET, contentType:"application/json", accept:"application/json",
      body: JSON.stringify({ anthropic_version:"bedrock-2023-05-31", max_tokens:4000, system:"SIEM correlation expert. Return ONLY valid JSON.", messages:[{role:"user",content:prompt}] }) }));
    const raw = JSON.parse(new TextDecoder().decode(resp.body)).content[0].text;
    const m = raw.match(/\{[\s\S]*\}/); if(!m) return res.status(500).json({error:"No JSON in response"});
    res.json(JSON.parse(jsonrepair(m[0])));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Multi-Stage Detection Playbook ────────────────────────────────────────────
app.post("/api/detection/chain-playbook", claudeLimiter, express.json(), async (req, res) => {
  const { steps, correlField, timeWindowMin, platform } = req.body;
  if (!steps || steps.length < 2) return res.status(400).json({ error: "At least 2 steps required" });
  const chainArrow = steps.map(s => s.name).join(" → ");
  const stepsText = steps.map((s, i) =>
    `Stage ${i+1} (${s.tactic||"Unknown"}): ${s.name}\nQuery: ${(s.query||"").slice(0,200)}`
  ).join("\n\n");
  const prompt = `You are a SIEM correlation expert. Build a ${steps.length}-stage attack playbook correlation.

Attack chain: ${chainArrow}
Correlation entity: ${correlField||"host"}
Time window between stages: ${timeWindowMin||15} minutes
Primary platform: ${platform||"Splunk"}

Stages:
${stepsText}

Return ONLY valid JSON:
{
  "playbook_name": "APT: descriptive attack chain name",
  "attack_narrative": "3-4 sentence story of the full attack progression",
  "risk_score": 99,
  "severity": "Critical",
  "mitre_techniques": ["T1xxx","T1xxx"],
  "stage_summaries": ["1-line summary per stage, array of ${steps.length} strings"],
  "splunk_correlation": "Splunk ES multi-stage correlation SPL using transaction or sequence",
  "elastic_query": "Elastic EQL sequence query covering all ${steps.length} stages",
  "sentinel_kql": "Microsoft Sentinel KQL multi-stage query",
  "chronicle_udm": "Chronicle YARA-L 2.0 rule",
  "response_steps": ["ordered response actions (5-7 steps)"],
  "coverage_gap": "any detection gaps between stages",
  "recommended_additions": ["detections to add to strengthen the chain"]
}`;
  try {
    const resp = await bedrock.send(new InvokeModelCommand({ modelId: SONNET, contentType:"application/json", accept:"application/json",
      body: JSON.stringify({ anthropic_version:"bedrock-2023-05-31", max_tokens:5000, system:"SIEM correlation expert. Return ONLY valid JSON.", messages:[{role:"user",content:prompt}] }) }));
    const raw = JSON.parse(new TextDecoder().decode(resp.body)).content[0].text;
    const m = raw.match(/\{[\s\S]*\}/); if(!m) return res.status(500).json({error:"No JSON in response"});
    res.json(JSON.parse(jsonrepair(m[0])));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Log Replay / Dry Run ──────────────────────────────────────────────────────
app.post("/api/detection/replay", claudeLimiter, express.json(), async (req, res) => {
  const { query, queryType, logs } = req.body;
  if (!query || !logs) return res.status(400).json({ error: "query and logs required" });
  const lines = logs.split("\n").filter(l => l.trim()).slice(0, 200); // cap at 200 lines
  const prompt = `You are a SIEM query expert. Evaluate which of these log lines would match the given ${queryType||"SPL"} detection query. For each matching line, briefly explain why it matches.

Detection Query:
${(query||"").slice(0,600)}

Log Lines (numbered):
${lines.map((l,i)=>`${i+1}. ${l.slice(0,300)}`).join("\n")}

Return ONLY valid JSON:
{
  "match_indices": [1, 3, 7],
  "match_explanations": {
    "1": "Matches because field X equals expected value Y",
    "3": "Matches because process_name contains suspicious string"
  },
  "non_match_reasons": "Most lines don't match because they lack the required field Z",
  "match_rate": "3/10 lines (30%)",
  "query_analysis": "This query looks for X — in this log sample it would catch Y type events",
  "tuning_suggestion": "Consider broadening/narrowing field Z to capture more/fewer events"
}`;
  try {
    const resp = await bedrock.send(new InvokeModelCommand({ modelId: HAIKU, contentType:"application/json", accept:"application/json",
      body: JSON.stringify({ anthropic_version:"bedrock-2023-05-31", max_tokens:2000, system:"SIEM query expert. Return ONLY valid JSON.", messages:[{role:"user",content:prompt}] }) }));
    const raw = JSON.parse(new TextDecoder().decode(resp.body)).content[0].text;
    const m = raw.match(/\{[\s\S]*\}/); if(!m) return res.status(500).json({error:"No JSON in response"});
    const data = JSON.parse(jsonrepair(m[0]));
    // Attach matched/unmatched lines
    const matchSet = new Set((data.match_indices||[]).map(i=>i-1));
    data.matched_lines = lines.filter((_,i)=>matchSet.has(i));
    data.unmatched_lines = lines.filter((_,i)=>!matchSet.has(i));
    data.total_lines = lines.length;
    data.match_count = data.matched_lines.length;
    res.json(data);
  } catch(e) { res.status(500).json({ error: e.message }); }
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


// ── Health check ──────────────────────────────────────────────────────────────
app.get("/health", (req, res) => {
  const uptime = Math.floor((Date.now() - startTime) / 1000);
  res.json({
    status: "ok",
    uptime,
    pid: process.pid,
    memory: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + "MB",
    version: process.env.npm_package_version || "5.4"
  });
});

// ── 404 handler ───────────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: "Not found" }));

// ── Global error handler ──────────────────────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error("[ERROR]", err.message);
  const status = err.status || err.statusCode || 500;
  res.status(status).json({ error: IS_PROD ? "An error occurred" : err.message });
});

app.listen(PORT, "127.0.0.1", () => console.log(`DetectIQ API running on 127.0.0.1:${PORT}`));
