import { Router } from "express";
import { randomUUID } from "crypto";
import { invokeClaude } from "../ai.js";
import { supabaseAdmin } from "../supabaseAdmin.js";
import { tryConsumeBudget } from "../budgetLimiter.js";

const router = Router();

function sanitize(input, maxLen = 6000) {
  return String(input || "")
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .slice(0, maxLen);
}

const MAX_BATCH = 10;

const SYSTEM_PROMPT = `You are an offensive security engineer whose entire job is to break specific detection
rules by studying their literal logic — not by running a generic library of canned attack techniques.

Given a detection query, read exactly what it checks: which fields, which operators, which literal
values, which process names, which thresholds. Then think like an attacker who has read this exact
rule and wants to achieve the same underlying malicious outcome while evading these specific checks.

For each blind spot you find:
- Name it concretely (not "evasion #1" — something like "rundll32 parent instead of cmd.exe").
- Explain in one or two sentences exactly which literal check in the query it slips past.
- Generate ONE realistic raw log line that demonstrates this exact bypass — same log format/fields
  the original query expects, just with the evading values.
- Give a short, concrete suggested patch to the query that would close this specific gap.
- Rate its severity: "critical" if trivially exploitable with no special access, "high" if it needs
  common tooling but no special privilege, "medium" if it needs specific conditions, "low" if it's a
  narrow edge case.

Find 3-5 real blind spots. Do not pad with restatements of the same idea. If the query is already
tight and you can't find a genuine gap, say so honestly rather than inventing weak ones.

Respond ONLY as JSON, no markdown fences, no preamble:
{
  "blindspots": [
    { "name": string, "description": string, "evasion_sample": string, "suggested_patch": string, "severity": "low"|"medium"|"high"|"critical" }
  ],
  "overall_assessment": string
}`;

async function analyzeOne({ query, tool, name }) {
  const prompt = `Detection name: ${name || "unnamed"}\nSIEM: ${tool || "unspecified"}\nQuery:\n${query}`;
  const raw = await invokeClaude(prompt, { system: SYSTEM_PROMPT, maxTokens: 2600 });
  return JSON.parse(raw.replace(/```json|```/g, "").trim());
}

async function persistFindings({ userId, detectionId, runId, blindspots }) {
  if (!detectionId || !blindspots?.length) return;
  const rows = blindspots.map((b) => ({
    user_id: userId,
    detection_id: detectionId,
    run_id: runId,
    name: sanitize(b.name, 300),
    description: sanitize(b.description, 2000),
    evasion_sample: sanitize(b.evasion_sample, 2000),
    suggested_patch: sanitize(b.suggested_patch, 2000),
    severity: ["low", "medium", "high", "critical"].includes(b.severity) ? b.severity : "medium",
  }));
  const { error } = await supabaseAdmin.from("blindspot_findings").insert(rows);
  if (error) console.error("blindspot findings insert error:", error.message);
}

// POST /api/blindspot/analyze { query, tool, name, detectionId? }
// detectionId is optional — pasted ad-hoc queries just return ephemeral
// results; pass a real detectionId to also persist findings as tracked
// records against that detection.
router.post("/analyze", budgetLimiter, async (req, res) => {
  try {
    const query = sanitize(req.body?.query);
    const tool = sanitize(req.body?.tool, 64);
    const name = sanitize(req.body?.name, 200);
    const detectionId = req.body?.detectionId;
    if (!query) return res.status(400).json({ error: "query is required" });

    let parsed;
    try {
      parsed = await analyzeOne({ query, tool, name });
    } catch {
      return res.status(502).json({ error: "AI response could not be parsed. Try again." });
    }

    const runId = randomUUID();
    if (detectionId && req.user) {
      await persistFindings({ userId: req.user.id, detectionId, runId, blindspots: parsed.blindspots });
    }

    res.json({ ...parsed, run_id: runId });
  } catch (err) {
    console.error("blindspot/analyze error:", err.message);
    res.status(500).json({ error: "Blindspot analysis failed" });
  }
});

// POST /api/blindspot/scan { detectionIds: [...] }
// Batch mode — runs the agent across up to MAX_BATCH detections in one go,
// so you can find your weakest rules instead of checking one at a time.
// Each detection is a real, separate AI call — this is genuinely N calls,
// not one, and is accounted against the daily budget per-detection.
router.post("/scan", async (req, res) => {
  try {
    if (!req.user) return res.status(401).json({ error: "Sign in required" });

    const detectionIds = Array.isArray(req.body?.detectionIds) ? req.body.detectionIds.slice(0, MAX_BATCH) : [];
    if (detectionIds.length === 0) return res.status(400).json({ error: "detectionIds is required (max 10)" });

    const { data: detections, error: fetchErr } = await supabaseAdmin
      .from("detections")
      .select("id,name,query,tool")
      .in("id", detectionIds)
      .eq("user_id", req.user.id);
    if (fetchErr) return res.status(500).json({ error: "Failed to load detections" });

    const runId = randomUUID();
    const results = [];
    let budgetExhausted = false;

    for (const d of detections) {
      if (!tryConsumeBudget()) {
        budgetExhausted = true;
        break;
      }
      try {
        const parsed = await analyzeOne({ query: d.query, tool: d.tool, name: d.name });
        await persistFindings({ userId: req.user.id, detectionId: d.id, runId, blindspots: parsed.blindspots });
        results.push({ detection_id: d.id, name: d.name, ...parsed });
      } catch {
        results.push({ detection_id: d.id, name: d.name, blindspots: [], overall_assessment: "Analysis failed for this detection — try it individually." });
      }
    }

    res.json({ run_id: runId, results, scanned: results.length, requested: detectionIds.length, budget_exhausted: budgetExhausted });
  } catch (err) {
    console.error("blindspot/scan error:", err.message);
    res.status(500).json({ error: "Batch scan failed" });
  }
});

export default router;
