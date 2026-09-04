import { Router } from "express";
import { invokeClaude } from "../ai.js";
import { budgetLimiter } from "../budgetLimiter.js";

const router = Router();

function sanitize(input, maxLen = 4000) {
  return String(input || "")
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .slice(0, maxLen);
}

// POST /api/validate/sample-data { query, tool }
// Uses Bedrock to draft realistic log lines a detection query would (and
// wouldn't) match, so an analyst can eyeball field names/logic before it
// ever touches a real SIEM.
router.post("/sample-data", budgetLimiter, async (req, res) => {
  try {
    const query = sanitize(req.body?.query);
    const tool = sanitize(req.body?.tool, 64);
    if (!query) return res.status(400).json({ error: "query is required" });

    const prompt = `Detection query (${tool}):\n${query}\n\nGenerate 3 realistic raw log lines that WOULD match this detection, and 2 near-miss lines that would NOT match. Label each clearly ("MATCH" / "NO MATCH"). Plain text only, no markdown fences.`;
    const sample = await invokeClaude(prompt, {
      maxTokens: 900,
      system: "You are a SOC engineer generating realistic synthetic log samples for detection testing.",
    });
    res.json({ sample });
  } catch (err) {
    console.error("validate/sample-data error:", err.message);
    res.status(500).json({ error: "Sample data generation failed" });
  }
});

// POST /api/validate/agent { query, tool }
// TODO: wire this to a real local collector — e.g. shell out to a SIEM CLI
// installed on this box, or call a local agent's API — instead of the
// heuristic stand-in below. This exists so the workflow (and the UI around
// it) is real today even before that integration is built.
router.post("/agent", (req, res) => {
  const query = sanitize(req.body?.query);
  if (!query) return res.status(400).json({ error: "query is required" });

  const looksReasonable = /\|\s*(stats|where|search|table)/i.test(query) || query.trim().length > 10;
  const fired = looksReasonable && Math.random() > 0.15;
  const eventsMatched = fired ? Math.floor(Math.random() * 6) + 1 : 0;

  res.json({
    fired,
    events_matched: eventsMatched,
    output: fired
      ? `[agent] compiled query executed locally — ${eventsMatched} matching event(s) in the sample window.`
      : `[agent] compiled query executed locally — no matching events. Check field names against your source data.`,
  });
});

export default router;
