import { Router } from "express";
import { invokeClaude } from "../ai.js";

const router = Router();

const SYSTEM_PROMPT = `You are a detection engineering assistant. Given a technique or
behavior description and a target SIEM query language, produce a detection strategy.
Respond ONLY as JSON with this exact shape, no markdown fences, no preamble:
{
  "name": string,
  "technique_id": string,
  "tactic": string,
  "severity": "low"|"medium"|"high"|"critical",
  "summary": string,
  "query": string,
  "false_positives": string[],
  "tuning_notes": string,
  "references": string[]
}`;

function sanitize(input, maxLen = 2000) {
  return String(input || "")
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .slice(0, maxLen);
}

// POST /api/claude/generate  { technique: string, siem: string }
router.post("/generate", async (req, res) => {
  try {
    const technique = sanitize(req.body?.technique);
    const siem = sanitize(req.body?.siem, 64);
    if (!technique || !siem) {
      return res.status(400).json({ error: "technique and siem are required" });
    }

    const prompt = `Technique/behavior: ${technique}\nTarget SIEM query language: ${siem}`;
    const raw = await invokeClaude(prompt, { system: SYSTEM_PROMPT, maxTokens: 4000 });

    let parsed;
    try {
      parsed = JSON.parse(raw.replace(/```json|```/g, "").trim());
    } catch {
      return res.status(502).json({ error: "AI response could not be parsed. Try again." });
    }

    res.json(parsed);
  } catch (err) {
    console.error("claude/generate error:", err.message);
    res.status(500).json({ error: "Detection generation failed" });
  }
});

// POST /api/claude/translate { query, from, to }
router.post("/translate", async (req, res) => {
  try {
    const query = sanitize(req.body?.query, 4000);
    const from = sanitize(req.body?.from, 64);
    const to = sanitize(req.body?.to, 64);
    if (!query || !from || !to) {
      return res.status(400).json({ error: "query, from, and to are required" });
    }
    if (from === to) {
      return res.json({ translated: query, notes: "Source and target are the same — nothing to translate." });
    }

    const prompt = `Translate this ${from} detection query into equivalent ${to} query syntax. Preserve the logic and intent as closely as that platform allows.\n\nQuery:\n${query}\n\nRespond ONLY as JSON, no markdown fences:\n{"translated": string, "notes": string}\n"notes" should call out anything that doesn't map cleanly (e.g. a field or function with no direct equivalent).`;
    const raw = await invokeClaude(prompt, {
      system: "You are a detection engineering assistant translating SIEM query syntax between platforms.",
      maxTokens: 2000,
    });

    let parsed;
    try {
      parsed = JSON.parse(raw.replace(/```json|```/g, "").trim());
    } catch {
      return res.status(502).json({ error: "AI response could not be parsed. Try again." });
    }

    res.json(parsed);
  } catch (err) {
    console.error("claude/translate error:", err.message);
    res.status(500).json({ error: "Query translation failed" });
  }
});

export default router;
