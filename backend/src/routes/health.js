import { Router } from "express";
import { activeProvider } from "../ai.js";

const router = Router();

router.get("/", (req, res) => {
  res.json({
    status: "ok",
    uptime_seconds: Math.round(process.uptime()),
    memory_mb: Math.round(process.memoryUsage().rss / 1024 / 1024),
    ai_provider: activeProvider(),
    model: activeProvider() === "anthropic"
      ? (process.env.ANTHROPIC_MODEL || "claude-sonnet-4-5")
      : (process.env.BEDROCK_MODEL_ID || "us.anthropic.claude-sonnet-4-6"),
    demo_mode: process.env.DEMO_MODE === "true",
  });
});

export default router;
