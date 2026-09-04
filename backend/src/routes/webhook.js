import { Router } from "express";
import { supabaseAdmin } from "../supabaseAdmin.js";

const router = Router();

const ALLOWED_PROVIDERS = ["jira", "outlook", "teams", "webex", "other"];

function sanitize(input, maxLen = 2000) {
  return String(input || "")
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .slice(0, maxLen);
}

/**
 * POST /api/webhook/intake/:provider
 * Header: X-Webhook-Secret: <INTAKE_WEBHOOK_SECRET>
 * Body: { title, notes?, priority? }
 *
 * This is a real, working endpoint — point a Jira Automation rule, a Power
 * Automate flow (Outlook/Teams), or a Webex webhook integration at it and
 * it will create a genuine row in intake_requests. What it can't do without
 * your input: the vendor-side setup (creating that automation/flow/webhook
 * in your actual Jira/Microsoft/Webex account) — that's account-specific
 * and has to be done in each vendor's own console.
 *
 * All requests land under one INTAKE_OWNER_USER_ID account, which fits a
 * single-org self-hosted deployment. For the public multi-tenant demo
 * instance, leave INTAKE_WEBHOOK_SECRET unset — the endpoint stays fully
 * disabled unless explicitly configured.
 */
router.post("/intake/:provider", async (req, res) => {
  const secret = process.env.INTAKE_WEBHOOK_SECRET;
  const ownerId = process.env.INTAKE_OWNER_USER_ID;

  if (!secret || !ownerId) {
    return res.status(501).json({ error: "Webhook intake is not configured on this server." });
  }
  if (req.headers["x-webhook-secret"] !== secret) {
    return res.status(401).json({ error: "Invalid webhook secret." });
  }

  const provider = ALLOWED_PROVIDERS.includes(req.params.provider) ? req.params.provider : "other";
  const title = sanitize(req.body?.title || req.body?.summary, 300);
  if (!title) return res.status(400).json({ error: "title is required" });

  const { error } = await supabaseAdmin.from("intake_requests").insert({
    user_id: ownerId,
    title,
    notes: sanitize(req.body?.notes || req.body?.description, 4000),
    priority: ["low", "medium", "high", "critical"].includes(req.body?.priority) ? req.body.priority : "medium",
    source: provider,
    status: "open",
  });

  if (error) {
    console.error("webhook/intake error:", error.message);
    return res.status(500).json({ error: "Could not create intake request." });
  }

  res.json({ ok: true });
});

export default router;
