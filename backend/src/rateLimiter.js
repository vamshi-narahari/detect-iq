/**
 * Demo-mode cap on AI generation calls, tracked per user per day in Supabase
 * (ai_usage table). Only active when DEMO_MODE=true. This is separate from the
 * express-rate-limit middleware in server.js, which guards against abuse
 * (req/min); this guards against exceeding the "N free AI runs" demo promise.
 */
export function makeDemoLimiter(supabase) {
  const demoMode = process.env.DEMO_MODE === "true";
  const dailyLimit = parseInt(process.env.DEMO_DAILY_AI_LIMIT || "2", 10);

  return async function demoLimiter(req, res, next) {
    if (!demoMode) return next();

    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ error: "Sign in required" });

    const today = new Date().toISOString().slice(0, 10);

    const { data: existing } = await supabase
      .from("ai_usage")
      .select("call_count")
      .eq("user_id", userId)
      .eq("usage_date", today)
      .maybeSingle();

    const count = existing?.call_count ?? 0;
    if (count >= dailyLimit) {
      return res.status(429).json({
        error: `Demo accounts get ${dailyLimit} AI runs per day. Come back tomorrow, or self-host DetectIQ for unlimited use.`,
      });
    }

    await supabase
      .from("ai_usage")
      .upsert(
        { user_id: userId, usage_date: today, call_count: count + 1 },
        { onConflict: "user_id,usage_date" }
      );

    next();
  };
}
