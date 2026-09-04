/**
 * A hard daily ceiling on AI calls, enforced ONLY when the direct Anthropic
 * API is active (ANTHROPIC_API_KEY set) — that's the pay-per-token path with
 * no natural spend ceiling. Bedrock billing/limits are managed through your
 * AWS account separately, so this is a no-op when Bedrock is the active
 * provider.
 *
 * This counter is in-memory and resets when the process restarts (e.g. a
 * PM2 restart or deploy). That's an acceptable tradeoff for a lightweight
 * safety net against runaway/abusive usage — it is NOT a substitute for
 * setting an actual spend limit in your Anthropic Console, which is the
 * only hard guarantee against surprise charges.
 */
let counter = { date: null, count: 0 };

function resetIfNewDay() {
  const today = new Date().toISOString().slice(0, 10);
  if (counter.date !== today) counter = { date: today, count: 0 };
}

function limit() {
  return parseInt(process.env.ANTHROPIC_MAX_DAILY_CALLS || "50", 10);
}

/**
 * Callable directly for code paths that make N AI calls in one request
 * (e.g. a batch scan across multiple detections) — each call should consume
 * one unit of budget individually, not just the one HTTP request. Returns
 * true if the call is allowed (and consumes budget), false if the daily
 * ceiling is already reached.
 */
export function tryConsumeBudget() {
  if (!process.env.ANTHROPIC_API_KEY) return true; // no-op when using Bedrock
  resetIfNewDay();
  if (counter.count >= limit()) return false;
  counter.count += 1;
  return true;
}

export function budgetLimiter(req, res, next) {
  if (tryConsumeBudget()) return next();
  res.status(429).json({
    error: `Daily Anthropic API call budget (${limit()}) reached for this server. Raise ANTHROPIC_MAX_DAILY_CALLS in the backend .env, or wait until tomorrow (UTC).`,
  });
}
