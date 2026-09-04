import { invokeClaudeViaBedrock } from "./bedrock.js";
import { invokeClaudeViaAnthropic, anthropicConfigured } from "./anthropic.js";

/**
 * If ANTHROPIC_API_KEY is set, calls go straight to the Anthropic API — no
 * AWS account needed, which matters for anyone cloning this repo who
 * doesn't already have Bedrock model access enabled. Otherwise falls back
 * to Bedrock. Only one provider is ever active at a time; there's no
 * blending or fallback mid-request.
 */
export function activeProvider() {
  return anthropicConfigured() ? "anthropic" : "bedrock";
}

export async function invokeClaude(prompt, opts = {}) {
  return anthropicConfigured() ? invokeClaudeViaAnthropic(prompt, opts) : invokeClaudeViaBedrock(prompt, opts);
}
