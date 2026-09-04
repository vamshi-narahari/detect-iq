import Anthropic from "@anthropic-ai/sdk";

let client = null;

export function anthropicConfigured() {
  return Boolean(process.env.ANTHROPIC_API_KEY);
}

function getClient() {
  if (!client) {
    const workspaceId = process.env.ANTHROPIC_WORKSPACE_ID;
    client = new Anthropic({
      apiKey: process.env.ANTHROPIC_API_KEY,
      // Only "identity-linked" API keys (tied to your personal login across
      // possibly multiple workspaces) require this header — standard
      // workspace-scoped keys don't need it, so this is a no-op for those.
      defaultHeaders: workspaceId ? { "anthropic-workspace-id": workspaceId } : undefined,
    });
  }
  return client;
}

const MODEL = process.env.ANTHROPIC_MODEL || "claude-sonnet-4-5";

/**
 * Send a single-turn prompt directly to the Anthropic API (no AWS required).
 * Same signature as invokeClaudeViaBedrock so callers don't need to care
 * which provider is active.
 */
export async function invokeClaudeViaAnthropic(prompt, { maxTokens = 4000, system } = {}) {
  const response = await getClient().messages.create({
    model: MODEL,
    max_tokens: maxTokens,
    system,
    messages: [{ role: "user", content: prompt }],
  });
  return response.content.map((c) => c.text || "").join("\n");
}
