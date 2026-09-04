import { BedrockRuntimeClient, InvokeModelCommand } from "@aws-sdk/client-bedrock-runtime";

const client = new BedrockRuntimeClient({ region: process.env.AWS_REGION || "us-east-1" });

const MODEL_ID = process.env.BEDROCK_MODEL_ID || "us.anthropic.claude-sonnet-4-6";

/**
 * Send a single-turn prompt to Claude via Bedrock and return the text response.
 * Keep max_tokens modest by default; callers can override for larger generations
 * like a full detection strategy.
 */
export async function invokeClaudeViaBedrock(prompt, { maxTokens = 4000, system } = {}) {
  const body = {
    anthropic_version: "bedrock-2023-05-31",
    max_tokens: maxTokens,
    messages: [{ role: "user", content: prompt }],
  };
  if (system) body.system = system;

  const command = new InvokeModelCommand({
    modelId: MODEL_ID,
    contentType: "application/json",
    accept: "application/json",
    body: JSON.stringify(body),
  });

  const response = await client.send(command);
  const payload = JSON.parse(new TextDecoder().decode(response.body));
  const text = payload?.content?.map((c) => c.text || "").join("\n") ?? "";
  return text;
}
