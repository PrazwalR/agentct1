import type { Address } from "viem";
import type { Policy, PolicyRule } from "../types.js";
import { getChain, usdToTokenUnits } from "../constants.js";
import { type RuleInput, compilerOutputSchema } from "./schema.js";

const COMPILER_MODEL = "claude-haiku-4-5-20251001"; // fast + cheap for a parse task

const COMPILER_SYSTEM_PROMPT = `You are a policy compiler for AI agent payments.
Convert the user's natural-language spending policy into a strict JSON structure.
Output ONLY valid JSON (no markdown fences, no prose) matching this schema:
{
  "rules": [
    { "type": "spend-cap", "window": "transaction"|"session"|"hour"|"day", "maxAmount": <USD number>, "escalateAbove": <USD number, optional> },
    { "type": "allowlist", "mode": "recipients"|"resources", "entries": [<string>...], "enforce": <bool> },
    { "type": "rate-limit", "maxPayments": <int>, "windowSeconds": <int> },
    { "type": "counterparty", "flagNewRecipients": <bool>, "action": "block"|"escalate"|"warn" },
    { "type": "time-window", "allowedHours": [<startHourUTC>, <endHourUTC>], "action": "block"|"escalate"|"warn" }
  ],
  "anomalyThreshold": <0-1>,
  "anomalyAction": "block"|"escalate"
}
Amounts are in USD. Be conservative: if the user says "small payments only", set a low
spend-cap. If they mention human approval for large amounts, use escalateAbove. If they say
"only known/used-before services", add a counterparty rule with action "escalate". If they
mention night/business hours, add a time-window rule.`;

interface AnthropicResponse {
  content?: Array<{ type: string; text?: string }>;
}

/**
 * Compile a natural-language spending policy into a structured Policy via Claude
 * Haiku, validating the model's JSON with zod before trusting it.
 */
export async function compilePolicy(
  naturalLanguage: string,
  agentId: string,
  apiKey?: string,
): Promise<Policy> {
  const key = apiKey ?? process.env.ANTHROPIC_API_KEY;
  if (!key) {
    throw new Error("LLM API key required to compile a natural-language policy");
  }

  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": key,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: COMPILER_MODEL,
      max_tokens: 1500,
      system: COMPILER_SYSTEM_PROMPT,
      messages: [{ role: "user", content: naturalLanguage }],
    }),
  });

  if (!res.ok) {
    throw new Error(`Policy compiler LLM call failed: ${res.status} ${await res.text()}`);
  }

  const data = (await res.json()) as AnthropicResponse;
  const text = data.content?.find((b) => b.type === "text")?.text ?? "";
  const json = extractJson(text);

  return compilePolicyObject(json, agentId, naturalLanguage);
}

/**
 * Build a Policy from an already-structured object (the compiler-output shape,
 * USD amounts) without calling an LLM. Validates with zod and converts USD →
 * token units. Used by the CLI `eval` command and the Python bridge.
 */
export function compilePolicyObject(input: unknown, agentId: string, sourceText?: string): Policy {
  const parsed = compilerOutputSchema.safeParse(input);
  if (!parsed.success) {
    throw new Error(`Invalid policy: ${parsed.error.message}`);
  }
  const usdc = getChain("eip155:84532").usdc; // default policy chain: Base Sepolia
  return {
    agentId,
    rules: parsed.data.rules.map((r) => toPolicyRule(r, usdc)),
    anomalyThreshold: parsed.data.anomalyThreshold,
    anomalyAction: parsed.data.anomalyAction,
    sourceText,
  };
}

/** Parse JSON from a model response, tolerating stray markdown fences. */
function extractJson(text: string): unknown {
  const cleaned = text.replace(/```json|```/g, "").trim();
  const start = cleaned.indexOf("{");
  const end = cleaned.lastIndexOf("}");
  const slice = start >= 0 && end > start ? cleaned.slice(start, end + 1) : cleaned;
  return JSON.parse(slice);
}

/** Convert a validated USD-denominated rule into a runtime PolicyRule (token units). */
function toPolicyRule(r: RuleInput, usdc: Address): PolicyRule {
  switch (r.type) {
    case "spend-cap":
      return {
        type: "spend-cap",
        window: r.window,
        maxAmount: usdToTokenUnits(r.maxAmount),
        escalateAbove:
          r.escalateAbove !== undefined ? usdToTokenUnits(r.escalateAbove) : undefined,
        token: usdc,
      };
    case "allowlist":
      return {
        type: "allowlist",
        mode: r.mode,
        entries: r.entries.map((e) => e.toLowerCase().trim()).filter((e) => e.length > 0),
        enforce: r.enforce,
      };
    case "rate-limit":
      return { type: "rate-limit", maxPayments: r.maxPayments, windowSeconds: r.windowSeconds };
    case "counterparty":
      return {
        type: "counterparty",
        flagNewRecipients: r.flagNewRecipients,
        action: r.action,
      };
    case "time-window":
      return {
        type: "time-window",
        allowedHours: [r.allowedHours[0], r.allowedHours[1]],
        action: r.action,
      };
  }
}
