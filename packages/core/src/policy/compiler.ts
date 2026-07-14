import type { Address } from "viem";
import type { Policy, PolicyRule } from "../types.js";
import { getChain, usdToTokenUnits } from "../constants.js";
import { type LLMConfig, callLLM } from "../llm/client.js";
import { type RuleInput, compilerOutputSchema } from "./schema.js";

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

/**
 * Compile a natural-language spending policy into a structured Policy via a
 * fast LLM, validating the model's JSON with zod before trusting it.
 *
 * The third argument accepts either a plain Anthropic API key (back-compat) or
 * a full LLMConfig — pass `{ provider: "ollama" }` to compile locally with zero
 * API key, using Ollama (`ollama serve`, default model `llama3.2`).
 *
 * `chain` selects which chain's USDC address spend-cap rules are denominated
 * in (default Base Sepolia, back-compat). Get this wrong and a spend-cap rule
 * silently never matches the payment token it's evaluated against — pass the
 * chain the guard will actually run on.
 */
export async function compilePolicy(
  naturalLanguage: string,
  agentId: string,
  llm?: string | LLMConfig,
  chain?: string,
): Promise<Policy> {
  const cfg: LLMConfig = typeof llm === "string" ? { apiKey: llm } : (llm ?? {});
  const text = await callLLM(cfg, {
    system: COMPILER_SYSTEM_PROMPT,
    prompt: naturalLanguage,
    maxTokens: 1500,
    json: true,
  });
  const json = extractJson(text);

  return compilePolicyObject(json, agentId, naturalLanguage, chain);
}

/**
 * Build a Policy from an already-structured object (the compiler-output shape,
 * USD amounts) without calling an LLM. Validates with zod and converts USD →
 * token units. Used by the CLI `eval` command and the Python bridge.
 *
 * `chain` (default Base Sepolia, back-compat) — see compilePolicy's note above.
 */
export function compilePolicyObject(
  input: unknown,
  agentId: string,
  sourceText?: string,
  chain = "eip155:84532",
): Policy {
  const parsed = compilerOutputSchema.safeParse(input);
  if (!parsed.success) {
    throw new Error(`invalid policy: ${parsed.error.message}`);
  }
  const usdc = getChain(chain).usdc;
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
        escalateAbove: r.escalateAbove !== undefined ? usdToTokenUnits(r.escalateAbove) : undefined,
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
