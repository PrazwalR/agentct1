import { formatUnits, parseUnits } from "viem";
import type { PaymentRequest, PolicyCheck } from "../types.js";
import { intentVerdictSchema } from "../policy/schema.js";

const INTENT_MODEL = "claude-haiku-4-5-20251001";

export interface IntentReconcilerOptions {
  /** Skip the LLM semantic check below this amount (token units). Default $1. */
  minAmountForLlm?: bigint;
  model?: string;
}

/**
 * Checks whether the executed payment matches the agent's STATED intent.
 *
 * The attack this catches: a prompt-injected agent declares a benign intent
 * ("pay $0.10 for weather data") but the actual recipient/amount was hijacked.
 *
 * A fast LLM compares the intent string to the concrete transaction. Gated by
 * an amount threshold so sub-dollar micropayments don't each incur an LLM call.
 */
export class IntentReconciler {
  private readonly apiKey?: string;
  private readonly minAmount: bigint;
  private readonly model: string;

  constructor(apiKey?: string, opts: IntentReconcilerOptions = {}) {
    this.apiKey = apiKey;
    this.minAmount = opts.minAmountForLlm ?? parseUnits("1", 6);
    this.model = opts.model ?? INTENT_MODEL;
  }

  async check(req: PaymentRequest): Promise<PolicyCheck> {
    if (!this.apiKey) {
      return info("intent semantic check skipped (no LLM key)");
    }
    if (req.amount < this.minAmount) {
      return info(`intent check skipped (below ${formatUnits(this.minAmount, 6)} USDC threshold)`);
    }
    try {
      return await this.semanticCheck(req);
    } catch (err) {
      // Fail open with a warning rather than blocking on an LLM outage.
      return {
        id: "intent-reconcile",
        passed: true,
        severity: "warning",
        message: `intent check unavailable: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  }

  private async semanticCheck(req: PaymentRequest): Promise<PolicyCheck> {
    const prompt = `An AI agent declared this intent for a payment:
"${req.intent}"

The actual payment is:
- Amount: ${req.amount} (smallest token units, USDC has 6 decimals)
- Recipient: ${req.recipient}
- Resource: ${req.resourceUrl ?? "unknown"}

Does this payment plausibly fulfill the stated intent? Consider whether the amount
is reasonable for the stated purpose and whether anything looks inconsistent.
Respond with JSON only: { "consistent": true|false, "concern": "<brief reason if inconsistent>" }`;

    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": this.apiKey!,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: this.model,
        max_tokens: 300,
        messages: [{ role: "user", content: prompt }],
      }),
    });

    if (!res.ok) throw new Error(`LLM ${res.status}`);

    const data = (await res.json()) as { content?: Array<{ type: string; text?: string }> };
    const text = data.content?.find((b) => b.type === "text")?.text ?? "";
    const parsed = intentVerdictSchema.safeParse(
      JSON.parse(text.replace(/```json|```/g, "").trim()),
    );
    if (!parsed.success) throw new Error("invalid intent verdict JSON");

    return {
      id: "intent-reconcile",
      passed: parsed.data.consistent,
      severity: parsed.data.consistent ? "info" : "critical",
      message: parsed.data.consistent
        ? "consistent with stated intent"
        : `intent mismatch: ${parsed.data.concern ?? "unspecified"}`,
    };
  }
}

function info(message: string): PolicyCheck {
  return { id: "intent-reconcile", passed: true, severity: "info", message };
}
