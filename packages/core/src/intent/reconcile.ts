import { formatUnits, parseUnits } from "viem";
import type { PaymentRequest, PolicyCheck } from "../types.js";
import { intentVerdictSchema } from "../policy/schema.js";
import { type LLMConfig, type LLMProvider, callLLM, resolveLLMConfig } from "../llm/client.js";

export interface IntentReconcilerOptions {
  /** Skip the LLM semantic check below this amount (token units). Default $1. */
  minAmountForLlm?: bigint;
  model?: string;
  provider?: LLMProvider;
  /** Ollama server URL, if provider is "ollama". */
  baseUrl?: string;
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
  private readonly llmConfig: LLMConfig;
  private readonly minAmount: bigint;

  constructor(apiKeyOrConfig?: string | LLMConfig, opts: IntentReconcilerOptions = {}) {
    const base: LLMConfig = typeof apiKeyOrConfig === "string" ? { apiKey: apiKeyOrConfig } : (apiKeyOrConfig ?? {});
    this.llmConfig = {
      ...base,
      provider: opts.provider ?? base.provider,
      model: opts.model ?? base.model,
      baseUrl: opts.baseUrl ?? base.baseUrl,
    };
    this.minAmount = opts.minAmountForLlm ?? parseUnits("1", 6);
  }

  async check(req: PaymentRequest): Promise<PolicyCheck> {
    if (!resolveLLMConfig(this.llmConfig)) {
      return info("intent semantic check skipped (no LLM configured)");
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

    const text = await callLLM(this.llmConfig, { prompt, maxTokens: 300, json: true });
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
