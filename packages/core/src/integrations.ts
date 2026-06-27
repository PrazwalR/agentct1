import { type Address, parseUnits } from "viem";
import type { AgentGuard, ExecuteResult } from "./index.js";
import type { PaymentRequest, PolicyDecision } from "./types.js";
import { getChain } from "./constants.js";

export interface PaymentToolInput {
  /** Natural-language reason for this payment (the declared intent). */
  intent?: string;
  reason?: string;
  /** USD amount if string/number; token units if bigint. */
  amount: string | number | bigint;
  /** "USDC" or a token address; defaults to the chain's USDC. */
  token?: string;
  recipient: string;
  /** CAIP-2 chain; defaults to Base Sepolia. */
  chain?: string;
}

/** Build a PaymentRequest from loose tool-call args. */
export function toPaymentRequest(input: PaymentToolInput, agentId: string): PaymentRequest {
  const chain = input.chain ?? "eip155:84532";
  const cfg = getChain(chain);
  const token =
    !input.token || input.token.toUpperCase() === "USDC" ? cfg.usdc : (input.token as Address);
  const amount =
    typeof input.amount === "bigint" ? input.amount : parseUnits(String(input.amount), 6);
  return {
    intent: input.intent ?? input.reason ?? "tool payment",
    amount,
    token,
    recipient: input.recipient as Address,
    chain,
    agentId,
  };
}

export interface BlockedToolResult {
  blocked: true;
  reason?: string;
  decision: PolicyDecision;
}

/**
 * Wrap an agent payment tool so the payment routes through the guard before the
 * tool's real work runs. Framework-agnostic: usable from LangChain.js, the
 * Vercel AI SDK, the OpenAI SDK, or a plain agent loop. On block/denied
 * escalation the tool returns a structured result the agent can reason about
 * instead of paying.
 */
export function wrapPaymentTool<TArgs extends PaymentToolInput, TResult>(
  guard: AgentGuard,
  run: (args: TArgs, result: ExecuteResult) => Promise<TResult>,
): (args: TArgs) => Promise<TResult | BlockedToolResult> {
  return async (args: TArgs) => {
    const req = toPaymentRequest(args, guard.agentId);
    const result = await guard.execute(req);
    if (!result.executed) {
      return { blocked: true, reason: result.reason, decision: result.decision };
    }
    return run(args, result);
  };
}
