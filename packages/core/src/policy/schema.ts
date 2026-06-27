import { z } from "zod";

/**
 * Schemas for the natural-language policy COMPILER output (what the LLM emits).
 * Amounts here are USD numbers — converted to token units by the compiler.
 * Validating the LLM response before trusting it is a hard requirement: a
 * hallucinated or malformed response must be rejected, not silently applied.
 */

const spendCapInput = z.object({
  type: z.literal("spend-cap"),
  window: z.enum(["transaction", "session", "hour", "day"]),
  maxAmount: z.coerce.number().positive(),
  escalateAbove: z.coerce.number().positive().optional(),
});

const allowlistInput = z.object({
  type: z.literal("allowlist"),
  mode: z.enum(["recipients", "resources"]),
  entries: z.array(z.string()).default([]),
  enforce: z.boolean().default(true),
});

const rateLimitInput = z.object({
  type: z.literal("rate-limit"),
  maxPayments: z.coerce.number().int().positive(),
  windowSeconds: z.coerce.number().int().positive(),
});

const counterpartyInput = z.object({
  type: z.literal("counterparty"),
  flagNewRecipients: z.boolean().default(true),
  action: z.enum(["block", "escalate", "warn"]).default("escalate"),
});

const timeWindowInput = z.object({
  type: z.literal("time-window"),
  allowedHours: z.tuple([z.coerce.number(), z.coerce.number()]),
  action: z.enum(["block", "escalate", "warn"]).default("escalate"),
});

export const ruleInputSchema = z.discriminatedUnion("type", [
  spendCapInput,
  allowlistInput,
  rateLimitInput,
  counterpartyInput,
  timeWindowInput,
]);

export const compilerOutputSchema = z.object({
  rules: z.array(ruleInputSchema).default([]),
  anomalyThreshold: z.coerce.number().min(0).max(1).default(0.8),
  anomalyAction: z.enum(["block", "escalate"]).default("escalate"),
});

export type CompilerOutput = z.infer<typeof compilerOutputSchema>;
export type RuleInput = z.infer<typeof ruleInputSchema>;

/** Schema for the intent reconciler's LLM response. */
export const intentVerdictSchema = z.object({
  consistent: z.boolean(),
  concern: z.string().optional(),
});
export type IntentVerdict = z.infer<typeof intentVerdictSchema>;
