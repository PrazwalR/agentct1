import { type Span, SpanStatusCode, trace } from "@opentelemetry/api";
import type { PaymentRequest, PolicyDecision } from "./types.js";

const TRACER_NAME = "@agentctl/core";

/**
 * OpenTelemetry tracer for agentctl. If the host app hasn't registered an OTel
 * SDK, this returns a no-op tracer and spans cost nothing — so tracing is always
 * on but only materializes when an exporter (LangSmith/Langfuse/Arize/OTLP) is wired.
 */
export function getTracer() {
  return trace.getTracer(TRACER_NAME);
}

export type SpanAttrs = Record<string, string | number | boolean>;

/** Run `fn` inside an active span, recording status + ending the span. */
export async function withSpan<T>(
  name: string,
  attrs: SpanAttrs,
  fn: (span: Span) => Promise<T>,
): Promise<T> {
  return getTracer().startActiveSpan(name, async (span) => {
    try {
      span.setAttributes(attrs);
      const result = await fn(span);
      span.setStatus({ code: SpanStatusCode.OK });
      return result;
    } catch (err) {
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: err instanceof Error ? err.message : String(err),
      });
      throw err;
    } finally {
      span.end();
    }
  });
}

export function paymentAttrs(req: PaymentRequest): SpanAttrs {
  return {
    "agentctl.agent_id": req.agentId,
    "agentctl.amount": req.amount.toString(),
    "agentctl.token": req.token,
    "agentctl.recipient": req.recipient,
    "agentctl.chain": req.chain,
  };
}

export function decisionAttrs(d: PolicyDecision): SpanAttrs {
  return {
    "agentctl.verdict": d.verdict,
    "agentctl.risk_score": Number(d.riskScore.toFixed(4)),
    "agentctl.checks_total": d.checks.length,
    "agentctl.checks_failed": d.checks.filter((c) => !c.passed).length,
  };
}
