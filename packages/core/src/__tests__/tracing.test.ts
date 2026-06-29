import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { trace } from "@opentelemetry/api";
import {
  BasicTracerProvider,
  InMemorySpanExporter,
  SimpleSpanProcessor,
} from "@opentelemetry/sdk-trace-base";
import { generatePrivateKey } from "viem/accounts";
import { parseUnits, type Address } from "viem";
import { createGuard } from "../index.js";
import { ViemAdapter } from "../adapters/viem.js";
import type { PaymentRequest, Policy } from "../types.js";

const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e" as Address;
const A = "0x1111111111111111111111111111111111111111" as Address;

const exporter = new InMemorySpanExporter();
let provider: BasicTracerProvider;

beforeAll(() => {
  provider = new BasicTracerProvider({ spanProcessors: [new SimpleSpanProcessor(exporter)] });
  trace.setGlobalTracerProvider(provider);
});

afterAll(async () => {
  await provider.shutdown();
  trace.disable();
});

function emptyPolicy(): Policy {
  return { agentId: "trace-agent", rules: [], anomalyThreshold: 0.8, anomalyAction: "escalate" };
}

describe("opentelemetry tracing", () => {
  it("emits an agentctl.evaluate span with payment + decision attributes", async () => {
    const guard = await createGuard({
      wallet: new ViemAdapter({ privateKey: generatePrivateKey() }),
      policy: emptyPolicy(),
    });
    const req: PaymentRequest = {
      intent: "weather data",
      amount: parseUnits("0.10", 6),
      token: USDC,
      recipient: A,
      chain: "eip155:84532",
      agentId: "trace-agent",
    };

    const decision = await guard.evaluate(req);
    const span = exporter.getFinishedSpans().find((s) => s.name === "agentctl.evaluate");

    expect(span).toBeDefined();
    expect(span?.attributes["agentctl.agent_id"]).toBe("trace-agent");
    expect(span?.attributes["agentctl.amount"]).toBe("100000");
    expect(span?.attributes["agentctl.verdict"]).toBe(decision.verdict);
    expect(span?.attributes["agentctl.checks_total"]).toBe(decision.checks.length);
  });
});
