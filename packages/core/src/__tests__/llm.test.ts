import { afterEach, describe, expect, it } from "vitest";
import { type Server, createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { parseUnits, type Address } from "viem";
import { callLLM, resolveLLMConfig } from "../llm/client.js";
import { compilePolicy } from "../policy/compiler.js";
import { IntentReconciler } from "../intent/reconcile.js";
import type { PaymentRequest } from "../types.js";

let server: Server | undefined;
afterEach(() => {
  server?.close();
  server = undefined;
});

/** Spin up a fake Ollama /api/chat endpoint; captures the request, replies with `content`. */
function fakeOllama(content: string): Promise<{ url: string; lastRequest: () => unknown }> {
  let captured: unknown;
  return new Promise((resolve) => {
    server = createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c)).on("end", () => {
        captured = JSON.parse(body);
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ model: "llama3.2", message: { role: "assistant", content }, done: true }));
      });
    });
    server.listen(0, "127.0.0.1", () => {
      const { port } = server!.address() as AddressInfo;
      resolve({ url: `http://127.0.0.1:${port}`, lastRequest: () => captured });
    });
  });
}

/** Spin up a fake Anthropic /v1/messages endpoint. */
function fakeAnthropic(text: string): Promise<{ url: string; lastHeaders: () => Record<string, unknown> }> {
  let headers: Record<string, unknown> = {};
  return new Promise((resolve) => {
    server = createServer((req, res) => {
      headers = req.headers;
      let body = "";
      req.on("data", (c) => (body += c)).on("end", () => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ content: [{ type: "text", text }] }));
      });
    });
    server.listen(0, "127.0.0.1", () => {
      const { port } = server!.address() as AddressInfo;
      resolve({ url: `http://127.0.0.1:${port}`, lastHeaders: () => headers });
    });
  });
}

describe("resolveLLMConfig", () => {
  it("auto-detects anthropic from an apiKey, ollama from a baseUrl, undefined otherwise", () => {
    expect(resolveLLMConfig({ apiKey: "sk-x" })?.provider).toBe("anthropic");
    expect(resolveLLMConfig({ baseUrl: "http://localhost:11434" })?.provider).toBe("ollama");
    expect(resolveLLMConfig({})).toBeUndefined();
  });

  it("explicit provider wins, but anthropic still needs a key", () => {
    expect(resolveLLMConfig({ provider: "ollama" })?.provider).toBe("ollama");
    expect(resolveLLMConfig({ provider: "anthropic" })).toBeUndefined();
  });

  it("defaults the ollama model and base URL", () => {
    const r = resolveLLMConfig({ provider: "ollama" });
    expect(r?.baseUrl).toBe("http://127.0.0.1:11434");
    expect(r?.model).toBe("llama3.2");
  });
});

describe("callLLM — ollama", () => {
  it("sends the chat request Ollama expects and extracts message.content", async () => {
    const { url, lastRequest } = await fakeOllama('{"ok":true}');
    const text = await callLLM(
      { provider: "ollama", baseUrl: url, model: "qwen2.5" },
      { system: "sys prompt", prompt: "user prompt", json: true },
    );
    expect(text).toBe('{"ok":true}');
    const req = lastRequest() as {
      model: string;
      stream: boolean;
      format?: string;
      messages: Array<{ role: string; content: string }>;
    };
    expect(req.model).toBe("qwen2.5");
    expect(req.stream).toBe(false);
    expect(req.format).toBe("json");
    expect(req.messages).toEqual([
      { role: "system", content: "sys prompt" },
      { role: "user", content: "user prompt" },
    ]);
  });

  it("gives a clear error when Ollama isn't running", async () => {
    await expect(
      callLLM({ provider: "ollama", baseUrl: "http://127.0.0.1:1" }, { prompt: "x" }),
    ).rejects.toThrow(/not reachable/);
  });
});

describe("callLLM — anthropic", () => {
  it("sends the x-api-key header and extracts the text block", async () => {
    const { url, lastHeaders } = await fakeAnthropic("hello from claude");
    const text = await callLLM({ apiKey: "sk-test", baseUrl: url }, { prompt: "hi" });
    expect(text).toBe("hello from claude");
    expect(lastHeaders()["x-api-key"]).toBe("sk-test");
  });
});

describe("callLLM — nothing configured", () => {
  it("throws a message naming both provider options", async () => {
    await expect(callLLM({}, { prompt: "x" })).rejects.toThrow(/ANTHROPIC_API_KEY|Ollama/);
  });
});

describe("compilePolicy over Ollama", () => {
  it("compiles a policy end-to-end via a local Ollama-shaped response", async () => {
    const { url } = await fakeOllama(
      JSON.stringify({
        rules: [{ type: "spend-cap", window: "day", maxAmount: 20, escalateAbove: 2 }],
        anomalyThreshold: 0.8,
        anomalyAction: "escalate",
      }),
    );
    const policy = await compilePolicy("max $20/day, escalate over $2", "agent-1", {
      provider: "ollama",
      baseUrl: url,
    });
    expect(policy.rules).toHaveLength(1);
    const rule = policy.rules[0];
    expect(rule?.type).toBe("spend-cap");
    if (rule?.type === "spend-cap") {
      expect(rule.maxAmount).toBe(parseUnits("20", 6));
      expect(rule.escalateAbove).toBe(parseUnits("2", 6));
    }
  });
});

describe("IntentReconciler over Ollama", () => {
  const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e" as Address;
  const req: PaymentRequest = {
    intent: "weather data",
    amount: parseUnits("5", 6),
    token: USDC,
    recipient: "0x000000000000000000000000000000000000dEaD" as Address,
    chain: "eip155:84532",
    agentId: "a",
  };

  it("flags a mismatch reported by the model", async () => {
    const { url } = await fakeOllama(
      JSON.stringify({ consistent: false, concern: "amount too high for weather data" }),
    );
    const r = new IntentReconciler({ provider: "ollama", baseUrl: url });
    const check = await r.check(req);
    expect(check.passed).toBe(false);
    expect(check.severity).toBe("critical");
    expect(check.message).toContain("amount too high");
  });

  it("passes when the model reports consistency", async () => {
    const { url } = await fakeOllama(JSON.stringify({ consistent: true }));
    const r = new IntentReconciler({ provider: "ollama", baseUrl: url });
    const check = await r.check(req);
    expect(check.passed).toBe(true);
  });

  it("skips (info) with no LLM configured, no network call made", async () => {
    const r = new IntentReconciler();
    const check = await r.check(req);
    expect(check.severity).toBe("info");
    expect(check.message).toMatch(/no LLM configured/);
  });

  it("fails open with a warning if Ollama is unreachable", async () => {
    const r = new IntentReconciler({ provider: "ollama", baseUrl: "http://127.0.0.1:1" });
    const check = await r.check(req);
    expect(check.passed).toBe(true);
    expect(check.severity).toBe("warning");
  });
});
