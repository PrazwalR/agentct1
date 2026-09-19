import { describe, expect, it } from "vitest";
import { getAddress, type Address } from "viem";
import { PolicyEvaluator } from "../policy/evaluator.js";
import type { PaymentRequest, Policy } from "../types.js";

const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e" as Address;
// Has hex letters, so its EIP-55 form is genuinely mixed-case (0x1111… checksums to itself).
const RECIPIENT = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" as Address;

function resourcePolicy(entries: string[], enforce = true): Policy {
  return {
    agentId: "a",
    anomalyThreshold: 0.8,
    anomalyAction: "escalate",
    rules: [{ type: "allowlist", mode: "resources", entries, enforce }],
  };
}

function req(resourceUrl?: string, recipient: Address = RECIPIENT): PaymentRequest {
  return {
    intent: "x",
    amount: 1_000_000n,
    token: USDC,
    recipient,
    chain: "eip155:84532",
    agentId: "a",
    resourceUrl,
  };
}

async function verdictFor(policy: Policy, r: PaymentRequest, id: string) {
  const checks = (await new PolicyEvaluator(policy).evaluate(r)).checks;
  return checks.find((c) => c.id === id);
}

describe("resource allowlist — structural URL matching", () => {
  const policy = resourcePolicy(["api.trusted.com"]);

  it("allows the exact host and its subdomains", async () => {
    for (const url of [
      "https://api.trusted.com/data",
      "https://api.trusted.com/",
      "https://v2.api.trusted.com/data",
    ]) {
      expect((await verdictFor(policy, req(url), "allowlist-resources"))?.passed).toBe(true);
    }
  });

  it("rejects a URL that merely CONTAINS the entry (the substring bypass)", async () => {
    // The old `target.includes(entry)` check let every one of these through an
    // enforced allowlist.
    for (const url of [
      "https://evil.example/?ref=api.trusted.com",
      "https://evil.example/api.trusted.com/drain",
      "https://evil.example/#api.trusted.com",
    ]) {
      const check = await verdictFor(policy, req(url), "allowlist-resources");
      expect(check?.passed, url).toBe(false);
      expect(check?.severity, url).toBe("critical");
    }
  });

  it("rejects a host that only ends with the entry's characters", async () => {
    // "evil-api.trusted.com" and a suffix-spoofed domain must not match.
    for (const url of [
      "https://evil-api.trusted.com/data",
      "https://api.trusted.com.attacker.net/data",
    ]) {
      expect((await verdictFor(policy, req(url), "allowlist-resources"))?.passed, url).toBe(false);
    }
  });

  it("honours an optional path prefix on the entry", async () => {
    const scoped = resourcePolicy(["api.trusted.com/v2"]);
    expect(
      (await verdictFor(scoped, req("https://api.trusted.com/v2/forecast"), "allowlist-resources"))
        ?.passed,
    ).toBe(true);
    expect(
      (await verdictFor(scoped, req("https://api.trusted.com/v2"), "allowlist-resources"))?.passed,
    ).toBe(true);
    // "/v2" must not license "/v2xyz" or a different path entirely.
    expect(
      (await verdictFor(scoped, req("https://api.trusted.com/v2xyz"), "allowlist-resources"))
        ?.passed,
    ).toBe(false);
    expect(
      (await verdictFor(scoped, req("https://api.trusted.com/admin"), "allowlist-resources"))
        ?.passed,
    ).toBe(false);
  });

  it("fails closed on an unparseable or missing resource URL", async () => {
    expect((await verdictFor(policy, req("not a url"), "allowlist-resources"))?.passed).toBe(false);
    expect((await verdictFor(policy, req(undefined), "allowlist-resources"))?.passed).toBe(false);
  });

  it("is case-insensitive on the host", async () => {
    expect(
      (await verdictFor(policy, req("https://API.Trusted.COM/data"), "allowlist-resources"))
        ?.passed,
    ).toBe(true);
  });
});

describe("recipient allowlist — entry normalization", () => {
  it("matches a checksummed entry against the lowercased recipient", async () => {
    // A hand-written policy.json carries EIP-55 checksummed addresses — the form
    // every explorer and wallet emits. Before normalizing, this matched nothing and
    // silently blocked every payment.
    const policy: Policy = {
      agentId: "a",
      anomalyThreshold: 0.8,
      anomalyAction: "escalate",
      rules: [
        { type: "allowlist", mode: "recipients", entries: [getAddress(RECIPIENT)], enforce: true },
      ],
    };
    expect(getAddress(RECIPIENT)).not.toBe(RECIPIENT); // the entry really is mixed-case
    expect((await verdictFor(policy, req(undefined), "allowlist-recipients"))?.passed).toBe(true);
  });

  it("still blocks a recipient that is genuinely not listed", async () => {
    const other = "0x2222222222222222222222222222222222222222" as Address;
    const policy: Policy = {
      agentId: "a",
      anomalyThreshold: 0.8,
      anomalyAction: "escalate",
      rules: [
        { type: "allowlist", mode: "recipients", entries: [getAddress(RECIPIENT)], enforce: true },
      ],
    };
    const check = await verdictFor(policy, req(undefined, other), "allowlist-recipients");
    expect(check?.passed).toBe(false);
    expect(check?.severity).toBe("critical");
  });
});
