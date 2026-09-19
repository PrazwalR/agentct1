import { describe, expect, it } from "vitest";
import { parseUnits, type Address } from "viem";
import { generatePrivateKey } from "viem/accounts";
import { createGuard } from "../index.js";
import { ViemAdapter } from "../adapters/viem.js";
import { getChain } from "../constants.js";
import { SOLANA_MAINNET_CAIP2 } from "../solana.js";
import type { PaymentRequest, Policy } from "../types.js";

const USDC = getChain("eip155:84532").usdc;
const GOOD = "0x1111111111111111111111111111111111111111" as Address;

/** No rules at all — anything malformed would otherwise sail through as "allow". */
const openPolicy: Policy = {
  agentId: "a",
  anomalyThreshold: 0.99,
  anomalyAction: "escalate",
  rules: [],
};

async function guard() {
  return createGuard({
    wallet: new ViemAdapter({ privateKey: generatePrivateKey() }),
    policy: openPolicy,
    auditStore: ":memory:",
    hydrate: false,
  });
}

function req(over: Partial<PaymentRequest> = {}): PaymentRequest {
  return {
    intent: "x",
    amount: parseUnits("1", 6),
    token: USDC,
    recipient: GOOD,
    chain: "eip155:84532",
    agentId: "a",
    ...over,
  };
}

describe("request validation at the guard boundary", () => {
  it("allows a well-formed request (control)", async () => {
    const d = await (await guard()).evaluate(req());
    expect(d.verdict).toBe("allow");
  });

  it("blocks a malformed recipient", async () => {
    const d = await (await guard()).evaluate(req({ recipient: "0xnope" as Address }));
    expect(d.verdict).toBe("block");
    expect(d.checks[0]?.id).toBe("invalid-recipient");
    expect(d.checks[0]?.message).toMatch(/not a valid address/);
  });

  it("blocks a mixed-case address whose EIP-55 checksum is wrong", async () => {
    // 40 hex chars, but the casing does not match the checksum — the exact
    // corruption EIP-55 exists to catch, and an unrecoverable payment if allowed.
    const corrupted = "0x00000000000000000000000000000000deAddEad" as Address;
    const d = await (await guard()).evaluate(req({ recipient: corrupted }));
    expect(d.verdict).toBe("block");
    expect(d.checks[0]?.message).toMatch(/checksum/);
  });

  it("accepts both all-lowercase and properly-checksummed addresses", async () => {
    for (const recipient of [
      "0x00000000000000000000000000000000deaddead",
      "0x00000000000000000000000000000000dEadDEaD",
    ] as Address[]) {
      const d = await (await guard()).evaluate(req({ recipient }));
      expect(d.verdict, recipient).toBe("allow");
    }
  });

  it("blocks a malformed token address", async () => {
    const d = await (await guard()).evaluate(req({ token: "0x1234" as Address }));
    expect(d.verdict).toBe("block");
    expect(d.checks[0]?.id).toBe("invalid-token");
  });

  it("blocks a chain id that is not CAIP-2", async () => {
    for (const chain of ["8453", "base", "eip155:"]) {
      const d = await (await guard()).evaluate(req({ chain }));
      expect(d.verdict, chain).toBe("block");
      expect(d.checks[0]?.id).toBe("invalid-chain");
    }
  });

  it("does not apply the EVM address check to Solana (base58, not hex)", async () => {
    const d = await (
      await guard()
    ).evaluate(
      req({
        chain: SOLANA_MAINNET_CAIP2,
        recipient: "3vZ5LDVUWjnrdMkxTGWFkYJTsBGXSxoiTvHhzWDNBzTh" as unknown as Address,
        token: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" as unknown as Address,
      }),
    );
    expect(d.verdict).toBe("allow");
  });
});
