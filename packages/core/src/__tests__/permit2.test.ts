import { describe, expect, it } from "vitest";
import { generatePrivateKey } from "viem/accounts";
import { parseUnits, type Address } from "viem";
import { ViemAdapter } from "../adapters/viem.js";
import { inspectPermit2Authorization, signPermit2Authorization } from "../x402/permit2.js";
import { recommendedAuthMethod } from "../constants.js";
import type { PaymentRequest } from "../types.js";

const USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7" as Address; // USDT (no EIP-3009)
const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e" as Address;
const DEAD = "0x000000000000000000000000000000000000dEaD" as Address;
const X402_PROXY = "0x402085c248EeA27D92E8b30b2C58ed07f9E20001".toLowerCase();

function req(token: Address): PaymentRequest {
  return {
    intent: "pay an API that settles in USDT",
    amount: parseUnits("0.10", 6),
    token,
    recipient: DEAD,
    chain: "eip155:84532",
    agentId: "a",
  };
}

describe("permit2 path", () => {
  it("signs a recipient-bound Permit2 witness for any ERC-20", async () => {
    const wallet = new ViemAdapter({ privateKey: generatePrivateKey() });
    const signed = await wallet.authorizePaymentPermit2!(req(USDT));
    const insp = inspectPermit2Authorization(signed);

    expect(insp.token.toLowerCase()).toBe(USDT.toLowerCase());
    expect(insp.recipient.toLowerCase()).toBe(DEAD.toLowerCase());
    expect(insp.amount).toBe(parseUnits("0.10", 6));
    expect(insp.spender.toLowerCase()).toBe(X402_PROXY);
    expect(signed.signature).toMatch(/^0x[0-9a-fA-F]{130}$/);
    expect(insp.deadline).toBeGreaterThan(Math.floor(Date.now() / 1000));
    expect(insp.nonce).toBeGreaterThan(0n);
  });

  it("generates a unique unordered nonce per authorization", async () => {
    const wallet = new ViemAdapter({ privateKey: generatePrivateKey() });
    const signer = await wallet.getSigner();
    const a = await signPermit2Authorization(req(USDT), signer);
    const b = await signPermit2Authorization(req(USDT), signer);
    expect(a.permit.nonce).not.toBe(b.permit.nonce);
  });

  it("recommends permit2 for USDT and eip3009 for USDC", () => {
    expect(recommendedAuthMethod(USDT)).toBe("permit2");
    expect(recommendedAuthMethod(USDC)).toBe("eip3009");
  });
});
