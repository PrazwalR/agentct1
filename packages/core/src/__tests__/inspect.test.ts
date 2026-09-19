import { describe, expect, it } from "vitest";
import { parseUnits, type Address } from "viem";
import { AuthorizationMismatchError, assertAuthorizationMatches } from "../x402/inspect.js";
import type { PaymentRequest } from "../types.js";

const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e" as Address;
const APPROVED = "0x1111111111111111111111111111111111111111" as Address;
const ATTACKER = "0x9999999999999999999999999999999999999999" as Address;

const req: PaymentRequest = {
  intent: "weather data",
  amount: parseUnits("1.5", 6),
  token: USDC,
  recipient: APPROVED,
  chain: "eip155:84532",
  agentId: "a",
};

const eip3009 = (to: Address, value: bigint) => ({
  signature: `0x${"11".repeat(65)}`,
  authorization: {
    from: "0x2222222222222222222222222222222222222222",
    to,
    value: value.toString(),
    validAfter: "0",
    validBefore: "9999999999",
    nonce: `0x${"22".repeat(32)}`,
  },
});

const permit2 = (to: Address, amount: bigint, token: Address = USDC) => ({
  signature: `0x${"11".repeat(65)}`,
  permit2Authorization: {
    from: "0x2222222222222222222222222222222222222222",
    permitted: { token, amount: amount.toString() },
    spender: "0x402085c248EeA27D92E8b30b2C58ed07f9E20001",
    nonce: "7",
    deadline: "9999999999",
    witness: { to, validAfter: "0" },
  },
});

describe("assertAuthorizationMatches", () => {
  it("accepts an EIP-3009 authorization matching the approved decision", () => {
    expect(() => assertAuthorizationMatches(eip3009(APPROVED, req.amount), req)).not.toThrow();
  });

  it("rejects a redirected recipient — the prompt-injection case at the signature level", () => {
    expect(() => assertAuthorizationMatches(eip3009(ATTACKER, req.amount), req)).toThrow(
      AuthorizationMismatchError,
    );
  });

  it("rejects an inflated amount", () => {
    try {
      assertAuthorizationMatches(eip3009(APPROVED, parseUnits("1000", 6)), req);
      expect.unreachable("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AuthorizationMismatchError);
      expect((err as AuthorizationMismatchError).mismatches.join()).toMatch(/amount/);
    }
  });

  it("compares addresses case-insensitively (EIP-55 vs lowercase)", () => {
    const checksummed = "0x000000000000000000000000000000000000dEaD" as Address;
    const lower = checksummed.toLowerCase() as Address;
    expect(() =>
      assertAuthorizationMatches(eip3009(checksummed, req.amount), { ...req, recipient: lower }),
    ).not.toThrow();
  });

  it("checks the witness recipient, amount and token on a Permit2 payload", () => {
    expect(() => assertAuthorizationMatches(permit2(APPROVED, req.amount), req)).not.toThrow();
    expect(() => assertAuthorizationMatches(permit2(ATTACKER, req.amount), req)).toThrow(
      AuthorizationMismatchError,
    );
    const otherToken = "0x4444444444444444444444444444444444444444" as Address;
    expect(() =>
      assertAuthorizationMatches(permit2(APPROVED, req.amount, otherToken), req),
    ).toThrow(/token/);
  });

  it("reports every mismatch at once, not just the first", () => {
    try {
      assertAuthorizationMatches(eip3009(ATTACKER, parseUnits("999", 6)), req);
      expect.unreachable("should have thrown");
    } catch (err) {
      expect((err as AuthorizationMismatchError).mismatches).toHaveLength(2);
    }
  });

  it("ignores a payload shape it cannot interpret (non-EVM schemes verify their own)", () => {
    expect(() => assertAuthorizationMatches({ someSvmField: "x" }, req)).not.toThrow();
  });
});
