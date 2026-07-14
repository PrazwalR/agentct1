import { describe, expect, it } from "vitest";
import { HTTPFacilitatorClient } from "@x402/core/http";
import { FailoverFacilitatorClient } from "../x402/facilitator.js";

// Minimal fakes shaped like HTTPFacilitatorClient (only settle/verify are used).
function fakeSettle(
  fn: () => Promise<{ success: boolean; transaction: string; network: string }>,
): HTTPFacilitatorClient {
  return {
    settle: fn,
    verify: async () => ({ isValid: true }),
  } as unknown as HTTPFacilitatorClient;
}

const ok = () =>
  fakeSettle(async () => ({ success: true, transaction: "0xabc", network: "eip155:84532" }));
const down = () =>
  fakeSettle(async () => {
    throw new Error("facilitator down");
  });
const settledFalse = () =>
  fakeSettle(async () => ({ success: false, transaction: "", network: "eip155:84532" }));

const args = [{} as never, {} as never] as const;

describe("FailoverFacilitatorClient", () => {
  it("falls over to the next facilitator when the primary throws", async () => {
    const fc = new FailoverFacilitatorClient([down(), ok()]);
    const res = await fc.settle(...args);
    expect(res.success).toBe(true);
    expect(res.transaction).toBe("0xabc");
  });

  it("does NOT fail over on a returned success:false (avoids double-settle)", async () => {
    const fc = new FailoverFacilitatorClient([settledFalse(), ok()]);
    const res = await fc.settle(...args);
    expect(res.success).toBe(false); // primary's definitive result is returned as-is
  });

  it("throws when every facilitator throws", async () => {
    const fc = new FailoverFacilitatorClient([down(), down()]);
    await expect(fc.settle(...args)).rejects.toThrow(/facilitator down/);
  });

  it("requires at least one facilitator", () => {
    expect(() => new FailoverFacilitatorClient([])).toThrow();
  });
});
