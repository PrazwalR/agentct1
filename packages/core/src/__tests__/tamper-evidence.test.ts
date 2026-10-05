import { describe, expect, it } from "vitest";
import { parseUnits, type Address } from "viem";
import { hashEntry } from "../audit/logger.js";
import { MerkleAuditBatch, entryToLeaf, type LeafContext } from "../audit/merkle.js";
import type { AuditEntry, PaymentRequest, PolicyDecision, Settlement } from "../types.js";

const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e" as Address;
const RECIPIENT = "0x000000000000000000000000000000000000dEaD" as Address;

const req: PaymentRequest = {
  intent: "weather data",
  amount: parseUnits("1.5", 6),
  token: USDC,
  recipient: RECIPIENT,
  chain: "eip155:84532",
  agentId: "a",
  resourceUrl: "https://api.trusted.com/forecast",
};
const decision: PolicyDecision = { verdict: "allow", riskScore: 0, checks: [], reason: "ok" };
const settled: Settlement = {
  success: true,
  txHash: `0x${"ab".repeat(32)}`,
  facilitator: "https://x402.org/facilitator",
};

const CTX: LeafContext = {
  chainId: 84532n,
  anchor: "0x5FbDB2315678afecb367f032d93F642f64180aa3" as Address,
  operator: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" as Address,
};

function entry(over: Partial<AuditEntry> = {}, s: Settlement | undefined = settled): AuditEntry {
  return {
    id: "e1",
    timestamp: 1_700_000_000_000,
    agentId: "a",
    request: req,
    decision,
    settlement: s,
    entryHash: hashEntry(req, decision, s),
    ...over,
  };
}

describe("hashEntry covers the payment outcome", () => {
  it("changes when the settlement success flag is flipped", () => {
    // The attack this closes: DB write access alone (no committer key) was enough to
    // rewrite whether a payment executed, because settlement sat outside the preimage.
    const honest = hashEntry(req, decision, settled);
    const forged = hashEntry(req, decision, { ...settled, success: false });
    expect(forged).not.toBe(honest);
  });

  it("changes when the settlement tx hash is swapped", () => {
    const honest = hashEntry(req, decision, settled);
    const forged = hashEntry(req, decision, { ...settled, txHash: `0x${"cd".repeat(32)}` });
    expect(forged).not.toBe(honest);
  });

  it("distinguishes an unsettled entry from a settled one", () => {
    expect(hashEntry(req, decision, undefined)).not.toBe(hashEntry(req, decision, settled));
  });

  it("changes when the resource URL is swapped", () => {
    const other = { ...req, resourceUrl: "https://evil.example/drain" };
    expect(hashEntry(other, decision, settled)).not.toBe(hashEntry(req, decision, settled));
  });

  it("still covers the request and the decision", () => {
    expect(hashEntry({ ...req, amount: req.amount + 1n }, decision, settled)).not.toBe(
      hashEntry(req, decision, settled),
    );
    expect(hashEntry(req, { ...decision, verdict: "block" }, settled)).not.toBe(
      hashEntry(req, decision, settled),
    );
  });

  it("is stable for identical input", () => {
    expect(hashEntry(req, decision, settled)).toBe(hashEntry(req, decision, { ...settled }));
  });
});

describe("leaf domain separation", () => {
  const root = (ctx: LeafContext): string => {
    const b = new MerkleAuditBatch(ctx);
    b.addEntry(entry());
    return b.root();
  };

  it("binds the chain, so a testnet root is not a mainnet root", () => {
    expect(root({ ...CTX, chainId: 8453n })).not.toBe(root(CTX));
  });

  it("binds the anchor deployment", () => {
    const other = "0x000000000000000000000000000000000000BEEF" as Address;
    expect(root({ ...CTX, anchor: other })).not.toBe(root(CTX));
  });

  it("binds the operator, so a published root cannot be claimed by someone else", () => {
    const thief = "0x00000000000000000000000000000000dEadDEaD" as Address;
    expect(root({ ...CTX, operator: thief })).not.toBe(root(CTX));
  });

  it("puts the context fields first in the leaf tuple, matching the contract", () => {
    const leaf = entryToLeaf(entry(), CTX);
    expect(leaf[0]).toBe(CTX.chainId);
    expect(leaf[1]).toBe(CTX.anchor);
    expect(leaf[2]).toBe(CTX.operator);
    expect(leaf[3]).toBe("a"); // agentId
  });
});

describe("MerkleAuditBatch", () => {
  it("produces verifiable proofs for every entry", () => {
    const batch = new MerkleAuditBatch(CTX);
    for (let i = 0; i < 5; i++) batch.addEntry(entry({ id: `e${i}`, timestamp: 1700 + i }));
    expect(batch.size()).toBe(5);
    expect(batch.root()).toMatch(/^0x[0-9a-fA-F]{64}$/);
    for (let i = 0; i < 5; i++) expect(batch.verify(i)).toBe(true);
  });

  it("changes its root when any single entry is altered", () => {
    const build = (hash: `0x${string}`) => {
      const b = new MerkleAuditBatch(CTX);
      b.addEntry(entry({ id: "e0" }));
      b.addEntry(entry({ id: "e1", entryHash: hash }));
      return b.root();
    };
    expect(build(`0x${"11".repeat(32)}`)).not.toBe(build(`0x${"22".repeat(32)}`));
  });
});

// ── the verifier must re-derive the hash, not trust the stored column ───────

describe("proofsForBatch re-derives entryHash from the row", () => {
  /**
   * The bug a live run surfaced: hashEntry() covered settlement, but entry_hash was
   * written once at record time and the leaf was built from that stored column. An
   * attacker with only database write access could rewrite amount, intent, token,
   * risk score, checks or settlement and the proof still matched — a $0.10 payment
   * edited to $99.00 verified as "verified on-chain". Putting a field inside
   * hashEntry is useless unless the hash is recomputed at verification time.
   */
  const CTX2: LeafContext = CTX;

  async function storeWith(entries: AuditEntry[]) {
    const { SqliteAuditStore } = await import("../audit/store.js");
    const { AuditLogger } = await import("../audit/logger.js");
    const store = new SqliteAuditStore(":memory:");
    for (const e of entries) await store.insert(e);
    await store.markBatched(
      entries.map((e) => e.id),
      0,
      "0xdeadbeef",
    );
    return { log: new AuditLogger(store), store };
  }

  it("flags a row whose stored hash disagrees with its contents", async () => {
    const honest = entry({ id: "ok" });
    // Same shape, but the hash column was not updated after the amount changed.
    const edited: AuditEntry = {
      ...entry({ id: "edited" }),
      request: { ...req, amount: parseUnits("99", 6) },
      // entryHash deliberately left as the pre-edit value
      entryHash: hashEntry(req, decision, settled),
    };

    const { log } = await storeWith([honest, edited]);
    const proofs = await log.proofsForBatch(0, CTX2);

    expect(proofs.get("ok")!.storedHashMatches).toBe(true);
    expect(proofs.get("edited")!.storedHashMatches).toBe(false);
    await log.close();
  });

  it("detects an edited settlement, which the stored column would have hidden", async () => {
    const edited: AuditEntry = {
      ...entry({ id: "s" }),
      settlement: { ...settled, txHash: `0x${"11".repeat(32)}` },
      entryHash: hashEntry(req, decision, settled), // hash of the ORIGINAL settlement
    };
    const { log } = await storeWith([edited]);
    const proofs = await log.proofsForBatch(0, CTX2);
    expect(proofs.get("s")!.storedHashMatches).toBe(false);
    await log.close();
  });

  it("changes the leaf, so the proof cannot match the committed root either", async () => {
    const good = entry({ id: "a" });
    const { log: l1 } = await storeWith([good]);
    const before = (await l1.proofsForBatch(0, CTX2)).get("a")!;
    await l1.close();

    const tampered: AuditEntry = {
      ...good,
      request: { ...req, amount: parseUnits("99", 6) },
      entryHash: good.entryHash,
    };
    const { log: l2 } = await storeWith([tampered]);
    const after = (await l2.proofsForBatch(0, CTX2)).get("a")!;
    await l2.close();

    // A single-entry batch has root == leaf, so the root itself moves.
    expect(after.leaf).not.toBe(before.leaf);
    expect(after.localRoot).not.toBe(before.localRoot);
  });

  it("leaves an untouched log fully verifiable", async () => {
    const entries = [0, 1, 2].map((i) => entry({ id: `e${i}`, timestamp: 1700 + i }));
    const { log } = await storeWith(entries);
    const proofs = await log.proofsForBatch(0, CTX2);
    expect([...proofs.values()].every((p) => p.storedHashMatches)).toBe(true);
    await log.close();
  });
});
