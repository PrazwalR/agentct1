import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { createPublicClient, http, type Address, type Hex } from "viem";
import { foundry } from "viem/chains";
import { AUDIT_ANCHOR_ABI, AuditAnchorClient, ZERO_ROOT } from "../audit/anchor.js";
import { MerkleAuditBatch } from "../audit/merkle.js";
import { hashEntry } from "../audit/logger.js";
import type { AuditEntry } from "../types.js";
import { CHAINS } from "../constants.js";

/**
 * End-to-end test of the anchoring client against a real EVM (anvil).
 *
 * This exists specifically to cover the batch-index fix: the index must come from
 * the commit's own BatchCommitted event, never from a `getBatchCount() - 1` read
 * that races a concurrent commit under the same operator key.
 *
 * Skipped automatically when anvil or forge is unavailable, so CI without Foundry
 * stays green.
 */

// Resolve the Foundry project absolutely: vitest's process.cwd() is the invocation
// directory, not this file's, so a relative cwd lands outside the repo.
const CONTRACTS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "../../../../contracts");

const RPC = "http://127.0.0.1:8546";
const CHAIN = "eip155:31337";
// anvil's first deterministic account
const KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;

function mkEntry(i: number): AuditEntry {
  const request = {
    intent: "buy data",
    amount: BigInt(100_000 + i),
    token: "0x036CbD53842c5426634e7929541eC2318f3dCF7e" as Address,
    recipient: `0x${(i + 1).toString(16).padStart(40, "0")}` as Address,
    chain: "eip155:84532",
    agentId: "anchor-agent",
  };
  const decision = { verdict: "allow" as const, riskScore: 0, checks: [], reason: "ok" };
  return {
    id: `e${i}`,
    timestamp: 1_700_000_000_000 + i,
    agentId: "anchor-agent",
    request,
    decision,
    entryHash: hashEntry(request, decision),
  };
}

function haveFoundry(): boolean {
  try {
    execFileSync("anvil", ["--version"], { stdio: "ignore" });
    execFileSync("forge", ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

const enabled = haveFoundry();
let anvil: ChildProcess | undefined;
let contract: Address;

async function waitForRpc(timeoutMs = 20_000): Promise<void> {
  const client = createPublicClient({ chain: foundry, transport: http(RPC) });
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      await client.getChainId();
      return;
    } catch {
      if (Date.now() > deadline) throw new Error("anvil did not become ready");
      await new Promise((r) => setTimeout(r, 150));
    }
  }
}

describe.skipIf(!enabled)("AuditAnchorClient against a live chain", () => {
  beforeAll(async () => {
    // Register a local chain config so the client's getChain() resolves.
    CHAINS[CHAIN] = {
      caip2: CHAIN,
      viemChain: foundry,
      usdc: "0x0000000000000000000000000000000000000001",
      usdcDomain: {
        name: "USDC",
        version: "2",
        chainId: 31337,
        verifyingContract: "0x0000000000000000000000000000000000000001",
      },
      defaultRpcUrl: RPC,
    };

    anvil = spawn("anvil", ["--port", "8546", "--silent"], { stdio: "ignore" });
    await waitForRpc();

    // Compile and deploy AuditAnchor.
    const out = execFileSync(
      "forge",
      [
        "create",
        "src/AuditAnchor.sol:AuditAnchor",
        "--rpc-url",
        RPC,
        "--private-key",
        KEY,
        "--broadcast",
        "--json",
      ],
      { cwd: CONTRACTS_DIR, encoding: "utf8" },
    );
    contract = (JSON.parse(out) as { deployedTo: string }).deployedTo as Address;
  }, 60_000);

  afterAll(() => {
    anvil?.kill();
  });

  function client() {
    return new AuditAnchorClient({
      chain: CHAIN,
      contractAddress: contract,
      committerKey: KEY,
      rpcUrl: RPC,
      // A devnet has no safe/finalized semantics — the tag never advances, so the
      // production default would (correctly) wait forever here.
      confirmationTag: "latest",
    });
  }

  it("returns the batch index from the BatchCommitted event, not a count read", async () => {
    const anchor = client();
    const operator = anchor.operatorAddress();
    const root0 = `0x${"11".repeat(32)}` as Hex;
    const first = await anchor.commit(await anchor.head(operator), root0, 3);

    expect(first.batchIndex).toBe(0);
    expect(first.txHash).toMatch(/^0x[0-9a-f]{64}$/);
    // The event index and the stored batch must agree.
    const stored = await anchor.getBatch(operator, first.batchIndex);
    expect(stored.found).toBe(true);
    expect(stored.root).toBe(root0);
    // The head advanced to what we just committed.
    expect(await anchor.head(operator)).toBe(root0);

    const second = await anchor.commit(root0, `0x${"22".repeat(32)}` as Hex, 5);
    expect(second.batchIndex).toBe(1);
  });

  it("returns each commit's OWN index, which a getBatchCount() read would get wrong", async () => {
    // The exact regression this fix exists for. Two flushes share one operator key
    // (the documented multi-agent Postgres topology). Sends are sequential here only
    // because one process cannot reuse a nonce; across processes they interleave
    // freely. What matters is that the OLD inference — getBatchCount() - 1, read
    // after both commits landed — would tag BOTH batches with the latest index.
    const anchor = client();
    const operator = anchor.operatorAddress();
    const rootA = `0x${"aa".repeat(32)}` as Hex;
    const rootB = `0x${"bb".repeat(32)}` as Hex;

    const a = await anchor.commit(await anchor.head(operator), rootA, 1);
    const b = await anchor.commit(rootA, rootB, 1);

    expect(a.batchIndex).not.toBe(b.batchIndex);
    expect(b.batchIndex).toBe(a.batchIndex + 1);

    const staleInference = (await anchor.getBatchCount(operator)) - 1;
    expect(staleInference).toBe(b.batchIndex);
    // A's rows would have been stamped with B's index and become unprovable.
    expect(a.batchIndex).not.toBe(staleInference);

    // Each returned index really does point at the root that commit reported.
    expect((await anchor.getBatch(operator, a.batchIndex)).root).toBe(rootA);
    expect((await anchor.getBatch(operator, b.batchIndex)).root).toBe(rootB);
  });

  it("rejects a commit that does not extend the operator's current head (no forks)", async () => {
    const anchor = client();
    const operator = anchor.operatorAddress();
    const stale = await anchor.head(operator);
    await anchor.commit(stale, `0x${"31".repeat(32)}` as Hex, 1);
    // `stale` is no longer the head; re-using it would fork the history.
    await expect(anchor.commit(stale, `0x${"32".repeat(32)}` as Hex, 1)).rejects.toThrow();
  });

  it("rejects an empty root and a zero entry count", async () => {
    const anchor = client();
    const operator = anchor.operatorAddress();
    const head = await anchor.head(operator);
    await expect(anchor.commit(head, ZERO_ROOT, 1)).rejects.toThrow();
    await expect(anchor.commit(head, `0x${"41".repeat(32)}` as Hex, 0)).rejects.toThrow();
  });

  it("ignores BatchCommitted events emitted by a different contract", async () => {
    // Deploy a second anchor and commit to it; the first client must not adopt its index.
    const out = execFileSync(
      "forge",
      [
        "create",
        "src/AuditAnchor.sol:AuditAnchor",
        "--rpc-url",
        RPC,
        "--private-key",
        KEY,
        "--broadcast",
        "--json",
      ],
      { cwd: CONTRACTS_DIR, encoding: "utf8" },
    );
    const other = (JSON.parse(out) as { deployedTo: string }).deployedTo as Address;
    const otherAnchor = new AuditAnchorClient({
      chain: CHAIN,
      contractAddress: other,
      committerKey: KEY,
      rpcUrl: RPC,
      confirmationTag: "latest",
    });
    const r = await otherAnchor.commit(ZERO_ROOT, `0x${"cc".repeat(32)}` as Hex, 1);
    expect(r.batchIndex).toBe(0); // fresh contract, independent numbering
  });

  it("assertChainId passes on a matching RPC and throws on a mismatched one", async () => {
    await expect(client().assertChainId()).resolves.toBeUndefined();

    // Point a Base-Sepolia-configured client at the local chain: ids disagree.
    const mismatched = new AuditAnchorClient({
      chain: "eip155:84532",
      contractAddress: contract,
      rpcUrl: RPC,
    });
    await expect(mismatched.assertChainId()).rejects.toThrow(/chain mismatch/i);
  });

  it("verifies a real StandardMerkleTree batch on-chain, and rejects tampering", async () => {
    const anchor = client();
    const operator = anchor.operatorAddress();
    const ctx = anchor.leafContext(operator);

    // Build a genuine 3-entry tree exactly as the logger would.
    const entries = [0, 1, 2].map((i) => mkEntry(i));
    const batch = new MerkleAuditBatch(ctx);
    for (const e of entries) batch.addEntry(e);

    const { batchIndex } = await anchor.commit(await anchor.head(operator), batch.root(), 3);

    for (let i = 0; i < entries.length; i++) {
      const e = entries[i]!;
      const fields = {
        agentId: e.agentId,
        timestamp: BigInt(e.timestamp),
        recipient: e.request.recipient,
        verdict: 0,
        entryHash: e.entryHash,
      };
      expect(await anchor.verifyEntry(operator, batchIndex, fields, batch.proofAt(i))).toBe(true);

      // Any altered field must fail — this is the whole point of the anchor.
      expect(
        await anchor.verifyEntry(
          operator,
          batchIndex,
          { ...fields, recipient: "0x000000000000000000000000000000000000dEaD" as Address },
          batch.proofAt(i),
        ),
      ).toBe(false);
    }

    // An internal node / the root itself must not verify as an entry.
    expect(
      await anchor.verifyEntry(
        operator,
        batchIndex,
        {
          agentId: "x",
          timestamp: 1n,
          recipient: "0x0000000000000000000000000000000000000001" as Address,
          verdict: 0,
          entryHash: batch.root(),
        },
        [],
      ),
    ).toBe(false);
  });

  it("defaults to waiting for a durable block tag, not the unsafe head", async () => {
    // Regression guard for the reorg finding: with the default tag, a commit on a
    // chain whose `safe` head lags must NOT return early and let rows be tagged.
    const strict = new AuditAnchorClient({
      chain: CHAIN,
      contractAddress: contract,
      committerKey: KEY,
      rpcUrl: RPC,
      confirmationTimeoutMs: 1_500, // don't actually wait 15 minutes
    });
    const head = await strict.head(strict.operatorAddress());
    await expect(strict.commit(head, `0x${"51".repeat(32)}` as Hex, 1)).rejects.toThrow(
      /did not reach "safe"/,
    );
  }, 20_000);

  it("flush() anchors the unbatched entries and proofsForBatch verifies them on-chain", async () => {
    const { AuditLogger } = await import("../audit/logger.js");
    const log = new AuditLogger(":memory:", {
      chain: CHAIN,
      contractAddress: contract,
      committerKey: KEY,
      rpcUrl: RPC,
      confirmationTag: "latest",
    });
    for (let i = 0; i < 4; i++) {
      await log.record(mkEntry(i).request, mkEntry(i).decision, { success: true });
    }

    const result = await log.flush();
    expect(result).toBeDefined();
    expect(result!.entryCount).toBe(4);

    const anchor = client();
    const operator = anchor.operatorAddress();
    const proofs = await log.proofsForBatch(result!.batchIndex, anchor.leafContext(operator));
    expect(proofs.size).toBe(4);

    for (const proof of proofs.values()) {
      expect(
        await anchor.verifyEntry(operator, result!.batchIndex, proof.fields, proof.proof),
      ).toBe(true);
    }
    // Nothing left unanchored, and a second flush is a no-op.
    expect(await log.flush()).toBeUndefined();
    await log.close();
  }, 30_000);

  it("reconcile() releases a batch whose root is not on chain, so it is re-anchored", async () => {
    const { AuditLogger } = await import("../audit/logger.js");
    const { SqliteAuditStore } = await import("../audit/store.js");
    const store = new SqliteAuditStore(":memory:");
    const log = new AuditLogger(store, {
      chain: CHAIN,
      contractAddress: contract,
      committerKey: KEY,
      rpcUrl: RPC,
      confirmationTag: "latest",
    });
    const e = mkEntry(90);
    await log.record(e.request, e.decision, { success: true });
    const flushed = await log.flush();
    expect(flushed).toBeDefined();

    // Healthy state: nothing to release.
    expect((await log.reconcile())!.releasedEntries).toBe(0);

    // Simulate a reorg dropping the commit: the local row still claims an index,
    // but at a root the chain never recorded.
    await store.markBatched([(await log.list())[0]!.id], 9_999, `0x${"ee".repeat(32)}`);

    const r = await log.reconcile();
    expect(r!.staleBatches).toContain(9_999);
    expect(r!.releasedEntries).toBe(1);
    // Released, so the next flush picks it back up rather than losing it silently.
    expect(await store.unbatched()).toHaveLength(1);
    await log.close();
  }, 30_000);

  it("anchors unattended on an interval, and stops when told to", async () => {
    const { AuditLogger } = await import("../audit/logger.js");
    const log = new AuditLogger(":memory:", {
      chain: CHAIN,
      contractAddress: contract,
      committerKey: KEY,
      rpcUrl: RPC,
      confirmationTag: "latest",
    });
    const e = mkEntry(70);
    await log.record(e.request, e.decision, { success: true });

    log.startAnchorScheduler(120);
    // Wait for a tick to land rather than assuming a fixed delay.
    const deadline = Date.now() + 15_000;
    while ((await log.list())[0] && Date.now() < deadline) {
      const stored = await log.getById((await log.list())[0]!.id);
      if (stored?.batchIndex !== null && stored?.batchIndex !== undefined) break;
      await new Promise((r) => setTimeout(r, 100));
    }
    const stored = await log.getById((await log.list())[0]!.id);
    expect(stored?.batchIndex).not.toBeNull();

    log.stopAnchorScheduler();
    await log.close();
  }, 30_000);

  it("a scheduled tick never overlaps itself and never throws", async () => {
    const { AuditLogger } = await import("../audit/logger.js");
    const log = new AuditLogger(":memory:", {
      chain: CHAIN,
      contractAddress: contract,
      // No committer key: every tick must fail softly rather than crash the timer.
      rpcUrl: RPC,
      confirmationTag: "latest",
    });
    const e = mkEntry(71);
    await log.record(e.request, e.decision, { success: true });

    // Without an anchor client this is a no-op; with a broken one it must not throw.
    await expect(log.anchorTick()).resolves.toBeUndefined();
    await expect(Promise.all([log.anchorTick(), log.anchorTick()])).resolves.toHaveLength(2);
    await log.close();
  }, 20_000);

  it("exposes BatchCommitted in the ABI so the index can be parsed at all", () => {
    const ev = AUDIT_ANCHOR_ABI.find((x) => x.type === "event" && x.name === "BatchCommitted");
    expect(ev).toBeDefined();
    // Both operator and batchIndex must stay indexed for log filtering to work.
    const inputs = (ev as { inputs: Array<{ name: string; indexed?: boolean }> }).inputs;
    expect(inputs.find((i) => i.name === "batchIndex")?.indexed).toBe(true);
    expect(inputs.find((i) => i.name === "operator")?.indexed).toBe(true);
  });
});

// Keep the suite honest about being skipped rather than silently passing.
describe.runIf(!enabled)("AuditAnchorClient integration (skipped)", () => {
  it("requires Foundry (anvil + forge) on PATH", () => {
    expect(enabled).toBe(false);
  });
});
