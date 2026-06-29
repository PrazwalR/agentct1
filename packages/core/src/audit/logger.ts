import { keccak256, toHex, type Address, type Hex } from "viem";
import { randomUUID } from "node:crypto";
import type { AuditEntry, PaymentRequest, PolicyDecision, Settlement } from "../types.js";
import { MerkleAuditBatch } from "./merkle.js";
import { AuditAnchorClient } from "./anchor.js";
import { type AuditStore, SqliteAuditStore } from "./store.js";
import { PostgresAuditStore } from "./postgres-store.js";

export interface AnchorConfig {
  chain: string;
  contractAddress: string;
  intervalMs?: number;
  /** Key that pays gas for root commits. Required to actually anchor. */
  committerKey?: Hex;
  rpcUrl?: string;
}

/** Canonical, bigint-safe serialization of the audited fields → keccak256 leaf. */
export function hashEntry(req: PaymentRequest, decision: PolicyDecision): Hex {
  const canonical = JSON.stringify({
    intent: req.intent,
    amount: req.amount.toString(),
    token: req.token.toLowerCase(),
    recipient: req.recipient.toLowerCase(),
    chain: req.chain,
    agentId: req.agentId,
    verdict: decision.verdict,
    riskScore: decision.riskScore,
    checks: decision.checks.map((c) => `${c.id}:${c.passed}`),
  });
  return keccak256(toHex(canonical));
}

export interface FlushResult {
  batchIndex: number;
  root: Hex;
  txHash: Hex;
  entryCount: number;
}

export interface EntryProof {
  batchIndex: number;
  leaf: Hex;
  proof: Hex[];
  localRoot: Hex;
}

function makeStore(store: string): AuditStore {
  if (store.startsWith("postgres")) return new PostgresAuditStore(store);
  const path = store === "sqlite" ? process.env.AUDIT_DB_PATH ?? "./agentctl.sqlite" : store;
  return new SqliteAuditStore(path);
}

/**
 * Records every policy decision (allowed, blocked, or escalated) to a pluggable
 * store, batches unanchored entries into a Merkle tree, and commits roots on-chain.
 */
export class AuditLogger {
  private readonly store: AuditStore;
  private readonly anchorClient?: AuditAnchorClient;

  constructor(store: string | AuditStore = "sqlite", anchor?: AnchorConfig) {
    this.store = typeof store === "string" ? makeStore(store) : store;
    if (anchor?.committerKey) {
      this.anchorClient = new AuditAnchorClient({
        chain: anchor.chain,
        contractAddress: anchor.contractAddress as Address,
        committerKey: anchor.committerKey,
        rpcUrl: anchor.rpcUrl,
      });
    }
  }

  async record(
    req: PaymentRequest,
    decision: PolicyDecision,
    settlement?: Settlement,
  ): Promise<AuditEntry> {
    const entry: AuditEntry = {
      id: randomUUID(),
      timestamp: Date.now(),
      agentId: req.agentId,
      request: req,
      decision,
      settlement,
      entryHash: hashEntry(req, decision),
    };
    await this.store.insert(entry);
    return entry;
  }

  list(opts: { agentId?: string } = {}): Promise<AuditEntry[]> {
    return this.store.list(opts.agentId);
  }

  async getById(id: string): Promise<(AuditEntry & { batchIndex: number | null }) | undefined> {
    const stored = await this.store.getById(id);
    return stored ? { ...stored.entry, batchIndex: stored.batchIndex } : undefined;
  }

  /**
   * Batch all not-yet-anchored entries into a Merkle tree and commit the root
   * on-chain. No-op (undefined) if anchoring isn't configured or nothing pending.
   */
  async flush(): Promise<FlushResult | undefined> {
    if (!this.anchorClient) return undefined;
    const rows = await this.store.unbatched();
    if (rows.length === 0) return undefined;

    const batch = new MerkleAuditBatch();
    for (const entry of rows) batch.addEntry(entry);
    const root = batch.root();
    const txHash = await this.anchorClient.commit(root, rows.length);

    const operator = this.anchorClient.operatorAddress();
    const idx = (await this.anchorClient.getBatchCount(operator)) - 1;
    await this.store.markBatched(
      rows.map((r) => r.id),
      idx,
    );
    return { batchIndex: idx, root, txHash, entryCount: rows.length };
  }

  /** Rebuild a committed batch and produce a proof for a single entry. */
  async proofFor(entryId: string): Promise<EntryProof | undefined> {
    const target = await this.getById(entryId);
    if (!target || target.batchIndex === null) return undefined;
    const rows = await this.store.entriesInBatch(target.batchIndex);

    const batch = new MerkleAuditBatch();
    let position = -1;
    rows.forEach((entry, i) => {
      batch.addEntry(entry);
      if (entry.id === entryId) position = i;
    });
    if (position < 0) return undefined;

    return {
      batchIndex: target.batchIndex,
      leaf: batch.leafAt(position),
      proof: batch.proofAt(position),
      localRoot: batch.root(),
    };
  }

  close(): Promise<void> {
    return this.store.close();
  }
}
