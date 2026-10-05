import { keccak256, toHex, type Address, type Hex } from "viem";
import { randomUUID } from "node:crypto";
import type { AuditEntry, PaymentRequest, PolicyDecision, Settlement } from "../types.js";
import { MerkleAuditBatch, type LeafContext } from "./merkle.js";
import { AuditAnchorClient, type LeafFields } from "./anchor.js";
import { type AuditStore, SqliteAuditStore } from "./store.js";
import { PostgresAuditStore } from "./postgres-store.js";

export interface AnchorConfig {
  chain: string;
  contractAddress: string;
  intervalMs?: number;
  /** Key that pays gas for root commits. Required to actually anchor. */
  committerKey?: Hex;
  rpcUrl?: string;
  /**
   * Block tag a commit must reach before entries are tagged as anchored.
   * Default "safe" — see AnchorClientConfig. Use "latest" only on a devnet whose
   * safe/finalized tags never advance.
   */
  confirmationTag?: "latest" | "safe" | "finalized";
  confirmationTimeoutMs?: number;
}

/**
 * Canonical, bigint-safe serialization of the audited fields → keccak256 leaf.
 *
 * `settlement` and `resourceUrl` are included deliberately. While they sat outside
 * the preimage, anyone with database write access — no committer key needed — could
 * rewrite whether a payment actually executed, and its transaction hash, on an
 * already-anchored entry: the recomputed root stayed bit-identical and verification
 * still passed. Tamper-evidence covered the decision and not the outcome, which is
 * the half an auditor cares about.
 */
export function hashEntry(
  req: PaymentRequest,
  decision: PolicyDecision,
  settlement?: Settlement,
): Hex {
  const canonical = JSON.stringify({
    intent: req.intent,
    amount: req.amount.toString(),
    token: req.token.toLowerCase(),
    recipient: req.recipient.toLowerCase(),
    chain: req.chain,
    agentId: req.agentId,
    resourceUrl: req.resourceUrl ?? null,
    verdict: decision.verdict,
    riskScore: decision.riskScore,
    checks: decision.checks.map((c) => `${c.id}:${c.passed}`),
    settlement: settlement
      ? {
          success: settlement.success,
          txHash: settlement.txHash?.toLowerCase() ?? null,
          nonce: settlement.nonce?.toLowerCase() ?? null,
          facilitator: settlement.facilitator ?? null,
        }
      : null,
  });
  return keccak256(toHex(canonical));
}

/**
 * Re-derive an entry's hash from its current contents.
 *
 * The stored `entry_hash` column must never be trusted when building or checking a
 * proof. It is written once at record time, so an attacker with database write
 * access could edit any field the leaf does not carry directly — amount, intent,
 * token, risk score, checks, settlement — and the stored hash, and therefore the
 * proof, would still match. Putting settlement inside hashEntry() is useless on its
 * own; the hash has to be recomputed from the row at verification time.
 */
export function recomputeEntryHash(e: AuditEntry): Hex {
  return hashEntry(e.request, e.decision, e.settlement);
}

/** An entry with its hash re-derived, so the leaf reflects the row's real contents. */
function canonicalize(e: AuditEntry): AuditEntry {
  return { ...e, entryHash: recomputeEntryHash(e) };
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
  /** The fields the contract re-hashes into the leaf; it accepts no pre-hashed leaf. */
  fields: LeafFields;
  /**
   * False when the row's stored hash disagrees with its contents — i.e. the row was
   * edited after it was written. The proof fails too, but this distinguishes
   * "someone edited the log" from "the wrong batch index" or "a reorg".
   */
  storedHashMatches: boolean;
}

export interface ReconcileResult {
  /** Batches whose locally-recorded root is absent or different on chain. */
  staleBatches: number[];
  /** Entries un-tagged so the next flush re-anchors them. */
  releasedEntries: number;
}

function verdictToNum(v: "allow" | "escalate" | "block"): number {
  return { allow: 0, escalate: 1, block: 2 }[v];
}

function makeStore(store: string): AuditStore {
  if (store.startsWith("postgres")) return new PostgresAuditStore(store);
  const path = store === "sqlite" ? (process.env.AUDIT_DB_PATH ?? "./agentctl.sqlite") : store;
  return new SqliteAuditStore(path);
}

/**
 * Records every policy decision (allowed, blocked, or escalated) to a pluggable
 * store, batches unanchored entries into a Merkle tree, and commits roots on-chain.
 */
export class AuditLogger {
  private readonly store: AuditStore;
  private readonly anchorClient?: AuditAnchorClient;
  private timer?: ReturnType<typeof setInterval>;
  /** A flush can block for minutes awaiting finality; never let two overlap. */
  private anchoring = false;

  constructor(store: string | AuditStore = "sqlite", anchor?: AnchorConfig) {
    this.store = typeof store === "string" ? makeStore(store) : store;
    if (anchor?.committerKey) {
      this.anchorClient = new AuditAnchorClient({
        chain: anchor.chain,
        contractAddress: anchor.contractAddress as Address,
        committerKey: anchor.committerKey,
        rpcUrl: anchor.rpcUrl,
        confirmationTag: anchor.confirmationTag,
        confirmationTimeoutMs: anchor.confirmationTimeoutMs,
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
      entryHash: hashEntry(req, decision, settlement),
    };
    await this.store.insert(entry);
    return entry;
  }

  list(opts: { agentId?: string } = {}): Promise<AuditEntry[]> {
    return this.store.list(opts.agentId);
  }

  /** Entries for an agent at or after `sinceMs`, oldest first (guard rehydration). */
  listSince(agentId: string, sinceMs: number): Promise<AuditEntry[]> {
    return this.store.listSince(agentId, sinceMs);
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

    const operator = this.anchorClient.operatorAddress();
    const batch = new MerkleAuditBatch(this.anchorClient.leafContext(operator));
    // Canonicalize so the committed root is a function of the rows' contents, not
    // of a hash column that could already have been edited before the first flush.
    for (const entry of rows) batch.addEntry(canonicalize(entry));
    const root = batch.root();

    // Name the head we are extending. The contract rejects anything else, so an
    // operator cannot publish a second, conflicting version of their history.
    const prevRoot = await this.anchorClient.head(operator);

    // The index comes from the commit's own BatchCommitted event, and commit()
    // does not return until the block is durable — tagging rows before that would
    // let a reorg silently un-anchor them with no path back (unbatched() filters
    // on batch_index IS NULL, so they would never be retried).
    const { txHash, batchIndex } = await this.anchorClient.commit(prevRoot, root, rows.length);

    await this.store.markBatched(
      rows.map((r) => r.id),
      batchIndex,
      root,
    );
    return { batchIndex, root, txHash, entryCount: rows.length };
  }

  /**
   * Re-check locally-anchored batches against chain and release any whose root is
   * absent or different, so the next flush() re-anchors them.
   *
   * Covers the two ways local state can drift from the chain: a reorg that drops a
   * commit we already recorded, and a crash between the commit landing and the rows
   * being tagged. Safe to run on startup and on a schedule.
   */
  async reconcile(): Promise<ReconcileResult | undefined> {
    if (!this.anchorClient) return undefined;
    const operator = this.anchorClient.operatorAddress();
    const staleBatches: number[] = [];
    let releasedEntries = 0;

    for (const [batchIndex, localRoot] of await this.store.anchoredBatches()) {
      const onChain = await this.anchorClient.getBatch(operator, batchIndex);
      const matches = onChain.found && onChain.root.toLowerCase() === localRoot.toLowerCase();
      if (matches) continue;
      staleBatches.push(batchIndex);
      releasedEntries += await this.store.releaseBatch(batchIndex);
    }
    return { staleBatches, releasedEntries };
  }

  /** Rebuild a committed batch and produce a proof for a single entry. */
  async proofFor(entryId: string, ctx: LeafContext): Promise<EntryProof | undefined> {
    const target = await this.getById(entryId);
    if (!target || target.batchIndex === null) return undefined;
    const proofs = await this.proofsForBatch(target.batchIndex, ctx);
    return proofs.get(entryId);
  }

  /**
   * Proofs for every entry in one batch, building the tree once.
   *
   * `proofFor` per entry rebuilds the whole batch tree each time, which makes
   * verifying a log O(N^2); callers walking a batch should use this instead.
   */
  async proofsForBatch(batchIndex: number, ctx: LeafContext): Promise<Map<string, EntryProof>> {
    const rows = await this.store.entriesInBatch(batchIndex);
    const canonical = rows.map(canonicalize);
    const batch = new MerkleAuditBatch(ctx);
    for (const entry of canonical) batch.addEntry(entry);
    const localRoot = batch.root();

    const out = new Map<string, EntryProof>();
    canonical.forEach((entry, i) => {
      out.set(entry.id, {
        batchIndex,
        leaf: batch.leafAt(i),
        proof: batch.proofAt(i),
        localRoot,
        fields: {
          agentId: entry.agentId,
          timestamp: BigInt(entry.timestamp),
          recipient: entry.request.recipient,
          verdict: verdictToNum(entry.decision.verdict),
          // Derived, never the stored column.
          entryHash: entry.entryHash,
        },
        storedHashMatches: entry.entryHash === rows[i]!.entryHash,
      });
    });
    return out;
  }

  /**
   * Anchor on a timer.
   *
   * `flush()` was manual-only, so a deployment that set `intervalMs` got no
   * anchoring at all — the field was declared and read by nothing. Each tick
   * reconciles first (releasing batches a reorg dropped) and then flushes, so a
   * dropped commit is retried rather than stranded.
   *
   * Errors are logged, never thrown: a scheduler that dies on one bad RPC response
   * stops anchoring forever, which is worse than a noisy log.
   */
  startAnchorScheduler(intervalMs: number): void {
    if (!this.anchorClient || this.timer) return;
    this.timer = setInterval(() => void this.anchorTick(), intervalMs);
    // Never hold the process open just to anchor.
    if (typeof this.timer.unref === "function") this.timer.unref();
  }

  stopAnchorScheduler(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
  }

  /** One reconcile-then-flush cycle. Exposed so an operator can trigger it manually. */
  async anchorTick(): Promise<FlushResult | undefined> {
    if (this.anchoring) return undefined; // a previous tick is still awaiting finality
    this.anchoring = true;
    try {
      await this.reconcile();
      return await this.flush();
    } catch (err) {
      console.warn(
        `agentctl: scheduled anchor failed, will retry next interval — ` +
          `${err instanceof Error ? err.message : String(err)}`,
      );
      return undefined;
    } finally {
      this.anchoring = false;
    }
  }

  async close(): Promise<void> {
    this.stopAnchorScheduler();
    await this.store.close();
  }
}
