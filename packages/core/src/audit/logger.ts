import Database from "better-sqlite3";
import { keccak256, toHex, type Address, type Hex } from "viem";
import { randomUUID } from "node:crypto";
import type { AuditEntry, PaymentRequest, PolicyDecision, Settlement } from "../types.js";
import { MerkleAuditBatch } from "./merkle.js";
import { AuditAnchorClient } from "./anchor.js";

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

const SCHEMA = `
CREATE TABLE IF NOT EXISTS audit_entries (
  id            TEXT PRIMARY KEY,
  timestamp     INTEGER NOT NULL,
  agent_id      TEXT NOT NULL,
  request_json  TEXT NOT NULL,
  decision_json TEXT NOT NULL,
  settlement_json TEXT,
  entry_hash    TEXT NOT NULL,
  batch_index   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_entries(agent_id);
CREATE INDEX IF NOT EXISTS idx_audit_batch ON audit_entries(batch_index);
`;

interface Row {
  id: string;
  timestamp: number;
  agent_id: string;
  request_json: string;
  decision_json: string;
  settlement_json: string | null;
  entry_hash: string;
  batch_index: number | null;
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

/**
 * Records every policy decision to SQLite (allowed, blocked, or escalated),
 * batches unanchored entries into a Merkle tree, and commits roots on-chain.
 */
export class AuditLogger {
  private _db?: Database.Database;
  private readonly path: string;
  private readonly anchorClient?: AuditAnchorClient;

  constructor(store = "sqlite", anchor?: AnchorConfig) {
    if (store.startsWith("postgres")) {
      throw new Error("Postgres audit store not yet supported (Phase: server). Use sqlite.");
    }
    this.path = store === "sqlite" ? process.env.AUDIT_DB_PATH ?? "./agentctl.sqlite" : store;
    if (anchor?.committerKey) {
      this.anchorClient = new AuditAnchorClient({
        chain: anchor.chain,
        contractAddress: anchor.contractAddress as Address,
        committerKey: anchor.committerKey,
        rpcUrl: anchor.rpcUrl,
      });
    }
  }

  /** Lazily open the DB so evaluate-only callers never create a file. */
  private db(): Database.Database {
    if (!this._db) {
      this._db = new Database(this.path);
      this._db.pragma("journal_mode = WAL");
      this._db.exec(SCHEMA);
    }
    return this._db;
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
    this.db()
      .prepare(
        `INSERT INTO audit_entries
         (id, timestamp, agent_id, request_json, decision_json, settlement_json, entry_hash, batch_index)
         VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
      )
      .run(
        entry.id,
        entry.timestamp,
        entry.agentId,
        serializeRequest(req),
        JSON.stringify(decision),
        settlement ? JSON.stringify(settlement) : null,
        entry.entryHash,
      );
    return entry;
  }

  list(opts: { agentId?: string } = {}): AuditEntry[] {
    const db = this.db();
    const rows = (
      opts.agentId
        ? db
            .prepare("SELECT * FROM audit_entries WHERE agent_id = ? ORDER BY rowid")
            .all(opts.agentId)
        : db.prepare("SELECT * FROM audit_entries ORDER BY rowid").all()
    ) as Row[];
    return rows.map(rowToEntry);
  }

  getById(id: string): (AuditEntry & { batchIndex: number | null }) | undefined {
    const row = this.db().prepare("SELECT * FROM audit_entries WHERE id = ?").get(id) as
      | Row
      | undefined;
    if (!row) return undefined;
    return { ...rowToEntry(row), batchIndex: row.batch_index };
  }

  /**
   * Batch all not-yet-anchored entries into a Merkle tree and commit the root
   * on-chain. No-op (returns undefined) if anchoring isn't configured or there
   * is nothing to anchor.
   */
  async flush(): Promise<FlushResult | undefined> {
    if (!this.anchorClient) return undefined;
    const db = this.db();
    const rows = db
      .prepare("SELECT * FROM audit_entries WHERE batch_index IS NULL ORDER BY rowid")
      .all() as Row[];
    if (rows.length === 0) return undefined;

    const batch = new MerkleAuditBatch();
    for (const r of rows) batch.addEntry(rowToEntry(r));
    const root = batch.root();
    const txHash = await this.anchorClient.commit(root, rows.length);

    const operator = this.anchorClient.operatorAddress();
    const idx = (await this.anchorClient.getBatchCount(operator)) - 1;
    const mark = db.prepare("UPDATE audit_entries SET batch_index = ? WHERE id = ?");
    const tx = db.transaction((ids: string[]) => {
      for (const id of ids) mark.run(idx, id);
    });
    tx(rows.map((r) => r.id));
    return { batchIndex: idx, root, txHash, entryCount: rows.length };
  }

  /** Rebuild a committed batch and produce a proof for a single entry. */
  proofFor(entryId: string): EntryProof | undefined {
    const target = this.getById(entryId);
    if (!target || target.batchIndex === null) return undefined;
    const rows = this.db()
      .prepare("SELECT * FROM audit_entries WHERE batch_index = ? ORDER BY rowid")
      .all(target.batchIndex) as Row[];
    const batch = new MerkleAuditBatch();
    let position = -1;
    rows.forEach((r, i) => {
      batch.addEntry(rowToEntry(r));
      if (r.id === entryId) position = i;
    });
    if (position < 0) return undefined;
    return {
      batchIndex: target.batchIndex,
      leaf: batch.leafAt(position),
      proof: batch.proofAt(position),
      localRoot: batch.root(),
    };
  }

  close(): void {
    this._db?.close();
    this._db = undefined;
  }
}

function serializeRequest(r: PaymentRequest): string {
  return JSON.stringify({ ...r, amount: r.amount.toString() });
}

function deserializeRequest(s: string): PaymentRequest {
  const o = JSON.parse(s) as Omit<PaymentRequest, "amount"> & { amount: string };
  return { ...o, amount: BigInt(o.amount) };
}

function rowToEntry(row: Row): AuditEntry {
  return {
    id: row.id,
    timestamp: row.timestamp,
    agentId: row.agent_id,
    request: deserializeRequest(row.request_json),
    decision: JSON.parse(row.decision_json) as PolicyDecision,
    settlement: row.settlement_json
      ? (JSON.parse(row.settlement_json) as Settlement)
      : undefined,
    entryHash: row.entry_hash as Hex,
  };
}
