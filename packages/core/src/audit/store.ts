import Database from "better-sqlite3";
import type { Hex } from "viem";
import type { AuditEntry, PaymentRequest, PolicyDecision, Settlement } from "../types.js";

/** A stored entry plus which committed batch it belongs to (null = not anchored). */
export interface StoredEntry {
  entry: AuditEntry;
  batchIndex: number | null;
}

/**
 * Storage backend for the audit log. SQLite for the CLI / single-agent case,
 * Postgres for multi-agent operators — same async interface either way.
 */
export interface AuditStore {
  insert(entry: AuditEntry): Promise<void>;
  list(agentId?: string): Promise<AuditEntry[]>;
  getById(id: string): Promise<StoredEntry | undefined>;
  unbatched(): Promise<AuditEntry[]>;
  markBatched(ids: string[], batchIndex: number): Promise<void>;
  entriesInBatch(batchIndex: number): Promise<AuditEntry[]>;
  close(): Promise<void>;
}

// ─── shared (de)serialization ────────────────────────────────────────────────

export interface AuditRow {
  id: string;
  timestamp: number | string;
  agent_id: string;
  request_json: string;
  decision_json: string;
  settlement_json: string | null;
  entry_hash: string;
  batch_index: number | string | null;
}

export function serializeRequest(r: PaymentRequest): string {
  return JSON.stringify({ ...r, amount: r.amount.toString() });
}

function deserializeRequest(s: string): PaymentRequest {
  const o = JSON.parse(s) as Omit<PaymentRequest, "amount"> & { amount: string };
  return { ...o, amount: BigInt(o.amount) };
}

export function rowToEntry(row: AuditRow): AuditEntry {
  return {
    id: row.id,
    timestamp: Number(row.timestamp),
    agentId: row.agent_id,
    request: deserializeRequest(row.request_json),
    decision: JSON.parse(row.decision_json) as PolicyDecision,
    settlement: row.settlement_json
      ? (JSON.parse(row.settlement_json) as Settlement)
      : undefined,
    entryHash: row.entry_hash as Hex,
  };
}

export function batchIndexOf(row: AuditRow): number | null {
  return row.batch_index === null ? null : Number(row.batch_index);
}

// ─── SQLite backend ──────────────────────────────────────────────────────────

const SQLITE_SCHEMA = `
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

export class SqliteAuditStore implements AuditStore {
  private _db?: Database.Database;

  constructor(private readonly path: string) {}

  private db(): Database.Database {
    if (!this._db) {
      this._db = new Database(this.path);
      this._db.pragma("journal_mode = WAL");
      this._db.exec(SQLITE_SCHEMA);
    }
    return this._db;
  }

  async insert(entry: AuditEntry): Promise<void> {
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
        serializeRequest(entry.request),
        JSON.stringify(entry.decision),
        entry.settlement ? JSON.stringify(entry.settlement) : null,
        entry.entryHash,
      );
  }

  async list(agentId?: string): Promise<AuditEntry[]> {
    const db = this.db();
    const rows = (
      agentId
        ? db.prepare("SELECT * FROM audit_entries WHERE agent_id = ? ORDER BY rowid").all(agentId)
        : db.prepare("SELECT * FROM audit_entries ORDER BY rowid").all()
    ) as AuditRow[];
    return rows.map(rowToEntry);
  }

  async getById(id: string): Promise<StoredEntry | undefined> {
    const row = this.db().prepare("SELECT * FROM audit_entries WHERE id = ?").get(id) as
      | AuditRow
      | undefined;
    if (!row) return undefined;
    return { entry: rowToEntry(row), batchIndex: batchIndexOf(row) };
  }

  async unbatched(): Promise<AuditEntry[]> {
    const rows = this.db()
      .prepare("SELECT * FROM audit_entries WHERE batch_index IS NULL ORDER BY rowid")
      .all() as AuditRow[];
    return rows.map(rowToEntry);
  }

  async markBatched(ids: string[], batchIndex: number): Promise<void> {
    const db = this.db();
    const stmt = db.prepare("UPDATE audit_entries SET batch_index = ? WHERE id = ?");
    const tx = db.transaction((batch: string[]) => {
      for (const id of batch) stmt.run(batchIndex, id);
    });
    tx(ids);
  }

  async entriesInBatch(batchIndex: number): Promise<AuditEntry[]> {
    const rows = this.db()
      .prepare("SELECT * FROM audit_entries WHERE batch_index = ? ORDER BY rowid")
      .all(batchIndex) as AuditRow[];
    return rows.map(rowToEntry);
  }

  async close(): Promise<void> {
    this._db?.close();
    this._db = undefined;
  }
}
