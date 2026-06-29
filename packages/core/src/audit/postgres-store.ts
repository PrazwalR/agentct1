import pg from "pg";
import type { Pool as PgPool } from "pg";
import type { AuditEntry } from "../types.js";
import {
  type AuditRow,
  type AuditStore,
  type StoredEntry,
  batchIndexOf,
  rowToEntry,
  serializeRequest,
} from "./store.js";

const PG_SCHEMA = `
CREATE TABLE IF NOT EXISTS audit_entries (
  seq           BIGSERIAL,
  id            TEXT PRIMARY KEY,
  timestamp     BIGINT NOT NULL,
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

/** Postgres-backed audit store for multi-agent operators. */
export class PostgresAuditStore implements AuditStore {
  private readonly pool: PgPool;
  private initialized?: Promise<void>;

  /** Accepts a connection string, or an injected Pool (e.g. pg-mem in tests). */
  constructor(connection: string | PgPool) {
    this.pool =
      typeof connection === "string" ? new pg.Pool({ connectionString: connection }) : connection;
  }

  private init(): Promise<void> {
    if (!this.initialized) {
      this.initialized = this.pool.query(PG_SCHEMA).then(() => undefined);
    }
    return this.initialized;
  }

  async insert(entry: AuditEntry): Promise<void> {
    await this.init();
    await this.pool.query(
      `INSERT INTO audit_entries
       (id, timestamp, agent_id, request_json, decision_json, settlement_json, entry_hash, batch_index)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NULL)`,
      [
        entry.id,
        entry.timestamp,
        entry.agentId,
        serializeRequest(entry.request),
        JSON.stringify(entry.decision),
        entry.settlement ? JSON.stringify(entry.settlement) : null,
        entry.entryHash,
      ],
    );
  }

  async list(agentId?: string): Promise<AuditEntry[]> {
    await this.init();
    const res = agentId
      ? await this.pool.query("SELECT * FROM audit_entries WHERE agent_id = $1 ORDER BY seq", [
          agentId,
        ])
      : await this.pool.query("SELECT * FROM audit_entries ORDER BY seq");
    return (res.rows as AuditRow[]).map(rowToEntry);
  }

  async getById(id: string): Promise<StoredEntry | undefined> {
    await this.init();
    const res = await this.pool.query("SELECT * FROM audit_entries WHERE id = $1", [id]);
    const row = res.rows[0] as AuditRow | undefined;
    return row ? { entry: rowToEntry(row), batchIndex: batchIndexOf(row) } : undefined;
  }

  async unbatched(): Promise<AuditEntry[]> {
    await this.init();
    const res = await this.pool.query(
      "SELECT * FROM audit_entries WHERE batch_index IS NULL ORDER BY seq",
    );
    return (res.rows as AuditRow[]).map(rowToEntry);
  }

  async markBatched(ids: string[], batchIndex: number): Promise<void> {
    await this.init();
    for (const id of ids) {
      await this.pool.query("UPDATE audit_entries SET batch_index = $1 WHERE id = $2", [
        batchIndex,
        id,
      ]);
    }
  }

  async entriesInBatch(batchIndex: number): Promise<AuditEntry[]> {
    await this.init();
    const res = await this.pool.query(
      "SELECT * FROM audit_entries WHERE batch_index = $1 ORDER BY seq",
      [batchIndex],
    );
    return (res.rows as AuditRow[]).map(rowToEntry);
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}
