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

/**
 * Postgres-backed audit store for multi-agent operators. `pg` is an optional
 * peer dependency of @agentctl/core — it's dynamically imported here so that
 * consumers who only use the default SQLite store never pay to resolve it.
 */
export class PostgresAuditStore implements AuditStore {
  private pool?: PgPool;
  private initialized?: Promise<void>;

  /** Accepts a connection string, or an already-constructed Pool (e.g. pg-mem in tests). */
  constructor(private readonly connection: string | PgPool) {}

  private async ensurePool(): Promise<PgPool> {
    if (this.pool) return this.pool;
    if (typeof this.connection === "string") {
      const pg = await import("pg");
      this.pool = new pg.default.Pool({ connectionString: this.connection });
    } else {
      this.pool = this.connection;
    }
    return this.pool;
  }

  /** Ensure the pool exists and the schema is created; returns the ready pool. */
  private async ready(): Promise<PgPool> {
    if (!this.initialized) {
      this.initialized = this.ensurePool()
        .then((pool) => pool.query(PG_SCHEMA))
        .then(() => undefined);
    }
    await this.initialized;
    // Safe: ensurePool() always sets this.pool before the schema query above resolves.
    return this.pool!;
  }

  async insert(entry: AuditEntry): Promise<void> {
    const pool = await this.ready();
    await pool.query(
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
    const pool = await this.ready();
    const res = agentId
      ? await pool.query("SELECT * FROM audit_entries WHERE agent_id = $1 ORDER BY seq", [agentId])
      : await pool.query("SELECT * FROM audit_entries ORDER BY seq");
    return (res.rows as AuditRow[]).map(rowToEntry);
  }

  async getById(id: string): Promise<StoredEntry | undefined> {
    const pool = await this.ready();
    const res = await pool.query("SELECT * FROM audit_entries WHERE id = $1", [id]);
    const row = res.rows[0] as AuditRow | undefined;
    return row ? { entry: rowToEntry(row), batchIndex: batchIndexOf(row) } : undefined;
  }

  async unbatched(): Promise<AuditEntry[]> {
    const pool = await this.ready();
    const res = await pool.query(
      "SELECT * FROM audit_entries WHERE batch_index IS NULL ORDER BY seq",
    );
    return (res.rows as AuditRow[]).map(rowToEntry);
  }

  async markBatched(ids: string[], batchIndex: number): Promise<void> {
    const pool = await this.ready();
    // Atomic: a crash mid-loop after the on-chain commit must not leave a split
    // batch (some rows tagged, some NULL) that can never be proven again.
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      for (const id of ids) {
        await client.query("UPDATE audit_entries SET batch_index = $1 WHERE id = $2", [
          batchIndex,
          id,
        ]);
      }
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  }

  async entriesInBatch(batchIndex: number): Promise<AuditEntry[]> {
    const pool = await this.ready();
    const res = await pool.query(
      "SELECT * FROM audit_entries WHERE batch_index = $1 ORDER BY seq",
      [batchIndex],
    );
    return (res.rows as AuditRow[]).map(rowToEntry);
  }

  async close(): Promise<void> {
    await this.pool?.end();
  }
}
