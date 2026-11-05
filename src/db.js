// The agent's own SQLite database. It never stores secrets or customer personal data.
import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';
import { migrateTeam } from './team/store.js';

export function openDb(dataDir) {
  fs.mkdirSync(dataDir, { recursive: true });
  const db = new Database(path.join(dataDir, 'galla-ops.db'));
  db.pragma('journal_mode = WAL');
  db.pragma('busy_timeout = 5000');
  migrate(db);
  return db;
}

export function openMemoryDb() {
  const db = new Database(':memory:');
  migrate(db);
  return db;
}

function migrate(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT, detail TEXT, outcome TEXT
    );
    CREATE INDEX IF NOT EXISTS audit_action ON audit_log(action, id);
    CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
      BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
    CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
      BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

    CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);

    -- uptime: current state per check, and daily counters for uptime %
    CREATE TABLE IF NOT EXISTS check_state (
      key TEXT PRIMARY KEY, brand TEXT, label TEXT,
      consecutive_failures INTEGER NOT NULL DEFAULT 0,
      last_ok TEXT, last_fail TEXT, last_error TEXT, last_kind TEXT, last_ms INTEGER
    );
    CREATE TABLE IF NOT EXISTS check_daily (
      day TEXT NOT NULL, key TEXT NOT NULL, brand TEXT, ok INTEGER NOT NULL DEFAULT 0, fail INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (day, key)
    );

    -- every alertable problem (uptime, security, orders, keeper, vps, sentinel)
    CREATE TABLE IF NOT EXISTS incidents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      key TEXT NOT NULL,
      brand TEXT,                       -- brand id, or NULL for agent/host-wide
      category TEXT NOT NULL,           -- uptime | security | orders | keeper | vps | sentinel | test
      severity TEXT NOT NULL,           -- critical | high | medium
      title TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'open',  -- open | resolved | test
      first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
      last_error TEXT,
      detail TEXT,                      -- JSON: where, evidence, verify/remediate commands
      parent_key TEXT,                  -- grouped under a host-level incident (no separate alert)
      notified_at TEXT, acknowledged_at TEXT, resolved_at TEXT
    );
    CREATE INDEX IF NOT EXISTS incidents_open ON incidents(key, status);
    CREATE INDEX IF NOT EXISTS incidents_brand ON incidents(brand, status);

    -- host sentinel
    CREATE TABLE IF NOT EXISTS sentinel_reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT NOT NULL,
      received_at TEXT NOT NULL, generated_at TEXT, report TEXT NOT NULL, sha256 TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS sentinel_reports_host ON sentinel_reports(host, id);
    CREATE TABLE IF NOT EXISTS sentinel_nonces (nonce TEXT PRIMARY KEY, host TEXT NOT NULL, ts INTEGER NOT NULL);

    -- approved baselines (sentinel host state, page script inventory)
    CREATE TABLE IF NOT EXISTS baselines (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scope TEXT NOT NULL,              -- 'sentinel:<host>' | 'page:<check key>'
      snapshot TEXT NOT NULL, sha256 TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('candidate','active','superseded')),
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      accepted_at TEXT
    );
    CREATE INDEX IF NOT EXISTS baselines_scope ON baselines(scope, status);

    -- signed, expiring, item-bound approvals (accept baseline, acknowledge finding)
    CREATE TABLE IF NOT EXISTS approvals (
      id TEXT PRIMARY KEY, kind TEXT NOT NULL, item_id TEXT NOT NULL, content_hash TEXT NOT NULL,
      requested_at TEXT NOT NULL, expires_at TEXT NOT NULL, decision TEXT, decided_at TEXT
    );

    -- orders: hourly counts only (no customer data)
    CREATE TABLE IF NOT EXISTS order_stats (
      brand TEXT NOT NULL, site TEXT NOT NULL, hour TEXT NOT NULL,
      created INTEGER NOT NULL DEFAULT 0, paid INTEGER NOT NULL DEFAULT 0, failed INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (brand, site, hour)
    );

    -- product data issues from the latest Curator run (report only)
    CREATE TABLE IF NOT EXISTS product_issues (
      id INTEGER PRIMARY KEY AUTOINCREMENT, brand TEXT NOT NULL, site TEXT, kind TEXT NOT NULL,
      product_id INTEGER, sku TEXT, name TEXT, url TEXT, detail TEXT, run_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS product_issues_brand ON product_issues(brand, kind);

    CREATE TABLE IF NOT EXISTS seo_reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT, brand TEXT NOT NULL, created_at TEXT NOT NULL,
      summary TEXT, fixes TEXT, stats TEXT
    );
  `);
  migrateTeam(db);
}

export const nowIso = () => new Date().toISOString();
export const kvGet = (db, key) => db.prepare('SELECT value FROM kv WHERE key = ?').get(key)?.value ?? null;
export function kvSet(db, key, value) {
  db.prepare('INSERT INTO kv(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(key, String(value));
}
export const kvJson = (db, key, fallback = null) => {
  const v = kvGet(db, key);
  try { return v == null ? fallback : JSON.parse(v); } catch { return fallback; }
};
