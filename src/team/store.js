// Team workspace storage: chats with agents, meetings, each agent's playbook of lessons,
// HR issues and training reviews. Lives in the agent's own SQLite file, never stores secrets.

export function migrateTeam(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS team_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      thread TEXT NOT NULL,              -- 'dm:<agentId>' or 'meeting:<id>'
      author TEXT NOT NULL,              -- 'owner' or an agent id
      text TEXT NOT NULL,
      kind TEXT NOT NULL DEFAULT 'msg',  -- msg | lesson | system
      ref TEXT,                          -- e.g. 'lesson:12'
      ts TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );
    CREATE INDEX IF NOT EXISTS team_messages_thread ON team_messages(thread, id);

    CREATE TABLE IF NOT EXISTS meetings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      agenda TEXT,
      started_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      ended_at TEXT,
      summary TEXT,
      actions TEXT                       -- JSON [{who, text}]
    );

    -- Each agent's playbook. 'proposed' lessons do nothing until Adham accepts them.
    CREATE TABLE IF NOT EXISTS lessons (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      agent TEXT NOT NULL,
      text TEXT NOT NULL,
      source TEXT NOT NULL,              -- chat | meeting | review | owner
      evidence TEXT,
      status TEXT NOT NULL DEFAULT 'proposed' CHECK (status IN ('proposed','active','declined','retired')),
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
      decided_at TEXT
    );
    CREATE INDEX IF NOT EXISTS lessons_agent ON lessons(agent, status);

    CREATE TABLE IF NOT EXISTS hr_issues (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      key TEXT NOT NULL,
      kind TEXT NOT NULL,
      agents TEXT NOT NULL,              -- JSON array of agent ids (and/or 'owner')
      title TEXT NOT NULL,
      detail TEXT,
      status TEXT NOT NULL DEFAULT 'open',
      first_seen TEXT NOT NULL,
      last_seen TEXT NOT NULL,
      resolved_at TEXT,
      notified_at TEXT
    );
    CREATE INDEX IF NOT EXISTS hr_issues_open ON hr_issues(key, status);

    CREATE TABLE IF NOT EXISTS reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      agent TEXT NOT NULL,
      period_from TEXT NOT NULL,
      period_to TEXT NOT NULL,
      score INTEGER,                     -- 1..10, null when no AI was available
      summary TEXT NOT NULL,
      strengths TEXT,                    -- JSON array
      gaps TEXT,                         -- JSON array
      stats TEXT,                        -- JSON: the measured numbers the review was based on
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );
  `);
}

export const LESSON_LIMIT = 12; // active rules per agent, oldest are retired when exceeded

export function activeLessons(db, agent) {
  return db.prepare("SELECT id, text FROM lessons WHERE agent = ? AND status = 'active' ORDER BY id").all(agent);
}

export function lessonRulesText(db, agent) {
  const rules = activeLessons(db, agent);
  return rules.length ? rules.map((r, i) => `${i + 1}. ${r.text}`).join('\n') : '(none yet)';
}

export function proposeLesson(db, { agent, text, source, evidence = null }) {
  const clean = String(text || '').replace(/\s+/g, ' ').trim().slice(0, 300);
  if (clean.length < 8) return null;
  // don't propose the same rule twice
  const dup = db.prepare("SELECT id FROM lessons WHERE agent = ? AND lower(text) = lower(?) AND status IN ('proposed','active')").get(agent, clean);
  if (dup) return null;
  const r = db.prepare('INSERT INTO lessons(agent, text, source, evidence) VALUES (?,?,?,?)').run(agent, clean, source, evidence ? String(evidence).slice(0, 1000) : null);
  return Number(r.lastInsertRowid);
}

export function decideLesson(db, id, decision) {
  const map = { accept: 'active', decline: 'declined', retire: 'retired' };
  const status = map[decision];
  if (!status) return null;
  const l = db.prepare('SELECT * FROM lessons WHERE id = ?').get(id);
  if (!l) return null;
  const allowed = decision === 'retire' ? l.status === 'active' : l.status === 'proposed';
  if (!allowed) return null;
  db.prepare("UPDATE lessons SET status = ?, decided_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?").run(status, id);
  if (status === 'active') enforceLessonLimit(db, l.agent);
  return { ...l, status };
}

/** Keeps each playbook short: beyond LESSON_LIMIT active rules, the oldest are retired. */
export function enforceLessonLimit(db, agent) {
  const active = activeLessons(db, agent);
  for (const old of active.slice(0, Math.max(0, active.length - LESSON_LIMIT))) {
    db.prepare("UPDATE lessons SET status = 'retired', decided_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?").run(old.id);
  }
}

export function addMessage(db, { thread, author, text, kind = 'msg', ref = null }) {
  const r = db.prepare('INSERT INTO team_messages(thread, author, text, kind, ref) VALUES (?,?,?,?,?)').run(thread, author, String(text).slice(0, 4000), kind, ref);
  return db.prepare('SELECT * FROM team_messages WHERE id = ?').get(Number(r.lastInsertRowid));
}

export function threadMessages(db, thread, limit = 60) {
  return db.prepare('SELECT * FROM (SELECT * FROM team_messages WHERE thread = ? ORDER BY id DESC LIMIT ?) ORDER BY id').all(thread, limit);
}
