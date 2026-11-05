// Approval-style actions on baselines. Each one is tied to the exact content Adham saw on the confirm
// page (content hash). If the content changes before he confirms, the link is refused.
import { sha256 } from './approvals.js';
import { nowIso } from './db.js';
import { candidateSentinelBaseline, acceptSentinelBaseline } from './sentinel/job.js';

export function pageCandidates(db, brandId) {
  return db.prepare("SELECT scope, snapshot, sha256 FROM baselines WHERE scope LIKE ? AND status = 'candidate' ORDER BY scope").all(`page:${brandId}:%`);
}
export const pageCandidateHash = (db, brandId) => {
  const c = pageCandidates(db, brandId);
  return c.length ? sha256(c.map((x) => `${x.scope}=${x.sha256}`).join('\n')) : null;
};
export function pageBaselineState(db, brandId) {
  const active = db.prepare("SELECT scope, accepted_at FROM baselines WHERE scope LIKE ? AND status = 'active'").all(`page:${brandId}:%`);
  const cands = pageCandidates(db, brandId);
  const activeMap = Object.fromEntries(db.prepare("SELECT scope, sha256 FROM baselines WHERE scope LIKE ? AND status = 'active'").all(`page:${brandId}:%`).map((r) => [r.scope, r.sha256]));
  return { pages: cands.length, accepted: active.length, differs: cands.filter((c) => activeMap[c.scope] !== c.sha256).length, lastAccepted: active.map((a) => a.accepted_at).sort().at(-1) || null };
}

export function acceptPageBaselines(db, brandId, expectedHash) {
  if (pageCandidateHash(db, brandId) !== expectedHash) return null;
  const cands = pageCandidates(db, brandId);
  const tx = db.transaction(() => {
    for (const c of cands) {
      db.prepare("UPDATE baselines SET status = 'superseded' WHERE scope = ? AND status = 'active'").run(c.scope);
      db.prepare("INSERT INTO baselines(scope, snapshot, sha256, status, accepted_at) VALUES (?,?,?,'active',?)").run(c.scope, c.snapshot, c.sha256, nowIso());
    }
  });
  tx();
  return cands.length;
}

/** Current content hash for an approval item (null = item gone). Used to verify confirm links. */
export function currentHashFor(db, kind, itemId) {
  if (kind === 'accept_sentinel_baseline') return candidateSentinelBaseline(db, itemId)?.sha256 || null;
  if (kind === 'accept_page_baseline') return pageCandidateHash(db, itemId);
  if (kind === 'ack_incident') {
    const i = db.prepare("SELECT key, first_seen FROM incidents WHERE id = ? AND status = 'open'").get(Number(itemId));
    return i ? sha256(`${i.key}|${i.first_seen}`) : null;
  }
  return null;
}

export { acceptSentinelBaseline, candidateSentinelBaseline };
