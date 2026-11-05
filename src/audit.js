// Append-only activity log (the database blocks UPDATE and DELETE). Everything is redacted first.
import { redact, redactText } from './redact.js';

export function audit(db, { actor = 'agent', action, target = null, detail = null, outcome = 'ok' }) {
  db.prepare('INSERT INTO audit_log(actor, action, target, detail, outcome) VALUES (?,?,?,?,?)').run(
    actor,
    action,
    target == null ? null : redactText(target),
    detail == null ? null : JSON.stringify(redact(detail)),
    outcome,
  );
  if (process.env.GALLA_QUIET) return;
  const line = `[${new Date().toISOString()}] ${actor} ${action}${target ? ' ' + redactText(target) : ''} → ${outcome}`;
  outcome === 'ok' ? console.log(line) : console.warn(line);
}
