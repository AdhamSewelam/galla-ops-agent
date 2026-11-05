// HTTP surface: /health, /ingest (signed host sentinel reports), /dashboard (+ /a/:id confirm pages).
import express from 'express';
import { mountDashboard } from './dashboard.js';
import { verifyAndStore } from './sentinel/ingest.js';
import { audit } from './audit.js';

export function createServer({ config, db, registry, jobs = {}, voice = null, claude = null, mailer = null, jobState = null }) {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 'loopback'); // Caddy runs on the same machine

  app.get('/health', (_req, res) => res.json({ ok: true }));
  app.get('/', (_req, res) => res.redirect('/dashboard'));

  // Ingest: raw body (the signature covers the exact bytes). Failed attempts are rate-limited per IP.
  const bad = new Map();
  app.post('/ingest', express.raw({ type: '*/*', limit: '12mb' }), (req, res) => {
    const ip = req.ip, now = Date.now();
    const recent = (bad.get(ip) || []).filter((t) => now - t < 10 * 60_000);
    if (recent.length >= 20) return res.status(429).json({ ok: false, error: 'too many bad requests' });
    const r = verifyAndStore({ config, db, registry, headers: req.headers, rawBody: req.body });
    if (!r.ok) {
      bad.set(ip, [...recent, now]);
      audit(db, { actor: 'visitor', action: 'ingest_rejected', target: String(req.get('x-galla-host') || '?').slice(0, 60), detail: { ip, reason: r.reason }, outcome: 'blocked' });
      return res.status(r.status).json({ ok: false, error: r.reason });
    }
    audit(db, { actor: 'warden', action: 'sentinel_report_received', target: r.host, detail: { bytes: req.body.length, installs: r.report.installs.length } });
    res.json({ ok: true, id: r.reportId });
    jobs.sentinel?.evaluate(r.host).catch((e) => audit(db, { actor: 'warden', action: 'sentinel_evaluate_failed', target: r.host, detail: { error: e.message }, outcome: 'error' }));
  });

  app.use(express.urlencoded({ extended: false, limit: '20kb' }));
  mountDashboard(app, { config, db, registry, jobState, voice, claude, mailer, jobs });
  return app;
}
