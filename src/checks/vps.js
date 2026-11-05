// Sentinel · VPS health (elgalla.com host only, VPS_MONITOR=true), every 10 min:
// CPU, RAM, disk, load, Caddy/FrankenPHP/Redis up, new PHP slow-log entries.
// CPU is sampled every minute in-process; sustained >85% for 15 min → urgent, because Hostinger's
// CPU limiter throttles this VPS (Cloudflare 524s) and the manual reset cap was already reached once.
// Everything here is read-only: /proc, statfs, `systemctl is-active`, reading the slow log.
import fs from 'node:fs';
import os from 'node:os';
import { execFile } from 'node:child_process';
import { kvGet, kvSet, nowIso } from '../db.js';

export function readCpu(procStat = () => fs.readFileSync('/proc/stat', 'utf8')) {
  const line = procStat().split('\n')[0].trim().split(/\s+/).slice(1).map(Number);
  const idle = line[3] + (line[4] || 0);
  const total = line.reduce((a, b) => a + b, 0);
  return { idle, total };
}
export const cpuPct = (a, b) => (b.total - a.total > 0 ? Math.round((1 - (b.idle - a.idle) / (b.total - a.total)) * 1000) / 10 : 0);

export function memPct(meminfo = () => fs.readFileSync('/proc/meminfo', 'utf8')) {
  const m = Object.fromEntries(meminfo().split('\n').map((l) => l.split(':')).filter((p) => p.length === 2).map(([k, v]) => [k.trim(), parseInt(v, 10)]));
  return m.MemTotal ? Math.round((1 - (m.MemAvailable ?? m.MemFree) / m.MemTotal) * 1000) / 10 : null;
}

/** Sustained = at least 13 of the last 15 one-minute samples above the threshold (tolerates a dip or a restart). */
export function sustainedHigh(samples, threshold, minutes = 15, now = Date.now()) {
  const recent = samples.filter((s) => s.t >= now - minutes * 60_000);
  if (recent.length < minutes - 2) return false;
  return recent.filter((s) => s.pct > threshold).length >= minutes - 2;
}

// 'unknown' when the unit isn't installed (so a missing frankenphp.service never alarms)
const isActive = (unit) => new Promise((resolve) => execFile('systemctl', ['show', '-p', 'LoadState,ActiveState', unit], { timeout: 5000 }, (_e, out) => {
  const kv = Object.fromEntries(String(out || '').trim().split('\n').map((l) => l.split('=')));
  resolve(!kv.LoadState || kv.LoadState === 'not-found' ? 'unknown' : kv.ActiveState || 'unknown');
}));

export function createVps({ config, db, incidents, deps = {} }) {
  const samples = [];
  let prev = null;
  const cpu = deps.readCpu || readCpu;

  function sample() {
    const cur = cpu();
    if (prev) { samples.push({ t: Date.now(), pct: cpuPct(prev, cur) }); while (samples.length > 60) samples.shift(); }
    prev = cur;
  }
  let timer = null;
  const startSampler = () => { if (!config.VPS_MONITOR || timer) return; sample(); timer = setInterval(sample, 60_000); timer.unref?.(); };

  async function run() {
    if (!config.VPS_MONITOR) return { skipped: 'VPS_MONITOR is off (only enable on the elgalla.com VPS)' };
    if (!samples.length) { sample(); await new Promise((r) => setTimeout(r, 3000)); sample(); } // manual run: quick sample
    const fresh = [];
    const flag = async (key, cond, spec) => {
      if (cond) { const { incident, isNew } = incidents.open({ key, brand: 'elgalla', category: 'vps', ...spec }); if (isNew) fresh.push(incident); }
      else await incidents.resolve(key);
    };
    const nowPct = samples.at(-1)?.pct ?? null;
    const load = os.loadavg();
    const cores = os.cpus().length;
    const ram = (deps.memPct || memPct)();
    let disk = null;
    try { const s = fs.statfsSync('/'); disk = Math.round((1 - s.bavail / s.blocks) * 1000) / 10; } catch { /* */ }
    const services = {};
    for (const u of config.VPS_SERVICES.split(',').map((x) => x.trim()).filter(Boolean)) services[u] = await (deps.isActive || isActive)(u);

    // PHP slow log: count entries added since last run
    let slow = null;
    if (config.PHP_SLOWLOG_PATH) {
      try {
        const st = fs.statSync(config.PHP_SLOWLOG_PATH);
        const last = Number(kvGet(db, 'slowlog_offset') || 0);
        const from = st.size < last ? 0 : last; // rotated
        const fd = fs.openSync(config.PHP_SLOWLOG_PATH, 'r');
        const len = Math.min(st.size - from, 2 * 1024 * 1024);
        const buf = Buffer.alloc(Math.max(0, len));
        fs.readSync(fd, buf, 0, len, from); fs.closeSync(fd);
        kvSet(db, 'slowlog_offset', st.size);
        const text = buf.toString('utf8');
        const entries = text.split(/\n(?=\[\d{2}-\w{3}-\d{4})/).filter((e) => /pool|script_filename/i.test(e));
        slow = { newEntries: entries.length, scripts: [...new Set(entries.map((e) => /script_filename = (\S+)/.exec(e)?.[1]).filter(Boolean))].slice(0, 5) };
      } catch (e) { slow = { error: e.message }; }
    }

    const sustained = sustainedHigh(samples, config.VPS_CPU_ALERT_PCT);
    await flag('vps:cpu', sustained, { severity: 'critical', title: `VPS CPU above ${config.VPS_CPU_ALERT_PCT}% for 15 minutes (now ${nowPct}%, load ${load[0].toFixed(2)} on ${cores} cores)`,
      error: `last 15 samples: ${samples.slice(-15).map((s) => s.pct).join(', ')}`,
      detail: { impact: 'Hostinger will activate the CPU limiter: elgalla.com then times out behind Cloudflare (524).', todo: 'Check `top -o %CPU` and the PHP slow log; if it is real traffic (ads), consider pausing the campaign or upgrading the VPS before the limiter kicks in.',
        verify: ['top -b -n1 -o %CPU | head -20', 'tail -50 /var/log/php*-fpm.slow.log 2>/dev/null || journalctl -u frankenphp --since "-20 min" | tail -50'] } });
    if (ram != null) await flag('vps:ram', ram > config.VPS_RAM_ALERT_PCT, { severity: 'high', title: `VPS memory at ${ram}%`, detail: { verify: ['free -m', 'ps aux --sort=-%mem | head'] } });
    if (disk != null) await flag('vps:disk', disk > config.VPS_DISK_ALERT_PCT, { severity: 'critical', title: `VPS disk ${disk}% full`, detail: { verify: ['df -h /', 'du -xh /var --max-depth=2 | sort -h | tail'] } });
    for (const [u, state] of Object.entries(services)) {
      if (state === 'unknown') continue; // unit not installed under that name
      await flag(`vps:service:${u}`, state !== 'active', { severity: 'critical', title: `${u} is ${state} on the VPS`, detail: { verify: [`systemctl status ${u} --no-pager | head -30`], remediate: [`systemctl restart ${u}`] } });
    }
    // a service removed from VPS_SERVICES (or no longer installed) closes its old incident
    for (const inc of db.prepare("SELECT key FROM incidents WHERE status = 'open' AND key LIKE 'vps:service:%'").all()) {
      const u = inc.key.slice('vps:service:'.length);
      if (!(u in services) || services[u] === 'unknown') await incidents.resolve(inc.key, { note: `${u} is no longer monitored.` });
    }
    await incidents.notify(fresh);
    const out = { at: nowIso(), cpuNow: nowPct, cpuSamples: samples.slice(-15).map((s) => s.pct), load, cores, ram, disk, services, slow };
    kvSet(db, 'vps_last', JSON.stringify(out));
    return out;
  }
  return { run, startSampler, _samples: samples };
}
