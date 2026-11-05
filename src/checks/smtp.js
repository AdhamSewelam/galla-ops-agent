// Minimal SMTP probe used by Keeper. "rcpt" mode logs in and walks the transaction up to RCPT TO,
// then RSET/QUIT, so NOTHING is sent. That's exactly where admin@elgalla.com was being refused
// ("550 ... suspicious activity"), so the block is caught without spamming anyone.
import net from 'node:net';
import tls from 'node:tls';

export function smtpProbe({ host, port = 465, user, pass, from = user, to, timeoutMs = 20000, connect = null }) {
  return new Promise((resolve) => {
    const steps = [];
    let sock;
    let buf = '';
    let waiter = null;
    const done = (result) => { try { sock?.end(); sock?.destroy(); } catch { /* */ } clearTimeout(timer); resolve({ ...result, steps }); };
    const timer = setTimeout(() => done({ ok: false, stage: steps.at(-1)?.cmd || 'connect', error: 'timed out' }), timeoutMs);
    const onData = (d) => {
      buf += d.toString('utf8');
      // a complete reply ends with a line "NNN text" (space, not dash)
      const lines = buf.split(/\r?\n/).filter(Boolean);
      const last = lines.at(-1);
      if (last && /^\d{3} /.test(last) && buf.endsWith('\n')) { const reply = buf; buf = ''; const w = waiter; waiter = null; w?.(reply); }
    };
    const read = () => new Promise((r) => { waiter = r; });
    const cmd = async (line, label = line.split(' ')[0]) => {
      sock.write(line + '\r\n');
      const reply = await read();
      steps.push({ cmd: label, code: Number(reply.slice(0, 3)), reply: reply.trim().split(/\r?\n/).at(-1).slice(0, 200) });
      return reply;
    };
    const attach = (s) => { sock = s; s.on('data', onData); s.on('error', (e) => done({ ok: false, stage: steps.at(-1)?.cmd || 'connect', error: e.message })); };
    const code = (r) => Number(String(r).slice(0, 3));

    (async () => {
      const implicit = port === 465;
      attach(connect ? connect() : implicit ? tls.connect({ host, port, servername: host }) : net.connect({ host, port }));
      const greet = await read();
      steps.push({ cmd: 'greeting', code: code(greet), reply: greet.trim().slice(0, 200) });
      if (code(greet) !== 220) return done({ ok: false, stage: 'greeting', error: greet.trim() });
      let r = await cmd('EHLO galla-ops.monitor', 'EHLO');
      if (!implicit && /STARTTLS/i.test(r) && !connect) {
        r = await cmd('STARTTLS');
        if (code(r) !== 220) return done({ ok: false, stage: 'STARTTLS', error: r.trim() });
        const plain = sock; plain.removeListener('data', onData);
        attach(tls.connect({ socket: plain, servername: host }));
        await new Promise((ok) => sock.once('secureConnect', ok));
        await cmd('EHLO galla-ops.monitor', 'EHLO');
      }
      r = await cmd('AUTH PLAIN ' + Buffer.from(`\u0000${user}\u0000${pass}`).toString('base64'), 'AUTH');
      if (code(r) !== 235) return done({ ok: false, stage: 'AUTH', code: code(r), error: r.trim().split(/\r?\n/).at(-1) });
      r = await cmd(`MAIL FROM:<${from}>`, 'MAIL FROM');
      if (code(r) >= 400) return done({ ok: false, stage: 'MAIL FROM', code: code(r), error: r.trim() });
      r = await cmd(`RCPT TO:<${to}>`, 'RCPT TO');
      if (code(r) >= 400) return done({ ok: false, stage: 'RCPT TO', code: code(r), error: r.trim() });
      await cmd('RSET').catch(() => {});
      sock.write('QUIT\r\n');
      done({ ok: true, stage: 'RCPT TO' });
    })().catch((e) => done({ ok: false, stage: 'protocol', error: e.message }));
  });
}
