// Command Center → Team: chat with each agent, hold team meetings, and Harmony's HR desk
// (team issues, performance reviews, and playbook lessons waiting for Adham's decision).
import express from 'express';
import { audit } from '../audit.js';
import { TEAM, agentById, activityOf } from './brief.js';
import { createTeam } from './chat.js';
import { createHr, LEARNS_IN_WORK } from './hr.js';
import { threadMessages, decideLesson, activeLessons, enforceLessonLimit } from './store.js';

export function mountTeam(app, { config, db, registry, jobState, claude, mailer, requireAuth, csrf, safeEq, shell, viewSwitch }) {
  const team = createTeam({ config, db, claude, registry, jobState });
  const hr = createHr({ config, db, claude, registry, mailer: mailer || { send: async () => ({ sent: false }) } });
  const json = express.json({ limit: '20kb' });

  // every write needs the CSRF header; AI calls are rate-limited to protect the AI quota
  const aiHits = [];
  const guard = (ai = false) => (req, res, next) => {
    if (!safeEq(req.get('x-csrf') || '', csrf(req))) return res.status(400).json({ error: 'Bad request (refresh the page)' });
    if (ai) {
      const now = Date.now();
      while (aiHits.length && now - aiHits[0] > 10 * 60_000) aiHits.shift();
      if (aiHits.length >= 40) return res.status(429).json({ error: 'Too many messages in 10 minutes. Wait a moment.' });
      aiHits.push(now);
    }
    next();
  };
  const handle = (fn) => async (req, res) => {
    try {
      res.json(await fn(req));
    } catch (e) {
      res.status(e.status || 500).json({ error: e.message || 'Something went wrong' });
    }
  };
  const lessonState = (agent) => Object.fromEntries(db.prepare('SELECT id, status FROM lessons WHERE agent = ?').all(agent).map((l) => [l.id, l.status]));
  const allLessonState = () => Object.fromEntries(db.prepare('SELECT id, status FROM lessons').all().map((l) => [l.id, l.status]));

  app.get('/dashboard/team', requireAuth, (req, res) => res.send(shell('Team', teamPage(csrf(req), viewSwitch), TEAM_CSS)));

  app.get('/dashboard/api/team', requireAuth, handle(() => {
    const people = Object.fromEntries(TEAM.map((a) => [a.id, activityOf(db, a, jobState)]));
    const counts = Object.fromEntries(db.prepare("SELECT agent, SUM(status='active') active, SUM(status='proposed') proposed FROM lessons GROUP BY agent").all().map((r) => [r.agent, r]));
    return {
      owner: config.OWNER_NAME || 'Adham',
      ai: Boolean(claude),
      team: TEAM.map((a) => ({
        ...a,
        learnsInWork: LEARNS_IN_WORK.has(a.id),
        activity: people[a.id]?.activity || 'unknown',
        activityText: people[a.id]?.activityText || '',
        lessons: counts[a.id]?.active || 0,
        proposed: counts[a.id]?.proposed || 0,
      })),
      hr: {
        open: db.prepare("SELECT COUNT(*) n FROM hr_issues WHERE status = 'open'").get().n,
        proposals: db.prepare("SELECT COUNT(*) n FROM lessons WHERE status = 'proposed'").get().n,
      },
      meetings: db.prepare('SELECT id, agenda, started_at, ended_at FROM meetings ORDER BY id DESC LIMIT 15').all(),
    };
  }));

  // ── 1:1 chat ──
  app.get('/dashboard/api/team/dm/:agent', requireAuth, handle((req) => {
    const agent = agentById(req.params.agent);
    if (!agent) throw Object.assign(new Error('Unknown team member'), { status: 404 });
    return {
      agent: { ...agent, learnsInWork: LEARNS_IN_WORK.has(agent.id) },
      messages: threadMessages(db, `dm:${agent.id}`, 80),
      lessonState: lessonState(agent.id),
      playbook: activeLessons(db, agent.id),
      review: db.prepare('SELECT score, summary, strengths, gaps, created_at FROM reviews WHERE agent = ? ORDER BY id DESC LIMIT 1').get(agent.id) || null,
    };
  }));
  app.post('/dashboard/api/team/dm/:agent', requireAuth, json, guard(true), handle(async (req) => ({
    messages: await team.chat(req.params.agent, req.body?.text),
    lessonState: lessonState(req.params.agent),
  })));

  // ── Meetings ──
  app.post('/dashboard/api/team/meetings', requireAuth, json, guard(true), handle(async (req) => team.startMeeting(req.body?.agenda)));
  app.get('/dashboard/api/team/meetings/:id', requireAuth, handle((req) => {
    const meeting = db.prepare('SELECT * FROM meetings WHERE id = ?').get(Number(req.params.id));
    if (!meeting) throw Object.assign(new Error('Meeting not found'), { status: 404 });
    return { meeting, messages: threadMessages(db, `meeting:${meeting.id}`, 200), lessonState: allLessonState() };
  }));
  app.post('/dashboard/api/team/meetings/:id/say', requireAuth, json, guard(true), handle(async (req) => ({
    messages: await team.meetingSay(Number(req.params.id), req.body?.text),
    lessonState: allLessonState(),
  })));
  app.post('/dashboard/api/team/meetings/:id/end', requireAuth, json, guard(true), handle(async (req) => ({ meeting: await team.endMeeting(Number(req.params.id)) })));

  // ── HR desk ──
  app.get('/dashboard/api/team/hr', requireAuth, handle(() => ({
    issues: db.prepare("SELECT * FROM hr_issues WHERE status = 'open' OR resolved_at >= ? ORDER BY status = 'open' DESC, id DESC LIMIT 40").all(new Date(Date.now() - 7 * 86400_000).toISOString()),
    reviews: db.prepare('SELECT id, agent, score, summary, strengths, gaps, created_at FROM reviews ORDER BY id DESC LIMIT 20').all(),
    proposals: db.prepare("SELECT id, agent, text, source, created_at FROM lessons WHERE status = 'proposed' ORDER BY id DESC").all(),
    nextReview: hr.nextForReview(),
  })));
  app.post('/dashboard/api/team/hr/check', requireAuth, json, guard(), handle(async () => {
    audit(db, { actor: 'owner', action: 'hr_check_requested' });
    return hr.runChecks();
  }));
  app.post('/dashboard/api/team/hr/review/:agent', requireAuth, json, guard(true), handle(async (req) => {
    if (!agentById(req.params.agent)) throw Object.assign(new Error('Unknown team member'), { status: 404 });
    audit(db, { actor: 'owner', action: 'review_requested', target: req.params.agent });
    return hr.review(req.params.agent);
  }));

  // ── Playbook lessons: Adham decides; nothing changes an agent's behaviour until accepted ──
  app.post('/dashboard/api/team/lessons/:id/:decision', requireAuth, json, guard(), handle((req) => {
    const l = decideLesson(db, Number(req.params.id), req.params.decision);
    if (!l) throw Object.assign(new Error('That lesson can no longer be changed.'), { status: 400 });
    audit(db, { actor: 'owner', action: `lesson_${l.status}`, target: `lesson:${l.id}`, detail: { agent: l.agent } });
    return { id: l.id, status: l.status, agent: l.agent };
  }));
  app.post('/dashboard/api/team/lessons', requireAuth, json, guard(), handle((req) => {
    const agent = agentById(String(req.body?.agent || ''));
    const text = String(req.body?.text || '').replace(/\s+/g, ' ').trim().slice(0, 300);
    if (!agent || text.length < 8) throw Object.assign(new Error('Pick a team member and write a rule (8+ characters).'), { status: 400 });
    const id = Number(db.prepare("INSERT INTO lessons(agent, text, source, status, decided_at) VALUES (?,?,'owner','active',strftime('%Y-%m-%dT%H:%M:%fZ','now'))").run(agent.id, text).lastInsertRowid);
    enforceLessonLimit(db, agent.id);
    audit(db, { actor: 'owner', action: 'lesson_added', target: `lesson:${id}`, detail: { agent: agent.id } });
    return { id, agent: agent.id, status: 'active' };
  }));
}

function teamPage(csrfToken, viewSwitch) {
  return `${viewSwitch('team')}
<div class="team" id="team" data-csrf="${csrfToken}">
  <aside class="side" aria-label="Team">
    <button class="room" data-open="meeting"><b>Meeting Room</b><span id="meetCount" class="muted small"></span></button>
    <button class="room" data-open="hr"><b>HR desk · Harmony</b><span id="hrCount" class="muted small"></span></button>
    <h3>Team</h3>
    <div id="roster" role="list"></div>
  </aside>
  <section class="pane" id="pane" aria-live="polite"><p class="muted">Loading…</p></section>
</div>
<script>${TEAM_JS}</script>`;
}

const TEAM_CSS = `
.team{display:grid;grid-template-columns:270px 1fr;gap:14px;min-height:calc(100vh - 140px)}
@media (max-width:820px){.team{grid-template-columns:1fr}.side{order:0}}
.side{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px;align-self:start}
.side h3{margin:14px 4px 6px}
.room,.who{display:flex;flex-direction:column;align-items:flex-start;width:100%;text-align:left;background:transparent;border:1px solid transparent;border-radius:10px;padding:9px 10px;color:var(--text);font:14px Inter,sans-serif;margin-bottom:4px}
.room{background:var(--bg);border-color:var(--line)}
.room.on,.who.on{border-color:var(--gold2);background:rgba(199,152,104,.12)}
.who .nm{display:flex;gap:8px;align-items:center;font-weight:600}.who .rl{font-size:12px;color:var(--muted);margin-left:16px}
.dot{width:8px;height:8px;border-radius:50%;background:var(--muted);flex:none}.dot.good{background:var(--good)}.dot.bad{background:var(--bad)}.dot.warn{background:var(--gold2)}.dot.blue{background:#3f78b5}
.badge{background:var(--bad);color:#fff;font-size:11px;font-weight:700;border-radius:999px;padding:1px 7px;margin-left:6px}
.pane{background:var(--card);border:1px solid var(--line);border-radius:12px;display:flex;flex-direction:column;min-height:560px;min-width:0}
.ph{padding:14px 16px;border-bottom:1px solid var(--line)}.ph h2{margin:0;font-size:18px}.ph p{margin:2px 0 0}
.msgs{flex:1;overflow:auto;padding:16px;display:flex;flex-direction:column;gap:10px;max-height:calc(100vh - 330px);min-height:260px}
.m{max-width:78%;padding:9px 12px;border-radius:12px;background:var(--bg);border:1px solid var(--line);white-space:pre-wrap;word-wrap:break-word}
.m .by{font-size:12px;font-weight:600;color:var(--gold);margin-bottom:2px}
.m.me{align-self:flex-end;background:var(--ink2);color:#f6f7fa;border-color:var(--ink2)}
.m.sys{align-self:center;background:transparent;border:0;color:var(--muted);font-size:13px;text-align:center;max-width:92%}
.m.lesson{border-left:3px solid var(--gold2)}.m.lesson .by:before{content:"Proposed rule · "}.m.lesson.decided .by:before{content:"Rule · "}.m.lesson.declined{opacity:.6}
.lact{display:flex;gap:6px;margin-top:8px}.lact button{padding:5px 10px;font-size:12.5px}
.composer{display:flex;gap:8px;padding:12px;border-top:1px solid var(--line)}
.composer textarea{margin:0;min-height:44px;max-height:160px;resize:vertical}
.composer button{align-self:flex-end}
.typing{color:var(--muted);font-size:13px;font-style:italic}
.pb{padding:0 16px 10px}.pb summary{font-size:13px}.pb ol{margin:6px 0;padding-left:20px;font-size:13.5px}.pb li{margin:3px 0}
.pb li button{padding:2px 8px;font-size:11.5px;margin-left:6px}
.sec{padding:14px 16px;border-top:1px solid var(--line)}.sec:first-of-type{border-top:0}
.issue{padding:10px 12px;border-left:3px solid var(--bad);background:var(--bg);border-radius:0 8px 8px 0;margin-bottom:8px}.issue.res{border-color:var(--good);opacity:.75}
.issue span{display:block;font-size:12.5px;color:var(--muted)}
.rv{padding:10px 12px;background:var(--bg);border-radius:8px;margin-bottom:8px;font-size:13.5px}.rv b{font-size:14px}
.score{display:inline-block;font-weight:700;border-radius:6px;padding:1px 7px;margin-left:6px;background:var(--line)}
.inline-form{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.inline-form select,.inline-form input{width:auto;flex:1;min-width:140px;border:1px solid var(--line);border-radius:8px;padding:8px;background:var(--card);color:var(--text);font:14px Inter,sans-serif;margin:0}
.mlist{list-style:none;padding:0;margin:0}.mlist li{padding:8px 0;border-top:1px solid var(--line)}.mlist li:first-child{border-top:0}.mlist a{color:var(--text);cursor:pointer;text-decoration:underline}
.err{color:var(--bad)}.sr{position:absolute;left:-9999px}`;

// Client script (vanilla). All text from the server is escaped before it touches the DOM.
const TEAM_JS = `
(() => {
  const root = document.getElementById('team');
  const CSRF = root.dataset.csrf;
  const pane = document.getElementById('pane');
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  const when = (iso) => iso ? new Date(iso).toLocaleString('en-GB', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }) : '';
  const api = async (url, body) => {
    // AI answers usually take 5-30s; never leave the page waiting forever
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), 100000);
    let r;
    try {
      r = await fetch(url, body === undefined ? { signal: ctl.signal } : { method: 'POST', signal: ctl.signal, headers: { 'content-type': 'application/json', 'x-csrf': CSRF }, body: JSON.stringify(body) });
    } catch (e) {
      throw new Error(e.name === 'AbortError' ? 'No answer after 100 seconds. The AI is probably busy: try again in a minute.' : 'Network error. Check your connection.');
    } finally { clearTimeout(t); }
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || 'Request failed');
    return j;
  };
  const DOT = { working: 'blue', incident: 'bad', error: 'bad', blocked: 'warn', handoff: 'warn', approval: 'warn', scheduled: 'good' };
  let state = { team: [], owner: 'Adham' }, view = null, lessonStatus = {};
  const nameOf = (id) => id === 'owner' ? state.owner : (state.team.find((a) => a.id === id)?.name || id);

  async function loadRoster() {
    state = await api('/dashboard/api/team');
    document.getElementById('roster').innerHTML = state.team.map((a) => '<button class="who" role="listitem" data-open="dm:' + a.id + '"><span class="nm"><i class="dot ' + (DOT[a.activity] || '') + '"></i>' + esc(a.name) + (a.proposed ? '<span class="badge" title="Lessons waiting for you">' + a.proposed + '</span>' : '') + '</span><span class="rl">' + esc(a.role) + '</span></button>').join('');
    document.getElementById('hrCount').innerHTML = (state.hr.open ? '<span class="badge">' + state.hr.open + ' issue' + (state.hr.open > 1 ? 's' : '') + '</span> ' : 'No open issues ') + (state.hr.proposals ? '· ' + state.hr.proposals + ' lesson(s) to decide' : '');
    document.getElementById('meetCount').textContent = state.meetings.length ? state.meetings.length + ' meeting(s)' : 'No meetings yet';
    mark();
  }
  const mark = () => document.querySelectorAll('[data-open]').forEach((b) => b.classList.toggle('on', b.dataset.open === view || (view || '').startsWith(b.dataset.open + ':')));

  function msgHtml(m) {
    if (m.kind === 'system') return '<div class="m sys">' + esc(m.text) + '<div class="small">' + when(m.ts) + '</div></div>';
    const me = m.author === 'owner';
    let extra = '', cls = '';
    if (m.kind === 'lesson' && m.ref) {
      const id = Number(m.ref.split(':')[1]);
      const st = lessonStatus[id];
      cls = st === 'active' || st === 'retired' ? ' decided' : st === 'declined' ? ' declined' : '';
      extra = st === 'proposed'
        ? '<div class="lact"><button class="ok" data-lesson="' + id + '" data-d="accept">Keep as rule</button><button class="ghost" data-lesson="' + id + '" data-d="decline">Dismiss</button></div>'
        : '<div class="small muted">' + (st === 'active' ? 'Kept as a rule' : st === 'declined' ? 'Dismissed' : st === 'retired' ? 'Retired' : '') + '</div>';
    }
    return '<div class="m ' + (me ? 'me' : '') + (m.kind === 'lesson' ? ' lesson' + cls : '') + '">' + (me ? '' : '<div class="by">' + esc(nameOf(m.author)) + '</div>') + esc(m.text) + extra + '</div>';
  }
  const scrollDown = () => { const box = pane.querySelector('.msgs'); if (box) box.scrollTop = box.scrollHeight; };

  function composer(placeholder, onSend) {
    const f = document.createElement('form');
    f.className = 'composer';
    f.innerHTML = '<label class="sr" for="say">Message</label><textarea id="say" maxlength="2000" placeholder="' + esc(placeholder) + '" required></textarea><button class="ok">Send</button>';
    const ta = f.querySelector('textarea');
    ta.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); f.requestSubmit(); } });
    f.addEventListener('submit', async (e) => {
      e.preventDefault();
      const text = ta.value.trim(); if (!text) return;
      const btn = f.querySelector('button'); btn.disabled = true; ta.value = '';
      const box = pane.querySelector('.msgs');
      box.insertAdjacentHTML('beforeend', msgHtml({ author: 'owner', text }) + '<div class="typing" id="typing">Thinking…</div>');
      scrollDown();
      const t0 = Date.now();
      const tick = setInterval(() => { const el = document.getElementById('typing'); if (el) el.textContent = 'Thinking… ' + Math.round((Date.now() - t0) / 1000) + 's'; }, 1000);
      try { await onSend(text); } catch (err) { document.getElementById('typing')?.remove(); box.insertAdjacentHTML('beforeend', '<div class="m sys err">' + esc(err.message) + '</div>'); scrollDown(); }
      clearInterval(tick);
      btn.disabled = false; ta.focus();
    });
    return f;
  }

  async function openDm(id) {
    const d = await api('/dashboard/api/team/dm/' + id);
    lessonStatus = d.lessonState;
    const a = d.agent, rv = d.review;
    pane.innerHTML = '<div class="ph"><h2>' + esc(a.name) + '</h2><p class="muted">' + esc(a.role) + '</p>' +
      (rv ? '<p class="small">Last review ' + when(rv.created_at) + (rv.score ? '<span class="score">' + rv.score + '/10</span>' : '') + ' · ' + esc(rv.summary) + '</p>' : '<p class="small muted">Not reviewed yet. Harmony reviews one agent a day.</p>') + '</div>' +
      '<details class="pb"><summary>Playbook: ' + d.playbook.length + ' rule(s)' + (a.learnsInWork ? ' (used in ' + esc(a.name) + "'s real work)" : ' (shapes how ' + esc(a.name) + ' reports to you; its work runs on fixed code)') + '</summary><ol>' +
      d.playbook.map((l) => '<li>' + esc(l.text) + '<button class="ghost" data-lesson="' + l.id + '" data-d="retire">Retire</button></li>').join('') + '</ol>' +
      '<form class="inline-form" id="addRule"><input name="rule" maxlength="300" placeholder="Add a rule for ' + esc(a.name) + ' yourself"><button class="ghost">Add</button></form></details>' +
      '<div class="msgs">' + (d.messages.length ? d.messages.map(msgHtml).join('') : '<div class="m sys">Say hello to ' + esc(a.name) + '. Ask what it did this week, what is blocking it, or tell it how you want things done.</div>') + '</div>';
    pane.appendChild(composer('Message ' + a.name + '…', async (text) => {
      const r = await api('/dashboard/api/team/dm/' + id, { text });
      lessonStatus = r.lessonState;
      document.getElementById('typing')?.remove();
      pane.querySelector('.msgs').insertAdjacentHTML('beforeend', r.messages.filter((m) => m.author !== 'owner').map(msgHtml).join(''));
      scrollDown(); loadRoster();
    }));
    pane.querySelector('#addRule').addEventListener('submit', async (e) => {
      e.preventDefault();
      const text = e.target.rule.value.trim(); if (!text) return;
      try { await api('/dashboard/api/team/lessons', { agent: id, text }); openDm(id); loadRoster(); } catch (err) { alertIn(err); }
    });
    scrollDown();
  }

  async function openMeetingList() {
    pane.innerHTML = '<div class="ph"><h2>Meeting Room</h2><p class="muted">Every agent reports from its real record; Harmony closes with HR notes. You can talk to everyone at once.</p></div>' +
      '<div class="sec"><form class="inline-form" id="startMeet"><input name="agenda" maxlength="500" placeholder="Agenda (optional), e.g. security status after the cleanup"><button class="ok">Start meeting</button></form></div>' +
      '<div class="sec"><h3>Past meetings</h3><ul class="mlist">' + (state.meetings.length ? state.meetings.map((m) => '<li><a data-open="meeting:' + m.id + '">' + esc(m.agenda || 'Meeting') + '</a> <span class="muted small">' + when(m.started_at) + (m.ended_at ? '' : ' · open') + '</span></li>').join('') : '<li class="muted">None yet.</li>') + '</ul></div>';
    pane.querySelector('#startMeet').addEventListener('submit', async (e) => {
      e.preventDefault();
      const b = e.target.querySelector('button'); b.disabled = true; b.textContent = 'Gathering the team…';
      try { const r = await api('/dashboard/api/team/meetings', { agenda: e.target.agenda.value }); await loadRoster(); go('meeting:' + r.id); }
      catch (err) { b.disabled = false; b.textContent = 'Start meeting'; alertIn(err); }
    });
  }

  async function openMeeting(id) {
    const d = await api('/dashboard/api/team/meetings/' + id);
    lessonStatus = d.lessonState;
    const m = d.meeting;
    pane.innerHTML = '<div class="ph"><h2>Meeting: ' + esc(m.agenda || '') + '</h2><p class="muted small">' + when(m.started_at) + (m.ended_at ? ' · ended' : ' · in progress') + '</p></div>' +
      '<div class="msgs">' + d.messages.map(msgHtml).join('') + '</div>' +
      (m.ended_at && m.actions ? '<div class="sec"><h3>Action items</h3><ul>' + JSON.parse(m.actions || '[]').map((a) => '<li><b>' + esc(a.who) + ':</b> ' + esc(a.text) + '</li>').join('') + '</ul></div>' : '');
    if (!m.ended_at) {
      pane.appendChild(composer('Talk to the team (address someone by name)…', async (text) => {
        const r = await api('/dashboard/api/team/meetings/' + id + '/say', { text });
        lessonStatus = r.lessonState;
        document.getElementById('typing')?.remove();
        pane.querySelector('.msgs').insertAdjacentHTML('beforeend', r.messages.filter((x) => x.author !== 'owner').map(msgHtml).join(''));
        scrollDown(); loadRoster();
      }));
      const end = document.createElement('div'); end.className = 'sec';
      end.innerHTML = '<button class="ghost" id="endMeet">End meeting & summarise</button>';
      pane.appendChild(end);
      end.querySelector('#endMeet').addEventListener('click', async (e) => { e.target.disabled = true; e.target.textContent = 'Summarising…'; try { await api('/dashboard/api/team/meetings/' + id + '/end', {}); openMeeting(id); loadRoster(); } catch (err) { alertIn(err); } });
    }
    scrollDown();
  }

  async function openHr() {
    const d = await api('/dashboard/api/team/hr');
    const names = (json) => { try { return JSON.parse(json).map(nameOf).join(' & '); } catch { return ''; } };
    const list = (json) => { try { return JSON.parse(json || '[]'); } catch { return []; } };
    pane.innerHTML = '<div class="ph"><h2>HR desk · Harmony</h2><p class="muted">Harmony checks the team every hour from the real records, tells you when two agents are causing problems for each other, and reviews one agent a day to train it.</p></div>' +
      '<div class="sec"><h3>Team issues</h3>' + (d.issues.length ? d.issues.map((i) => '<div class="issue ' + (i.status === 'open' ? '' : 'res') + '"><b>' + esc(i.title) + '</b><span>Between: ' + esc(names(i.agents)) + ' · ' + (i.status === 'open' ? 'open since ' + when(i.first_seen) : 'resolved ' + when(i.resolved_at)) + '</span><span>' + esc(i.detail || '') + '</span></div>').join('') : '<p class="muted">No issues. The team is working well together.</p>') +
      '<button class="ghost" id="hrCheck">Check now</button></div>' +
      '<div class="sec"><h3>Lessons waiting for your decision</h3>' + (d.proposals.length ? d.proposals.map((l) => '<div class="rv"><b>' + esc(nameOf(l.agent)) + '</b> <span class="muted small">from ' + esc(l.source) + ' · ' + when(l.created_at) + '</span><div>' + esc(l.text) + '</div><div class="lact"><button class="ok" data-lesson="' + l.id + '" data-d="accept">Keep as rule</button><button class="ghost" data-lesson="' + l.id + '" data-d="decline">Dismiss</button></div></div>').join('') : '<p class="muted">Nothing to decide.</p>') + '</div>' +
      '<div class="sec"><h3>Training reviews</h3><form class="inline-form" id="reviewNow"><select name="agent" aria-label="Agent to review">' + state.team.map((a) => '<option value="' + a.id + '"' + (a.id === d.nextReview ? ' selected' : '') + '>' + esc(a.name) + (a.id === d.nextReview ? ' (next in rotation)' : '') + '</option>').join('') + '</select><button class="ghost">Review now</button></form>' +
      (d.reviews.length ? d.reviews.map((r) => '<div class="rv"><b>' + esc(nameOf(r.agent)) + '</b>' + (r.score ? '<span class="score">' + r.score + '/10</span>' : '') + ' <span class="muted small">' + when(r.created_at) + '</span><div>' + esc(r.summary) + '</div>' + (list(r.gaps).length ? '<div class="small muted">To improve: ' + list(r.gaps).map(esc).join(' · ') + '</div>' : '') + '</div>').join('') : '<p class="muted">No reviews yet. The first one runs at 11:00, or press Review now.</p>') + '</div>';
    pane.querySelector('#hrCheck').addEventListener('click', async (e) => { e.target.disabled = true; try { await api('/dashboard/api/team/hr/check', {}); await loadRoster(); openHr(); } catch (err) { alertIn(err); } });
    pane.querySelector('#reviewNow').addEventListener('submit', async (e) => {
      e.preventDefault(); const b = e.target.querySelector('button'); b.disabled = true; b.textContent = 'Reviewing…';
      try { await api('/dashboard/api/team/hr/review/' + e.target.agent.value, {}); await loadRoster(); openHr(); } catch (err) { b.disabled = false; b.textContent = 'Review now'; alertIn(err); }
    });
  }

  function alertIn(err) { pane.insertAdjacentHTML('afterbegin', '<p class="m sys err">' + esc(err.message) + '</p>'); }

  // lesson buttons anywhere in the pane
  pane.addEventListener('click', async (e) => {
    const b = e.target.closest('[data-lesson]'); if (!b) return;
    b.disabled = true;
    try { await api('/dashboard/api/team/lessons/' + b.dataset.lesson + '/' + b.dataset.d, {}); await loadRoster(); go(view, true); } catch (err) { alertIn(err); }
  });

  function go(v, keep) {
    view = v; mark();
    if (!keep) history.replaceState(null, '', '#' + v);
    const [kind, id] = v.split(':');
    const run = kind === 'dm' ? openDm(id) : kind === 'hr' ? openHr() : kind === 'meeting' ? (id ? openMeeting(Number(id)) : openMeetingList()) : null;
    run?.catch((err) => { pane.innerHTML = '<p class="m sys err">' + esc(err.message) + '</p>'; });
  }
  document.addEventListener('click', (e) => { const b = e.target.closest('[data-open]'); if (b && !b.closest('form')) { e.preventDefault(); go(b.dataset.open); } });

  loadRoster().then(() => go(location.hash.slice(1) || 'meeting')).catch((err) => { pane.innerHTML = '<p class="m sys err">' + esc(err.message) + '</p>'; });
})();`;
