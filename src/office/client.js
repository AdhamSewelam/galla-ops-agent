/* Galla Ops — Office Simulator (browser). Pixel-art office on <canvas>, A* walking, live data + isolated demo.
   Business facts come only from /dashboard/api/office. Demo people live in this file and are never sent anywhere. */
(() => {
  'use strict';
  const T = 16, MW = 64, MH = 42;
  const $ = (s) => document.querySelector(s);
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  const ago = (iso) => { if (!iso) return '—'; const m = Math.round((Date.now() - new Date(iso)) / 60000); return m < 1 ? 'just now' : m < 60 ? `${m} min ago` : m < 1440 ? `${Math.round(m / 60)} h ago` : `${Math.round(m / 1440)} d ago`; };
  const when = (iso) => iso ? new Date(iso).toLocaleString('en-GB', { timeZone: 'Asia/Dubai', weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }) : '—';

  // ───────────────────────── MAP ─────────────────────────
  const GRASS = 0, PATH = 1, FLOOR = 2, WALL = 3, DOOR = 4, WATER = 5;
  const tiles = new Uint8Array(MW * MH).fill(GRASS);
  const floorOf = new Array(MW * MH).fill(null); // room id per floor tile
  const blocked = new Uint8Array(MW * MH);
  const at = (x, y) => y * MW + x;
  const inMap = (x, y) => x >= 0 && y >= 0 && x < MW && y < MH;

  const ROOMS = [
    { id: 'executive', name: 'Executive Office', x0: 4, y0: 4, x1: 11, y1: 14, floor: '#a87650', floor2: '#9a6a46' },
    { id: 'meeting', name: 'Meeting Room', x0: 13, y0: 4, x1: 18, y1: 14, floor: '#b88d63', floor2: '#ab8158' },
    { id: 'finance', name: 'Finance', x0: 20, y0: 4, x1: 30, y1: 14, floor: '#d2c9b6', floor2: '#c6bca8' },
    { id: 'marketing', name: 'Marketing', x0: 32, y0: 4, x1: 46, y1: 14, floor: '#caa47c', floor2: '#bd976f' },
    { id: 'technology', name: 'Security & Tech', x0: 48, y0: 4, x1: 59, y1: 14, floor: '#9ea7b1', floor2: '#929ba6' },
    { id: 'sales', name: 'Sales & Showroom', x0: 4, y0: 20, x1: 18, y1: 35, floor: '#c7ab85', floor2: '#ba9e78' },
    { id: 'operations', name: 'Operations', x0: 20, y0: 20, x1: 36, y1: 35, floor: '#bdb6a6', floor2: '#b1aa9a' },
    { id: 'cx', name: 'Customer Experience', x0: 38, y0: 20, x1: 47, y1: 35, floor: '#cbb79c', floor2: '#bfab90' },
    { id: 'lounge', name: 'Lounge', x0: 49, y0: 20, x1: 59, y1: 35, floor: '#b47d58', floor2: '#a6704c' },
    { id: 'corridor', name: 'Corridor', x0: 4, y0: 16, x1: 59, y1: 18, floor: '#dcd2bd', floor2: '#d2c7b1', hidden: true },
  ];
  const roomById = Object.fromEntries(ROOMS.map((r) => [r.id, r]));

  // building shell + inner walls
  for (let y = 3; y <= 36; y++) for (let x = 3; x <= 60; x++) {
    const edge = x === 3 || x === 60 || y === 3 || y === 36;
    tiles[at(x, y)] = edge ? WALL : FLOOR;
  }
  for (let x = 3; x <= 60; x++) { tiles[at(x, 15)] = WALL; tiles[at(x, 19)] = WALL; }
  for (const x of [12, 19, 31, 47]) for (let y = 3; y <= 15; y++) tiles[at(x, y)] = WALL;
  for (const x of [19, 37, 48]) for (let y = 19; y <= 36; y++) tiles[at(x, y)] = WALL;
  const door = (x, y) => { tiles[at(x, y)] = DOOR; };
  [[7, 15], [8, 15], [15, 15], [16, 15], [25, 15], [26, 15], [39, 15], [40, 15], [53, 15], [54, 15],
   [11, 19], [12, 19], [28, 19], [29, 19], [42, 19], [43, 19], [54, 19], [55, 19],
   [12, 9], [12, 10], [3, 17], [60, 17]].forEach(([x, y]) => door(x, y));
  for (const r of ROOMS) for (let y = r.y0; y <= r.y1; y++) for (let x = r.x0; x <= r.x1; x++) if (tiles[at(x, y)] === FLOOR) floorOf[at(x, y)] = r.id;
  // outdoor paths & pond
  for (let x = 0; x <= 3; x++) tiles[at(x, 17)] = PATH;
  for (let y = 17; y < MH; y++) tiles[at(1, y)] = PATH;
  for (let x = 60; x < MW; x++) tiles[at(x, 17)] = PATH;
  for (let y = 38; y <= 40; y++) for (let x = 44; x <= 50; x++) if (!((x === 44 || x === 50) && (y === 38 || y === 40))) tiles[at(x, y)] = WATER;

  // furniture
  const furniture = [];
  const seats = {}; // id -> {x,y,face,room}
  const put = (type, x, y, w = 1, h = 1, opts = {}) => {
    furniture.push({ type, x, y, w, h, ...opts });
    if (opts.walk !== true) for (let j = 0; j < h; j++) for (let i = 0; i < w; i++) blocked[at(x + i, y + j)] = 1;
  };
  const seat = (id, x, y, face = 'up') => { seats[id] = { x, y, face, room: floorOf[at(x, y)] }; furniture.push({ type: 'chair', x, y, w: 1, h: 1, walk: true, face }); };
  const desk = (id, x, y, opts = {}) => { put('desk', x, y, 2, 1, opts); seat(id, x, y + 1, 'up'); };

  // Executive
  put('bookshelf', 4, 4, 2, 1); put('plant', 11, 4); put('bigdesk', 6, 7, 3, 1); seat('ceo', 7, 8, 'up');
  seats.ceoVisit = { x: 7, y: 10, face: 'up', room: 'executive' };
  put('sofa', 4, 13, 3, 1); put('plant', 11, 14); desk('jarvis', 9, 11, { tint: 'gold' });
  put('rug', 6, 10, 3, 2, { walk: true });
  // Meeting
  put('whiteboard', 14, 4, 4, 1); put('mtable', 14, 8, 4, 2);
  [[14, 7, 'down'], [15, 7, 'down'], [16, 7, 'down'], [17, 7, 'down'], [14, 10, 'up'], [15, 10, 'up'], [16, 10, 'up'], [17, 10, 'up'], [13, 8, 'right'], [18, 9, 'left']]
    .forEach(([x, y, f], i) => seat(`meet${i}`, x, y, f));
  put('plant', 18, 13);
  // Finance
  desk('fin1', 21, 6); desk('fin2', 24, 6); desk('fin3', 27, 6); desk('fin4', 21, 10); desk('fin5', 24, 10);
  put('cabinet', 30, 4); put('cabinet', 30, 5); put('plant', 20, 14); put('safe', 29, 12, 2, 1);
  // Marketing
  desk('mkt1', 33, 6); desk('mkt2', 36, 6); desk('mkt3', 39, 6); desk('mkt4', 33, 10); desk('mkt5', 36, 10);
  desk('seo', 42, 6, { tint: 'chart' }); desk('design', 42, 10, { tint: 'design' }); put('board', 43, 4, 4, 1); put('plant', 46, 14);
  // Technology
  desk('tech1', 49, 6); desk('tech2', 52, 6); desk('tech3', 49, 10); desk('tech4', 52, 10);
  put('server', 56, 5, 1, 2); put('server', 57, 5, 1, 2); put('server', 58, 5, 1, 2); put('server', 56, 9, 1, 2); put('server', 57, 9, 1, 2);
  seats.serverWatch = { x: 57, y: 12, face: 'up', room: 'technology' };
  // Sales
  desk('sal1', 5, 22); desk('sal2', 8, 22); desk('sal3', 11, 22); desk('sal4', 5, 26); desk('sal5', 8, 26);
  put('ctable', 14, 30, 3, 2); seat('consult1', 13, 30, 'right'); seat('consult2', 17, 31, 'left'); seat('consult3', 15, 32, 'up');
  put('plant', 18, 20); put('plant', 4, 35); put('board', 14, 20, 3, 1);
  // Operations
  desk('ops1', 21, 22); desk('ops2', 24, 22); desk('ops3', 27, 22); desk('ops4', 21, 26); desk('ops5', 24, 26);
  desk('incident', 31, 22, { tint: 'alert' }); desk('inventory', 31, 26, { tint: 'chart' }); put('board', 33, 20, 3, 1);
  put('shelf', 20, 33, 3, 1); put('boxes', 34, 33, 2, 2); put('plant', 36, 20);
  // Customer Experience
  desk('cx1', 39, 22); desk('cx2', 42, 22); desk('cx3', 39, 26); desk('cx4', 42, 26);
  put('ctable', 43, 31, 3, 2); seat('review1', 42, 31, 'right'); seat('review2', 46, 32, 'left'); put('plant', 47, 20);
  // Lounge
  put('sofa', 50, 21, 3, 1); put('coffee', 58, 20); put('cooler', 59, 20); put('ltable', 53, 27, 3, 2);
  [[52, 27, 'right'], [52, 28, 'right'], [56, 27, 'left'], [56, 28, 'left'], [54, 26, 'down'], [54, 29, 'up']].forEach(([x, y, f], i) => seat(`lounge${i}`, x, y, f));
  put('plant', 49, 35); put('plant', 59, 35); put('rug', 51, 25, 7, 6, { walk: true }); put('tv', 50, 33, 3, 1);
  // Outdoors
  const trees = [[0, 1], [5, 1], [10, 0], [16, 1], [22, 0], [28, 1], [34, 0], [40, 1], [46, 0], [52, 1], [58, 0], [62, 2], [62, 8], [63, 14], [62, 22], [63, 28], [62, 34], [61, 39], [55, 40], [36, 40], [30, 39], [24, 40], [18, 39], [12, 40], [6, 39], [0, 6], [1, 12], [0, 24], [0, 30], [0, 36]];
  for (const [x, y] of trees) if (inMap(x, y) && tiles[at(x, y)] === GRASS) put('tree', x, y);
  [[2, 4], [2, 33], [61, 5], [61, 30], [40, 38], [52, 38], [20, 38], [9, 38]].forEach(([x, y]) => put('bush', x, y));
  const flowers = []; for (let i = 0; i < 70; i++) { const x = (i * 37) % MW, y = (i * 53 + 7) % MH; if (tiles[at(x, y)] === GRASS && !blocked[at(x, y)]) flowers.push([x, y, i % 3]); }

  const walkable = (x, y) => inMap(x, y) && !blocked[at(x, y)] && tiles[at(x, y)] !== WALL && tiles[at(x, y)] !== WATER;

  // ───────────────────────── PATHFINDING (A*) ─────────────────────────
  function findPath(sx, sy, tx, ty) {
    if (!walkable(tx, ty)) return null;
    const key = (x, y) => y * MW + x;
    const open = [[sx, sy]]; const g = new Map([[key(sx, sy), 0]]); const from = new Map(); const f = new Map([[key(sx, sy), Math.abs(sx - tx) + Math.abs(sy - ty)]]);
    const closed = new Set();
    while (open.length) {
      let bi = 0; for (let i = 1; i < open.length; i++) if (f.get(key(...open[i])) < f.get(key(...open[bi]))) bi = i;
      const [x, y] = open.splice(bi, 1)[0]; const k = key(x, y);
      if (x === tx && y === ty) { const path = [[x, y]]; let c = k; while (from.has(c)) { c = from.get(c); path.unshift([c % MW, Math.floor(c / MW)]); } return path; }
      closed.add(k);
      for (const [dx, dy] of [[1, 0], [-1, 0], [0, 1], [0, -1]]) {
        const nx = x + dx, ny = y + dy, nk = key(nx, ny);
        if (closed.has(nk) || (!walkable(nx, ny) && !(nx === sx && ny === sy))) continue;
        const ng = g.get(k) + 1;
        if (ng < (g.get(nk) ?? Infinity)) { from.set(nk, k); g.set(nk, ng); f.set(nk, ng + Math.abs(nx - tx) + Math.abs(ny - ty)); if (!open.some(([ox, oy]) => ox === nx && oy === ny)) open.push([nx, ny]); }
      }
    }
    return null;
  }

  // ───────────────────────── BACKGROUND (cached) ─────────────────────────
  const bg = document.createElement('canvas'); bg.width = MW * T; bg.height = MH * T;
  const b = bg.getContext('2d');
  const R = (c, x, y, w, h) => { b.fillStyle = c; b.fillRect(x, y, w, h); };
  function drawBackground() {
    for (let y = 0; y < MH; y++) for (let x = 0; x < MW; x++) {
      const t = tiles[at(x, y)], px = x * T, py = y * T, n = (x * 7 + y * 13) % 5;
      if (t === GRASS) { R(['#6aa84f', '#64a249', '#70ae55', '#66a54c', '#6cab52'][n], px, py, T, T); if (n === 2) R('#5c9843', px + 4, py + 9, 2, 2); }
      else if (t === PATH) { R('#cdb88e', px, py, T, T); R('#bfa97f', px + (n * 3) % 12, py + 6, 3, 2); }
      else if (t === WATER) { R('#4f8fbf', px, py, T, T); R('#7ab3dc', px + 3 + n, py + 5, 5, 1); }
      else if (t === WALL) {
        const below = inMap(x, y + 1) && tiles[at(x, y + 1)] !== WALL;
        R('#575c6b', px, py, T, T); R('#6e7484', px, py, T, 5); if (below) { R('#3f4350', px, py + 12, T, 4); R('#8a7a62', px, py + 13, T, 1); }
      } else {
        const r = roomById[floorOf[at(x, y)]] || roomById.corridor;
        const ry = r || { floor: '#d8cdb8', floor2: '#cfc3ad' };
        R((x + y) % 2 ? ry.floor : ry.floor2, px, py, T, T);
        if (r && ['executive', 'meeting', 'marketing', 'sales', 'lounge', 'cx'].includes(r.id)) R('rgba(0,0,0,.06)', px, py + 15, T, 1);
        if (t === DOOR) { R('#d6c6a8', px, py, T, T); R('#7a5b3c', px, py, 1, T); R('#7a5b3c', px + 15, py, 1, T); }
      }
    }
    for (const [x, y, c] of flowers) { const px = x * T, py = y * T; b.fillStyle = ['#f2d16b', '#f0a1b5', '#ffffff'][c]; b.fillRect(px + 5, py + 4, 2, 2); b.fillRect(px + 10, py + 10, 2, 2); }
    const order = { rug: 0, chair: 1 };
    [...furniture].sort((a, c) => (order[a.type] ?? 2) - (order[c.type] ?? 2) || a.y - c.y).forEach(drawFurniture);
  }
  function drawFurniture(f) {
    const px = f.x * T, py = f.y * T, w = f.w * T, h = f.h * T;
    switch (f.type) {
      case 'rug': R('#7b3f3f', px + 2, py + 2, w - 4, h - 4); R('#9b5a4a', px + 5, py + 5, w - 10, h - 10); R('#c8a06a', px + 2, py + 2, w - 4, 1); R('#c8a06a', px + 2, py + h - 3, w - 4, 1); break;
      case 'chair': R('#3b3f4a', px + 4, py + (f.face === 'up' ? 6 : 3), 8, 7); R('#4d5260', px + 5, py + (f.face === 'up' ? 12 : 3), 6, 2); break;
      case 'desk': case 'bigdesk': {
        R('#6d4529', px, py + 3, w, h - 2); R('#8a5a37', px, py + 2, w, 9); R('#a06a43', px, py + 2, w, 2);
        const mx = px + (f.type === 'bigdesk' ? w / 2 - 6 : 4);
        R('#1d222c', mx, py - 3, 12, 9); R(f.tint === 'alert' ? '#d9534f' : f.tint === 'chart' ? '#2e7d5b' : f.tint === 'design' ? '#9c6ade' : f.tint === 'gold' ? '#c79868' : '#3f78b5', mx + 1, py - 2, 10, 6);
        if (f.tint === 'chart') { R('#bdf0d6', mx + 2, py + 1, 2, 2); R('#bdf0d6', mx + 5, py - 1, 2, 4); R('#bdf0d6', mx + 8, py, 2, 3); }
        R('#333844', mx + 5, py + 6, 2, 2); R('#e6e2d8', mx + (f.w > 2 ? 16 : 14), py + 5, 8, 3);
        if (f.tint === 'alert') { R('#ff6b5b', px + w - 6, py - 2, 4, 4); R('#ffd4cf', px + w - 5, py - 1, 2, 2); }
        if (f.type === 'bigdesk') { R('#c79868', px + 3, py + 4, 6, 3); R('#f6f7fa', px + w - 10, py + 4, 6, 4); }
        break;
      }
      case 'bookshelf': R('#5e3b22', px, py, w, h); for (let i = 0; i < 7; i++) R(['#c0392b', '#2e86c1', '#d4ac0d', '#27ae60', '#8e44ad', '#e67e22', '#ecf0f1'][i], px + 2 + i * 4, py + 3, 3, 9); break;
      case 'plant': R('#8b5a2b', px + 4, py + 10, 8, 6); R('#3e8e41', px + 2, py + 2, 12, 9); R('#57b05b', px + 5, py, 6, 6); R('#2f7a33', px + 3, py + 7, 4, 3); break;
      case 'sofa': R('#46597a', px, py + 2, w, h - 2); R('#5a6f94', px + 2, py + 5, w - 4, 7); R('#34445f', px, py + 2, 3, h - 2); R('#34445f', px + w - 3, py + 2, 3, h - 2); break;
      case 'mtable': case 'ctable': case 'ltable': R('#6d4529', px + 1, py + 2, w - 2, h - 2); R('#9a6640', px + 1, py + 1, w - 2, h - 5); R('#b07a50', px + 3, py + 2, w - 6, 2);
        if (f.type === 'mtable') { R('#f6f7fa', px + 10, py + 8, 7, 5); R('#f6f7fa', px + 36, py + 10, 7, 5); R('#c79868', px + 26, py + 12, 6, 4); }
        if (f.type === 'ltable') { R('#ffffff', px + 14, py + 10, 4, 4); R('#6b3f22', px + 15, py + 11, 2, 2); }
        break;
      case 'whiteboard': R('#bfc4cc', px, py + 1, w, 12); R('#f8f9fb', px + 2, py + 2, w - 4, 9); R('#3f78b5', px + 6, py + 4, 14, 1); R('#d9534f', px + 6, py + 7, 22, 1); R('#2e7d5b', px + 34, py + 4, 16, 1); break;
      case 'board': R('#6b4a2e', px, py + 1, w, 12); R('#d9c7a5', px + 2, py + 2, w - 4, 9); ['#f7d774', '#f4a7b9', '#a8d8f0', '#b6e3a8', '#f7d774', '#a8d8f0'].forEach((c, i) => { if (i * 8 + 4 < w - 6) R(c, px + 4 + i * 8, py + 3 + (i % 2) * 3, 6, 5); }); break;
      case 'cabinet': R('#8d939e', px + 1, py, 14, 16); R('#a7adb7', px + 2, py + 2, 12, 5); R('#a7adb7', px + 2, py + 9, 12, 5); R('#555', px + 7, py + 4, 2, 1); R('#555', px + 7, py + 11, 2, 1); break;
      case 'safe': R('#4b505c', px + 2, py + 2, w - 4, h - 3); R('#c79868', px + w / 2 - 2, py + 6, 4, 4); break;
      case 'server': R('#1f232c', px + 1, py, 14, h); for (let i = 0; i < 6; i++) { R('#2f3542', px + 2, py + 2 + i * 5, 12, 3); R(i % 2 ? '#3ddc84' : '#4fc3f7', px + 11, py + 3 + i * 5, 2, 1); } break;
      case 'shelf': R('#7a5636', px, py + 2, w, 12); for (let i = 0; i < 5; i++) R('#c8a97e', px + 3 + i * 9, py + 4, 7, 7); break;
      case 'boxes': R('#b9875a', px + 2, py + 8, 13, 12); R('#c99a6b', px + 14, py + 4, 14, 14); R('#a07045', px + 6, py + 20, 18, 10); R('#e6d2b5', px + 18, py + 9, 6, 2); break;
      case 'coffee': R('#2c2f36', px + 2, py + 1, 12, 14); R('#c0392b', px + 4, py + 3, 8, 3); R('#ffffff', px + 6, py + 10, 4, 4); break;
      case 'cooler': R('#dfe8f0', px + 4, py + 6, 8, 10); R('#7ec4f0', px + 4, py, 8, 7); break;
      case 'tv': R('#1d222c', px, py + 2, w, 11); R('#2d4f7a', px + 2, py + 4, w - 4, 7); break;
      case 'tree': R('#5b3a22', px + 6, py + 10, 4, 6); R('#2f6e33', px, py, 16, 12); R('#3f8a43', px + 2, py - 2, 12, 8); R('#4fa354', px + 4, py, 5, 4); break;
      case 'bush': R('#3f8a43', px + 1, py + 5, 14, 10); R('#57b05b', px + 3, py + 4, 6, 5); break;
    }
  }
  drawBackground();

  // ───────────────────────── CHARACTERS ─────────────────────────
  const SKIN = ['#f1c7a5', '#d9a47c', '#b47a55', '#8a5a3c'];
  const HAIR = ['#2b1d14', '#5a3a22', '#b07a3a', '#1c1c1c', '#7a7a7a', '#c9a15a'];
  const OUTFIT = ['#3f78b5', '#2e7d5b', '#9c4f4f', '#6b4fa0', '#c79868', '#3d4659', '#b5653f', '#2f8f8f'];
  const hash = (s) => [...String(s)].reduce((h, c) => (h * 31 + c.charCodeAt(0)) >>> 0, 7);
  function look(p) {
    const h = hash(p.id + p.name);
    if (p.type === 'agent') return { agent: true, body: p.id === 'jarvis' ? '#c79868' : OUTFIT[h % OUTFIT.length], eye: p.id === 'jarvis' ? '#4fc3f7' : '#ffd27a' };
    return { skin: SKIN[h % SKIN.length], hair: HAIR[(h >> 3) % HAIR.length], body: p.id === 'owner' || /CEO/.test(p.role || '') ? '#1d2433' : OUTFIT[(h >> 5) % OUTFIT.length], tie: p.id === 'owner' ? '#c79868' : null };
  }

  let chars = [];
  function makeChar(p, home) {
    const s = seats[home] || seats.ceoVisit;
    return { ...p, look: look(p), home, x: s.x * T, y: s.y * T, tx: s.x, ty: s.y, path: [], face: s.face, moving: false, frame: 0, goal: home, wait: 0, bubble: null, sit: true };
  }
  function goTo(c, seatId) {
    const s = seats[seatId]; if (!s) return;
    const sx = Math.round(c.x / T), sy = Math.round(c.y / T);
    const p = findPath(sx, sy, s.x, s.y);
    if (p && p.length > 1) { c.path = p.slice(1); c.goal = seatId; c.sit = false; } else if (p) { c.goal = seatId; c.face = s.face; c.sit = true; }
  }

  function drawChar(ctx, c, t, dim) {
    const L = c.look, x = Math.round(c.x), y = Math.round(c.y) - (c.sit ? 2 : 4);
    const step = c.moving ? (Math.floor(t / 140) % 2) : 0;
    const bob = !c.moving && c.bubble === 'working' ? (Math.floor(t / 300) % 2) : 0;
    const P = (col, dx, dy, w = 1, h = 1) => { ctx.fillStyle = col; ctx.fillRect(x + dx, y + dy, w, h); };
    ctx.globalAlpha = dim ? 0.25 : c.activity === 'offline' ? 0.5 : 1;
    P('rgba(0,0,0,.22)', 3, 15, 10, 2); // shadow
    if (L.agent) {
      P('#9aa3b2', 7, 0, 2, 2); P(L.eye, 7, 0, 2, 1); // antenna
      P('#c4cbd6', 3, 2, 10, 7); P('#a7afbd', 3, 8, 10, 1); P('#1d222c', 4, 4, 8, 3);
      if (c.face !== 'up') { P(L.eye, 5, 5, 2, 1); P(L.eye, 9, 5, 2, 1); }
      P(L.body, 4, 9 - bob, 8, 5); P('#ffffff33', 5, 10 - bob, 2, 2);
      P('#6b7384', 4 + (step ? 1 : 0), 14, 3, 2); P('#6b7384', 9 - (step ? 1 : 0), 14, 3, 2);
    } else {
      P(L.hair, 4, 0, 8, 3); P(L.skin, 4, 2, 8, 6); if (c.face === 'up') P(L.hair, 4, 2, 8, 5); else { P(L.hair, 4, 2, 1, 3); P(L.hair, 11, 2, 1, 3); P('#2b2b2b', 6, 5, 1, 1); P('#2b2b2b', 9, 5, 1, 1); }
      P(L.body, 3, 8 - bob, 10, 6); P(L.skin, 2, 9 - bob, 1, 3); P(L.skin, 13, 9 - bob, 1, 3); if (L.tie) P(L.tie, 7, 8 - bob, 2, 4);
      P('#2f3440', 4 + (step ? 1 : 0), 14, 3, 2); P('#2f3440', 9 - (step ? 1 : 0), 14, 3, 2);
    }
    ctx.globalAlpha = 1;
  }

  // pixel icons above heads
  function drawBubble(ctx, c, t, showAlerts) {
    const kind = c.bubble; if (!kind || (kind === 'alert' && !showAlerts)) return;
    const x = Math.round(c.x) + 2, y = Math.round(c.y) - 18 + (Math.floor(t / 500) % 2);
    const P = (col, dx, dy, w = 1, h = 1) => { ctx.fillStyle = col; ctx.fillRect(x + dx, y + dy, w, h); };
    const bgc = kind === 'alert' ? '#d9534f' : kind === 'error' ? '#e08a2b' : '#ffffff';
    P('#1d222c', 0, 0, 12, 10); P(bgc, 1, 1, 10, 8); P('#1d222c', 5, 10, 2, 2);
    const ink = kind === 'alert' || kind === 'error' ? '#ffffff' : '#1d222c';
    switch (kind) {
      case 'alert': case 'error': P(ink, 5, 2, 2, 4); P(ink, 5, 7, 2, 1); break;
      case 'working': P('#3f78b5', 2, 2, 8, 5); P('#1d222c', 3, 7, 6, 1); break;
      case 'handoff': P('#2e7d5b', 2, 4, 6, 2); P('#2e7d5b', 7, 3, 1, 4); P('#2e7d5b', 8, 4, 1, 2); break;
      case 'approval': P('#c79868', 4, 2, 4, 4); P('#c79868', 3, 5, 6, 2); P('#1d222c', 5, 7, 2, 1); break;
      case 'meeting': P('#6b4fa0', 2, 3, 3, 3); P('#6b4fa0', 7, 3, 3, 3); P('#6b4fa0', 3, 6, 6, 2); break;
      case 'blocked': P('#1d222c', 3, 2, 2, 6); P('#1d222c', 7, 2, 2, 6); break;
      case 'scheduled': P('#1d222c', 3, 2, 6, 6); P('#ffffff', 4, 3, 4, 4); P('#1d222c', 6, 4, 1, 2); P('#1d222c', 6, 5, 2, 1); break;
      case 'unknown': P(ink, 4, 2, 4, 1); P(ink, 7, 3, 1, 2); P(ink, 5, 5, 2, 1); P(ink, 5, 7, 2, 1); break;
      case 'coffee': P('#8b5a2b', 3, 3, 5, 5); P('#8b5a2b', 8, 4, 1, 2); break;
      case 'offline': P('#9aa3b2', 2, 4, 8, 2); break;
    }
  }

  // ───────────────────────── STATE / MODES ─────────────────────────
  const ui = { mode: 'live', playing: true, speed: 1, zoom: 2, ox: 0, oy: 0, dept: 'all', type: 'all', q: '', alerts: true, links: false, selected: null, hover: null };
  let live = null, liveError = null, liveAt = 0;

  const ACT_BUBBLE = { working: 'working', incident: 'alert', error: 'error', handoff: 'handoff', approval: 'approval', blocked: 'blocked', scheduled: 'scheduled', unknown: 'unknown', offline: 'offline' };

  function buildLive(state) {
    const prev = Object.fromEntries(chars.map((c) => [c.id, c]));
    chars = state.people.map((p) => {
      const c = prev[p.id] && ui.mode === 'live' ? Object.assign(prev[p.id], p, { look: look(p) }) : makeChar(p, p.seat);
      c.bubble = ACT_BUBBLE[p.activity] || null;
      return c;
    });
    for (const c of chars) {
      const target = c.activity === 'incident' && c.id === 'sentinel' ? 'incident' : c.activity === 'incident' && c.id === 'keeper' ? 'serverWatch' : c.home;
      if (c.goal !== target && c.path.length === 0 && c.goal !== 'ceoVisit') goTo(c, target);
    }
  }

  // ---- DEMO (fictional, clearly labelled, never sent anywhere) ----
  const DEMO_PEOPLE = [
    ['d-ceo', 'Demo CEO', 'CEO', 'executive', 'ceo', 'human', null], ['d-asst', 'Demo JARVIS', 'Voice assistant', 'executive', 'jarvis', 'agent', 'd-ceo'],
    ['d-cfo', 'Lina (demo)', 'CFO', 'finance', 'fin1', 'human', 'd-ceo'], ['d-acc', 'Omar (demo)', 'Accountant', 'finance', 'fin2', 'human', 'd-cfo'],
    ['d-cmo', 'Sara (demo)', 'Head of Marketing', 'marketing', 'mkt1', 'human', 'd-ceo'], ['d-cur', 'Curator (demo)', 'Product data agent', 'marketing', 'mkt2', 'agent', 'd-cmo'],
    ['d-seo', 'Scout (demo)', 'SEO agent', 'marketing', 'seo', 'agent', 'd-cmo'], ['d-des', 'Nour (demo)', 'Designer', 'marketing', 'design', 'human', 'd-cmo'],
    ['d-sal1', 'Karim (demo)', 'Sales lead', 'sales', 'sal1', 'human', 'd-ceo'], ['d-sal2', 'Mona (demo)', 'Sales rep', 'sales', 'sal2', 'human', 'd-sal1'], ['d-sal3', 'Youssef (demo)', 'Sales rep', 'sales', 'sal4', 'human', 'd-sal1'],
    ['d-ops', 'Hana (demo)', 'Operations lead', 'operations', 'ops1', 'human', 'd-ceo'], ['d-sent', 'Sentinel (demo)', 'Monitoring agent', 'operations', 'ops2', 'agent', 'd-ops'],
    ['d-cto', 'Ali (demo)', 'CTO', 'technology', 'tech1', 'human', 'd-ceo'], ['d-dev', 'Dina (demo)', 'Developer', 'technology', 'tech2', 'human', 'd-cto'],
    ['d-cx1', 'Rana (demo)', 'Support lead', 'cx', 'cx1', 'human', 'd-ceo'], ['d-cx2', 'Tarek (demo)', 'Support agent', 'cx', 'cx2', 'human', 'd-cx1'],
  ];
  const DEMO_TASKS = ['Quarterly budget review', 'Photograph new FINAL PIECES', 'Follow up 3 valuation requests', 'Fix checkout bug', 'Reconcile Paymob payouts', 'Answer customer about ring sizing', 'SEO: hreflang between /eg and /ae', 'Update gold price list', 'Prepare Ramadan collection'];
  let demoClock = 0, demoNext = 0;
  function startDemo() {
    chars = DEMO_PEOPLE.map(([id, name, role, dept, seatId, type, manager], i) => {
      const c = makeChar({ id, name, role, dept, seat: seatId, type, manager, demo: true, tasks: [{ title: DEMO_TASKS[i % DEMO_TASKS.length], status: 'In progress (demo)', due: null }], activityText: 'Working (demo)', recent: [] }, seatId);
      c.bubble = 'working'; c.activity = 'working'; return c;
    });
    demoClock = 0; demoNext = 1500;
  }
  function demoEvent() {
    const free = chars.filter((c) => c.path.length === 0 && c.wait <= 0);
    const r = Math.random();
    if (r < 0.25 && free.length > 3) { // meeting
      const group = free.sort(() => Math.random() - 0.5).slice(0, 3 + Math.floor(Math.random() * 3));
      group.forEach((c, i) => { goTo(c, `meet${i}`); c.bubble = 'meeting'; c.activity = 'meeting'; c.activityText = 'In a meeting (demo)'; c.wait = 9000 + Math.random() * 4000; });
    } else if (r < 0.5 && free.length) { // handoff to another department
      const c = free[Math.floor(Math.random() * free.length)];
      const other = chars.filter((o) => o.dept !== c.dept)[Math.floor(Math.random() * (chars.length - 1))] || chars[0];
      const s = seats[other.home]; if (s) { seats[`visit-${c.id}`] = { x: s.x, y: s.y + 1, face: 'up', room: s.room }; if (walkable(s.x, s.y + 1)) { goTo(c, `visit-${c.id}`); c.bubble = 'handoff'; c.activity = 'handoff'; c.activityText = `Handing a task to ${other.name} (demo)`; c.wait = 3500; } }
    } else if (r < 0.65 && free.length) { // break (explicitly simulated)
      const c = free[Math.floor(Math.random() * free.length)];
      goTo(c, `lounge${Math.floor(Math.random() * 6)}`); c.bubble = 'coffee'; c.activity = 'break'; c.activityText = 'Coffee break (demo)'; c.wait = 7000;
    } else if (r < 0.72) { // an incident drill
      const s = chars.find((c) => c.id === 'd-sent'); if (s && s.path.length === 0) { goTo(s, 'incident'); s.bubble = 'alert'; s.activity = 'incident'; s.activityText = 'Demo incident drill'; s.wait = 8000; }
    } else {
      chars.filter((c) => c.wait <= 0 && c.goal !== c.home && c.path.length === 0).forEach((c) => { goTo(c, c.home); c.bubble = 'working'; c.activity = 'working'; c.activityText = 'Working (demo)'; });
    }
  }

  // ───────────────────────── LOOP ─────────────────────────
  const canvas = $('#office'), ctx = canvas.getContext('2d');
  let last = performance.now(), raf = 0;
  function update(dt) {
    const sp = (ui.mode === 'demo' ? ui.speed : 1) * (ui.playing ? 1 : 0);
    if (ui.mode === 'demo' && sp > 0) {
      demoClock += dt * sp;
      if (demoClock > demoNext) { demoEvent(); demoNext = demoClock + 1800 + Math.random() * 2200; }
      for (const c of chars) if (c.wait > 0) { c.wait -= dt * sp; if (c.wait <= 0 && c.goal !== c.home) { goTo(c, c.home); c.bubble = 'working'; c.activity = 'working'; c.activityText = 'Working (demo)'; } }
    }
    if (ui.mode === 'live' && live) {
      const t = performance.now();
      for (const c of chars) if (c.activity === 'handoff' && c.handoff && c.path.length === 0) {
        // Visualises the recorded handoff (drafts → owner approval): walk to the CEO, pause, walk back.
        c.cycle = (c.cycle || 0);
        if (t > (c.nextMove || 0)) { goTo(c, c.goal === 'ceoVisit' ? c.home : 'ceoVisit'); c.nextMove = t + (c.goal === 'ceoVisit' ? 6000 : 14000); }
      }
    }
    const moveSp = 3.2 * T * (dt / 1000) * (ui.mode === 'demo' ? Math.max(sp, 0) : (ui.playing ? 1 : 0));
    for (const c of chars) {
      c.moving = false;
      if (!c.path.length || moveSp === 0) continue;
      const [nx, ny] = c.path[0]; const gx = nx * T, gy = ny * T;
      const dx = gx - c.x, dy = gy - c.y, d = Math.hypot(dx, dy);
      c.face = Math.abs(dx) > Math.abs(dy) ? (dx > 0 ? 'right' : 'left') : (dy > 0 ? 'down' : 'up');
      if (d <= moveSp) { c.x = gx; c.y = gy; c.path.shift(); if (!c.path.length) { const s = seats[c.goal]; c.face = s ? s.face : c.face; c.sit = true; } }
      else { c.x += (dx / d) * moveSp; c.y += (dy / d) * moveSp; c.moving = true; }
    }
  }

  function visible(c) {
    if (ui.dept !== 'all' && c.dept !== ui.dept) return false;
    if (ui.type !== 'all' && c.type !== ui.type) return false;
    if (ui.q) { const q = ui.q.toLowerCase(); if (!(`${c.name} ${c.role}`.toLowerCase().includes(q) || (c.tasks || []).some((t) => t.title.toLowerCase().includes(q)))) return false; }
    return true;
  }

  function render(t) {
    const dpr = window.devicePixelRatio || 1;
    const W = canvas.clientWidth, H = canvas.clientHeight;
    if (canvas.width !== Math.round(W * dpr) || canvas.height !== Math.round(H * dpr)) { canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr); }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.imageSmoothingEnabled = false;
    ctx.fillStyle = '#4f8a3d'; ctx.fillRect(0, 0, W, H);
    const z = ui.zoom;
    ctx.setTransform(dpr * z, 0, 0, dpr * z, dpr * ui.ox, dpr * ui.oy); ctx.imageSmoothingEnabled = false;
    ctx.drawImage(bg, 0, 0);
    // department filter: shade other rooms
    if (ui.dept !== 'all') for (const r of ROOMS) if (r.id !== ui.dept && !r.hidden) { ctx.fillStyle = 'rgba(11,18,32,.35)'; ctx.fillRect(r.x0 * T, r.y0 * T, (r.x1 - r.x0 + 1) * T, (r.y1 - r.y0 + 1) * T); }
    // incident pulse on the incident desk
    if (ui.alerts && chars.some((c) => c.activity === 'incident')) { const a = 0.25 + 0.2 * Math.sin(t / 250); const r = roomById.operations; ctx.fillStyle = `rgba(217,83,79,${a})`; ctx.fillRect(30 * T, 21 * T, 3 * T, 3 * T); }
    // manager links
    if (ui.links) {
      ctx.strokeStyle = 'rgba(199,152,104,.85)'; ctx.lineWidth = 1; ctx.setLineDash([3, 2]);
      for (const c of chars) { const m = chars.find((o) => o.id === c.manager); if (!m) continue; ctx.beginPath(); ctx.moveTo(c.x + 8, c.y + 6); ctx.lineTo(m.x + 8, m.y + 6); ctx.stroke(); }
      ctx.setLineDash([]);
    }
    const sorted = [...chars].sort((a, c) => a.y - c.y);
    for (const c of sorted) {
      const on = visible(c);
      if (ui.selected === c.id) { ctx.strokeStyle = '#c79868'; ctx.lineWidth = 1; ctx.strokeRect(Math.round(c.x) + 1.5, Math.round(c.y) - 5.5, 13, 21); }
      drawChar(ctx, c, t, !on);
      if (on) drawBubble(ctx, c, t, ui.alerts);
    }
    // screen-space labels
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.textBaseline = 'middle';
    for (const r of ROOMS) if (!r.hidden) {
      const sx = r.x0 * T * z + ui.ox + 6, sy = r.y0 * T * z + ui.oy + 10;
      ctx.font = `600 ${Math.max(10, Math.min(13, 5 * z))}px Inter, system-ui, sans-serif`;
      const w = ctx.measureText(r.name).width + 10;
      ctx.fillStyle = 'rgba(11,18,32,.72)'; ctx.fillRect(sx, sy - 9, w, 18); ctx.fillStyle = '#f6f7fa'; ctx.fillText(r.name, sx + 5, sy);
    }
    if (z >= 1.0) for (const c of sorted) {
      if (!visible(c) && ui.selected !== c.id) continue;
      const sx = (c.x + 8) * z + ui.ox, sy = (c.y + 18) * z + ui.oy;
      ctx.font = '600 10.5px Inter, system-ui, sans-serif';
      const label = c.name; const w = ctx.measureText(label).width + (c.type === 'agent' ? 18 : 8);
      ctx.fillStyle = c.type === 'agent' ? 'rgba(199,152,104,.95)' : 'rgba(255,255,255,.92)'; ctx.fillRect(sx - w / 2, sy - 7, w, 14);
      ctx.fillStyle = '#0b1220'; ctx.fillText((c.type === 'agent' ? 'AI ' : '') + label, sx - w / 2 + 4, sy);
    }
    if (ui.mode === 'demo') { ctx.font = '700 12px Inter, sans-serif'; ctx.fillStyle = '#c79868'; ctx.fillRect(W - 92, 10, 82, 24); ctx.fillStyle = '#0b1220'; ctx.fillText('DEMO DATA', W - 84, 22); }
  }

  function frame(t) {
    const dt = Math.min(64, t - last); last = t;
    update(dt); render(t);
    raf = requestAnimationFrame(frame);
  }

  // ───────────────────────── CAMERA ─────────────────────────
  function fit() {
    const W = canvas.clientWidth, H = canvas.clientHeight;
    ui.zoom = Math.max(0.6, Math.min(W / (MW * T), H / (MH * T)));
    ui.ox = (W - MW * T * ui.zoom) / 2; ui.oy = (H - MH * T * ui.zoom) / 2;
  }
  function zoomAt(f, cx = canvas.clientWidth / 2, cy = canvas.clientHeight / 2) {
    const nz = Math.max(0.6, Math.min(6, ui.zoom * f));
    ui.ox = cx - (cx - ui.ox) * (nz / ui.zoom); ui.oy = cy - (cy - ui.oy) * (nz / ui.zoom); ui.zoom = nz;
  }
  const toWorld = (sx, sy) => [(sx - ui.ox) / ui.zoom, (sy - ui.oy) / ui.zoom];
  let drag = null;
  canvas.addEventListener('pointerdown', (e) => { drag = { x: e.clientX, y: e.clientY, ox: ui.ox, oy: ui.oy, moved: false }; canvas.setPointerCapture(e.pointerId); });
  canvas.addEventListener('pointermove', (e) => {
    if (drag) { const dx = e.clientX - drag.x, dy = e.clientY - drag.y; if (Math.abs(dx) + Math.abs(dy) > 4) drag.moved = true; ui.ox = drag.ox + dx; ui.oy = drag.oy + dy; }
    const r = canvas.getBoundingClientRect(); const hit = hitChar(...toWorld(e.clientX - r.left, e.clientY - r.top)); canvas.style.cursor = hit ? 'pointer' : drag ? 'grabbing' : 'grab';
  });
  canvas.addEventListener('pointerup', (e) => {
    const wasDrag = drag?.moved; drag = null; if (wasDrag) return;
    const r = canvas.getBoundingClientRect(); const [wx, wy] = toWorld(e.clientX - r.left, e.clientY - r.top);
    const c = hitChar(wx, wy);
    if (c) return openChar(c.id);
    const tx = Math.floor(wx / T), ty = Math.floor(wy / T);
    const room = inMap(tx, ty) && floorOf[at(tx, ty)];
    if (room && room !== 'corridor') openDept(room); else closePanel();
  });
  canvas.addEventListener('wheel', (e) => { e.preventDefault(); const r = canvas.getBoundingClientRect(); zoomAt(e.deltaY < 0 ? 1.12 : 1 / 1.12, e.clientX - r.left, e.clientY - r.top); }, { passive: false });
  function hitChar(wx, wy) { return [...chars].reverse().find((c) => wx >= c.x && wx <= c.x + 16 && wy >= c.y - 8 && wy <= c.y + 16); }

  // ───────────────────────── PANELS ─────────────────────────
  const panel = $('#panel');
  function closePanel() { ui.selected = null; panel.hidden = true; }
  const pill = (txt, tone = '') => `<span class="pill ${tone}">${esc(txt)}</span>`;
  const ACT_LABEL = { working: ['Working now', 'good'], incident: ['Handling incident', 'bad'], error: ['Last run failed', 'bad'], handoff: ['Handoff', 'warn'], approval: ['Needs decisions', 'warn'], blocked: ['Blocked', 'warn'], scheduled: ['Scheduled', ''], unknown: ['Activity not tracked', ''], offline: ['Not set up', ''], meeting: ['In meeting', ''], break: ['Break', ''] };
  function openChar(id) {
    const c = chars.find((x) => x.id === id); if (!c) return;
    ui.selected = id;
    const mgr = chars.find((x) => x.id === c.manager);
    const reports = chars.filter((x) => x.manager === c.id);
    const [al, tone] = ACT_LABEL[c.activity] || [c.activity || '—', ''];
    const tasks = c.tasks || [];
    const overdue = tasks.filter((t) => t.due && new Date(t.due) < new Date());
    panel.innerHTML = `
      <button class="x" aria-label="Close panel">×</button>
      ${c.demo ? '<div class="demo">DEMO PERSON — not a real record</div>' : ''}
      <div class="ph"><div class="av ${c.type}">${c.type === 'agent' ? 'AI' : esc(c.name[0])}</div><div><h2>${esc(c.name)}</h2><div class="muted">${esc(c.role)} · ${esc(roomById[c.dept]?.name || c.dept)}</div></div></div>
      <div class="row">${pill(c.type === 'agent' ? 'AI agent' : 'Human', c.type === 'agent' ? 'gold' : '')} ${pill(al, tone)}</div>
      <p>${esc(c.activityText || '')}</p>
      <dl>
        <dt>Reports to</dt><dd>${mgr ? `<a href="#" data-open="${esc(mgr.id)}">${esc(mgr.name)}</a>` : '—'}</dd>
        ${reports.length ? `<dt>Direct reports</dt><dd>${reports.map((r) => `<a href="#" data-open="${esc(r.id)}">${esc(r.name)}</a>`).join(', ')}</dd>` : ''}
        ${c.jobs?.length ? `<dt>Runs</dt><dd>${esc(c.jobs.join(', '))}</dd>` : ''}
        ${c.lastRun ? `<dt>Last run</dt><dd>${esc(c.lastRun.job)} · ${pill(c.lastRun.outcome === 'ok' ? 'OK' : 'Error', c.lastRun.outcome === 'ok' ? 'good' : 'bad')} · ${esc(ago(c.lastRun.ts))}</dd>` : ''}
      </dl>
      <h3>Assigned tasks (${tasks.length})</h3>
      ${tasks.length ? `<ul class="tasks">${tasks.map((t) => `<li><b>${esc(t.title)}</b><span>${esc(t.status)}${t.due ? ' · due ' + esc(when(t.due)) : ''}</span></li>`).join('')}</ul>` : '<p class="muted">No assigned tasks recorded.</p>'}
      ${overdue.length ? `<p class="bad">${overdue.length} overdue</p>` : ''}
      <h3>KPIs</h3><p class="muted">${c.demo ? 'Demo only.' : 'No KPI data source connected yet.'}</p>
      <h3>Recent verified activity</h3>
      ${(c.recent || []).length ? `<ul class="log">${c.recent.map((a) => `<li><span>${esc(ago(a.ts))}</span> ${esc(a.action.replace(/_/g, ' '))}${a.outcome !== 'ok' ? ' ' + pill(a.outcome, 'bad') : ''}</li>`).join('')}</ul>` : '<p class="muted">Nothing recorded.</p>'}
      <div class="actions">${c.demo ? '' : `<a class="btn" href="/dashboard#security">Open findings & approvals</a> <a class="btn ghost" href="/dashboard">Operations Dashboard</a>`}
      <button class="btn ghost" data-dept="${esc(c.dept)}">Open department</button></div>`;
    panel.hidden = false;
  }
  function openDept(id) {
    const r = roomById[id]; if (!r) return;
    ui.selected = null;
    const members = chars.filter((c) => c.dept === id);
    const d = ui.mode === 'live' && live ? live.departments.find((x) => x.id === id) : null;
    const tasks = members.flatMap((m) => (m.tasks || []).map((t) => ({ ...t, who: m.name })));
    const head = members.find((m) => m.id === d?.head) || members.find((m) => !m.manager || !members.some((x) => x.id === m.manager));
    panel.innerHTML = `
      <button class="x" aria-label="Close panel">×</button>
      ${ui.mode === 'demo' ? '<div class="demo">DEMO DATA</div>' : ''}
      <h2>${esc(r.name)}</h2>
      <dl><dt>Head</dt><dd>${head ? `<a href="#" data-open="${esc(head.id)}">${esc(head.name)}</a>` : 'No one assigned'}</dd>
      <dt>Members</dt><dd>${members.length ? members.map((m) => `<a href="#" data-open="${esc(m.id)}">${esc(m.name)}</a>${m.type === 'agent' ? ' (AI)' : ''}`).join(', ') : 'No people or agents assigned yet'}</dd>
      ${d ? `<dt>Active tasks</dt><dd>${d.activeTasks}</dd><dt>Blocked</dt><dd>${d.blockedTasks}</dd><dt>Incidents</dt><dd>${d.incidents}</dd><dt>Next deadline</dt><dd>${esc(when(d.nextDeadline))}</dd>` : ''}
      ${d?.kpi ? `<dt>KPIs</dt><dd class="muted">${esc(d.kpi)}</dd>` : ''}</dl>
      <h3>Workload</h3>
      ${members.length ? `<ul class="bars">${members.map((m) => `<li><span>${esc(m.name)}</span><i style="width:${Math.min(100, (m.tasks || []).length * 12)}%"></i><b>${(m.tasks || []).length}</b></li>`).join('')}</ul>` : '<p class="muted">—</p>'}
      <h3>Tasks</h3>
      ${tasks.length ? `<ul class="tasks">${tasks.slice(0, 15).map((t) => `<li><b>${esc(t.title)}</b><span>${esc(t.who)} · ${esc(t.status)}</span></li>`).join('')}</ul>` : '<p class="muted">No tasks recorded.</p>'}
      ${ui.mode === 'live' ? '<div class="actions"><a class="btn" href="/dashboard">Open in Operations Dashboard</a></div>' : ''}`;
    panel.hidden = false;
  }
  panel.addEventListener('click', (e) => {
    const o = e.target.closest('[data-open]'); if (o) { e.preventDefault(); openChar(o.dataset.open); }
    const d = e.target.closest('[data-dept]'); if (d) openDept(d.dataset.dept);
    if (e.target.closest('.x')) closePanel();
  });

  // ───────────────────────── TOOLBAR ─────────────────────────
  const deptSel = $('#dept');
  deptSel.innerHTML = '<option value="all">All departments</option>' + ROOMS.filter((r) => !r.hidden).map((r) => `<option value="${r.id}">${esc(r.name)}</option>`).join('');
  const setMode = (m) => {
    ui.mode = m; document.body.dataset.mode = m;
    $('#modeLive').setAttribute('aria-pressed', m === 'live'); $('#modeDemo').setAttribute('aria-pressed', m === 'demo');
    $('#demoCtl').hidden = m !== 'demo'; closePanel();
    if (m === 'demo') startDemo(); else { chars = []; if (live) buildLive(live); }
    status();
  };
  $('#modeLive').onclick = () => setMode('live');
  $('#modeDemo').onclick = () => setMode('demo');
  $('#play').onclick = () => { ui.playing = !ui.playing; $('#play').textContent = ui.playing ? 'Pause' : 'Play'; $('#play').setAttribute('aria-pressed', !ui.playing); };
  $('#speed').onchange = (e) => { ui.speed = Number(e.target.value); };
  $('#reset').onclick = () => startDemo();
  $('#zin').onclick = () => zoomAt(1.25); $('#zout').onclick = () => zoomAt(0.8); $('#fit').onclick = fit;
  deptSel.onchange = (e) => { ui.dept = e.target.value; };
  $('#type').onchange = (e) => { ui.type = e.target.value; };
  $('#q').oninput = (e) => { ui.q = e.target.value.trim(); };
  $('#alerts').onchange = (e) => { ui.alerts = e.target.checked; };
  $('#links').onchange = (e) => { ui.links = e.target.checked; };
  $('#legendBtn').onclick = () => { const l = $('#legend'); l.hidden = !l.hidden; };
  $('#full').onclick = () => { const el = $('#stage'); if (document.fullscreenElement) document.exitFullscreen(); else el.requestFullscreen?.(); };
  document.addEventListener('keydown', (e) => {
    if (e.target.matches('input, select, textarea')) return;
    if (e.key === '+' || e.key === '=') zoomAt(1.25); else if (e.key === '-') zoomAt(0.8); else if (e.key === '0') fit();
    else if (e.key === 'Escape') closePanel(); else if (e.key === 'f') $('#full').click();
    else if (e.key.startsWith('Arrow')) { const s = 40; if (e.key === 'ArrowLeft') ui.ox += s; if (e.key === 'ArrowRight') ui.ox -= s; if (e.key === 'ArrowUp') ui.oy += s; if (e.key === 'ArrowDown') ui.oy -= s; e.preventDefault(); }
  });

  function status() {
    const el = $('#status');
    if (ui.mode === 'demo') { el.className = 'status demo'; el.textContent = 'Demo / Simulation — fictional people, nothing is real or saved'; return; }
    if (liveError && !live) { el.className = 'status bad'; el.textContent = `Couldn't load live data: ${liveError}`; return; }
    if (!live) { el.className = 'status'; el.textContent = 'Loading live data…'; return; }
    const stale = Date.now() - liveAt > 120000;
    el.className = 'status ' + (stale || liveError ? 'warn' : 'good');
    const inc = live.incidents.length;
    el.textContent = `Live Operations · ${live.people.length} on the team · ${inc ? inc + ' open incident(s)' : 'no open incidents'} · updated ${ago(new Date(liveAt).toISOString())}${liveError ? ' (refresh failed, showing last data)' : stale ? ' (stale)' : ''}`;
  }
  async function poll() {
    try {
      const r = await fetch('/dashboard/api/office', { credentials: 'same-origin', headers: { accept: 'application/json' } });
      if (r.status === 401 || r.redirected) { location.href = '/dashboard/login'; return; }
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      live = await r.json(); liveAt = Date.now(); liveError = null;
      if (ui.mode === 'live') { buildLive(live); if (ui.selected) openChar(ui.selected); }
    } catch (e) { liveError = e.message; }
    status();
  }

  // pause rendering when the tab is hidden; clean up on leave
  document.addEventListener('visibilitychange', () => { if (document.hidden) cancelAnimationFrame(raf); else { last = performance.now(); raf = requestAnimationFrame(frame); } });
  const pollTimer = setInterval(poll, 15000);
  const statusTimer = setInterval(status, 5000);
  window.addEventListener('pagehide', () => { cancelAnimationFrame(raf); clearInterval(pollTimer); clearInterval(statusTimer); });
  window.addEventListener('resize', () => {});

  window.__office = { findPath, walkable, seats, ui, chars: () => chars, setMode }; // for tests
  fit(); setMode('live'); poll(); raf = requestAnimationFrame(frame);
})();
