'use strict';
// Order Documentation Tracker - standalone server. Needs Node.js >= 22.13, no npm packages.
const http = require('node:http'), fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = +process.env.PORT || 3000;
const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');
const PUB = path.join(__dirname, 'public');
const MAXUP = (+process.env.MAX_UPLOAD_MB || 25) * 1048576;
const SESSION_DAYS = +process.env.SESSION_DAYS || 7;
fs.mkdirSync(path.join(DATA, 'uploads'), { recursive: true });

const db = new DatabaseSync(path.join(DATA, 'tracker.db'));
db.exec(`PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE COLLATE NOCASE, name TEXT, role TEXT, pw TEXT, tv INTEGER DEFAULT 0, active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS orders(id TEXT PRIMARY KEY, data TEXT, rev INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS files(id TEXT PRIMARY KEY, oid TEXT, name TEXT, type TEXT, size INTEGER, uploader TEXT, ts TEXT);`);

const E = (status, msg) => Object.assign(new Error(msg), { status });
const now = () => new Date().toISOString().slice(0, 16).replace('T', ' ');
const uid = () => crypto.randomBytes(6).toString('hex');
const kvGet = k => { const r = db.prepare('SELECT v FROM kv WHERE k=?').get(k); return r ? JSON.parse(r.v) : undefined; };
const kvSet = (k, v) => db.prepare('INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v').run(k, JSON.stringify(v));
const SECRET = process.env.SECRET || kvGet('secret') || (() => { const s = crypto.randomBytes(32).toString('hex'); kvSet('secret', s); return s; })();

const DEF = {
  app: 'Order Documentation Tracker', mfr: 'Your Valve Company', weeks: 12, fields: [], ac: '#24415e', public: true,
  ms: [{ w: 2, t: 'Drawings & GA submitted', r: 7 }, { w: 4, t: 'Material certificates (MTC)', r: 7 }, { w: 6, t: 'ITP / QAP & test procedures', r: 7 },
       { w: 8, t: 'Inspection & test reports', r: 7 }, { w: 10, t: 'Data book draft', r: 7 }, { w: 12, t: 'Final data book submitted', r: 7 }],
};
const getCfg = () => ({ ...DEF, ...kvGet('cfg') });

// ---------- passwords & sessions ----------
const hashPw = pw => { const s = crypto.randomBytes(16).toString('hex'); return s + ':' + crypto.scryptSync(pw, s, 32).toString('hex'); };
const checkPw = (pw, stored) => {
  const [s, h] = String(stored).split(':'); if (!s || !h) return false;
  const a = crypto.scryptSync(pw, s, 32), b = Buffer.from(h, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};
const sign = p => { const b = Buffer.from(JSON.stringify(p)).toString('base64url'); return b + '.' + crypto.createHmac('sha256', SECRET).update(b).digest('base64url'); };
const unsign = t => {
  const [b, m] = String(t || '').split('.'); if (!b || !m) return null;
  const good = crypto.createHmac('sha256', SECRET).update(b).digest('base64url');
  if (good.length !== m.length || !crypto.timingSafeEqual(Buffer.from(good), Buffer.from(m))) return null;
  try { return JSON.parse(Buffer.from(b, 'base64url').toString()); } catch { return null; }
};
const cookies = req => Object.fromEntries((req.headers.cookie || '').split(';').map(s => s.trim().split(/=(.*)/s).slice(0, 2)).filter(x => x[0]));
const setCookie = (req, res, val, age) => {
  const secure = process.env.COOKIE_SECURE === '1' || req.headers['x-forwarded-proto'] === 'https';
  res.setHeader('Set-Cookie', `vt=${val}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${age}${secure ? '; Secure' : ''}`);
};
const pub = u => ({ id: u.id, username: u.username, name: u.name, role: u.role, active: !!u.active });
const userFrom = req => {
  const p = unsign(cookies(req).vt); if (!p || p.e < Date.now()) return null;
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(p.u);
  return u && u.active && u.tv === p.tv ? u : null;
};
const issue = (req, res, u) => setCookie(req, res, sign({ u: u.id, tv: u.tv, e: Date.now() + SESSION_DAYS * 864e5 }), SESSION_DAYS * 86400);

const fails = new Map();
const ipOf = req => (process.env.TRUST_PROXY === '1' && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress;

// first run: create the admin account
if (!db.prepare('SELECT 1 FROM users').get()) {
  const pw = process.env.ADMIN_PASSWORD || crypto.randomBytes(9).toString('base64url');
  const un = process.env.ADMIN_USER || 'admin';
  db.prepare('INSERT INTO users(username,name,role,pw) VALUES(?,?,?,?)').run(un, 'Administrator', 'admin', hashPw(pw));
  console.log(`\n  First run: admin account created\n  username: ${un}\n  password: ${process.env.ADMIN_PASSWORD ? '(from ADMIN_PASSWORD)' : pw}\n  Change it after logging in.\n`);
}

// ---------- order validation & audit log ----------
const S = (v, n) => String(v ?? '').trim().slice(0, n);
const D = v => /^\d{4}-\d\d-\d\d$/.test(v || '') ? v : '';
// reminder lead time (days before the milestone due date); default 7
const R = v => { const n = parseInt(v); return Number.isFinite(n) ? Math.max(0, Math.min(365, n)) : 7; };
// customer email field may hold several addresses (comma / semicolon / space separated); stored as "a@x.com, b@y.com"
const EMAIL_RE = /^[^\s@,;]+@[^\s@,;]+$/;
const emails = v => {
  const seen = new Set(), list = [];
  for (const x of String(v ?? '').split(/[\s,;]+/).map(t => t.trim()).filter(Boolean)) {
    if (x.length > 254 || !EMAIL_RE.test(x)) throw E(400, 'Invalid email address: ' + S(x, 60));
    if (!seen.has(x.toLowerCase())) { seen.add(x.toLowerCase()); list.push(x); }
  }
  if (list.length > 20) throw E(400, 'At most 20 customer email addresses are allowed');
  return list.join(', ');
};
// built-in order fields: their labels can be renamed per order; the optional ones can be removed
const LABEL_KEYS = ['date', 'orderNo', 'customer', 'email', 'est', 'mref', 'weeks'], HIDEABLE = ['email', 'est', 'mref', 'weeks'];
function clean(d, old) {
  if (!D(d.date) || !S(d.orderNo, 80) || !S(d.customer, 200)) throw E(400, 'PO receipt date, order no and customer are required');
  const extra = {};
  Object.entries(d.extra || {}).slice(0, 40).forEach(([k, v]) => { if (S(k, 60)) extra[S(k, 60)] = S(v, 500); });
  const labels = {};
  Object.entries(d.labels || {}).forEach(([k, v]) => { if (LABEL_KEYS.includes(k) && S(v, 60)) labels[k] = S(v, 60); });
  const hide = [...new Set(Array.isArray(d.hide) ? d.hide : [])].filter(k => HIDEABLE.includes(k));
  const ms = (Array.isArray(d.ms) ? d.ms : []).slice(0, 60).map(m => ({ w: Math.max(0, Math.min(520, parseInt(m.w) || 0)), t: S(m.t, 200), r: R(m.r), done: D(m.done) || null, note: S(m.note, 2000) }));
  // an unchanged legacy address is kept as is, so old orders can still be updated; anything edited is validated
  const email = hide.includes('email') ? '' : (old && String(d.email ?? '') === String(old.email ?? '')) ? S(d.email, 1000) : emails(d.email);
  return { date: d.date, orderNo: S(d.orderNo, 80), customer: S(d.customer, 200), email, est: hide.includes('est') ? '' : D(d.est), mref: hide.includes('mref') ? '' : S(d.mref, 80),
           weeks: Math.max(1, Math.min(520, parseInt(d.weeks) || 12)), extra, labels, hide, ms, files: old ? old.files : [], log: old ? old.log : [] };
}
function diffLog(o, n, who) {
  const out = [], at = now(), L = t => out.push({ who, at, what: t });
  const head = x => JSON.stringify([x.date, x.orderNo, x.customer, x.email, x.est, x.mref, x.weeks, x.extra, x.labels || {}, x.hide || []]);
  if (head(o) !== head(n)) L('Order details edited');
  const om = new Map(o.ms.map(m => [m.w + '|' + m.t, m]));
  for (const m of n.ms) {
    const k = 'W' + m.w + ' ' + m.t, p = om.get(m.w + '|' + m.t);
    if (!p) { L(k + ': milestone added'); continue; }
    if ((p.done || null) !== (m.done || null)) L(k + ': ' + (m.done ? 'Passed' : 'Pass undone'));
    if ((p.note || '') !== (m.note || '')) L(k + ': remarks updated');
    if ((p.r ?? 7) !== (m.r ?? 7)) L(k + ': reminder set to ' + m.r + ' days before due');
    om.delete(m.w + '|' + m.t);
  }
  om.forEach(m => L('W' + m.w + ' ' + m.t + ': milestone removed'));
  return out;
}
const getOrder = id => { const r = db.prepare('SELECT * FROM orders WHERE id=?').get(id); return r && { ...JSON.parse(r.data), id: r.id, rev: r.rev }; };
const saveOrder = (id, d, rev) => db.prepare('INSERT INTO orders(id,data,rev) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data, rev=excluded.rev').run(id, JSON.stringify(d), rev);
const strip = o => { const { id, rev, ...d } = o; return d; };

// ---------- http helpers ----------
const send = (res, code, obj) => { const b = JSON.stringify(obj); res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }); res.end(b); };
function readBody(req, max) {
  return new Promise((ok, no) => {
    const c = []; let n = 0, big = false;
    req.on('data', d => { n += d.length; if (n > max) big = true; else c.push(d); });
    req.on('end', () => big ? no(E(413, 'File or request too large')) : ok(Buffer.concat(c)));
    req.on('error', no);
  });
}
const lastAdmin = id => !db.prepare("SELECT 1 FROM users WHERE role='admin' AND active=1 AND id<>?").get(id);

// ---------- API ----------
async function api(req, res, url, p) {
  const m = req.method, u = userFrom(req), cfg = getCfg();
  if (m !== 'GET' && req.headers['x-req'] !== '1') throw E(403, 'Bad request');
  const need = role => {
    if (!u) throw E(401, 'Login required');
    if (role === 'admin' && u.role !== 'admin') throw E(403, 'Admin access required');
    if (role === 'editor' && u.role === 'viewer') throw E(403, 'Editor access required');
  };
  const canRead = () => { if (!u && !cfg.public) throw E(401, 'Login required'); };
  const body = async () => { try { return JSON.parse((await readBody(req, 1e6)).toString() || '{}'); } catch (e) { throw e.status ? e : E(400, 'Invalid JSON'); } };
  let g;

  if (m === 'GET' && p === '/api/state') {
    if (!u && !cfg.public) return send(res, 401, { error: 'login', brand: { app: cfg.app, mfr: cfg.mfr, ac: cfg.ac } });
    const orders = db.prepare('SELECT * FROM orders').all().map(r => ({ ...JSON.parse(r.data), id: r.id, rev: r.rev }));
    return send(res, 200, { me: u ? pub(u) : null, cfg, orders });
  }
  if (m === 'POST' && p === '/api/login') {
    const ip = ipOf(req), f = fails.get(ip);
    if (f && f.n >= 8 && Date.now() - f.t < 9e5) throw E(429, 'Too many attempts. Try again in 15 minutes.');
    const b = await body(), row = db.prepare('SELECT * FROM users WHERE username=?').get(S(b.username, 60));
    if (!row || !row.active || !checkPw(String(b.password || ''), row.pw)) {
      fails.set(ip, { n: (f && Date.now() - f.t < 9e5 ? f.n : 0) + 1, t: Date.now() });
      throw E(401, 'Invalid username or password');
    }
    fails.delete(ip); issue(req, res, row); return send(res, 200, { me: pub(row) });
  }
  if (m === 'POST' && p === '/api/logout') { setCookie(req, res, '', 0); return send(res, 200, {}); }
  if (m === 'POST' && p === '/api/password') {
    need(); const b = await body();
    if (!checkPw(String(b.old || ''), u.pw)) throw E(400, 'Current password is wrong');
    if (String(b.new || '').length < 8) throw E(400, 'New password must be at least 8 characters');
    db.prepare('UPDATE users SET pw=?, tv=tv+1 WHERE id=?').run(hashPw(b.new), u.id);
    issue(req, res, { ...u, tv: u.tv + 1 }); return send(res, 200, {});
  }

  // orders
  if (m === 'POST' && p === '/api/orders') {
    need('editor'); const b = await body(), d = clean(b.data || {}), id = uid();
    d.log = [{ who: u.name, at: now(), what: 'Order created' }]; saveOrder(id, d, 1); return send(res, 200, { id });
  }
  if ((g = p.match(/^\/api\/orders\/(\w+)$/))) {
    if (m === 'PUT') {
      need('editor'); const old = getOrder(g[1]); if (!old) throw E(404, 'Order not found');
      const b = await body(); if (b.rev !== old.rev) throw E(409, 'Order was changed by someone else');
      const n = clean(b.data || {}, strip(old)); n.log = [...old.log, ...diffLog(old, n, u.name)].slice(-500);
      saveOrder(old.id, n, old.rev + 1); return send(res, 200, { rev: old.rev + 1 });
    }
    if (m === 'DELETE') {
      need('admin');
      for (const f of db.prepare('SELECT id FROM files WHERE oid=?').all(g[1])) fs.rmSync(path.join(DATA, 'uploads', f.id), { force: true });
      db.prepare('DELETE FROM files WHERE oid=?').run(g[1]); db.prepare('DELETE FROM orders WHERE id=?').run(g[1]); return send(res, 200, {});
    }
  }
  if (m === 'POST' && (g = p.match(/^\/api\/orders\/(\w+)\/files$/))) {
    need('editor'); const o = getOrder(g[1]); if (!o) throw E(404, 'Order not found');
    const buf = await readBody(req, MAXUP); if (!buf.length) throw E(400, 'Empty file');
    const fid = uid() + uid(), name = S(url.searchParams.get('name'), 200).replace(/[\\/\r\n"]/g, '_') || 'file';
    fs.writeFileSync(path.join(DATA, 'uploads', fid), buf);
    db.prepare('INSERT INTO files(id,oid,name,type,size,uploader,ts) VALUES(?,?,?,?,?,?,?)').run(fid, o.id, name, S(req.headers['content-type'], 100), buf.length, u.name, now());
    const d = strip(o); d.files.push({ id: fid, name, size: buf.length }); d.log.push({ who: u.name, at: now(), what: 'Attached ' + name });
    saveOrder(o.id, d, o.rev + 1); return send(res, 200, { id: fid });
  }
  if ((g = p.match(/^\/api\/files\/(\w+)$/))) {
    if (m === 'GET') {
      canRead(); const f = db.prepare('SELECT * FROM files WHERE id=?').get(g[1]); if (!f) throw E(404, 'File not found');
      const inline = /^(application\/pdf|image\/(png|jpeg|gif|webp))$/.test(f.type);
      res.writeHead(200, { 'Content-Type': inline ? f.type : 'application/octet-stream', 'Content-Length': f.size, 'Cache-Control': 'private, max-age=300',
        'Content-Disposition': `${inline ? 'inline' : 'attachment'}; filename*=UTF-8''${encodeURIComponent(f.name)}`, 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': 'sandbox' });
      return fs.createReadStream(path.join(DATA, 'uploads', f.id)).pipe(res);
    }
    if (m === 'DELETE') {
      need('editor'); const f = db.prepare('SELECT * FROM files WHERE id=?').get(g[1]); if (!f) throw E(404, 'File not found');
      const o = getOrder(f.oid);
      if (o) { const d = strip(o); d.files = d.files.filter(x => x.id !== f.id); d.log.push({ who: u.name, at: now(), what: 'Removed attachment ' + f.name }); saveOrder(o.id, d, o.rev + 1); }
      fs.rmSync(path.join(DATA, 'uploads', f.id), { force: true }); db.prepare('DELETE FROM files WHERE id=?').run(f.id); return send(res, 200, {});
    }
  }

  // settings
  if (m === 'PUT' && p === '/api/cfg') {
    need('admin'); const b = await body();
    kvSet('cfg', {
      app: S(b.app, 80) || DEF.app, mfr: S(b.mfr, 120), weeks: Math.max(1, parseInt(b.weeks) || 12), public: !!b.public,
      ac: /^#[0-9a-f]{6}$/i.test(b.ac) ? b.ac : DEF.ac,
      fields: (Array.isArray(b.fields) ? b.fields : []).map(x => S(x, 60)).filter(Boolean).slice(0, 40),
      ms: (Array.isArray(b.ms) ? b.ms : []).slice(0, 60).map(x => ({ w: Math.max(0, parseInt(x.w) || 0), t: S(x.t, 200), r: R(x.r) })),
    });
    return send(res, 200, {});
  }

  // users (admin)
  if (p === '/api/users' && m === 'GET') { need('admin'); return send(res, 200, { users: db.prepare('SELECT * FROM users ORDER BY username').all().map(pub) }); }
  if (p === '/api/users' && m === 'POST') {
    need('admin'); const b = await body(), un = S(b.username, 40);
    if (!/^[\w.@-]{3,40}$/.test(un)) throw E(400, 'Username: 3-40 letters, digits, . _ - @');
    if (!['admin', 'editor', 'viewer'].includes(b.role)) throw E(400, 'Role must be admin, editor or viewer');
    if (String(b.password || '').length < 8) throw E(400, 'Password must be at least 8 characters');
    if (db.prepare('SELECT 1 FROM users WHERE username=?').get(un)) throw E(409, 'Username already exists');
    db.prepare('INSERT INTO users(username,name,role,pw) VALUES(?,?,?,?)').run(un, S(b.name, 80) || un, b.role, hashPw(b.password)); return send(res, 200, {});
  }
  if ((g = p.match(/^\/api\/users\/(\d+)$/))) {
    need('admin'); const id = +g[1], row = db.prepare('SELECT * FROM users WHERE id=?').get(id); if (!row) throw E(404, 'User not found');
    if (m === 'DELETE') { if (row.role === 'admin' && lastAdmin(id)) throw E(400, 'Cannot delete the last admin'); db.prepare('DELETE FROM users WHERE id=?').run(id); return send(res, 200, {}); }
    if (m === 'PUT') {
      const b = await body(), role = b.role ?? row.role, active = b.active === undefined ? row.active : +!!b.active;
      if (!['admin', 'editor', 'viewer'].includes(role)) throw E(400, 'Invalid role');
      if (row.role === 'admin' && (role !== 'admin' || !active) && lastAdmin(id)) throw E(400, 'At least one active admin is required');
      let pw = row.pw, tv = row.tv;
      if (b.password !== undefined) { if (String(b.password).length < 8) throw E(400, 'Password must be at least 8 characters'); pw = hashPw(b.password); tv++; }
      if (!active) tv++;
      db.prepare('UPDATE users SET name=?, role=?, active=?, pw=?, tv=? WHERE id=?').run(S(b.name ?? row.name, 80), role, active, pw, tv, id); return send(res, 200, {});
    }
  }
  throw E(404, 'Not found');
}

// ---------- static files ----------
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.json': 'application/json' };
function serveStatic(req, res, p) {
  if (p === '/healthz') { res.writeHead(200); return res.end('ok'); }
  let f; try { f = path.normalize(path.join(PUB, decodeURIComponent(p === '/' ? '/index.html' : p))); } catch { res.writeHead(400); return res.end(); }
  if (!f.startsWith(PUB + path.sep) || !fs.existsSync(f) || !fs.statSync(f).isFile()) { res.writeHead(404); return res.end('Not found'); }
  res.writeHead(200, { 'Content-Type': MIME[path.extname(f)] || 'application/octet-stream', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'same-origin', 'Cache-Control': f.endsWith('.html') ? 'no-cache' : 'public, max-age=86400' });
  fs.createReadStream(f).pipe(res);
}

http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x'), p = url.pathname;
    if (p.startsWith('/api/')) return await api(req, res, url, p);
    if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
    serveStatic(req, res, p);
  } catch (e) {
    if (e.status) return send(res, e.status, { error: e.message });
    console.error(e); send(res, 500, { error: 'Server error' });
  }
}).listen(PORT, () => console.log(`Tracker running on http://localhost:${PORT}  (data: ${DATA})`));
