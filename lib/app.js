'use strict';
// Order Documentation Tracker - request handler (Vercel serverless / local). Postgres for data, Vercel Blob for attachments.
const crypto = require('node:crypto');
const { Pool } = require('pg');
const { handleUpload } = require('@vercel/blob/client');
const blob = require('@vercel/blob');

const MAXUP = (+process.env.MAX_UPLOAD_MB || 100) * 1048576;
const SESSION_DAYS = +process.env.SESSION_DAYS || 7;

const DB_URL = process.env.DATABASE_URL || process.env.POSTGRES_URL;
if (!DB_URL) console.error('DATABASE_URL is not set');
const pool = new Pool({ connectionString: DB_URL, max: 3, idleTimeoutMillis: 10000 });
pool.on('error', e => console.error('pg pool error', e.message));
const q = async (text, params) => (await pool.query(text, params)).rows;
const q1 = async (text, params) => (await q(text, params))[0];

const E = (status, msg) => Object.assign(new Error(msg), { status });
const now = () => new Date().toISOString().slice(0, 16).replace('T', ' ');
const uid = () => crypto.randomBytes(6).toString('hex');

// ---------- schema + first-run bootstrap (once per cold start) ----------
let SECRET, ready;
const hashPw = pw => { const s = crypto.randomBytes(16).toString('hex'); return s + ':' + crypto.scryptSync(pw, s, 32).toString('hex'); };
function init() {
  return ready || (ready = (async () => {
    await q(`CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY, username TEXT NOT NULL, name TEXT, role TEXT, pw TEXT, tv INTEGER DEFAULT 0, active INTEGER DEFAULT 1)`);
    await q(`CREATE UNIQUE INDEX IF NOT EXISTS users_username_ci ON users (LOWER(username))`);
    await q(`CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT)`);
    await q(`CREATE TABLE IF NOT EXISTS orders(id TEXT PRIMARY KEY, data TEXT, rev INTEGER DEFAULT 1)`);
    await q(`CREATE TABLE IF NOT EXISTS files(id TEXT PRIMARY KEY, oid TEXT, name TEXT, type TEXT, size BIGINT, uploader TEXT, ts TEXT, path TEXT)`);
    await q(`CREATE TABLE IF NOT EXISTS login_fails(ip TEXT PRIMARY KEY, n INTEGER, t BIGINT)`);
    SECRET = process.env.SECRET;
    if (!SECRET) {
      await q(`INSERT INTO kv(k,v) VALUES('secret',$1) ON CONFLICT DO NOTHING`, [JSON.stringify(crypto.randomBytes(32).toString('hex'))]);
      SECRET = JSON.parse((await q1(`SELECT v FROM kv WHERE k='secret'`)).v);
    }
    if (!(await q1('SELECT 1 FROM users'))) {
      const pw = process.env.ADMIN_PASSWORD || crypto.randomBytes(9).toString('base64url'), un = process.env.ADMIN_USER || 'admin';
      const r = await pool.query(`INSERT INTO users(username,name,role,pw) VALUES($1,'Administrator','admin',$2) ON CONFLICT DO NOTHING`, [un, hashPw(pw)]);
      if (r.rowCount) console.log(`First run: admin account created. username: ${un} password: ${process.env.ADMIN_PASSWORD ? '(from ADMIN_PASSWORD)' : pw}`);
    }
  })().catch(e => { ready = null; throw e; }));
}

const kvGet = async k => { const r = await q1('SELECT v FROM kv WHERE k=$1', [k]); return r ? JSON.parse(r.v) : undefined; };
const kvSet = (k, v) => q('INSERT INTO kv(k,v) VALUES($1,$2) ON CONFLICT(k) DO UPDATE SET v=excluded.v', [k, JSON.stringify(v)]);
const DEF = {
  app: 'Order Documentation Tracker', mfr: 'Your Valve Company', weeks: 12, fields: [], ac: '#24415e', public: true,
  ms: [{ w: 2, t: 'Drawings & GA submitted', r: 7 }, { w: 4, t: 'Material certificates (MTC)', r: 7 }, { w: 6, t: 'ITP / QAP & test procedures', r: 7 },
       { w: 8, t: 'Inspection & test reports', r: 7 }, { w: 10, t: 'Data book draft', r: 7 }, { w: 12, t: 'Final data book submitted', r: 7 }],
};
const getCfg = async () => ({ ...DEF, ...(await kvGet('cfg')) });

// ---------- passwords & sessions ----------
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
const userFrom = async req => {
  const p = unsign(cookies(req).vt); if (!p || p.e < Date.now()) return null;
  const u = await q1('SELECT * FROM users WHERE id=$1', [p.u]);
  return u && u.active && u.tv === p.tv ? u : null;
};
const issue = (req, res, u) => setCookie(req, res, sign({ u: u.id, tv: u.tv, e: Date.now() + SESSION_DAYS * 864e5 }), SESSION_DAYS * 86400);
// On Vercel the platform sets x-forwarded-for itself, so it can be trusted
const trustProxy = () => process.env.VERCEL === '1' || process.env.TRUST_PROXY === '1';
const ipOf = req => (trustProxy() && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress || 'unknown';

// ---------- order validation & audit log ----------
const S = (v, n) => String(v ?? '').trim().slice(0, n);
const D = v => /^\d{4}-\d\d-\d\d$/.test(v || '') ? v : '';
const R = v => { const n = parseInt(v); return Number.isFinite(n) ? Math.max(0, Math.min(365, n)) : 7; };
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
const LABEL_KEYS = ['date', 'orderNo', 'customer', 'email', 'est', 'mref', 'weeks'], HIDEABLE = ['email', 'est', 'mref', 'weeks'];
function clean(d, old) {
  if (!D(d.date) || !S(d.orderNo, 80) || !S(d.customer, 200)) throw E(400, 'PO receipt date, order no and customer are required');
  const extra = {};
  Object.entries(d.extra || {}).slice(0, 40).forEach(([k, v]) => { if (S(k, 60)) extra[S(k, 60)] = S(v, 500); });
  const labels = {};
  Object.entries(d.labels || {}).forEach(([k, v]) => { if (LABEL_KEYS.includes(k) && S(v, 60)) labels[k] = S(v, 60); });
  const hide = [...new Set(Array.isArray(d.hide) ? d.hide : [])].filter(k => HIDEABLE.includes(k));
  const ms = (Array.isArray(d.ms) ? d.ms : []).slice(0, 60).map(m => ({ w: Math.max(0, Math.min(520, parseInt(m.w) || 0)), t: S(m.t, 200), r: R(m.r), done: D(m.done) || null, note: S(m.note, 2000) }));
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
const getOrder = async id => { const r = await q1('SELECT * FROM orders WHERE id=$1', [id]); return r && { ...JSON.parse(r.data), id: r.id, rev: r.rev }; };
const strip = o => { const { id, rev, ...d } = o; return d; };
// compare-and-swap save: returns false when someone else changed the order in between
const casOrder = async (id, d, rev) => (await pool.query('UPDATE orders SET data=$2, rev=rev+1 WHERE id=$1 AND rev=$3', [id, JSON.stringify(d), rev])).rowCount === 1;
// read-modify-write with retry (used for attachments, where the user did not edit the order form)
async function mutate(id, fn) {
  for (let i = 0; i < 6; i++) {
    const o = await getOrder(id); if (!o) throw E(404, 'Order not found');
    const d = strip(o); fn(d, o);
    if (await casOrder(id, d, o.rev)) return;
  }
  throw E(409, 'Order is being changed by someone else, please retry');
}

// ---------- http helpers ----------
const send = (res, code, obj) => { res.statusCode = code; res.setHeader('Content-Type', 'application/json'); res.setHeader('Cache-Control', 'no-store'); res.setHeader('X-Content-Type-Options', 'nosniff'); res.end(JSON.stringify(obj)); };
const readRaw = (req, max) => new Promise((ok, no) => {
  const c = []; let n = 0, big = false;
  req.on('data', d => { n += d.length; if (n > max) big = true; else c.push(d); });
  req.on('end', () => big ? no(E(413, 'Request too large')) : ok(Buffer.concat(c)));
  req.on('error', no);
});
// Vercel may already have parsed a JSON body into req.body; locally we read the stream
async function readJson(req) {
  try {
    if (req.body !== undefined && req.body !== null) {
      if (Buffer.isBuffer(req.body)) return JSON.parse(req.body.toString() || '{}');
      return typeof req.body === 'string' ? JSON.parse(req.body || '{}') : req.body;
    }
    return JSON.parse((await readRaw(req, 1e6)).toString() || '{}');
  } catch (e) { throw e.status ? e : E(400, 'Invalid JSON'); }
}
const lastAdmin = async id => !(await q1("SELECT 1 FROM users WHERE role='admin' AND active=1 AND id<>$1", [id]));
const safeName = n => S(n, 200).replace(/[\\/\r\n"]/g, '_') || 'file';

// ---------- API ----------
async function api(req, res, url, p) {
  const m = req.method, u = await userFrom(req), cfg = await getCfg();
  if (m !== 'GET' && req.headers['x-req'] !== '1') throw E(403, 'Bad request');
  const need = role => {
    if (!u) throw E(401, 'Login required');
    if (role === 'admin' && u.role !== 'admin') throw E(403, 'Admin access required');
    if (role === 'editor' && u.role === 'viewer') throw E(403, 'Editor access required');
  };
  const canRead = () => { if (!u && !cfg.public) throw E(401, 'Login required'); };
  const body = () => readJson(req);
  let g;

  if (m === 'GET' && p === '/api/state') {
    if (!u && !cfg.public) return send(res, 401, { error: 'login', brand: { app: cfg.app, mfr: cfg.mfr, ac: cfg.ac } });
    const orders = (await q('SELECT * FROM orders')).map(r => ({ ...JSON.parse(r.data), id: r.id, rev: r.rev }));
    return send(res, 200, { me: u ? pub(u) : null, cfg, orders });
  }
  if (m === 'POST' && p === '/api/login') {
    const ip = ipOf(req), f = await q1('SELECT * FROM login_fails WHERE ip=$1', [ip]), t = Date.now();
    if (f && f.n >= 8 && t - f.t < 9e5) throw E(429, 'Too many attempts. Try again in 15 minutes.');
    const b = await body(), row = await q1('SELECT * FROM users WHERE LOWER(username)=LOWER($1)', [S(b.username, 60)]);
    if (!row || !row.active || !checkPw(String(b.password || ''), row.pw)) {
      await q('INSERT INTO login_fails(ip,n,t) VALUES($1,$2,$3) ON CONFLICT(ip) DO UPDATE SET n=excluded.n, t=excluded.t', [ip, (f && t - f.t < 9e5 ? f.n : 0) + 1, t]);
      throw E(401, 'Invalid username or password');
    }
    await q('DELETE FROM login_fails WHERE ip=$1', [ip]); issue(req, res, row); return send(res, 200, { me: pub(row) });
  }
  if (m === 'POST' && p === '/api/logout') { setCookie(req, res, '', 0); return send(res, 200, {}); }
  if (m === 'POST' && p === '/api/password') {
    need(); const b = await body();
    if (!checkPw(String(b.old || ''), u.pw)) throw E(400, 'Current password is wrong');
    if (String(b.new || '').length < 8) throw E(400, 'New password must be at least 8 characters');
    await q('UPDATE users SET pw=$1, tv=tv+1 WHERE id=$2', [hashPw(b.new), u.id]);
    issue(req, res, { ...u, tv: u.tv + 1 }); return send(res, 200, {});
  }

  // orders
  if (m === 'POST' && p === '/api/orders') {
    need('editor'); const b = await body(), d = clean(b.data || {}), id = uid();
    d.log = [{ who: u.name, at: now(), what: 'Order created' }];
    await q('INSERT INTO orders(id,data,rev) VALUES($1,$2,1)', [id, JSON.stringify(d)]); return send(res, 200, { id });
  }
  if ((g = p.match(/^\/api\/orders\/(\w+)$/))) {
    if (m === 'PUT') {
      need('editor'); const old = await getOrder(g[1]); if (!old) throw E(404, 'Order not found');
      const b = await body(); if (b.rev !== old.rev) throw E(409, 'Order was changed by someone else');
      const n = clean(b.data || {}, strip(old)); n.log = [...old.log, ...diffLog(old, n, u.name)].slice(-500);
      if (!(await casOrder(old.id, n, old.rev))) throw E(409, 'Order was changed by someone else');
      return send(res, 200, { rev: old.rev + 1 });
    }
    if (m === 'DELETE') {
      need('admin');
      const fs_ = await q('SELECT path FROM files WHERE oid=$1', [g[1]]);
      if (fs_.length) await blob.del(fs_.map(f => f.path).filter(Boolean)).catch(e => console.error('blob delete', e.message));
      await q('DELETE FROM files WHERE oid=$1', [g[1]]); await q('DELETE FROM orders WHERE id=$1', [g[1]]); return send(res, 200, {});
    }
  }

  // Step 1 of an upload: the browser asks for a short-lived token and then sends the file straight to Vercel Blob
  if (m === 'POST' && p === '/api/blob') {
    need('editor'); const b = await body();
    const out = await handleUpload({
      body: b, request: req,
      onBeforeGenerateToken: async (pathname, clientPayload) => {
        let oid; try { oid = String(JSON.parse(clientPayload || '{}').oid || ''); } catch { /* */ }
        if (!/^\w+$/.test(oid) || !pathname.startsWith('orders/' + oid + '/')) throw E(400, 'Bad upload path');
        if (!(await getOrder(oid))) throw E(404, 'Order not found');
        return { maximumSizeInBytes: MAXUP, addRandomSuffix: true };
      },
    });
    return send(res, 200, out);
  }
  // Step 2: register the uploaded blob on the order
  if (m === 'POST' && (g = p.match(/^\/api\/orders\/(\w+)\/files$/))) {
    need('editor'); const oid = g[1], b = await body();
    if (!(await getOrder(oid))) throw E(404, 'Order not found');
    const path = S(b.pathname, 500);
    if (!path.startsWith('orders/' + oid + '/')) throw E(400, 'Bad file path');
    let info; try { info = await blob.head(path); } catch { throw E(400, 'Upload not found'); }
    if (await q1('SELECT 1 FROM files WHERE path=$1', [path])) throw E(409, 'File already attached');
    const fid = uid() + uid(), name = safeName(b.name);
    await q('INSERT INTO files(id,oid,name,type,size,uploader,ts,path) VALUES($1,$2,$3,$4,$5,$6,$7,$8)', [fid, oid, name, S(info.contentType || b.type, 100), info.size, u.name, now(), path]);
    await mutate(oid, d => { d.files.push({ id: fid, name, size: info.size }); d.log.push({ who: u.name, at: now(), what: 'Attached ' + name }); });
    return send(res, 200, { id: fid });
  }
  if ((g = p.match(/^\/api\/files\/(\w+)$/))) {
    if (m === 'GET') {
      canRead(); const f = await q1('SELECT * FROM files WHERE id=$1', [g[1]]); if (!f) throw E(404, 'File not found');
      const r = await blob.get(f.path, { access: 'private' }); if (!r || r.statusCode !== 200) throw E(404, 'File not found');
      const inline = /^(application\/pdf|image\/(png|jpeg|gif|webp))$/.test(f.type);
      res.writeHead(200, { 'Content-Type': inline ? f.type : 'application/octet-stream', 'Content-Length': String(f.size), 'Cache-Control': 'private, max-age=300',
        'Content-Disposition': `${inline ? 'inline' : 'attachment'}; filename*=UTF-8''${encodeURIComponent(f.name)}`, 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': 'sandbox' });
      const rd = r.stream.getReader();
      try { for (;;) { const { done, value } = await rd.read(); if (done) break; if (!res.write(value)) await new Promise(ok => res.once('drain', ok)); } } finally { res.end(); }
      return;
    }
    if (m === 'DELETE') {
      need('editor'); const f = await q1('SELECT * FROM files WHERE id=$1', [g[1]]); if (!f) throw E(404, 'File not found');
      if (await getOrder(f.oid)) await mutate(f.oid, d => { d.files = d.files.filter(x => x.id !== f.id); d.log.push({ who: u.name, at: now(), what: 'Removed attachment ' + f.name }); });
      if (f.path) await blob.del(f.path).catch(e => console.error('blob delete', e.message));
      await q('DELETE FROM files WHERE id=$1', [f.id]); return send(res, 200, {});
    }
  }

  // settings
  if (m === 'PUT' && p === '/api/cfg') {
    need('admin'); const b = await body();
    await kvSet('cfg', {
      app: S(b.app, 80) || DEF.app, mfr: S(b.mfr, 120), weeks: Math.max(1, parseInt(b.weeks) || 12), public: !!b.public,
      ac: /^#[0-9a-f]{6}$/i.test(b.ac) ? b.ac : DEF.ac,
      fields: (Array.isArray(b.fields) ? b.fields : []).map(x => S(x, 60)).filter(Boolean).slice(0, 40),
      ms: (Array.isArray(b.ms) ? b.ms : []).slice(0, 60).map(x => ({ w: Math.max(0, parseInt(x.w) || 0), t: S(x.t, 200), r: R(x.r) })),
    });
    return send(res, 200, {});
  }

  // users (admin)
  if (p === '/api/users' && m === 'GET') { need('admin'); return send(res, 200, { users: (await q('SELECT * FROM users ORDER BY LOWER(username)')).map(pub) }); }
  if (p === '/api/users' && m === 'POST') {
    need('admin'); const b = await body(), un = S(b.username, 40);
    if (!/^[\w.@-]{3,40}$/.test(un)) throw E(400, 'Username: 3-40 letters, digits, . _ - @');
    if (!['admin', 'editor', 'viewer'].includes(b.role)) throw E(400, 'Role must be admin, editor or viewer');
    if (String(b.password || '').length < 8) throw E(400, 'Password must be at least 8 characters');
    const r = await pool.query('INSERT INTO users(username,name,role,pw) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING', [un, S(b.name, 80) || un, b.role, hashPw(b.password)]);
    if (!r.rowCount) throw E(409, 'Username already exists');
    return send(res, 200, {});
  }
  if ((g = p.match(/^\/api\/users\/(\d+)$/))) {
    need('admin'); const id = +g[1], row = await q1('SELECT * FROM users WHERE id=$1', [id]); if (!row) throw E(404, 'User not found');
    if (m === 'DELETE') { if (row.role === 'admin' && await lastAdmin(id)) throw E(400, 'Cannot delete the last admin'); await q('DELETE FROM users WHERE id=$1', [id]); return send(res, 200, {}); }
    if (m === 'PUT') {
      const b = await body(), role = b.role ?? row.role, active = b.active === undefined ? row.active : +!!b.active;
      if (!['admin', 'editor', 'viewer'].includes(role)) throw E(400, 'Invalid role');
      if (row.role === 'admin' && (role !== 'admin' || !active) && await lastAdmin(id)) throw E(400, 'At least one active admin is required');
      let pw = row.pw, tv = row.tv;
      if (b.password !== undefined) { if (String(b.password).length < 8) throw E(400, 'Password must be at least 8 characters'); pw = hashPw(b.password); tv++; }
      if (!active) tv++;
      await q('UPDATE users SET name=$1, role=$2, active=$3, pw=$4, tv=$5 WHERE id=$6', [S(b.name ?? row.name, 80), role, active, pw, tv, id]); return send(res, 200, {});
    }
  }
  throw E(404, 'Not found');
}

module.exports = async function handler(req, res) {
  try {
    await init();
    const url = new URL(req.url, 'http://x');
    return await api(req, res, url, url.pathname);
  } catch (e) {
    if (res.headersSent) { console.error(e); return res.end(); }
    if (e.status) return send(res, e.status, { error: e.message });
    console.error(e); send(res, 500, { error: 'Server error' });
  }
};
module.exports.init = init; module.exports.pool = pool;
