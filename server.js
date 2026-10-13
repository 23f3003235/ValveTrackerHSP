'use strict';
// Local development only:  DATABASE_URL=postgres://... BLOB_READ_WRITE_TOKEN=... node server.js
// On Vercel, api/index.js is used instead and public/ is served by Vercel's CDN.
const http = require('node:http'), fs = require('node:fs'), path = require('node:path');
const handler = require('./lib/app');
const PUB = path.join(__dirname, 'public'), PORT = +process.env.PORT || 3000;
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.json': 'application/json' };
http.createServer((req, res) => {
  const p = new URL(req.url, 'http://x').pathname;
  if (p.startsWith('/api/')) return handler(req, res);
  if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
  let f; try { f = path.normalize(path.join(PUB, decodeURIComponent(p === '/' ? '/index.html' : p))); } catch { res.writeHead(400); return res.end(); }
  if (!f.startsWith(PUB + path.sep) || !fs.existsSync(f) || !fs.statSync(f).isFile()) { res.writeHead(404); return res.end('Not found'); }
  res.writeHead(200, { 'Content-Type': MIME[path.extname(f)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
  fs.createReadStream(f).pipe(res);
}).listen(PORT, () => console.log(`Tracker running on http://localhost:${PORT}`));
