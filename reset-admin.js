'use strict';
// Usage: node reset-admin.js [username] [new-password]
// Sets (or creates) an ACTIVE ADMIN with that password. Needs DATABASE_URL, e.g. run `vercel env pull .env.local`
// then:  node --env-file=.env.local reset-admin.js admin NewPassword123
const crypto = require('node:crypto');
const { Pool } = require('pg');
const user = process.argv[2] || 'admin';
const pw = process.argv[3] || crypto.randomBytes(9).toString('base64url');
const pool = new Pool({ connectionString: process.env.DATABASE_URL || process.env.POSTGRES_URL });
(async () => {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = salt + ':' + crypto.scryptSync(pw, salt, 32).toString('hex');
  const r = await pool.query("UPDATE users SET pw=$1, role='admin', active=1, tv=tv+1 WHERE LOWER(username)=LOWER($2)", [hash, user]);
  if (!r.rowCount) await pool.query("INSERT INTO users(username,name,role,pw) VALUES($1,$1,'admin',$2)", [user, hash]);
  console.log(`\n  Login ready\n  username: ${user}\n  password: ${pw}\n`);
  await pool.end();
})().catch(e => { console.error(e.message); process.exit(1); });
