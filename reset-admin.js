'use strict';
// Usage: node reset-admin.js [username] [new-password]
// Sets (or creates) an ACTIVE ADMIN with that password. Run it on the server, in the app folder.
// Uses the same DATA_DIR as server.js. Stop/restart is not required.
const path = require('node:path'), crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');
const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');
const user = process.argv[2] || 'admin';
const pw = process.argv[3] || crypto.randomBytes(9).toString('base64url');
const db = new DatabaseSync(path.join(DATA, 'tracker.db'));
const salt = crypto.randomBytes(16).toString('hex');
const hash = salt + ':' + crypto.scryptSync(pw, salt, 32).toString('hex');
if (db.prepare('SELECT 1 FROM users WHERE username=?').get(user))
  db.prepare("UPDATE users SET pw=?, role='admin', active=1, tv=tv+1 WHERE username=?").run(hash, user);
else
  db.prepare("INSERT INTO users(username,name,role,pw) VALUES(?,?,?,?)").run(user, user, 'admin', hash);
console.log(`\n  Login ready\n  username: ${user}\n  password: ${pw}\n`);
