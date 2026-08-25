const express = require('express');
const http = require('http');
const path = require('path');
const os = require('os');
const fs = require('fs');
const crypto = require('crypto');
const { finished, pipeline } = require('stream');
const { WebSocketServer, WebSocket } = require('ws');
const { Client } = require('ssh2');
const Database = require('better-sqlite3');

const PORT = process.env.PORT || 9998;
const AUTH_COOKIE = 'webssh_auth';
const AUTH_TTL_MS = 8 * 60 * 60 * 1000;
// Used only when creating the first administrator in a fresh data directory.
// Existing accounts are never overwritten by later environment changes.
const ADMIN_USERNAME = process.env.WEBSSH_ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.WEBSSH_ADMIN_PASSWORD || 'changeme';

const app = express();
// Skip JSON body parsing for upload routes (they carry raw binary bodies).
app.use((req, res, next) => {
  if (req.method === 'POST' && req.path.includes('/upload')) return next();
  return express.json({ limit: '2mb' })(req, res, next);
});
app.use(express.static(path.join(__dirname, 'public'), {
  // Authentication/bootstrap code must not remain stuck in an old browser or
  // proxy cache after an update.
  setHeaders(res, filePath) {
    if (/\.(?:html|js|css)$/.test(filePath)) res.setHeader('Cache-Control', 'no-store');
  },
}));

/**
 * Session store: id -> session
 * session = { id, client, host, port, username, sudoPassword, connected, createdAt }
 */
const sessions = new Map();
/** ws -> sessionId (terminal sockets) */
const termSockets = new Map();

/* ---------------- server store (SQLite) ---------------- */

const DATA_DIR = process.env.WEBSSH_DATA_DIR || path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { mode: 0o700 });
const DB_PATH = path.join(DATA_DIR, 'servers.db');
const db = new Database(DB_PATH);
try { fs.chmodSync(DB_PATH, 0o600); } catch (e) { /* ignore */ }

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS servers (
    uid TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    algorithms TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS server_creds (
    server_uid TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    creds TEXT NOT NULL DEFAULT '{}',
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (server_uid, user_id)
  )
`);

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const digest = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$${salt.toString('base64')}$${digest.toString('base64')}`;
}

function verifyPassword(password, encoded) {
  try {
    const [, saltText, digestText] = String(encoded || '').split('$');
    if (!saltText || !digestText) return false;
    const expected = Buffer.from(digestText, 'base64');
    const actual = crypto.scryptSync(password, Buffer.from(saltText, 'base64'), expected.length, { N: 16384, r: 8, p: 1 });
    return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
  } catch (e) {
    return false;
  }
}

const stmtGetUserByName = db.prepare('SELECT id, username, password_hash, is_admin, created_at FROM users WHERE username = ? COLLATE NOCASE');
const stmtGetUserById = db.prepare('SELECT id, username, is_admin, created_at FROM users WHERE id = ?');
const stmtInsertUser = db.prepare('INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?)');
const stmtSetAdmin = db.prepare('UPDATE users SET is_admin = 1 WHERE id = ?');
let admin = stmtGetUserByName.get(ADMIN_USERNAME);
if (!admin) {
  stmtInsertUser.run(ADMIN_USERNAME, hashPassword(ADMIN_PASSWORD), 1, Date.now());
  admin = stmtGetUserByName.get(ADMIN_USERNAME);
} else if (!admin.is_admin) {
  stmtSetAdmin.run(admin.id);
  admin = stmtGetUserByName.get(ADMIN_USERNAME);
}
// Databases created before per-user credentials stored the SSH username and
// credentials on the server row itself. Move them into server_creds (owned by
// the row's user, or the seeded admin for unowned rows) and drop the legacy
// columns so the servers table holds only the shared server definition.
const serverColumns = db.prepare('PRAGMA table_info(servers)').all();
if (serverColumns.some((c) => c.name === 'user_id')) {
  const insCreds = db.prepare(`
    INSERT OR IGNORE INTO server_creds (server_uid, user_id, username, creds, updated_at)
    VALUES (?, ?, ?, ?, ?)
  `);
  const migrate = db.transaction(() => {
    for (const r of db.prepare('SELECT uid, user_id, username, creds FROM servers').all()) {
      insCreds.run(r.uid, r.user_id ?? admin.id, r.username, r.creds || '{}', Date.now());
    }
  });
  migrate();
  for (const col of ['user_id', 'username', 'creds']) {
    try { db.exec(`ALTER TABLE servers DROP COLUMN ${col}`); } catch (e) { /* older SQLite: keep column */ }
  }
}

const authSessions = new Map();
const loginAttempts = new Map();

function parseCookies(header) {
  const cookies = {};
  for (const part of String(header || '').split(';')) {
    const i = part.indexOf('=');
    if (i <= 0) continue;
    cookies[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return cookies;
}

function authFromRequest(req) {
  const token = parseCookies(req.headers.cookie)[AUTH_COOKIE];
  if (!token) return null;
  const entry = authSessions.get(token);
  if (!entry || entry.expiresAt <= Date.now()) {
    if (entry) {
      authSessions.delete(token);
      if (entry.expiresAt <= Date.now()) closeUserSshSessions(entry.userId);
    }
    return null;
  }
  const user = stmtGetUserById.get(entry.userId);
  if (!user) {
    authSessions.delete(token);
    return null;
  }
  return { token, user };
}

function setAuthCookie(res, token) {
  const secure = process.env.WEBSSH_SECURE_COOKIE === '1' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${AUTH_COOKIE}=${encodeURIComponent(token)}; Max-Age=${AUTH_TTL_MS / 1000}; Path=/; HttpOnly; SameSite=Lax${secure}`);
}

function clearAuthCookie(res) {
  res.setHeader('Set-Cookie', `${AUTH_COOKIE}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax`);
}

function authRequired(req, res, next) {
  const publicPaths = new Set(['/auth/login', '/auth/me', '/auth/logout']);
  if (publicPaths.has(req.path)) return next();
  const auth = authFromRequest(req);
  if (!auth) return res.status(401).json({ error: 'Please sign in' });
  req.auth = auth;
  req.user = auth.user;
  next();
}

app.use('/api', authRequired);

app.post('/api/auth/login', (req, res) => {
  const username = typeof req.body?.username === 'string' ? req.body.username.trim() : '';
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  const attemptKey = `${req.socket.remoteAddress || 'unknown'}|${username.toLowerCase()}`;
  const attempt = loginAttempts.get(attemptKey);
  if (attempt && attempt.blockedUntil > Date.now()) {
    res.setHeader('Retry-After', '60');
    return res.status(429).json({ error: 'Too many failed sign-in attempts. Try again later.' });
  }
  const user = username ? stmtGetUserByName.get(username) : null;
  if (!user || !verifyPassword(password, user.password_hash)) {
    const next = attempt && attempt.expiresAt > Date.now()
      ? { count: attempt.count + 1, expiresAt: attempt.expiresAt, blockedUntil: attempt.blockedUntil }
      : { count: 1, expiresAt: Date.now() + 10 * 60 * 1000, blockedUntil: 0 };
    if (next.count >= 5) next.blockedUntil = Date.now() + 60 * 1000;
    loginAttempts.set(attemptKey, next);
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  loginAttempts.delete(attemptKey);
  const token = crypto.randomBytes(32).toString('hex');
  authSessions.set(token, { userId: user.id, expiresAt: Date.now() + AUTH_TTL_MS });
  setAuthCookie(res, token);
  res.json({ ok: true, user: { id: user.id, username: user.username, isAdmin: !!user.is_admin } });
});

app.get('/api/auth/me', (req, res) => {
  const auth = authFromRequest(req);
  if (!auth) return res.status(401).json({ error: 'Not signed in' });
  res.json({ user: { id: auth.user.id, username: auth.user.username, isAdmin: !!auth.user.is_admin } });
});

function closeUserSshSessions(userId) {
  for (const session of [...sessions.values()]) {
    if (session.userId !== userId) continue;
    for (const [ws, sid] of termSockets) {
      if (sid === session.id && ws.readyState === WebSocket.OPEN) ws.close();
    }
    sessions.delete(session.id);
    try { session.client.end(); } catch (e) { /* ignore */ }
  }
}

app.post('/api/auth/logout', (req, res) => {
  const auth = authFromRequest(req);
  if (auth) {
    authSessions.delete(auth.token);
    closeUserSshSessions(auth.user.id);
  }
  clearAuthCookie(res);
  res.json({ ok: true });
});

function validateNewUser(username, password) {
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{2,31}$/.test(username)) {
    return 'Username must be 3-32 letters, numbers, dots, underscores, or hyphens';
  }
  if (password.length < 8 || password.length > 128) {
    return 'Password must be 8-128 characters';
  }
  return null;
}

function createUser(username, password) {
  const result = stmtInsertUser.run(username, hashPassword(password), 0, Date.now());
  return { id: result.lastInsertRowid, username, isAdmin: false };
}

app.post('/api/auth/register', (req, res) => {
  if (!req.user?.is_admin) return res.status(403).json({ error: 'Only administrators can register users' });
  const username = typeof req.body?.username === 'string' ? req.body.username.trim() : '';
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  const err = validateNewUser(username, password);
  if (err) return res.status(400).json({ error: err });
  try {
    res.json({ ok: true, user: createUser(username, password) });
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) return res.status(409).json({ error: 'Username already exists' });
    res.status(500).json({ error: e.message });
  }
});

setInterval(() => {
  const now = Date.now();
  for (const [token, entry] of authSessions) if (entry.expiresAt <= now) authSessions.delete(token);
  for (const [key, entry] of loginAttempts) if (entry.expiresAt <= now && entry.blockedUntil <= now) loginAttempts.delete(key);
}, 10 * 60 * 1000).unref();

/* ---------------- user management (admin only) ---------------- */

const stmtListUsers = db.prepare('SELECT id, username, is_admin, created_at FROM users ORDER BY created_at, id');
const stmtCountAdmins = db.prepare('SELECT COUNT(*) AS n FROM users WHERE is_admin = 1');
const stmtSetAdminFlag = db.prepare('UPDATE users SET is_admin = ? WHERE id = ?');
const stmtSetPassword = db.prepare('UPDATE users SET password_hash = ? WHERE id = ?');
const stmtDeleteUser = db.prepare('DELETE FROM users WHERE id = ?');
const stmtServerCount = db.prepare('SELECT COUNT(*) AS n FROM server_creds WHERE user_id = ?');

function requireAdmin(req, res) {
  if (!req.user || !req.user.is_admin) {
    res.status(403).json({ error: 'Only administrators can manage users' });
    return false;
  }
  return true;
}

function parseUserId(req) {
  const id = Number(req.params.id);
  return Number.isInteger(id) && id > 0 ? id : null;
}

function invalidateUserSessions(userId) {
  // Force the target to sign in again and drop their live SSH sessions.
  for (const [token, entry] of [...authSessions]) {
    if (entry.userId === userId) authSessions.delete(token);
  }
  closeUserSshSessions(userId);
}

app.get('/api/users', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const users = stmtListUsers.all().map((u) => ({
    id: u.id,
    username: u.username,
    isAdmin: !!u.is_admin,
    createdAt: u.created_at,
    serverCount: stmtServerCount.get(u.id).n,
    sessionCount: [...sessions.values()].filter((s) => s.userId === u.id && s.connected).length,
  }));
  res.json({ users });
});

app.post('/api/users', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const username = typeof req.body?.username === 'string' ? req.body.username.trim() : '';
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  const err = validateNewUser(username, password);
  if (err) return res.status(400).json({ error: err });
  try {
    res.json({ ok: true, user: createUser(username, password) });
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) return res.status(409).json({ error: 'Username already exists' });
    res.status(500).json({ error: e.message });
  }
});

app.patch('/api/users/:id', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const id = parseUserId(req);
  const target = id ? stmtGetUserById.get(id) : null;
  if (!target) return res.status(404).json({ error: 'User does not exist' });
  const b = req.body || {};
  if (typeof b.password === 'string' && b.password) {
    const err = validateNewUser(target.username, b.password);
    if (err) return res.status(400).json({ error: err });
    stmtSetPassword.run(hashPassword(b.password), target.id);
    invalidateUserSessions(target.id);
  }
  if (typeof b.isAdmin === 'boolean') {
    if (!b.isAdmin && target.is_admin && stmtCountAdmins.get().n <= 1) {
      return res.status(400).json({ error: 'Cannot revoke the last administrator' });
    }
    stmtSetAdminFlag.run(b.isAdmin ? 1 : 0, target.id);
  }
  res.json({ ok: true });
});

app.delete('/api/users/:id', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const id = parseUserId(req);
  const target = id ? stmtGetUserById.get(id) : null;
  if (!target) return res.status(404).json({ error: 'User does not exist' });
  if (target.id === req.user.id) {
    return res.status(400).json({ error: 'You cannot delete your own account' });
  }
  invalidateUserSessions(target.id);
  stmtDeleteCredsByUser.run(target.id);
  stmtDeleteUser.run(target.id);
  res.json({ ok: true });
});

const stmtUpsert = db.prepare(`
  INSERT INTO servers (uid, label, host, port, algorithms, created_at, updated_at)
  VALUES (@uid, @label, @host, @port, @algorithms, @now, @now)
  ON CONFLICT(uid) DO UPDATE SET
    label = excluded.label,
    host = excluded.host,
    port = excluded.port,
    algorithms = excluded.algorithms,
    updated_at = excluded.updated_at
`);
const stmtGetAllServers = db.prepare('SELECT * FROM servers ORDER BY created_at');
const stmtGetServer = db.prepare('SELECT uid FROM servers WHERE uid = ?');
const stmtDeleteServer = db.prepare('DELETE FROM servers WHERE uid = ?');
const stmtGetCred = db.prepare('SELECT username, creds FROM server_creds WHERE server_uid = ? AND user_id = ?');
const stmtUpsertCred = db.prepare(`
  INSERT INTO server_creds (server_uid, user_id, username, creds, updated_at)
  VALUES (@server_uid, @user_id, @username, @creds, @now)
  ON CONFLICT(server_uid, user_id) DO UPDATE SET
    username = excluded.username,
    creds = excluded.creds,
    updated_at = excluded.updated_at
`);
const stmtDeleteCred = db.prepare('DELETE FROM server_creds WHERE server_uid = ? AND user_id = ?');
const stmtDeleteCredsByServer = db.prepare('DELETE FROM server_creds WHERE server_uid = ?');
const stmtDeleteCredsByUser = db.prepare('DELETE FROM server_creds WHERE user_id = ?');

function safeParse(s, dflt) {
  try { return s ? JSON.parse(s) : dflt; } catch (e) { return dflt; }
}

function rowToServer(r) {
  return {
    uid: r.uid,
    label: r.label,
    host: r.host,
    port: r.port,
    algorithms: safeParse(r.algorithms, null),
  };
}

// Servers are shared: every user sees the full list, plus (mine) their own
// connection info for each server, or null when they have none configured.
app.get('/api/servers', (req, res) => {
  const servers = stmtGetAllServers.all().map((r) => {
    const s = rowToServer(r);
    const cred = stmtGetCred.get(r.uid, req.user.id);
    s.mine = cred ? { username: cred.username, creds: safeParse(cred.creds, {}) } : null;
    return s;
  });
  res.json({ servers });
});

// Server definitions (host/label/port) are admin-managed.
app.post('/api/servers', (req, res) => {
  if (!requireAdmin(req, res)) return;
  const b = req.body || {};
  if (!b.uid || !b.host) {
    return res.status(400).json({ error: 'uid and host are required' });
  }
  const host = String(b.host);
  try {
    stmtUpsert.run({
      uid: String(b.uid),
      label: String(b.label || '').trim() || host,
      host,
      port: Math.min(Math.max(parseInt(b.port || 22, 10) || 22, 1), 65535),
      algorithms: b.algorithms && typeof b.algorithms === 'object' ? JSON.stringify(b.algorithms) : null,
      now: Date.now(),
    });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
  res.json({ ok: true });
});

app.delete('/api/servers/:uid', (req, res) => {
  if (!requireAdmin(req, res)) return;
  stmtDeleteCredsByServer.run(req.params.uid);
  stmtDeleteServer.run(req.params.uid);
  res.json({ ok: true });
});

// Per-user connection info (username + password/key) for a shared server.
app.post('/api/servers/:uid/creds', (req, res) => {
  const server = stmtGetServer.get(req.params.uid);
  if (!server) return res.status(404).json({ error: 'Server does not exist' });
  const b = req.body || {};
  const username = typeof b.username === 'string' ? b.username.trim() : '';
  if (!username) return res.status(400).json({ error: 'username is required' });
  const creds = b.creds && typeof b.creds === 'object' ? b.creds : {};
  for (const k of Object.keys(creds)) {
    if (creds[k] != null && typeof creds[k] !== 'string') delete creds[k];
  }
  if (!creds.password && !creds.privateKey && !creds.keyRef) {
    return res.status(400).json({ error: 'A password or private key is required' });
  }
  stmtUpsertCred.run({ server_uid: server.uid, user_id: req.user.id, username, creds: JSON.stringify(creds), now: Date.now() });
  res.json({ ok: true });
});

app.delete('/api/servers/:uid/creds', (req, res) => {
  stmtDeleteCred.run(req.params.uid, req.user.id);
  res.json({ ok: true });
});

/* ---------------- helpers ---------------- */

function shq(s) {
  return "'" + String(s).replace(/'/g, "'\\''") + "'";
}

function joinPath(dir, name) {
  if (!dir || dir === '/') return '/' + name;
  if (dir.endsWith('/')) return dir + name;
  return dir + '/' + name;
}

function parentPath(remotePath) {
  const i = remotePath.lastIndexOf('/');
  return i <= 0 ? '/' : remotePath.slice(0, i);
}

/**
 * File-manager jail: resolve `remotePath` against the session's home dir and
 * verify the result stays inside it. Returns the canonical path, or null when
 * the path is invalid/escapes (empty, contains '..', resolves outside home,
 * or home is unknown). Pure path logic — no I/O, safe for every file endpoint.
 */
function resolveJailedPath(session, remotePath) {
  if (!session || !session.homeDir) return null;
  if (typeof remotePath !== 'string' || !remotePath) return null;
  const home = session.homeDir;
  const p = remotePath.startsWith('/')
    ? remotePath
    : home === '/' ? '/' + remotePath : home + '/' + remotePath;
  // Lexically collapse '..' / '.' — any surviving '..' would climb out.
  const parts = [];
  for (const seg of p.split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') {
      if (!parts.length) return null;
      parts.pop();
    } else parts.push(seg);
  }
  const abs = '/' + parts.join('/');
  if (abs !== home && !abs.startsWith(home + '/')) return null;
  return abs;
}

/**
 * Resolve symlinks on the remote so a link inside home cannot be used to
 * reach files outside it. Returns the canonical path, or null if it cannot be
 * resolved or escapes home.
 */
async function realPathJailed(session, jailedPath) {
  const r = await runCommand(session, `readlink -f -- ${shq(jailedPath)}`, 8000);
  if (r.code !== 0) return null;
  const real = r.stdout.trim().split('\n').pop();
  const home = session.homeDir;
  if (!real || !real.startsWith('/') || (real !== home && !real.startsWith(home + '/'))) return null;
  return real;
}

/**
 * Resolve the private key to use for a connection request.
 * - body.privateKey: raw PEM content (from the UI)
 * - body.keyRef:     a key file name under ~/.ssh (never leaves the server)
 */
function loadKeyRef(name) {
  if (typeof name !== 'string' || !/^[A-Za-z0-9._-]+$/.test(name)) return null;
  const dir = path.join(os.homedir(), '.ssh');
  const full = path.resolve(dir, name);
  if (full !== path.join(dir, name)) return null;
  try {
    const st = fs.statSync(full);
    if (!st.isFile() || st.size > 65536) return null;
    return fs.readFileSync(full, 'utf8');
  } catch (e) {
    return null;
  }
}

function makeConfig(body) {
  const config = {
    host: String(body.host),
    port: parseInt(body.port || 22, 10),
    username: String(body.username),
    readyTimeout: 20000,
    keepaliveInterval: 15000,
    keepaliveCountMax: 4,
  };
  let key = body.privateKey || null;
  if (!key && body.keyRef) key = loadKeyRef(body.keyRef);
  if (key) {
    config.privateKey = key;
    if (body.passphrase) config.passphrase = body.passphrase;
  } else {
    config.password = body.password;
  }
  // Optional legacy algorithm overrides (for old OpenSSH servers).
  if (body.algorithms && typeof body.algorithms === 'object') {
    const alg = {};
    const arr = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === 'string' && x.length > 0) : null);
    if (arr(body.algorithms.kex)) alg.kex = arr(body.algorithms.kex);
    if (arr(body.algorithms.serverHostKey)) alg.serverHostKey = arr(body.algorithms.serverHostKey);
    if (arr(body.algorithms.cipher)) alg.cipher = arr(body.algorithms.cipher);
    if (arr(body.algorithms.hmac)) alg.hmac = arr(body.algorithms.hmac);
    if (Object.keys(alg).length) config.algorithms = alg;
  }
  return config;
}

function runCommand(session, command, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    if (!session || !session.connected) return reject(new Error('Not connected'));
    let done = false;
    let channel = null;
    const timer = setTimeout(() => {
      if (done) return;
      done = true;
      if (channel) channel.close();
      reject(new Error('Command execution timed out'));
    }, timeoutMs);
    session.client.exec(command, (err, ch) => {
      if (err) {
        clearTimeout(timer);
        if (!done) { done = true; reject(err); }
        return;
      }
      channel = ch;
      let stdout = '';
      let stderr = '';
      ch.on('data', (d) => { stdout += d; });
      ch.stderr.on('data', (d) => { stderr += d; });
      ch.on('close', (code) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        resolve({ stdout, stderr, code: code ?? 0 });
      });
      ch.on('error', (e) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        reject(e);
      });
    });
  });
}

async function getSftp(session) {
  // Some SSH servers permit only one SFTP subsystem channel per connection.
  // Reuse it across file-manager requests instead of opening a new channel for
  // every list/read/write operation.
  if (session.sftp) return session.sftp;
  if (!session.sftpPromise) {
    session.sftpPromise = new Promise((resolve, reject) => {
      session.client.sftp((err, sftp) => {
        if (err) {
          session.sftpPromise = null;
          reject(err);
          return;
        }
        session.sftp = sftp;
        const clearSftp = () => {
          if (session.sftp === sftp) {
            session.sftp = null;
            session.sftpPromise = null;
          }
        };
        sftp.once('close', clearSftp);
        sftp.once('error', clearSftp);
        resolve(sftp);
      });
    });
  }
  return session.sftpPromise;
}

function requireSession(req, res) {
  const session = sessions.get(req.params.id || req.body.sessionId || req.query.sessionId);
  if (!session || !session.connected || !req.user || session.userId !== req.user.id) {
    res.status(404).json({ error: 'Session does not exist or has disconnected' });
    return null;
  }
  return session;
}

/* ---------------- SSH connection ---------------- */

app.post('/api/connect', (req, res) => {
  const body = req.body || {};
  if (!body.host || !body.username) {
    return res.status(400).json({ error: 'host and username are required' });
  }
  if (!body.password && !body.privateKey && !body.keyRef) {
    return res.status(400).json({ error: 'A password or private key is required' });
  }
  if (body.keyRef && !body.privateKey && !body.password && !loadKeyRef(body.keyRef)) {
    return res.status(400).json({ error: `Local key file not found: ~/.ssh/${body.keyRef}` });
  }
  const client = new Client();
  const id = crypto.randomBytes(8).toString('hex');
  const session = {
    id,
    client,
    userId: req.user.id,
    host: body.host,
    port: parseInt(body.port || 22, 10),
    username: body.username,
    sudoPassword: body.sudoPassword || '',
    homeDir: null, // resolved after connect; file manager is jailed to it
    sftp: null,
    sftpPromise: null,
    connected: false,
    createdAt: Date.now(),
  };
  client.on('ready', async () => {
    session.connected = true;
    sessions.set(id, session);
    try {
      const r = await runCommand(session, 'echo $HOME', 8000);
      const h = r.stdout.trim();
      if (r.code === 0 && h.startsWith('/')) session.homeDir = h;
    } catch (e) { /* keep null: file ops will report "home unavailable" */ }
    res.json({ ok: true, sessionId: id, host: session.host, port: session.port, username: session.username, homeDir: session.homeDir });
  });
  client.on('error', (err) => {
    sessions.delete(id);
    if (!res.headersSent) {
      // This is an upstream SSH failure, not a Web SSH Manager login failure.
      // Keeping it distinct prevents the browser from discarding a valid web
      // session when a saved server has stale credentials.
      res.status(502).json({ error: 'SSH connection failed: ' + err.message });
    }
  });
  client.on('close', () => {
    sessions.delete(id);
    for (const [ws, sid] of termSockets) {
      if (sid === id && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'error', message: 'SSH connection closed' }));
        ws.close();
      }
    }
  });
  client.connect(makeConfig(body));
});

// Local ~/.ssh/config content (for the "import from ssh config" feature).
app.get('/api/ssh-config', (req, res) => {
  try {
    const content = fs.readFileSync(path.join(os.homedir(), '.ssh', 'config'), 'utf8');
    res.json({ content });
  } catch (e) {
    res.status(404).json({ error: 'Local ~/.ssh/config does not exist' });
  }
});

// List private key file names available under ~/.ssh (no content).
app.get('/api/ssh-keys', (req, res) => {
  const dir = path.join(os.homedir(), '.ssh');
  let names = [];
  try {
    names = fs
      .readdirSync(dir)
      .filter((n) => !n.endsWith('.pub') && !n.endsWith('.known_hosts'))
      .filter((n) => {
        try {
          const st = fs.statSync(path.join(dir, n));
          return st.isFile() && st.size > 0 && st.size < 65536;
        } catch (e) {
          return false;
        }
      });
  } catch (e) { /* no .ssh dir */ }
  res.json({ keys: names });
});

app.get('/api/sessions', (req, res) => {
  res.json({
    sessions: [...sessions.values()].filter((s) => s.userId === req.user.id).map((s) => ({
      id: s.id,
      host: s.host,
      port: s.port,
      username: s.username,
      createdAt: s.createdAt,
    })),
  });
});

app.delete('/api/sessions/:id', (req, res) => {
  const session = sessions.get(req.params.id);
  if (!session || session.userId !== req.user.id) return res.status(404).json({ error: 'Session does not exist' });
  for (const [ws, sid] of termSockets) {
    if (sid === session.id && ws.readyState === WebSocket.OPEN) ws.close();
  }
  sessions.delete(session.id);
  try { session.client.end(); } catch (e) { /* ignore */ }
  res.json({ ok: true });
});

/* ---------------- generic exec ---------------- */

app.post('/api/exec', async (req, res) => {
  const { sessionId, command, sudo, timeout } = req.body || {};
  const session = sessions.get(sessionId);
  if (!session || !session.connected || session.userId !== req.user.id) return res.status(404).json({ error: 'Session does not exist or has disconnected' });
  if (!command || typeof command !== 'string' || command.length > 10000) {
    return res.status(400).json({ error: 'Invalid command parameter' });
  }
  let cmd = command;
  if (sudo) {
    if (!session.sudoPassword) return res.status(400).json({ error: 'No sudo password was provided' });
    cmd = `echo ${shq(session.sudoPassword)} | sudo -S -p '' ${command}`;
  }
  try {
    const r = await runCommand(session, cmd, Math.min(parseInt(timeout || 30000, 10), 300000));
    res.json(r);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ---------------- GPU monitoring ---------------- */

const GPU_QUERY =
  "nvidia-smi --query-gpu=index,name,driver_version,utilization.gpu,utilization.memory," +
  "memory.used,memory.total,temperature.gpu,power.draw,power.limit --format=csv,noheader,nounits";
const GPU_PROCS_QUERY =
  "nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv,noheader,nounits";

function num(v) {
  const n = parseFloat(v);
  return Number.isFinite(n) ? n : null;
}

async function gpuInfo(session) {
  try {
    const check = await runCommand(session, 'command -v nvidia-smi', 8000);
    if (check.code !== 0 || !check.stdout.trim()) return { available: false };
    const gpuRes = await runCommand(session, GPU_QUERY, 15000);
    const procRes = await runCommand(session, GPU_PROCS_QUERY, 15000).catch(() => null);
    const gpus = gpuRes.stdout.trim().split('\n').filter(Boolean).map((line) => {
      const p = line.split(',').map((s) => s.trim());
      return {
        index: num(p[0]),
        name: p[1] || 'GPU',
        driver: p[2] || '',
        util: num(p[3]),
        memUtil: num(p[4]),
        memUsed: num(p[5]),
        memTotal: num(p[6]),
        temp: num(p[7]),
        power: num(p[8]),
        powerLimit: num(p[9]),
      };
    });
    let processes = [];
    if (procRes && procRes.code === 0 && procRes.stdout.trim()) {
      processes = procRes.stdout.trim().split('\n').filter(Boolean).map((line) => {
        const p = line.split(',').map((s) => s.trim());
        const mem = num(p[p.length - 1]);
        return { pid: p[0], name: p.slice(1, -1).join(', ') || 'unknown', memUsed: mem, user: null, command: null };
      });
    }
    // Enrich each process with its owner user and full command line.
    const pids = [...new Set(processes.map((p) => p.pid).filter(Boolean))].join(',');
    if (pids) {
      try {
        const [userRes, argsRes] = await Promise.all([
          runCommand(session, `ps -o pid=,user= -p ${pids} --no-headers 2>/dev/null`, 8000),
          runCommand(session, `ps -o pid=,args= -p ${pids} --no-headers 2>/dev/null`, 8000),
        ]);
        const userMap = new Map();
        const cmdMap = new Map();
        for (const line of userRes.stdout.split('\n')) {
          const m = /^\s*(\d+)\s+(.+?)\s*$/.exec(line);
          if (m) userMap.set(m[1], m[2]);
        }
        for (const line of argsRes.stdout.split('\n')) {
          const m = /^\s*(\d+)\s+(.+?)\s*$/.exec(line);
          if (m) cmdMap.set(m[1], m[2]);
        }
        for (const p of processes) {
          p.user = userMap.get(p.pid) || null;
          p.command = cmdMap.get(p.pid) || p.name;
        }
      } catch (e) { /* ps unavailable: keep name only */ }
    }
    return {
      available: true,
      driver: gpus[0] ? gpus[0].driver : null,
      count: gpus.length,
      gpus,
      processes,
    };
  } catch (e) {
    return { available: false, error: e.message };
  }
}

app.get('/api/gpu/:id', async (req, res) => {
  const session = requireSession(req, res);
  if (!session) return;
  res.json(await gpuInfo(session));
});

/* ---------------- system info ---------------- */

// Each section may contain multiple lines (primary tool + fallback);
// the parser picks the first valid line, so minimal/container systems
// without `free` or GNU `df --output` still report what they can.
const SYS_SCRIPT = [
  'echo ===LOAD===; head -1 /proc/loadavg 2>/dev/null',
  'echo ===CPU===; nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null',
  'echo ===MEM===; free -m 2>/dev/null | awk \'^Mem:/{print $2" "$3" "$4}\'; awk \'/^MemTotal:/{t=int($2/1024)} /^MemAvailable:/{a=int($2/1024)} END{if(t>0) printf "%d %d %d\\n", t, t-a, a}\' /proc/meminfo 2>/dev/null',
  'echo ===DISK===; df -BM --output=size,used,pcent / 2>/dev/null | tail -1; df -BM / 2>/dev/null | tail -1 | awk \'{print $2" "$3" "$5}\'',
  'echo ===OS===; . /etc/os-release 2>/dev/null; echo ${PRETTY_NAME:-$(uname -s 2>/dev/null)}',
  'echo ===UPTIME===; awk \'{printf "%d", $1}\' /proc/uptime 2>/dev/null',
  'echo ===HOSTNAME===; hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null',
].join('; ');

function parseSizeMB(v) {
  const m = /^(\d+)([KMGTP]?)B?$/i.exec(String(v).trim());
  if (!m) return null;
  const mult = { K: 1 / 1024, M: 1, G: 1024, T: 1024 * 1024, P: 1024 * 1024 * 1024 }[m[2].toUpperCase()] || 1;
  return Math.round(parseInt(m[1], 10) * mult);
}

function firstNumLine(s, count) {
  for (const line of String(s || '').split('\n')) {
    const p = line.trim().split(/\s+/).map((v) => num(v)).filter((v) => v != null);
    if (p.length >= count) return p;
  }
  return [];
}

function parseDiskSection(s) {
  for (const line of String(s || '').split('\n')) {
    const p = line.trim().split(/\s+/);
    if (p.length >= 3) {
      const total = parseSizeMB(p[0]);
      const used = parseSizeMB(p[1]);
      if (total != null && used != null) {
        return { total, used, pct: num(p[2].replace('%', '')) };
      }
    }
  }
  return { total: null, used: null, pct: null };
}

async function sysInfo(session) {
  const { stdout } = await runCommand(session, SYS_SCRIPT, 15000);
  const sections = {};
  for (const block of stdout.split(/\n(?====)/)) {
    const m = /^===([A-Z_]+)===\n?([\s\S]*)$/.exec(block.trim());
    if (m) sections[m[1]] = m[2].trim();
  }
  const load = firstNumLine(sections.LOAD, 3);
  const mem = firstNumLine(sections.MEM, 3);
  const disk = parseDiskSection(sections.DISK);
  return {
    load: [num(load[0]), num(load[1]), num(load[2])],
    cpuCount: num(firstNumLine(sections.CPU, 1)[0]),
    memTotal: num(mem[0]),
    memUsed: num(mem[1]),
    memFree: num(mem[2]),
    diskTotal: disk.total,
    diskUsed: disk.used,
    diskPct: disk.pct,
    os: sections.OS || 'unknown',
    hostname: sections.HOSTNAME || session.host,
    uptimeSec: num(sections.UPTIME),
  };
}

app.get('/api/info/:id', async (req, res) => {
  const session = requireSession(req, res);
  if (!session) return;
  try {
    res.json(await sysInfo(session));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ---------------- dashboard status (lightweight poll) ---------------- */

const STATUS_GPU_QUERY =
  'nvidia-smi --query-gpu=index,name,utilization.gpu,memory.used,memory.total,temperature.gpu --format=csv,noheader,nounits';

app.get('/api/status/:id', async (req, res) => {
  const session = sessions.get(req.params.id);
  if (!session || !session.connected || session.userId !== req.user.id) return res.json({ connected: false });
  let gpu = { available: false };
  try {
    const r = await runCommand(session, STATUS_GPU_QUERY, 8000);
    if (r.code === 0 && r.stdout.trim()) {
      const gpus = r.stdout.trim().split('\n').filter(Boolean).map((line) => {
        const p = line.split(',').map((s) => s.trim());
        return { index: num(p[0]), name: p[1] || 'GPU', util: num(p[2]), memUsed: num(p[3]), memTotal: num(p[4]), temp: num(p[5]) };
      });
      gpu = { available: true, count: gpus.length, gpus };
    }
  } catch (e) { /* ignore */ }
  let system = null;
  try { system = await sysInfo(session); } catch (e) { /* ignore */ }
  res.json({ connected: true, gpu, system, ts: Date.now() });
});

/* ---------------- SFTP file manager ---------------- */

app.get('/api/files/:id', async (req, res) => {
  const session = requireSession(req, res);
  if (!session) return;
  if (!session.homeDir) return res.status(400).json({ error: 'Home directory is unknown; file manager is unavailable' });
  // Default to home; accept explicit paths only if they stay inside home.
  const requested = req.query.path || session.homeDir;
  const remotePath = resolveJailedPath(session, requested);
  if (!remotePath) return res.status(403).json({ error: 'Path is outside the home directory and access is denied' });
  try {
    const real = await realPathJailed(session, remotePath);
    if (!real) return res.status(403).json({ error: 'Path cannot be resolved or its symlink points outside the home directory' });
    const sftp = await getSftp(session);
    const entries = await new Promise((resolve, reject) => {
      sftp.readdir(remotePath, (err, list) => (err ? reject(err) : resolve(list)));
    });
    const items = entries
      .map((e) => ({
        name: e.filename,
        path: joinPath(remotePath, e.filename),
        isDirectory: e.attrs.isDirectory(),
        size: e.attrs.size || 0,
        mtime: e.attrs.mtime ? e.attrs.mtime * 1000 : null,
        owner: e.attrs.uid,
      }))
      .filter((i) => i.name !== '.' && i.name !== '..');
    // Hide interrupted atomic-upload leftovers from the UI. They are
    // implementation details and can remain after a remote disconnect.
    const visibleItems = items.filter((i) => !/\.webssh-[0-9a-f]{16}\.tmp$/.test(i.name));
    visibleItems.sort((a, b) => (b.isDirectory - a.isDirectory) || a.name.localeCompare(b.name));
    res.json({ path: remotePath, homeDir: session.homeDir, items: visibleItems });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// Upload: POST /api/files/:id/upload?path=/dir&name=file  (raw binary body)
app.post('/api/files/:id/upload', async (req, res) => {
  const session = requireSession(req, res);
  if (!session) return;
  if (!session.homeDir) return res.status(400).json({ error: '无法确定主目录，文件管理不可用' });
  const dir = req.query.path || session.homeDir;
  const name = req.query.name || 'upload.bin';
  const dest = resolveJailedPath(session, joinPath(dir, name));
  if (!dest) return res.status(403).json({ error: 'Path is outside the home directory and upload is denied' });
  const parent = parentPath(dest);
  try {
    // Resolve the parent before opening the destination. This prevents a
    // symlinked directory inside the home from redirecting an upload outside.
    const parentReal = await realPathJailed(session, parent);
    if (!parentReal) return res.status(403).json({ error: 'Upload directory cannot be resolved or is outside the home directory' });
    const sftp = await getSftp(session);
    // Stream into a unique temporary file so large uploads do not consume
    // server memory and an interrupted upload cannot truncate the old file.
    const temp = `${dest}.webssh-${crypto.randomBytes(8).toString('hex')}.tmp`;
    try {
      const ws = sftp.createWriteStream(temp, { flags: 'wx' });
      await new Promise((resolve, reject) => {
        pipeline(req, ws, (err) => (err ? reject(err) : resolve()));
      });
      await sftpReplace(sftp, temp, dest);
      const size = Number(req.headers['content-length'] || 0);
      res.json({ ok: true, path: dest, size });
    } catch (e) {
      await sftpUnlink(sftp, temp).catch(() => {});
      throw e;
    }
  } catch (e) {
    if (!res.headersSent) res.status(400).json({ error: e.message });
  }
});

app.get('/api/files/:id/download', async (req, res) => {
  const session = requireSession(req, res);
  if (!session) return;
  if (!session.homeDir) return res.status(400).json({ error: '无法确定主目录，文件管理不可用' });
  const remotePath = resolveJailedPath(session, req.query.path);
  if (!remotePath) return res.status(403).json({ error: 'path is required and must remain inside the home directory' });
  try {
    const real = await realPathJailed(session, remotePath);
    if (!real) return res.status(403).json({ error: '路径不可解析或符号链接指向主目录之外' });
    const sftp = await getSftp(session);
    const name = remotePath.split('/').filter(Boolean).pop() || 'file';
    res.setHeader('Content-Disposition', "attachment; filename*=UTF-8''" + encodeURIComponent(name));
    // createReadStream() takes the remote path as its first string argument.
    const rs = sftp.createReadStream(remotePath);
    rs.on('error', (e) => {
      if (!res.headersSent) res.status(404).json({ error: e.message });
      else res.end();
    });
    rs.pipe(res);
  } catch (e) {
    if (!res.headersSent) res.status(500).json({ error: e.message });
  }
});

/* Small text editor: keep reads/writes bounded and inside the user's home. */
const EDIT_MAX_BYTES = 1024 * 1024;

function sftpStat(sftp, remotePath) {
  return new Promise((resolve, reject) => {
    sftp.stat(remotePath, (err, attrs) => (err ? reject(err) : resolve(attrs)));
  });
}

function sftpRename(sftp, from, to) {
  return new Promise((resolve, reject) => {
    sftp.rename(from, to, (err) => (err ? reject(err) : resolve()));
  });
}

function sftpPosixRename(sftp, from, to) {
  return new Promise((resolve, reject) => {
    sftp.ext_openssh_rename(from, to, (err) => (err ? reject(err) : resolve()));
  });
}

async function sftpReplace(sftp, from, to) {
  // OpenSSH's extension has POSIX replacement semantics. Plain SFTP RENAME is
  // allowed to reject an existing destination, which is what some servers
  // report simply as "Failure" when saving an edited file.
  if (sftp._extensions?.['posix-rename@openssh.com'] === '1') {
    return sftpPosixRename(sftp, from, to);
  }
  try {
    return await sftpRename(sftp, from, to);
  } catch (renameError) {
    // For servers without the extension, move the old file aside first. If
    // installing the replacement fails, restore the original before returning
    // the error so an interrupted save does not discard the user's file.
    const backup = `${to}.webssh-${crypto.randomBytes(8).toString('hex')}.bak`;
    try {
      await sftpRename(sftp, to, backup);
      try {
        await sftpRename(sftp, from, to);
      } catch (replaceError) {
        await sftpRename(sftp, backup, to).catch(() => {});
        throw replaceError;
      }
      await sftpUnlink(sftp, backup).catch(() => {});
    } catch (fallbackError) {
      // Keep the original error when the fallback could not even move it.
      throw fallbackError || renameError;
    }
  }
}

function sftpUnlink(sftp, remotePath) {
  return new Promise((resolve, reject) => {
    sftp.unlink(remotePath, (err) => (err ? reject(err) : resolve()));
  });
}

function fileVersion(attrs) {
  return {
    size: Number(attrs?.size || 0),
    mtime: Number(attrs?.mtime || 0),
  };
}

function readRemoteText(sftp, remotePath) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    const rs = sftp.createReadStream(remotePath);
    rs.on('data', (chunk) => {
      total += chunk.length;
      if (total > EDIT_MAX_BYTES) {
        rs.destroy(new Error('File is too large; the editor supports text files up to 1 MiB'));
        return;
      }
      chunks.push(chunk);
    });
    rs.on('error', reject);
    rs.on('end', () => {
      const content = Buffer.concat(chunks);
      if (content.includes(0)) return reject(new Error('Binary content detected; download and edit the file locally'));
      resolve(content.toString('utf8'));
    });
  });
}

app.get('/api/files/:id/edit', async (req, res) => {
  const session = requireSession(req, res);
  if (!session) return;
  if (!session.homeDir) return res.status(400).json({ error: '无法确定主目录，文件管理不可用' });
  const remotePath = resolveJailedPath(session, req.query.path);
  if (!remotePath) return res.status(403).json({ error: 'path 必填且不能超出主目录范围' });
  try {
    const real = await realPathJailed(session, remotePath);
    if (!real) return res.status(403).json({ error: '路径不可解析或符号链接指向主目录之外' });
    const sftp = await getSftp(session);
    const attrs = await sftpStat(sftp, remotePath);
    if (attrs.isDirectory()) return res.status(400).json({ error: 'Directories cannot be opened in the editor' });
    if (Number(attrs.size || 0) > EDIT_MAX_BYTES) {
      return res.status(413).json({ error: 'File is too large; the editor supports text files up to 1 MiB' });
    }
    res.json({ path: remotePath, content: await readRemoteText(sftp, remotePath), version: fileVersion(attrs) });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.post('/api/files/:id/edit', async (req, res) => {
  const session = requireSession(req, res);
  if (!session) return;
  if (!session.homeDir) return res.status(400).json({ error: '无法确定主目录，文件管理不可用' });
  const { path: target, content, version: expectedVersion } = req.body || {};
  if (typeof content !== 'string') return res.status(400).json({ error: 'content must be text' });
  const size = Buffer.byteLength(content, 'utf8');
  if (size > EDIT_MAX_BYTES) return res.status(413).json({ error: 'File is too large; the editor supports text files up to 1 MiB' });
  const remotePath = resolveJailedPath(session, target);
  if (!remotePath) return res.status(403).json({ error: 'path 必填且不能超出主目录范围' });
  try {
    const real = await realPathJailed(session, remotePath);
    if (!real) return res.status(403).json({ error: '路径不可解析或符号链接指向主目录之外' });
    const sftp = await getSftp(session);
    const attrs = await sftpStat(sftp, remotePath);
    if (attrs.isDirectory()) return res.status(400).json({ error: 'A directory cannot be saved as a file' });
    const currentVersion = fileVersion(attrs);
    if (expectedVersion && (
      Number(expectedVersion.size) !== currentVersion.size
      || Number(expectedVersion.mtime) !== currentVersion.mtime
    )) {
      return res.status(409).json({ error: 'The remote file changed. Reopen it before saving.', version: currentVersion });
    }
    // Write to a sibling temp file first. A failed connection or SFTP write
    // must not leave the user's original file truncated or half-written.
    const temp = `${remotePath}.webssh-${crypto.randomBytes(8).toString('hex')}.tmp`;
    try {
      const ws = sftp.createWriteStream(temp, {
        flags: 'wx',
        mode: attrs.mode ? attrs.mode & 0o7777 : 0o644,
      });
      ws.end(Buffer.from(content, 'utf8'));
      await new Promise((resolve, reject) => {
        finished(ws, (err) => (err ? reject(err) : resolve()));
      });
      await sftpReplace(sftp, temp, remotePath);
    } catch (e) {
      await sftpUnlink(sftp, temp).catch(() => {});
      throw e;
    }
    const savedAttrs = await sftpStat(sftp, remotePath);
    res.json({ ok: true, path: remotePath, size, version: fileVersion(savedAttrs) });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.post('/api/files/:id/delete', async (req, res) => {
  const session = requireSession(req, res);
  if (!session) return;
  if (!session.homeDir) return res.status(400).json({ error: '无法确定主目录，文件管理不可用' });
  const { path: target } = req.body || {};
  const jailed = resolveJailedPath(session, target);
  if (!jailed) return res.status(403).json({ error: '路径超出主目录范围，已禁止删除' });
  // Never allow deleting the home dir itself.
  if (jailed === session.homeDir) return res.status(403).json({ error: '不能删除主目录本身' });
  // Resolve symlinks so a link to outside home cannot be deleted.
  try {
    const real = await realPathJailed(session, jailed);
    if (!real) return res.status(403).json({ error: '路径不可解析或符号链接指向主目录之外' });
  } catch (e) { return res.status(400).json({ error: e.message }); }
  // No sudo: file ops are confined to the user's own home.
  const cmd = `rm -rf -- ${shq(jailed)}`;
  try {
    const r = await runCommand(session, cmd, 60000);
    if (r.code !== 0) return res.status(400).json({ error: r.stderr.trim() || '删除失败' });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/files/:id/mkdir', async (req, res) => {
  const session = requireSession(req, res);
  if (!session) return;
  if (!session.homeDir) return res.status(400).json({ error: '无法确定主目录，文件管理不可用' });
  const { path: target } = req.body || {};
  const jailed = resolveJailedPath(session, target);
  if (!jailed) return res.status(403).json({ error: '路径超出主目录范围，已禁止创建' });
  if (jailed === session.homeDir) return res.status(400).json({ error: '主目录已存在' });
  try {
    const parentReal = await realPathJailed(session, parentPath(jailed));
    if (!parentReal) return res.status(403).json({ error: '上级目录不可解析或位于主目录之外' });
    const sftp = await getSftp(session);
    await new Promise((resolve, reject) => sftp.mkdir(jailed, (e) => (e ? reject(e) : resolve())));
    res.json({ ok: true, path: jailed });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// Create an empty file. Unlike the editor save endpoint, this intentionally
// works for a path which does not yet exist, while still resolving its parent
// directory to prevent symlinks from escaping the user's home directory.
app.post('/api/files/:id/new', async (req, res) => {
  const session = requireSession(req, res);
  if (!session) return;
  if (!session.homeDir) return res.status(400).json({ error: '无法确定主目录，文件管理不可用' });
  const { path: target } = req.body || {};
  const jailed = resolveJailedPath(session, target);
  if (!jailed) return res.status(403).json({ error: '路径超出主目录范围，已禁止创建' });
  if (jailed === session.homeDir) return res.status(400).json({ error: '不能用主目录名创建文件' });
  try {
    const parentReal = await realPathJailed(session, parentPath(jailed));
    if (!parentReal) return res.status(403).json({ error: '上级目录不可解析或位于主目录之外' });
    const sftp = await getSftp(session);
    // `wx` creates exclusively, so a typo cannot overwrite an existing file.
    const ws = sftp.createWriteStream(jailed, { flags: 'wx', mode: 0o644 });
    ws.end();
    await new Promise((resolve, reject) => {
      finished(ws, (err) => (err ? reject(err) : resolve()));
    });
    res.json({ ok: true, path: jailed });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.post('/api/files/:id/rename', async (req, res) => {
  const session = requireSession(req, res);
  if (!session) return;
  if (!session.homeDir) return res.status(400).json({ error: '无法确定主目录，文件管理不可用' });
  const { from, to } = req.body || {};
  const fromJ = resolveJailedPath(session, from);
  const toJ = resolveJailedPath(session, to);
  if (!fromJ || !toJ) return res.status(403).json({ error: 'from/to 必填且不能超出主目录范围' });
  // Renaming the home dir itself would break the jail.
  if (fromJ === session.homeDir) return res.status(403).json({ error: '不能重命名主目录本身' });
  try {
    const fromReal = await realPathJailed(session, fromJ);
    const toParentReal = await realPathJailed(session, parentPath(toJ));
    if (!fromReal || !toParentReal) return res.status(403).json({ error: '源文件或目标目录不可解析，已禁止重命名' });
    const sftp = await getSftp(session);
    await new Promise((resolve, reject) => sftp.rename(fromJ, toJ, (e) => (e ? reject(e) : resolve())));
    res.json({ ok: true, path: toJ });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

/* ---------------- terminal (WebSocket + pty) ---------------- */

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws/terminal' });

wss.on('connection', (ws, req) => {
  let channel = null;
  let sessionId = null;
  // Messages that arrive before the shell channel is assigned are queued
  // (and flushed in order) instead of being dropped.
  const pending = [];
  let pendingResize = null;
  const url = new URL(req.url, 'http://localhost');
  const id = url.searchParams.get('sessionId');
  const cols = Math.max(2, parseInt(url.searchParams.get('cols') || 80, 10));
  const rows = Math.max(2, parseInt(url.searchParams.get('rows') || 24, 10));
  const session = sessions.get(id);

  const auth = authFromRequest(req);
  if (!auth || !session || !session.connected || session.userId !== auth.user.id) {
    ws.send(JSON.stringify({ type: 'error', message: '会话不存在或已断开' }));
    ws.close();
    return;
  }
  sessionId = id;
  termSockets.set(ws, id);

  // ssh2 signature: shell(wndopts, opts, cb). pty size/term go in wndopts,
  // env/x11 go in opts. (Putting env in the first arg makes ssh2 treat the
  // whole object as opts and the pty falls back to 80x24.)
  session.client.shell(
    {
      term: 'xterm-256color',
      cols,
      rows,
    },
    {
      env: { TERM: 'xterm-256color', LANG: 'en_US.UTF-8', LC_ALL: 'en_US.UTF-8' },
    },
    (err, ch) => {
      if (err) {
        ws.send(JSON.stringify({ type: 'error', message: '分配终端失败: ' + err.message }));
        ws.close();
        return;
      }
      channel = ch;
      ch.on('data', (data) => {
        if (ws.readyState === WebSocket.OPEN) ws.send(data.toString('utf8'));
      });
      ch.stderr.on('data', (data) => {
        if (ws.readyState === WebSocket.OPEN) ws.send(data.toString('utf8'));
      });
      ch.on('close', () => {
        if (ws.readyState === WebSocket.OPEN) ws.close();
      });
      // Flush anything that arrived before the channel existed.
      if (pendingResize) {
        const c = Math.max(2, parseInt(pendingResize.cols || cols, 10));
        const r = Math.max(2, parseInt(pendingResize.rows || rows, 10));
        channel.setWindow(r, c);
      }
      for (const m of pending) channel.write(m.data);
      pending.length = 0;
      pendingResize = null;
      if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'ready' }));
    }
  );

  ws.on('message', (msg) => {
    let obj;
    try {
      obj = JSON.parse(msg.toString());
    } catch {
      return;
    }
    if (!obj || typeof obj !== 'object') return;
    if (!channel) {
      if (obj.type === 'resize') pendingResize = obj;
      else if (obj.type === 'input' && typeof obj.data === 'string' && pending.length < 4096) pending.push(obj);
      return;
    }
    if (obj.type === 'input' && typeof obj.data === 'string') {
      channel.write(obj.data);
    } else if (obj.type === 'resize') {
      const c = Math.max(2, parseInt(obj.cols || cols, 10));
      const r = Math.max(2, parseInt(obj.rows || rows, 10));
      // ssh2 Channel API: setWindow(rows, cols, height?, width?) — no resize() method.
      channel.setWindow(r, c);
    }
  });

  const cleanup = () => {
    termSockets.delete(ws);
    if (channel) {
      try { channel.close(); } catch (e) { /* ignore */ }
    }
  };
  ws.on('close', cleanup);
  ws.on('error', cleanup);
});

server.listen(PORT, () => {
  console.log(`Web SSH Manager listening on http://0.0.0.0:${PORT}`);
});
