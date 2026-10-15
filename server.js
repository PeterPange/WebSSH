const express = require('express');
const http = require('http');
const path = require('path');
const os = require('os');
const fs = require('fs');
const crypto = require('crypto');
const { pipeline, Transform } = require('stream');
const { parseCookies, allowedOrigin, RateLimiter, createVault, dimensions, expireAuthSessions } = require('./security');
const limits = new RateLimiter();
function securityEvent(event, req, userId = null) {
  if (!limits.take('audit:' + event + ':' + (req.socket.remoteAddress || ''), 20, 60000)) return;
  console.log(JSON.stringify({ type: 'security', event, userId, ip: req.socket.remoteAddress, at: new Date().toISOString() }));
}
process.umask(0o077);
const { WebSocketServer, WebSocket } = require('ws');
const { Client } = require('ssh2');
const Database = require('better-sqlite3');

const PORT = process.env.PORT || 9998;
const AUTH_COOKIE = 'webssh_auth';
const AUTH_TTL_MS = 8 * 60 * 60 * 1000;
// Used only when creating the first administrator in a fresh data directory.
// Existing accounts are never overwritten by later environment changes.
const ADMIN_USERNAME = process.env.WEBSSH_ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.WEBSSH_ADMIN_PASSWORD || crypto.randomBytes(24).toString('base64url');
// Every user receives this initial SSH password for every shared server.
// Users can replace their own connection information afterwards.
const DEFAULT_SSH_PASSWORD = process.env.WEBSSH_DEFAULT_SSH_PASSWORD || '';
const UPLOAD_MAX_BYTES = Math.max(1, Number(process.env.WEBSSH_UPLOAD_MAX_MB) || 2048) * 1024 * 1024;

const app = express();
app.disable('x-powered-by');
app.set('query parser', 'simple');
// Proxy IP headers are ignored unless the administrator explicitly trusts a proxy.
if (process.env.WEBSSH_TRUST_PROXY) app.set('trust proxy', process.env.WEBSSH_TRUST_PROXY.split(',').map(s => s.trim()));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
  if (process.env.WEBSSH_SECURE_COOKIE === '1') res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  if (req.path.startsWith('/api/')) {
    res.setHeader('Cache-Control', 'no-store');
    if (!allowedOrigin(req)) { securityEvent('cross_origin_denied', req); return res.status(403).json({ error: 'Cross-origin request denied' }); }
    if (!limits.take('api:' + req.ip, 3000, 60000)) return res.status(429).json({ error: 'Too many requests' });
    const upload = /^\/api\/files\/[^/]+\/upload$/.test(req.path);
    if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method) && !upload && (req.headers['transfer-encoding'] || Number(req.headers['content-length']) > 0) && !req.is('application/json')) {
      return res.status(415).json({ error: 'JSON content type is required' });
    }
  }
  next();
});
// Skip JSON body parsing for upload routes (they carry raw binary bodies).
app.use((req, res, next) => {
  if (req.method === 'POST' && /^\/api\/files\/[^/]+\/upload$/.test(req.path)) return next();
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
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { mode: 0o700, recursive: true });
fs.chmodSync(DATA_DIR, 0o700);
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

const dummyPasswordHash = hashPassword(crypto.randomBytes(32).toString('hex'));
let passwordChecks = 0;
async function verifyPasswordAsync(password, encoded) {
  if (passwordChecks >= 8) return false;
  passwordChecks++;
  try {
    const [, saltText, digestText] = String(encoded).split('$');
    const expected = Buffer.from(digestText, 'base64');
    if (expected.length !== 64) return false;
    const actual = await new Promise((resolve, reject) => crypto.scrypt(password, Buffer.from(saltText, 'base64'), 64, { N: 16384, r: 8, p: 1 }, (err, result) => err ? reject(err) : resolve(result)));
    return crypto.timingSafeEqual(actual, expected);
  } catch { return false; }
  finally { passwordChecks--; }
}

const stmtGetUserByName = db.prepare('SELECT id, username, password_hash, is_admin, created_at FROM users WHERE username = ? COLLATE NOCASE');
const stmtGetUserById = db.prepare('SELECT id, username, password_hash, is_admin, created_at FROM users WHERE id = ?');
const stmtInsertUser = db.prepare('INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?)');
let admin = stmtGetUserByName.get(ADMIN_USERNAME);
if (!admin) {
  if (ADMIN_PASSWORD.length < 12 || ADMIN_PASSWORD.length > 128) throw new Error('Initial administrator password must be 12-128 characters');
  stmtInsertUser.run(ADMIN_USERNAME, hashPassword(ADMIN_PASSWORD), 1, Date.now());
  admin = stmtGetUserByName.get(ADMIN_USERNAME);
}
if (!process.env.WEBSSH_ADMIN_PASSWORD && db.prepare('SELECT COUNT(*) n FROM users').get().n === 1 && verifyPassword(ADMIN_PASSWORD, admin.password_hash)) {
  fs.writeFileSync(path.join(DATA_DIR, 'initial-admin-password'), ADMIN_PASSWORD + '\n', { mode: 0o600, flag: 'wx' });
  console.log('Initial admin password saved in the private data directory: initial-admin-password');
}
// Databases created before per-user credentials stored the SSH username and
// credentials on the server row itself. Move them into server_creds (owned by
// the row's user, or the seeded admin for unowned rows) and drop the legacy
// columns so the servers table holds only the shared server definition.
const serverColumns = db.prepare('PRAGMA table_info(servers)').all();
const legacyServerColumns = new Set(serverColumns.map((c) => c.name));
// A prior migration can be interrupted after it has copied credentials and
// dropped some (but not all) legacy columns. Only read username/creds when
// both still exist, then remove every remaining legacy column independently.
if (legacyServerColumns.has('username') && legacyServerColumns.has('creds')) {
  const insCreds = db.prepare(`
    INSERT OR IGNORE INTO server_creds (server_uid, user_id, username, creds, updated_at)
    VALUES (?, ?, ?, ?, ?)
  `);
  const migrate = db.transaction(() => {
    const ownerExpr = legacyServerColumns.has('user_id') ? 'user_id' : String(admin.id);
    for (const r of db.prepare(`SELECT uid, ${ownerExpr} AS user_id, username, creds FROM servers`).all()) {
      insCreds.run(r.uid, r.user_id ?? admin.id, r.username, r.creds || '{}', Date.now());
    }
  });
  migrate();
}
for (const col of ['user_id', 'username', 'creds']) {
  if (!legacyServerColumns.has(col)) continue;
  try { db.exec(`ALTER TABLE servers DROP COLUMN ${col}`); } catch (e) { /* older SQLite: keep column */ }
}

const authSessions = new Map();
const loginAttempts = new Map();

function authFromRequest(req) {
  const token = parseCookies(req.headers.cookie)[AUTH_COOKIE];
  if (!token) return null;
  const entry = authSessions.get(token);
  if (!entry || entry.expiresAt <= Date.now()) {
    if (entry) {
      authSessions.delete(token);
      if (entry.expiresAt <= Date.now()) closeAuthSshSessions(token);
    }
    return null;
  }
  const user = stmtGetUserById.get(entry.userId);
  if (!user) {
    authSessions.delete(token);
    return null;
  }
  return { token, user, expiresAt: entry.expiresAt };
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
  if (!['GET', 'HEAD'].includes(req.method) && !limits.take('write:' + auth.user.id, 120, 60000)) return res.status(429).json({ error: 'Too many write requests' });
  next();
}

app.use('/api', authRequired);

app.post('/api/auth/login', async (req, res) => {
  const username = typeof req.body?.username === 'string' ? req.body.username.trim() : '';
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  if (!username || username.length > 32 || !password || password.length > 128) return res.status(401).json({ error: 'Invalid username or password' });
  if (!limits.take('login-global', 240, 60000)) return res.status(429).json({ error: 'Login service busy; retry later' });
  if (!limits.take('login-ip:' + req.ip, 30, 60000) || !limits.take('login-user:' + username.toLowerCase(), 20, 60000)) {
    res.setHeader('Retry-After', '60');
    return res.status(429).json({ error: 'Too many login attempts. Try again later.' });
  }
  const attemptKey = `${req.ip}|${username.toLowerCase()}`;
  const attempt = loginAttempts.get(attemptKey);
  if (attempt && attempt.blockedUntil > Date.now()) {
    res.setHeader('Retry-After', '60');
    return res.status(429).json({ error: 'Too many failed sign-in attempts. Try again later.' });
  }
  if (loginAttempts.size >= 10000 && !loginAttempts.has(attemptKey)) return res.status(429).json({ error: 'Too many login attempts' });
  const user = username ? stmtGetUserByName.get(username) : null;
  if (passwordChecks >= 8) return res.status(429).json({ error: 'Login service busy; retry later' });
  const valid = await verifyPasswordAsync(password, user?.password_hash || dummyPasswordHash);
  if (!user || !valid) {
    const next = attempt && attempt.expiresAt > Date.now()
      ? { count: attempt.count + 1, expiresAt: attempt.expiresAt, blockedUntil: attempt.blockedUntil }
      : { count: 1, expiresAt: Date.now() + 10 * 60 * 1000, blockedUntil: 0 };
    if (next.count >= 5) next.blockedUntil = Date.now() + 60 * 1000;
    loginAttempts.set(attemptKey, next);
    securityEvent('login_failed', req);
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  loginAttempts.delete(attemptKey);
  securityEvent('login_success', req, user.id);
  const previousToken = parseCookies(req.headers.cookie)[AUTH_COOKIE];
  if (previousToken && authSessions.has(previousToken)) { authSessions.delete(previousToken); closeAuthSshSessions(previousToken); }
  if (authSessions.size >= 4096 || [...authSessions.values()].filter(s => s.userId === user.id).length >= 16) return res.status(429).json({ error: 'Too many active logins' });
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

app.post('/api/auth/password', async (req, res) => {
  if (!limits.take('password:' + req.user.id, 5, 60000)) return res.status(429).json({ error: 'Too many password attempts' });
  const currentPassword = typeof req.body?.currentPassword === 'string' ? req.body.currentPassword : '';
  const newPassword = typeof req.body?.newPassword === 'string' ? req.body.newPassword : '';
  if (currentPassword.length > 128 || !await verifyPasswordAsync(currentPassword, req.user.password_hash)) {
    return res.status(401).json({ error: 'Current password is incorrect' });
  }
  const err = validateNewUser(req.user.username, newPassword);
  if (err) return res.status(400).json({ error: err });
  stmtSetPassword.run(hashPassword(newPassword), req.user.id);
  invalidateUserSessions(req.user.id);
  clearAuthCookie(res);
  res.json({ ok: true });
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
  if (password.length < 12 || password.length > 128) {
    return 'Password must be 12-128 characters';
  }
  return null;
}

function createUser(username, password) {
  const result = stmtInsertUser.run(username, hashPassword(password), 0, Date.now());
  const user = { id: result.lastInsertRowid, username, isAdmin: false };
  ensureDefaultCredentialsForUser(user);
  return user;
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

function closeAuthSshSessions(token) {
  for (const session of [...sessions.values()]) {
    if (session.authToken !== token) continue;
    sessions.delete(session.id);
    session.connected = false;
    for (const [ws, sid] of termSockets) if (sid === session.id) ws.terminate();
    session.client.end();
  }
}
setInterval(() => {
  const now = Date.now();
  expireAuthSessions(authSessions, closeAuthSshSessions, now);
  for (const [key, entry] of loginAttempts) if (entry.expiresAt <= now && entry.blockedUntil <= now) loginAttempts.delete(key);
}, 15000).unref();

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
    if (!!target.is_admin !== b.isAdmin) invalidateUserSessions(target.id);
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
const stmtInsertDefaultCred = db.prepare(`
  INSERT OR IGNORE INTO server_creds (server_uid, user_id, username, creds, updated_at)
  VALUES (?, ?, ?, ?, ?)
`);
const stmtAllServerUids = db.prepare('SELECT uid FROM servers');

function defaultSshCreds() {
  return vault.seal({ password: DEFAULT_SSH_PASSWORD, privateKey: null, keyRef: null, passphrase: null, sudoPassword: null });
}

function ensureDefaultCredentialsForUser(user) {
  if (!DEFAULT_SSH_PASSWORD) return;
  const now = Date.now();
  const creds = defaultSshCreds();
  const seed = db.transaction(() => {
    for (const server of stmtAllServerUids.all()) {
      stmtInsertDefaultCred.run(server.uid, user.id, user.username, creds, now);
    }
  });
  seed();
}

function ensureDefaultCredentialsForServer(serverUid) {
  if (!DEFAULT_SSH_PASSWORD) return;
  const now = Date.now();
  const creds = defaultSshCreds();
  const seed = db.transaction(() => {
    for (const user of stmtListUsers.all()) {
      stmtInsertDefaultCred.run(serverUid, user.id, user.username, creds, now);
    }
  });
  seed();
}

db.exec('PRAGMA secure_delete=ON');
const vault = createVault(DATA_DIR, !!db.prepare("SELECT 1 FROM server_creds WHERE creds LIKE 'enc:v1:%' LIMIT 1").get());
db.transaction(() => {
  const update = db.prepare('UPDATE server_creds SET creds = ? WHERE server_uid = ? AND user_id = ?');
  for (const row of db.prepare('SELECT server_uid, user_id, creds FROM server_creds').all()) {
    if (row.creds.startsWith('enc:v1:')) vault.open(row.creds); // fail closed on a wrong key
    else update.run(vault.seal(JSON.parse(row.creds || '{}')), row.server_uid, row.user_id);
  }
})();
db.exec('PRAGMA secure_delete=ON');

for (const user of stmtListUsers.all()) ensureDefaultCredentialsForUser(user);

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
  ensureDefaultCredentialsForUser(req.user);
  const servers = stmtGetAllServers.all().map((r) => {
    const s = rowToServer(r);
    const cred = stmtGetCred.get(r.uid, req.user.id);
    s.mine = cred ? { username: cred.username, creds: vault.open(cred.creds) } : null;
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
  ensureDefaultCredentialsForServer(String(b.uid));
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
  if (!username || username.length > 128) return res.status(400).json({ error: 'Invalid SSH username' });
  const creds = b.creds && typeof b.creds === 'object' ? b.creds : {};
  for (const k of Object.keys(creds)) {
    if (creds[k] != null && typeof creds[k] !== 'string') delete creds[k];
  }
  if (creds.keyRef && !req.user.is_admin) return res.status(403).json({ error: 'Local SSH keys are restricted to administrators' });
  if (!creds.password && !creds.privateKey && !creds.keyRef) {
    return res.status(400).json({ error: 'A password or private key is required' });
  }
  stmtUpsertCred.run({ server_uid: server.uid, user_id: req.user.id, username, creds: vault.seal(creds), now: Date.now() });
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

function validRemoteName(name) { return typeof name === 'string' && name !== '.' && name !== '..' && !/[\/\0]/.test(name); }

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
  if (typeof remotePath !== 'string' || !remotePath || remotePath.includes('\0')) return null;
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
  if (home !== '/' && abs !== home && !abs.startsWith(home + '/')) return null;
  return abs;
}

/**
 * Resolve symlinks on the remote so a link inside home cannot be used to
 * reach files outside it. Returns the canonical path, or null if it cannot be
 * resolved or escapes home.
 */
async function realPathJailed(session, jailedPath) {
  const sftp = await getSftp(session);
  const real = await new Promise((resolve, reject) => {
    sftp.realpath(jailedPath, (err, result) => err ? reject(err) : resolve(result));
  });
  return resolveJailedPath(session, real) === real ? real : null;
}

/**
 * Resolve the private key to use for a connection request.
 * - body.privateKey: raw PEM content (from the UI)
 * - body.keyRef:     a key file name under ~/.ssh (never leaves the server)
 */
function loadKeyRef(name) {
  if (typeof name !== 'string' || !/^[A-Za-z0-9._-]+$/.test(name)) return null;
  const dir = path.join(os.homedir(), '.ssh');
  if (name === '.' || name === '..') return null;
  const full = path.resolve(dir, name);
  if (full !== path.join(dir, name)) return null;
  try {
    const real = fs.realpathSync(full);
    if (!real.startsWith(fs.realpathSync(dir) + path.sep)) return null;
    const st = fs.statSync(real);
    if (!st.isFile() || st.size > 65536) return null;
    return fs.readFileSync(full, 'utf8');
  } catch (e) {
    return null;
  }
}

db.exec('CREATE TABLE IF NOT EXISTS ssh_host_keys (host TEXT NOT NULL, port INTEGER NOT NULL, fingerprint TEXT NOT NULL, first_seen INTEGER NOT NULL, PRIMARY KEY(host, port))');
const getHostKey = db.prepare('SELECT fingerprint FROM ssh_host_keys WHERE host = ? AND port = ?');
const insertHostKey = db.prepare('INSERT OR IGNORE INTO ssh_host_keys VALUES (?, ?, ?, ?)');
function makeConfig(body) {
  const config = {
    host: String(body.host),
    port: parseInt(body.port || 22, 10),
    username: String(body.username),
    readyTimeout: 20000,
    hostHash: 'sha256',
    hostVerifier: (fingerprint) => {
      const host = String(body.host).toLowerCase();
      const port = Number(body.port || 22);
      const known = getHostKey.get(host, port);
      if (known) return known.fingerprint === fingerprint;
      // TOFU: the initial connection must be made over a trusted network.
      insertHostKey.run(host, port, fingerprint, Date.now());
      return getHostKey.get(host, port).fingerprint === fingerprint;
    },
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

function runCommand(session, command, timeoutMs = 15000, input = null) {
  let charged = false;
  return new Promise((resolve, reject) => {
    if (!session || !session.connected) return reject(new Error('Not connected'));
    if ((session.execCount || 0) >= 12) return reject(new Error('Too many simultaneous commands'));
    session.execCount = (session.execCount || 0) + 1;
    charged = true;
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
      if (done) { ch.close(); return; }
      channel = ch;
      let outputBytes = 0;
      const accept = (data) => {
        outputBytes += data.length;
        if (outputBytes <= 8 * 1024 * 1024) return true;
        if (!done) { done = true; clearTimeout(timer); ch.close(); reject(new Error('Command output limit exceeded')); }
        return false;
      };
      let stdout = '';
      let stderr = '';
      ch.on('data', (d) => { if (accept(d)) stdout += d; });
      ch.stderr.on('data', (d) => { if (accept(d)) stderr += d; });
      ch.on('close', (code) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        resolve({ stdout, stderr, code: code ?? 0 });
      });
      if (input !== null) ch.end(input);
      ch.on('error', (e) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        reject(e);
      });
    });
  }).finally(() => { if (charged) session.execCount--; });
}

async function getSftp(session) {
  // Some SSH servers permit only one SFTP subsystem channel per connection.
  // Reuse it across file-manager requests instead of opening a new channel for
  // every list/read/write operation.
  if (session.sftp) return session.sftp;
  if (!session.sftpPromise) {
    session.sftpPromise = new Promise((resolve, reject) => {
      let timedOut = false;
      const timer = setTimeout(() => { timedOut = true; session.sftpPromise = null; reject(new Error('SFTP setup timed out')); }, 10000);
      session.client.sftp((err, sftp) => {
        clearTimeout(timer);
        if (timedOut) { if (sftp) sftp.end(); return; }
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
  const session = sessions.get(req.params.id || req.body?.sessionId || req.query.sessionId);
  if (!session || !session.connected || !req.user || session.userId !== req.user.id) {
    res.status(404).json({ error: 'Session does not exist or has disconnected' });
    return null;
  }
  return session;
}

/* ---------------- SSH connection ---------------- */

app.post('/api/connect', (req, res) => {
  const body = req.body || {};
  const port = Number(body.port || 22);
  if (typeof body.host !== 'string' || !/^[A-Za-z0-9_.:-]{1,253}$/.test(body.host) || !Number.isInteger(port) || port < 1 || port > 65535 || typeof body.username !== 'string' || body.username.length > 128) {
    return res.status(400).json({ error: 'Invalid SSH host, port or username' });
  }
  if (body.keyRef && !req.user.is_admin) return res.status(403).json({ error: 'Local SSH keys are restricted to administrators' });
  if (!req.user.is_admin && !stmtGetAllServers.all().some((s) => s.host.toLowerCase() === body.host.toLowerCase() && s.port === port)) {
    return res.status(403).json({ error: 'Only administrator-registered SSH destinations are permitted' });
  }
  if (!limits.take('connect:' + req.user.id, 30, 60000)) return res.status(429).json({ error: 'Too many SSH connection attempts' });
  if (sessions.size >= 256 || [...sessions.values()].filter((s) => s.userId === req.user.id).length >= 32) return res.status(429).json({ error: 'SSH connection limit reached' });
  for (const field of ['password', 'privateKey', 'passphrase', 'sudoPassword', 'keyRef']) {
    if (body[field] != null && (typeof body[field] !== 'string' || body[field].length > 65536)) return res.status(400).json({ error: 'Invalid SSH credentials' });
  }
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
    authToken: req.auth.token,
    expiresAt: req.auth.expiresAt,
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
  sessions.set(id, session); // include pending handshakes in the connection limit
  res.on('close', () => {
    if (!res.writableEnded) { sessions.delete(id); client.end(); }
  });
  client.on('ready', async () => {
    if (!authSessions.has(session.authToken) || session.expiresAt <= Date.now() || !sessions.has(id)) { client.end(); return; }
    session.connected = true;
    sessions.set(id, session);
    try {
      const sftp = await getSftp(session);
      const home = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('SFTP home lookup timed out')), 8000);
        sftp.realpath('.', (err, result) => { clearTimeout(timer); err ? reject(err) : resolve(result); });
      });
      if (home.startsWith('/')) session.homeDir = path.posix.normalize(home);
    } catch (e) { session.fileError = 'SFTP unavailable: ' + e.message; }
    if (res.headersSent || res.destroyed || !session.connected) return;
    res.json({ ok: true, sessionId: id, host: session.host, port: session.port, username: session.username, homeDir: session.homeDir, fileError: session.fileError });
  });
  client.on('error', (err) => {
    session.connected = false;
    sessions.delete(id);
    if (!res.headersSent) {
      // This is an upstream SSH failure, not a Web SSH Manager login failure.
      // Keeping it distinct prevents the browser from discarding a valid web
      // session when a saved server has stale credentials.
      res.status(502).json({ error: 'SSH connection failed: ' + err.message });
    }
  });
  client.on('close', () => {
    session.connected = false;
    sessions.delete(id);
    if (!res.headersSent && !res.destroyed) res.status(502).json({ error: 'SSH connection closed before ready' });
    for (const [ws, sid] of termSockets) {
      if (sid === id && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'error', message: 'SSH connection closed' }));
        ws.close();
      }
    }
  });
  try { client.connect(makeConfig(body)); } catch (e) {
    sessions.delete(id);
    client.end();
    if (!res.headersSent) res.status(400).json({ error: 'Invalid SSH connection configuration' });
  }
});

// Local ~/.ssh/config content (for the "import from ssh config" feature).
app.get('/api/ssh-config', (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    const content = fs.readFileSync(path.join(os.homedir(), '.ssh', 'config'), 'utf8');
    res.json({ content });
  } catch (e) {
    res.status(404).json({ error: 'Local ~/.ssh/config does not exist' });
  }
});

// List private key file names available under ~/.ssh (no content).
app.get('/api/ssh-keys', (req, res) => {
  if (!requireAdmin(req, res)) return;
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
    cmd = `sudo -S -p '' -- sh -c ${shq(command)}`;
  }
  try {
    const r = await runCommand(session, cmd, Math.min(Math.max(Number(timeout) || 30000, 1000), 300000), sudo ? session.sudoPassword + '\n' : null);
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
    const pids = [...new Set(processes.map((p) => p.pid).filter((pid) => /^\d{1,10}$/.test(pid)))].join(',');
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
  'echo ===MEM===; free -m 2>/dev/null | awk \'/^Mem:/{print $2" "$3" "$4}\'; awk \'/^MemTotal:/{t=int($2/1024)} /^MemAvailable:/{a=int($2/1024)} END{if(t>0) printf "%d %d %d\\n", t, t-a, a}\' /proc/meminfo 2>/dev/null',
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

/* Administrator-only host visibility. Reuse the administrator's own SSH connection. */
const { collectMonitor } = require('./monitoring');
app.get('/api/admin/monitor/:id', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  const session = requireSession(req, res);
  if (!session) return;
  try {
    if (!session.monitorPromise || (!session.monitorPending && Date.now() - session.monitorAt > 5000)) {
      session.monitorPending = true;
      session.monitorPromise = collectMonitor(session, runCommand).then((data) => {
        session.monitorAt = Date.now();
        return data;
      }).catch((error) => {
        session.monitorPromise = null;
        throw error;
      }).finally(() => { session.monitorPending = false; });
    }
    const data = await session.monitorPromise;
    const webSessions = [...sessions.values()]
      .filter((s) => s.connected && s.host === session.host && s.port === session.port)
      .map((s) => ({ username: s.username, webUser: stmtGetUserById.get(s.userId)?.username || 'unknown', createdAt: s.createdAt }));
    res.json({ ...data, webSessions });
  } catch (e) { res.status(502).json({ error: e.message }); }
});

/* On-demand root-filesystem ownership scan; isolated to the admin's SSH session. */
const { collectDiskUsage } = require('./disk-usage');
let diskScansRunning = 0;
const diskScanHosts = new Set();
app.get('/api/admin/disk-usage/:id', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  const session = requireSession(req, res);
  if (!session) return;
  const host = JSON.stringify([session.host, session.port]);
  if (!session.diskUsagePromise || (!session.diskUsagePending && Date.now() - session.diskUsageAt > 300000)) {
    if (diskScansRunning >= 2 || diskScanHosts.has(host)) return res.status(429).json({ error: '磁盘扫描正在进行，请稍后重试（最多同时扫描两台服务器）。' });
    diskScansRunning++;
    diskScanHosts.add(host);
    session.diskUsagePending = true;
    session.diskUsagePromise = collectDiskUsage(session, runCommand).then((data) => {
      session.diskUsageAt = Date.now();
      return data;
    }).catch((error) => {
      session.diskUsagePromise = null;
      throw error;
    }).finally(() => {
      diskScansRunning--;
      diskScanHosts.delete(host);
      session.diskUsagePending = false;
    });
  }
  try { res.json(await session.diskUsagePromise); }
  catch (e) { res.status(502).json({ error: e.message }); }
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
const fileRequests = new Map();
app.use('/api/files', (req, res, next) => {
  const user = req.user.id;
  const count = fileRequests.get(user) || 0;
  if (count >= 8) return res.status(429).json({ error: 'Too many simultaneous file operations' });
  fileRequests.set(user, count + 1);
  let released = false;
  const release = () => { if (!released) { released = true; const n = (fileRequests.get(user) || 1) - 1; if (n) fileRequests.set(user, n); else fileRequests.delete(user); } };
  res.once('finish', release); res.once('close', release);
  next();
});

app.get('/api/files/:id', async (req, res) => {
  const session = requireSession(req, res);
  if (!session) return;
  if (!session.homeDir) return res.status(400).json({ error: session.fileError || 'Home directory is unknown; file manager is unavailable' });
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
    for (const entry of entries) {
      if (!validRemoteName(entry.filename)) continue;
      if (entry.attrs.isSymbolicLink()) {
        try {
          const target = await realPathJailed(session, joinPath(remotePath, entry.filename));
          if (target) entry.attrs = await sftpStat(sftp, target);
        } catch (e) { /* Keep broken or inaccessible links visible as files. */ }
      }
    }
    const items = entries
      .map((e) => ({
        name: e.filename,
        path: joinPath(remotePath, e.filename),
        isDirectory: e.attrs.isDirectory(),
        size: e.attrs.size || 0,
        mtime: e.attrs.mtime ? e.attrs.mtime * 1000 : null,
        owner: e.attrs.uid,
      }))
      .filter((i) => validRemoteName(i.name));
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
  if (Number(req.headers['content-length']) > UPLOAD_MAX_BYTES) return res.status(413).json({ error: 'Upload size limit exceeded' });
  const dir = req.query.path || session.homeDir;
  const name = req.query.name || 'upload.bin';
  if (!validRemoteName(name)) return res.status(400).json({ error: 'Invalid upload filename' });
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
      let bytes = 0;
      const sizeLimit = new Transform({ transform(chunk, encoding, callback) {
        bytes += chunk.length;
        callback(bytes > UPLOAD_MAX_BYTES ? new Error('Upload size limit exceeded') : null, chunk);
      }});
      const ws = sftp.createWriteStream(temp, { flags: 'wx', mode: 0o600 });
      const closed = new Promise((resolve, reject) => { ws.once('close', resolve); ws.once('error', reject); });
      await Promise.all([closed, new Promise((resolve, reject) => {
        pipeline(req, sizeLimit, ws, (err) => (err ? reject(err) : resolve()));
      })]);
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
    res.on('close', () => rs.destroy());
    res.setHeader('Content-Type', 'application/octet-stream');
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

// Wait for the remote CLOSE acknowledgement: stream finish can precede OPEN
// for empty files, or CLOSE/flush for edited files.
async function writeRemoteFile(sftp, target, buffer, mode) {
  const handle = await new Promise((resolve, reject) => sftp.open(target, 'wx', mode, (err, h) => err ? reject(err) : resolve(h)));
  try {
    if (buffer.length) await new Promise((resolve, reject) => sftp.write(handle, buffer, 0, buffer.length, 0, (err) => err ? reject(err) : resolve()));
  } finally {
    await new Promise((resolve, reject) => sftp.close(handle, (err) => err ? reject(err) : resolve()));
  }
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
  let remotePath = resolveJailedPath(session, target);
  if (!remotePath) return res.status(403).json({ error: 'path 必填且不能超出主目录范围' });
  try {
    const real = await realPathJailed(session, remotePath);
    if (!real) return res.status(403).json({ error: '路径不可解析或符号链接指向主目录之外' });
    remotePath = real;
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
      await writeRemoteFile(sftp, temp, Buffer.from(content, 'utf8'), attrs.mode ? attrs.mode & 0o7777 : 0o644);
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
  try {
    const sftp = await getSftp(session);
    const remove = async (target) => {
      const attrs = await new Promise((resolve, reject) => sftp.lstat(target, (e, a) => e ? reject(e) : resolve(a)));
      if (attrs.isDirectory()) {
        const entries = await new Promise((resolve, reject) => sftp.readdir(target, (e, a) => e ? reject(e) : resolve(a)));
        for (const entry of entries) {
          if (entry.filename === '.' || entry.filename === '..') continue;
          if (!validRemoteName(entry.filename)) throw new Error('Invalid remote directory entry');
          await remove(joinPath(target, entry.filename));
        }
        await new Promise((resolve, reject) => sftp.rmdir(target, (e) => e ? reject(e) : resolve()));
      } else await sftpUnlink(sftp, target);
    };
    await remove(jailed);
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
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
    await writeRemoteFile(sftp, jailed, Buffer.alloc(0), 0o644);
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

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  res.status(err.status >= 400 && err.status < 500 ? err.status : 500).json({ error: err.status === 413 ? 'Request body too large' : 'Invalid request or internal error' });
});
const server = http.createServer({ maxHeaderSize: 16384 }, app);
server.headersTimeout = 15000;
server.requestTimeout = 300000;
server.maxRequestsPerSocket = 1000;
const wss = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024, perMessageDeflate: false });
server.on('upgrade', (req, socket, head) => {
  const deny = (code) => { socket.write(`HTTP/1.1 ${code} Rejected\r\nConnection: close\r\n\r\n`); socket.destroy(); };
  if (!allowedOrigin(req)) return deny(403);
  if (!authFromRequest(req)) return deny(401);
  try { if (new URL(req.url, 'http://localhost').pathname !== '/ws/terminal') return deny(404); } catch { return deny(400); }
  if (!limits.take('ws:' + req.socket.remoteAddress, 120, 60000)) return deny(429);
  wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
});

wss.on('connection', (ws, req) => {
  let channel = null;
  let sessionId = null;
  // Messages that arrive before the shell channel is assigned are queued
  // (and flushed in order) instead of being dropped.
  const pending = [];
  let pendingResize = null;
  let pendingBytes = 0;
  let inputBytes = 0, inputWindow = Date.now();
  const url = new URL(req.url, 'http://localhost');
  const id = url.searchParams.get('sessionId');
  const cols = dimensions(url.searchParams.get('cols'), 80);
  const rows = dimensions(url.searchParams.get('rows'), 24);
  const session = sessions.get(id);

  const auth = authFromRequest(req);
  if (!auth || !session || !session.connected || session.userId !== auth.user.id) {
    ws.send(JSON.stringify({ type: 'error', message: '会话不存在或已断开' }));
    ws.close();
    return;
  }
  if ([...termSockets.values()].filter((sid) => sid === id).length >= 12 || termSockets.size >= 512) {
    ws.close(1008, 'Terminal limit reached'); return;
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
      if (ws.readyState !== WebSocket.OPEN) {
        if (ch) ch.close();
        return;
      }
      if (err) {
        ws.send(JSON.stringify({ type: 'error', message: '分配终端失败: ' + err.message }));
        ws.close();
        return;
      }
      channel = ch;
      const sendOutput = (data) => {
        if (ws.bufferedAmount > 1024 * 1024) { ws.terminate(); ch.close(); return; }
        if (ws.readyState === WebSocket.OPEN) ws.send(data.toString('utf8'));
      };
      ch.on('data', sendOutput);
      ch.stderr.on('data', sendOutput);
      ch.on('error', () => { if (ws.readyState === WebSocket.OPEN) ws.close(1011, 'SSH channel error'); });
      ch.on('close', () => {
        if (ws.readyState === WebSocket.OPEN) ws.close();
      });
      // Flush anything that arrived before the channel existed.
      if (pendingResize) {
        const c = dimensions(pendingResize.cols, cols);
        const r = dimensions(pendingResize.rows, rows);
        channel.setWindow(r, c);
      }
      for (const m of pending) channel.write(m.data);
      pending.length = 0;
      pendingResize = null;
      if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'ready' }));
    }
  );

  ws.on('message', (msg) => {
    if (!authSessions.has(auth.token) || auth.expiresAt <= Date.now()) { ws.close(1008, 'Login expired'); return; }
    if (Date.now() - inputWindow > 1000) { inputWindow = Date.now(); inputBytes = 0; }
    inputBytes += msg.length;
    if (inputBytes > 1024 * 1024) { ws.close(1008, 'Terminal input rate exceeded'); return; }
    let obj;
    try {
      obj = JSON.parse(msg.toString());
    } catch {
      return;
    }
    if (!obj || typeof obj !== 'object') return;
    if (!channel) {
      if (obj.type === 'resize') pendingResize = obj;
      else if (obj.type === 'input' && typeof obj.data === 'string') {
        pendingBytes += Buffer.byteLength(obj.data);
        if (pendingBytes > 65536) { ws.close(1008, 'Terminal pending input limit'); return; }
        pending.push(obj);
      }
      return;
    }
    if (obj.type === 'input' && typeof obj.data === 'string') {
      if (channel.writableLength > 1024 * 1024) { ws.close(1008, 'SSH input backlog'); return; }
      channel.write(obj.data);
    } else if (obj.type === 'resize') {
      const c = dimensions(obj.cols, cols);
      const r = dimensions(obj.rows, rows);
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

server.listen(PORT, process.env.WEBSSH_BIND_HOST || '0.0.0.0', () => {
  console.log(`Web SSH Manager listening on http://0.0.0.0:${server.address().port}`);
});
