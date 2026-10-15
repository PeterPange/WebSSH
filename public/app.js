'use strict';

const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];

function addPasswordVisibilityButtons() {
  $$('input[type="password"]').forEach((input) => {
    if (input.dataset.visibilityReady) return;
    input.dataset.visibilityReady = '1';
    const wrap = document.createElement('span');
    wrap.className = 'password-input';
    input.parentNode.insertBefore(wrap, input);
    wrap.appendChild(input);
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'password-toggle';
    button.textContent = 'Show';
    button.setAttribute('aria-label', 'Show password');
    button.onclick = () => {
      const shown = input.type === 'text';
      input.type = shown ? 'password' : 'text';
      button.textContent = shown ? 'Show' : 'Hide';
      button.setAttribute('aria-label', shown ? 'Show password' : 'Hide password');
    };
    wrap.appendChild(button);
  });
}

addPasswordVisibilityButtons();

function updateAuthClock() {
  const now = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  const text = `Current time: ${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
  for (const id of ['auth-clock', 'dashboard-clock']) {
    const clock = $('#' + id);
    if (clock) clock.textContent = text;
  }
}

updateAuthClock();
setInterval(updateAuthClock, 1000);

const LS_KEY = 'webssh.servers.v2';
const GPU_COLORS = ['#58a6ff', '#3fb950', '#d29922', '#f85149', '#bc8cff', '#39c5cf', '#ff7b72', '#7ee787'];
// Prevent the initial /api/auth/me request from overwriting a login that
// started while the page was still checking the existing session.
let authFlow = 0;

const state = {
  servers: [],         // {uid, host, port, label, algorithms, mine, sessionId, connecting}
  view: 'dashboard',   // 'dashboard' | 'detail'
  activeUid: null,     // server uid in detail view
  activeId: null,      // sessionId of active server
  activeTab: 'terminal',
  terminals: new Map(),// terminalId -> independent shell and xterm instance
  activeTerminals: new Map(), // sessionId -> selected terminalId
  terminalSequence: 0,
  status: new Map(),   // sessionId -> {connected, gpu, system, ts}
  gpuHistory: new Map(),// sessionId -> [{t, utils:[], mems:[]}]
  sysHistory: [],
  currentPath: null,   // current dir in file manager (home-relative or abs)
  homeDir: null,       // active session's home dir (file-manager jail root)
  fileUploadActive: false,
  currentUser: null,
  timers: { gpu: null, sys: null },
  pollTimer: null,
};

/* ================= themes ================= */

const THEME_KEY = 'webssh.theme.v1';
// Each theme: label + xterm color set (kept in sync with style.css palettes).
const THEMES = [
  {
    id: 'dark', label: 'Midnight blue', icon: '🌙', sw: ['#0d1117', '#58a6ff'],
    xterm: {
      background: '#0d1117', foreground: '#e6edf3', cursor: '#58a6ff',
      cursorAccent: '#0d1117', selectionBackground: 'rgba(88,166,255,.3)',
      black: '#484f58', red: '#ff7b72', green: '#3fb950', yellow: '#d29922',
      blue: '#58a6ff', magenta: '#bc8cff', cyan: '#39c5cf', white: '#b1bac4',
    },
  },
  {
    id: 'light', label: 'Light', icon: '☀️', sw: ['#f6f8fa', '#0969da'],
    xterm: {
      background: '#f6f8fa', foreground: '#1f2328', cursor: '#0969da',
      cursorAccent: '#f6f8fa', selectionBackground: 'rgba(9,105,218,.25)',
      black: '#24292f', red: '#cf222e', green: '#1a7f37', yellow: '#9a6700',
      blue: '#0969da', magenta: '#8250df', cyan: '#1b7c83', white: '#57606a',
    },
  },
  {
    id: 'contrast', label: 'High contrast', icon: '🔲', sw: ['#000000', '#4dc9ff'],
    xterm: {
      background: '#000000', foreground: '#ffffff', cursor: '#4dc9ff',
      cursorAccent: '#000000', selectionBackground: 'rgba(77,201,255,.4)',
      black: '#767676', red: '#ff5c57', green: '#3dff6e', yellow: '#ffd60a',
      blue: '#4dc9ff', magenta: '#ff7bd5', cyan: '#00ffff', white: '#ffffff',
    },
  },
  {
    id: 'warm', label: 'Warm', icon: '🔥', sw: ['#1d1a16', '#b58900'],
    xterm: {
      background: '#1d1a16', foreground: '#eee8d9', cursor: '#b58900',
      cursorAccent: '#1d1a16', selectionBackground: 'rgba(181,137,0,.3)',
      black: '#586e75', red: '#dc322f', green: '#85994b', yellow: '#b58900',
      blue: '#268bd2', magenta: '#d33682', cyan: '#2aa198', white: '#eee8d9',
    },
  },
];

function currentTheme() {
  const id = localStorage.getItem(THEME_KEY) || 'dark';
  return THEMES.find((t) => t.id === id) || THEMES[0];
}

function applyTheme(id) {
  const t = THEMES.find((x) => x.id === id) || THEMES[0];
  if (id === 'dark') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme', id);
  localStorage.setItem(THEME_KEY, t.id);
  // Re-theme any already-open terminals.
  for (const [, entry] of state.terminals) {
    try { entry.term.options.theme = { ...t.xterm }; } catch (e) { /* ignore */ }
  }
  renderThemeMenu();
}

function renderThemeMenu() {
  const menu = $('#theme-menu');
  if (!menu) return;
  const active = currentTheme().id;
  menu.innerHTML =
    '<div class="tm-title">Appearance</div>' +
    THEMES.map((t) => `
      <button class="theme-opt ${t.id === active ? 'active' : ''}" data-theme="${t.id}" role="menuitem">
        <span class="swatch" style="--sw-bg:${t.sw[0]};--sw-accent:${t.sw[1]}"></span>
        <span>${t.icon} ${t.label}</span>
        <span class="tk">${t.id === active ? '✓' : ''}</span>
      </button>`).join('');
  $$('#theme-menu .theme-opt').forEach((b) => (b.onclick = () => {
    applyTheme(b.dataset.theme);
    closeThemeMenu();
  }));
}

let themeMenuOpen = false;
function closeThemeMenu() {
  const m = $('#theme-menu'), b = $('#btn-theme');
  if (m) m.classList.remove('open');
  if (b) b.setAttribute('aria-expanded', 'false');
  themeMenuOpen = false;
}

function initThemeSwitcher() {
  const btn = $('#btn-theme'), menu = $('#theme-menu');
  if (!btn || !menu) return;
  // apply persisted theme immediately (before first paint of terminals)
  applyTheme(currentTheme().id);
  btn.onclick = (e) => {
    e.stopPropagation();
    const open = menu.classList.toggle('open');
    btn.setAttribute('aria-expanded', String(open));
    themeMenuOpen = open;
  };
  document.addEventListener('click', (e) => {
    if (themeMenuOpen && !menu.contains(e.target) && e.target !== btn) closeThemeMenu();
  });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeThemeMenu(); });
}

/* ================= utils ================= */

// Map a 0-100 utilization percentage to a green->red color class.
function utilCls(v) {
  const n = Number(v);
  if (!Number.isFinite(n)) return '';
  if (n >= 90) return 'util-val crit';
  if (n >= 80) return 'util-val hi';
  if (n >= 50) return 'util-val mid';
  return 'util-val lo';
}

function toast(msg, type = '') {
  const el = $('#toast');
  el.textContent = msg;
  el.className = 'toast ' + type;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.add('hidden'), 3500);
}

async function api(url, opts = {}) {
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
    credentials: opts.credentials || 'same-origin',
  });
  let data = null;
  try { data = await res.json(); } catch (e) { /* ignore */ }
  if (!res.ok) {
    // A 401 can also come from an SSH server (for example, a saved host with
    // an expired password). Only the application's explicit auth response
    // should return the UI to the login page.
    if (res.status === 401 && data?.error === 'Please sign in') showLoginPage();
    const error = new Error((data && data.error) || `HTTP ${res.status}`);
    error.status = res.status;
    error.data = data;
    throw error;
  }
  return data;
}

function showLoginPage() {
  document.getElementById('disk-usage-dialog')?.close();
  authFlow += 1;
  clearTimers();
  if (state.pollTimer) clearInterval(state.pollTimer);
  state.pollTimer = null;
  for (const id of [...state.terminals.keys()]) disposeTerminal(id);
  state.activeTerminals.clear();
  state.status.clear();
  state.gpuHistory.clear();
  state.sysHistory = [];
  state.currentUser = null;
  state.servers = [];
  state.activeId = null;
  state.activeUid = null;
  $('#app-view')?.classList.add('hidden');
  $('#auth-view')?.classList.remove('hidden');
  const error = $('#login-error');
  if (error) error.textContent = '';
}

async function enterApp(user, flow = authFlow) {
  if (flow !== authFlow) return;
  state.currentUser = user;
  $('#current-user').textContent = `${user.isAdmin ? 'Admin · ' : ''}${user.username}`;
  $('#btn-add-server').classList.toggle('hidden', !user.isAdmin);
  $('#btn-import-server').classList.toggle('hidden', !user.isAdmin);
  $('#btn-users').classList.toggle('hidden', !user.isAdmin);
  $('#auth-view').classList.add('hidden');
  $('#app-view').classList.remove('hidden');

  let saved = [];
  try {
    saved = (await api('/api/servers')).servers;
  } catch (e) {
    if (e.status === 401) return;
    toast('Failed to load server list: ' + e.message, 'error');
  }
  if (flow !== authFlow) return;

  // One-time migration: move legacy localStorage data into this logged-in
  // user's account, so old browser data is not silently discarded.
  if (!saved.length && user.isAdmin) {
    const legacy = loadLegacy();
    if (legacy.length) {
      for (const s of legacy) {
        if (!s.uid) s.uid = newUid();
        try { await persistServer(s); } catch (e) { /* ignore invalid legacy rows */ }
      }
      try { localStorage.removeItem(LS_KEY); } catch (e) { /* ignore */ }
      try { saved = (await api('/api/servers')).servers; } catch (e) { saved = []; }
    }
  }

  state.servers = saved.map((s) => {
    const mine = s.mine || null;
    const hasCreds = !!(mine?.username && (mine.creds?.password || mine.creds?.privateKey || mine.creds?.keyRef));
    return { ...s, mine, sessionId: null, connecting: hasCreds };
  });
  initThemeSwitcher();
  renderDashboard();

  const withCreds = state.servers.filter((s) => hasMyCreds(s));
  for (const s of withCreds) s.connecting = false;
  for (const s of withCreds) connectServer(s, { silent: true });
  state.pollTimer = setInterval(pollStatus, 5000);
}

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  // Event.currentTarget is cleared after an awaited promise; keep the form
  // reference so a successful login can safely reset it.
  const loginForm = e.currentTarget;
  const form = new FormData(loginForm);
  const btn = $('#btn-login');
  const error = $('#login-error');
  const flow = ++authFlow;
  btn.disabled = true;
  error.textContent = '';
  try {
    const data = await api('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username: form.get('username'), password: form.get('password') }),
    });
    loginForm.reset();
    await enterApp(data.user, flow);
  } catch (err) {
    error.textContent = err.message;
  } finally {
    btn.disabled = false;
  }
});

async function logout() {
  $('#btn-logout').disabled = true;
  try { await api('/api/auth/logout', { method: 'POST' }); } catch (e) { /* reload also clears stale UI */ }
  window.location.reload();
}

$('#btn-logout').onclick = logout;

function closeChangePasswordModal() {
  $('#change-password-modal').classList.add('hidden');
  $('#change-password-form').reset();
}

$('#btn-change-password').onclick = () => {
  $('#change-password-form').reset();
  $('#change-password-modal').classList.remove('hidden');
  setTimeout(() => $('#change-password-form').currentPassword.focus(), 50);
};
$('#btn-change-password-close').onclick = closeChangePasswordModal;
$('#btn-change-password-cancel').onclick = closeChangePasswordModal;
$('#change-password-form').onsubmit = async (e) => {
  e.preventDefault();
  const form = e.currentTarget;
  const currentPassword = String(form.currentPassword.value || '');
  const newPassword = String(form.newPassword.value || '');
  if (newPassword !== String(form.confirmPassword.value || '')) return toast('New passwords do not match', 'error');
  try {
    await api('/api/auth/password', { method: 'POST', body: JSON.stringify({ currentPassword, newPassword }) });
    closeChangePasswordModal();
    toast('Password updated. Please sign in again.', 'ok');
    showLoginPage();
  } catch (err) { toast('Password update failed: ' + err.message, 'error'); }
};

/* ================= user management (admin) ================= */

function closeUserModal() {
  $('#user-modal').classList.add('hidden');
  $('#user-form').classList.add('hidden');
  $('#user-form').reset();
}

$('#btn-users').onclick = () => {
  $('#user-form').classList.add('hidden');
  $('#user-form').reset();
  $('#user-modal').classList.remove('hidden');
  loadUsers();
};
$('#btn-user-modal-close').onclick = closeUserModal;
$('#btn-user-modal-cancel').onclick = () => {
  $('#user-form').classList.add('hidden');
  $('#user-form').reset();
};
$('#btn-user-add-toggle').onclick = () => {
  const form = $('#user-form');
  const willOpen = form.classList.contains('hidden');
  form.classList.toggle('hidden');
  if (willOpen) form.username.focus();
};

async function loadUsers() {
  const tbody = $('#users-tbody');
  tbody.innerHTML = '<tr><td colspan="5" class="dim">Loading…</td></tr>';
  let users;
  try {
    users = (await api('/api/users')).users;
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="5" class="dim">${esc(e.message)}</td></tr>`;
    $('#users-count').textContent = '';
    return;
  }
  const me = state.currentUser?.username;
  $('#users-count').textContent = `${users.length} user${users.length === 1 ? '' : 's'}`;
  if (!users.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="dim">No users</td></tr>';
    return;
  }
  tbody.innerHTML = users.map((u) => `
    <tr data-id="${u.id}">
      <td class="mono">${esc(u.username)}${u.username === me ? ' <span class="tag dup">you</span>' : ''}</td>
      <td>${u.isAdmin ? '<span class="tag admin">Admin</span>' : '<span class="tag dup">User</span>'}</td>
      <td class="dim">${u.serverCount}${u.sessionCount ? ` · ${u.sessionCount} online` : ''}</td>
      <td class="dim">${fmtDate(u.createdAt)}</td>
      <td class="ops">
        <button class="btn small user-pwd" title="Reset password">Reset password</button>
        <button class="btn small user-role">${u.isAdmin ? 'Revoke admin' : 'Make admin'}</button>
        <button class="btn small danger user-del" ${u.username === me ? 'disabled title="You cannot delete your own account"' : 'title="Delete user"'}>Delete</button>
      </td>
    </tr>`).join('');

  for (const tr of $$('#users-tbody tr')) {
    const user = users.find((x) => x.id === Number(tr.dataset.id));
    if (!user) continue;
    tr.querySelector('.user-pwd').onclick = async () => {
      const pwd = prompt(`New password for ${user.username} (12-128 characters):`);
      if (pwd == null) return;
      if (pwd.length < 12 || pwd.length > 128) return toast('Password must be 12-128 characters', 'error');
      try {
        await api(`/api/users/${user.id}`, { method: 'PATCH', body: JSON.stringify({ password: pwd }) });
        toast(`Password reset for ${user.username}`, 'ok');
      } catch (e) {
        toast('Reset failed: ' + e.message, 'error');
      }
    };
    tr.querySelector('.user-role').onclick = async () => {
      const makeAdmin = !user.isAdmin;
      if (!makeAdmin && !confirm(`Revoke admin rights from ${user.username}?`)) return;
      try {
        await api(`/api/users/${user.id}`, { method: 'PATCH', body: JSON.stringify({ isAdmin: makeAdmin }) });
        toast(`${user.username} is now ${makeAdmin ? 'an administrator' : 'a regular user'}`, 'ok');
        loadUsers();
      } catch (e) {
        toast(e.message, 'error');
      }
    };
    tr.querySelector('.user-del').onclick = async () => {
      const msg = `Delete user "${user.username}"?` +
        (user.serverCount ? ` Their ${user.serverCount} saved connection record(s) will be deleted.` : '') +
        ' Any active sessions will be closed.';
      if (!confirm(msg)) return;
      try {
        await api(`/api/users/${user.id}`, { method: 'DELETE' });
        toast(`User ${user.username} deleted`, 'ok');
        loadUsers();
      } catch (e) {
        toast('Delete failed: ' + e.message, 'error');
      }
    };
  }
}

$('#user-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = e.currentTarget;
  const username = String(form.username.value || '').trim();
  const password = String(form.password.value || '');
  const confirmPassword = String(form.passwordConfirm.value || '');
  if (password !== confirmPassword) return toast('Passwords do not match', 'error');
  try {
    await api('/api/users', { method: 'POST', body: JSON.stringify({ username, password }) });
    form.reset();
    form.classList.add('hidden');
    toast(`User ${username} created`, 'ok');
    loadUsers();
  } catch (err) {
    toast('Failed to create user: ' + err.message, 'error');
  }
});

function fmtSize(bytes) {
  if (bytes == null) return '-';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0, v = bytes;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return v.toFixed(v >= 100 || i === 0 ? 0 : 1) + ' ' + units[i];
}

function fmtMB(mb) {
  if (mb == null) return '-';
  return mb >= 1024 ? (mb / 1024).toFixed(2) + ' GB' : mb + ' MB';
}

function fmtDate(ts) {
  if (!ts) return '-';
  const d = new Date(ts);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function fmtUptime(sec) {
  if (sec == null) return '-';
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  return (d > 0 ? d + 'd ' : '') + h + 'h ' + m + 'm';
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function newUid() {
  return (window.crypto && crypto.randomUUID) ? crypto.randomUUID() : 's' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

function serverLabel(s) {
  return s.label || s.host;
}

/* ================= persistence (server-side SQLite) ================= */

function loadLegacy() {
  try { return JSON.parse(localStorage.getItem(LS_KEY) || '[]'); } catch (e) { return []; }
}

async function persistServer(server) {
  await api('/api/servers', {
    method: 'POST',
    body: JSON.stringify({
      uid: server.uid,
      label: server.label,
      host: server.host,
      port: server.port,
      algorithms: server.algorithms || null,
    }),
  });
}

function hasMyCreds(server) {
  const c = server?.mine?.creds || {};
  return !!(server?.mine?.username && (c.password || c.privateKey || c.keyRef));
}

/* ================= server lifecycle ================= */

function findServer(uid) {
  return state.servers.find((s) => s.uid === uid);
}

async function connectServer(server, opts = {}) {
  if (server.sessionId || server.connecting) return;
  if (!hasMyCreds(server)) {
    if (!opts.silent) toast('No connection information is configured for your account on this server.', 'error');
    return;
  }
  server.connecting = true;
  renderDashboard();
  updateDetailStatus();
  try {
    const creds = server.mine.creds || {};
    const data = await api('/api/connect', {
      method: 'POST',
      body: JSON.stringify({
        host: server.host,
        port: server.port,
        username: server.mine.username,
        password: creds.password,
        privateKey: creds.privateKey,
        keyRef: creds.keyRef || undefined,
        passphrase: creds.passphrase,
        sudoPassword: creds.sudoPassword,
        algorithms: server.algorithms || undefined,
      }),
    });
    server.sessionId = data.sessionId;
    server.homeDir = data.homeDir || null;
    try {
      const st = await api(`/api/status/${data.sessionId}`);
      if (st.connected) state.status.set(data.sessionId, st);
    } catch (e) { /* pollStatus will retry */ }
    if (state.view === 'detail' && state.activeUid === server.uid) {
      state.activeId = data.sessionId;
      if (state.activeTab === 'terminal') ensureTerminal(server);
    }
    toast(`Connected to ${serverLabel(server)}`, 'ok');
  } catch (e) {
    if (!opts.silent) toast(`Failed to connect to ${serverLabel(server)}: ${e.message}`, 'error');
  } finally {
    server.connecting = false;
    renderDashboard();
    updateDetailStatus();
  }
}

async function disconnectServer(server, opts = {}) {
  const sid = server.sessionId;
  server.sessionId = null;
  server.connecting = false;
  if (sid) {
    try { await fetch('/api/sessions/' + sid, { method: 'DELETE' }); } catch (e) { /* ignore */ }
    disposeSessionTerminals(sid);
    state.status.delete(sid);
    state.gpuHistory.delete(sid);
  }
  if (state.activeId === sid) {
    closeFileEditor(true);
    state.activeId = null;
    renderTerminalTabs();
  }
  if (!opts.silent) toast(`Disconnected from ${serverLabel(server)}`);
  renderDashboard();
  updateDetailStatus();
}

async function removeServer(server) {
  if (!state.currentUser?.isAdmin) return;
  const msg = `Delete server “${serverLabel(server)}”?` + (server.sessionId ? ' (it will be disconnected)' : '');
  if (!confirm(msg)) return;
  if (server.sessionId) await disconnectServer(server, { silent: true });
  state.servers = state.servers.filter((s) => s.uid !== server.uid);
  try {
    await api('/api/servers/' + encodeURIComponent(server.uid), { method: 'DELETE' });
  } catch (e) { /* ignore */ }
  if (state.activeUid === server.uid) showDashboard();
  renderDashboard();
}

/* ================= dashboard ================= */

function renderDashboard() {
  const grid = $('#server-grid');
  const total = state.servers.length;
  const online = state.servers.filter((s) => s.sessionId && state.status.get(s.sessionId)?.connected).length;
  const connecting = state.servers.filter((s) => s.connecting).length;
  $('#summary').textContent = total
    ? `${total} servers · ${online} online` + (connecting ? ` · ${connecting} connecting` : '')
    : '';
  $('#empty-dashboard').style.display = total ? 'none' : '';
  grid.innerHTML = '';
  // Sort only the dashboard presentation; keep state.servers' order intact
  // so connection polling and other operations continue using the same data.
  const displayServers = [...state.servers].sort((a, b) =>
    serverLabel(a).localeCompare(serverLabel(b), 'zh-CN', { numeric: true, sensitivity: 'base' })
      || a.uid.localeCompare(b.uid)
  );
  for (const s of displayServers) grid.appendChild(renderCard(s));
}

function renderCard(s) {
  const sid = s.sessionId;
  const st = sid ? state.status.get(sid) : null;
  const online = !!(sid && st && st.connected);
  const card = document.createElement('div');
  card.className = 'server-card ' + (online ? 'online' : s.connecting ? 'connecting' : 'offline');
  const audit = auditState(s);

  let bodyHtml;
  if (online && st) {
    const sys = st.system, gpu = st.gpu;
    const memPct = sys && sys.memTotal && sys.memTotal > 0 ? (sys.memUsed / sys.memTotal) * 100 : null;
    const diskPct = sys && sys.diskPct != null ? sys.diskPct : null;
    const cpuPct = sys && sys.cpuCount ? (sys.load?.[0] ?? 0) / sys.cpuCount * 100 : null;
    const barCls = (v) => (v >= 90 ? 'critical' : v >= 70 ? 'hot' : '');
    const barRow = (label, pct) => `
      <div class="stat-row">
        <span class="stat-label">${label}</span>
        <div class="bar"><i class="${pct == null ? '' : barCls(pct)}" style="width:${pct == null ? 0 : Math.min(100, pct)}%"></i></div>
      </div>`;
    bodyHtml = `
      <div class="card-stats">
        <div class="stat">
          <span class="stat-label">GPU utilization</span>
          <span class="stat-val">${gpu.available
            // "0:100%" = GPU index 0 at 100%; each card's % is colored by load.
            ? gpu.gpus.map((g) => `<span class="dim">GPU${g.index ?? '?'} </span><span class="${utilCls(g.util)}">${g.util ?? '-'}%</span>`).join('  ')
            : 'No GPU'}</span>
        </div>
        ${gpu.available && gpu.gpus[0] && gpu.gpus[0].memTotal ? barRow(
          `Memory ${gpu.gpus.map((g) => g.memTotal ? Math.round((g.memUsed / g.memTotal) * 100) + '%' : '-').join(' ')}`,
          (gpu.gpus[0].memUsed / gpu.gpus[0].memTotal) * 100
        ) : ''}
        ${barRow(`CPU ${sys?.load?.[0] ?? '-'}<span class="dim"> / ${sys?.cpuCount ?? '-'} cores</span>`, cpuPct)}
        ${barRow(`Memory ${memPct == null ? '-' : memPct.toFixed(0) + '%'}`, memPct)}
        ${barRow(`Disk ${diskPct == null ? '-' : diskPct + '%'}`, diskPct)}
      </div>
      ${sys ? `<div class="card-os">${esc(sys.os)} · ${esc(sys.hostname)} · Up ${fmtUptime(sys.uptimeSec)}</div>` : '<div class="card-os">Failed to collect system information (exec timed out or is unavailable)</div>'}`;
  } else if (!hasMyCreds(s)) {
    bodyHtml = `<div class="card-note missing-creds">No account is configured for you on this server. Add your SSH username and credentials to connect.</div>`;
  } else if (s.connecting) {
    bodyHtml = `<div class="card-spinner"><span class="spin"></span>Connecting to server...</div>`;
  } else {
    bodyHtml = `<div class="card-note">Disconnected</div>`;
  }

  card.innerHTML = `
    <div class="card-top">
      <span class="dot"></span>
      <span class="card-name">${esc(serverLabel(s))}</span>
      <span class="card-host">${esc(s.host)}:${s.port}</span>
      ${state.currentUser?.isAdmin ? `<button type="button" class="audit-light audit-${audit.level}" data-act="audit" aria-disabled="${!online}" aria-label="SSH 安全：${auditLabels[audit.level]}。${esc(audit.message)}" title="SSH 安全：${auditLabels[audit.level]} · ${esc(audit.message)}${online ? ' · 点击查看详情' : ''}"><span class="audit-light-dot" aria-hidden="true"></span><span>安全</span></button>` : ''}
    </div>
    ${bodyHtml}
    <div class="card-actions">
      ${hasMyCreds(s)
        ? (online ? '<button class="btn small primary" data-act="open">Manage</button>'
          : s.connecting
            ? '<button class="btn small primary" data-act="connect" disabled><span class="btn-spin"></span>Connecting...</button>'
            : '<button class="btn small primary" data-act="connect">Connect</button>')
        : '<button class="btn small primary" data-act="my-creds">Set my connection</button>'}
      ${online ? '<button class="btn small" data-act="disconnect">Disconnect</button>' : ''}
      ${hasMyCreds(s) ? '<button class="btn small" data-act="my-creds">My connection</button>' : ''}
      ${state.currentUser?.isAdmin ? '<button class="btn small" data-act="edit">Edit server</button>' : ''}
      ${state.currentUser?.isAdmin ? '<button class="btn small danger" data-act="remove">Delete server</button>' : ''}
    </div>`;

  card.querySelector('[data-act="audit"]')?.addEventListener('click', () => {
    if (!online) return;
    showDetail(s.uid);
    $('#tabs [data-tab="system"]').click();
  });
  card.querySelector('[data-act="open"]')?.addEventListener('click', () => showDetail(s.uid));
  card.querySelector('[data-act="connect"]')?.addEventListener('click', () => connectServer(s));
  card.querySelector('[data-act="disconnect"]')?.addEventListener('click', () => disconnectServer(s));
  card.querySelector('[data-act="my-creds"]')?.addEventListener('click', () => openCredsModal(s));
  card.querySelector('[data-act="edit"]')?.addEventListener('click', () => openModal(s));
  card.querySelector('[data-act="remove"]')?.addEventListener('click', () => removeServer(s));
  return card;
}

/* status polling (dashboard overview) */

let statusPollPending = false;
async function pollStatus() {
  if (statusPollPending) return;
  const targets = state.servers.filter((s) => s.sessionId);
  if (!targets.length) return;
  statusPollPending = true;
  await Promise.all(targets.map(async (s) => {
    const sessionId = s.sessionId;
    try {
      const [data, monitor] = await Promise.all([
        api(`/api/status/${sessionId}`),
        state.currentUser?.isAdmin ? api(`/api/admin/monitor/${sessionId}`).catch((e) => ({ error: e.message })) : Promise.resolve(null),
      ]);
      if (s.sessionId !== sessionId) return;
      if (monitor) s.auditMonitor = { ...monitor, sessionId };
      if (data.connected) s.statusError = false;
      if (data.connected) {
        state.status.set(s.sessionId, data);
      } else {
        // SSH session died on server side
        const sid = s.sessionId;
        s.sessionId = null;
        disposeSessionTerminals(sid);
        state.status.delete(sid);
        state.gpuHistory.delete(sid);
        if (state.activeId === sid) { state.activeId = null; renderTerminalTabs(); }
      }
    } catch (e) { s.statusError = true; }
  }));
  statusPollPending = false;
  if (state.view === 'dashboard') renderDashboard();
  else updateDetailStatus();
}

/* ================= modal (add / edit) ================= */

let editingUid = null;

let editingFilePath = null;
let fileEditorVersion = null;
let fileEditorDirty = false;
let fileEditorSession = null;
let fileEditorRequest = 0;

function fileNameFromPath(filePath) {
  return filePath.split('/').filter(Boolean).pop() || filePath;
}

async function openFileEditor(filePath) {
  if (fileEditorDirty && !confirm('当前文件有未保存的修改，放弃修改并打开另一个文件？')) return;
  const request = ++fileEditorRequest;
  const sessionId = state.activeId;
  fileEditorSession = sessionId;
  const modal = $('#file-editor-modal');
  const text = $('#file-editor-text');
  const save = $('#btn-file-editor-save');
  editingFilePath = filePath;
  fileEditorVersion = null;
  fileEditorDirty = false;
  $('#file-editor-title').textContent = 'Edit file · ' + fileNameFromPath(filePath);
  $('#file-editor-path').textContent = filePath;
  $('#file-editor-status').textContent = 'Loading...';
  text.value = '';
  text.disabled = true;
  save.disabled = true;
  modal.classList.remove('hidden');
  try {
    const data = await api(`/api/files/${sessionId}/edit?path=${encodeURIComponent(filePath)}`);
    if (fileEditorRequest !== request || state.activeId !== sessionId) return;
    text.value = data.content;
    fileEditorVersion = data.version || null;
    text.disabled = false;
    save.disabled = false;
    $('#file-editor-status').textContent = 'No changes';
    text.focus();
  } catch (e) {
    if (fileEditorRequest === request && state.activeId === sessionId) {
      closeFileEditor(true);
      toast('无法编辑文件：' + friendlyFileError(e), 'error');
    }
  }
}

function closeFileEditor(force = false) {
  if (!force && fileEditorDirty && !confirm('The file has unsaved changes. Close the editor?')) return;
  editingFilePath = null;
  fileEditorSession = null;
  fileEditorRequest++;
  fileEditorVersion = null;
  fileEditorDirty = false;
  $('#file-editor-modal').classList.add('hidden');
  $('#file-editor-text').disabled = true;
}

async function saveFileEditor() {
  const filePath = editingFilePath;
  const sessionId = fileEditorSession;
  const request = fileEditorRequest;
  if (!filePath || !sessionId || state.activeId !== sessionId) return;
  const save = $('#btn-file-editor-save');
  const text = $('#file-editor-text');
  const submitted = text.value;
  save.disabled = true;
  $('#file-editor-status').textContent = 'Saving...';
  try {
    const data = await api(`/api/files/${sessionId}/edit`, {
      method: 'POST',
      body: JSON.stringify({ path: filePath, content: submitted, version: fileEditorVersion }),
    });
    if (fileEditorRequest !== request || state.activeId !== sessionId) return;
    fileEditorVersion = data.version || fileEditorVersion;
    fileEditorDirty = text.value !== submitted;
    $('#file-editor-status').textContent = fileEditorDirty ? '本次提交已保存，仍有新的未保存修改' : 'Saved';
    toast('File saved', 'ok');
    loadDir(state.currentPath);
  } catch (e) {
    if (fileEditorRequest !== request || state.activeId !== sessionId) return;
    $('#file-editor-status').textContent = e.status === 409 ? 'Remote file changed' : 'Save failed';
    toast('Failed to save file: ' + e.message, 'error');
  } finally {
    if (fileEditorRequest === request && state.activeId === sessionId) save.disabled = false;
  }
}

$('#btn-file-editor-close').onclick = () => closeFileEditor();
$('#btn-file-editor-cancel').onclick = () => closeFileEditor();
$('#file-editor-text').addEventListener('input', () => {
  fileEditorDirty = true;
  $('#file-editor-status').textContent = 'Unsaved changes';
});
$('#file-editor-text').addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') {
    e.preventDefault();
    if (!$('#btn-file-editor-save').disabled) saveFileEditor();
    return;
  }
  if (e.key === 'Tab') {
    e.preventDefault();
    const start = e.target.selectionStart;
    const end = e.target.selectionEnd;
    e.target.setRangeText('  ', start, end, 'end');
    e.target.dispatchEvent(new Event('input'));
  }
});
$('#btn-file-editor-save').onclick = saveFileEditor;

async function loadKeyOptions() {
  const sel = $('#sel-keyref');
  const current = sel.value;
  try {
    const data = state.currentUser?.isAdmin ? await api('/api/ssh-keys') : { keys: [] };
    sel.innerHTML = '<option value="">— None —</option>' +
      data.keys.map((k) => `<option value="${esc(k)}">${esc(k)}</option>`).join('');
    if (current && data.keys.includes(current)) sel.value = current;
  } catch (e) { /* no keys */ }
}

function openModal(server) {
  if (!state.currentUser?.isAdmin) return;
  editingUid = server ? server.uid : null;
  $('#modal-title').textContent = server ? 'Edit server' : 'Add server';
  const f = $('#server-form');
  f.reset();
  f.port.value = 22;
  if (server) {
    f.label.value = server.label || '';
    f.host.value = server.host;
    f.port.value = server.port;
  }
  $('#server-modal').classList.remove('hidden');
  setTimeout(() => f.host.focus(), 50);
}

function closeModal() {
  $('#server-modal').classList.add('hidden');
  editingUid = null;
}

$('#btn-add-server').onclick = () => openModal(null);
// Form dialogs intentionally ignore backdrop clicks, including clicks generated
// by selecting text inside the dialog and releasing the pointer outside it.
$('#btn-modal-close').onclick = closeModal;
$('#btn-cancel-server').onclick = closeModal;

$('#server-form').onsubmit = async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  const host = f.get('host').trim();
  if (!host) return toast('Host is required', 'error');

  let server;
  if (editingUid) {
    server = findServer(editingUid);
    Object.assign(server, {
      label: f.get('label').trim() || host,
      host,
      port: parseInt(f.get('port') || 22, 10),
    });
  } else {
    server = {
      uid: newUid(),
      label: f.get('label').trim() || host,
      host,
      port: parseInt(f.get('port') || 22, 10),
      sessionId: null,
      connecting: false,
    };
    state.servers.push(server);
  }
  try {
    await persistServer(server);
  } catch (e) {
    toast(`Save failed: ${e.message}`, 'error');
  }
  closeModal();
  renderDashboard();

  if (server.sessionId) {
    // edit a connected server -> reconnect with new config
    await disconnectServer(server, { silent: true });
    await connectServer(server);
  }
};

let credsServerUid = null;

async function loadCredKeyOptions(selected = null) {
  const sel = $('#sel-creds-keyref');
  try {
    const data = state.currentUser?.isAdmin ? await api('/api/ssh-keys') : { keys: [] };
    sel.innerHTML = '<option value="">— None —</option>' + data.keys.map((k) => `<option value="${esc(k)}">${esc(k)}</option>`).join('');
    if (selected && data.keys.includes(selected)) sel.value = selected;
  } catch (e) { /* no local keys */ }
}

function openCredsModal(server) {
  credsServerUid = server.uid;
  const f = $('#creds-form');
  f.reset();
  const mine = server.mine;
  $('#creds-modal-title').textContent = `${mine?.isDefault ? 'Default admin connection' : 'My connection'} · ${serverLabel(server)}`;
  if (mine) {
    f.username.value = mine.username || '';
    f.password.value = mine.creds?.password || '';
    f.privateKey.value = mine.creds?.privateKey || '';
    f.passphrase.value = mine.creds?.passphrase || '';
    f.sudoPassword.value = mine.creds?.sudoPassword || '';
    $('#btn-creds-remove').classList.toggle('hidden', !!mine.isDefault);
  } else {
    $('#btn-creds-remove').classList.add('hidden');
  }
  loadCredKeyOptions(mine?.creds?.keyRef || null);
  $('#creds-modal').classList.remove('hidden');
  setTimeout(() => f.username.focus(), 50);
}

function closeCredsModal() {
  $('#creds-modal').classList.add('hidden');
  credsServerUid = null;
}

$('#btn-creds-modal-close').onclick = closeCredsModal;
$('#btn-creds-cancel').onclick = closeCredsModal;
$('#creds-form').onsubmit = async (e) => {
  e.preventDefault();
  const server = findServer(credsServerUid);
  if (!server) return;
  const f = new FormData(e.target);
  const username = String(f.get('username') || '').trim();
  const creds = { password: f.get('password') || null, privateKey: String(f.get('privateKey') || '').trim() || null, keyRef: f.get('keyRef') || null, passphrase: f.get('passphrase') || null, sudoPassword: f.get('sudoPassword') || null };
  if (!username) return toast('SSH username is required', 'error');
  if (!creds.password && !creds.privateKey && !creds.keyRef) return toast('Provide a password, private key, or local key', 'error');
  try {
    await api(`/api/servers/${encodeURIComponent(server.uid)}/creds`, { method: 'POST', body: JSON.stringify({ username, creds }) });
    server.mine = { username, creds };
    closeCredsModal();
    renderDashboard();
    toast('Your connection information was saved', 'ok');
  } catch (err) { toast(`Failed to save connection information: ${err.message}`, 'error'); }
};
$('#btn-creds-remove').onclick = async () => {
  const server = findServer(credsServerUid);
  if (!server || !confirm(`Remove your connection information for ${serverLabel(server)}?`)) return;
  try {
    if (server.sessionId) await disconnectServer(server, { silent: true });
    await api(`/api/servers/${encodeURIComponent(server.uid)}/creds`, { method: 'DELETE' });
    server.mine = null;
    closeCredsModal(); renderDashboard();
  } catch (err) { toast(`Failed to remove connection information: ${err.message}`, 'error'); }
};

/* ================= view switching ================= */

function showDashboard() {
  closeFileEditor(true);
  state.view = 'dashboard';
  state.activeUid = null;
  state.activeId = null;
  clearTimers();
  $('#view-detail').classList.add('hidden');
  $('#view-dashboard').classList.remove('hidden');
  renderDashboard();
}

function showDetail(uid) {
  const s = findServer(uid);
  if (!s) return;
  if (!s.sessionId) {
    toast('This server is not connected', 'error');
    return;
  }
  state.view = 'detail';
  state.activeUid = uid;
  state.activeId = s.sessionId;
  state.homeDir = s.homeDir || null;
  state.currentPath = s.homeDir || null;
  state.gpuHistory.delete(s.sessionId);
  state.sysHistory = [];
  $('#view-dashboard').classList.add('hidden');
  $('#view-detail').classList.remove('hidden');
  $('#detail-name').textContent = serverLabel(s);
  $('#detail-meta').textContent = `${s.mine?.username || 'No account'}@${s.host}:${s.port}`;
  updateDetailStatus();
  // reset to terminal tab
  state.activeTab = 'terminal';
  $$('#tabs button').forEach((b) => b.classList.toggle('active', b.dataset.tab === 'terminal'));
  $$('.tab').forEach((t) => t.classList.toggle('active', t.id === 'tab-terminal'));
  ensureTerminal(s);
}

$('#btn-back').onclick = showDashboard;

function updateDetailStatus() {
  const s = findServer(state.activeUid);
  if (!s) return;
  const badge = $('#detail-status');
  const btn = $('#btn-detail-action');
  const st = s.sessionId ? state.status.get(s.sessionId) : null;
  if (s.connecting) {
    badge.innerHTML = '<span class="btn-spin"></span> Connecting';
    badge.className = 'status-badge connecting';
    btn.innerHTML = '<span class="btn-spin"></span>Connecting...';
    btn.className = 'btn primary small';
    btn.disabled = true;
  } else if (s.sessionId) {
    badge.textContent = '● Connected';
    badge.className = 'status-badge online';
    btn.textContent = 'Disconnect';
    btn.className = 'btn danger small';
    btn.disabled = false;
  } else {
    badge.textContent = '○ Disconnected';
    badge.className = 'status-badge offline';
    btn.textContent = 'Connect';
    btn.className = 'btn primary small';
    btn.disabled = false;
  }
}

$('#btn-detail-action').onclick = () => {
  const s = findServer(state.activeUid);
  if (!s) return;
  if (s.sessionId) disconnectServer(s);
  else connectServer(s);
};

/* ================= tabs ================= */

$$('#tabs button').forEach((b) => {
  b.onclick = () => {
    state.activeTab = b.dataset.tab;
    $$('#tabs button').forEach((x) => x.classList.toggle('active', x === b));
    $$('.tab').forEach((t) => t.classList.toggle('active', t.id === 'tab-' + b.dataset.tab));
    onTabShown();
  };
});

function onTabShown() {
  clearTimers();
  if (!state.activeId) return;
  if (state.activeTab === 'terminal') {
    const server = findServer(state.activeUid);
    if (server) ensureTerminal(server);
  } else if (state.activeTab === 'gpu') {
    refreshGpu();
    state.timers.gpu = setInterval(refreshGpu, 2000);
  } else if (state.activeTab === 'files') {
    // null/undefined -> server defaults to the session's home dir
    loadDir(state.currentPath || undefined);
  } else if (state.activeTab === 'system') {
    refreshSystem();
    state.timers.sys = setInterval(refreshSystem, 5000);
  }
}

function clearTimers() {
  for (const k of Object.keys(state.timers)) {
    if (state.timers[k]) { clearInterval(state.timers[k]); state.timers[k] = null; }
  }
}

/* ================= terminal ================= */

function disposeTerminal(terminalId) {
  const entry = state.terminals.get(terminalId);
  if (!entry) return;
  state.terminals.delete(terminalId);
  entry.ws.onopen = entry.ws.onclose = entry.ws.onmessage = entry.ws.onerror = null;
  try { entry.ws.close(); } catch (e) { /* ignore */ }
  entry.term.dispose();
  entry.el.remove();
}

function disposeSessionTerminals(sessionId) {
  for (const [id, entry] of state.terminals) {
    if (entry.sessionId === sessionId) disposeTerminal(id);
  }
  state.activeTerminals.delete(sessionId);
  renderTerminalTabs();
}

function sessionTerminals(sessionId) {
  return [...state.terminals.values()].filter((entry) => entry.sessionId === sessionId);
}

function renderTerminalTabs() {
  const tabs = $('#terminal-tabs');
  const selected = state.activeTerminals.get(state.activeId);
  tabs.innerHTML = '';
  for (const entry of sessionTerminals(state.activeId)) {
    const wrapper = document.createElement('div');
    wrapper.className = 'terminal-tab' + (entry.id === selected ? ' selected' : '');
    const button = document.createElement('button');
    button.type = 'button';
    button.setAttribute('role', 'tab');
    button.setAttribute('aria-selected', String(entry.id === selected));
    button.textContent = entry.title + (entry.status === 'closed' ? ' · 已结束' : entry.status === 'connecting' ? ' · 连接中' : '');
    button.onclick = () => showTerminal(entry.id);
    const close = document.createElement('button');
    close.type = 'button';
    close.className = 'terminal-tab-close';
    close.textContent = '×';
    close.title = '关闭此终端（会结束该 shell）';
    close.setAttribute('aria-label', '关闭' + entry.title);
    close.onclick = () => {
      const entries = sessionTerminals(entry.sessionId);
      const index = entries.indexOf(entry);
      const wasSelected = state.activeTerminals.get(entry.sessionId) === entry.id;
      disposeTerminal(entry.id);
      if (wasSelected) {
        const next = entries[index + 1] || entries[index - 1];
        if (next) showTerminal(next.id);
        else state.activeTerminals.delete(entry.sessionId);
      }
      renderTerminalTabs();
    };
    wrapper.append(button, close);
    tabs.appendChild(wrapper);
  }
  $('#btn-new-terminal').disabled = !state.activeId;
  $('#terminal-empty').classList.toggle('hidden', sessionTerminals(state.activeId).length > 0);
}

function ensureTerminal(server) {
  if (!server?.sessionId) return null;
  const entries = sessionTerminals(server.sessionId);
  const selected = state.activeTerminals.get(server.sessionId);
  const entry = entries.find((t) => t.id === selected) || entries[0] || createTerminal(server, server.sessionId);
  showTerminal(entry.id);
  return entry;
}

$('#btn-new-terminal').onclick = () => {
  const server = findServer(state.activeUid);
  if (server?.sessionId) showTerminal(createTerminal(server, server.sessionId).id);
};

function createTerminal(server, sessionId) {
  const term = new Terminal({
    cursorBlink: true,
    fontSize: 14,
    fontFamily: '"JetBrains Mono", "Cascadia Code", Consolas, "Courier New", monospace',
    scrollback: 8000,
    theme: { ...currentTheme().xterm },
  });
  const fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  term.loadAddon(new WebLinksAddon.WebLinksAddon());

  const el = document.createElement('div');
  el.className = 'term-wrap';
  $('#terminal-container').appendChild(el);
  term.open(el);
  try { fit.fit(); } catch (e) { /* ignore */ }

  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(
    `${proto}://${location.host}/ws/terminal?sessionId=${sessionId}&cols=${term.cols}&rows=${term.rows}`
  );
  const id = 'terminal-' + (++state.terminalSequence);
  server.terminalCount = (server.terminalCount || 0) + 1;
  const entry = { id, sessionId, title: '终端 ' + server.terminalCount, term, fit, ws, el, status: 'connecting', uid: server.uid };
  state.terminals.set(id, entry);

  ws.onopen = () => { /* Wait for the remote shell ready message. */ };
  ws.onerror = () => { term.write('\r\n[终端连接失败]\r\n'); };
  ws.onclose = () => {
    entry.status = 'closed';
    renderTerminalTabs();
    term.write('\r\n\x1b[33m[Connection closed]\x1b[0m\r\n');
  };
  ws.onmessage = (ev) => {
    const txt = ev.data;
    let obj = null;
    try { obj = JSON.parse(txt); } catch (e) { /* raw */ }
    if (obj && typeof obj === 'object' && (obj.type === 'ready' || obj.type === 'error')) {
      if (obj.type === 'ready') { entry.status = 'open'; renderTerminalTabs(); }
      if (obj.type === 'error') term.write('\r\n\x1b[31m' + obj.message + '\x1b[0m\r\n');
      return;
    }
    term.write(txt);
  };
  term.onData((data) => {
    if (ws.readyState !== WebSocket.OPEN) return;
    // Keep pasted text within the server's per-message cap without splitting
    // a UTF-16 surrogate pair across two SSH writes.
    for (let offset = 0; offset < data.length;) {
      let end = Math.min(offset + 8192, data.length);
      if (end < data.length && /[\uD800-\uDBFF]/.test(data[end - 1])) end++;
      ws.send(JSON.stringify({ type: 'input', data: data.slice(offset, end) }));
      offset = end;
    }
  });
  term.onResize(({ cols, rows }) => {
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'resize', cols, rows }));
  });
  return entry;
}

function showTerminal(terminalId) {
  const entry = state.terminals.get(terminalId);
  if (!entry || entry.sessionId !== state.activeId) return;
  state.activeTerminals.set(entry.sessionId, terminalId);
  for (const [id, t] of state.terminals) t.el.classList.toggle('active', id === terminalId);
  renderTerminalTabs();
  requestAnimationFrame(() => {
    if (!state.terminals.has(terminalId) || state.activeTerminals.get(state.activeId) !== terminalId) return;
    try { entry.fit.fit(); } catch (e) { /* ignore */ }
    if (state.view === 'detail' && state.activeTab === 'terminal') entry.term.focus();
  });
}

window.addEventListener('resize', () => {
  const t = state.terminals.get(state.activeTerminals.get(state.activeId));
  if (t && state.view === 'detail' && state.activeTab === 'terminal') {
    try { t.fit.fit(); } catch (e) { /* ignore */ }
  }
});

/* ================= GPU ================= */

function gpuHistory(sid) {
  if (!state.gpuHistory.has(sid)) state.gpuHistory.set(sid, []);
  return state.gpuHistory.get(sid);
}

async function refreshGpu() {
  if (!state.activeId) return;
  let data;
  try {
    data = await api('/api/gpu/' + state.activeId);
  } catch (e) {
    return;
  }
  const box = $('#gpu-container');
  if (!data.available) {
    box.innerHTML = `<div class="empty-state">No NVIDIA GPU detected (nvidia-smi is unavailable)${data.error ? ' - ' + esc(data.error) : ''}</div>`;
    return;
  }
  const h = gpuHistory(state.activeId);
  h.push({
    t: Date.now(),
    utils: data.gpus.map((g) => g.util ?? 0),
    mems: data.gpus.map((g) => g.memUsed ?? 0),
  });
  if (h.length > 150) h.shift();

  box.innerHTML = `
    <div class="gpu-header">
      <b>GPU monitor</b>
      <span class="meta">Driver: ${esc(data.driver || 'Unknown')} | GPUs: ${data.count} | Updates every 2 seconds</span>
    </div>
    <div class="gpu-grid" id="gpu-grid"></div>
    <div class="gpu-charts">
      <div class="chart-box">
        <h4>Utilization history (GPU %)</h4>
        <canvas id="chart-util"></canvas>
        <div class="chart-legend" id="legend-util"></div>
      </div>
      <div class="chart-box">
        <h4>Memory history (MiB)</h4>
        <canvas id="chart-mem"></canvas>
        <div class="chart-legend" id="legend-mem"></div>
      </div>
    </div>
    <div class="gpu-procs">
      <h4>GPU processes (user / command / memory)</h4>
      <div class="file-table-wrap" style="max-height:300px">
        <table class="tbl gpu-proc-tbl">
          <thead><tr><th>PID</th><th>User</th><th>Process</th><th>Command</th><th>Memory</th></tr></thead>
          <tbody>
            ${data.processes.length
              ? data.processes.map((p) => `<tr>
                  <td class="mono">${esc(p.pid)}</td>
                  <td>${esc(p.user || '-')}</td>
                  <td>${esc(p.name)}</td>
                  <td class="cmd" title="${esc(p.command || p.name)}">${esc(p.command || p.name)}</td>
                  <td>${fmtMB(p.memUsed)}</td>
                </tr>`).join('')
              : '<tr><td colspan="5" class="dim">No GPU processes</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>`;

  const grid = $('#gpu-grid');
  data.gpus.forEach((g, i) => {
    const util = g.util ?? 0;
    const memPct = g.memTotal ? Math.min(100, (g.memUsed / g.memTotal) * 100) : 0;
    const barCls = (v) => (v >= 90 ? 'critical' : v >= 70 ? 'hot' : '');
    const card = document.createElement('div');
    card.className = 'gpu-card';
    card.innerHTML = `
      <div class="title"><span class="idx">GPU ${g.index ?? i}</span><span class="name">${esc(g.name)}</span></div>
      <div class="metric-row">
        <div class="lbl"><span>Utilization</span><span class="${utilCls(util)}">${util}%</span></div>
        <div class="bar"><i class="${barCls(util)}" style="width:${util}%"></i></div>
      </div>
      <div class="metric-row">
        <div class="lbl"><span>Memory ${fmtMB(g.memUsed)} / ${fmtMB(g.memTotal)}</span><span class="${utilCls(memPct)}">${memPct.toFixed(0)}%</span></div>
        <div class="bar"><i class="${barCls(memPct)}" style="width:${memPct}%"></i></div>
      </div>
      <div class="metric-row">
        <div class="lbl"><span>Memory bandwidth utilization</span><span class="${utilCls(g.memUtil)}">${g.memUtil ?? '-'}%</span></div>
        <div class="bar"><i class="${barCls(g.memUtil ?? 0)}" style="width:${g.memUtil ?? 0}%"></i></div>
      </div>
      <div class="gpu-stats">
        <span>Temperature <b>${g.temp ?? '-'}°C</b></span>
        <span>Power <b>${g.power != null ? g.power.toFixed(1) + ' W' : '-'}</b>${g.powerLimit ? ' / ' + g.powerLimit + ' W' : ''}</span>
      </div>`;
    grid.appendChild(card);
  });

  // History is stored by sample: [{ utils: [gpu0, gpu1], mems: [...] }].
  // The chart renderer expects one series per GPU, with samples ordered by
  // time.  Passing h.map(p => p.utils) made every sample look like a series;
  // with one GPU that meant every series had only one point and no line was
  // visible at all.
  const utilSeries = data.gpus.map((_, gpuIndex) => h.map((p) => p.utils[gpuIndex] ?? 0));
  const memSeries = data.gpus.map((_, gpuIndex) => h.map((p) => p.mems[gpuIndex] ?? 0));
  drawLineChart($('#chart-util'), utilSeries, GPU_COLORS, 100, '%');
  drawLineChart($('#chart-mem'), memSeries, GPU_COLORS, null, 'MiB');
  renderLegend('#legend-util', data.gpus, 'GPU utilization');
  renderLegend('#legend-mem', data.gpus, 'GPU memory');
}

function renderLegend(sel, gpus, label) {
  const el = document.querySelector(sel);
  if (!el) return;
  el.innerHTML = gpus.map((g, i) =>
    `<span><i style="background:${GPU_COLORS[i % GPU_COLORS.length]}"></i>GPU ${g.index ?? i} ${label}</span>`
  ).join('');
}

function drawLineChart(canvas, series, colors, maxVal, unit) {
  if (!canvas) return;
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth, hgt = canvas.clientHeight;
  if (w === 0 || hgt === 0) return;
  if (canvas.width !== w * dpr || canvas.height !== hgt * dpr) {
    canvas.width = w * dpr;
    canvas.height = hgt * dpr;
  }
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, hgt);

  const pad = { l: 40, r: 8, t: 8, b: 18 };
  const cw = w - pad.l - pad.r, chh = hgt - pad.t - pad.b;
  let max = maxVal;
  if (max == null) {
    max = 10;
    for (const s of series) for (const v of s) if (v > max) max = v;
    max *= 1.1;
  }

  ctx.strokeStyle = 'rgba(139,148,158,.2)';
  ctx.fillStyle = '#8b949e';
  ctx.font = '10px sans-serif';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = pad.t + (chh * i) / 4;
    ctx.beginPath();
    ctx.moveTo(pad.l, y);
    ctx.lineTo(w - pad.r, y);
    ctx.stroke();
    const val = max - (max * i) / 4;
    ctx.fillText(Math.round(val) + (unit === '%' ? '%' : ''), 2, y + 3);
  }

  const n = series.length;
  if (!n) return;
  const len = series[0].length;
  const xAt = (i) => pad.l + (len <= 1 ? cw / 2 : (cw * i) / (len - 1));
  const yAt = (v) => pad.t + chh - (Math.min(v, max) / max) * chh;

  series.forEach((s, si) => {
    ctx.strokeStyle = colors[si % colors.length];
    ctx.lineWidth = 1.6;
    ctx.beginPath();
    s.forEach((v, i) => (i === 0 ? ctx.moveTo(xAt(i), yAt(v)) : ctx.lineTo(xAt(i), yAt(v))));
    ctx.stroke();
  });

  ctx.fillStyle = '#8b949e';
  ctx.fillText('now', w - 28, hgt - 4);
  ctx.fillText('-' + Math.round(n / 2.5) + 's', 4, hgt - 4);
}

/* ================= files ================= */

function fileUrl(p) {
  return `/api/files/${state.activeId}` + p;
}

let directoryRequest = 0;
function fileAction(item) {
  if (item.isDirectory) return { label: '文件夹', action: '进入文件夹', icon: '📁', edit: false };
  const text = /(?:\.(?:txt|md|markdown|log|json|jsonl|yaml|yml|toml|ini|conf|cfg|csv|tsv|xml|html|css|js|jsx|ts|tsx|py|sh|bash|zsh|sql|c|h|cpp|hpp|rs|go|java|r|tex|env|gitignore)|^(?:README|LICENSE|Makefile|Dockerfile|\.bashrc|\.zshrc|\.profile|\.env))$/i.test(item.name);
  const binary = /\.(?:zip|gz|tar|bz2|xz|7z|rar|png|jpe?g|gif|webp|ico|pdf|mp4|mp3|wav|avi|exe|so|bin|pt|pth|ckpt|safetensors|npy|npz|parquet|docx?|xlsx?|pptx?)$/i.test(item.name);
  return { label: text ? '文本文件' : '文件', action: text && item.size <= 1048576 ? '打开文本编辑' : '下载文件', icon: text ? '📝' : '📄', edit: !binary && item.size <= 1048576 };
}
function validFileName(name) {
  if (!name || name === '.' || name === '..' || /[\/\\\0]/.test(name)) {
    toast('请输入一个文件名，不要包含路径、斜杠或 ..', 'error');
    return false;
  }
  return true;
}
function friendlyFileError(error) {
  const message = error.message || '未知错误';
  if (/permission denied/i.test(message)) return '当前 SSH 用户没有访问权限。可以返回上级目录或联系服务器管理员。';
  if (/no such file|not found/i.test(message)) return '文件或目录可能已被移动或删除，请刷新列表。';
  if (/not a directory/i.test(message)) return '这不是文件夹，请使用编辑或下载操作。';
  if (/binary content/i.test(message)) return '这是二进制文件，不能在线编辑，请使用“下载”。';
  if (/too large/i.test(message)) return '文件超过在线编辑的 1 MiB 限制，请下载后编辑。';
  if (/outside|主目录之外|超出主目录/i.test(message)) return '这个路径或链接超出了允许访问的主目录。';
  return message;
}

async function loadDir(path) {
  if (state.fileUploadActive) {
    toast('文件上传进行中，请等待完成后再切换目录', 'error');
    return;
  }
  if (!state.activeId) return;
  const sessionId = state.activeId;
  const requestId = ++directoryRequest;
  const container = $('#files-container');
  if (container.dataset.sessionId !== sessionId) {
    container.innerHTML = '<div class="empty-state">正在读取文件列表…</div>';
    container.dataset.sessionId = sessionId;
  }
  container.setAttribute('aria-busy', 'true');
  let data;
  try {
    // path may be undefined -> server defaults to home
    data = await api(fileUrl(`?path=${encodeURIComponent(path == null ? '' : path)}`));
  } catch (e) {
    if (state.activeId !== sessionId || requestId !== directoryRequest) return;
    container.querySelector('.file-error')?.remove();
    const errorBox = document.createElement('div');
    errorBox.className = 'file-error';
    errorBox.setAttribute('role', 'alert');
    errorBox.innerHTML = `<span>无法打开目录：${esc(friendlyFileError(e))}</span><button class="btn small files-retry">重试</button><button class="btn small files-home">返回主目录</button>`;
    if (!container.querySelector('#file-drop')) container.innerHTML = '';
    container.prepend(errorBox);
    errorBox.querySelector('.files-retry').onclick = () => loadDir(path);
    errorBox.querySelector('.files-home').onclick = () => loadDir();
    return;
  } finally {
    if (state.activeId === sessionId && requestId === directoryRequest) container.removeAttribute('aria-busy');
  }
  if (state.activeId !== sessionId || requestId !== directoryRequest) return;
  state.currentPath = data.path;
  state.homeDir = data.homeDir || state.homeDir;
  const box = $('#files-container');

  // Breadcrumbs: home (shown as ~) followed by the relative sub-path.
  const home = state.homeDir;
  const rel = data.path === home ? '' : data.path.slice(home.length).replace(/^\/+/, '');
  const segs = rel ? rel.split('/') : [];
  let crumbsHtml = `<a data-path="" title="${esc(home)}">~</a>`;
  let acc = '';
  for (const c of segs) {
    acc += (acc ? '/' : '') + c;
    crumbsHtml += `<span class="sep">/</span><a data-path="${esc(acc)}">${esc(c)}</a>`;
  }
  const atHome = segs.length === 0;

  box.innerHTML = `
    <div class="file-toolbar">
      <div class="crumbs" id="crumbs">${crumbsHtml}</div>
      ${atHome ? '' : '<button class="btn small" id="f-up">⬆ 上级</button>'}
      <button class="btn small" id="f-mkdir">新建目录</button>
      <button class="btn small" id="f-new-file">新建文件</button>
      <button class="btn small" id="f-refresh">刷新</button>
      <button class="btn small primary" id="f-upload">⬆ 上传文件</button>
      <input type="file" id="f-upload-input" multiple style="display:none" />
    </div>
    <div class="file-list-help">点击文件夹进入；点击文本文件编辑，其他文件下载。在线编辑最多支持 1 MiB。</div>
    <div id="file-upload-progress" class="upload-progress hidden" aria-live="polite">
      <div class="upload-progress-head">
        <span id="file-upload-label">准备上传</span>
        <span id="file-upload-percent">0%</span>
      </div>
      <div class="upload-progress-track"><i id="file-upload-bar"></i></div>
      <div id="file-upload-detail" class="dim"></div>
    </div>
    <div class="file-table-wrap" id="file-drop">
      <table class="tbl">
        <thead><tr><th>名称</th><th>类型</th><th>大小</th><th>修改时间</th><th style="width:150px">操作</th></tr></thead>
        <tbody>
          ${data.items.length
            ? data.items.map((it) => { const kind = fileAction(it); return `
              <tr data-path="${esc(it.path)}" data-dir="${it.isDirectory ? 1 : 0}">
                <td class="fname"><button type="button" class="file-open ${it.isDirectory ? 'file-folder' : ''}" title="${kind.action}：${esc(it.name)}" data-action="${kind.action === '打开文本编辑' ? 'edit' : it.isDirectory ? 'folder' : 'download'}"><span class="ico" aria-hidden="true">${kind.icon}</span><span>${esc(it.name)}</span><span class="file-action-hint">${it.isDirectory ? '进入 →' : kind.action === '打开文本编辑' ? '编辑' : '下载 ↓'}</span></button></td>
                <td class="dim file-kind">${kind.label}</td>
                <td class="dim">${it.isDirectory ? '-' : fmtSize(it.size)}</td>
                <td class="dim">${fmtDate(it.mtime)}</td>
                <td class="ops">
                  ${it.isDirectory ? '<button class="btn small enter">打开</button>' : `${kind.edit ? '<button class="btn small edit" title="编辑文本文件（最多 1 MiB）">编辑</button>' : ''}<button class="btn small dl" title="下载文件">下载</button>`}
                  <button class="btn small rn" title="重命名">重命名</button>
                  <button class="btn small danger del" title="删除">删除</button>
                </td>
              </tr>`; }).join('')
            : '<tr><td colspan="5" class="dim">这个文件夹还是空的，可以新建文件或拖拽上传。</td></tr>'}
        </tbody>
      </table>
    </div>
    <div style="margin-top:8px;font-size:12px;color:var(--text-dim)">仅可操作主目录 ${esc(home)} 内的文件；提示：可直接将文件拖拽到表格区域上传</div>`;

  $$('#crumbs a').forEach((a) => (a.onclick = () => loadDir(a.dataset.path)));
  const upBtn = $('#f-up');
  if (upBtn) upBtn.onclick = () => {
    const parent = state.currentPath.replace(/\/+[^/]+\/?$/, '');
    // Clamp at home: if parent escapes home, go home instead.
    if (parent === home || parent.startsWith(home + '/')) loadDir(parent);
    else loadDir(home);
  };
  $('#f-refresh').onclick = () => loadDir(state.currentPath);
  $('#f-mkdir').onclick = () => {
    const name = prompt('新目录名:');
    if (name === null || !validFileName(name)) return;
    api(fileUrl('/mkdir'), { method: 'POST', body: JSON.stringify({ path: joinRemote(state.currentPath, name) }) })
      .then(() => loadDir(state.currentPath))
      .catch((e) => toast(e.message, 'error'));
  };
  $('#f-new-file').onclick = async () => {
    const name = prompt('新文件名:');
    if (name === null || !validFileName(name)) return;
    const filePath = joinRemote(state.currentPath, name);
    try {
      await api(fileUrl('/new'), { method: 'POST', body: JSON.stringify({ path: filePath }) });
      if (state.activeId !== sessionId) return;
      await loadDir(state.currentPath);
      if (state.activeId === sessionId) openFileEditor(filePath);
    } catch (e) {
      toast('创建文件失败: ' + e.message, 'error');
    }
  };
  const input = $('#f-upload-input');
  $('#f-upload').onclick = () => {
    if (state.fileUploadActive) return toast('已有上传任务正在进行', 'error');
    input.click();
  };
  input.onchange = () => {
    if (input.files.length) uploadFiles([...input.files]);
    input.value = '';
  };

  const drop = $('#file-drop');
  drop.ondragover = (e) => { e.preventDefault(); drop.classList.add('dragover'); };
  drop.ondragleave = () => drop.classList.remove('dragover');
  drop.ondrop = (e) => {
    e.preventDefault();
    drop.classList.remove('dragover');
    const files = [...e.dataTransfer.files];
    if (files.length && !state.fileUploadActive) uploadFiles(files);
  };

  $$('#file-drop tbody tr').forEach((tr) => {
    if (!tr.dataset.path) return;
    const isDirectory = tr.dataset.dir === '1';
    const download = () => {
      const link = document.createElement('a');
      link.href = `/api/files/${sessionId}/download?path=${encodeURIComponent(tr.dataset.path)}`;
      link.download = tr.dataset.path.split('/').pop();
      document.body.appendChild(link);
      link.click();
      link.remove();
    };
    tr.querySelector('.file-open').onclick = () => {
      if (isDirectory) loadDir(tr.dataset.path);
      else if (tr.querySelector('.file-open').dataset.action === 'edit') openFileEditor(tr.dataset.path);
      else download();
    };
    tr.querySelector('.enter')?.addEventListener('click', () => loadDir(tr.dataset.path));
    tr.querySelector('.dl')?.addEventListener('click', download);
    tr.querySelector('.edit')?.addEventListener('click', (e) => {
      e.stopPropagation();
      openFileEditor(tr.dataset.path);
    });
    tr.querySelector('.rn')?.addEventListener('click', (e) => {
      e.stopPropagation();
      const cur = tr.dataset.path.split('/').filter(Boolean).pop();
      const newName = prompt('新名称:', cur);
      if (newName === null || newName === cur || !validFileName(newName)) return;
      const parent = tr.dataset.path.replace(/\/+[^/]+$/, '') || '/';
      api(fileUrl('/rename'), { method: 'POST', body: JSON.stringify({ from: tr.dataset.path, to: joinRemote(parent, newName) }) })
        .then(() => loadDir(state.currentPath))
        .catch((er) => toast(er.message, 'error'));
    });
    tr.querySelector('.del')?.addEventListener('click', async (e) => {
      e.stopPropagation();
      const p = tr.dataset.path;
      if (!confirm(`确定删除 ${p} ？${isDirectory ? '（文件夹及其中全部内容都会删除，无法撤销）' : '（文件将被删除，无法撤销）'}`)) return;
      try {
        await api(fileUrl('/delete'), { method: 'POST', body: JSON.stringify({ path: p }) });
        loadDir(state.currentPath);
      } catch (er) {
        toast(er.message, 'error');
      }
    });
  });
}

function joinRemote(dir, name) {
  if (!dir || dir === '/') return '/' + name;
  if (dir.endsWith('/')) return dir + name;
  return dir + '/' + name;
}

function setUploadProgress(index, total, file, loaded, size) {
  const box = $('#file-upload-progress');
  if (!box) return;
  const currentRatio = size > 0 ? Math.min(1, loaded / size) : 1;
  const overall = Math.min(100, ((index + currentRatio) / total) * 100);
  $('#file-upload-label').textContent = `上传中（${index + 1}/${total}）${file.name}`;
  $('#file-upload-percent').textContent = `${Math.round(overall)}%`;
  $('#file-upload-bar').style.width = `${overall}%`;
  $('#file-upload-detail').textContent = `当前文件 ${Math.round(currentRatio * 100)}% · ${fmtSize(loaded)} / ${fmtSize(size)}`;
  box.classList.remove('hidden');
}

function uploadFileWithProgress(file, dir, sessionId, index, total) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', `/api/files/${sessionId}/upload?path=${encodeURIComponent(dir)}&name=${encodeURIComponent(file.name)}`);
    xhr.withCredentials = true;
    xhr.setRequestHeader('Content-Type', file.type || 'application/octet-stream');
    xhr.upload.onprogress = (e) => {
      setUploadProgress(index, total, file, e.loaded, e.lengthComputable ? e.total : file.size);
    };
    xhr.onerror = () => reject(new Error('网络连接失败'));
    xhr.onabort = () => reject(new Error('上传已取消'));
    xhr.onload = () => {
      let data = null;
      try { data = JSON.parse(xhr.responseText || '{}'); } catch (e) { /* handled below */ }
      if (xhr.status >= 200 && xhr.status < 300 && data?.ok) {
        setUploadProgress(index, total, file, file.size, file.size);
        resolve(data);
      } else {
        reject(new Error(data?.error || `HTTP ${xhr.status}`));
      }
    };
    setUploadProgress(index, total, file, 0, file.size);
    xhr.send(file);
  });
}

async function uploadFiles(files) {
  if (state.fileUploadActive) return toast('已有上传任务正在进行', 'error');
  const queue = files.filter(Boolean);
  if (!queue.length || !state.activeId) return;
  state.fileUploadActive = true;
  const sessionId = state.activeId;
  let succeeded = 0;
  let failed = 0;
  try {
    for (let i = 0; i < queue.length; i++) {
      const f = queue[i];
      const relative = f.webkitRelativePath || '';
      const subdir = relative ? relative.slice(0, -f.name.length - 1) : '';
      const dir = subdir ? joinRemote(state.currentPath, subdir) : state.currentPath;
      try {
        await uploadFileWithProgress(f, dir, sessionId, i, queue.length);
        succeeded++;
      } catch (e) {
        failed++;
        toast(`上传 ${f.name} 失败: ${e.message}`, 'error');
      }
    }
  } finally {
    state.fileUploadActive = false;
    const box = $('#file-upload-progress');
    if (box) {
      $('#file-upload-label').textContent = failed ? '上传完成（部分失败）' : '上传完成';
      $('#file-upload-percent').textContent = '100%';
      $('#file-upload-bar').style.width = '100%';
      $('#file-upload-detail').textContent = `成功 ${succeeded} 个，失败 ${failed} 个`;
    }
    if (state.activeId === sessionId) await loadDir(state.currentPath);
  }
  if (succeeded && !failed) toast(`已上传 ${succeeded} 个文件`, 'ok');
}

/* ================= system ================= */

let systemRefreshPending = false;
async function refreshSystem() {
  if (!state.activeId || systemRefreshPending) return;
  const sessionId = state.activeId;
  systemRefreshPending = true;
  let data, monitor;
  try {
    [data, monitor] = await Promise.all([
      api('/api/info/' + sessionId),
      state.currentUser?.isAdmin ? api('/api/admin/monitor/' + sessionId).catch((e) => ({ error: e.message })) : Promise.resolve(null),
    ]);
  } catch (e) {
    if (state.activeId === sessionId && state.activeTab === 'system') $('#system-container').textContent = '读取系统信息失败：' + e.message;
    return;
  } finally { systemRefreshPending = false; }
  if (state.activeId !== sessionId || state.activeTab !== 'system') return;
  state.sysHistory.push({
    t: Date.now(),
    load1: data.load?.[0] ?? 0,
    memPct: data.memTotal ? (data.memUsed / data.memTotal) * 100 : 0,
  });
  if (state.sysHistory.length > 120) state.sysHistory.shift();

  const memPct = data.memTotal ? (data.memUsed / data.memTotal) * 100 : 0;
  const diskPct = data.diskPct ?? 0;
  const barCls = (v) => (v >= 90 ? 'critical' : v >= 70 ? 'hot' : '');

  const box = $('#system-container');
  const openAuditDetails = [...box.querySelectorAll('.audit-raw[open], .audit-rules[open]')].map((el) => el.className);
  box.innerHTML = `
    <div class="gpu-header"><b>系统信息</b><span class="meta">${esc(data.os)} | ${esc(data.hostname)} | 已运行 ${fmtUptime(data.uptimeSec)}</span></div>
    <div class="sys-grid">
      <div class="sys-card">
        <h4>CPU 负载 (${data.cpuCount ?? '-'} 核)</h4>
        <div class="big">${data.load?.[0] ?? '-'} / ${data.load?.[1] ?? '-'} / ${data.load?.[2] ?? '-'}</div>
        <div class="sub">1min / 5min / 15min</div>
        <div class="metric-row" style="margin-top:12px">
          <div class="bar"><i class="${barCls(((data.load?.[0] ?? 0) / (data.cpuCount || 1)) * 100)}" style="width:${Math.min(100, ((data.load?.[0] ?? 0) / (data.cpuCount || 1)) * 100)}%"></i></div>
        </div>
      </div>
      <div class="sys-card">
        <h4>内存</h4>
        <div class="big">${fmtMB(data.memUsed)} <span style="font-size:13px;color:var(--text-dim)">/ ${fmtMB(data.memTotal)}</span></div>
        <div class="bar"><i class="${barCls(memPct)}" style="width:${memPct.toFixed(1)}%"></i></div>
        <div class="sub">可用 ${fmtMB(data.memFree)} | 使用率 ${memPct.toFixed(1)}%</div>
      </div>
      <div class="sys-card">
        <h4>磁盘 (/)</h4>
        <div class="big">${fmtMB(data.diskUsed)} <span style="font-size:13px;color:var(--text-dim)">/ ${fmtMB(data.diskTotal)}</span></div>
        <div class="bar"><i class="${barCls(diskPct)}" style="width:${diskPct}%"></i></div>
        <div class="sub">使用率 ${diskPct}%</div>
        ${state.currentUser?.isAdmin ? '<button class="btn small" data-act="disk-users" style="margin-top:12px">查看各用户磁盘占用</button>' : ''}
      </div>
    </div>
    <div class="gpu-charts" style="margin-top:16px">
      <div class="chart-box">
        <h4>负载趋势 (1min)</h4>
        <canvas id="chart-load"></canvas>
      </div>
      <div class="chart-box">
        <h4>内存使用率趋势 (%)</h4>
        <canvas id="chart-mem"></canvas>
      </div>
    </div>`;

  if (monitor) box.insertAdjacentHTML('afterbegin', renderAdminMonitor(monitor));
  box.querySelector('[data-act="disk-users"]')?.addEventListener('click', () => {
    const server = state.servers.find((s) => s.sessionId === sessionId);
    if (server) openDiskUsage(server);
  });
  for (const className of openAuditDetails) box.querySelector('.' + className)?.setAttribute('open', '');
  drawLineChart($('#chart-load'), [state.sysHistory.map((p) => p.load1)], [GPU_COLORS[0]], null, '');
  drawLineChart($('#chart-mem'), [state.sysHistory.map((p) => p.memPct)], [GPU_COLORS[1]], 100, '%');
}

const auditLabels = { normal: '正常', warning: '可疑', critical: '高风险', unknown: '待确认' };
function auditState(server) {
  const data = server.auditMonitor;
  if (!server.sessionId) return { level: 'unknown', message: '未连接，无法审计' };
  if (server.statusError) return { level: 'unknown', message: '连接状态读取失败，等待重试' };
  if (!data || data.sessionId !== server.sessionId) return { level: 'unknown', message: '等待首次采集' };
  if (data.error) return { level: 'unknown', message: '采集失败：' + data.error };
  if (!data.audit) return { level: 'unknown', message: '后端未返回审计数据，请重启服务并刷新页面' };
  if (Date.now() - data.collectedAt > 30000) return { level: 'unknown', message: '数据已过期，等待重新采集' };
  return { level: data.audit?.level || 'unknown', message: data.audit?.reasons[0]?.message || (data.audit?.complete ? '未触发异常规则' : (data.audit?.issues?.[0]?.message?.slice(0, 120) || '审计数据不完整，请查看详情')) };
}

function renderSshAudit(data) {
  const a = data.audit;
  if (!a) return '<p class="audit-badge audit-unknown">SSH 审计数据不可用</p>';
  const metric = (label, value) => `<div class="audit-metric"><span>${label}</span><strong>${value == null ? '—' : value}</strong></div>`;
  return `<section class="ssh-audit audit-${a.level}">
    <div class="audit-heading"><div><h3>SSH 安全审计</h3><span class="dim">${esc(new Date(data.collectedAt).toLocaleTimeString())} 更新 · 每约 5 秒自动检查</span></div><span class="audit-badge audit-${a.level}">${auditLabels[a.level]}</span></div>
    <div class="audit-metrics">${metric('当前 SSH 连接', a.connectionCount)}${metric('失败登录 / 最近一小时', a.failureCount == null ? null : `${a.truncated ? '≥' : ''}${a.failureCount}`)}${metric('已观测来源', a.sources.length)}</div>
    <p><span class="audit-badge audit-${a.connectionLevel || 'unknown'}">连接检查：${a.connectionLevel === 'normal' ? '未触发异常规则' : auditLabels[a.connectionLevel || 'unknown']}</span> <span class="dim">${data.failures?.available ? '失败日志来源：' + esc(data.failures.source || 'lastb') : '失败登录检查：日志不可用'}</span></p>
    <div class="audit-findings">${a.reasons.length ? a.reasons.map((r) => `<p class="audit-badge audit-${r.level}">${esc(r.message)}</p>`).join('') : `<p>${a.complete ? '✓ 当前未触发异常规则' : '审计不完整，暂不能判定为正常'}</p>`}
    ${!a.complete ? `<p class="audit-incomplete">部分数据不可用：${esc(a.missing.map((k) => k === 'failures' ? '失败登录日志' : 'SSH 连接').join('、'))}${a.unparsed ? ` · ${a.unparsed} 行无法解析` : ''}。已检测到的异常仍会显示。</p>${(a.issues || []).map((issue) => `<p class="audit-incomplete">${esc(issue.message)}</p>${issue.hint ? `<p>${esc(issue.hint)}</p>` : ''}`).join('')}` : ''}</div>
    <h4>来源分布</h4><div class="file-table-wrap"><table><thead><tr><th>来源 IP</th><th>当前连接</th><th>一小时失败次数</th><th>状态</th></tr></thead><tbody>
    ${a.sources.map((source) => `<tr class="audit-source-${source.level}"><td>${esc(source.address)}</td><td>${a.connectionCount == null ? '—' : source.connections}</td><td><div class="audit-frequency"><i style="width:${Math.min(100, source.failures / 20 * 100)}%"></i><span>${a.failureCount == null ? '—' : source.failures}</span></div></td><td><span class="audit-badge audit-${source.level === 'normal' && !a.complete ? 'unknown' : source.level}">${source.level === 'normal' ? (a.complete ? '未触发规则' : '数据不完整') : auditLabels[source.level]}</span></td></tr>`).join('') || '<tr><td colspan="4">暂无来源数据</td></tr>'}
    </tbody></table></div>
    <details class="audit-rules"><summary>判定规则与采集范围</summary><p>${esc(a.rules)}</p><p>优先读取最多 200 条失败登录记录；不可用时尝试读取最近一小时的系统 SSH 日志（最多 5000 条日志）。达到上限时显示下界。灰色表示未连接、采集失败或数据不足；颜色表示规则告警，不代表已确认入侵。此面板按当前快照判定，不自动封禁 IP，也不保存历史审计记录。</p></details>
  </section>`;
}

function renderAdminMonitor(data) {
  if (data.error) return `<p class="audit-badge audit-unknown">SSH 审计待确认 · 采集失败：${esc(data.error)}</p>`;
  const raw = (section, empty) => section?.available
    ? `<pre class="monitor-output">${esc(section.text || empty)}</pre>`
    : `<p class="dim">无法读取：${esc(section?.error || '数据不可用')}</p>`;
  const rows = (data.processes?.items || []).map((p) => `<tr><td>${esc(p.user)}</td><td>${p.pid}</td><td>${p.cpu}%</td><td>${p.memory}%</td><td>${esc(p.command)}</td></tr>`).join('');
  return `<section class="admin-monitor">
    ${renderSshAudit(data)}
    <details class="audit-raw"><summary>查看 SSH 原始采集记录与平台连接</summary>
    <p class="dim">采集于 ${esc(new Date(data.collectedAt).toLocaleTimeString())}，约每 5 秒刷新。可见范围取决于当前 SSH 用户权限。</p>
    <h4>SSH TCP 连接（远端端口 ${data.port}）</h4>
    <p class="dim">列：接收队列 / 发送队列 / 本地地址 / 来源地址。含尚未认证的连接；端口转发环境下端口可能与远端监听端口不同。</p>
    ${raw(data.connections, '当前没有连接')}
    <h4>已登录会话（用户、终端、登录时间、来源）</h4>
    ${raw(data.logins, '当前没有终端登录记录（无终端的 SSH 会话不在此列）')}
    <h4>最近一小时失败登录 · ${esc(data.failures?.source || '日志不可用')}</h4>
    ${raw(data.failures, '当前没有失败登录记录')}
    <p class="dim">失败日志通常需要 root 或日志读取权限，记录取决于服务器配置；此页面用于排查异常，不会自动封禁来源 IP。</p>
    <h4>本平台到这台机器的连接</h4>
    <div class="file-table-wrap"><table><thead><tr><th>平台用户</th><th>SSH 用户</th><th>连接时间</th></tr></thead><tbody>
    ${(data.webSessions || []).map((s) => `<tr><td>${esc(s.webUser)}</td><td>${esc(s.username)}</td><td>${esc(new Date(s.createdAt).toLocaleString())}</td></tr>`).join('')}
    </tbody></table></div>
    </details>
    <h4>CPU 占用最高的 30 个进程</h4>
    <p class="dim">CPU 为 ps 报告的进程生命周期平均占用，多线程进程可超过 100%；内存为物理内存占比。</p>
    ${data.processes?.available ? `<div class="file-table-wrap"><table><thead><tr><th>所属用户</th><th>PID</th><th>CPU</th><th>内存</th><th>进程</th></tr></thead><tbody>${rows || '<tr><td colspan="5">没有进程数据</td></tr>'}</tbody></table></div>` : raw(data.processes, '')}
  </section>`;
}

/* ================= import from ssh config ================= */

function globMatch(pattern, host) {
  if (pattern === host) return true;
  if (!pattern.includes('*') && !pattern.includes('?')) return false;
  const re = new RegExp(
    '^' + pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$'
  );
  return re.test(host);
}

function parseSshConfig(text) {
  const blocks = [];
  let cur = null;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const m = /^([A-Za-z][A-Za-z0-9_-]*)\s+(.+)$/.exec(line);
    if (!m) continue;
    const key = m[1].toLowerCase();
    const val = m[2].trim().replace(/^["']|["']$/g, '');
    if (key === 'host') {
      cur = { patterns: val.split(/\s+/), opts: {} };
      blocks.push(cur);
    } else if (cur) {
      cur.opts[key] = cur.opts[key] ? cur.opts[key] + ' ' + val : val;
    }
  }
  const first = (o, k) => (o[k] || '').split(/\s+/)[0] || null;

  const servers = [];
  const seen = new Set();
  for (const b of blocks) {
    const host = first(b.opts, 'hostname');
    const user = first(b.opts, 'user');
    if (!host || !user) continue;
    if (b.patterns.some((p) => p.includes('*') || p.includes('?'))) continue;
    const port = parseInt(first(b.opts, 'port') || '22', 10) || 22;
    const dedupeKey = host + ':' + port + '|' + user;
    const dup = seen.has(dedupeKey);
    seen.add(dedupeKey);

    const s = {
      label: b.patterns[0],
      host,
      port,
      username: user,
      creds: { password: null, privateKey: null, passphrase: null, sudoPassword: null, keyRef: null },
      algorithms: null,
      _dup: dup,
    };

    const idf = first(b.opts, 'identityfile');
    if (idf) {
      const name = idf.replace(/^~\/?/, '').split('/').pop();
      if (/^[A-Za-z0-9._-]+$/.test(name)) s.creds.keyRef = name;
    }

    // Merge algorithm overrides from every block whose patterns match this host.
    const alg = {};
    for (const b2 of blocks) {
      if (!b2.patterns.some((p) => globMatch(p, host))) continue;
      const clean = (v) => (v || '').replace(/\+/g, '').split(/[,\s]+/).filter(Boolean);
      const kex = clean(b2.opts.kexalgorithms);
      const hk = clean(b2.opts.hostkeyalgorithms);
      const ci = clean(b2.opts.ciphers);
      const ma = clean(b2.opts.macs);
      if (kex.length) alg.kex = [...new Set([...(alg.kex || []), ...kex])];
      if (hk.length) alg.serverHostKey = [...new Set([...(alg.serverHostKey || []), ...hk])];
      if (ci.length) alg.cipher = [...new Set([...(alg.cipher || []), ...ci])];
      if (ma.length) alg.hmac = [...new Set([...(alg.hmac || []), ...ma])];
    }
    if (Object.keys(alg).length) s.algorithms = alg;

    servers.push(s);
  }
  return servers;
}

let importParsed = [];

function openImportModal() {
  if (!state.currentUser?.isAdmin) return;
  $('#import-text').value = '';
  importParsed = [];
  $('#import-preview').classList.add('hidden');
  $('#btn-import-confirm').disabled = true;
  $('#btn-import-confirm').textContent = 'Import';
  $('#import-modal').classList.remove('hidden');
}

function closeImportModal() {
  $('#import-modal').classList.add('hidden');
}

$('#btn-import-server').onclick = openImportModal;
$('#btn-import-close').onclick = closeImportModal;
$('#btn-import-cancel').onclick = closeImportModal;

$('#btn-import-load-config').onclick = async () => {
  try {
    const data = await api('/api/ssh-config');
    $('#import-text').value = data.content;
    parseImportText();
  } catch (e) {
    toast(e.message, 'error');
  }
};

$('#import-text').addEventListener('input', () => parseImportText());

function parseImportText() {
  importParsed = parseSshConfig($('#import-text').value);
  renderImportPreview();
}

function renderImportPreview() {
  const box = $('#import-preview');
  const btn = $('#btn-import-confirm');
  if (!importParsed.length) {
    box.innerHTML = '<div style="padding:14px" class="dim">未解析到服务器（需要 Host/HostName/User 字段）</div>';
    box.classList.remove('hidden');
    btn.disabled = true;
    return;
  }
  const usable = importParsed.filter((s) => !s._dup).length;
  box.innerHTML = `
    <table>
      <thead><tr><th>标签</th><th>地址</th><th>用户</th><th>凭据 / 选项</th></tr></thead>
      <tbody>
        ${importParsed.map((s) => `
          <tr style="${s._dup ? 'opacity:.45' : ''}">
            <td>${esc(s.label)}</td>
            <td class="mono">${esc(s.host)}:${s.port}</td>
            <td>${esc(s.username)}</td>
            <td>
              ${s.creds.keyRef ? `<span class="tag key">本机密钥 ${esc(s.creds.keyRef)}</span>` : '<span class="tag dup">无密钥，需补密码</span>'}
              ${s.algorithms ? '<span class="tag algo">旧版算法</span>' : ''}
              ${s._dup ? '<span class="tag dup">重复，跳过</span>' : ''}
            </td>
          </tr>`).join('')}
      </tbody>
    </table>`;
  box.classList.remove('hidden');
  btn.disabled = !usable;
  btn.textContent = `导入 ${usable} 台服务器`;
}

async function runWithConcurrency(items, n, fn) {
  const q = [...items];
  await Promise.all(
    Array.from({ length: Math.max(1, Math.min(n, q.length)) }, async () => {
      while (q.length) {
        const it = q.shift();
        if (it) await fn(it);
      }
    })
  );
}

$('#btn-import-confirm').onclick = async () => {
  const usable = importParsed.filter((s) => !s._dup);
  const newServers = [];
  for (const s of usable) {
    if (state.servers.some((x) => x.host === s.host && x.port === s.port)) continue;
    const server = { uid: newUid(), label: s.label, host: s.host, port: s.port, algorithms: s.algorithms, mine: { username: s.username, creds: s.creds }, sessionId: null, connecting: false };
    state.servers.push(server);
    newServers.push(server);
  }
  if (!newServers.length) {
    toast('这些服务器都已导入过', 'error');
    return;
  }
  for (const s of newServers) {
    try {
      await persistServer(s);
      await api(`/api/servers/${encodeURIComponent(s.uid)}/creds`, { method: 'POST', body: JSON.stringify(s.mine) });
    } catch (e) { toast(`Save ${s.label} failed: ${e.message}`, 'error'); }
  }
  renderDashboard();
  closeImportModal();
  toast(`已导入 ${newServers.length} 台服务器，正在连接测试...`, 'ok');
  const queue = state.servers.filter((s) => !s.sessionId && !s.connecting);
  await runWithConcurrency(queue, 4, (s) => connectServer(s, { silent: true }));
  renderDashboard();
  toast('连接测试完成，请在仪表盘查看各服务器状态');
};

/* ================= boot ================= */

(async function boot() {
  const flow = authFlow;
  try {
    const data = await api('/api/auth/me');
    if (flow !== authFlow) return;
    await enterApp(data.user, flow);
  } catch (e) {
    if (flow !== authFlow || state.currentUser) return;
    showLoginPage();
    $('#login-username').focus();
  }
})();


/* Administrator-only, on-demand disk ownership visualization. */
const diskDialog = document.createElement('dialog');
diskDialog.id = 'disk-usage-dialog';
diskDialog.className = 'disk-dialog';
diskDialog.setAttribute('aria-labelledby', 'disk-usage-title');
document.body.appendChild(diskDialog);
let diskViewRequest = 0;
diskDialog.addEventListener('close', () => { diskViewRequest++; });
function diskBytes(value) {
  const n = Math.max(0, Number(value) || 0);
  if (n < 1024) return n + ' B';
  const unit = Math.min(4, Math.floor(Math.log(n) / Math.log(1024)));
  return (n / 1024 ** unit).toFixed(1) + ' ' + ['B', 'KiB', 'MiB', 'GiB', 'TiB'][unit];
}
async function openDiskUsage(server) {
  if (!state.currentUser?.isAdmin || !server.sessionId) return;
  const request = ++diskViewRequest;
  diskDialog.innerHTML = `<div class="disk-heading"><h3 id="disk-usage-title">${esc(serverLabel(server))} · 用户系统盘占用</h3><button class="btn" id="disk-close">关闭</button></div>
    <p class="dim">统计根文件系统 /，按文件所属 UID 归属；包含系统用户，不包含独立挂载的数据盘。点击后扫描，结果缓存 5 分钟。</p>
    <div id="disk-usage-result" aria-live="polite"><p><span class="spin"></span> 正在扫描，最多约 90 秒。关闭窗口不影响扫描，可稍后重新查看。</p></div>`;
  diskDialog.querySelector('#disk-close').onclick = () => diskDialog.close();
  if (!diskDialog.open) diskDialog.showModal();
  const result = diskDialog.querySelector('#disk-usage-result');
  try {
    const data = await api('/api/admin/disk-usage/' + encodeURIComponent(server.sessionId));
    if (request !== diskViewRequest || !diskDialog.open || !state.currentUser?.isAdmin) return;
    const scanned = data.users.reduce((sum, row) => sum + row.bytes, 0);
    const percent = (bytes) => data.total ? Math.min(100, bytes / data.total * 100) : 0;
    result.innerHTML = `<p class="disk-notice ${data.complete ? '' : 'disk-partial'}">${data.complete ? '扫描完成' : '部分统计：已读到的占用仅为下界'} · ${esc(new Date(data.collectedAt).toLocaleString())} · 耗时 ${data.duration} 秒
      ${!data.privileged ? '<br>当前 SSH 用户不是 root，无法确认全盘可见性；平台管理员权限不等于远端 root。完整统计需要使用有读取权限的 SSH 账号或已有的免密 sudo 权限。' : ''}
      ${data.errors ? `<br>${data.errors} 个读取错误（可能为权限不足或扫描期间文件发生变化）。` : ''}
      ${data.limited ? '<br>已达到扫描时间、条目数或内存保护上限。' : ''}</p>
      <div class="disk-totals"><span>总容量 <b>${diskBytes(data.total)}</b></span><span>文件系统已用 <b>${diskBytes(data.used)}</b></span><span>已归属用户 <b>${diskBytes(scanned)}</b></span><span>可用 <b>${diskBytes(data.available)}</b></span></div>
      <div class="bar disk-total-bar" aria-label="系统盘使用率 ${percent(data.used).toFixed(1)}%"><i style="width:${percent(data.used)}%"></i></div>
      <p class="dim">按已分配磁盘块统计，硬链接只计一次，不跟随符号链接。文件系统元数据、已删除但仍打开的文件、快照及扫描期间的变化，会导致汇总与系统已用容量不同。</p>
      <label class="disk-filter"><input type="checkbox" id="disk-show-zero"> 显示未观测到占用的用户（${data.users.filter(r => !r.bytes).length}）</label>
      <div class="file-table-wrap"><table class="disk-users-table"><thead><tr><th>远端用户 / UID</th><th>磁盘占用</th><th>占系统盘总容量</th></tr></thead><tbody></tbody></table></div>
      <p class="dim">${data.complete ? '0 表示本次扫描未观测到占用。' : '未观测到占用不代表实际为 0。'} 此视图只读取统计，不修改文件或权限。</p>`;
    const renderRows = () => {
      const rows = data.users.filter(row => row.bytes || result.querySelector('#disk-show-zero').checked);
      result.querySelector('tbody').innerHTML = rows.map(row => `<tr><td>${esc(row.user)} <span class="dim">(${row.uid})</span></td><td>${!row.bytes && !data.complete ? '未观测到' : diskBytes(row.bytes)}</td><td><div class="disk-user-meter"><div class="bar"><i style="width:${percent(row.bytes)}%"></i></div><span>${row.bytes && percent(row.bytes) < 0.1 ? '<0.1' : percent(row.bytes).toFixed(1)}%</span></div></td></tr>`).join('') || '<tr><td colspan="3">未观测到用户占用数据。</td></tr>';
    };
    result.querySelector('#disk-show-zero').onchange = renderRows;
    renderRows();
  } catch (error) {
    if (request !== diskViewRequest || !diskDialog.open) return;
    result.innerHTML = `<p role="alert">${esc(error.message)}</p><button class="btn" id="disk-retry">重试</button>`;
    result.querySelector('#disk-retry').onclick = () => openDiskUsage(server);
  }
}
