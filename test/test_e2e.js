'use strict';
/* E2E test against the mock paramiko SSH server on 127.0.0.1:2222 */
const WebSocket = require('ws');

const BASE = 'http://127.0.0.1:8080';
let passed = 0, failed = 0;
let cookie = '';

function check(name, cond, extra = '') {
  if (cond) { passed++; console.log(`  ok  ${name}`); }
  else { failed++; console.log(`FAIL  ${name} ${extra}`); }
}

async function api(url, opts = {}) {
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  if (cookie) headers.Cookie = cookie;
  const res = await fetch(BASE + url, {
    ...opts,
    headers,
  });
  const setCookie = res.headers.get('set-cookie');
  if (setCookie) cookie = setCookie.split(';')[0];
  let data = null;
  try { data = await res.json(); } catch (e) { /* ignore */ }
  return { status: res.status, data };
}

async function main() {
  console.log('0. auth');
  const protectedBeforeLogin = await api('/api/servers');
  check('protected before login', protectedBeforeLogin.status === 401);
  let auth = await api('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username: 'admin', password: 'wrong-password' }),
  });
  check('bad login rejected', auth.status === 401);
  auth = await api('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username: 'admin', password: 'changeme' }),
  });
  check('admin login ok', auth.status === 200 && auth.data.user?.isAdmin === true);
  let me = await api('/api/auth/me');
  check('current user is admin', me.status === 200 && me.data.user?.username === 'admin');
  const isolatedUid = 'e2e-isolated-' + Date.now();
  const newUsername = 'e2euser' + Date.now();
  let reg = await api('/api/auth/register', {
    method: 'POST',
    body: JSON.stringify({ username: newUsername, password: 'e2e-pass-123' }),
  });
  check('admin can register user', reg.status === 200 && reg.data.ok === true);
  await api('/api/auth/logout', { method: 'POST' });
  auth = await api('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username: newUsername, password: 'e2e-pass-123' }),
  });
  check('new user login ok', auth.status === 200 && auth.data.user?.isAdmin === false);
  let ownServers = await api('/api/servers');
  check('new user starts with no servers', ownServers.status === 200 && ownServers.data.servers.length === 0);
  reg = await api('/api/servers', {
    method: 'POST',
    body: JSON.stringify({ uid: isolatedUid, label: 'isolated', host: 'isolated.example', port: 22, username: 'user', creds: {} }),
  });
  check('new user saves own server', reg.status === 200 && reg.data.ok === true);
  await api('/api/auth/logout', { method: 'POST' });
  auth = await api('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username: 'admin', password: 'changeme' }),
  });
  check('admin can log back in', auth.status === 200);
  ownServers = await api('/api/servers');
  check('admin cannot see other user server', ownServers.status === 200 && !ownServers.data.servers.some((s) => s.uid === isolatedUid));

  console.log('1. connect');
  const { status, data } = await api('/api/connect', {
    method: 'POST',
    body: JSON.stringify({
      host: '127.0.0.1', port: 2222, username: 'testuser',
      password: 'testpass', sudoPassword: 's3cret',
    }),
  });
  check('connect returns session', status === 200 && data.ok && data.sessionId, JSON.stringify(data));
  const id = data.sessionId;

  const bad = await api('/api/connect', {
    method: 'POST',
    body: JSON.stringify({ host: '127.0.0.1', port: 2222, username: 'testuser', password: 'wrong' }),
  });
  check('bad SSH password rejected without looking like web auth failure', bad.status === 502, JSON.stringify(bad.data));

  console.log('2. sessions');
  const sess = await api('/api/sessions');
  check('sessions listed', sess.status === 200 && sess.data.sessions.length === 1);

  console.log('3. gpu');
  const gpu = await api('/api/gpu/' + id);
  check('gpu available', gpu.data.available === true, JSON.stringify(gpu.data));
  check('gpu count=2', gpu.data.gpus?.length === 2);
  check('gpu0 util=73', gpu.data.gpus?.[0]?.util === 73);
  check('gpu0 mem 40960/81920', gpu.data.gpus?.[0]?.memUsed === 40960 && gpu.data.gpus?.[0]?.memTotal === 81920);
  check('gpu0 temp=58', gpu.data.gpus?.[0]?.temp === 58);
  check('gpu0 power=250.5', gpu.data.gpus?.[0]?.power === 250.5);
  check('gpu process python 1234', gpu.data.processes?.[0]?.pid === '1234' && gpu.data.processes?.[0]?.name === 'python');

  console.log('4. system info');
  const info = await api('/api/info/' + id);
  check('load parsed', info.data.load?.[0] === 0.52 && info.data.load?.[2] === 0.91, JSON.stringify(info.data));
  check('cpu=64', info.data.cpuCount === 64);
  check('mem 204800/512000', info.data.memUsed === 204800 && info.data.memTotal === 512000);
  check('disk 50%', info.data.diskPct === 50 && info.data.diskUsed === 512000);
  check('os parsed', info.data.os === 'Ubuntu 22.04.4 LTS');
  check('uptime 90061s', info.data.uptimeSec === 90061);
  check('hostname', info.data.hostname === 'mock-gpu-node');

  console.log('5. files: list (jailed to home)');
  // Default list returns the session's home dir.
  let fl = await api(`/api/files/${id}`);
  const homeDir = fl.data.homeDir;
  check('home listed by default', fl.status === 200 && !!homeDir && Array.isArray(fl.data.items), JSON.stringify(fl.data));

  console.log('6. files: upload + download roundtrip (home-relative)');
  const payload = Buffer.from('web-ssh e2e upload test ' + Date.now());
  const up = await fetch(`${BASE}/api/files/${id}/upload?path=.&name=e2e.bin`, { method: 'POST', body: payload, headers: { Cookie: cookie } });
  const upData = await up.json();
  check('upload ok', up.status === 200 && upData.ok === true, JSON.stringify(upData));
  const dl = await fetch(`${BASE}/api/files/${id}/download?path=e2e.bin`, { headers: { Cookie: cookie } });
  const dlBuf = Buffer.from(await dl.arrayBuffer());
  check('download matches', dl.status === 200 && dlBuf.equals(payload));

  console.log('6b. files: text editor read + save');
  let ed = await api(`/api/files/${id}/edit?path=e2e.bin`);
  check('editor reads text', ed.status === 200 && ed.data.content === payload.toString());
  const originalVersion = ed.data.version;
  const edited = 'web-ssh editor save test ' + Date.now() + '\nsecond line';
  ed = await api(`/api/files/${id}/edit`, {
    method: 'POST',
    body: JSON.stringify({ path: 'e2e.bin', content: edited, version: originalVersion }),
  });
  check('editor saves text', ed.status === 200 && ed.data.ok === true);
  const savedVersion = ed.data.version;
  const externalEdit = edited + '\nexternal update';
  ed = await api(`/api/files/${id}/edit`, {
    method: 'POST',
    body: JSON.stringify({ path: 'e2e.bin', content: externalEdit, version: savedVersion }),
  });
  check('editor saves second change', ed.status === 200 && ed.data.ok === true);
  const stale = await api(`/api/files/${id}/edit`, {
    method: 'POST',
    body: JSON.stringify({ path: 'e2e.bin', content: 'stale overwrite', version: savedVersion }),
  });
  check('stale editor save rejected', stale.status === 409);
  const editedDl = await fetch(`${BASE}/api/files/${id}/download?path=e2e.bin`, { headers: { Cookie: cookie } });
  const editedBuf = Buffer.from(await editedDl.arrayBuffer());
  check('saved content matches', editedDl.status === 200 && editedBuf.toString() === externalEdit);

  console.log('7. files: mkdir/rename/delete (home-relative)');
  const uniq = 'e2e_' + Date.now();
  let r = await api(`/api/files/${id}/mkdir`, { method: 'POST', body: JSON.stringify({ path: uniq }) });
  check('mkdir ok', r.status === 200 && r.data.ok, JSON.stringify(r.data));
  fl = await api(`/api/files/${id}`);
  check('newdir listed', fl.data.items.some((i) => i.name === uniq && i.isDirectory));
  r = await api(`/api/files/${id}/rename`, { method: 'POST', body: JSON.stringify({ from: 'e2e.bin', to: uniq + '.bin' }) });
  check('rename ok', r.status === 200 && r.data.ok);
  fl = await api(`/api/files/${id}`);
  check('renamed listed', fl.data.items.some((i) => i.name === uniq + '.bin'));
  r = await api(`/api/files/${id}/delete`, { method: 'POST', body: JSON.stringify({ path: uniq + '.bin' }) });
  check('delete file ok', r.status === 200 && r.data.ok);
  r = await api(`/api/files/${id}/delete`, { method: 'POST', body: JSON.stringify({ path: uniq }) });
  check('delete dir ok', r.status === 200 && r.data.ok);

  console.log('7b. files: jail enforcement');
  // Absolute path outside home (e.g. /etc) must be refused.
  let j = await api(`/api/files/${id}?path=/etc`);
  check('list /etc refused', j.status === 403, JSON.stringify(j.data));
  j = await api(`/api/files/${id}/download?path=/etc/passwd`);
  check('download /etc/passwd refused', j.status === 403);
  j = await api(`/api/files/${id}/delete`, { method: 'POST', body: JSON.stringify({ path: '/etc/hostname' }) });
  check('delete outside home refused', j.status === 403);
  j = await api(`/api/files/${id}/mkdir`, { method: 'POST', body: JSON.stringify({ path: '/tmp/x' }) });
  check('mkdir outside home refused', j.status === 403);
  j = await api(`/api/files/${id}/rename`, { method: 'POST', body: JSON.stringify({ from: 'e2e.bin', to: '/tmp/e2e.bin' }) });
  check('rename out of home refused', j.status === 403);
  // A path in the SFTP root but outside home (the mock's /hello.txt) must be refused.
  j = await api(`/api/files/${id}?path=/hello.txt`);
  check('list outside-home file refused', j.status === 403, JSON.stringify(j.data));
  // Dot-dot traversal must be refused.
  j = await api(`/api/files/${id}?path=../etc`);
  check('list ../etc refused', j.status === 403, JSON.stringify(j.data));
  j = await api(`/api/files/${id}/delete`, { method: 'POST', body: JSON.stringify({ path: '..' }) });
  check('delete .. refused', j.status === 403);
  // Deleting home itself must be refused.
  j = await api(`/api/files/${id}/delete`, { method: 'POST', body: JSON.stringify({ path: homeDir }) });
  check('delete home itself refused', j.status === 403, JSON.stringify(j.data));

  console.log('8. exec + sudo');
  r = await api('/api/exec', { method: 'POST', body: JSON.stringify({ sessionId: id, command: 'whoami' }) });
  check('exec ok', r.status === 200 && r.data.stdout.includes('mock-exec: whoami'), JSON.stringify(r.data));
  r = await api('/api/exec', { method: 'POST', body: JSON.stringify({ sessionId: id, command: 'whoami', sudo: true }) });
  check('sudo exec wraps password', r.status === 200 && r.data.stdout.includes("echo 's3cret' | sudo -S"), JSON.stringify(r.data));
  r = await api('/api/exec', { method: 'POST', body: JSON.stringify({ sessionId: 'nope', command: 'whoami' }) });
  check('exec bad session 404', r.status === 404);

  console.log('9. terminal websocket');
  await new Promise((resolve) => {
    const ws = new WebSocket(`ws://127.0.0.1:8080/ws/terminal?sessionId=${id}&cols=100&rows=30`, { headers: { Cookie: cookie } });
    let ready = false, gotEcho = false;
    const done = (ok) => { check('terminal ws roundtrip', ok && ready && gotEcho); ws.close(); resolve(); };
    const timer = setTimeout(() => done(false), 8000);
    ws.on('open', () => {
      ws.send(JSON.stringify({ type: 'input', data: 'hello-term' }));
      ws.send(JSON.stringify({ type: 'resize', cols: 120, rows: 40 }));
    });
    ws.on('message', (m) => {
      const s = m.toString();
      if (s.includes('"ready"')) ready = true;
      if (s.includes('hello-term')) { gotEcho = true; clearTimeout(timer); done(true); }
    });
    ws.on('error', () => { clearTimeout(timer); done(false); });
  });

  console.log('10. terminal bad session');
  await new Promise((resolve) => {
    const ws = new WebSocket('ws://127.0.0.1:8080/ws/terminal?sessionId=bad', { headers: { Cookie: cookie } });
    ws.on('message', (m) => {
      check('terminal rejects bad session', m.toString().includes('error'));
      ws.close(); resolve();
    });
    ws.on('close', resolve);
    ws.on('error', () => resolve());
  });

  console.log('11. disconnect');
  r = await api('/api/sessions/' + id, { method: 'DELETE' });
  check('disconnect ok', r.status === 200 && r.data.ok);
  const gpu2 = await api('/api/gpu/' + id);
  check('gpu 404 after disconnect', gpu2.status === 404);

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
}

main().catch((e) => { console.error('E2E crashed:', e); process.exit(1); });
