'use strict';

// Fixed, read-only collector. Never interpolate browser paths or user names.
const script = String.raw`
import os, stat, pwd, json, signal, time
started = time.time()
root = os.lstat('/')
fs = os.statvfs('/')
users = {}
for p in pwd.getpwall():
    users[p.pw_uid] = {'uid': p.pw_uid, 'user': p.pw_name, 'bytes': 0, 'files': 0}
errors = 0
limited = False
seen = set()
mounts = set()
try:
    with open('/proc/self/mountinfo') as f:
        for line in f:
            path = line.split()[4]
            for a,b in [('\\040',' '),('\\011','\t'),('\\012','\n'),('\\134','\\')]:
                path = path.replace(a,b)
            if path != '/': mounts.add(path)
except OSError:
    errors += 1
class ScanTimeout(Exception): pass
def expire(*args): raise ScanTimeout()
signal.signal(signal.SIGALRM, expire)
signal.alarm(90)
try:
    try: os.nice(15)
    except OSError: pass
    pending = ['/']
    visited = 0
    def account(s):
        global visited
        visited += 1
        if visited > 2000000 or len(seen) > 500000 or len(pending) > 200000: raise ScanTimeout()
        if not stat.S_ISDIR(s.st_mode) and s.st_nlink > 1:
            key = (s.st_dev, s.st_ino)
            if key in seen: return
            seen.add(key)
        row = users.setdefault(s.st_uid, {'uid': s.st_uid, 'user': 'UID ' + str(s.st_uid), 'bytes': 0, 'files': 0})
        row['bytes'] += s.st_blocks * 512
        row['files'] += 1
    account(root)
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    try:
                        s = entry.stat(follow_symlinks=False)
                        if s.st_dev != root.st_dev or entry.path in mounts: continue
                        account(s)
                        if stat.S_ISDIR(s.st_mode): pending.append(entry.path)
                    except OSError: errors += 1
        except OSError: errors += 1
except ScanTimeout:
    limited = True
finally:
    signal.alarm(0)
print(json.dumps({'users': sorted(users.values(), key=lambda r: (-r['bytes'], r['uid'])), 'total': fs.f_blocks * fs.f_frsize, 'used': (fs.f_blocks-fs.f_bfree)*fs.f_frsize, 'available': fs.f_bavail*fs.f_frsize, 'errors': errors, 'limited': limited, 'privileged': os.geteuid()==0, 'complete': errors==0 and not limited and os.geteuid()==0, 'duration': round(time.time()-started, 1), 'collectedAt': int(time.time()*1000)}))
`;
const quote = (s) => "'" + s.replace(/'/g, "'\\''") + "'";
const python = 'python3 -c ' + quote(script);
// Existing noninteractive sudo access only. Failure to elevate falls back to
// the connected account, whose result is explicitly marked partial.
const command = `if [ "$(id -u)" = 0 ]; then ${python}; else sudo -n -- ${python} 2>/dev/null || ${python}; fi`;
async function collectDiskUsage(session, runCommand) {
  const result = await runCommand(session, command, 105000);
  if (result.code !== 0) throw new Error('磁盘统计失败：远端需要 Python 3，且 SSH 连接必须保持在线。' + result.stderr.slice(0, 300));
  const data = JSON.parse(result.stdout);
  const number = (n) => Number.isSafeInteger(n) && n >= 0;
  if (!Array.isArray(data.users) || data.users.length > 100000 ||
      !['total', 'used', 'available', 'errors', 'collectedAt'].every(k => number(data[k])) ||
      !Number.isFinite(data.duration) || data.duration < 0 ||
      !['complete', 'limited', 'privileged'].every(k => typeof data[k] === 'boolean') ||
      !data.users.every(r => r && number(r.uid) && number(r.bytes) && number(r.files) && typeof r.user === 'string' && r.user.length <= 1024)) {
    throw new Error('远端磁盘统计返回无效数据');
  }
  return data;
}
module.exports = { collectDiskUsage, script, command };
