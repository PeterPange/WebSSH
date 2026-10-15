'use strict';

// Fixed commands only; no remote shell input is taken from the browser.
const commands = {
  connections: (port) => `LC_ALL=C ss -Htn state established '( sport = :${port} )'`,
  logins: () => 'LC_ALL=C who -u',
  processes: () => 'rows=$(LC_ALL=C ps -eo user:64,pid,pcpu,pmem,comm --sort=-pcpu) && printf "%s\\n" "$rows" | head -n 31',
  failures: () => 'LC_ALL=C lastb -s -1hours -n 200 -w -i',
};

function parseProcesses(output) {
  return output.split('\n').flatMap((line) => {
    const m = /^\s*(\S+)\s+(\d+)\s+([\d.]+)\s+([\d.]+)\s+(.+?)\s*$/.exec(line);
    return m ? [{ user: m[1], pid: Number(m[2]), cpu: Number(m[3]), memory: Number(m[4]), command: m[5] }] : [];
  }).sort((a, b) => b.cpu - a.cpu).slice(0, 30);
}

// Read only: use existing noninteractive sudo permissions, never request a
// password or change remote log/sudo configuration.
async function collectFailures(session, runCommand) {
  const attempts = [];
  const lastb = 'lastb -s -1hours -n 200 -w -i';
  const journal = "journalctl --system --since '-1 hour' --no-pager -o json -n 5000 _COMM=sshd _COMM=sshd-session";
  for (const [source, command, format] of [
    ['lastb', 'LC_ALL=C ' + lastb, 'lastb'],
    ['sudo lastb', 'LC_ALL=C sudo -n -- ' + lastb, 'lastb'],
    ['journal', 'LC_ALL=C ' + journal, 'journal'],
    ['sudo journal', 'LC_ALL=C sudo -n -- ' + journal, 'journal'],
  ]) {
    try {
      const result = await runCommand(session, command, 8000);
      if (result.code !== 0 || /permission|not seeing messages|no journal files|access denied/i.test(result.stderr || '')) {
        attempts.push(source + ': ' + (result.stderr.trim() || '命令执行失败'));
        continue;
      }
      if (format === 'lastb') return { available: true, text: result.stdout.trim(), source };
      const lines = result.stdout.split('\n').filter((line) => line.trim());
      const items = [];
      // No journal output is not evidence that this account can read sshd
      // logs. Validate access against a nonempty system journal record first.
      if (!lines.length) {
        const probe = await runCommand(session, command.replace("--since '-1 hour'", '').replace('-n 5000 _COMM=sshd _COMM=sshd-session', '-n 1'), 8000);
        if (probe.code !== 0 || probe.stderr.trim() || !probe.stdout.trim().startsWith('{')) throw new Error('无法确认系统日志读取权限或系统日志为空');
      }
      for (const line of lines) {
        const record = JSON.parse(line);
        const message = record.MESSAGE;
        if (typeof message !== 'string') continue;
        const match = /Failed (?:password|publickey|keyboard-interactive(?:\/pam)?) for (?:invalid user )?(.+?) from (\S+) port \d+/.exec(message);
        if (match) items.push({ address: match[2], user: match[1], message });
      }
      return { available: true, source, items, text: items.map((i) => i.message).join('\n'), limited: lines.length >= 5000 };
    } catch (e) { attempts.push(source + ': ' + e.message); }
  }
  return { available: false, error: attempts.join(' | '),
    hint: '当前 SSH 用户无法读取失败登录日志。需要远端管理员授予日志读取权限，或配置仅允许读取日志的 sudo 权限；平台管理员身份不等于远端 root。' };
}

async function collectMonitor(session, runCommand) {
  const port = Number(session.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid SSH port');
  const entries = await Promise.all(Object.entries(commands).map(async ([name, build]) => {
    if (name === 'failures') return [name, await collectFailures(session, runCommand)];
    try {
      const result = await runCommand(session, build(port), 10000);
      if (result.code !== 0) return [name, { available: false, error: result.stderr.trim() || '命令不可用或当前 SSH 用户权限不足' }];
      return [name, { available: true, ...(name === 'processes' ? { items: parseProcesses(result.stdout) } : { text: result.stdout.trim() }) }];
    } catch (e) { return [name, { available: false, error: e.message }]; }
  }));
  const data = { ...Object.fromEntries(entries), port, collectedAt: Date.now() };
  return { ...data, audit: buildAudit(data) };
}

function buildAudit(data) {
  const sources = new Map();
  const source = (address) => {
    if (!sources.has(address)) sources.set(address, { address, connections: 0, failures: 0 });
    return sources.get(address);
  };
  let connectionCount = 0, failureCount = 0, unparsed = 0, connectionUnparsed = 0;
  if (data.connections.available) {
    for (const line of data.connections.text.split('\n').filter((s) => s.trim())) {
      const fields = line.trim().split(/\s+/);
      // ss without a state column: Recv-Q Send-Q Local Peer.
      const offset = /^\d+$/.test(fields[0]) ? 0 : 1;
      const peer = fields[offset + 3];
      if (!peer || !/:\d+$/.test(peer)) { unparsed++; connectionUnparsed++; continue; }
      const address = peer.replace(/:\d+$/, '').replace(/^\[|\]$/g, '').replace(/^::ffff:/, '');
      source(address).connections++;
      connectionCount++;
    }
  }
  if (data.failures.available && data.failures.items) {
    for (const item of data.failures.items) {
      source(item.address).failures++;
      failureCount++;
    }
  } else if (data.failures.available) {
    for (const line of data.failures.text.split('\n').filter((s) => s.trim())) {
      if (/^btmp begins\b/.test(line.trim())) continue;
      const fields = line.trim().split(/\s+/);
      if (fields.length < 6) { unparsed++; continue; }
      source(fields[2]).failures++;
      failureCount++;
    }
  }
  const reasons = [];
  let level = 'normal';
  const flag = (severity, message) => {
    reasons.push({ level: severity, message });
    if (severity === 'critical' || level === 'normal') level = severity;
  };
  for (const item of sources.values()) {
    item.level = item.failures >= 20 || item.connections >= 30 ? 'critical'
      : item.failures >= 5 || item.connections >= 10 ? 'warning' : 'normal';
    if (item.failures >= 5) flag(item.failures >= 20 ? 'critical' : 'warning', `${item.address} 最近一小时失败登录 ${item.failures} 次，疑似密码尝试`);
    if (item.connections >= 10) flag(item.connections >= 30 ? 'critical' : 'warning', `${item.address} 当前并发连接 ${item.connections} 条，连接数偏高`);
  }
  if (failureCount >= 10) flag(failureCount >= 50 ? 'critical' : 'warning', `最近一小时共 ${failureCount >= 200 ? '至少 ' : ''}${failureCount} 次失败登录`);
  const missing = ['connections', 'failures'].filter((key) => !data[key].available);
  const complete = missing.length === 0 && unparsed === 0 && !data.failures.limited;
  const issues = missing.map((key) => ({ key, message: data[key].error || '数据不可用', hint: data[key].hint || '' }));
  if (unparsed) issues.push({ key: 'parse', message: `${unparsed} 行远端输出无法解析`, hint: '' });
  if (data.failures.limited) issues.push({ key: 'limit', message: '系统日志达到 5000 条采集上限，失败次数仅为已读取部分', hint: '' });
  if (!complete && level === 'normal') level = 'unknown';
  const maxConnections = Math.max(0, ...[...sources.values()].map((s) => s.connections));
  const connectionLevel = !data.connections.available || connectionUnparsed ? 'unknown' : maxConnections >= 30 ? 'critical' : maxConnections >= 10 ? 'warning' : 'normal';
  return {
    connectionLevel,
    level, complete, reasons, connectionCount: data.connections.available ? connectionCount : null,
    failureCount: data.failures.available ? failureCount : null, truncated: data.failures.items ? !!data.failures.limited : failureCount >= 200,
    missing, unparsed, issues,
    sources: [...sources.values()].sort((a, b) => b.failures - a.failures || b.connections - a.connections),
    rules: '单来源失败登录 ≥5 次黄色、≥20 次红色；总失败 ≥10 次黄色、≥50 次红色（最近一小时）；单来源并发 ≥10 条黄色、≥30 条红色。',
  };
}

module.exports = { collectMonitor, parseProcesses, buildAudit, collectFailures };
