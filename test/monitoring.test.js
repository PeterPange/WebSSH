'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { collectMonitor, parseProcesses } = require('../monitoring');
test('parse CPU process owners, multicore usage and sort', () => {
  const rows = parseProcesses('USER PID %CPU %MEM COMMAND\nalice 20 1.0 0.2 worker\ntrainer 11 250.5 30.1 python\nbad line\n');
  assert.deepEqual(rows[0], { user: 'trainer', pid: 11, cpu: 250.5, memory: 30.1, command: 'python' });
  assert.equal(rows.length, 2);
});
test('report permission and timeout errors independently from other sections', async () => {
  const data = await collectMonitor({ port: 2222 }, async (_, command) => {
    if (command.includes('lastb')) return { code: 1, stdout: '', stderr: 'Permission denied' };
    if (command.includes('who')) throw new Error('timeout');
    return { code: 0, stdout: '', stderr: '' };
  });
  assert.equal(data.failures.available, false);
  assert.equal(data.logins.error, 'timeout');
  assert.equal(data.connections.available, true);
  assert.deepEqual(data.processes.items, []);
});
test('reject shell metacharacters in SSH port', async () => {
  await assert.rejects(collectMonitor({ port: '22;id' }, () => assert.fail('must not execute')));
});
const { buildAudit } = require('../monitoring');
function snapshot(connections = '', failures = '') {
  return { connections: { available: true, text: connections }, failures: { available: true, text: failures } };
}
const failure = (ip) => `invalid ssh:notty ${ip} Wed Sep 30 12:00 - 12:00 (00:00)\n`;
test('complete empty snapshot is normal; missing logs is unknown', () => {
  assert.equal(buildAudit(snapshot()).level, 'normal');
  const data = snapshot(); data.failures = { available: false };
  const audit = buildAudit(data);
  assert.equal(audit.level, 'unknown'); assert.equal(audit.failureCount, null);
});
test('failure thresholds change colour and explain the source', () => {
  assert.equal(buildAudit(snapshot('', failure('1.2.3.4').repeat(4))).level, 'normal');
  assert.equal(buildAudit(snapshot('', failure('1.2.3.4').repeat(5))).level, 'warning');
  const audit = buildAudit(snapshot('', failure('1.2.3.4').repeat(20)));
  assert.equal(audit.level, 'critical'); assert.equal(audit.sources[0].failures, 20);
  assert.match(audit.reasons[0].message, /1\.2\.3\.4/);
});
test('IPv6 and mapped IPv4 peers are parsed and connection thresholds apply', () => {
  const audit = buildAudit(snapshot('0 0 [::]:22 [2001:db8::1]:12345\n'.repeat(30) + 'ESTAB 0 0 1.2.3.4:22 [::ffff:192.0.2.1]:12345\n'));
  assert.equal(audit.connectionCount, 31); assert.equal(audit.level, 'critical');
  assert.equal(audit.sources[0].address, '2001:db8::1');
  assert.equal(audit.sources[1].address, '192.0.2.1');
});
test('partial observations preserve alerts, malformed rows never indicate normal', () => {
  const data = snapshot('0 0 1.1.1.1:22 2.2.2.2:4567\n'.repeat(10));
  data.failures = { available: false };
  assert.equal(buildAudit(data).level, 'warning');
  assert.equal(buildAudit(snapshot('unexpected format')).level, 'unknown');
});
test('distributed failures, footer filtering, cap and recovery', () => {
  const failures = Array.from({length:50}, (_, i) => failure(`192.0.2.${i}`)).join('');
  assert.equal(buildAudit(snapshot('', failures + '\nbtmp begins Wed Sep 30 12:00:00 2026\n')).level, 'critical');
  assert.equal(buildAudit(snapshot('', failure('1.1.1.1').repeat(200))).truncated, true);
  assert.equal(buildAudit(snapshot()).level, 'normal');
});
const { collectFailures } = require('../monitoring');
test('use existing passwordless sudo for lastb without sending passwords', async () => {
  const seen = [];
  const result = await collectFailures({}, async (_, cmd) => {
    seen.push(cmd);
    return cmd.includes('sudo -n') ? {code:0,stdout:failure('192.0.2.1'),stderr:''} : {code:1,stdout:'',stderr:'Permission denied'};
  });
  assert.equal(result.source, 'sudo lastb'); assert.equal(seen.length, 2);
  assert.ok(seen.every(cmd => !cmd.includes('sudo -S')));
});
test('journal fallback counts failed authentication once and ignores invalid-user notices', async () => {
  const result = await collectFailures({}, async (_, cmd) => cmd.includes('lastb')
    ? {code:1,stdout:'',stderr:'Permission denied'}
    : {code:0,stderr:'',stdout:[{MESSAGE:'Invalid user foo from 192.0.2.1 port 1234'}, {MESSAGE:'Failed password for invalid user foo from 192.0.2.1 port 1234 ssh2'}].map(JSON.stringify).join('\n')});
  assert.equal(result.source, 'journal'); assert.equal(result.items.length, 1);
  const data = snapshot(); data.failures = result;
  assert.equal(buildAudit(data).failureCount, 1);
});
test('empty inaccessible journal is unknown, never a false clean result', async () => {
  const result = await collectFailures({}, async (_, cmd) => cmd.includes('lastb')
    ? {code:1,stdout:'',stderr:'Permission denied'} : {code:0,stdout:'',stderr:''});
  assert.equal(result.available, false); assert.match(result.error, /无法确认/);
});
test('empty SSH results require a readable system journal probe', async () => {
  const result = await collectFailures({}, async (_, cmd) => cmd.includes('lastb')
    ? {code:1,stdout:'',stderr:'not found'} : {code:0,stdout:cmd.includes('-n 1') ? '{"MESSAGE":"system started"}' : '',stderr:''});
  assert.equal(result.available, true); assert.deepEqual(result.items, []);
});
test('missing failure logs do not hide connection evaluation', () => {
  const data = snapshot('0 0 1.1.1.1:22 2.2.2.2:3456'); data.failures = {available:false,error:'Permission denied'};
  const audit = buildAudit(data);
  assert.equal(audit.level, 'unknown'); assert.equal(audit.connectionLevel, 'normal');
  assert.equal(audit.issues[0].message, 'Permission denied');
});
