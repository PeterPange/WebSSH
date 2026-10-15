'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { script, collectDiskUsage } = require('../disk-usage');

test('collector counts allocated blocks, deduplicates hardlinks and does not follow symlinks', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'disk-owners-'));
  try {
    fs.writeFileSync(path.join(dir, 'file'), Buffer.alloc(8192));
    fs.linkSync(path.join(dir, 'file'), path.join(dir, 'hardlink'));
    fs.symlinkSync('/etc', path.join(dir, 'symlink'));
    const fd = fs.openSync(path.join(dir, 'sparse'), 'w');
    fs.ftruncateSync(fd, 100 * 1024 * 1024); fs.closeSync(fd);
    const source = script.replaceAll("'/'", JSON.stringify(dir));
    const result = JSON.parse(execFileSync('python3', ['-c', source], { encoding: 'utf8' }));
    const expected = [dir, ...['file', 'symlink', 'sparse'].map(p => path.join(dir, p))]
      .reduce((sum, p) => sum + fs.lstatSync(p).blocks * 512, 0);
    assert.equal(result.users.reduce((sum, r) => sum + r.bytes, 0), expected);
    assert.equal(result.users.reduce((sum, r) => sum + r.files, 0), 4);
    assert.equal(result.errors, 0);
    assert.equal(result.limited, false);
    const partial = JSON.parse(execFileSync('python3', ['-c', source.replace("directory = pending.pop()", "directory = pending.pop()\n        raise ScanTimeout()")], { encoding: 'utf8' }));
    assert.equal(partial.limited, true);
    assert.equal(partial.complete, false);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
test('remote collector uses fixed command, finite timeout and reports missing Python', async () => {
  await assert.rejects(collectDiskUsage({}, async (_, command, timeout) => {
    assert.match(command, /sudo -n -- python3/);
    assert.equal(timeout, 105000);
    return { code: 127, stdout: '', stderr: 'python3: not found' };
  }), /Python 3/);
  await assert.rejects(collectDiskUsage({}, async () => ({ code: 0, stdout: '{}', stderr: '' })), /无效数据/);
});
