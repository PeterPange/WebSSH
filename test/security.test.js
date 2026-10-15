'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { parseCookies, allowedOrigin, RateLimiter, createVault, dimensions } = require('../security');
test('malformed cookie cannot throw or modify object prototype', () => {
  assert.equal(parseCookies('webssh_auth=%E0%A4%A').webssh_auth, undefined);
  assert.equal(Object.getPrototypeOf(parseCookies('__proto__=bad')), null);
  assert.equal(parseCookies('webssh_auth=abc; x=1').webssh_auth, 'abc');
});
test('origin check rejects foreign sites, null, sibling sites and allows configured proxy origin', () => {
  const req = (headers) => ({headers:{host:'manager.example:9998',...headers}});
  assert.equal(allowedOrigin(req({origin:'http://manager.example:9998'}), ''), true);
  for(const origin of ['https://evil.example','null','file:///tmp/test','http://manager.example:9998/']) assert.equal(allowedOrigin(req({origin}), ''), false);
  assert.equal(allowedOrigin(req({'sec-fetch-site':'cross-site'}), ''), false);
  assert.equal(allowedOrigin(req({origin:'https://portal.example'}), 'https://portal.example'), true);
  assert.equal(allowedOrigin(req({}), ''), true); // authenticated non-browser clients
});
test('limiter is bounded and cannot be evaded by creating extra keys', () => {
  const limiter = new RateLimiter(2);
  assert.equal(limiter.take('one',1,10,0),true);
  assert.equal(limiter.take('one',1,10,1),false);
  assert.equal(limiter.take('two',1,10,0),true);
  assert.equal(limiter.take('three',1,10,1),false);
  assert.equal(limiter.take('three',1,10,11),true);
});
test('credential encryption survives reload and rejects tampering and missing keys', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(),'webssh-vault-test-'));
  try {
    const vault = createVault(dir,false);
    const encrypted = vault.seal({password:'sensitive',privateKey:'testkey'});
    assert.ok(!encrypted.includes('sensitive'));
    assert.deepEqual(createVault(dir,true).open(encrypted),{password:'sensitive',privateKey:'testkey'});
    const bytes = Buffer.from(encrypted.slice(7),'base64');bytes[30]^=1;
    assert.throws(()=>vault.open('enc:v1:'+bytes.toString('base64')));
    assert.equal(fs.statSync(path.join(dir,'credentials.key')).mode & 0o777,0o600);
    fs.unlinkSync(path.join(dir,'credentials.key'));
    assert.throws(()=>createVault(dir,true), /missing/);
  } finally {fs.rmSync(dir,{recursive:true,force:true});}
});
test('terminal dimensions are finite and bounded', () => {
  assert.equal(dimensions('120',80),120);
  for(const value of ['NaN',Infinity,-1,999999,0,'',2.5]) assert.equal(dimensions(value,80),80);
});
test('expired logins close their SSH sessions without closing another login', () => {
  const {expireAuthSessions}=require('../security');
  const entries=new Map([['expired',{expiresAt:100}],['live',{expiresAt:200}]]),closed=[];
  expireAuthSessions(entries,t=>closed.push(t),100);
  assert.deepEqual(closed,['expired']);assert.deepEqual([...entries.keys()],['live']);
});
test('same host with wrong protocol is not same origin',()=>{
  assert.equal(allowedOrigin({headers:{host:'app.test',origin:'https://app.test'}},''),false);
});
