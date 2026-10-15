'use strict';
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const { generateKeyPairSync } = require('crypto');
const { Server } = require('ssh2');
const WebSocket = require('ws');
const Database = require('better-sqlite3');
const { createVault } = require('../security');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'webssh-security-e2e-'));
let processHandle, sshServer, base, cookie = '', passed = 0, diskExecutions = 0;
const check = (name, condition) => {assert.ok(condition, name);passed++;console.log('ok '+name)};
async function api(route, options = {}) {
  const response = await fetch(base + route, {...options, headers:{'Content-Type':'application/json',Cookie:cookie,...options.headers}});
  const setCookie=response.headers.get('set-cookie'); if(setCookie)cookie=setCookie.split(';')[0];
  let data;try{data=await response.json()}catch{}
  return {status:response.status,data,headers:response.headers};
}
function wsReject(headers) {
 return new Promise((resolve,reject)=>{
  const ws=new WebSocket(base.replace('http:','ws:')+'/ws/terminal?sessionId=bad',{headers});
  ws.on('unexpected-response',(_,res)=>{res.resume();resolve(res.statusCode);});ws.on('open',()=>{ws.close();reject(new Error('unexpected accepted upgrade'))});ws.on('error',reject);
 });
}
async function startSsh(port=0) {
 const key=generateKeyPairSync('rsa',{modulusLength:2048,privateKeyEncoding:{type:'pkcs1',format:'pem'},publicKeyEncoding:{type:'spki',format:'pem'}}).privateKey;
 sshServer=new Server({hostKeys:[key]},client=>{
  client.on('error',()=>{});
  client.on('authentication',ctx=>ctx.accept());
  client.on('ready',()=>client.on('session',accept=>{
   const session=accept();
   session.on('exec', (accept, reject, info) => {
    if (!info.command.includes('statvfs')) return reject();
    diskExecutions++;
    const stream=accept();
    setTimeout(()=>{stream.write(JSON.stringify({users:[{uid:1000,user:'test',bytes:4096,files:1}],total:8192,used:4096,available:4096,errors:0,collectedAt:Date.now(),duration:0.1,limited:false,privileged:true,complete:true}));stream.exit(0);stream.end();},100);
   });
   session.on('sftp',(_,reject)=>reject());
   session.on('pty',accept=>accept());session.on('shell',accept=>{const stream=accept();stream.on('error',()=>{});stream.on('data',data=>stream.write(data));});
  }));
 });
 await new Promise(resolve=>sshServer.listen(port,'127.0.0.1',resolve));return sshServer.address().port;
}
async function main(){
 const seed=new Database(path.join(dir,'servers.db'));seed.exec('CREATE TABLE server_creds (server_uid TEXT NOT NULL,user_id INTEGER NOT NULL,username TEXT NOT NULL,creds TEXT NOT NULL,updated_at INTEGER NOT NULL,PRIMARY KEY(server_uid,user_id))');seed.prepare('INSERT INTO server_creds VALUES (?,?,?,?,?)').run('legacy',1,'test',JSON.stringify({password:'migration-secret-unique'}),Date.now());seed.close();
 processHandle=spawn(process.execPath,['server.js'],{cwd:path.join(__dirname,'..'),env:{...process.env,PORT:'0',WEBSSH_DATA_DIR:dir,WEBSSH_ADMIN_PASSWORD:'test-admin-12345',WEBSSH_UPLOAD_MAX_MB:'1'},stdio:['ignore','pipe','pipe']});
 base=await new Promise((resolve,reject)=>{let output='';const timer=setTimeout(()=>reject(new Error('startup timeout: '+output)),10000);processHandle.stdout.on('data',d=>{output+=d;const m=output.match(/http:\/\/[^:]+:(\d+)/);if(m){clearTimeout(timer);resolve('http://127.0.0.1:'+m[1])}});processHandle.on('exit',code=>reject(new Error('server exit '+code)));});
 check('malformed cookie safely rejected',(await api('/api/auth/me',{headers:{Cookie:'webssh_auth=%E0%A4%A'}})).status===401);
 check('malformed websocket cookie rejected before upgrade',await wsReject({Cookie:'webssh_auth=%E0%A4%A'})===401);
 check('foreign origin login refused',(await api('/api/auth/login',{method:'POST',headers:{Origin:'https://attacker.invalid'},body:JSON.stringify({username:'admin',password:'test-admin-12345'})})).status===403);
 check('simple form requests refused',(await api('/api/auth/login',{method:'POST',headers:{'Content-Type':'text/plain'},body:'{}'})).status===415);
 check('login works',(await api('/api/auth/login',{method:'POST',body:JSON.stringify({username:'admin',password:'test-admin-12345'})})).status===200);
 const adminCookie=cookie;
 const headers=(await api('/api/servers')).headers;
 check('security headers present',headers.get('content-security-policy').includes("script-src 'self'") && headers.get('x-frame-options')==='DENY' && headers.get('cache-control')==='no-store' && !headers.has('x-powered-by'));
 check('foreign websocket origin rejected',await wsReject({Cookie:cookie,Origin:'https://attacker.invalid'})===403);
 const port=await startSsh();
 await api('/api/servers',{method:'POST',body:JSON.stringify({uid:'test-host',host:'127.0.0.1',port})});
 await api('/api/servers/test-host/creds',{method:'POST',body:JSON.stringify({username:'test',creds:{password:'secret-only-test'}})});
 const db=new Database(path.join(dir,'servers.db'),{readonly:true});
 const stored=db.prepare("SELECT creds FROM server_creds WHERE server_uid='test-host'").get().creds;
 check('legacy credentials automatically encrypted',createVault(dir,true).open(db.prepare("SELECT creds FROM server_creds WHERE server_uid='legacy'").get().creds).password==='migration-secret-unique');
 check('migration scrubs old plaintext pages',!fs.readFileSync(path.join(dir,'servers.db')).includes(Buffer.from('migration-secret-unique')));
 check('credentials encrypted in SQLite',stored.startsWith('enc:v1:') && !stored.includes('secret-only-test'));
 check('persisted credentials decrypt with private key',createVault(dir,true).open(stored).password==='secret-only-test');
 check('data directory private',(fs.statSync(dir).mode&0o777)===0o700);
 const connectBody=JSON.stringify({host:'127.0.0.1',port,username:'test',password:'pass'});
 const connected=await api('/api/connect',{method:'POST',body:connectBody});
 check('first host key accepted',connected.status===200);
 const id=connected.data.sessionId;
 const diskResults=await Promise.all([api('/api/admin/disk-usage/'+id),api('/api/admin/disk-usage/'+id)]);
 check('admin receives user disk ownership',diskResults.every(r=>r.status===200 && r.data.users[0].bytes===4096));
 await api('/api/admin/disk-usage/'+id);
 check('disk scan coalesces concurrent requests and caches result',diskExecutions===1);
 check('disk scan rejects unknown sessions',(await api('/api/admin/disk-usage/missing')).status===404);

 check('host key persisted',!!db.prepare('SELECT fingerprint FROM ssh_host_keys WHERE port=?').get(port));
 await new Promise((resolve,reject)=>{
  const ws=new WebSocket(base.replace('http:','ws:')+'/ws/terminal?sessionId='+id,{headers:{Cookie:cookie,Origin:base}});
  ws.on('message',data=>{if(data.toString().includes('"ready"'))ws.send('x'.repeat(70000))});
  ws.on('close',code=>{try{check('oversized terminal payload rejected',code===1009);resolve()}catch(e){reject(e)}});ws.on('error',reject);
 });
 await api('/api/sessions/'+id,{method:'DELETE'});
 await new Promise(resolve=>sshServer.close(resolve));await startSsh(port);
 check('changed host key rejected',(await api('/api/connect',{method:'POST',body:connectBody})).status===502);
 await api('/api/auth/register',{method:'POST',body:JSON.stringify({username:'ordinary',password:'ordinary-pass-123'})});
 await api('/api/auth/login',{method:'POST',body:JSON.stringify({username:'ordinary',password:'ordinary-pass-123'})});
 check('ordinary user cannot list local SSH keys',(await api('/api/ssh-keys')).status===403);
 check('ordinary user cannot read local SSH config',(await api('/api/ssh-config')).status===403);
 check('ordinary user cannot use local key',(await api('/api/connect',{method:'POST',body:JSON.stringify({host:'127.0.0.1',port,username:'test',keyRef:'id_rsa'})})).status===403);
 check('ordinary user cannot dial arbitrary destination',(await api('/api/connect',{method:'POST',body:JSON.stringify({host:'127.0.0.1',port:12345,username:'test',password:'pass'})})).status===403);
 check('ordinary user cannot save local key',(await api('/api/servers/test-host/creds',{method:'POST',body:JSON.stringify({username:'test',creds:{keyRef:'id_rsa'}})})).status===403);
 check('ordinary user cannot access audit',(await api('/api/admin/monitor/'+id)).status===403);
 check('ordinary user cannot scan disk ownership',(await api('/api/admin/disk-usage/'+id)).status===403);
 check('no default SSH credentials seeded',(await api('/api/servers')).data.servers[0].mine===null);
 let limited=false;for(let i=0;i<35;i++){const r=await api('/api/auth/login',{method:'POST',body:JSON.stringify({username:'rotate'+i,password:'wrong-password'})});if(r.status===429){limited=true;break}}
 check('changing usernames cannot evade IP login limit',limited);
 check('service still responds after malformed requests',(await api('/api/auth/me')).status===200);
 db.close();console.log(`${passed} security integration checks passed`);
}
main().catch(e=>{console.error(e);process.exitCode=1}).finally(async()=>{if(processHandle){processHandle.kill('SIGTERM');await new Promise(r=>processHandle.once('exit',r));}if(sshServer)sshServer.close();fs.rmSync(dir,{recursive:true,force:true});});
