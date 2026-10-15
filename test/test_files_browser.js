// Browser regression test: requires Playwright and Chromium. API calls are mocked.
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch({headless:true, ...(process.env.PLAYWRIGHT_CHROMIUM_PATH ? {executablePath:process.env.PLAYWRIGHT_CHROMIUM_PATH} : {})});
 try {
  const page=await browser.newPage();const errors=[],listed=[],writes=[];
  page.on('pageerror',e=>errors.push(e.message));
  const home='/home/test';
  const items=[{name:'notes.txt',path:home+'/notes.txt',isDirectory:false,size:20},{name:'photo.png',path:home+'/photo.png',isDirectory:false,size:30},{name:'large.log',path:home+'/large.log',isDirectory:false,size:2097152},{name:'folder',path:home+'/folder',isDirectory:true,size:0},{name:'denied',path:home+'/denied',isDirectory:true,size:0}];
  await page.route('**/api/**',async route=>{
   const url=new URL(route.request().url()),p=url.pathname;
   const json=(body,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(body)});
   if(p==='/api/auth/me')return json({user:{id:1,username:'admin',isAdmin:true}});
   if(p==='/api/servers')return json({servers:[]});
   if(p.endsWith('/edit')){if(route.request().method()==='POST')await new Promise(r=>setTimeout(r,250));return json({content:'sample text',version:{size:20,mtime:1}});}
   if(p.endsWith('/download'))return route.fulfill({contentType:'application/octet-stream',headers:{'Content-Disposition':'attachment; filename="photo.png"'},body:'image data'});
   if(route.request().method()==='POST'){writes.push(p);return json({ok:true})}
   if(p==='/api/files/test-session'){
    const target=url.searchParams.get('path')||home;listed.push(target);
    if(target.endsWith('/denied'))return json({error:'Permission denied'},400);
    if(target.endsWith('/slow'))await new Promise(r=>setTimeout(r,250));
    return json({homeDir:home,path:target,items:target===home?items:[]});
   }
   return json({});
  });
  await page.goto(process.env.WEBSSH_TEST_BASE_URL || 'http://127.0.0.1:8080',{waitUntil:'networkidle'});
  await page.evaluate(async()=>{state.activeId='test-session';state.homeDir='/home/test';state.activeTab='files';state.view='detail';document.querySelector('#view-dashboard').classList.add('hidden');document.querySelector('#view-detail').classList.remove('hidden');document.querySelector('#tab-terminal').classList.remove('active');document.querySelector('#tab-files').classList.add('active');await loadDir();});
  await page.locator('tr[data-path="/home/test/notes.txt"] .file-open').click();
  await page.locator('#file-editor-modal').waitFor({state:'visible'});
  assert.equal(await page.locator('#file-editor-text').inputValue(),'sample text');
  assert.ok(!listed.includes(home+'/notes.txt'));
  await page.locator('#file-editor-text').fill('submitted version');
  await page.locator('#btn-file-editor-save').click();
  await page.locator('#file-editor-text').fill('new edits during save');
  await page.getByText('本次提交已保存，仍有新的未保存修改',{exact:true}).waitFor();
  assert.equal(await page.evaluate(()=>fileEditorDirty),true);
  page.once('dialog',d=>d.accept());
  await page.locator('#btn-file-editor-close').click();
  const downloadPromise=page.waitForEvent('download');
  await page.locator('tr[data-path="/home/test/photo.png"] .file-open').click();await downloadPromise;
  assert.ok(!listed.includes(home+'/photo.png'));
  assert.equal(await page.locator('tr[data-path="/home/test/photo.png"] .edit').count(),0);
  assert.equal(await page.locator('tr[data-path="/home/test/large.log"] .edit').count(),0);
  await page.locator('tr[data-path="/home/test/denied"] .file-open').click();
  await page.locator('.file-error').waitFor();
  assert.match(await page.locator('.file-error').innerText(),/没有访问权限/);
  assert.equal(await page.locator('#file-drop tbody tr').count(),5);
  let message='';page.once('dialog',d=>{message=d.message();d.dismiss()});
  await page.locator('tr[data-path="/home/test/notes.txt"] .del').click();
  assert.ok(!message.includes('全部内容'));assert.match(message,/无法撤销/);
  page.once('dialog',d=>d.accept('../bad'));await page.locator('#f-new-file').click();assert.equal(writes.length,0);
  await page.locator('tr[data-path="/home/test/folder"] .enter').click();await page.locator('#file-drop').getByText('这个文件夹还是空的',{exact:false}).waitFor();
  assert.ok(listed.includes(home+'/folder'));
  await page.locator('#f-up').click();await page.locator('tr[data-path="/home/test/notes.txt"]').waitFor();
  await page.evaluate(async()=>{await Promise.all([loadDir('/home/test/slow'),loadDir('/home/test/fast')]);});
  assert.equal(await page.evaluate(()=>state.currentPath),home+'/fast');
  await page.setViewportSize({width:390,height:844});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  assert.deepEqual(errors,[]);
  console.log('PASS: text opens editor; binary downloads; folders navigate; file never listed as directory; large/binary edit hidden; failed navigation keeps list; correct delete warning; invalid names blocked; stale response ignored; mobile layout');
 }finally{await browser.close()}
})().catch(e=>{console.error(e);process.exit(1)});
