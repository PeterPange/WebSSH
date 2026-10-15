// Requires optional Playwright; API responses are mocked, no remote scans.
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
(async () => {
  const browser = await chromium.launch({ headless: true, ...(process.env.PLAYWRIGHT_CHROMIUM_PATH ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_PATH } : {}) });
  try {
    const page = await browser.newPage();
    const errors = []; page.on('pageerror', e => errors.push(e.message));
    let partial = false, fail = false;
    await page.route('**/api/**', async route => {
      const p = new URL(route.request().url()).pathname;
      let data = {};
      if (p === '/api/auth/me') data = { user: { id: 1, username: 'admin', isAdmin: true } };
      if (p.includes('/admin/monitor/')) data = {error:'Test monitor unavailable'};
      if (p === '/api/servers') data = { servers: [] };
      if (p.includes('/disk-usage/')) {
        if (fail) return route.fulfill({ status: 502, contentType: 'application/json', body: JSON.stringify({error: '测试扫描失败'}) });
        data = { users: [{uid:0,user:'root',bytes:600,files:10},{uid:1000,user:'<img src=x onerror=alert(1)>',bytes:200,files:2},{uid:1001,user:'empty',bytes:0,files:0}], total:1000,used:850,available:150,errors:partial?3:0,limited:partial,privileged:!partial,complete:!partial,duration:2,collectedAt:Date.now() };
      }
      return route.fulfill({ contentType: 'application/json', body: JSON.stringify(data) });
    });
    await page.goto(process.env.WEBSSH_TEST_BASE_URL || 'http://127.0.0.1:9998', { waitUntil: 'networkidle' });
    await page.evaluate(async () => {
      const s={uid:'disk-test',name:'磁盘测试',host:'localhost',port:22,sessionId:'disk-test'};
      state.status.set(s.sessionId,{connected:true,gpu:{available:false}});
      if (renderCard(s).querySelector('[data-act="disk-users"]')) throw new Error('Dashboard entry must be removed');
      state.servers.push(s);
      state.activeId=s.sessionId;
      state.activeTab='system';
      state.view='detail';
      document.querySelector('#view-dashboard').classList.add('hidden');
      document.querySelector('#view-detail').classList.remove('hidden');
      document.querySelector('#tab-system').classList.add('active');
      await refreshSystem();
    });
    await page.locator('[data-act="disk-users"]').click();
    await page.getByText('扫描完成', {exact:false}).waitFor();
    assert.equal(await page.locator('.disk-users-table tbody tr').count(),2);
    assert.equal(await page.locator('.disk-users-table img').count(),0);
    assert.match(await page.locator('.disk-users-table').innerText(),/60.0%/);
    await page.locator('#disk-show-zero').check();
    assert.equal(await page.locator('.disk-users-table tbody tr').count(),3);
    await page.setViewportSize({width:390,height:844});
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),true);
    await page.locator('#disk-close').click();
    partial=true;
    await page.locator('[data-act="disk-users"]').click();
    await page.locator('.disk-partial').waitFor();
    assert.match(await page.locator('.disk-partial').innerText(),/当前 SSH 用户不是 root/);
    await page.locator('#disk-show-zero').check();
    assert.match(await page.locator('.disk-users-table').innerText(),/未观测到/);
    await page.keyboard.press('Escape');
    fail=true;
    await page.locator('[data-act="disk-users"]').click();
    await page.locator('#disk-retry').waitFor();
    fail=false;
    await page.locator('#disk-retry').click();
    await page.locator('.disk-users-table').waitFor();
    await page.locator('#disk-close').click();
    assert.equal(await page.evaluate(async () => {state.currentUser.isAdmin=false; await refreshSystem(); return document.querySelector('#system-container [data-act="disk-users"]')===null}),true);
    assert.deepEqual(errors,[]);
    console.log('PASS disk UI: admin entry, bars, zero toggle, partial data, escaped username, retry, mobile, close, non-admin hidden');
  } finally { await browser.close(); }
})().catch(e=>{console.error(e);process.exitCode=1});
