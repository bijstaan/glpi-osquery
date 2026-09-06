// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Bijstaan
const { chromium } = require('playwright');
(async () => {
  const b = await chromium.launch();
  const p = await b.newPage();
  const posts = [];
  p.on('request', r => { if (r.method()==='POST' && r.url().includes('agent.form')) posts.push(r.postData()); });
  p.on('response', async r => { if (r.request().method()==='POST' && r.url().includes('agent.form')) console.log('POST ->', r.status(), r.url()); });
  await p.goto('http://localhost:8081/', {waitUntil:'networkidle'});
  await p.fill('#login_name','glpi'); await p.fill('input[type=password]','glpi');
  await p.click('button[type=submit]'); await p.waitForLoadState('networkidle');
  await p.goto('http://localhost:8081/plugins/glpiosquery/front/agent.form.php?id=1', {waitUntil:'networkidle'});
  await p.click('button[name=quarantine]');
  await p.waitForLoadState('networkidle');
  console.log('post bodies:', JSON.stringify(posts));
  const msg = await p.evaluate(() => {
    const el = document.querySelector('.toast-body, .alert, #messages_after_redirect');
    return el ? el.innerText.trim().slice(0,120) : null;
  });
  console.log('message shown:', msg);
  await b.close();
})().catch(e=>{console.error(e.message);process.exit(1)});
