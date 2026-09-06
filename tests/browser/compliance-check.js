// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Bijstaan
const { chromium } = require('playwright');
const SHOTS = process.env.SHOT_DIR || '.';
(async () => {
  const b = await chromium.launch();
  const p = await b.newPage({viewport:{width:1600,height:1000}});
  const errs=[]; p.on('pageerror',e=>errs.push(e.message));
  p.on('response', r=>{ if(r.status()>=500) errs.push('HTTP '+r.status()+' '+r.url()); });
  await p.goto('http://localhost:8081/', {waitUntil:'networkidle'});
  await p.fill('#login_name','glpi'); await p.fill('input[type=password]','glpi');
  await p.click('button[type=submit]'); await p.waitForLoadState('networkidle');
  await p.goto('http://localhost:8081/plugins/glpiosquery/front/compliance.php', {waitUntil:'networkidle'});
  await p.waitForTimeout(1500);
  const text = await p.evaluate(()=>document.body.innerText);
  for (const w of ['Disk encryption','Firewall','Antivirus','Matt-Framework','osq-linux-01','unknown','fail','n/a']) {
    console.log(`shows "${w}":`, text.includes(w));
  }
  await p.screenshot({path:`${SHOTS}/osq-compliance.png`, fullPage:true});
  console.log('errors:', errs.length ? errs.slice(0,3) : 'none');
  await b.close();
})().catch(e=>{console.error('FAILED',e.message);process.exit(1)});
