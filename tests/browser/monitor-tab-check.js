// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Bijstaan
const { chromium } = require('playwright');
const SHOTS = process.env.SHOT_DIR || '.';
(async () => {
  const b = await chromium.launch();
  const p = await b.newPage({viewport:{width:1600,height:1000}});
  const errs=[];
  p.on('pageerror', e=>errs.push(e.message));
  p.on('response', r=>{ if(r.status()>=500) errs.push('HTTP '+r.status()+' '+r.url()); });
  await p.goto('http://localhost:8081/', {waitUntil:'networkidle'});
  await p.fill('#login_name','glpi'); await p.fill('input[type=password]','glpi');
  await p.click('button[type=submit]'); await p.waitForLoadState('networkidle');
  await p.goto('http://localhost:8081/front/monitor.form.php?id=5', {waitUntil:'networkidle'});
  await p.waitForTimeout(1500);
  const tabs = await p.$$eval('a', els => els.map(e=>e.textContent.trim()).filter(t=>t==='Display details'));
  console.log('tab present:', tabs.length > 0);
  if (tabs.length) {
    await p.evaluate(async () => {
      const a = Array.from(document.querySelectorAll('a')).find(x=>x.textContent.trim()==='Display details');
      a.click(); await new Promise(r=>setTimeout(r,3000));
    });
    const text = await p.evaluate(() => document.body.innerText);
    for (const want of ['MSI','MPG 491C OLED','5120x1440','49','DP-2','Digital','Raw EDID']) {
      console.log(`  shows "${want}":`, text.includes(want));
    }
    await p.screenshot({path:`${SHOTS}/osq-monitor-tab.png`});
  }
  console.log('errors:', errs.length ? errs.slice(0,3) : 'none');
  await b.close();
})().catch(e=>{console.error('FAILED',e.message);process.exit(1)});
