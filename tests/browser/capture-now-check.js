// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Bijstaan
// Drives the "Capture now" button the way a technician would: open the ticket,
// find the tab, press the button. The form posts to a plugin front script, and
// a CSRF or right-check mistake there fails silently as a redirect — which is
// indistinguishable from success unless the capture count is checked.
const { chromium } = require('playwright');
const SHOTS = process.env.SHOT_DIR || '.';
(async () => {
  const b = await chromium.launch();
  const p = await b.newPage({viewport:{width:1600,height:1200}});
  const problems=[];
  p.on('pageerror', e=>problems.push('pageerror: '+e.message));
  p.on('response', r=>{ if(r.status()>=400) problems.push('HTTP '+r.status()+' '+r.url()); });

  await p.goto('http://localhost:8081/', {waitUntil:'networkidle'});
  await p.fill('#login_name','glpi'); await p.fill('input[type=password]','glpi');
  await p.click('button[type=submit]'); await p.waitForLoadState('networkidle');

  await p.goto('http://localhost:8081/front/ticket.form.php?id=46', {waitUntil:'networkidle'});

  const tab = p.locator('a.nav-link', {hasText: 'Machine state'}).first();
  console.log('  tab present:', await tab.count() > 0);
  await tab.click();
  await p.waitForLoadState('networkidle');
  await p.waitForTimeout(800);

  const body = await p.innerText('body');
  console.log('  names the asset:', body.includes('Matt-Framework'));
  console.log('  lists past captures:', body.includes('on request') || body.includes('asset attached'));

  const btn = p.locator('button[name=capture_now]').first();
  console.log('  button present:', await btn.count() > 0);
  await p.screenshot({path:`${SHOTS}/osq-capture-tab.png`, fullPage:true});

  await btn.click();
  await p.waitForLoadState('networkidle');
  const after = await p.innerText('body');
  console.log('  confirmation shown:', after.includes('Asking the machine now'));

  console.log('errors:', problems.length ? [...new Set(problems)].slice(0,3) : 'none');
  await b.close();
})().catch(e=>{console.error('FAILED',e.message);process.exit(1)});
