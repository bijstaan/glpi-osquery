// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Bijstaan
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const { openDark, audit } = require('./dark');
const SHOTS = process.env.SHOT_DIR || '.';
const DARK_SHOTS = path.join(SHOTS, 'dark');
(async () => {
  const b = await chromium.launch();
  const p = await b.newPage({viewport:{width:1600,height:1200}});
  const problems=[];
  p.on('console', m=>{ if(m.type()==='error') problems.push(m.text()); });
  p.on('pageerror', e=>problems.push('pageerror: '+e.message));
  p.on('response', r=>{ if(r.status()>=500) problems.push('HTTP '+r.status()+' '+r.url()); });
  await p.goto('http://localhost:8081/', {waitUntil:'networkidle'});
  await p.fill('#login_name','glpi'); await p.fill('input[type=password]','glpi');
  await p.click('button[type=submit]'); await p.waitForLoadState('networkidle');
  await p.goto('http://localhost:8081/plugins/glpiosquery/front/settings.php', {waitUntil:'networkidle'});
  const text = await p.innerText('body');
  console.log('has fleet tuning:', text.includes('Fleet tuning'));
  console.log('has enrollment secrets:', text.includes('Enrollment secrets'));
  console.log('has agent updates:', text.includes('Agent updates'));
  console.log('has version spread:', text.includes('versions in the fleet'));
  console.log('has published packages:', text.includes('Published packages'));
  console.log('has endpoints table:', text.includes('--enroll_tls_endpoint'));
  await p.screenshot({path:`${SHOTS}/osq-settings.png`, fullPage:true});
  console.log('errors:', problems.length ? [...new Set(problems)].slice(0,5) : 'none');

  // --- The dark palette --------------------------------------------------
  //
  // The settings page carries the fleet tuning panels, the enrollment secrets
  // and the version spread — all this plugin's own markup, none of it covered
  // by GLPI's dark stylesheet.
  fs.mkdirSync(DARK_SHOTS, { recursive: true });
  console.log('switching to the dark palette...');

  const dark = await openDark(b, { plugin: 'glpiosquery', viewport: { width: 1600, height: 1200 } });

  for (const [url, name, shot] of [
    ['http://localhost:8081/plugins/glpiosquery/front/settings.php', 'settings', 'osq-dark-01-settings.png'],
    ['http://localhost:8081/plugins/glpiosquery/front/agent.php', 'the agent fleet', 'osq-dark-02-agent-list.png'],
    ['http://localhost:8081/plugins/glpiosquery/front/console.php', 'the live query console', 'osq-dark-03-console.png'],
  ]) {
    await dark.goto(url, { waitUntil: 'networkidle' });
    await dark.waitForTimeout(500);
    const bad = await audit(dark, 'glpiosquery-');
    console.log(`[dark] ${name}: near-white panels:`, JSON.stringify(bad.whiteBg));
    console.log(`[dark] ${name}: sub-4.5:1 muted text:`, JSON.stringify(bad.lowContrast));
    if (bad.whiteBg.length || bad.lowContrast.length) problems.push(`[dark] ${name} fails the contrast audit`);
    await dark.screenshot({ path: `${DARK_SHOTS}/${shot}`, fullPage: true });
  }

  await b.close();
})().catch(e=>{console.error('FAILED',e.message);process.exit(1)});
