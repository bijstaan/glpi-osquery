// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Bijstaan
const { chromium } = require('playwright');
const SHOTS = process.env.SHOT_DIR || '.';
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
  await b.close();
})().catch(e=>{console.error('FAILED',e.message);process.exit(1)});
