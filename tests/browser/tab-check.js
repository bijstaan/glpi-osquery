// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Bijstaan
const { chromium } = require('playwright');
const SHOTS = process.env.SHOT_DIR || '.';
(async () => {
  const b = await chromium.launch();
  const p = await b.newPage({viewport:{width:1600,height:1000}});
  const problems=[];
  p.on('console', m => { if (m.type()==='error') problems.push(m.text()); });
  p.on('pageerror', e => problems.push('pageerror: '+e.message));
  await p.goto('http://localhost:8081/', {waitUntil:'networkidle'});
  await p.fill('#login_name','glpi'); await p.fill('input[type=password]','glpi');
  await p.click('button[type=submit]'); await p.waitForLoadState('networkidle');

  await p.goto('http://localhost:8081/front/computer.form.php?id=11', {waitUntil:'networkidle'});
  await p.evaluate(() => {
    const a = Array.from(document.querySelectorAll('a')).find(a=>a.textContent.trim().startsWith('Live query'));
    a.click();
  });
  await p.waitForSelector('.monaco-editor', {timeout:30000});
  await p.waitForFunction(()=>document.querySelectorAll('[data-osq-schema-list] button').length>0, {timeout:15000});

  const count = await p.textContent('[data-osq-schema-count]');
  const windowsOnly = await p.evaluate(()=>
    Array.from(document.querySelectorAll('[data-osq-schema-list] button')).some(b=>b.textContent.includes('bitlocker_info')));
  const hasLinux = await p.evaluate(()=>
    Array.from(document.querySelectorAll('[data-osq-schema-list] button')).some(b=>b.textContent.includes('deb_packages')));
  console.log('tables offered for this Linux host:', count);
  console.log('offers windows-only bitlocker_info:', windowsOnly, '(should be false)');
  console.log('offers linux deb_packages:', hasLinux, '(should be true)');
  console.log('targeting controls shown:', await p.evaluate(()=>!!document.querySelector('[data-osq-entities]')), '(should be false in device mode)');

  await p.click('[data-osq-run]');
  const got = await p.waitForFunction(()=>document.querySelectorAll('[data-osq-results] tbody tr').length>0, {timeout:90000}).then(()=>true).catch(()=>false);
  console.log('device query returned rows:', got);
  console.log('status:', (await p.textContent('[data-osq-status]')).trim());
  await p.screenshot({path:`${SHOTS}/osq-device-tab.png`});
  console.log('errors:', problems.length ? [...new Set(problems)].slice(0,5) : 'none');
  await b.close();
})().catch(e=>{console.error('FAILED',e.message);process.exit(1)});
