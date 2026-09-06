// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Bijstaan
// The evidence followup has to be readable in the ticket timeline, which is
// the only place it will ever be seen. Rendering it correctly into a database
// column proves nothing about that.
const { chromium } = require('playwright');
const SHOTS = process.env.SHOT_DIR || '.';
(async () => {
  const b = await chromium.launch();
  const p = await b.newPage({viewport:{width:1500,height:1500}});
  const problems=[];
  p.on('pageerror', e=>problems.push('pageerror: '+e.message));
  p.on('response', r=>{ if(r.status()>=500) problems.push('HTTP '+r.status()+' '+r.url()); });

  await p.goto('http://localhost:8081/', {waitUntil:'networkidle'});
  await p.fill('#login_name','glpi'); await p.fill('input[type=password]','glpi');
  await p.click('button[type=submit]'); await p.waitForLoadState('networkidle');

  const id = process.env.TICKET || '46';
  await p.goto(`http://localhost:8081/front/ticket.form.php?id=${id}`, {waitUntil:'networkidle'});
  const text = await p.innerText('body');

  for (const [what, needle] of [
    ['heading',        'Machine state when this ticket was raised'],
    ['os section',     'Operating system'],
    ['disk section',   'Disk space'],
    ['memory section', 'Memory'],
    ['process list',   'Top processes by memory'],
    ['active user',    'Active user'],
    ['real data',      'Resolute Raccoon'],
  ]) console.log(`  shows ${what}: ${text.includes(needle)}`);

  console.log('  marked private:', text.toLowerCase().includes('private'));
  console.log('  snap noise absent:', !text.includes('/snap/'));

  await p.screenshot({path:`${SHOTS}/osq-ticket-evidence.png`, fullPage:true});
  console.log('errors:', problems.length ? [...new Set(problems)].slice(0,3) : 'none');
  await b.close();
})().catch(e=>{console.error('FAILED',e.message);process.exit(1)});
