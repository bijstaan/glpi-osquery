// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Bijstaan
const { chromium } = require('playwright');
const SHOTS = process.env.SHOT_DIR || '.';
(async () => {
  const b = await chromium.launch();
  const p = await b.newPage({viewport:{width:1500,height:1000}});
  await p.goto('http://localhost:8081/', {waitUntil:'networkidle'});
  await p.fill('#login_name','glpi'); await p.fill('input[type=password]','glpi');
  await p.click('button[type=submit]'); await p.waitForLoadState('networkidle');
  await p.goto('http://localhost:8081/front/computer.form.php?id=11', {waitUntil:'networkidle'});
  await p.waitForTimeout(2500);

  // Click the "Agent status" refresh control the same way a user would.
  const has = await p.evaluate(() => !!document.querySelector('#update-status'));
  console.log('agent panel present:', has);
  if (has) {
    await p.click('#update-status');
    await p.waitForFunction(() => {
      const el = document.querySelector('#agent_status');
      return el && el.textContent.trim() !== '' && el.textContent.trim() !== 'Unknown';
    }, {timeout: 30000}).catch(()=>{});
    console.log('agent status shown:', (await p.textContent('#agent_status')).trim());
  }
  const panel = await p.evaluate(() => {
    const card = Array.from(document.querySelectorAll('.card')).find(c => c.textContent.includes('Inventory information'));
    return card ? card.innerText.replace(/\n+/g,' | ').slice(0, 400) : null;
  });
  console.log('panel:', panel);
  await p.screenshot({path:`${SHOTS}/osq-agent-panel.png`});
  await b.close();
})().catch(e=>{console.error('FAILED',e.message);process.exit(1)});
