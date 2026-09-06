// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Bijstaan
// Checks the device page's "Agent status" field before and after the refresh
// control is clicked, plus the raw ajax the control uses.
const { chromium } = require('playwright');

const BASE = process.env.GLPI_URL || 'http://localhost:8081';
const ID = process.env.COMPUTER_ID || '11';
const AGENT_ID = process.env.AGENT_ID || '1';

(async () => {
  const b = await chromium.launch();
  const p = await b.newPage({ viewport: { width: 1500, height: 1000 } });

  await p.goto(`${BASE}/`, { waitUntil: 'networkidle' });
  await p.fill('#login_name', 'glpi');
  await p.fill('input[type=password]', 'glpi');
  await p.click('button[type=submit]');
  await p.waitForLoadState('networkidle');

  await p.goto(`${BASE}/front/computer.form.php?id=${ID}`, { waitUntil: 'networkidle' });
  await p.waitForTimeout(2000);

  console.log('BEFORE clicking refresh :', JSON.stringify((await p.textContent('#agent_status')).trim()));

  await p.click('#update-status');
  await p.waitForTimeout(6000);
  console.log('AFTER clicking refresh  :', JSON.stringify((await p.textContent('#agent_status')).trim()));

  const raw = await p.evaluate(async (agentId) => {
    const r = await fetch(`${CFG_GLPI.root_doc}/ajax/agent.php`, {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Glpi-Csrf-Token': document.querySelector('meta[property="glpi:csrf_token"]').content,
        'X-Requested-With': 'XMLHttpRequest',
      },
      body: new URLSearchParams({ action: 'status', id: agentId }).toString(),
    });
    return r.status + ' ' + (await r.text()).slice(0, 200);
  }, AGENT_ID);
  console.log('raw /ajax/agent.php     :', raw);

  await b.close();
})().catch((e) => {
  console.error('FAILED', e.message);
  process.exit(1);
});
