// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Bijstaan
// Saved query library: the list page, the picker in the console, running a
// saved query, and CSV export.
const { chromium } = require('playwright');

const BASE = process.env.GLPI_URL || 'http://localhost:8081';
const SHOTS = process.env.SHOT_DIR || '.';

(async () => {
  const b = await chromium.launch();
  const p = await b.newPage({ viewport: { width: 1600, height: 1000 } });
  const problems = [];
  p.on('pageerror', (e) => problems.push('pageerror: ' + e.message));
  p.on('response', (r) => {
    if (r.status() >= 500) problems.push(`HTTP ${r.status()} ${r.url()}`);
  });

  await p.goto(`${BASE}/`, { waitUntil: 'networkidle' });
  await p.fill('#login_name', 'glpi');
  await p.fill('input[type=password]', 'glpi');
  await p.click('button[type=submit]');
  await p.waitForLoadState('networkidle');

  // --- library list
  await p.goto(`${BASE}/plugins/glpiosquery/front/savedquery.php`, { waitUntil: 'networkidle' });
  await p.waitForTimeout(1200);
  const listed = await p.evaluate(() => document.body.innerText);
  console.log('library lists "Disk space":', listed.includes('Disk space'));
  console.log('library lists "Uptime"    :', listed.includes('Uptime'));

  // --- console picker
  await p.goto(`${BASE}/plugins/glpiosquery/front/console.php`, { waitUntil: 'networkidle' });
  await p.waitForSelector('.monaco-editor', { timeout: 30000 });
  await p.waitForTimeout(1500);

  const options = await p.$$eval('[data-osq-saved] option', (els) =>
    els.map((e) => e.textContent.trim()).filter((t) => t && !t.startsWith('—'))
  );
  console.log('picker options            :', options.length, JSON.stringify(options.slice(0, 4)));

  // Choose "Uptime" and confirm it loads into the editor.
  const uptime = await p.$$eval('[data-osq-saved] option', (els) => {
    const o = els.find((e) => e.textContent.trim() === 'Uptime');
    return o ? o.value : null;
  });
  await p.selectOption('[data-osq-saved]', uptime);
  await p.waitForTimeout(600);
  const loaded = await p.evaluate(() => window.monaco.editor.getEditors()[0].getValue());
  console.log('editor loaded the query   :', JSON.stringify(loaded.slice(0, 60)));

  // --- run it
  await p.uncheck('[data-osq-online]').catch(() => {});
  await p.click('[data-osq-run]');
  const got = await p
    .waitForFunction(() => document.querySelectorAll('[data-osq-results] tbody tr').length > 0, { timeout: 90000 })
    .then(() => true)
    .catch(() => false);
  console.log('saved query returned rows :', got);
  console.log('status                    :', (await p.textContent('[data-osq-status]')).trim().slice(0, 90));

  const exportEnabled = await p.evaluate(
    () => !document.querySelector('[data-osq-export]').disabled
  );
  console.log('CSV export enabled        :', exportEnabled);

  await p.screenshot({ path: `${SHOTS}/osq-savedquery.png` });
  console.log('errors                    :', problems.length ? [...new Set(problems)].slice(0, 3) : 'none');
  await b.close();
})().catch((e) => {
  console.error('FAILED', e.message);
  process.exit(1);
});
