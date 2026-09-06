// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Bijstaan
// Verifies the console's completion in the positions an operator actually
// types in, and that extension-provided tables are discoverable.
const { chromium } = require('playwright');

const BASE = process.env.GLPI_URL || 'http://localhost:8081';

async function suggestionsAfter(page, text, caretBack = 0) {
  await page.click('.monaco-editor .view-lines');
  await page.keyboard.press('Control+A');
  await page.keyboard.type(text);
  for (let i = 0; i < caretBack; i++) await page.keyboard.press('ArrowLeft');
  await page.keyboard.press('Control+Space');
  const ok = await page
    .waitForSelector('.suggest-widget .monaco-list-row', { timeout: 8000 })
    .then(() => true)
    .catch(() => false);
  if (!ok) return [];
  const rows = await page.$$eval('.suggest-widget .monaco-list-row', (els) =>
    els.map((e) => e.innerText.split('\n')[0].trim()).slice(0, 6)
  );
  await page.keyboard.press('Escape');
  return rows;
}

(async () => {
  const b = await chromium.launch();
  const p = await b.newPage({ viewport: { width: 1600, height: 1000 } });
  await p.goto(`${BASE}/`, { waitUntil: 'networkidle' });
  await p.fill('#login_name', 'glpi');
  await p.fill('input[type=password]', 'glpi');
  await p.click('button[type=submit]');
  await p.waitForLoadState('networkidle');

  await p.goto(`${BASE}/plugins/glpiosquery/front/console.php`, { waitUntil: 'networkidle' });
  await p.waitForSelector('.monaco-editor', { timeout: 30000 });
  await p.waitForFunction(
    () => document.querySelectorAll('[data-osq-schema-list] button').length > 0,
    { timeout: 15000 }
  );

  console.log('tables in catalogue :', await p.textContent('[data-osq-schema-count]'));

  // Is the extension table discoverable in the browser panel?
  await p.fill('[data-osq-schema-filter]', 'glpi');
  await p.waitForTimeout(400);
  const found = await p.$$eval('[data-osq-schema-list] button', (els) =>
    els.map((e) => e.innerText.replace(/\s+/g, ' ').trim())
  );
  console.log('schema browser "glpi" :', JSON.stringify(found));

  console.log('SELECT <caret>       :', JSON.stringify(await suggestionsAfter(p, 'SELECT ')));
  console.log('SELECT host<caret>   :', JSON.stringify(await suggestionsAfter(p, 'SELECT host')));
  console.log('with FROM known      :', JSON.stringify(await suggestionsAfter(p, 'SELECT  FROM system_info', 16)));
  console.log('FROM glpi_<caret>    :', JSON.stringify(await suggestionsAfter(p, 'SELECT * FROM glpi_')));
  console.log('glpi_edid columns    :', JSON.stringify(await suggestionsAfter(p, 'SELECT  FROM glpi_edid', 15)));

  await b.close();
})().catch((e) => {
  console.error('FAILED', e.message);
  process.exit(1);
});
