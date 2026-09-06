// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Bijstaan
// Exercises the osquery live-query console in a real browser: loads the page,
// waits for Monaco, drives the autocomplete, runs a query against the test
// agent, and screenshots the result.
//
// Any console error or failed request is reported — a silent JS failure would
// otherwise look like "the editor just didn't appear".
const { chromium } = require('playwright');

const SHOTS = process.env.SHOT_DIR || '.';
const BASE = process.env.GLPI_URL || 'http://localhost:8081';

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });

  const problems = [];
  page.on('console', (m) => {
    if (m.type() === 'error') problems.push('console: ' + m.text());
  });
  page.on('requestfailed', (r) => problems.push('request failed: ' + r.url()));
  page.on('response', (r) => {
    if (r.status() >= 400) problems.push(`HTTP ${r.status()} ${r.url()}`);
  });

  await page.goto(`${BASE}/`, { waitUntil: 'networkidle' });
  await page.fill('#login_name', 'glpi');
  await page.fill('input[type=password]', 'glpi');
  await page.click('button[type=submit]');
  await page.waitForLoadState('networkidle');
  console.log('logged in');

  await page.goto(`${BASE}/plugins/glpiosquery/front/console.php`, { waitUntil: 'networkidle' });

  // Monaco is loaded lazily by GLPI's module, so wait for the real editor.
  await page.waitForSelector('.monaco-editor', { timeout: 30000 });
  console.log('monaco ready');

  await page.waitForFunction(
    () => document.querySelectorAll('[data-osq-schema-list] button').length > 0,
    { timeout: 15000 }
  );
  const tableCount = await page.textContent('[data-osq-schema-count]');
  console.log('schema browser tables:', tableCount);

  await page.screenshot({ path: `${SHOTS}/osq-console-initial.png` });

  // --- autocomplete: type a FROM and check tables are offered
  await page.click('.monaco-editor .view-lines');
  await page.keyboard.press('Control+A');
  await page.keyboard.type('SELECT * FROM inter');
  await page.keyboard.press('Control+Space');
  const gotSuggest = await page
    .waitForSelector('.suggest-widget .monaco-list-row', { timeout: 8000 })
    .then(() => true)
    .catch(() => false);

  let suggestions = [];
  if (gotSuggest) {
    suggestions = await page.$$eval('.suggest-widget .monaco-list-row', (rows) =>
      rows.map((r) => r.innerText.split('\n')[0].trim()).slice(0, 8)
    );
    await page.screenshot({ path: `${SHOTS}/osq-console-autocomplete.png` });
  }
  console.log('table suggestions:', JSON.stringify(suggestions));

  // --- column completion after a dot
  await page.keyboard.press('Escape');
  await page.keyboard.press('Control+A');
  await page.keyboard.type('SELECT i. FROM interface_details i');
  // put the caret back after the dot
  await page.keyboard.press('Home');
  for (let i = 0; i < 9; i++) await page.keyboard.press('ArrowRight');
  await page.keyboard.press('Control+Space');
  const gotCols = await page
    .waitForSelector('.suggest-widget .monaco-list-row', { timeout: 8000 })
    .then(() => true)
    .catch(() => false);
  let columns = [];
  if (gotCols) {
    columns = await page.$$eval('.suggest-widget .monaco-list-row', (rows) =>
      rows.map((r) => r.innerText.split('\n')[0].trim()).slice(0, 8)
    );
    await page.screenshot({ path: `${SHOTS}/osq-console-columns.png` });
  }
  console.log('column suggestions:', JSON.stringify(columns));

  // --- run a real query
  await page.keyboard.press('Escape');
  await page.keyboard.press('Control+A');
  await page.keyboard.type('SELECT hostname, cpu_brand FROM system_info');
  await page.uncheck('[data-osq-online]').catch(() => {});
  await page.click('[data-osq-run]');

  await page.waitForSelector('[data-osq-status]:visible', { timeout: 10000 });
  console.log('status:', (await page.textContent('[data-osq-status]')).trim());

  // Results arrive on the agent's next check-in.
  const gotRow = await page
    .waitForFunction(
      () => document.querySelectorAll('[data-osq-results] tbody tr').length > 0,
      { timeout: 90000 }
    )
    .then(() => true)
    .catch(() => false);

  console.log('rows arrived:', gotRow);
  console.log('final status:', (await page.textContent('[data-osq-status]')).trim());
  await page.screenshot({ path: `${SHOTS}/osq-console-results.png` });

  if (problems.length) {
    console.log('\nPROBLEMS:');
    [...new Set(problems)].forEach((p) => console.log('  -', p));
  } else {
    console.log('\nno console errors or failed requests');
  }

  await browser.close();
})().catch((e) => {
  console.error('FAILED:', e.message);
  process.exit(1);
});
