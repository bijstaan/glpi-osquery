// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Bijstaan
// Exercises the agent management UI: fleet list, search engine, per-agent
// detail, its tabs, and the operator actions.
const { chromium } = require('playwright');

const BASE = process.env.GLPI_URL || 'http://localhost:8081';
const SHOTS = process.env.SHOT_DIR || '.';

(async () => {
  const b = await chromium.launch();
  const p = await b.newPage({ viewport: { width: 1600, height: 1100 } });
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

  // --- fleet list
  await p.goto(`${BASE}/plugins/glpiosquery/front/agent.php`, { waitUntil: 'networkidle' });
  await p.waitForTimeout(1500);

  const summary = await p.evaluate(() =>
    Array.from(document.querySelectorAll('.row-cards .card')).map((c) =>
      c.innerText.replace(/\n+/g, ' ').trim()
    )
  );
  console.log('fleet summary :', JSON.stringify(summary));

  const rows = await p.evaluate(
    () => document.querySelectorAll('table.search-results tbody tr, table tbody tr').length
  );
  console.log('list rendered :', rows > 0 ? `${rows} rows` : 'NO ROWS');

  const hasSearch = await p.evaluate(
    () => !!document.querySelector('form[name=searchform], .search-form, #searchcriteria')
  );
  console.log('search engine :', hasSearch);
  await p.screenshot({ path: `${SHOTS}/osq-agent-list.png` });

  // --- agent detail
  await p.goto(`${BASE}/plugins/glpiosquery/front/agent.form.php?id=3`, { waitUntil: 'networkidle' });
  await p.waitForTimeout(1500);
  const detail = await p.evaluate(() => document.body.innerText);
  for (const want of ['Matt-Framework', 'Last check-in', 'Agent version', 'Inventoried asset']) {
    console.log(`detail has "${want}":`, detail.includes(want));
  }

  const tabs = await p.evaluate(() =>
    Array.from(document.querySelectorAll('a[role=tab], .nav-link'))
      .map((e) => e.textContent.trim())
      .filter((t) => t && t.length < 30)
  );
  console.log('tabs          :', JSON.stringify(tabs.filter((t) => /Collected|log|History/i.test(t))));
  await p.screenshot({ path: `${SHOTS}/osq-agent-detail.png` });

  // --- collected data tab
  const collected = await p.evaluate(async () => {
    const a = Array.from(document.querySelectorAll('a')).find((x) =>
      x.textContent.trim().startsWith('Collected data')
    );
    if (!a) return null;
    a.click();
    await new Promise((r) => setTimeout(r, 3000));
    const rows = document.querySelectorAll('table tbody tr').length;
    return rows;
  });
  console.log('collected rows:', collected);

  console.log('errors        :', problems.length ? [...new Set(problems)].slice(0, 4) : 'none');
  await b.close();
})().catch((e) => {
  console.error('FAILED', e.message);
  process.exit(1);
});
