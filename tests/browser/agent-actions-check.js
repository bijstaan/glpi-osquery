// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Bijstaan
// Exercises the operator actions on an agent, through the real form so CSRF and
// rights are covered. Runs against the container agent, never the host one.
const { chromium } = require('playwright');
const { execSync } = require('child_process');

const BASE = process.env.GLPI_URL || 'http://localhost:8081';
const ID = process.env.AGENT_ID || '1';

const q = (sql) =>
  execSync(`docker exec glpi-db-1 mariadb -uglpi -pglpi glpi -N -e ${JSON.stringify(sql)} 2>/dev/null`)
    .toString()
    .trim();

const state = () =>
  q(`SELECT CONCAT(is_active,'|',IF(node_key_hash='','cleared','present'),'|',inventory_dirty) FROM glpi_plugin_glpiosquery_agents WHERE id=${ID};`);

async function click(page, name) {
  await page.goto(`${BASE}/plugins/glpiosquery/front/agent.form.php?id=${ID}`, { waitUntil: 'networkidle' });
  const btn = await page.$(`button[name=${name}]`);
  if (!btn) return false;
  await btn.click();
  await page.waitForLoadState('networkidle');
  return true;
}

(async () => {
  const b = await chromium.launch();
  const p = await b.newPage({ viewport: { width: 1500, height: 1000 } });
  await p.goto(`${BASE}/`, { waitUntil: 'networkidle' });
  await p.fill('#login_name', 'glpi');
  await p.fill('input[type=password]', 'glpi');
  await p.click('button[type=submit]');
  await p.waitForLoadState('networkidle');

  console.log('start           is_active|node_key|dirty =', state());

  console.log('quarantine clicked:', await click(p, 'quarantine'));
  console.log('after quarantine                        =', state());

  console.log('reinstate clicked :', await click(p, 'reinstate'));
  console.log('after reinstate                         =', state());

  console.log('rebuild clicked   :', await click(p, 'reinventory'));
  console.log('after rebuild                           =', state());

  console.log('re-enrol clicked  :', await click(p, 'reenroll'));
  console.log('after re-enrol                          =', state());

  await b.close();
})().catch((e) => {
  console.error('FAILED', e.message);
  process.exit(1);
});
