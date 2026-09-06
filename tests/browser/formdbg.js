// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Bijstaan
const { chromium } = require('playwright');
(async () => {
  const b = await chromium.launch();
  const p = await b.newPage();
  await p.goto('http://localhost:8081/', {waitUntil:'networkidle'});
  await p.fill('#login_name','glpi'); await p.fill('input[type=password]','glpi');
  await p.click('button[type=submit]'); await p.waitForLoadState('networkidle');
  await p.goto('http://localhost:8081/plugins/glpiosquery/front/agent.form.php?id=1', {waitUntil:'networkidle'});
  console.log(await p.evaluate(() => {
    const btn = document.querySelector('button[name=quarantine]');
    if (!btn) return 'NO BUTTON';
    const forms = [];
    let el = btn;
    while (el && el !== document.body) {
      if (el.tagName === 'FORM') forms.push({action: el.getAttribute('action'), method: el.getAttribute('method'), id: el.id});
      el = el.parentElement;
    }
    return JSON.stringify({
      buttonForm: btn.form ? {action: btn.form.getAttribute('action'), method: btn.form.getAttribute('method')} : null,
      ancestorForms: forms,
      totalFormsOnPage: document.querySelectorAll('form').length,
      csrfInButtonForm: btn.form ? !!btn.form.querySelector('input[name=_glpi_csrf_token]') : false,
      idInButtonForm: btn.form ? !!btn.form.querySelector('input[name=id]') : false,
    }, null, 1);
  }));
  await b.close();
})().catch(e=>{console.error(e.message);process.exit(1)});
