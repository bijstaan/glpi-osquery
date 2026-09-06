// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Bijstaan
// Verifies the package publish form: it renders, rejects bad input with a
// message, and a valid submission lands in the table. A form that silently
// does nothing looks identical to one that worked, which is exactly the
// failure mode worth a browser check.
const { chromium } = require('playwright');
const SHOTS = process.env.SHOT_DIR || '.';
(async () => {
  const b = await chromium.launch();
  const p = await b.newPage({viewport:{width:1600,height:1400}});
  const problems=[];
  p.on('console', m=>{ if(m.type()==='error') problems.push(m.text()); });
  p.on('pageerror', e=>problems.push('pageerror: '+e.message));
  p.on('response', r=>{ if(r.status()>=400) problems.push('HTTP '+r.status()+' '+r.url()); });

  await p.goto('http://localhost:8081/', {waitUntil:'networkidle'});
  await p.fill('#login_name','glpi'); await p.fill('input[type=password]','glpi');
  await p.click('button[type=submit]'); await p.waitForLoadState('networkidle');

  const url = 'http://localhost:8081/plugins/glpiosquery/front/settings.php';
  await p.goto(url, {waitUntil:'networkidle'});
  console.log('publish form present:', await p.locator('input[name=pkg_sha256]').count() === 1);

  // Rejection path: plain http must be refused with an explanation.
  await p.fill('input[name=pkg_version]','9.9.9');
  await p.fill('input[name=pkg_url]','http://packages.example.com/a.tar.gz');
  await p.fill('input[name=pkg_sha256]','a'.repeat(64));
  await p.fill('input[name=pkg_size]','123');
  await p.click('button[name=publish_package]');
  await p.waitForLoadState('networkidle');
  let text = await p.innerText('body');
  console.log('rejects plain http:', text.includes('must be https'));
  console.log('9.9.9 not published:', !text.includes('9.9.9'));

  // Accept path.
  await p.fill('input[name=pkg_version]','9.9.9');
  await p.fill('input[name=pkg_url]','https://packages.example.com/a.tar.gz');
  await p.fill('input[name=pkg_sha256]','b'.repeat(64));
  await p.fill('input[name=pkg_size]','4242');
  await p.selectOption('select[name=pkg_platform]','windows');
  await p.selectOption('select[name=pkg_arch]','arm64');
  await p.click('button[name=publish_package]');
  await p.waitForLoadState('networkidle');
  text = await p.innerText('body');
  console.log('published:', text.includes('Package published'));
  console.log('row visible:', text.includes('9.9.9') && text.includes('windows'));

  await p.screenshot({path:`${SHOTS}/osq-publish.png`, fullPage:true});

  // Withdraw it again so the check leaves no residue.
  const row = p.locator('tr', {hasText:'9.9.9'}).first();
  await row.locator('button[name=retire_package]').click();
  await p.waitForLoadState('networkidle');
  text = await p.innerText('body');
  console.log('withdrawn:', !text.includes('9.9.9'));

  console.log('errors:', problems.length ? [...new Set(problems)].slice(0,5) : 'none');
  await b.close();
})().catch(e=>{console.error('FAILED',e.message);process.exit(1)});
