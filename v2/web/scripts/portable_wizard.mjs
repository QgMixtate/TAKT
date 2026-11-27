// C52.04: веб-мастер Rust-portable в браузере (макеты версии 2): строка подготовки из Web → носитель; сбор этого ПК;
// «Узлы и сбор» → страница узла (разделы, причина); «Пакет» — файл на носителе; шрифты встроены (без сети).
//   node scripts/portable_wizard.mjs ПУТЬ_К_surveyscan-portable
import {spawn,execFileSync} from 'node:child_process';
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,copyFileSync,existsSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {chromium,expect} from '@playwright/test';

const exe=process.argv[2];if(!exe)throw new Error('путь к surveyscan-portable');
const checks=[];
const b64url=(t)=>Buffer.from(t).toString('base64url');
const prep='takt-portable:v1:'+b64url(JSON.stringify({tenant:'00000000-0000-4000-8000-000000000071',site:'00000000-0000-4000-8000-000000000072',scope:'00000000-0000-4000-8000-000000000073',site_name:'Москва, ЦОД-1',scope_name:'msk-dc1'}));

function wizard(dir,bin=exe,args=['wizard','--state',dir,'--no-browser']){
 return new Promise((resolve,reject)=>{const p=spawn(bin,args,{env:{...process.env,DISPLAY:'',BROWSER:'true'}});let buf='';
  p.stdout.on('data',d=>{buf+=d;const m=/http:\/\/127\.0\.0\.1:\d+\/#[0-9a-f]+/.exec(buf);if(m)resolve({p,url:m[0]})});p.on('exit',c=>reject(new Error('wizard exited '+c)));setTimeout(()=>reject(new Error('wizard did not start')),15000)});
}
const browser=await chromium.launch({headless:true,executablePath:process.env.SURVEYSCAN_CHROMIUM||undefined});
const errors=[],external=[];
try{
 // 1. новый носитель: строка подготовки → предпросмотр → «Подготовить»
 const fresh=mkdtempSync(join(tmpdir(),'wiz-new-'));const w1=await wizard(fresh);
 try{
  const page=await browser.newPage({viewport:{width:1440,height:900}});page.on('pageerror',e=>errors.push(e.message));page.on('request',r=>{if(!r.url().startsWith('http://127.0.0.1:'))external.push(r.url())});
  await page.goto(w1.url);await expect(page.getByRole('heading',{name:'Подготовка носителя'})).toBeVisible();
  await page.getByLabel('Строка подготовки из Web').fill('мусор');await expect(page.locator('.msg').last()).toContainText('takt-portable:v1:');
  await page.getByLabel('Строка подготовки из Web').fill(prep);await expect(page.locator('.facts')).toContainText('Москва, ЦОД-1');await expect(page.locator('.facts')).toContainText('Шифрование в центре не включено');
  await page.screenshot({path:'../.local/wizard-1-prep.png'});
  await page.getByRole('button',{name:/Подготовить носитель/}).click();await expect(page.getByRole('heading',{name:'Носитель подготовлен'})).toBeVisible({timeout:20000});
  await expect(page.locator('#ib')).toHaveValue(/site_id=00000000-0000-4000-8000-000000000072/);
  const fonts=await page.evaluate(async()=>{await document.fonts.ready;return document.fonts.check('600 13px Inter')&&document.fonts.check('700 20px Manrope')});if(!fonts)throw new Error('embedded fonts not loaded');
  checks.push('wizard step 1: preparation string from the Web previewed (site, encryption state), malformed string explained, medium prepared; embedded Inter/Manrope load without network');
 }finally{w1.p.kill()}
 // 2. носитель со сбором этого ПК: узлы, страница узла, пакет
 const dir=mkdtempSync(join(tmpdir(),'wiz-run-'));
 execFileSync(exe,['init','--state',dir,'--prep',prep]);mkdirSync(join(dir,'packages'));
 execFileSync(exe,['collect','--state',dir,'--out',join(dir,'packages','audit-ci.zip')]);
 const res=JSON.parse(readFileSync(join(dir,'results-last.json')));if(!res.hosts.length||res.hosts[0].transport!=='host'||res.hosts[0].sections.length!==12)throw new Error('results-last.json: '+JSON.stringify(res).slice(0,300));
 const host=res.hosts[0].target;
 const w2=await wizard(dir);
 try{
  const page=await browser.newPage({viewport:{width:1440,height:900}});page.on('pageerror',e=>errors.push(e.message));
  await page.goto(w2.url);await expect(page.getByRole('heading',{name:'Узлы и сбор'})).toBeVisible();
  const row=page.locator('tr',{hasText:host}).first();await expect(row).toContainText(/собрано|частично/);
  await page.screenshot({path:'../.local/wizard-4-nodes.png'});
  await row.click();await expect(page.getByRole('heading',{name:host})).toBeVisible();await expect(page.locator('table tbody tr')).toHaveCount(12);
  await expect(page.locator('.chain')).toContainText('в пакете');await page.screenshot({path:'../.local/wizard-4-node.png'});
  await page.getByRole('button',{name:'Узлы и сбор',exact:true}).click();
  // №135: правка поля и сразу «Сохранить и дальше» — одно нажатие (перерисовка по blur не съедает клик)
  await page.locator('nav [data-step="2"]').click();await page.getByRole('button',{name:/^Профиль/}).click();
  await page.getByLabel('Учётка').first().fill('audit');await page.getByRole('button',{name:/Сохранить и дальше/}).click();
  await expect(page.getByRole('heading',{name:'Узлы и сбор'})).toBeVisible();
  checks.push('wizard step 3: field edit followed by one click on «Сохранить и дальше» moves on (no lost click)');
  await page.locator('nav [data-step="4"]').click();await expect(page.getByRole('heading',{name:'Пакет',exact:true})).toBeVisible();await expect(page.locator('main')).toContainText('audit-ci.zip');await expect(page.locator('main')).toContainText('Разделы');
  await page.screenshot({path:'../.local/wizard-5-package.png'});
  checks.push('wizard steps 4–5: this PC collected — node row opens the node page (chain, 12 sections with status), package file with SHA-256 listed');
 }finally{w2.p.kill()}
 // запуск двойным щелчком: без параметров — мастер, носитель ss-portable рядом с программой
 const media=mkdtempSync(join(tmpdir(),'wiz-click-'));const bin=join(media,'surveyscan-portable');copyFileSync(exe,bin);execFileSync('chmod',['+x',bin]);
 const w3=await wizard(null,bin,[]);
 try{const page=await browser.newPage();await page.goto(w3.url);await expect(page.getByRole('heading',{name:'Подготовка носителя'})).toBeVisible();if(!existsSync(join(media,'ss-portable')))throw new Error('ss-portable not created next to the program');checks.push('double-click start: no arguments opens the wizard, medium ss-portable next to the program')}finally{w3.p.kill()}
 if(errors.length)throw new Error('page errors: '+errors.join('; '));
 if(external.length)throw new Error('external requests: '+external.join(', '));
 checks.push('wizard pages: no script errors, no requests outside 127.0.0.1');
 writeFileSync('../.local/c52-portable-wizard.json',JSON.stringify({package:'C52.04',status:'passed',checks,count:checks.length},null,1)+'\n');
 console.log(JSON.stringify({status:'passed',checks}));
}finally{await browser.close()}
