// Скриншоты для README: демо-стенд (scripts/demo_stand.py, SURVEYSCAN_README=1) → системы, компоненты и привязки
// заводятся через настоящий API, затем снимаются экраны нового интерфейса. Только для показа, не проверка.
import {readFileSync} from 'node:fs';
import {chromium,expect} from '@playwright/test';
const c=JSON.parse(readFileSync(process.argv[2]));const out=process.argv[3];
const browser=await chromium.launch({headless:true,...(process.env.SURVEYSCAN_CHROMIUM?{executablePath:process.env.SURVEYSCAN_CHROMIUM}:{})});
try{
 const ctx=await browser.newContext({viewport:{width:1600,height:1000},deviceScaleFactor:1});const page=await ctx.newPage();
 // ширины сверки с макетами: раздел рядом с макетом при 1440 и 1280 px (доводка C53)
 const widths=(process.env.SURVEYSCAN_AUDIT_WIDTHS||'1440,1280').split(',').map(Number);let W=widths[0];
 const shot=async n=>{await page.waitForTimeout(700);await page.screenshot({path:`${out}/${W}-${n}.png`})};
 await page.goto(c.origin);await expect(page.getByRole('heading',{name:'Вход',exact:true})).toBeVisible();
 for(W of widths){await page.setViewportSize({width:W,height:900});await shot('00-login')}
 const sessionReply=page.waitForResponse(r=>r.url().endsWith('/api/v1/auth/sessions')&&r.status()===201);
 await page.getByLabel('Логин').fill(c.username);await page.getByLabel('Пароль',{exact:true}).fill(c.password);await page.getByRole('button',{name:'Войти',exact:true}).click();
 const s=await (await sessionReply).json();const H={Origin:c.origin,'X-CSRF-Token':s.csrf_token};
 const api=async(method,path,data)=>{const r=await ctx.request.fetch(c.origin+path,{method,headers:H,...(data!==undefined?{data}:{})});if(!r.ok())throw new Error(method+' '+path+' '+r.status()+' '+await r.text());return r.status()===204?null:r.json()};
 // хосты демо-сети
 const hosts={};let cur='';do{const p=await api('GET','/api/v1/assets?limit=200'+(cur?'&cursor='+cur:''));for(const a of p.items)if(a.observed_hostname)hosts[a.observed_hostname]=a.asset_uid;cur=p.next_cursor??''}while(cur);
 const fin=await api('POST','/api/v1/rsm/directions',{name:'Финансы'}),inf=await api('POST','/api/v1/rsm/directions',{name:'Инфраструктура'});
 async function system(name,crit,dir,owner,envs){const sv=await api('POST','/api/v1/services',{name,criticality:crit});let sys=await api('GET','/api/v1/rsm/systems/'+sv.service_uid);
  await api('PATCH','/api/v1/rsm/systems/'+sv.service_uid,{revision:sys.system.revision,direction_uid:dir.direction_uid,business_owner:owner,maintenance_window:'вс 02:00–05:00',on_call:'дежурная смена ИТ'});
  for(const [kind,ename,comps] of envs){const env=await api('POST','/api/v1/rsm/systems/'+sv.service_uid+'/environments',{kind,name:ename});
   for(const [cname,critical,names,baseline] of comps){const comp=await api('POST','/api/v1/rsm/environments/'+env.environment_id+'/components',{name:cname,critical,...(baseline?{baseline}:{})});
    const uids=names.map(n=>hosts[n]).filter(Boolean);if(uids.length)await api('POST','/api/v1/rsm/components/'+comp.component_id+'/bindings',{asset_uids:uids})}}
  return sv}
 const pay=await system('Расчёт зарплаты','high',fin,'Главный бухгалтер',[['prod','Продуктив',[['Веб-приложение',true,['demo-app01'],{os:'Ubuntu'}],['СУБД',true,['demo-db01'],{os:'Ubuntu'}]]],['test','Тест',[['Веб-приложение',false,[]]]]]);
 const ad=await system('Каталог AD','high',inf,'Начальник ИТ',[['prod','Продуктив',[['Контроллеры домена',true,['demo-dc01'],{os:'Windows Server'}]]]]);
 await system('Файловый сервис','medium',inf,'Начальник ИТ',[['prod','Продуктив',[['Файловый сервер',false,['demo-files01']],['Резервное копирование',false,['demo-backup01']]]]]);
 await system('Сеть передачи данных','high',inf,'Начальник ИТ',[['prod','Продуктив',[['Ядро сети',true,['demo-core-router']]]]]);
 await api('POST','/api/v1/relations',{relation_type:'depends_on',from:{kind:'service',id:pay.service_uid},to:{kind:'service',id:ad.service_uid},note:'вход пользователей'});
 if(hosts['demo-db01'])await api('POST','/api/v1/itsm/tickets',{kind:'incident',title:'demo-db01: медленные запросы в отчётах',description:'Отчёт по зарплате строится дольше 10 минут.',impact:2,urgency:2,asset_uid:hosts['demo-db01'],service_uid:pay.service_uid});
 await api('POST','/api/v1/rsm/recompute',{});
 const nav=page.getByRole('navigation',{name:'Разделы'});
 const go=async(name)=>{await nav.getByRole('button',{name:new RegExp('^'+name)}).click();await page.waitForTimeout(1500)};
 const tab=async(name)=>{await page.getByRole('tab',{name}).first().click();await page.waitForTimeout(1000)};
 const safe=async(n,fn)=>{try{await fn();await shot('audit-'+n)}catch(e){console.error('audit '+n+': '+e.message.split('\n')[0])}};
 for(W of widths){await page.setViewportSize({width:W,height:900});
 await page.reload();await page.waitForTimeout(1500);
 await safe('01-systems',async()=>{await go('Системы');await page.getByRole('button',{name:'Расчёт зарплаты',exact:true}).click();await page.waitForTimeout(800)});
 await safe('02-system-card',async()=>{await page.getByRole('button',{name:'Карточка системы →'}).click();await page.waitForTimeout(1200)});
 await safe('03-component-card',async()=>{await page.getByRole('button',{name:'СУБД'}).first().click();await page.waitForTimeout(1200)});
 await safe('04-health',async()=>{await go('Здоровье');await page.getByRole('combobox',{name:'Показывать'}).selectOption('all');await page.locator('.health-table tr.h-row').nth(1).click()});
 await safe('05-components',async()=>{await go('Компоненты')});
 await safe('06-hosts',async()=>{await go('Хосты')});
 await safe('07-host-card',async()=>{await page.locator('.asset-link',{hasText:'demo-app01'}).first().click();await page.waitForTimeout(1500)});
 await page.keyboard.press('Escape');
 await safe('08-topology',async()=>{await go('Схема сети');await page.locator('.network .tree-item').first().click();await page.waitForTimeout(1500)});
 await safe('09-reconcile',async()=>{await go('Разбор конфликтов')});
 await safe('10-sources',async()=>{await go('Источники');await page.locator('tr.src-row').nth(1).click()});
 await safe('11-discovery',async()=>{await go('Обследования сети')});
 await safe('12-portable',async()=>{await go('Portable-аудит')});
 await safe('13-worklist',async()=>{await go('Мои задачи')});
 await safe('14-tickets',async()=>{await go('Обращения');const r=page.locator('.systems-main tbody tr button').first();if(await r.count())await r.click();await page.waitForTimeout(800)});
 await safe('15-servicedesk',async()=>{await page.getByRole('button',{name:'Закрыть'}).first().click().catch(()=>{});await tab('Каталог услуг')});
 await safe('16-warehouse',async()=>{await go('Склад');const p=page.getByRole('button',{name:'Предпросмотр акта'});if(await p.count())await p.first().click()});
 await safe('17-org',async()=>{await go('Оргструктура')});
 await safe('18-hooks',async()=>{await go('Уведомления')});
 await safe('19-search',async()=>{await page.getByLabel('Общий поиск').fill('demo');await page.getByLabel('Общий поиск').press('Enter');await page.waitForTimeout(2000)});
 await safe('20-unassigned',async()=>{await go('Системы');await page.getByRole('button',{name:/хостов вне систем/}).click()});
 await safe('21-wizard',async()=>{await go('Системы');await page.locator('summary',{hasText:'Действия'}).click();await page.getByRole('button',{name:'Новая система…'}).click();await page.getByLabel('Название').fill('Кадровый портал');await page.getByRole('button',{name:/Далее: среды/}).click();await page.getByRole('button',{name:/Далее: компоненты/}).click()});
 await safe('22-platforms',async()=>{await page.keyboard.press('Escape');await go('Платформы')});
 await safe('23-sources-install',async()=>{await go('Источники');await tab(/Установка/)});
 await safe('24-hosts-full',async()=>{await go('Хосты');await page.screenshot({path:`${out}/${W}-24-hosts-fullpage.png`,fullPage:true})});
 await safe('25-org-full',async()=>{await go('Оргструктура');await page.screenshot({path:`${out}/${W}-25-org-fullpage.png`,fullPage:true})});
 await safe('26-hooks-full',async()=>{await go('Уведомления');await page.screenshot({path:`${out}/${W}-26-hooks-fullpage.png`,fullPage:true})});
 }
}finally{await browser.close()}
