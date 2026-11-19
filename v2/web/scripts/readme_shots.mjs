// Скриншоты для README: демо-стенд (scripts/demo_stand.py, SURVEYSCAN_README=1) → системы, компоненты и привязки
// заводятся через настоящий API, затем снимаются экраны нового интерфейса. Только для показа, не проверка.
import {readFileSync} from 'node:fs';
import {chromium,expect} from '@playwright/test';
const c=JSON.parse(readFileSync(process.argv[2]));const out=process.argv[3];
const browser=await chromium.launch({headless:true,...(process.env.SURVEYSCAN_CHROMIUM?{executablePath:process.env.SURVEYSCAN_CHROMIUM}:{})});
try{
 const ctx=await browser.newContext({viewport:{width:1440,height:900},deviceScaleFactor:1});const page=await ctx.newPage();
 const shot=async n=>{await page.waitForTimeout(700);await page.screenshot({path:`${out}/${n}.png`})};
 await page.goto(c.origin);await expect(page.getByRole('heading',{name:'Вход',exact:true})).toBeVisible();await shot('readme-login');
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
 await page.reload();await expect(page.getByRole('button',{name:'Расчёт зарплаты',exact:true})).toBeVisible();await shot('readme-systems');
 await page.getByRole('button',{name:'Расчёт зарплаты',exact:true}).click();await page.getByRole('button',{name:'Карточка системы →'}).click();await expect(page.getByRole('heading',{name:'Расчёт зарплаты',level:1})).toBeVisible();await shot('readme-system-card');
 await nav.getByRole('button',{name:/^Компоненты/}).click();await page.waitForTimeout(500);await shot('readme-components');
 await nav.getByRole('button',{name:/^Хосты/}).click();await expect(page.locator('.asset-link').first()).toBeVisible();await shot('readme-hosts');
 await page.locator('.asset-link',{hasText:'demo-app01'}).first().click();await expect(page.getByRole('dialog')).toBeVisible();await shot('readme-host-card');
 await page.keyboard.press('Escape');
 await nav.getByRole('button',{name:/^Схема сети/}).click();await page.waitForTimeout(1500);await shot('readme-topology');
 await nav.getByRole('button',{name:/^Обращения/}).click();await page.waitForTimeout(800);await shot('readme-tickets');
}finally{await browser.close()}
