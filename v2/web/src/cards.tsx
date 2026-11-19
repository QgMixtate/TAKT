import {useEffect,useState} from 'react';
import {api,ApiError,errorMessage,type RSMChange,type RSMComponentCard,type RSMEnvKind,type RSMHostRow,type RSMOverview,type RSMProblems,type RSMSystemCard} from './api';
import {CritBadge,critLabel,problemsText} from './systems';
import {SystemCard as SystemEdit,ComponentCard as ComponentEdit} from './rsm';

// C53.03 — карточки системы (макет C53-mockups/7) и компонента (макет 8): шапка с показателями, вкладки, обзор.
// Редактирование (среды, компоненты, поля системы, правила, привязка списком) — вкладками на прежних формах.

const envShort:Record<RSMEnvKind,string>={prod:'Прод',dr:'DR',stage:'Предпрод',test:'Тест',dev:'Разр.',other:'Другая'};
const envLower:Record<RSMEnvKind,string>={prod:'прод',dr:'DR',stage:'предпрод',test:'тест',dev:'разработка',other:'другая'};
const fmt=(n:number)=>n.toLocaleString('ru-RU');
const when=(v:string|null)=>v?new Date(v).toLocaleString('ru-RU',{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'}).replace(',',''):'—';
function plural(n:number,a:string,b:string,c:string){const m10=n%10,m100=n%100;return m10===1&&m100!==11?a:m10>=2&&m10<=4&&(m100<10||m100>=20)?b:c}
function useLive<T>(load:()=>Promise<T>,deps:unknown[],onExpired:()=>void):[T|null,unknown,()=>void]{
 const [data,setData]=useState<T|null>(null),[error,setError]=useState<unknown>(null),[n,setN]=useState(0);
 useEffect(()=>{let live=true;setError(null);load().then(d=>{if(live)setData(d)}).catch(e=>{if(live){setError(e);if(e instanceof ApiError&&e.status===401)onExpired()}});return()=>{live=false}},[...deps,n]);
 return [data,error,()=>setN(x=>x+1)];
}
const Err=({e}:{e:unknown})=>e?<div className="error" role="alert">{errorMessage(e)}</div>:null;
const reasonPhrase:Record<string,string>={INVENTORY_STALE:'данные устарели',INVENTORY_LOST:'данных нет больше недели',NO_INVENTORY:'нет инвентаризации',HOST_MISSING:'пропали из подсети',RECONCILIATION_CONFLICT:'конфликт сопоставления',BASELINE_OS:'ОС не по эталону',BASELINE_SOFTWARE_MISSING:'нет ПО из эталона',BASELINE_SOFTWARE_VERSION:'версия ПО не по эталону'};
const changeName:Record<string,string>={'binding/created':'Хост привязан к компоненту','binding/closed':'Хост отвязан от компонента','binding/proposed':'Правило предложило привязку','binding/confirmed':'Привязка подтверждена','binding/rejected':'Предложение отклонено','binding/retargeted':'Привязка перенесена при слиянии','binding/updated':'Сменилась основная привязка','component/created':'Создан компонент','environment/created':'Создана среда','service/created':'Создана система','service/updated':'Изменены поля системы','service/retired':'Система выведена','binding_rule/created':'Добавлено правило автопривязки','binding_rule/retired':'Снято правило автопривязки','component_dependency/created':'Добавлена зависимость компонентов','relation/created':'Добавлена связь','relation/retired':'Снята связь'};
const assetChange:Record<string,string>={HOSTNAME_CHANGED:'Сменилось имя ПК',ASSET_MERGE:'Слияние карточек',ASSET_SPLIT:'Разделение карточки',AUTO_STRONG_MATCH:'Автопривязка по сильному признаку',BUSINESS_FIELDS_CHANGED:'Изменены поля карточки',ASSET_CLASS_CHANGED:'Изменён класс',ASSET_RETIRED:'Выведен из учёта',MANUAL_RECONCILIATION:'Разбор конфликта',SOURCE_MAPPING:'Привязан источник',CSV_IMPORT:'Импорт CSV'};
function changeText(c:RSMChange){
 if(c.source==='asset'){const base=assetChange[c.object_type]??c.object_type;const d=c.detail as {from?:string[];to?:string[]};return c.object_type==='HOSTNAME_CHANGED'&&d.from&&d.to?base+': '+d.from.join(', ')+' → '+d.to.join(', '):base}
 const base=changeName[c.object_type+'/'+c.action]??c.object_type+' · '+c.action;const d=c.detail as Record<string,string>;
 return base+(d.name?' «'+d.name+'»':'')+(d.pattern?': '+d.pattern:'')+(c.object_type==='service'&&c.action==='updated'&&d.business_owner!==undefined?'':'')
}
function ProblemPill({p,color}:{p:RSMProblems;color:string}){const t=problemsText({problems:p,computed_at:'x'} as never);return t?<span className={'pill '+(color==='red'?'pill-bad':'pill-warn')}>{t}</span>:<span className="pill pill-ok">ок</span>}
function Kpi({label,children}:{label:string;children:React.ReactNode}){return <div className="kpi"><small>{label}</small><strong>{children}</strong></div>}
function Tabs<T extends string>({tabs,value,onChange}:{tabs:[T,string][];value:T;onChange:(t:T)=>void}){return <div className="card-tabs-bar" role="tablist">{tabs.map(([k,l])=><button key={k} role="tab" aria-selected={value===k} className={value===k?'active':''} onClick={()=>onChange(k)}>{l}</button>)}</div>}
function ChangesTable({list,total,onOpenAsset,filter}:{list:RSMChange[];total:number;onOpenAsset:(uid:string)=>void;filter?:boolean}){
 const [q,setQ]=useState('');const shown=list.filter(c=>!q||(changeText(c)+' '+c.asset_name).toLowerCase().includes(q.toLowerCase()));
 return <section className="panel"><header><h3>Изменения за 7 дней · {fmt(total)}</h3>{filter?<input className="panel-filter" placeholder="Фильтр по изменениям" value={q} onChange={e=>setQ(e.target.value)} aria-label="Фильтр по изменениям"/>:null}</header>
  {shown.length===0?<p className="muted pad">Изменений нет.</p>:<table className="panel-table"><thead><tr><th>Когда</th><th>Что</th><th>Где</th></tr></thead><tbody>{shown.map((c,i)=><tr key={i}><td>{when(c.occurred_at)}</td><td>{changeText(c)}</td><td>{c.asset_uid?<button className="link mono-link" onClick={()=>onOpenAsset(c.asset_uid!)}>{c.asset_name||c.asset_uid.slice(0,8)}</button>:<span className="muted">—</span>}</td></tr>)}</tbody></table>}
 </section>;
}

type SysTab='overview'|'composition'|'deps'|'changes';
export function SystemCardPage({uid,csrf,canWrite,directions,onBack,onComponent,onOpenAsset,onOpenSystem,onExpired,onChanged}:{uid:string;csrf:string;canWrite:boolean;directions:RSMOverview['directions'];onBack:()=>void;onComponent:(id:string,from:string)=>void;onOpenAsset:(uid:string)=>void;onOpenSystem:(uid:string)=>void;onExpired:()=>void;onChanged:()=>void}){
 const [tab,setTab]=useState<SysTab>('overview'),[mq,setMq]=useState(''),[aq,setAq]=useState('');
 const [d,error,reload]=useLive<RSMSystemCard>(()=>api.rsmSystemCard(uid),[uid],onExpired);
 if(error)return <Err e={error}/>;
 if(!d)return <p className="muted" role="status">Загрузка карточки…</p>;
 const s=d.system,st=d.state,hosts=st?.hosts??0,fresh=st?.fresh??0,pt=problemsText(st);
 const kinds=d.env_kinds;const matrix=d.matrix.filter(r=>!mq||r.name.toLowerCase().includes(mq.toLowerCase()));
 const attention=d.attention.filter(a=>!aq||(a.component_name+' '+a.hosts.map(h=>h.name).join(' ')+' '+(reasonPhrase[a.code]??a.code)).toLowerCase().includes(aq.toLowerCase()));
 const compCount=new Set(d.matrix.flatMap(r=>Object.values(r.cells).map(c=>c!.component_id))).size;
 const dep=(x:RSMSystemCard['depends_on'][number],critical:boolean)=><li key={x.service_uid}><button className="link plain" onClick={()=>onOpenSystem(x.service_uid)}>{x.name}</button>{critical?<CritBadge value={x.criticality}/>:<ProblemPill p={x.problems} color={x.color}/>}</li>;
 return <div className="card-page">
  <button className="link back" onClick={onBack}>← Все системы</button>
  <header className="card-header">
   <small className="kicker">Система{d.direction_name?' · направление «'+d.direction_name+'»':''}</small>
   <div className="card-title"><h1>{s.name}</h1><span className={'crit crit-'+s.criticality}>критичность {critLabel[s.criticality]}</span>{kinds.length?<span className="pill">{kinds.map(k=>envLower[k]).join(' · ')}</span>:null}</div>
   <div className="kpis"><Kpi label="Владелец (бизнес)">{s.business_owner??<span className="amber-text">не задан</span>}</Kpi><Kpi label="Ответственный ИТ">{d.it_subject_name??<span className="muted">не задан</span>}</Kpi><Kpi label="Хостов">{fmt(hosts)} · {d.sites} {plural(d.sites,'площадка','площадки','площадок')}</Kpi><Kpi label="Данные актуальны">{hosts?Math.round(fresh*100/hosts)+'% ('+fmt(fresh)+' из '+fmt(hosts)+')':'—'}</Kpi><Kpi label="Проблемы">{pt?<span className="problem-text">{pt}</span>:st?'нет':'не рассчитано'}</Kpi><Kpi label="Окно обслуживания">{s.maintenance_window??<span className="muted">не задано</span>}</Kpi></div>
  </header>
  <Tabs<SysTab> tabs={[['overview','Обзор'],['composition','Состав · '+fmt(hosts)],['deps','Зависимости'],['changes','Изменения']]} value={tab} onChange={setTab}/>
  {tab==='overview'?<div className="card-grid">
   <div className="card-col">
    <section className="panel"><header><h3>Состав по средам</h3><input className="panel-filter" placeholder="Фильтр по компонентам" aria-label="Фильтр по компонентам" value={mq} onChange={e=>setMq(e.target.value)}/></header>
     {d.matrix.length===0?<p className="muted pad">Компонентов нет — добавьте их на вкладке «Состав».</p>:<table className="panel-table"><thead><tr><th>Компонент</th>{kinds.map(k=><th key={k} className="num">{envShort[k]}</th>)}<th>Проблемы</th></tr></thead><tbody>{matrix.map(r=><tr key={r.name}><td><button className="link plain" onClick={()=>{const first=kinds.map(k=>r.cells[k]).find(Boolean);if(first)onComponent(first.component_id,uid)}}>{r.name}</button>{r.critical?<small className="muted"> · критичный</small>:null}</td>{kinds.map(k=><td key={k} className="num">{r.cells[k]?<button className="link plain num-link" onClick={()=>onComponent(r.cells[k]!.component_id,uid)}>{fmt(r.cells[k]!.hosts)}</button>:'—'}</td>)}<td className={problemsText({problems:r.problems,computed_at:'x'} as never)?(r.color==='red'?'problem-text':'amber-text'):'muted'}>{problemsText({problems:r.problems,computed_at:'x'} as never)||'—'}</td></tr>)}</tbody></table>}
    </section>
    <section className="panel"><header><h3>Требует внимания · {d.attention.reduce((n,a)=>n+a.total,0)}</h3><input className="panel-filter" placeholder="Фильтр" aria-label="Фильтр требует внимания" value={aq} onChange={e=>setAq(e.target.value)}/></header>
     {attention.length===0?<p className="muted pad">{st?'Проблем нет.':'Состояние появится после пересчёта.'}</p>:<ul className="attention">{attention.map((a,i)=><li key={i}><span className={'hdot h-'+a.color}/><span className="att-main">{a.hosts.map((h,j)=><span key={h.asset_uid}>{j?', ':''}<button className="link plain" onClick={()=>onOpenAsset(h.asset_uid)}>{h.name||h.asset_uid.slice(0,8)}</button></span>)}{a.total>a.hosts.length?' и ещё '+(a.total-a.hosts.length):''} — {reasonPhrase[a.code]??a.code}{a.detail?': '+a.detail:''}</span><span className="att-where">{a.component_name} · {a.environment_name}</span></li>)}</ul>}
    </section>
   </div>
   <div className="card-col narrow">
    <section className="panel"><header><h3>Зависимости</h3></header><div className="dep-block"><small>Зависит от</small>{d.depends_on.length?<ul className="dep-list">{d.depends_on.map(x=>dep(x,false))}</ul>:<p className="muted">—</p>}<small>От неё зависят</small>{d.dependents.length?<ul className="dep-list">{d.dependents.map(x=>dep(x,true))}</ul>:<p className="muted">—</p>}</div></section>
    <section className="panel"><header><h3>Ответственные</h3></header><dl className="resp"><dt>Владелец</dt><dd>{s.business_owner??'не задан'}</dd><dt>ИТ</dt><dd>{d.it_subject_name??'не задан'}</dd><dt>Компонентов</dt><dd>{compCount}</dd></dl></section>
   </div>
   <div className="card-wide"><ChangesTable list={d.changes} total={d.changes_total} onOpenAsset={onOpenAsset} filter/></div>
  </div>:null}
  {tab==='composition'?<SystemEdit uid={uid} csrf={csrf} canWrite={canWrite} directions={directions} onBack={onBack} onComponent={id=>onComponent(id,uid)} onExpired={onExpired} onDirection={()=>{reload();onChanged()}} embedded/>:null}
  {tab==='deps'?<section className="panel"><header><h3>Зависимости</h3></header><div className="dep-block"><small>Зависит от</small>{d.depends_on.length?<ul className="dep-list">{d.depends_on.map(x=>dep(x,false))}</ul>:<p className="muted">—</p>}<small>От неё зависят</small>{d.dependents.length?<ul className="dep-list">{d.dependents.map(x=>dep(x,true))}</ul>:<p className="muted">—</p>}<p className="muted small">Связи «зависит от» между системами заводятся в разделе «Сервисы и связи».</p></div></section>:null}
  {tab==='changes'?<ChangesTable list={d.changes} total={d.changes_total} onOpenAsset={onOpenAsset} filter/>:null}
 </div>;
}

function freshText(h:RSMHostRow){if(!h.last_inventory_at)return 'нет данных';const days=Math.floor((Date.now()-Date.parse(h.last_inventory_at))/86400000);return days>=1?'устарело '+days+' дн':'актуально'}
type CompTab='hosts'|'baseline'|'rules';
export function ComponentCardPage({id,csrf,canWrite,onBack,backLabel,onOpenSystem,onOpenAsset,onExpired}:{id:string;csrf:string;canWrite:boolean;onBack:()=>void;backLabel:string;onOpenSystem:(uid:string)=>void;onOpenAsset:(uid:string)=>void;onExpired:()=>void}){
 const [tab,setTab]=useState<CompTab>('hosts'),[typed,setTyped]=useState(''),[q,setQ]=useState(''),[site,setSite]=useState(''),[color,setColor]=useState(''),[offset,setOffset]=useState(0);
 const [picked,setPicked]=useState<Set<string>>(new Set()),[busy,setBusy]=useState(false),[actError,setActError]=useState<unknown>(null);
 const [hidden,setHidden]=useState<Set<string>>(new Set()),[colMenu,setColMenu]=useState(false);
 useEffect(()=>{const t=setTimeout(()=>{setQ(typed.trim());setOffset(0)},300);return()=>clearTimeout(t)},[typed]);
 const [d,error,reload]=useLive<RSMComponentCard>(()=>api.rsmComponentCard(id,{q,site,color,offset}),[id,q,site,color,offset],onExpired);
 if(error)return <Err e={error}/>;
 if(!d)return <p className="muted" role="status">Загрузка карточки…</p>;
 const c=d.component,st=d.state,hosts=st?.hosts??0,stale=(st?.problems.stale??0)+(st?.problems.no_data??0),dev=d.baseline_summary.reduce((n,b)=>n+b.deviations,0);
 const keys=d.baseline_summary.map(b=>b.key);
 const cols:[string,string][]=[['ip','IP-адрес'],['site','Площадка'],['fresh','Свежесть'],...d.baseline_summary.map(b=>[b.key,b.key==='os'?'ОС':b.label] as [string,string]),['collected','Сбор']];
 const show=(k:string)=>!hidden.has(k);
 async function unbind(){if(!window.confirm('Отвязать выбранные хосты ('+picked.size+') от компонента? Изменение попадёт в историю.'))return;setBusy(true);setActError(null);try{for(const h of d!.hosts.filter(x=>picked.has(x.asset_uid)&&x.binding_id))await api.rsmUnbind(h.binding_id,csrf);setPicked(new Set());reload()}catch(e){setActError(e);if(e instanceof ApiError&&e.status===401)onExpired()}finally{setBusy(false)}}
 const baselineSummary=d.baseline_summary.map(b=>(b.key==='os'?'':b.label+' ')+(b.expected||'есть')).join(' · ');
 return <div className="card-page">
  <button className="link back" onClick={onBack}>← {backLabel}</button>
  <header className="card-header">
   <small className="kicker">Компонент системы <button className="link plain" onClick={()=>onOpenSystem(d.service_uid)}>{d.system_name}</button> · среда {d.environment.name.toLowerCase()}</small>
   <div className="card-title"><h1>{c.name}</h1><span className="pill">{fmt(hosts)} {plural(hosts,'хост','хоста','хостов')}</span>{stale?<span className="pill pill-bad">{fmt(stale)} {plural(stale,'устарел','устарели','устарели')}</span>:null}{dev?<span className="pill pill-warn">расхождение с эталоном</span>:null}
    {d.baseline_summary.length?<span className="title-actions"><button className="button" onClick={()=>setTab('baseline')}>Сравнить с эталоном</button></span>:null}</div>
   <div className="kpis"><Kpi label="Роль">{c.critical?'критичный компонент':'компонент'}</Kpi><Kpi label="Ответственный">{d.it_subject_name??<span className="muted">не задан</span>}</Kpi><Kpi label="Площадки">{d.sites.length?d.sites.map(x=>(x.name||'—')+' · '+x.count).join(', '):'—'}</Kpi><Kpi label="Сеть">{d.networks.length?d.networks.map(x=>x.name).join(', '):'—'}</Kpi><Kpi label="Данные актуальны">{hosts?fmt(st!.fresh)+' из '+fmt(hosts):'—'}</Kpi><Kpi label="Эталон">{baselineSummary||<span className="muted">не задан</span>}</Kpi></div>
  </header>
  <Tabs<CompTab> tabs={[['hosts','Хосты · '+fmt(hosts)],['baseline','Отклонения от эталона'],['rules','Правила и привязка']]} value={tab} onChange={setTab}/>
  <Err e={actError}/>
  {tab==='hosts'?<div className="card-grid">
   <div className="card-col"><section className="panel"><header><h3>Хосты компонента</h3><div className="menu-anchor"><button className="button" onClick={()=>setColMenu(!colMenu)} aria-expanded={colMenu}>Колонки</button>{colMenu?<div className="popover right" role="dialog" aria-label="Колонки хостов">{cols.map(([k,l])=><label key={k} className="check"><input type="checkbox" checked={show(k)} onChange={e=>{const n=new Set(hidden);if(e.target.checked)n.delete(k);else n.add(k);setHidden(n)}}/>{l}</label>)}<button className="button small" onClick={()=>setColMenu(false)}>Готово</button></div>:null}</div></header>
    <div className="panel-filters"><input placeholder="Фильтр: хост, IP" aria-label="Фильтр хостов" value={typed} onChange={e=>setTyped(e.target.value)}/><select aria-label="Площадка" value={site} onChange={e=>{setSite(e.target.value);setOffset(0)}}><option value="">Все площадки</option>{d.sites.map(x=><option key={x.name} value={x.name}>{x.name||'—'}</option>)}</select><select aria-label="Состояние" value={color} onChange={e=>{setColor(e.target.value);setOffset(0)}}><option value="">Любое состояние</option><option value="red">авария</option><option value="yellow">внимание</option><option value="grey">нет данных</option><option value="green">норма</option></select><span className="muted counter">{fmt(d.hosts.length)} из {fmt(d.matched)}{d.matched<hosts?' (всего '+fmt(hosts)+')':''}</span></div>
    {picked.size&&canWrite?<div className="bulk-bar">Выбрано: {picked.size} <button className="button small" disabled={busy} onClick={()=>void unbind()}>Отвязать от компонента</button> <button className="link" onClick={()=>setPicked(new Set())}>снять выбор</button></div>:null}
    {d.hosts.length===0?<p className="muted pad">{d.matched===0&&hosts===0?'Хостов нет — привяжите их на вкладке «Правила и привязка».':'По фильтру хостов нет.'}</p>:
    <div className="table-scroll"><table className="panel-table hosts-table"><thead><tr><th className="cb">{canWrite?<input type="checkbox" aria-label="Выбрать все" checked={d.hosts.every(h=>picked.has(h.asset_uid))} onChange={e=>setPicked(e.target.checked?new Set(d.hosts.map(h=>h.asset_uid)):new Set())}/>:null}</th><th>Хост</th>{cols.filter(([k])=>show(k)).map(([k,l])=><th key={k}>{l}</th>)}</tr></thead>
     <tbody>{d.hosts.map(h=><tr key={h.asset_uid}><td className="cb">{canWrite?<input type="checkbox" aria-label={'Выбрать '+(h.name||h.asset_uid)} checked={picked.has(h.asset_uid)} onChange={e=>{const n=new Set(picked);if(e.target.checked)n.add(h.asset_uid);else n.delete(h.asset_uid);setPicked(n)}}/>:null}</td>
      <td><button className="link plain mono-link" onClick={()=>onOpenAsset(h.asset_uid)}>{h.name||h.asset_uid.slice(0,8)}</button>{h.is_primary?null:<small className="muted"> · общий</small>}</td>
      {show('ip')?<td>{h.ip||'—'}</td>:null}{show('site')?<td>{h.site||'—'}</td>:null}
      {show('fresh')?<td><span className={'hdot h-'+h.color}/> {freshText(h)}</td>:null}
      {keys.filter(k=>show(k)).map(k=>{const b=d.baseline_summary.find(x=>x.key===k)!;const v=h.values[k];const bad=v===undefined?false:k==='os'?!v.toLowerCase().includes(b.expected.toLowerCase()):b.expected?!v.split(', ').some(x=>x.startsWith(b.expected)):false;return <td key={k} className={v===undefined?'muted':bad?'amber-text':''}>{v??(h.values['os']!==undefined||Object.keys(h.values).length?'нет':'—')}</td>})}
      {show('collected')?<td className="muted">{when(h.last_inventory_at)}</td>:null}</tr>)}</tbody></table></div>}
    {d.next_offset!=null||offset>0?<div className="pager"><small>по 100</small><div><button className="button small" disabled={offset===0} onClick={()=>setOffset(Math.max(0,offset-100))}>← Назад</button><button className="button small" disabled={d.next_offset==null} onClick={()=>setOffset(d.next_offset!)}>Далее →</button></div></div>:null}
   </section></div>
   <div className="card-col narrow"><BaselinePanel d={d} onSetup={()=>setTab('rules')}/></div>
  </div>:null}
  {tab==='baseline'?<BaselinePanel d={d} wide onSetup={()=>setTab('rules')}/>:null}
  {tab==='rules'?<ComponentEdit id={id} csrf={csrf} canWrite={canWrite} onBack={onBack} onOpenAsset={onOpenAsset} onExpired={onExpired} embedded/>:null}
 </div>;
}

function BaselinePanel({d,wide,onSetup}:{d:RSMComponentCard;wide?:boolean;onSetup:()=>void}){
 return <section className={'panel'+(wide?' wide':'')}><header><h3>Отклонения от эталона</h3></header>
  {d.baseline_summary.length===0?<p className="muted pad">Эталон не задан. Эталон задаётся при создании компонента (ОС и версии ПО); <button className="link" onClick={onSetup}>правила и привязка</button>.</p>:
  <table className="panel-table baseline"><tbody>{d.baseline_summary.map(b=><tr key={b.key}><td>{b.key==='os'?'ОС':b.label}{b.expected?<small className="muted"> · эталон {b.expected}</small>:null}</td><td className="values">{b.values.map(v=>v.name+' — '+fmt(v.count)).join(' · ')||'—'}{b.no_data?<small className="muted"> · нет данных — {fmt(b.no_data)}</small>:null}</td><td>{b.deviations?<span className="pill pill-warn">{fmt(b.deviations)} откл.</span>:<span className="pill pill-ok">ок</span>}</td></tr>)}</tbody></table>}
  <p className="muted small pad">Антивирус, обновления ОС, открытые порты и локальные администраторы появятся в эталоне вместе с мониторингом (C55).</p>
 </section>;
}
