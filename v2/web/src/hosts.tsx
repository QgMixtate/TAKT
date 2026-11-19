import {Fragment,useEffect,useMemo,useState,type ReactNode} from 'react';
import {api,ApiError,errorMessage,type HostQuery,type HostRegistryPage,type HostTree,type RegistryHost,type Subject} from './api';
import {TicketDialog} from './cards';
import {fmt,useLoad} from './ui';

// C53.04 (макеты 1, 2, 5 — «Реестр — плотный»): счётчики на сервере, дерево группировки (площадка → сегмент,
// команда → ответственный, система → компонент, ОС → версия), фильтры-чипы, сортировка по колонкам, выбор колонок,
// группировка страницы, 100/250/500 строк, выгрузка CSV по фильтру и массовые действия по выбору или по фильтру.
type TreeBy='site'|'owner'|'system'|'os';
type Col='ip'|'os'|'class'|'site'|'freshness'|'data'|'sources'|'owner'|'system'|'last';
const colNames:Record<Col,string>={ip:'IP-адрес',os:'ОС',class:'Тип',site:'Площадка',freshness:'Свежесть',data:'Данные',sources:'Источники',owner:'Ответственный',system:'Система',last:'Сбор'};
const defaultCols:Col[]=['ip','os','freshness','data','sources','owner','system','last'];
const sortOf:Partial<Record<Col|'name',string>>={name:'name',ip:'ip',os:'os',freshness:'freshness',owner:'owner',system:'system',last:'last'};
const treeNames:Record<TreeBy,string>={site:'Площадка → сегмент',owner:'Команда → ответственный',system:'Система → компонент',os:'ОС → версия'};
const familyNames:Record<string,string>={windows:'Windows',linux:'Linux',macos:'macOS',network:'Сетевые ОС',other:'Другие',unknown:'ОС не определена'};
const classNames:Record<string,string>={server:'сервер',workstation:'рабочая станция',laptop:'ноутбук',network:'сетевое',printer:'принтер',virtual:'виртуальная',unknown:'не определён'};
const freshNames:Record<string,[string,string]>={fresh:['актуально','state-ok'],stale:['устарело','state-unavailable'],unknown:['нет сведений','state-unknown'],partial:['неполные','state-partial']};
const srcNames:Record<string,string>={agent:'Агент',collector:'Collector',portable:'Portable',ssh:'SSH',winrm:'WinRM',snmp:'SNMP'};
const filterKeys=['q','site','segment','class','os_family','os','owner','team','system','component','freshness'] as const;
type Filter=Partial<Record<typeof filterKeys[number],string>>;
const when=(v:string|null)=>v?new Date(v).toLocaleString('ru-RU',{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'}):'—';
const roleNames:Record<string,string>={accountable:'Ответственный',business_owner:'Бизнес-владелец',technical:'Технический ответственный',custodian:'Пользователь (хранитель)'};

function loadCols():Col[]{try{const v=JSON.parse(localStorage.getItem('takt.hosts.cols')??'null');if(Array.isArray(v)&&v.every(x=>x in colNames))return v as Col[]}catch{/* хранилище недоступно */}return defaultCols}

export function HostsScreen({csrf,canWrite,refresh,onOpenAsset,onOpenSystem,onExpired}:{csrf:string;canWrite:boolean;refresh:number;onOpenAsset:(uid:string)=>void;onOpenSystem?:(uid:string)=>void;onExpired:()=>void}){
 const [filter,setFilter]=useState<Filter>({}),[labels,setLabels]=useState<Record<string,string>>({}),[typed,setTyped]=useState('');
 const [sort,setSort]=useState('name'),[desc,setDesc]=useState(false),[offset,setOffset]=useState(0),[limit,setLimit]=useState<100|250|500>(100);
 const [by,setBy]=useState<TreeBy>('site'),[open,setOpen]=useState<Record<string,boolean>>({}),[cols,setCols]=useState<Col[]>(loadCols),[colMenu,setColMenu]=useState(false),[group,setGroup]=useState<''|'os'|'system'|'site'>('');
 const [sel,setSel]=useState<string[]>([]),[allByFilter,setAllByFilter]=useState(false),[n,setN]=useState(0),[note,setNote]=useState(''),[busy,setBusy]=useState(false),[actError,setActError]=useState<unknown>(null);
 const [assign,setAssign]=useState(false),[role,setRole]=useState('accountable'),[subject,setSubject]=useState(''),[ticket,setTicket]=useState(false);
 useEffect(()=>{const t=setTimeout(()=>{setFilter(f=>({...f,q:typed.trim()||undefined}));setOffset(0)},300);return()=>clearTimeout(t)},[typed]);
 const query:HostQuery={...filter,sort,dir:desc?'desc':'asc',offset,limit};
 const [page,error]=useLoad<HostRegistryPage>(()=>api.hosts(query),[JSON.stringify(query),n,refresh],onExpired);
 const [tree,treeError]=useLoad<HostTree>(()=>api.hostsTree(by),[by,n,refresh],onExpired);
 const [subjects]=useLoad<{items:Subject[]}>(()=>assign?api.subjects():Promise.resolve({items:[]}),[assign],onExpired);
 useEffect(()=>{setSel([]);setAllByFilter(false)},[JSON.stringify(filter)]);
 useEffect(()=>{if(!note)return;const t=setTimeout(()=>setNote(''),6000);return()=>clearTimeout(t)},[note]);
 const c=page?.counters;
 function set(key:keyof Filter,value:string|undefined,label?:string){setFilter(f=>({...f,[key]:value||undefined}));if(label)setLabels(l=>({...l,[key]:label}));setOffset(0)}
 function pickTree(k1:string,l1:string,k2?:string,l2?:string){
  const f:Filter={q:filter.q};const L:Record<string,string>={};
  if(by==='site'){f.site=k1;L.site=l1||'без площадки';if(k2!==undefined){f.segment=k2;L.segment=l2||'без сегмента'}}
  if(by==='owner'){if(k1)f.team=k1;L.team=l1||'без команды';if(k2){f.owner=k2;L.owner=l2||'—'}}
  if(by==='system'){f.system=k1;L.system=k1==='none'?'вне систем':l1;if(k2)f.component=k2,L.component=l2??k2}
  if(by==='os'){f.os_family=k1;L.os_family=familyNames[k1]??k1;if(k2)f.os=k2,L.os=l2||'—'}
  setFilter(f);setLabels(L);setOffset(0);
 }
 function toggleCol(col:Col){const next=cols.includes(col)?cols.filter(x=>x!==col):[...cols,col];setCols(next);try{localStorage.setItem('takt.hosts.cols',JSON.stringify(next))}catch{/* хранилище недоступно */}}
 function sortBy(key:string){if(sort===key)setDesc(!desc);else{setSort(key);setDesc(false)}setOffset(0)}
 const target=()=>allByFilter?{filter:Object.fromEntries(Object.entries(filter).filter(([,v])=>v)) as Record<string,string>}:{asset_uids:sel};
 async function act(fn:()=>Promise<string>){setBusy(true);setActError(null);try{setNote(await fn());setN(x=>x+1)}catch(e){setActError(e);if(e instanceof ApiError&&e.status===401)onExpired()}finally{setBusy(false)}}
 const items=page?.items??[];
 const chosenCount=allByFilter?Math.min(page?.total??0,1000):sel.length;
 const groups=useMemo(()=>{if(!group)return [['',items]] as [string,RegistryHost[]][];const m=new Map<string,RegistryHost[]>();for(const h of items){const k=group==='os'?(h.os||'ОС не определена'):group==='system'?(h.system_name||'вне систем'):(h.site_name||'без площадки');m.set(k,[...(m.get(k)??[]),h])}return [...m.entries()]},[items,group]);
 const chips=filterKeys.filter(k=>k!=='q'&&filter[k]).map(k=><span key={k} className="chip">{({site:'Площадка',segment:'Сегмент',class:'Тип',os_family:'ОС',os:'Версия ОС',owner:'Ответственный',team:'Команда',system:'Система',component:'Компонент',freshness:'Свежесть'} as Record<string,string>)[k]}: {labels[k]??(k==='freshness'?freshNames[filter[k]!]?.[0]:filter[k])} <button aria-label={'Убрать фильтр '+k} onClick={()=>set(k,undefined)}>×</button></span>);
 const th=(key:'name'|Col,label:string,cls='')=>{const s=sortOf[key];return <th className={cls} aria-sort={s&&sort===s?(desc?'descending':'ascending'):undefined}>{s?<button className="th-sort" onClick={()=>sortBy(s)}>{label}{sort===s?(desc?' ↓':' ↑'):''}</button>:label}</th>};
 const cell:Record<Col,(h:RegistryHost)=>ReactNode>={
  ip:h=><span className="mono">{h.ip||'—'}</span>,os:h=>h.os||<span className="muted">нет сведений</span>,class:h=>classNames[h.asset_class]??h.asset_class,site:h=><>{h.site_name}{h.segment?<small className="muted"> · {h.segment}</small>:null}</>,
  freshness:h=>{const k=h.freshness==='fresh'&&h.sections_ok<h.sections_total?'partial':h.freshness;return <span className={'badge '+freshNames[k][1]}><i/>{freshNames[k][0]}</span>},
  data:h=><span className={h.sections_total&&h.sections_ok<h.sections_total?'problem-text':''}>{h.sections_total?h.sections_ok+'/'+h.sections_total:'—'}</span>,
  sources:h=>h.sources.length?h.sources.map(s=>srcNames[s]??s).join(', '):<span className="muted">—</span>,
  owner:h=>h.site_fallback?<span className="amber-text" title="Назначена резервная команда площадки">{h.accountable_name||'резерв площадки'}</span>:h.accountable_name||<span className="muted">—</span>,
  system:h=>h.system_uid?<button className="link plain" onClick={()=>onOpenSystem?.(h.system_uid!)}>{h.system_name}</button>:<span className="muted">вне систем</span>,
  last:h=><span className="time">{when(h.last_inventory_at)}</span>};
 const strip:[string,string,number|undefined,string,()=>void][]=[['all','всего',c?.total,'',()=>setFilter({q:filter.q})],['fresh','актуальны',c?.fresh,'',()=>set('freshness','fresh')],['partial','неполные',c?.partial,'amber',()=>set('freshness','partial')],['stale','устарели',c?.stale,'warn',()=>set('freshness','stale')],['none','без ответственного',c?.without_owner,'amber',()=>set('owner','none','резерв площадки')],['new','новые за 7 дней',c?.new_7d,'',()=>undefined]];
 return <div className="hosts-screen">
  <div className="count-strip" role="toolbar" aria-label="Сводка хостов">{strip.map(([k,l,v,tone,on])=><button key={k} className={'count'+((k==='all'&&!filter.freshness&&!filter.owner)||(filter.freshness===k)||(k==='none'&&filter.owner==='none')?' active':'')+(tone&&v?' '+tone:'')} disabled={k==='new'} onClick={on}><b>{v===undefined?'…':fmt(v)}</b> {l}</button>)}<span className="spacer"/><span className="muted strip-note">счётчики — на сервере{c?.computed_at?', обновлено '+new Date(c.computed_at).toLocaleTimeString('ru-RU',{hour:'2-digit',minute:'2-digit'}):''}</span></div>
  <div className="hosts-grid">
   <aside className="hosts-tree panel" aria-label="Дерево группировки">
    <label className="tree-by">Дерево<select aria-label="Дерево группировки" value={by} onChange={e=>{setBy(e.target.value as TreeBy);setOpen({})}}>{(Object.keys(treeNames) as TreeBy[]).map(k=><option key={k} value={k}>{treeNames[k]}</option>)}</select></label>
    {treeError?<div className="error" role="alert">{errorMessage(treeError)}</div>:null}
    <div className="tree"><button className={'tree-item'+(Object.keys(filter).filter(k=>k!=='q'&&filter[k as keyof Filter]).length===0?' active':'')} onClick={()=>{setFilter({q:filter.q});setOffset(0)}}><span>Все хосты</span><span className="muted">{c?fmt(c.total):''}</span></button>
     {(tree?.nodes??[]).map(n1=>{const l1=by==='os'?(familyNames[n1.label]??n1.label):by==='system'&&n1.key==='none'?'Вне систем':n1.label||(by==='owner'?'Без команды':'—');const active=(by==='site'&&filter.site===n1.key)||(by==='owner'&&filter.team===n1.key)||(by==='system'&&filter.system===n1.key)||(by==='os'&&filter.os_family===n1.key);return <div key={n1.key}>
      <button className={'tree-item'+(active&&!filter.segment&&!filter.owner&&!filter.component&&!filter.os?' active':'')} onClick={()=>pickTree(n1.key,l1)}><span className="caret" role="button" aria-label={open[n1.key]?'Свернуть':'Развернуть'} onClick={e=>{e.stopPropagation();setOpen(o=>({...o,[n1.key]:!o[n1.key]}))}}>{open[n1.key]?'▾':'▸'}</span><span>{l1}</span><span className="muted">{fmt(n1.count)}</span></button>
      {open[n1.key]?n1.children.map(n2=>{const l2=n2.label||(by==='site'?'без сегмента':by==='owner'?'—':by==='system'?(n1.key==='none'?'—':'без компонента'):'—');return <button key={n2.key} className={'tree-item child'+(active&&((by==='site'&&filter.segment===n2.key)||(by==='owner'&&filter.owner===n2.key)||(by==='system'&&filter.component===n2.key)||(by==='os'&&filter.os===n2.key))?' active':'')} onClick={()=>pickTree(n1.key,l1,n2.key,l2)}><span>{l2}</span><span className="muted">{fmt(n2.count)}</span></button>}):null}
     </div>})}</div>
   </aside>
   <section className="hosts-main">
    <div className="systems-toolbar"><input className="toolbar-search" aria-label="Поиск хостов" placeholder="Имя, IP или ОС" value={typed} onChange={e=>setTyped(e.target.value)}/>{chips}
     <select aria-label="Свежесть" value={filter.freshness??''} onChange={e=>set('freshness',e.target.value||undefined)}><option value="">+ Свежесть</option>{Object.entries(freshNames).map(([k,[l]])=><option key={k} value={k}>{l}</option>)}</select>
     <span className="spacer"/>
     <select aria-label="Группировать" value={group} onChange={e=>setGroup(e.target.value as typeof group)}><option value="">без группировки</option><option value="os">Группировать: ОС</option><option value="system">Группировать: система</option><option value="site">Группировать: площадка</option></select>
     <span className="menu-anchor"><button className="button" aria-expanded={colMenu} onClick={()=>setColMenu(!colMenu)}>Колонки</button>{colMenu?<div className="popover right col-menu">{(Object.keys(colNames) as Col[]).map(k=><label key={k} className="inline-check"><input type="checkbox" checked={cols.includes(k)} onChange={()=>toggleCol(k)}/> {colNames[k]}</label>)}</div>:null}</span>
     <a className="button" href={api.hostsCSVURL(query)} download="hosts.csv">Выгрузить CSV</a></div>
    {error?<div className="error" role="alert">{errorMessage(error)}</div>:null}{actError?<div className="error" role="alert">{errorMessage(actError)}</div>:null}{note?<div className="notice" role="status">{note}</div>:null}
    {canWrite&&chosenCount?<div className="bulk-bar"><b>Выбрано: {allByFilter?'все '+fmt(chosenCount)+' по фильтру':fmt(sel.length)}</b>{!allByFilter&&page&&page.total>items.length&&sel.length===items.length?<button className="link" onClick={()=>setAllByFilter(true)}>выбрать все {fmt(Math.min(page.total,1000))} по фильтру</button>:null}
     <button className="button small" disabled={busy} onClick={()=>setAssign(!assign)}>Назначить ответственного</button>
     <button className="button small" disabled={busy} onClick={()=>void act(async()=>{const r=await api.hostsCollect(csrf,target());return 'Сбор запрошен: целей '+r.requested+', с агентом '+r.agents+(r.no_target?', без цели сбора '+r.no_target:'')})}>Собрать сейчас</button>
     <button className="button small" disabled={busy||allByFilter} title={allByFilter?'Обращение создаётся по выбранным на странице':''} onClick={()=>setTicket(true)}>Создать обращение</button>
     <button className="link" onClick={()=>{setSel([]);setAllByFilter(false)}}>Снять выбор</button>
     {assign?<span className="form-row"><select aria-label="Роль" value={role} onChange={e=>setRole(e.target.value)}>{Object.entries(roleNames).map(([k,v])=><option key={k} value={k}>{v}</option>)}</select><select aria-label="Кого назначить" value={subject} onChange={e=>setSubject(e.target.value)}><option value="">кого…</option>{(subjects?.items??[]).filter(s=>s.active&&(role!=='custodian'||s.kind==='person')).map(s=><option key={s.subject_id} value={s.subject_id}>{s.kind==='team'?'Команда: ':''}{s.name}</option>)}</select>
      <button className="button small primary-sm" disabled={busy||!subject} onClick={()=>{if(!window.confirm('Подтвердите: назначить роль «'+roleNames[role]+'» для '+chosenCount+' хост(ов). Изменение попадёт в историю и аудит.'))return;void act(async()=>{const r=await api.hostsAssign(csrf,{...target(),role:role as 'accountable',subject_id:subject});setAssign(false);setSel([]);setAllByFilter(false);return 'Назначено: '+r.applied+(r.unchanged?', уже было так: '+r.unchanged:'')})}}>Назначить</button></span>:null}
    </div>:null}
    <div className="table-panel dense"><div className="table-scroll"><table className="systems-table hosts-table"><thead><tr>{canWrite?<th className="check"><input type="checkbox" aria-label="Выбрать все на странице" checked={!!items.length&&sel.length===items.length} onChange={e=>{setSel(e.target.checked?items.map(h=>h.asset_uid):[]);setAllByFilter(false)}}/></th>:null}{th('name','Имя')}{cols.map(k=><Fragment key={k}>{th(k,colNames[k])}</Fragment>)}</tr></thead>
     <tbody>{groups.map(([g,list])=><GroupRows key={g||'all'} label={g} count={list.length} span={cols.length+1+(canWrite?1:0)}>{list.map(h=><tr key={h.asset_uid} className={sel.includes(h.asset_uid)||allByFilter?'selected':''}>
      {canWrite?<td className="check"><input type="checkbox" aria-label={'Выбрать '+h.name} checked={allByFilter||sel.includes(h.asset_uid)} onChange={e=>{setAllByFilter(false);setSel(s=>e.target.checked?[...s,h.asset_uid]:s.filter(x=>x!==h.asset_uid))}}/></td>:null}
      <td><button className="asset-link plain" aria-label={'Открыть карточку '+h.name} onClick={()=>onOpenAsset(h.asset_uid)}><strong>{h.name}</strong></button></td>
      {cols.map(k=><td key={k} className={k==='last'?'num':''}>{cell[k](h)}</td>)}</tr>)}</GroupRows>)}</tbody></table></div>
     {page&&!items.length?<div className="empty"><span>▦</span><h3>{c?.total?'Совпадений нет':'Здесь появятся ваши хосты'}</h3><p>{c?.total?'Измените поиск или уберите фильтры.':'Зарегистрированные источники наполнят реестр после первого успешного сбора.'}</p></div>:!page?<div className="empty" role="status">Загружаем реестр…</div>:null}</div>
    <div className="systems-footer hosts-footer"><span>Показаны {page&&items.length?fmt(offset+1)+'–'+fmt(offset+items.length):'0'} из {fmt(page?.total??0)} по фильтру · всего в реестре {fmt(c?.total??0)}</span><span className="spacer"/>
     <label>Строк на странице <select aria-label="Строк на странице" value={limit} onChange={e=>{setLimit(Number(e.target.value) as 100|250|500);setOffset(0)}}><option value={100}>100</option><option value={250}>250</option><option value={500}>500</option></select></label>
     <button className="button small" disabled={!offset} onClick={()=>setOffset(Math.max(0,offset-limit))}>← Назад</button><button className="button small" disabled={!page||offset+items.length>=page.total} onClick={()=>setOffset(offset+limit)}>Далее →</button></div>
   </section>
  </div>
  {ticket?<TicketDialog csrf={csrf} title={(items.find(h=>h.asset_uid===sel[0])?.name??'')+(sel.length>1?' и ещё '+(sel.length-1):'')+': '} assetUid={sel[0]} description={sel.length>1?'Хосты: '+items.filter(h=>sel.includes(h.asset_uid)).map(h=>h.name).join(', '):''} onClose={()=>setTicket(false)} onCreated={num=>{setTicket(false);setNote('Создано обращение '+num)}} onExpired={onExpired}/>:null}
 </div>;
}

function GroupRows({label,count,span,children}:{label:string;count:number;span:number;children:ReactNode}){
 const [open,setOpen]=useState(true);
 if(!label)return <>{children}</>;
 return <><tr className="group-row"><td colSpan={span}><button className="link plain" aria-expanded={open} onClick={()=>setOpen(!open)}><span className="caret">{open?'▾':'▸'}</span> <b>{label}</b></button> <span className="muted">{count}</span></td></tr>{open?children:null}</>;
}
