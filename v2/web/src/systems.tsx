import React,{useEffect,useMemo,useState} from 'react';
import {api,ApiError,errorMessage,type RSMColor,type RSMComposition,type RSMComponentRow,type RSMCompHost,type RSMEnvKind,type RSMNodeState,type RSMOverview,type RSMSystemPage,type RSMSystemQuery,type RSMSystemState} from './api';

// C53.02 — экран «Системы» по макету C53-mockups/6: полоса счётчиков (она же быстрые фильтры), представления,
// фильтры-чипы, группировка, выбор колонок, таблица систем (критичность, владелец, хосты, «данные актуальны»,
// проблемы) и правая панель состава выбранной системы. Все фильтры — на сервере.

export const critLabel:Record<string,string>={critical:'критичная',high:'высокая',medium:'средняя',low:'низкая',unknown:'не задана'};
const envLabel:Record<RSMEnvKind,string>={prod:'прод',dr:'DR',stage:'предпрод',test:'тест',dev:'разработка',other:'другая'};
const envTitle:Record<RSMEnvKind,string>={prod:'Прод',dr:'DR',stage:'Предпрод',test:'Тест',dev:'Разработка',other:'Другая'};
const problemLabel:[keyof RSMNodeState['problems'],string][]=[['missing','пропали'],['stale','устарели'],['no_data','нет данных'],['baseline','не по эталону'],['conflict','конфликт сопоставления']];
const fmt=(n:number)=>n.toLocaleString('ru-RU');
function plural(n:number,one:string,few:string,many:string){const m10=n%10,m100=n%100;return m10===1&&m100!==11?one:m10>=2&&m10<=4&&(m100<10||m100>=20)?few:many}
export function problemsText(s:RSMNodeState|null):string{if(!s||s.computed_at.startsWith('1970'))return '';const parts=problemLabel.filter(([k])=>s.problems?.[k]).map(([k,l])=>fmt(s.problems[k]!)+' '+l);return parts.join(' · ')}
function useLive<T>(load:()=>Promise<T>,deps:unknown[],onExpired:()=>void):[T|null,unknown,()=>void]{
 const [data,setData]=useState<T|null>(null),[error,setError]=useState<unknown>(null),[n,setN]=useState(0);
 useEffect(()=>{let live=true;setError(null);load().then(d=>{if(live)setData(d)}).catch(e=>{if(live){setError(e);if(e instanceof ApiError&&e.status===401)onExpired()}});return()=>{live=false}},[...deps,n]);
 return [data,error,()=>setN(x=>x+1)];
}
export function CritBadge({value}:{value:string}){return <span className={'crit crit-'+value}>{critLabel[value]??value}</span>}
function Fresh({s}:{s:RSMNodeState}){if(!s.hosts||s.computed_at.startsWith('1970'))return <span className="muted">—</span>;const p=Math.round(s.fresh*100/s.hosts);return <span className="fresh"><i className={p>=95?'ok':p>=85?'warn':'bad'}><b style={{width:p+'%'}}/></i>{p}%</span>}

type Preset='all'|'problems'|'critical'|'no_owner';
type Filters={env:string;criticality:string[];direction:string;color:string;problems:boolean;no_owner:boolean};
const empty:Filters={env:'',criticality:[],direction:'',color:'',problems:false,no_owner:false};
const presets:Record<Preset,[string,Filters]>={all:['Все системы',empty],problems:['С проблемами',{...empty,problems:true}],critical:['Критичные и высокой важности',{...empty,criticality:['critical','high']}],no_owner:['Без владельца',{...empty,no_owner:true}]};
type Column='owner'|'hosts'|'fresh'|'problems';
const columnNames:Record<Column,string>={owner:'Владелец',hosts:'Хостов',fresh:'Данные актуальны',problems:'Проблемы'};
function savedColumns():Column[]{try{const v=JSON.parse(localStorage.getItem('takt.systems.columns')??'null');if(Array.isArray(v))return v.filter((c:string)=>c in columnNames)}catch{/* недоступно */}return ['owner','hosts','fresh','problems']}

export function SystemsScreen({overview,actions,onOpenSystem,onOpenComponent,onOpenAsset,onUnassigned,onProposals,onExpired}:{overview:RSMOverview|null;actions?:React.ReactNode;onOpenSystem:(uid:string)=>void;onOpenComponent:(id:string)=>void;onOpenAsset:(uid:string)=>void;onUnassigned:()=>void;onProposals:()=>void;onExpired:()=>void}){
 const [preset,setPreset]=useState<Preset>('all'),[f,setF]=useState<Filters>(empty),[group,setGroup]=useState<'direction'|'criticality'|'none'>('direction');
 const [columns,setColumns]=useState<Column[]>(savedColumns),[menu,setMenu]=useState<''|'filter'|'columns'>(''),[selected,setSelected]=useState<string|null>(null),[offset,setOffset]=useState(0);
 const query:RSMSystemQuery={...f,offset,limit:500};
 const [page,error]=useLive<RSMSystemPage>(()=>api.rsmSystems(query),[JSON.stringify(query),overview?.state?.computed_at],onExpired); // после пересчёта — свежие цвета
 useEffect(()=>{if(page&&!selected&&page.items.length)setSelected(page.items[0].service_uid)},[page]);
 const dirName=(uid:string|null)=>uid?overview?.directions.find(d=>d.direction_uid===uid)?.name??'Направление':'Без направления';
 const groups=useMemo(()=>{const items=page?.items??[];if(group==='none')return [['',items] as [string,RSMSystemState[]]];const m=new Map<string,RSMSystemState[]>();for(const s of items){const k=group==='direction'?dirName(s.direction_uid):critLabel[s.criticality]??s.criticality;m.set(k,[...(m.get(k)??[]),s])}return [...m.entries()].sort((a,b)=>a[0]==='Без направления'?1:b[0]==='Без направления'?-1:a[0].localeCompare(b[0],'ru'))},[page,group,overview]);
 const set=(next:Filters)=>{setF(next);setOffset(0);setSelected(null);setPreset('all')};
 const c=overview?.counters,hosts=overview?.state?.hosts??0;
 const strip:[string,number|undefined,string,boolean,()=>void][]=[['systems',c?.systems,plural(c?.systems??0,'система','системы','систем'),preset==='all'&&!f.problems&&!f.no_owner&&!f.criticality.length,()=>{setPreset('all');setF(empty);setSelected(null)}],['critical',c?.critical,'критичных',preset==='critical',()=>{setPreset('critical');setF(presets.critical[1]);setSelected(null)}],['problems',c?.with_problems,'с проблемами',preset==='problems',()=>{setPreset('problems');setF(presets.problems[1]);setSelected(null)}],['owner',c?.without_owner,'без владельца',preset==='no_owner',()=>{setPreset('no_owner');setF(presets.no_owner[1]);setSelected(null)}],['hosts',hosts,'хостов в системах',false,()=>{}],['unassigned',overview?.unassigned,'хостов вне систем',false,onUnassigned]];
 const chips:[string,()=>void][]=[];
 if(f.env)chips.push(['Среда: '+envLabel[f.env as RSMEnvKind],()=>set({...f,env:''})]);
 if(f.criticality.length)chips.push(['Критичность: '+f.criticality.map(x=>critLabel[x]).join(', '),()=>set({...f,criticality:[]})]);
 if(f.direction)chips.push(['Направление: '+(f.direction==='none'?'без направления':dirName(f.direction)),()=>set({...f,direction:''})]);
 if(f.color)chips.push(['Цвет: '+({red:'авария',yellow:'внимание',green:'норма',grey:'нет данных'} as Record<string,string>)[f.color],()=>set({...f,color:''})]);
 if(f.problems)chips.push(['Только с проблемами',()=>set({...f,problems:false})]);
 if(f.no_owner)chips.push(['Без владельца',()=>set({...f,no_owner:false})]);
 return <div className="systems-screen">
  <div className="count-strip" role="toolbar" aria-label="Сводка систем">{strip.map(([k,n,label,active,on])=><button key={k} className={'count'+(active?' active':'')+(k==='problems'||k==='unassigned'?' warn':'')+(k==='owner'?' amber':'')} disabled={k==='hosts'} onClick={on}><b>{n===undefined?'…':fmt(n)}</b> {label}</button>)}{overview?.proposals?<button className="count warn" onClick={onProposals}><b>{fmt(overview.proposals)}</b> {plural(overview.proposals,'предложение','предложения','предложений')} правил</button>:null}<span className="spacer"/>{actions}</div>
  <div className="systems-grid">
   <section className="systems-main">
    <div className="systems-toolbar">
     <select aria-label="Представление" value={preset} onChange={e=>{const p=e.target.value as Preset;setPreset(p);setF(presets[p][1]);setOffset(0);setSelected(null)}}>{(Object.keys(presets) as Preset[]).map(p=><option key={p} value={p}>Представление: {presets[p][0]}</option>)}</select>
     {chips.map(([label,drop])=><span key={label} className="chip">{label}<button aria-label={'Убрать фильтр '+label} onClick={drop}>×</button></span>)}
     <div className="menu-anchor"><button className="chip add" onClick={()=>setMenu(menu==='filter'?'':'filter')} aria-expanded={menu==='filter'}>+ Фильтр</button>
      {menu==='filter'?<div className="popover" role="dialog" aria-label="Фильтр систем">
       <label>Среда<select value={f.env} onChange={e=>set({...f,env:e.target.value})}><option value="">любая</option>{(Object.keys(envLabel) as RSMEnvKind[]).map(k=><option key={k} value={k}>{envTitle[k]}</option>)}</select></label>
       <fieldset><legend>Критичность</legend>{['critical','high','medium','low','unknown'].map(k=><label key={k} className="check"><input type="checkbox" checked={f.criticality.includes(k)} onChange={e=>set({...f,criticality:e.target.checked?[...f.criticality,k]:f.criticality.filter(x=>x!==k)})}/>{critLabel[k]}</label>)}</fieldset>
       <label>Направление<select value={f.direction} onChange={e=>set({...f,direction:e.target.value})}><option value="">любое</option><option value="none">без направления</option>{overview?.directions.map(d=><option key={d.direction_uid} value={d.direction_uid}>{d.name}</option>)}</select></label>
       <label>Цвет<select value={f.color} onChange={e=>set({...f,color:e.target.value})}><option value="">любой</option><option value="red">авария</option><option value="yellow">внимание</option><option value="grey">нет данных</option><option value="green">норма</option></select></label>
       <label className="check"><input type="checkbox" checked={f.no_owner} onChange={e=>set({...f,no_owner:e.target.checked})}/>Только без владельца</label>
       <button className="button small" onClick={()=>setMenu('')}>Готово</button></div>:null}</div>
    </div>
    <div className="systems-toolbar end">
     <select aria-label="Группировка" value={group} onChange={e=>setGroup(e.target.value as typeof group)}><option value="direction">Группировать: направление</option><option value="criticality">Группировать: критичность</option><option value="none">Без группировки</option></select>
     <div className="menu-anchor"><button className="button" onClick={()=>setMenu(menu==='columns'?'':'columns')} aria-expanded={menu==='columns'}>Колонки</button>
      {menu==='columns'?<div className="popover right" role="dialog" aria-label="Колонки">{(Object.keys(columnNames) as Column[]).map(k=><label key={k} className="check"><input type="checkbox" checked={columns.includes(k)} onChange={e=>{const next=e.target.checked?[...columns,k]:columns.filter(x=>x!==k);setColumns(next);try{localStorage.setItem('takt.systems.columns',JSON.stringify(next))}catch{/* без сохранения */}}}/>{columnNames[k]}</label>)}<button className="button small" onClick={()=>setMenu('')}>Готово</button></div>:null}</div>
    </div>
    {error?<div className="error" role="alert">{errorMessage(error)}</div>:null}
    <div className="table-panel dense">
     {page&&page.items.length===0?<div className="empty"><h3>Систем по фильтру нет</h3><p>Системы — это бизнес-сервисы. Заведите сервис в «Сервисы и связи», затем среды и компоненты — в карточке системы или импортом.</p></div>:
     <div className="table-scroll"><table className="systems-table"><thead><tr><th>Система</th><th>Критичность</th>{columns.includes('owner')?<th>Владелец</th>:null}{columns.includes('hosts')?<th className="num">Хостов</th>:null}{columns.includes('fresh')?<th>Данные актуальны</th>:null}{columns.includes('problems')?<th>Проблемы</th>:null}</tr></thead>
      {groups.map(([name,items])=><tbody key={name||'all'}>{name?<tr className="group-row"><td colSpan={2+columns.length}>▾ <b>{name}</b> <span>{items.length} {plural(items.length,'система','системы','систем')}</span></td></tr>:null}
       {items.map(s=>{const pt=problemsText(s.state);return <tr key={s.service_uid} className={selected===s.service_uid?'selected':''} onClick={()=>setSelected(s.service_uid)}>
        <td><button className="row-title" onClick={e=>{e.stopPropagation();setSelected(s.service_uid)}} onDoubleClick={()=>onOpenSystem(s.service_uid)}>{s.name}</button></td>
        <td><CritBadge value={s.criticality}/></td>
        {columns.includes('owner')?<td>{s.business_owner??<span className="amber-text">нет владельца</span>}</td>:null}
        {columns.includes('hosts')?<td className="num">{fmt(s.state.hosts)}</td>:null}
        {columns.includes('fresh')?<td><Fresh s={s.state}/></td>:null}
        {columns.includes('problems')?<td className={pt?'problem-text':'muted'}>{pt||(s.state.computed_at.startsWith('1970')?'не рассчитано':'—')}</td>:null}
       </tr>})}</tbody>)}
     </table></div>}
    </div>
    <div className="systems-footer">Показаны {fmt(page?.items.length??0)} из {fmt(c?.systems??0)} систем по фильтру · хостов вне систем: {fmt(overview?.unassigned??0)} — <button className="link" onClick={onUnassigned}>разобрать</button>{page?.next_offset!=null?<> · <button className="link" onClick={()=>setOffset(page.next_offset!)}>следующие 500</button></>:null}{offset>0?<> · <button className="link" onClick={()=>setOffset(Math.max(0,offset-500))}>предыдущие</button></>:null}</div>
   </section>
   {selected?<CompositionPanel key={selected+(overview?.state?.computed_at??'')} uid={selected} onOpenSystem={onOpenSystem} onOpenComponent={onOpenComponent} onOpenAsset={onOpenAsset} onExpired={onExpired}/>:<aside className="composition empty-panel"><p className="muted">Выберите систему — здесь появится её состав.</p></aside>}
  </div>
 </div>;
}

function shortReason(h:RSMCompHost):string{
 const r=h.reasons[0];if(!r)return h.color==='green'?'':'нет данных';
 const days=(d?:string)=>{if(!d)return '';const t=Date.parse(d);return Number.isFinite(t)?Math.max(1,Math.round((Date.now()-t)/86400000))+' дн':''};
 switch(r.code){case 'INVENTORY_STALE':case 'INVENTORY_LOST':return 'устарело '+days(r.detail);case 'NO_INVENTORY':return 'нет данных';case 'HOST_MISSING':return 'пропал из сети';case 'BASELINE_SOFTWARE_MISSING':return 'нет '+(r.detail??'ПО');case 'BASELINE_SOFTWARE_VERSION':return 'версия '+(r.detail?.split(':')[0]??'ПО');case 'BASELINE_OS':return 'ОС не по эталону';case 'RECONCILIATION_CONFLICT':return 'конфликт';default:return r.code}
}
const nonGreen=(s:RSMNodeState|null)=>s?s.red+s.yellow:0;
function compSummary(s:RSMNodeState|null){if(!s)return 'не рассчитано';const pt=problemsText(s);return fmt(s.hosts)+' · '+(pt||'ок')}

export function CompositionPanel({uid,onOpenSystem,onOpenComponent,onOpenAsset,onExpired}:{uid:string;onOpenSystem:(uid:string)=>void;onOpenComponent:(id:string)=>void;onOpenAsset:(uid:string)=>void;onExpired:()=>void}){
 const [q,setQ]=useState(''),[typed,setTyped]=useState(''),[env,setEnv]=useState(''),[problems,setProblems]=useState(false),[open,setOpen]=useState<Record<string,boolean>>({});
 useEffect(()=>{const t=setTimeout(()=>setQ(typed.trim()),300);return()=>clearTimeout(t)},[typed]);
 const [d,error]=useLive<RSMComposition>(()=>api.rsmComposition(uid,q,env,problems),[uid,q,env,problems],onExpired);
 const [allEnvs,setAllEnvs]=useState<RSMComposition['environments']>([]);
 useEffect(()=>{if(d&&!q&&!env)setAllEnvs(d.environments)},[d]);
 const isOpen=(k:string,def:boolean)=>open[k]??def;
 const toggle=(k:string,def:boolean)=>setOpen({...open,[k]:!isOpen(k,def)});
 if(error)return <aside className="composition"><div className="error" role="alert">{errorMessage(error)}</div></aside>;
 if(!d)return <aside className="composition"><p className="muted" role="status">Загрузка состава…</p></aside>;
 const sys=d.system;
 return <aside className="composition" aria-label={'Состав системы '+sys.name}>
  <div className="comp-head"><small className="muted">Системы / {sys.name} / состав</small>
   <div className="comp-title"><h2>{sys.name}</h2><CritBadge value={sys.criticality}/><button className="link right" onClick={()=>onOpenSystem(uid)}>Карточка системы →</button></div>
   <small className="comp-meta">Владелец: {sys.business_owner??'не задан'}{sys.maintenance_window?' · окно: '+sys.maintenance_window:''} · {fmt(d.state?.hosts??0)} {plural(d.state?.hosts??0,'хост','хоста','хостов')} · {d.sites} {plural(d.sites,'площадка','площадки','площадок')}</small></div>
  <div className="comp-filters"><input aria-label="Фильтр состава" placeholder="Фильтр: компонент, хост, IP" value={typed} onChange={e=>setTyped(e.target.value)}/><select aria-label="Среда" value={env} onChange={e=>setEnv(e.target.value)}><option value="">Все среды</option>{allEnvs.map(x=><option key={x.environment_id} value={x.environment_id}>{x.name}</option>)}</select>
   <select aria-label="Хосты" value={problems?'p':''} onChange={e=>setProblems(e.target.value==='p')}><option value="">Все хосты</option><option value="p">Только с проблемами</option></select></div>
  <div className="comp-tree" role="tree">
   {d.environments.length===0?<p className="muted pad">{q?'По фильтру ничего не найдено.':'Сред нет — добавьте их в карточке системы или импортом.'}</p>:null}
   {d.environments.map((e,ei)=>{const ek='e'+e.environment_id,eo=isOpen(ek,ei===0||!!q);const ng=nonGreen(e.state);return <div key={e.environment_id} role="treeitem" aria-expanded={eo}>
    <button className="tree-row env" onClick={()=>toggle(ek,ei===0||!!q)}><span className="caret">{eo?'▾':'▸'}</span><b>{e.name}</b><span className={'tree-note'+(ng?' problem-text':'')}>{fmt(e.state?.hosts??0)} {plural(e.state?.hosts??0,'хост','хоста','хостов')} · {ng?ng+' '+plural(ng,'проблема','проблемы','проблем'):'ок'}</span></button>
    {eo?e.components.map(c=>{const ck='c'+c.component_id,hasProblems=nonGreen(c.state)>0,co=isOpen(ck,hasProblems||!!q);const shownBad=c.hosts.filter(h=>h.color!=='green').length;return <div key={c.component_id} role="group">
     <button className="tree-row comp" onClick={()=>toggle(ck,hasProblems||!!q)}><span className="caret">{co?'▾':'▸'}</span><span className="tree-name" onDoubleClick={()=>onOpenComponent(c.component_id)}>{c.name}</span><span className={'tree-note'+(hasProblems?' problem-text':'')}>{compSummary(c.state)}</span></button>
     {co?<>{c.hosts.map(h=><button key={h.asset_uid} className="tree-row host" onClick={()=>onOpenAsset(h.asset_uid)}><span className={'hdot h-'+h.color}/><span className="tree-name">{h.name||h.asset_uid.slice(0,8)}{h.ip?' · '+h.ip:''}</span><span className={'tree-note'+(h.color==='green'?'':' problem-text'+(h.color==='yellow'?' amber-text':''))}>{shortReason(h)}</span></button>)}
      {c.more>0?<button className="tree-row more" onClick={()=>onOpenComponent(c.component_id)}>ещё {fmt(c.more)} {plural(c.more,'хост','хоста','хостов')}{nonGreen(c.state)<=shownBad&&!problems?' — все актуальны':''}</button>:null}
      <button className="tree-row more link-row" onClick={()=>onOpenComponent(c.component_id)}>Карточка компонента →</button></>:null}
    </div>}):null}
   </div>})}
   <button className="tree-row env" onClick={()=>toggle('deps',false)}><span className="caret">{isOpen('deps',false)?'▾':'▸'}</span><b>Зависит от</b><span className="tree-note">{d.depends_on.map(x=>x.name).join(', ')||'—'}</span></button>
   <button className="tree-row env" onClick={()=>toggle('rdeps',false)}><span className="caret">{isOpen('rdeps',false)?'▾':'▸'}</span><b>От неё зависят</b><span className="tree-note">{d.dependents.map(x=>x.name).join(', ')||'—'}</span></button>
  </div>
 </aside>;
}
export type {RSMColor};

// Раздел «Компоненты» (меню макета): компоненты всех систем, сначала проблемные, поиск по компоненту, роли, системе.
export function ComponentsScreen({onOpen,onOpenSystem,onExpired}:{onOpen:(id:string)=>void;onOpenSystem?:(uid:string)=>void;onExpired:()=>void}){
 // C53.07 (макет «Компоненты»): сводка с фильтрами, группировка по системе, эталон и отклонения, экспорт CSV.
 const [typed,setTyped]=useState(''),[q,setQ]=useState(''),[offset,setOffset]=useState(0),[filter,setFilter]=useState(''),[group,setGroup]=useState(true);
 useEffect(()=>{const t=setTimeout(()=>{setQ(typed.trim());setOffset(0)},300);return()=>clearTimeout(t)},[typed]);
 const [page,error]=useLive(()=>api.rsmComponents(q,offset,filter),[q,offset,filter],onExpired);
 const c=page?.counters;const pick=(f:string)=>()=>{setFilter(filter===f?'':f);setOffset(0)};
 const base=(r:RSMComponentRow)=>[r.baseline.os?'ОС '+r.baseline.os:'',...Object.entries(r.baseline.software??{}).map(([n,v])=>n+(v?' '+v:''))].filter(Boolean).join(' · ');
 function csv(){if(!page)return;const cell=(v:string)=>'"'+v.replace(/"/g,'""')+'"';const rows=[['Компонент','Система','Среда','Роль','Критичный','Хостов','Эталон','Отклонений','Проблемы'],...page.items.map(r=>[r.name,r.system_name,r.environment_name,r.role??'',r.critical?'да':'нет',String(r.state?.hosts??0),base(r),String(r.state?.problems?.baseline??0),problemsText(r.state)])];
  const blob=new Blob(['\ufeff'+rows.map(x=>x.map(cell).join(';')).join('\r\n')],{type:'text/csv;charset=utf-8'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='компоненты.csv';a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000)}
 const rows:React.ReactNode[]=[];let last='';
 for(const r of page?.items??[]){
  if(group&&r.service_uid!==last){last=r.service_uid;const n=(page?.items??[]).filter(x=>x.service_uid===r.service_uid);rows.push(<tr key={'g'+r.service_uid} className="group-row"><td colSpan={9}><span className="caret">▾</span> <button className="link plain" onClick={()=>onOpenSystem?.(r.service_uid)}><b>{r.system_name}</b></button> <span className="muted">· {[...new Set(n.map(x=>envTitle[x.environment_kind].toLowerCase()))].join(', ')} · {n.length} {plural(n.length,'компонент','компонента','компонентов')}</span></td></tr>)}
  const st=r.state,pt=problemsText(st),dev=st?.problems?.baseline??0,b=base(r);
  rows.push(<tr key={r.component_id}><td><button className="row-title" onClick={()=>onOpen(r.component_id)}>{r.name}</button></td><td className="muted">{r.system_name} / {envTitle[r.environment_kind].toLowerCase()}</td><td>{r.role??<span className="muted">—</span>}</td><td>{r.critical?<span className="crit crit-high">критичный</span>:<span className="crit crit-low">обычный</span>}</td><td className="num">{fmt(st?.hosts??0)}</td><td className={b?'':'muted'}>{b||'эталон не задан'}</td><td className={'num'+(dev?' problem-text':'')}>{b?fmt(dev):'—'}</td><td>{st?<Fresh s={st}/>:<span className="muted">—</span>}</td><td className={pt?'problem-text':'muted'}>{pt||'—'}</td></tr>);
 }
 return <div className="systems-screen">
  <div className="count-strip" role="toolbar" aria-label="Сводка компонентов">{([['','компонентов',c?.total,''],['critical','критичных',c?.critical,''],['deviating','с отклонением от эталона',c?.deviating,'warn'],['no_baseline','без эталона',c?.no_baseline,'amber'],['no_hosts','без хостов',c?.no_hosts,'amber']] as [string,string,number|undefined,string][]).map(([k,l,n,tone])=><button key={k||'all'} className={'count'+(filter===k?' active':'')+(tone&&n?' '+tone:'')} onClick={pick(k)}><b>{n===undefined?'…':fmt(n)}</b> {l}</button>)}</div>
  <div className="systems-main solo">
   <div className="systems-toolbar"><input className="toolbar-search" aria-label="Поиск компонентов" placeholder="Компонент, роль или система" value={typed} onChange={e=>setTyped(e.target.value)}/>{filter?<span className="chip">{({critical:'Критичные',deviating:'С отклонением от эталона',no_baseline:'Без эталона',no_hosts:'Без хостов'} as Record<string,string>)[filter]} <button aria-label="Убрать фильтр" onClick={pick(filter)}>×</button></span>:null}
    <span className="spacer"/><select aria-label="Группировать" value={group?'system':''} onChange={e=>setGroup(!!e.target.value)}><option value="system">Группировать: система</option><option value="">Без группировки</option></select><button className="button" disabled={!page?.items.length} onClick={csv}>Экспорт CSV</button></div>
   {error?<div className="error" role="alert">{errorMessage(error)}</div>:null}
   <div className="table-panel dense">{page&&page.items.length===0?<div className="empty"><h3>Компонентов нет</h3><p>{filter||q?'Нет компонентов по фильтру.':'Компоненты заводятся в карточке системы (вкладка «Состав») или импортом.'}</p></div>:
    <div className="table-scroll"><table className="systems-table"><thead><tr><th>Компонент</th><th>Система / среда</th><th>Роль</th><th>Критичность</th><th className="num">Хостов</th><th>Эталон</th><th className="num">Отклонений</th><th>Данные актуальны</th><th>Проблемы</th></tr></thead><tbody>{rows}</tbody></table></div>}</div>
   <div className="systems-footer">Показаны {fmt(page?.items.length??0)} из {fmt(page?.total??0)}{page?.next_offset!=null?<> · <button className="link" onClick={()=>setOffset(page.next_offset!)}>следующие 100</button></>:null}{offset>0?<> · <button className="link" onClick={()=>setOffset(Math.max(0,offset-100))}>предыдущие</button></>:null} · клик по компоненту — карточка компонента, по системе — карточка системы</div>
  </div>
 </div>;
}
