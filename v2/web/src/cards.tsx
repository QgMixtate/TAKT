import {useEffect,useState,type ReactNode} from 'react';
import {api,ApiError,errorMessage,type RSMChange,type RSMComponentCard,type RSMEnvKind,type RSMHostRow,type RSMOverview,type RSMProblems,type RSMSoftwarePage,type RSMSystemCard,type RSMTicketList,type Subject,type TicketKind} from './api';
import {CritBadge,critLabel,problemsText} from './systems';
import {SystemCard as SystemEdit,ComponentCard as ComponentEdit} from './rsm';

// C53.03 — карточки системы (макет C53-mockups/7) и компонента (макет 8) — по макетам: шапка с кнопками «Экспорт»,
// «Создать обращение» / «Сравнить с эталоном», «Собрать по …», показатели, вкладки. Редактирование — вкладками
// «Состав» и «Ответственные» (система), «настроить эталон», «Правила» и «Привязать хосты» (компонент).

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
const changeName:Record<string,string>={'binding/created':'Хост привязан к компоненту','binding/closed':'Хост отвязан от компонента','binding/proposed':'Правило предложило привязку','binding/confirmed':'Привязка подтверждена','binding/rejected':'Предложение отклонено','binding/retargeted':'Привязка перенесена при слиянии','binding/updated':'Сменилась основная привязка','component/created':'Создан компонент','component/updated':'Изменён компонент','environment/created':'Создана среда','service/created':'Создана система','service/updated':'Изменены поля системы','service/retired':'Система выведена','binding_rule/created':'Добавлено правило автопривязки','binding_rule/retired':'Снято правило автопривязки','component_dependency/created':'Добавлена зависимость компонентов','relation/created':'Добавлена связь','relation/retired':'Снята связь'};
const assetChange:Record<string,string>={ASSET_RESTORED:'Возвращён в учёт',SITE_FALLBACK:'Назначен ответственный площадки',MERGED_INTO_ASSET:'Поглощён другой карточкой',RELATION_CHANGED:'Изменены связи',HOSTNAME_CHANGED:'Сменилось имя ПК',ASSET_MERGE:'Слияние карточек',ASSET_SPLIT:'Разделение карточки',AUTO_STRONG_MATCH:'Автопривязка по сильному признаку',BUSINESS_FIELDS_CHANGED:'Изменены поля карточки',ASSET_CLASS_CHANGED:'Изменён класс',ASSET_RETIRED:'Выведен из учёта',MANUAL_RECONCILIATION:'Разбор конфликта',SOURCE_MAPPING:'Привязан источник',CSV_IMPORT:'Импорт CSV'};
function changeText(c:RSMChange){
 if(c.source==='asset'){const base=assetChange[c.object_type]??c.object_type;const d=c.detail as {from?:string[];to?:string[]};return c.object_type==='HOSTNAME_CHANGED'&&d.from&&d.to?base+': '+d.from.join(', ')+' → '+d.to.join(', '):base}
 const d=c.detail as Record<string,string>;return (changeName[c.object_type+'/'+c.action]??c.object_type+' · '+c.action)+(d.name?' «'+d.name+'»':'')+(d.pattern?': '+d.pattern:'')
}
const ptext=(p:RSMProblems)=>problemsText({problems:p,computed_at:'x'} as never);
function ProblemPill({p,color}:{p:RSMProblems;color:string}){const t=ptext(p);return t?<span className={'pill '+(color==='red'?'pill-bad':'pill-warn')}>{t}</span>:<span className="pill pill-ok">ок</span>}
function Kpi({label,children}:{label:string;children:ReactNode}){return <div className="kpi"><small>{label}</small><strong>{children}</strong></div>}
function Tabs<T extends string>({tabs,value,onChange}:{tabs:[T,string][];value:T;onChange:(t:T)=>void}){return <div className="card-tabs-bar" role="tablist">{tabs.map(([k,l])=><button key={k} role="tab" aria-selected={value===k} className={value===k?'active':''} onClick={()=>onChange(k)}>{l}</button>)}</div>}
function Toast({text,onClose}:{text:string;onClose:()=>void}){useEffect(()=>{if(!text)return;const t=setTimeout(onClose,6000);return()=>clearTimeout(t)},[text]);return text?<p className="rsm-note" role="status">{text} <button className="link" onClick={onClose}>скрыть</button></p>:null}

function ChangesPanel({list,total,onOpenAsset,onAll}:{list:RSMChange[];total:number;onOpenAsset:(uid:string)=>void;onAll?:()=>void}){
 const [q,setQ]=useState('');const shown=list.filter(c=>!q||(changeText(c)+' '+c.asset_name).toLowerCase().includes(q.toLowerCase()));
 return <section className="panel"><header><h3>Изменения за 7 дней · {fmt(total)}</h3><input className="panel-filter" placeholder="Фильтр по изменениям" value={q} onChange={e=>setQ(e.target.value)} aria-label="Фильтр по изменениям"/>{onAll?<button className="link" onClick={onAll}>все →</button>:null}</header>
  {shown.length===0?<p className="muted pad">Изменений нет.</p>:<table className="panel-table"><thead><tr><th>Когда</th><th>Что</th><th>Где</th></tr></thead><tbody>{shown.map((c,i)=><tr key={i}><td>{when(c.occurred_at)}</td><td>{changeText(c)}</td><td>{c.asset_uid?<button className="link plain mono-link" onClick={()=>onOpenAsset(c.asset_uid!)}>{c.asset_name||c.asset_uid.slice(0,8)}</button>:<span className="muted">—</span>}</td></tr>)}</tbody></table>}
 </section>;
}

function SoftwarePanel({kind,id,onExpired}:{kind:'systems'|'components';id:string;onExpired:()=>void}){
 const [typed,setTyped]=useState(''),[q,setQ]=useState('');
 useEffect(()=>{const t=setTimeout(()=>setQ(typed.trim()),300);return()=>clearTimeout(t)},[typed]);
 const [d,error]=useLive<RSMSoftwarePage>(()=>api.rsmSoftware(kind,id,q),[kind,id,q],onExpired);
 return <section className="panel wide"><header><h3>ПО и версии{d?' · '+fmt(d.products.length):''}</h3><input className="panel-filter" placeholder="Фильтр по названию" aria-label="Фильтр ПО" value={typed} onChange={e=>setTyped(e.target.value)}/></header>
  <Err e={error}/>{!d?<p className="muted pad">Загрузка…</p>:d.products.length===0?<p className="muted pad">{q?'По фильтру ничего нет.':'Нет данных о ПО (собирается агентами и сбором по SSH/WinRM профиля 1.2).'}</p>:
  <table className="panel-table"><thead><tr><th>Продукт</th><th>Версии — хостов</th><th className="num">Хостов</th><th/></tr></thead><tbody>{d.products.map(p=><tr key={p.name}><td>{p.name}</td><td className="muted">{p.versions.map(v=>(v.version||'без версии')+' — '+fmt(v.hosts)).join(' · ')}</td><td className="num">{fmt(p.hosts)} из {fmt(d.hosts)}</td><td>{p.versions.length>1?<span className="pill pill-warn">расхождение версий</span>:null}</td></tr>)}</tbody></table>}
  {d?.truncated?<p className="muted small pad">Показаны первые 5000 сочетаний «продукт — версия»; уточните фильтр.</p>:null}
 </section>;
}

const ticketKind:Record<string,string>={incident:'Инцидент',request:'Запрос',change:'Изменение',problem:'Проблема'};
export function TicketsPanel({kind,id,onCreate,onExpired}:{kind:'systems'|'components'|'assets';id:string;onCreate?:()=>void;onExpired:()=>void}){
 const [d,error]=useLive<RSMTicketList>(()=>kind==='assets'?api.assetTickets(id):api.rsmTickets(kind,id),[kind,id],onExpired);
 return <section className="panel wide"><header><h3>Обращения{d?' · '+fmt(d.items.length):''}</h3>{onCreate?<button className="button small right" onClick={onCreate}>Создать обращение</button>:null}</header>
  <Err e={error}/>{!d?<p className="muted pad">Загрузка…</p>:d.items.length===0?<p className="muted pad">Обращений нет. Обращения, связанные с системой или её хостами, появятся здесь.</p>:
  <table className="panel-table"><thead><tr><th>Номер</th><th>Вид</th><th>Тема</th><th>Состояние</th><th>Создано</th></tr></thead><tbody>{d.items.map(t=><tr key={t.ticket_id} className={t.open?'':'muted'}><td className="mono-link">{t.number}</td><td>{ticketKind[t.kind]}</td><td>{t.title}</td><td>{t.open?<span className="pill pill-warn">{t.state}</span>:<span className="pill">{t.state}</span>}</td><td>{when(t.created_at)}</td></tr>)}</tbody></table>}
 </section>;
}

// «Создать обращение» — обращение ITSM со связью с системой (сервис) или активом.
export function TicketDialog({csrf,title,serviceUid,assetUid,description='',onClose,onCreated,onExpired}:{csrf:string;title:string;serviceUid?:string;assetUid?:string;description?:string;onClose:()=>void;onCreated:(number:string)=>void;onExpired:()=>void}){
 const [kind,setKind]=useState<TicketKind>('incident'),[t,setT]=useState(title),[desc,setDesc]=useState(description),[impact,setImpact]=useState(2),[urgency,setUrgency]=useState(2),[busy,setBusy]=useState(false),[error,setError]=useState<unknown>(null);
 async function submit(e:React.FormEvent){e.preventDefault();setBusy(true);setError(null);try{const d=await api.createTicket(csrf,{kind,title:t.trim(),description:desc,impact,urgency,service_uid:serviceUid,asset_uid:assetUid});onCreated(d.number)}catch(x){setError(x);if(x instanceof ApiError&&x.status===401)onExpired()}finally{setBusy(false)}}
 return <div className="modal-shade" role="presentation" onClick={onClose}><form className="modal" role="dialog" aria-label="Создать обращение" onClick={e=>e.stopPropagation()} onSubmit={e=>void submit(e)}>
  <h2>Создать обращение</h2><Err e={error}/>
  <label>Вид<select value={kind} onChange={e=>setKind(e.target.value as TicketKind)}>{Object.entries(ticketKind).map(([k,v])=><option key={k} value={k}>{v}</option>)}</select></label>
  <label>Тема<input value={t} onChange={e=>setT(e.target.value)} maxLength={256} required/></label>
  <label>Описание<textarea rows={4} value={desc} onChange={e=>setDesc(e.target.value)} maxLength={8000}/></label>
  <div className="row2"><label>Влияние<select value={impact} onChange={e=>setImpact(Number(e.target.value))}><option value={1}>высокое</option><option value={2}>среднее</option><option value={3}>низкое</option></select></label><label>Срочность<select value={urgency} onChange={e=>setUrgency(Number(e.target.value))}><option value={1}>высокая</option><option value={2}>средняя</option><option value={3}>низкая</option></select></label></div>
  <div className="modal-actions"><button type="button" className="button" onClick={onClose}>Отмена</button><button className="button primary-sm" disabled={busy||!t.trim()}>Создать</button></div>
 </form></div>;
}

function CollectButton({kind,id,label,csrf,canWrite,onDone,onExpired}:{kind:'systems'|'components';id:string;label:string;csrf:string;canWrite:boolean;onDone:(t:string)=>void;onExpired:()=>void}){
 const [busy,setBusy]=useState(false);
 if(!canWrite)return null;
 async function run(){setBusy(true);try{const r=await api.rsmCollect(kind,id,csrf);onDone('Сбор запрошен: целей сбора — '+r.requested+(r.recent?' (ещё '+r.recent+' уже запрошены недавно)':'')+(r.agents?'; хостов с агентом — '+r.agents+', соберут по своему расписанию':'')+(r.no_target?'; без цели сбора — '+r.no_target:''))}catch(e){onDone(errorMessage(e));if(e instanceof ApiError&&e.status===401)onExpired()}finally{setBusy(false)}}
 return <button className="button primary-sm" disabled={busy} onClick={()=>void run()}>{label}</button>;
}

type SysTab='overview'|'composition'|'deps'|'software'|'changes'|'tickets'|'people';
export function SystemCardPage({uid,csrf,canWrite,directions,onBack,onComponent,onOpenAsset,onOpenSystem,onExpired,onChanged,onCrumbs}:{uid:string;csrf:string;canWrite:boolean;directions:RSMOverview['directions'];onBack:()=>void;onComponent:(id:string,from:string)=>void;onOpenAsset:(uid:string)=>void;onOpenSystem:(uid:string)=>void;onExpired:()=>void;onChanged:()=>void;onCrumbs:(c:string[])=>void}){
 const [tab,setTab]=useState<SysTab>('overview'),[mq,setMq]=useState(''),[aq,setAq]=useState(''),[ticket,setTicket]=useState(false),[note,setNote]=useState('');
 const [d,error,reload]=useLive<RSMSystemCard>(()=>api.rsmSystemCard(uid),[uid],onExpired);
 useEffect(()=>{if(d)onCrumbs([d.system.name])},[d?.system.name]);
 if(error)return <Err e={error}/>;
 if(!d)return <p className="muted pad" role="status">Загрузка карточки…</p>;
 const s=d.system,st=d.state,hosts=st?.hosts??0,fresh=st?.fresh??0,pt=problemsText(st);
 const kinds=d.env_kinds;const matrix=d.matrix.filter(r=>!mq||r.name.toLowerCase().includes(mq.toLowerCase()));
 const attention=d.attention.filter(a=>!aq||(a.component_name+' '+a.hosts.map(h=>h.name).join(' ')+' '+(reasonPhrase[a.code]??a.code)).toLowerCase().includes(aq.toLowerCase()));
 const dep=(x:RSMSystemCard['depends_on'][number],critical:boolean)=><li key={x.service_uid}><button className="link plain" onClick={()=>onOpenSystem(x.service_uid)}>{x.name}</button>{critical?<CritBadge value={x.criticality}/>:<ProblemPill p={x.problems} color={x.color}/>}</li>;
 const depsPanel=<section className="panel"><header><h3>Зависимости</h3></header><div className="dep-block"><small>Зависит от</small>{d.depends_on.length?<ul className="dep-list">{d.depends_on.map(x=>dep(x,false))}</ul>:<p className="muted">—</p>}<small>От неё зависят</small>{d.dependents.length?<ul className="dep-list">{d.dependents.map(x=>dep(x,true))}</ul>:<p className="muted">—</p>}</div></section>;
 const people=<section className="panel"><header><h3>Ответственные</h3></header><dl className="resp"><dt>Владелец</dt><dd>{s.business_owner??<span className="muted">не задан</span>}</dd><dt>ИТ</dt><dd>{d.it_subject_name??<span className="muted">не задан</span>}</dd><dt>Дежурные</dt><dd>{s.on_call??<span className="muted">не заданы</span>}</dd><dt>Резерв</dt><dd>{d.backup_subject_name??<span className="muted">не задан</span>}</dd></dl></section>;
 return <div className="card-page">
  <header className="card-header">
   <small className="kicker">Система{d.direction_name?' · направление «'+d.direction_name+'»':''}</small>
   <div className="card-title"><h1>{s.name}</h1><span className={'crit crit-'+s.criticality}>критичность {critLabel[s.criticality]}</span>{kinds.length?<span className="pill">{kinds.map(k=>envLower[k]).join(' · ')}</span>:null}
    <span className="title-actions"><a className="button" href={'/api/v1/rsm/systems/'+encodeURIComponent(uid)+'/hosts.csv'} download>Экспорт</a>{canWrite?<button className="button" onClick={()=>setTicket(true)}>Создать обращение</button>:null}<CollectButton kind="systems" id={uid} label="Собрать по системе" csrf={csrf} canWrite={canWrite} onDone={setNote} onExpired={onExpired}/></span></div>
   <div className="kpis"><Kpi label="Владелец (бизнес)">{s.business_owner??<span className="amber-text">не задан</span>}</Kpi><Kpi label="Ответственный ИТ">{d.it_subject_name??<span className="muted">не задан</span>}</Kpi><Kpi label="Хостов">{fmt(hosts)} · {d.sites} {plural(d.sites,'площадка','площадки','площадок')}</Kpi><Kpi label="Данные актуальны">{hosts?Math.round(fresh*100/hosts)+'% ('+fmt(fresh)+' из '+fmt(hosts)+')':'—'}</Kpi><Kpi label="Проблемы">{pt?<span className="problem-text">{pt}</span>:st?'нет':'не рассчитано'}</Kpi><Kpi label="Окно обслуживания">{s.maintenance_window??<span className="muted">не задано</span>}</Kpi></div>
  </header>
  <Tabs<SysTab> tabs={[['overview','Обзор'],['composition','Состав · '+fmt(hosts)],['deps','Зависимости'],['software','ПО и версии'],['changes','Изменения'],['tickets','Обращения · '+fmt(d.tickets_total)],['people','Ответственные']]} value={tab} onChange={setTab}/>
  {tab==='overview'?<div className="card-grid">
   <div className="card-col">
    <section className="panel"><header><h3>Состав по средам</h3><input className="panel-filter" placeholder="Фильтр по компонентам" aria-label="Фильтр по компонентам" value={mq} onChange={e=>setMq(e.target.value)}/></header>
     {d.matrix.length===0?<p className="muted pad">Компонентов нет — добавьте их на вкладке «Состав».</p>:<table className="panel-table"><thead><tr><th>Компонент</th>{kinds.map(k=><th key={k} className="num">{envShort[k]}</th>)}<th>Проблемы</th></tr></thead><tbody>{matrix.map(r=><tr key={r.name}><td><button className="link plain" onClick={()=>{const first=kinds.map(k=>r.cells[k]).find(Boolean);if(first)onComponent(first.component_id,uid)}}>{r.name}</button></td>{kinds.map(k=><td key={k} className="num">{r.cells[k]?fmt(r.cells[k]!.hosts):'—'}</td>)}<td className={ptext(r.problems)?(r.color==='red'?'problem-text':'amber-text'):'muted'}>{ptext(r.problems)||'—'}</td></tr>)}</tbody></table>}
    </section>
    <section className="panel"><header><h3>Требует внимания · {d.attention.reduce((n,a)=>n+a.total,0)}</h3><input className="panel-filter" placeholder="Фильтр" aria-label="Фильтр требует внимания" value={aq} onChange={e=>setAq(e.target.value)}/></header>
     {attention.length===0?<p className="muted pad">{st?'Проблем нет.':'Состояние появится после пересчёта.'}</p>:<ul className="attention">{attention.map((a,i)=><li key={i}><span className={'hdot h-'+a.color}/><span className="att-main">{a.hosts.map((h,j)=><span key={h.asset_uid}>{j?', ':''}<button className="link plain" onClick={()=>onOpenAsset(h.asset_uid)}>{h.name||h.asset_uid.slice(0,8)}</button></span>)}{a.total>a.hosts.length?' и ещё '+(a.total-a.hosts.length):''} — {reasonPhrase[a.code]??a.code}{a.detail?': '+a.detail:''}</span><span className="att-where">{a.component_name} · {a.environment_name.toLowerCase()}</span></li>)}</ul>}
    </section>
   </div>
   <div className="card-col">{depsPanel}{people}</div>
   <div className="card-wide"><ChangesPanel list={d.changes.slice(0,5)} total={d.changes_total} onOpenAsset={onOpenAsset} onAll={()=>setTab('changes')}/></div>
  </div>:null}
  {tab==='composition'?<div className="card-pad"><SystemEdit uid={uid} csrf={csrf} canWrite={canWrite} directions={directions} onBack={onBack} onComponent={id=>onComponent(id,uid)} onExpired={onExpired} onDirection={()=>{reload();onChanged()}} embedded/></div>:null}
  {tab==='deps'?<div className="card-pad">{depsPanel}<p className="muted small">Связи «зависит от» между системами заводятся в «Действия → Новая система, связи систем».</p></div>:null}
  {tab==='software'?<div className="card-pad"><SoftwarePanel kind="systems" id={uid} onExpired={onExpired}/></div>:null}
  {tab==='changes'?<div className="card-pad"><ChangesPanel list={d.changes} total={d.changes_total} onOpenAsset={onOpenAsset}/></div>:null}
  {tab==='tickets'?<div className="card-pad"><TicketsPanel kind="systems" id={uid} onCreate={canWrite?()=>setTicket(true):undefined} onExpired={onExpired}/></div>:null}
  {tab==='people'?<div className="card-pad"><PeopleEditor card={d} csrf={csrf} canWrite={canWrite} directions={directions} onSaved={()=>{reload();onChanged()}} onExpired={onExpired}/></div>:null}
  {ticket?<TicketDialog csrf={csrf} title={s.name+': '} serviceUid={uid} onClose={()=>setTicket(false)} onCreated={n=>{setTicket(false);setNote('Создано обращение '+n);reload()}} onExpired={onExpired}/>:null}
  <Toast text={note} onClose={()=>setNote('')}/>
 </div>;
}

// Вкладка «Ответственные»: владелец, ИТ, дежурные, резерв, окно обслуживания, направление.
function PeopleEditor({card,csrf,canWrite,directions,onSaved,onExpired}:{card:RSMSystemCard;csrf:string;canWrite:boolean;directions:RSMOverview['directions'];onSaved:()=>void;onExpired:()=>void}){
 const s=card.system;
 const [f,setF]=useState({owner:s.business_owner??'',it:s.it_subject_id??'',onCall:s.on_call??'',backup:s.backup_subject_id??'',window:s.maintenance_window??'',direction:s.direction_uid??''});
 const [subjects,setSubjects]=useState<Subject[]>([]),[busy,setBusy]=useState(false),[error,setError]=useState<unknown>(null),[saved,setSaved]=useState(false);
 useEffect(()=>{api.subjects('').then(p=>setSubjects(p.items)).catch(()=>setSubjects([]))},[]);
 async function save(e:React.FormEvent){e.preventDefault();setBusy(true);setError(null);setSaved(false);try{await api.rsmPatchSystem(s.service_uid,csrf,{revision:s.revision,business_owner:f.owner,it_subject_id:f.it,on_call:f.onCall,backup_subject_id:f.backup,maintenance_window:f.window,direction_uid:f.direction});setSaved(true);onSaved()}catch(x){setError(x);if(x instanceof ApiError&&x.status===401)onExpired()}finally{setBusy(false)}}
 const subj=(v:string,set:(x:string)=>void,label:string)=><label>{label}<select value={v} disabled={!canWrite} onChange={e=>set(e.target.value)}><option value="">не задан</option>{subjects.map(x=><option key={x.subject_id} value={x.subject_id}>{x.name}{x.kind==='team'?' (команда)':''}</option>)}</select></label>;
 return <section className="panel"><header><h3>Ответственные</h3></header><form className="people-form" onSubmit={e=>void save(e)}><Err e={error}/>
  <label>Владелец (бизнес)<input value={f.owner} disabled={!canWrite} onChange={e=>setF({...f,owner:e.target.value})} placeholder="например, Финансовый департамент — И. Петрова" maxLength={512}/></label>
  {subj(f.it,v=>setF({...f,it:v}),'Ответственный ИТ')}
  <label>Дежурные<input value={f.onCall} disabled={!canWrite} onChange={e=>setF({...f,onCall:e.target.value})} placeholder="например, Группа приложений, неделя 47" maxLength={256}/></label>
  {subj(f.backup,v=>setF({...f,backup:v}),'Резерв')}
  <label>Окно обслуживания<input value={f.window} disabled={!canWrite} onChange={e=>setF({...f,window:e.target.value})} placeholder="например, вс 02:00–06:00" maxLength={256}/></label>
  <label>Направление<select value={f.direction} disabled={!canWrite} onChange={e=>setF({...f,direction:e.target.value})}><option value="">не задано</option>{directions.map(x=><option key={x.direction_uid} value={x.direction_uid}>{x.name}</option>)}</select></label>
  {canWrite?<div><button className="button primary-sm" disabled={busy}>Сохранить</button>{saved?<span className="muted small"> Сохранено.</span>:null}</div>:null}
 </form></section>;
}

function freshText(h:RSMHostRow){if(!h.last_inventory_at)return 'нет данных';const days=Math.floor((Date.now()-Date.parse(h.last_inventory_at))/86400000);return days>=1?'устарело '+days+' дн':'актуально'}
type CompTab='hosts'|'baseline'|'software'|'changes'|'tickets';
export function ComponentCardPage({id,csrf,canWrite,onBack,backLabel,onOpenSystem,onOpenAsset,onExpired,onCrumbs}:{id:string;csrf:string;canWrite:boolean;onBack:()=>void;backLabel:string;onOpenSystem:(uid:string)=>void;onOpenAsset:(uid:string)=>void;onExpired:()=>void;onCrumbs:(c:string[])=>void}){
 const [tab,setTab]=useState<CompTab>('hosts'),[typed,setTyped]=useState(''),[q,setQ]=useState(''),[site,setSite]=useState(''),[color,setColor]=useState(''),[offset,setOffset]=useState(0);
 const [picked,setPicked]=useState<Set<string>>(new Set()),[busy,setBusy]=useState(false),[actError,setActError]=useState<unknown>(null),[note,setNote]=useState('');
 const [hidden,setHidden]=useState<Set<string>>(new Set()),[colMenu,setColMenu]=useState(false),[manage,setManage]=useState(false),[setup,setSetup]=useState(false);
 useEffect(()=>{const t=setTimeout(()=>{setQ(typed.trim());setOffset(0)},300);return()=>clearTimeout(t)},[typed]);
 const [d,error,reload]=useLive<RSMComponentCard>(()=>api.rsmComponentCard(id,{q,site,color,offset}),[id,q,site,color,offset],onExpired);
 useEffect(()=>{if(d)onCrumbs([d.system_name,d.environment.name,d.component.name])},[d?.component.name,d?.system_name]);
 if(error)return <Err e={error}/>;
 if(!d)return <p className="muted pad" role="status">Загрузка карточки…</p>;
 const c=d.component,st=d.state,hosts=st?.hosts??0,stale=(st?.problems.stale??0)+(st?.problems.no_data??0),dev=d.baseline_summary.reduce((n,b)=>n+b.deviations,0);
 const keys=d.baseline_summary.map(b=>b.key);
 const cols:[string,string][]=[['ip','IP-адрес'],['site','Площадка'],['fresh','Свежесть'],...d.baseline_summary.map(b=>[b.key,b.key==='os'?'ОС':b.label] as [string,string]),['collected','Сбор']];
 const show=(k:string)=>!hidden.has(k);
 async function unbind(){if(!window.confirm('Отвязать выбранные хосты ('+picked.size+') от компонента? Изменение попадёт в историю.'))return;setBusy(true);setActError(null);try{for(const h of d!.hosts.filter(x=>picked.has(x.asset_uid)&&x.binding_id))await api.rsmUnbind(h.binding_id,csrf);setPicked(new Set());reload()}catch(e){setActError(e);if(e instanceof ApiError&&e.status===401)onExpired()}finally{setBusy(false)}}
 const baselineSummary=d.baseline_summary.map(b=>(b.key==='os'?'':b.label+' ')+(b.expected||'есть')).join(' · ');
 const okHosts=d.hosts.filter(h=>h.color==='green').length;
 return <div className="card-page">
  <header className="card-header">
   <small className="kicker">Компонент системы <button className="link plain" onClick={()=>onOpenSystem(d.service_uid)}>{d.system_name}</button> · среда {d.environment.name.toLowerCase()}</small>
   <div className="card-title"><h1>{c.name}</h1><span className="pill">{fmt(hosts)} {plural(hosts,'хост','хоста','хостов')}</span>{stale?<span className="pill pill-bad">{fmt(stale)} {plural(stale,'устарел','устарели','устарели')}</span>:null}{dev?<span className="pill pill-warn">расхождение версий</span>:null}
    <span className="title-actions"><a className="button" href={'/api/v1/rsm/components/'+encodeURIComponent(id)+'/hosts.csv'} download>Экспорт</a><button className="button" onClick={()=>setTab('baseline')}>Сравнить с эталоном</button><CollectButton kind="components" id={id} label="Собрать по компоненту" csrf={csrf} canWrite={canWrite} onDone={setNote} onExpired={onExpired}/></span></div>
   <div className="kpis"><Kpi label="Роль">{c.role??(c.critical?'критичный компонент':<span className="muted">не задана</span>)}</Kpi><Kpi label="Ответственный">{d.it_subject_name??<span className="muted">не задан</span>}</Kpi><Kpi label="Площадки">{d.sites.length?d.sites.map(x=>(x.name||'—')+' · '+x.count).join(', '):'—'}</Kpi><Kpi label="Сеть">{d.networks.length?d.networks.map(x=>x.name).join(', '):'—'}</Kpi><Kpi label="Данные актуальны">{hosts?fmt(st!.fresh)+' из '+fmt(hosts):'—'}</Kpi><Kpi label="Эталон">{baselineSummary||<span className="muted">не задан</span>}</Kpi></div>
  </header>
  <Tabs<CompTab> tabs={[['hosts','Хосты · '+fmt(hosts)],['baseline','Отклонения от эталона'],['software','ПО и версии'],['changes','Изменения'],['tickets','Обращения'+(d.tickets_total?' · '+fmt(d.tickets_total):'')]]} value={tab} onChange={setTab}/>
  <Err e={actError}/>
  {tab==='hosts'?<div className="card-grid">
   <div className="card-col"><section className="panel"><header><h3>Хосты компонента</h3><span className="header-actions">{canWrite?<button className="button" onClick={()=>setManage(!manage)} aria-expanded={manage}>Привязка и правила</button>:null}<span className="menu-anchor"><button className="button" onClick={()=>setColMenu(!colMenu)} aria-expanded={colMenu}>Колонки</button>{colMenu?<div className="popover right" role="dialog" aria-label="Колонки хостов">{cols.map(([k,l])=><label key={k} className="check"><input type="checkbox" checked={show(k)} onChange={e=>{const n=new Set(hidden);if(e.target.checked)n.delete(k);else n.add(k);setHidden(n)}}/>{l}</label>)}<button className="button small" onClick={()=>setColMenu(false)}>Готово</button></div>:null}</span></span></header>
    {manage?<div className="manage-box"><ComponentEdit id={id} csrf={csrf} canWrite={canWrite} onBack={onBack} onOpenAsset={onOpenAsset} onExpired={onExpired} embedded/><button className="link" onClick={()=>{setManage(false);reload()}}>Готово — обновить список</button></div>:null}
    <div className="panel-filters"><input placeholder="Фильтр: хост, IP" aria-label="Фильтр хостов" value={typed} onChange={e=>setTyped(e.target.value)}/><select aria-label="Площадка" value={site} onChange={e=>{setSite(e.target.value);setOffset(0)}}><option value="">Все площадки</option>{d.sites.map(x=><option key={x.name} value={x.name}>{x.name||'—'}</option>)}</select><select aria-label="Состояние" value={color} onChange={e=>{setColor(e.target.value);setOffset(0)}}><option value="">Любое состояние</option><option value="red">устарело / пропал</option><option value="yellow">требует внимания</option><option value="grey">нет данных</option><option value="green">актуально</option></select><span className="muted counter">{fmt(d.hosts.length)} из {fmt(d.matched)}{okHosts&&okHosts<d.hosts.length?' · ещё '+fmt(okHosts)+' актуальны':''}</span></div>
    {picked.size&&canWrite?<div className="bulk-bar">Выбрано: {picked.size} <button className="button small" disabled={busy} onClick={()=>void unbind()}>Отвязать от компонента</button> <button className="link" onClick={()=>setPicked(new Set())}>снять выбор</button></div>:null}
    {d.hosts.length===0?<p className="muted pad">{hosts===0?'Хостов нет — привяжите их кнопкой «Привязка и правила».':'По фильтру хостов нет.'}</p>:
    <div className="table-scroll"><table className="panel-table hosts-table"><thead><tr><th className="cb">{canWrite?<input type="checkbox" aria-label="Выбрать все" checked={d.hosts.every(h=>picked.has(h.asset_uid))} onChange={e=>setPicked(e.target.checked?new Set(d.hosts.map(h=>h.asset_uid)):new Set())}/>:null}</th><th>Хост</th>{cols.filter(([k])=>show(k)).map(([k,l])=><th key={k}>{l}</th>)}</tr></thead>
     <tbody>{d.hosts.map(h=><tr key={h.asset_uid}><td className="cb">{canWrite?<input type="checkbox" aria-label={'Выбрать '+(h.name||h.asset_uid)} checked={picked.has(h.asset_uid)} onChange={e=>{const n=new Set(picked);if(e.target.checked)n.add(h.asset_uid);else n.delete(h.asset_uid);setPicked(n)}}/>:null}</td>
      <td><button className="link plain mono-link" onClick={()=>onOpenAsset(h.asset_uid)}>{h.name||h.asset_uid.slice(0,8)}</button>{h.is_primary?null:<small className="muted"> · общий</small>}</td>
      {show('ip')?<td>{h.ip||'—'}</td>:null}{show('site')?<td>{h.site||'—'}</td>:null}
      {show('fresh')?<td><span className={'hdot h-'+h.color}/> {freshText(h)}</td>:null}
      {keys.filter(k=>show(k)).map(k=>{const b=d.baseline_summary.find(x=>x.key===k)!;const v=h.values[k];const bad=v===undefined?false:k==='os'?!v.toLowerCase().includes(b.expected.toLowerCase()):b.expected?!v.split(', ').some(x=>x.startsWith(b.expected)):false;const missing=v===undefined&&k!=='os'&&Object.keys(h.values).some(x=>x.startsWith('software:'));return <td key={k} className={missing?'problem-text':v===undefined?'muted':bad?'amber-text':''}>{v??(missing?'нет':'—')}</td>})}
      {show('collected')?<td className="muted">{when(h.last_inventory_at)}</td>:null}</tr>)}</tbody></table></div>}
    {d.next_offset!=null||offset>0?<div className="pager"><small>по 100</small><div><button className="button small" disabled={offset===0} onClick={()=>setOffset(Math.max(0,offset-100))}>← Назад</button><button className="button small" disabled={d.next_offset==null} onClick={()=>setOffset(d.next_offset!)}>Далее →</button></div></div>:null}
   </section></div>
   <div className="card-col"><BaselinePanel d={d} onSetup={canWrite?()=>setSetup(true):undefined}/></div>
  </div>:null}
  {tab==='baseline'?<div className="card-pad"><BaselinePanel d={d} wide onSetup={canWrite?()=>setSetup(true):undefined}/></div>:null}
  {tab==='software'?<div className="card-pad"><SoftwarePanel kind="components" id={id} onExpired={onExpired}/></div>:null}
  {tab==='changes'?<div className="card-pad"><ComponentChanges id={id} onOpenAsset={onOpenAsset} onExpired={onExpired}/></div>:null}
  {tab==='tickets'?<div className="card-pad"><TicketsPanel kind="components" id={id} onExpired={onExpired}/></div>:null}
  {setup?<BaselineDialog d={d} csrf={csrf} onClose={()=>setSetup(false)} onSaved={()=>{setSetup(false);setNote('Эталон сохранён — отклонения пересчитаются при следующем пересчёте состояния');reload()}} onExpired={onExpired}/>:null}
  <Toast text={note} onClose={()=>setNote('')}/>
  <span className="sr-only">{backLabel}</span>
 </div>;
}

function ComponentChanges({id,onOpenAsset,onExpired}:{id:string;onOpenAsset:(uid:string)=>void;onExpired:()=>void}){
 const [d,error]=useLive(()=>api.rsmComponentChanges(id),[id],onExpired);
 if(error)return <Err e={error}/>;
 return d?<ChangesPanel list={d.changes} total={d.total} onOpenAsset={onOpenAsset}/>:<p className="muted pad">Загрузка…</p>;
}

function BaselinePanel({d,wide,onSetup}:{d:RSMComponentCard;wide?:boolean;onSetup?:()=>void}){
 return <section className={'panel'+(wide?' wide':'')}><header><h3>Отклонения от эталона</h3>{onSetup?<button className="link right" onClick={onSetup}>настроить эталон</button>:null}</header>
  {d.baseline_summary.length===0?<p className="muted pad">Эталон не задан{onSetup?<> — <button className="link" onClick={onSetup}>задать</button></>:null}.</p>:
  <table className="panel-table baseline"><tbody>{d.baseline_summary.map(b=><tr key={b.key}><td>{b.key==='os'?'ОС':b.label}</td><td className="values">{b.values.map(v=>v.name+' — '+fmt(v.count)).join(' · ')||'—'}{b.no_data?<small className="muted"> · нет данных — {fmt(b.no_data)}</small>:null}</td><td>{b.deviations?<span className="pill pill-warn">{fmt(b.deviations)} откл.</span>:<span className="pill pill-ok">ок</span>}</td></tr>)}</tbody></table>}
  <p className="muted small pad">Антивирус, обновления ОС, открытые порты и локальные администраторы — в эталоне вместе с мониторингом (C55).</p>
 </section>;
}

// «настроить эталон»: роль, критичность, ОС и ПО с версиями.
function BaselineDialog({d,csrf,onClose,onSaved,onExpired}:{d:RSMComponentCard;csrf:string;onClose:()=>void;onSaved:()=>void;onExpired:()=>void}){
 const b=d.component.baseline as {os?:string;software?:Record<string,string>};
 const [role,setRole]=useState(d.component.role??''),[critical,setCritical]=useState(d.component.critical),[os,setOs]=useState(b.os??'');
 const [sw,setSw]=useState<[string,string][]>(Object.entries(b.software??{}).length?Object.entries(b.software??{}):[['','']]);
 const [busy,setBusy]=useState(false),[error,setError]=useState<unknown>(null);
 async function save(e:React.FormEvent){e.preventDefault();setBusy(true);setError(null);const baseline:Record<string,unknown>={...(d.component.baseline as Record<string,unknown>)};if(os.trim())baseline.os=os.trim();else delete baseline.os;const software=Object.fromEntries(sw.filter(([n])=>n.trim()).map(([n,v])=>[n.trim(),v.trim()]));if(Object.keys(software).length)baseline.software=software;else delete baseline.software;
  try{await api.rsmPatchComponent(d.component.component_id,csrf,{revision:d.component.revision,role,critical,baseline});onSaved()}catch(x){setError(x);if(x instanceof ApiError&&x.status===401)onExpired()}finally{setBusy(false)}}
 return <div className="modal-shade" role="presentation" onClick={onClose}><form className="modal" role="dialog" aria-label="Эталон компонента" onClick={e=>e.stopPropagation()} onSubmit={e=>void save(e)}>
  <h2>Эталон компонента</h2><Err e={error}/>
  <label>Роль<input value={role} onChange={e=>setRole(e.target.value)} placeholder="например, кластер серверов 1С" maxLength={256}/></label>
  <label className="check-row"><input type="checkbox" checked={critical} onChange={e=>setCritical(e.target.checked)}/> критичный компонент (красный компонент красит среду)</label>
  <label>ОС (подстрока)<input value={os} onChange={e=>setOs(e.target.value)} placeholder="например, Windows Server 2022"/></label>
  <fieldset><legend>ПО и версии (версия — начало строки версии; пусто — достаточно наличия)</legend>{sw.map(([n,v],i)=><div key={i} className="row2"><input aria-label={'ПО '+(i+1)} value={n} onChange={e=>setSw(sw.map((x,j)=>j===i?[e.target.value,x[1]]:x))} placeholder="1С:Предприятие"/><input aria-label={'Версия '+(i+1)} value={v} onChange={e=>setSw(sw.map((x,j)=>j===i?[x[0],e.target.value]:x))} placeholder="8.3.24"/></div>)}<button type="button" className="link" onClick={()=>setSw([...sw,['','']])}>+ ещё ПО</button></fieldset>
  <div className="modal-actions"><button type="button" className="button" onClick={onClose}>Отмена</button><button className="button primary-sm" disabled={busy}>Сохранить</button></div>
 </form></div>;
}
