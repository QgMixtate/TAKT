import {useEffect,useState,type ReactNode} from 'react';
import {SystemsScreen,ComponentsScreen} from './systems';
import {SystemCardPage,ComponentCardPage} from './cards';
import {api,ApiError,errorMessage,type AssetRSM,type RSMColor,type RSMComponentDetail,type RSMEnvKind,type RSMImportResult,type RSMNodeState,type RSMOverview,type RSMProposal,type RSMReason,type RSMSystemDetail,type RSMUnassignedPage} from './api';

// C54.04 — РСМ в Web: системы со светофором (сначала проблемные), карточки системы и компонента, предложения правил,
// хосты вне систем, импорт CSV; блок «Входит в системы» в карточке актива. Цвет считает центр раз в 5 минут.

const colorNames:Record<RSMColor,string>={red:'Авария',yellow:'Внимание',green:'Норма',grey:'Нет данных'};
const envNames:Record<RSMEnvKind,string>={prod:'Прод',dr:'DR',stage:'Предпрод',test:'Тест',dev:'Разработка',other:'Другая'};
const critNames:Record<string,string>={unknown:'не задана',low:'низкая',medium:'средняя',high:'высокая',critical:'критичная'};
const ruleKinds:Record<string,string>={hostname_glob:'Маска имени',subnet:'Подсеть',software:'Установлено ПО',asset_class:'Класс актива'};
const originNames:Record<string,string>={manual:'вручную',import:'импорт',rule:'правило'};
const reasonNames:Record<string,string>={HOST_MISSING:'пропал из подсети',NO_INVENTORY:'нет инвентаризации',INVENTORY_LOST:'инвентаризация старше 7 сут',INVENTORY_STALE:'инвентаризация старше суток',RECONCILIATION_CONFLICT:'конфликт сопоставления',BASELINE_OS:'ОС не по эталону',BASELINE_SOFTWARE_MISSING:'нет ПО из эталона',BASELINE_SOFTWARE_VERSION:'версия ПО не по эталону',NO_HOSTS:'нет хостов',NO_DATA:'нет данных по хостам',HOSTS_RED:'красные хосты',HOSTS_YELLOW:'жёлтые хосты',HOSTS_NO_DATA:'хосты без данных',CRITICAL_COMPONENT_RED:'критичный компонент красный',COMPONENT_RED:'компонент красный',COMPONENT_YELLOW:'компонент жёлтый',NO_COMPONENTS:'нет компонентов',ENVIRONMENT_RED:'среда красная',NONPROD_ENVIRONMENT_RED:'непрод-среда красная',ENVIRONMENT_YELLOW:'среда жёлтая',NO_ENVIRONMENTS:'нет сред',CRITICAL_SYSTEM_RED:'важная система красная',SYSTEM_RED:'система красная',SYSTEM_YELLOW:'система жёлтая',UNASSIGNED_HOSTS:'хосты вне систем',MORE:'и ещё'};
const time=(v:string|null)=>v?new Date(v).toLocaleString('ru-RU',{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'}):'—';
const reasonText=(r:RSMReason)=>(reasonNames[r.code]??r.code)+(r.name?' «'+r.name+'»':'')+(r.detail?': '+r.detail:r.count?': '+r.count:'');

export function Dot({color,label}:{color:RSMColor;label?:boolean}){return <span className={'rsm-dot rsm-'+color} title={colorNames[color]}>{label?colorNames[color]:''}</span>}
function Counts({s}:{s:RSMNodeState|null}){if(!s)return <span className="muted">не рассчитано</span>;return <span className="rsm-counts">{s.hosts} хост.{s.red?<b className="rsm-t-red"> {s.red}</b>:null}{s.yellow?<b className="rsm-t-yellow"> {s.yellow}</b>:null}{s.grey?<b className="rsm-t-grey"> {s.grey}</b>:null}</span>}
function Reasons({list,max=3}:{list:RSMReason[];max?:number}){if(!list.length)return null;return <small className="rsm-reasons">{list.slice(0,max).map(reasonText).join(' · ')}{list.length>max?' · ещё '+(list.length-max):''}</small>}

function useLoad<T>(load:()=>Promise<T>,deps:unknown[],onExpired:()=>void):[T|null,unknown,()=>void]{
 const [data,setData]=useState<T|null>(null),[error,setError]=useState<unknown>(null),[n,setN]=useState(0);
 useEffect(()=>{let live=true;setError(null);load().then(d=>{if(live)setData(d)}).catch(e=>{if(live){setError(e);if(e instanceof ApiError&&e.status===401)onExpired()}});return()=>{live=false}},[...deps,n]);
 return [data,error,()=>setN(x=>x+1)];
}
function useAct(onExpired:()=>void):[boolean,unknown,(fn:()=>Promise<unknown>,after?:()=>void)=>Promise<void>]{
 const [busy,setBusy]=useState(false),[error,setError]=useState<unknown>(null);
 return [busy,error,async(fn,after)=>{setBusy(true);setError(null);try{await fn();after?.()}catch(e){setError(e);if(e instanceof ApiError&&e.status===401)onExpired()}finally{setBusy(false)}}];
}
const Err=({e}:{e:unknown})=>e?<div className="error" role="alert">{errorMessage(e)}</div>:null;

export type Mode={kind:'components'}|{kind:'list'}|{kind:'system';uid:string}|{kind:'component';id:string;from?:string}|{kind:'proposals'}|{kind:'unassigned'}|{kind:'import'};
export function RSMView({start='list',open,csrf,canWrite,onOpenAsset,onNavigate,onCrumbs,onExpired}:{start?:'list'|'components';open?:Mode;csrf:string;canWrite:boolean;onOpenAsset:(uid:string)=>void;onNavigate:(view:string)=>void;onCrumbs:(c:string[])=>void;onExpired:()=>void}){
 const home:Mode=start==='components'?{kind:'components'}:{kind:'list'};
 const [mode,setMode0]=useState<Mode>(open??home),[v,setV]=useState(0),[note,setNote]=useState(''),[dirName,setDirName]=useState('');
 const setMode=(m:Mode)=>{if(m.kind==='list'||m.kind==='components')onCrumbs([]);else if(m.kind==='proposals')onCrumbs(['Предложения правил']);else if(m.kind==='unassigned')onCrumbs(['Хосты вне систем']);else if(m.kind==='import')onCrumbs(['Импорт привязок']);setMode0(m)};
 const [overview,error]=useLoad<RSMOverview>(()=>api.rsmOverview(),[v],onExpired);
 useEffect(()=>{if(!note)return;const t=setTimeout(()=>setNote(''),6000);return()=>clearTimeout(t)},[note]);
 const [busy,actError,act]=useAct(onExpired);
 const back=<button className="link back" onClick={()=>{setMode(home);setV(x=>x+1)}}>← {start==='components'?'Все компоненты':'Все системы'}</button>;
 const actions=canWrite?<details className="actions-menu"><summary>Действия</summary><div className="popover right">
  <button className="menu-item" disabled={busy} onClick={()=>void act(async()=>{const r=await api.rsmRecompute(csrf);setNote(r.skipped?'Пересчёт уже идёт в другом процессе':'Пересчитано: хостов '+r.hosts+', узлов '+r.nodes)},()=>setV(x=>x+1))}>Пересчитать состояние сейчас</button>
  <button className="menu-item" disabled={busy} onClick={()=>void act(async()=>{const r=await api.rsmApplyRules(csrf);setNote('Правила: хостов '+r.assets+', привязано '+r.bound+', предложено '+r.proposed+(r.conflicts?', конфликтов '+r.conflicts:''))},()=>setV(x=>x+1))}>Применить правила ко всем хостам</button>
  <button className="menu-item" onClick={()=>onNavigate('services')}>Новая система, связи систем…</button>
  <button className="menu-item" onClick={()=>setMode({kind:'import'})}>Импорт привязок CSV…</button>
  <button className="menu-item" onClick={()=>onNavigate('software')}>Поиск ПО по реестру</button>
  <form className="menu-form" onSubmit={e=>{e.preventDefault();if(!dirName.trim())return;void act(()=>api.rsmCreateDirection(csrf,dirName.trim()),()=>{setDirName('');setV(x=>x+1);setNote('Направление добавлено')})}}><label>Новое направление<input value={dirName} onChange={e=>setDirName(e.target.value)} placeholder="например, Финансы"/></label><button className="button small" disabled={busy||!dirName.trim()}>Добавить</button></form>
 </div></details>:null;
 return <section className="rsm">
  <Err e={error}/><Err e={actError}/>{note?<p className="rsm-note" role="status">{note} <button className="link" onClick={()=>setNote('')}>скрыть</button></p>:null}
  {mode.kind==='components'?<ComponentsScreen onOpen={id=>setMode({kind:'component',id})} onExpired={onExpired}/>:null}
  {mode.kind==='list'?<SystemsScreen overview={overview} actions={actions} onOpenSystem={uid=>setMode({kind:'system',uid})} onOpenComponent={id=>setMode({kind:'component',id})} onOpenAsset={onOpenAsset} onUnassigned={()=>setMode({kind:'unassigned'})} onProposals={()=>setMode({kind:'proposals'})} onExpired={onExpired}/>:null}
  {mode.kind==='system'?<SystemCardPage uid={mode.uid} csrf={csrf} canWrite={canWrite} directions={overview?.directions??[]} onBack={()=>{setMode(home);setV(x=>x+1)}} onComponent={(id,from)=>setMode({kind:'component',id,from})} onOpenAsset={onOpenAsset} onOpenSystem={uid=>setMode({kind:'system',uid})} onExpired={onExpired} onChanged={()=>setV(x=>x+1)} onCrumbs={onCrumbs}/>:null}
  {mode.kind==='component'?<ComponentCardPage key={mode.id} id={mode.id} csrf={csrf} canWrite={canWrite} backLabel={mode.from?'Карточка системы':start==='components'?'Все компоненты':'Все системы'} onBack={()=>mode.from?setMode({kind:'system',uid:mode.from}):setMode(home)} onCrumbs={onCrumbs} onOpenSystem={uid=>setMode({kind:'system',uid})} onOpenAsset={onOpenAsset} onExpired={onExpired}/>:null}
  {mode.kind==='proposals'?<>{back}<Proposals csrf={csrf} canWrite={canWrite} onOpenAsset={onOpenAsset} onExpired={onExpired} onChange={()=>setV(x=>x+1)}/></>:null}
  {mode.kind==='unassigned'?<>{back}<Unassigned onOpenAsset={onOpenAsset} onExpired={onExpired}/></>:null}
  {mode.kind==='import'?<>{back}<Import csrf={csrf} canWrite={canWrite} onExpired={onExpired}/></>:null}
 </section>;
}

export function SystemCard({uid,csrf,canWrite,directions,onBack,onComponent,onExpired,onDirection,embedded=false}:{uid:string;csrf:string;canWrite:boolean;directions:RSMOverview['directions'];onBack:()=>void;onComponent:(id:string)=>void;onExpired:()=>void;onDirection:()=>void;embedded?:boolean}){
 const [d,error,reload]=useLoad<RSMSystemDetail>(()=>api.rsmSystem(uid),[uid],onExpired);
 const [busy,actError,act]=useAct(onExpired);
 const [owner,setOwner]=useState<string|null>(null),[window_,setWindow]=useState<string|null>(null);
 const [envKind,setEnvKind]=useState<RSMEnvKind>('prod'),[envName,setEnvName]=useState('');
 const [comp,setComp]=useState<{env:string;name:string;critical:boolean;baseline:string}|null>(null);
 if(error)return <Err e={error}/>;
 if(!d)return <div className="empty" role="status">Загрузка…</div>;
 const sys=d.system;
 const patch=(body:{direction_uid?:string;business_owner?:string;maintenance_window?:string})=>void act(()=>api.rsmPatchSystem(uid,csrf,{revision:sys.revision,...body}),()=>{reload();onDirection();setOwner(null);setWindow(null)});
 let baselineError='';let baseline:Record<string,unknown>|undefined;
 if(comp?.baseline.trim()){try{const v=JSON.parse(comp.baseline);if(typeof v!=='object'||Array.isArray(v)||v===null)baselineError='эталон — JSON-объект';else baseline=v}catch{baselineError='эталон — неверный JSON'}}
 return <div className="table-panel rsm-card">
  {embedded?null:<div className="table-toolbar"><button className="text-link" onClick={onBack}>← Все системы</button><h2>{sys.name}</h2>{d.state?<Dot color={d.state.color} label/>:null}</div>}
  <Err e={actError}/>
  <div className="rsm-fields">
   <div><span className="muted">Важность</span><strong>{critNames[sys.criticality]}</strong><small>меняется в разделе «Сервисы»</small></div>
   <div><span className="muted">Направление</span>{canWrite?<select aria-label="Направление" disabled={busy} value={sys.direction_uid??''} onChange={e=>patch({direction_uid:e.target.value})}><option value="">не задано</option>{directions.map(x=><option key={x.direction_uid} value={x.direction_uid}>{x.name}</option>)}</select>:<strong>{directions.find(x=>x.direction_uid===sys.direction_uid)?.name??'не задано'}</strong>}</div>
   <div><span className="muted">Владелец от бизнеса</span>{owner===null?<><strong>{sys.business_owner??'не задан'}</strong>{canWrite?<button className="text-link" onClick={()=>setOwner(sys.business_owner??'')}>Изменить</button>:null}</>:<form onSubmit={e=>{e.preventDefault();patch({business_owner:owner})}}><input aria-label="Владелец" value={owner} onChange={e=>setOwner(e.target.value)} placeholder="например, Финансовый департамент"/><button className="button small" disabled={busy}>Сохранить</button></form>}</div>
   <div><span className="muted">Окно обслуживания</span>{window_===null?<><strong>{sys.maintenance_window??'не задано'}</strong>{canWrite?<button className="text-link" onClick={()=>setWindow(sys.maintenance_window??'')}>Изменить</button>:null}</>:<form onSubmit={e=>{e.preventDefault();patch({maintenance_window:window_})}}><input aria-label="Окно обслуживания" value={window_} onChange={e=>setWindow(e.target.value)} placeholder="например, вс 02:00–06:00"/><button className="button small" disabled={busy}>Сохранить</button></form>}</div>
  </div>
  {d.state?<p className="panel-note"><Counts s={d.state}/> <Reasons list={d.state.reasons} max={6}/></p>:<p className="panel-note">Состояние появится после пересчёта.</p>}
  {d.environments.length===0?<div className="empty"><span>◇</span><h3>Сред нет</h3><p>Добавьте среду (прод, тест…), затем компоненты — роли хостов в системе.</p></div>:null}
  {d.environments.map(env=><div key={env.environment_id} className="rsm-env">
   <h3>{env.state?<Dot color={env.state.color}/>:null}{env.name} <small className="muted">{envNames[env.kind]}</small> <Counts s={env.state}/></h3>
   {env.state?.reasons.length?<Reasons list={env.state.reasons}/>:null}
   <table><tbody>{env.components.map(c=><tr key={c.component_id}><td>{c.state?<Dot color={c.state.color}/>:<Dot color="grey"/>}</td><td><button className="asset-link" onClick={()=>onComponent(c.component_id)}><strong>{c.name}</strong></button>{c.critical?<span className="badge state-unavailable"><i/>критичный</span>:null}{Object.keys(c.baseline).length?<small className="muted"> · есть эталон</small>:null}</td><td><Counts s={c.state}/></td><td>{c.state?<Reasons list={c.state.reasons}/>:null}</td></tr>)}</tbody></table>
   {canWrite?(comp?.env===env.environment_id?<form className="rsm-inline" onSubmit={e=>{e.preventDefault();if(baselineError)return;void act(()=>api.rsmCreateComponent(env.environment_id,csrf,{name:comp.name.trim(),critical:comp.critical,baseline}),()=>{setComp(null);reload()})}}>
     <label>Компонент<input value={comp.name} onChange={e=>setComp({...comp,name:e.target.value})} placeholder="например, Сервер приложений 1С" autoFocus/></label>
     <label className="rsm-check"><input type="checkbox" checked={comp.critical} onChange={e=>setComp({...comp,critical:e.target.checked})}/> критичный</label>
     <label>Эталон (необязательно, JSON)<textarea className="mono" rows={3} value={comp.baseline} onChange={e=>setComp({...comp,baseline:e.target.value})} placeholder={'{"os":"Windows Server 2022","software":{"1С:Предприятие":"8.3.24"}}'}/></label>
     {baselineError?<small className="error-text">{baselineError}</small>:null}
     <span><button className="button small" disabled={busy||!comp.name.trim()||!!baselineError}>Добавить</button> <button type="button" className="text-link" onClick={()=>setComp(null)}>Отмена</button></span></form>
    :<button className="text-link" onClick={()=>setComp({env:env.environment_id,name:'',critical:false,baseline:''})}>+ Компонент</button>):null}
  </div>)}
  {canWrite?<form className="rsm-inline" onSubmit={e=>{e.preventDefault();if(!envName.trim())return;void act(()=>api.rsmCreateEnvironment(uid,csrf,{kind:envKind,name:envName.trim()}),()=>{setEnvName('');reload()})}}>
   <label>Новая среда<select value={envKind} onChange={e=>setEnvKind(e.target.value as RSMEnvKind)}>{Object.entries(envNames).map(([k,v])=><option key={k} value={k}>{v}</option>)}</select></label>
   <label>Название<input value={envName} onChange={e=>setEnvName(e.target.value)} placeholder="например, Прод"/></label><button className="button small" disabled={busy||!envName.trim()}>Добавить среду</button></form>:null}
 </div>;
}

export function ComponentCard({id,csrf,canWrite,onBack,onOpenAsset,onExpired,embedded=false}:{id:string;csrf:string;canWrite:boolean;onBack:()=>void;onOpenAsset:(uid:string)=>void;onExpired:()=>void;embedded?:boolean}){
 const [offset,setOffset]=useState(0);
 const [d,error,reload]=useLoad<RSMComponentDetail>(()=>api.rsmComponent(id,offset),[id,offset],onExpired);
 const [busy,actError,act]=useAct(onExpired);
 const [rule,setRule]=useState({kind:'hostname_glob',pattern:'',mode:'propose'}),[bulk,setBulk]=useState(''),[note,setNote]=useState('');
 if(error)return <Err e={error}/>;
 if(!d)return <div className="empty" role="status">Загрузка…</div>;
 const uids=bulk.split(/[\s,;]+/).map(x=>x.trim().toLowerCase()).filter(Boolean);
 const badUID=uids.find(u=>!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(u));
 const baseline=Object.keys(d.component.baseline).length?JSON.stringify(d.component.baseline):'';
 return <div className="table-panel rsm-card">
  {embedded?null:<div className="table-toolbar"><button className="text-link" onClick={onBack}>← {d.system_name}</button><h2>{d.component.name}</h2>{d.state?<Dot color={d.state.color} label/>:null}<small className="muted">{d.system_name} / {d.environment.name}{d.component.critical?' · критичный':''}</small></div>}
  <Err e={actError}/>{note?<p className="panel-note" role="status">{note}</p>:null}
  {baseline?<p className="panel-note">Эталон: <span className="mono">{baseline}</span></p>:null}
  {d.state?<p className="panel-note"><Counts s={d.state}/> <Reasons list={d.state.reasons} max={6}/></p>:null}
  {embedded?null:<><h3>Хосты</h3>
  {d.hosts.length===0?<div className="empty"><span>◌</span><h3>Хостов нет</h3><p>Привяжите хосты списком ниже или правилом — новые хосты под правилом попадут в предложения.</p></div>:
  <div className="table-scroll"><table><thead><tr><th/><th>Хост</th><th>Почему</th><th>Инвентаризация</th><th>Привязка</th>{canWrite?<th/>:null}</tr></thead><tbody>{d.hosts.map(h=><tr key={h.asset_uid}>
   <td><Dot color={h.color}/></td><td><button className="asset-link" onClick={()=>onOpenAsset(h.asset_uid)}><span><strong>{h.name||h.asset_uid.slice(0,8)}</strong><small className="mono">{h.asset_uid}</small></span></button></td>
   <td><Reasons list={h.reasons} max={4}/></td><td>{time(h.last_inventory_at)}</td><td>{h.is_primary?'основная':'дополнительная (общий хост)'}<small> · {originNames[h.origin]??h.origin}</small></td>
   {canWrite?<td className="actions">{!h.is_primary&&h.binding_id?<button className="text-link" disabled={busy} onClick={()=>void act(()=>api.rsmPrimary(h.binding_id,csrf),reload)}>Сделать основной</button>:null}{h.binding_id?<button className="text-link" disabled={busy} onClick={()=>{if(window.confirm('Отвязать хост от компонента? Изменение попадёт в историю.'))void act(()=>api.rsmUnbind(h.binding_id,csrf),reload)}}>Отвязать</button>:null}</td>:null}</tr>)}</tbody></table></div>}
  <div className="pager"><small>Сначала проблемные</small><div><button className="button small" disabled={offset===0} onClick={()=>setOffset(Math.max(0,offset-100))}>← Назад</button><button className="button small" disabled={d.next_offset==null} onClick={()=>setOffset(d.next_offset!)}>Далее →</button></div></div></>}
  <h3>Правила автопривязки</h3>
  {d.rules.length===0?<p className="muted">Правил нет.</p>:<table><tbody>{d.rules.map(r=><tr key={r.rule_id}><td>{ruleKinds[r.kind]??r.kind}</td><td className="mono">{r.pattern}</td><td>{r.mode==='auto'?'привязывать сразу':'предлагать оператору'}</td>{canWrite?<td className="actions"><button className="text-link" disabled={busy} onClick={()=>void act(()=>api.rsmRetireRule(r.rule_id,csrf),reload)}>Снять</button></td>:null}</tr>)}</tbody></table>}
  {canWrite?<form className="rsm-inline" onSubmit={e=>{e.preventDefault();void act(()=>api.rsmCreateRule(id,csrf,rule),()=>{setRule({...rule,pattern:''});setNote('Правило добавлено: новые хосты проверяются при приёме данных; для уже известных — «Применить правила ко всем хостам».');reload()})}}>
   <label>Правило<select value={rule.kind} onChange={e=>setRule({...rule,kind:e.target.value})}>{Object.entries(ruleKinds).map(([k,v])=><option key={k} value={k}>{v}</option>)}</select></label>
   <label>Образец<input value={rule.pattern} onChange={e=>setRule({...rule,pattern:e.target.value})} placeholder={rule.kind==='subnet'?'10.20.0.0/24':rule.kind==='software'?'1С:Предприятие':rule.kind==='asset_class'?'server':'msk1-app-*'}/></label>
   <label>Режим<select value={rule.mode} onChange={e=>setRule({...rule,mode:e.target.value})}><option value="propose">предлагать оператору</option><option value="auto">привязывать сразу</option></select></label>
   <button className="button small" disabled={busy||!rule.pattern.trim()}>Добавить правило</button></form>:null}
  {canWrite?<form className="rsm-inline" onSubmit={e=>{e.preventDefault();if(badUID||!uids.length)return;void act(async()=>{const r=await api.rsmBind(id,csrf,uids);setNote('Привязано: '+r.bound+(r.existing?', уже были: '+r.existing:'')+(r.missing?', не найдено: '+r.missing:''));setBulk('')},reload)}}>
   <label>Привязать хосты списком (UID активов, по одному в строке; до 10 000)<textarea className="mono" rows={3} value={bulk} onChange={e=>setBulk(e.target.value)}/></label>
   {badUID?<small className="error-text">не UID актива: {badUID}</small>:null}
   <button className="button small" disabled={busy||!uids.length||!!badUID}>Привязать {uids.length||''}</button></form>:null}
 </div>;
}

function Proposals({csrf,canWrite,onOpenAsset,onExpired,onChange}:{csrf:string;canWrite:boolean;onOpenAsset:(uid:string)=>void;onExpired:()=>void;onChange:()=>void}){
 const [data,error,reload]=useLoad<{items:RSMProposal[]}>(()=>api.rsmProposals(),[],onExpired);
 const [busy,actError,act]=useAct(onExpired);
 const done=()=>{reload();onChange()};
 return <div className="table-panel"><div className="table-toolbar"><h2>Предложения правил <span>{data?.items.length??''}</span></h2></div>
  <Err e={error}/><Err e={actError}/>
  {data&&data.items.length===0?<div className="empty"><span>✓</span><h3>Разбирать нечего</h3><p>Хосты, попавшие под правила с режимом «предлагать», и конфликты правил появятся здесь.</p></div>:null}
  {data?.items.length?<div className="table-scroll"><table><thead><tr><th>Хост</th><th>Куда</th><th>С</th>{canWrite?<th/>:null}</tr></thead><tbody>{data.items.map(p=><tr key={p.binding.binding_id}>
   <td><button className="asset-link" onClick={()=>onOpenAsset(p.binding.asset_uid)}><span><strong>{p.asset_name||p.binding.asset_uid.slice(0,8)}</strong><small className="mono">{p.binding.asset_uid}</small></span></button></td>
   <td>{p.system_name} / {p.environment_name} / <strong>{p.component_name}</strong></td><td>{time(p.binding.valid_from)}</td>
   {canWrite?<td className="actions"><button className="button small" disabled={busy} onClick={()=>void act(()=>api.rsmConfirm(p.binding.binding_id,csrf),done)}>Подтвердить</button><button className="text-link" disabled={busy} onClick={()=>void act(()=>api.rsmReject(p.binding.binding_id,csrf),done)}>Отклонить</button></td>:null}</tr>)}</tbody></table></div>:null}
  <p className="panel-note">Отклонённую пару правила больше не предлагают. Если хост подошёл под правила «привязывать сразу» двух компонентов, он тоже попадает сюда — молча ничего не привязывается.</p></div>;
}

function Unassigned({onOpenAsset,onExpired}:{onOpenAsset:(uid:string)=>void;onExpired:()=>void}){
 const [stack,setStack]=useState<(string|null)[]>([null]);
 const [page,error]=useLoad<RSMUnassignedPage>(()=>api.rsmUnassigned(stack.at(-1)??null),[stack],onExpired);
 return <div className="table-panel"><div className="table-toolbar"><h2>Хосты вне систем <span>{page?.total??''}</span></h2></div>
  <Err e={error}/>
  {page&&page.items.length===0?<div className="empty"><span>✓</span><h3>Все хосты в системах</h3></div>:null}
  {page?.items.length?<div className="table-scroll"><table><thead><tr><th>Хост</th></tr></thead><tbody>{page.items.map(x=><tr key={x.asset_uid}><td><button className="asset-link" onClick={()=>onOpenAsset(x.asset_uid)}><span><strong>{x.name||x.asset_uid.slice(0,8)}</strong><small className="mono">{x.asset_uid}</small></span></button></td></tr>)}</tbody></table></div>:null}
  <div className="pager"><small>Привяжите хосты в карточке компонента, правилом или импортом</small><div><button className="button small" disabled={stack.length===1} onClick={()=>setStack(stack.slice(0,-1))}>← Назад</button><button className="button small" disabled={!page?.next_cursor} onClick={()=>setStack([...stack,page!.next_cursor])}>Далее →</button></div></div></div>;
}

const importStatus:Record<string,string>={bound:'привязан',existing:'уже был',will_bind:'будет привязан',system_not_found:'нет такой системы',host_not_found:'хост не найден',host_ambiguous:'имя у нескольких хостов',invalid:'ошибка в строке'};
function Import({csrf,canWrite,onExpired}:{csrf:string;canWrite:boolean;onExpired:()=>void}){
 const [text,setText]=useState(''),[result,setResult]=useState<RSMImportResult|null>(null);
 const [busy,error,act]=useAct(onExpired);
 const sample='surveyscan-rsm-bindings;1\nsystem;environment;component;host\n1С:ERP;Прод;Сервер приложений;msk1-app-*\n1С:ERP;Прод;СУБД;10.20.0.15';
 const run=(dry:boolean)=>void act(async()=>setResult(await api.rsmImport(csrf,text,dry)));
 return <div className="table-panel"><div className="table-toolbar"><h2>Импорт привязок CSV</h2></div>
  <p className="panel-note">Формат: первая строка <span className="mono">surveyscan-rsm-bindings;1</span>, затем заголовок <span className="mono">system;environment;component;host</span>. Хост — UID, IP, имя или маска имени (<span className="mono">*</span>, <span className="mono">?</span>). Система должна существовать; среда и компонент создаются. Excel — «Сохранить как CSV (разделитель — точка с запятой)». Сначала проверка — она ничего не меняет.</p>
  <Err e={error}/>
  <label className="rsm-file">Файл<input type="file" accept=".csv,text/csv" onChange={e=>{const f=e.target.files?.[0];if(f)void f.text().then(t=>{setText(t);setResult(null)})}}/></label>
  <textarea className="mono" rows={6} value={text} onChange={e=>{setText(e.target.value);setResult(null)}} placeholder={sample} aria-label="Содержимое CSV"/>
  {canWrite?<div className="rsm-actions"><button className="button small" disabled={busy||!text.trim()} onClick={()=>run(true)}>Проверить</button><button className="button small secondary" disabled={busy||!result?.dry_run} onClick={()=>{if(window.confirm('Применить импорт? Изменения попадут в историю и аудит.'))run(false)}}>Применить</button></div>:<p className="muted">Импорт доступен оператору и администратору.</p>}
  {result?<><p className="panel-note">{result.dry_run?'Проверка (ничего не изменено): ':'Применено: '}{Object.entries(result.counts).map(([k,v])=>(importStatus[k]??k)+' — '+v).join(' · ')}</p>
   <div className="table-scroll"><table><thead><tr><th>Строка</th><th>Система / среда / компонент</th><th>Хост</th><th>Итог</th></tr></thead><tbody>{result.rows.map(r=><tr key={r.line} className={['system_not_found','host_not_found','host_ambiguous','invalid'].includes(r.status)?'rsm-row-bad':''}>
    <td>{r.line}</td><td>{r.system} / {r.environment} / {r.component}{r.creates.length?<small className="muted"> · создаст: {r.creates.map(c=>c==='environment'?'среду':'компонент').join(', ')}</small>:null}</td><td className="mono">{r.host}{r.asset_uids.length>1?<small> · хостов: {r.asset_uids.length}</small>:null}</td><td>{importStatus[r.status]??r.status}{r.detail?<small> · {r.detail}</small>:null}</td></tr>)}</tbody></table></div></>:null}
 </div>;
}

// Блок карточки актива: состояние хоста и системы, в которые он входит.
export function AssetRSMBlock({asset,onExpired}:{asset:string;onExpired:()=>void}):ReactNode{
 const [data,error]=useLoad<AssetRSM>(()=>api.assetRSM(asset),[asset],onExpired);
 if(error)return <Err e={error}/>;
 if(!data)return null;
 return <div className="rsm-asset"><h3>Входит в системы</h3>
  {data.state?<p><Dot color={data.state.color} label/> <Reasons list={data.state.reasons} max={6}/></p>:null}
  {data.bindings.length===0?<p className="muted">Хост не привязан ни к одной системе — он в очереди «Вне систем».</p>:
  <ul>{data.bindings.map(b=><li key={b.binding.binding_id}><strong>{b.system_name}</strong> / {b.environment_name} / {b.component_name}{b.binding.status==='proposed'?<span className="badge state-pending"><i/>предложено правилом</span>:b.binding.is_primary?<small className="muted"> · основная</small>:<small className="muted"> · общий хост</small>}</li>)}</ul>}
 </div>;
}
