import {useEffect,useState} from 'react';
import {DirectorySyncPanel} from './integrations';
import {Panel,Pill,Split,StateDot} from './ui';
import {api,ApiError,errorMessage,type AssetAssignments,type OrgOverview,type RoleName,type Subject,type WorklistItem,type WorklistPage,type Ticket} from './api';

// C27 — ответственность в Web: роли актива и история передач, рабочие списки и массовое назначение, оргструктура.
export const roleNames:Record<RoleName,string>={accountable:'Ответственный',business_owner:'Бизнес-владелец',technical:'Технический ответственный',custodian:'Пользователь (хранитель)'};
const reasonNames:Record<string,string>={SITE_FALLBACK:'резервная команда площадки',MANUAL_ASSIGNMENT:'назначено оператором',SUBJECT_DEACTIVATED:'прежний ответственный выбыл',ASSET_MERGE:'при слиянии карточек'};
const scopes:[string,string][]=[['mine','На мне'],['team','На моих командах'],['unassigned','Не распределено'],['attention','Требует передачи']];
const time=(v:string)=>new Date(v).toLocaleString('ru-RU',{day:'2-digit',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit'});
const confirmAction=(what:string)=>window.confirm('Подтвердите: '+what+'. Изменение попадёт в историю и аудит.');
const expired=(e:unknown,onExpired:()=>void)=>{if(e instanceof ApiError&&e.status===401)onExpired()};

function useSubjects(onExpired:()=>void,inactive=false):[Subject[],()=>void]{
 const [items,setItems]=useState<Subject[]>([]),[n,setN]=useState(0);
 useEffect(()=>{let live=true;api.subjects('',inactive).then(p=>{if(live)setItems(p.items)}).catch(e=>expired(e,onExpired));return()=>{live=false}},[n,inactive]);
 return [items,()=>setN(x=>x+1)];
}
function SubjectSelect({subjects,role,value,onChange,label}:{subjects:Subject[];role:RoleName;value:string;onChange:(v:string)=>void;label:string}){
 return <select aria-label={label} value={value} onChange={e=>onChange(e.target.value)}><option value="">Выберите…</option>{subjects.filter(s=>s.active&&(role!=='custodian'||s.kind==='person')).map(s=><option key={s.subject_id} value={s.subject_id}>{s.kind==='team'?'Команда: ':''}{s.name}{s.site_fallback?' (резервная)':''}</option>)}</select>;
}

export function AssignmentsTab({asset,csrf,onExpired}:{asset:string;csrf:string;onExpired:()=>void}){
 const [data,setData]=useState<AssetAssignments|null>(null),[error,setError]=useState<unknown>(null),[n,setN]=useState(0);
 const [subjects]=useSubjects(onExpired);
 const [role,setRole]=useState<RoleName>('accountable'),[subject,setSubject]=useState(''),[note,setNote]=useState(''),[busy,setBusy]=useState(false);
 useEffect(()=>{let live=true;setError(null);api.assignments(asset).then(d=>{if(live)setData(d)}).catch(e=>{if(live){setError(e);expired(e,onExpired)}});return()=>{live=false}},[asset,n]);
 async function act(body:{role:RoleName;subject_id:string|null},what:string){if(!data||!confirmAction(what))return;setBusy(true);setError(null);try{setData(await api.assign(asset,csrf,{...body,note:note.trim()||undefined,expected_version:data.version}));setSubject('');setNote('')}catch(e){setError(e);expired(e,onExpired);setN(x=>x+1)}finally{setBusy(false)}}
 if(!data)return error?<div className="error" role="alert">{errorMessage(error)}</div>:<p role="status">Загружаем…</p>;
 const byRole=Object.fromEntries(data.active.map(a=>[a.role,a]));
 return <div className="tab-body">
  {error?<div className="error" role="alert">{errorMessage(error)}</div>:null}
  <dl className="roles">{(Object.keys(roleNames) as RoleName[]).map(r=><div key={r}><dt>{roleNames[r]}</dt><dd>{byRole[r]?<>{byRole[r].subject_kind==='team'?'Команда: ':''}{byRole[r].subject_name}<small>с {time(byRole[r].valid_from)} · {reasonNames[byRole[r].reason_code]??byRole[r].reason_code}</small>{r!=='accountable'?<button className="text-link" disabled={busy} onClick={()=>void act({role:r,subject_id:null},'снять роль «'+roleNames[r]+'»')}>Снять</button>:null}</>:<span className="muted">не назначен</span>}</dd></div>)}</dl>
  <div className="relation-form"><select aria-label="Роль" value={role} onChange={e=>{setRole(e.target.value as RoleName);setSubject('')}}>{(Object.keys(roleNames) as RoleName[]).map(r=><option key={r} value={r}>{roleNames[r]}</option>)}</select>
   <SubjectSelect subjects={subjects} role={role} value={subject} onChange={setSubject} label="Кому передать"/>
   <input aria-label="Основание" placeholder="Основание (необязательно)" value={note} maxLength={1024} onChange={e=>setNote(e.target.value)}/>
   <button className="button small" disabled={busy||!subject} onClick={()=>void act({role,subject_id:subject},'передать роль «'+roleNames[role]+'»')}>Передать</button></div>
  <h4>История передач</h4>
  <table className="mini-table"><thead><tr><th>Роль</th><th>Кому</th><th>Период</th><th>Основание</th></tr></thead><tbody>{data.history.map((h,i)=><tr key={i}><td>{roleNames[h.role]}</td><td>{h.subject_name}</td><td>{time(h.valid_from)} — {h.valid_to?time(h.valid_to):'сейчас'}</td><td>{reasonNames[h.reason_code]??h.reason_code}{h.note?<small>{h.note}</small>:null}<small className="mono">{h.actor_ref}</small></td></tr>)}</tbody></table>
 </div>;
}

export function WorklistView({csrf,canWrite,onOpenAsset,onNavigate,onExpired}:{csrf:string;canWrite:boolean;onOpenAsset:(uid:string)=>void;onNavigate?:(view:string)=>void;onExpired:()=>void}){
 // C53.07 (макет «Мои задачи»): показатели по спискам, обращения на мне и требующее передачи, затем список с массовым назначением.
 const [scope,setScope]=useState('mine'),[items,setItems]=useState<WorklistItem[]>([]),[next,setNext]=useState<string|null>(null),[error,setError]=useState<unknown>(null),[notice,setNotice]=useState(''),[loading,setLoading]=useState(false),[n,setN]=useState(0);
 const [selected,setSelected]=useState<string[]>([]),[role,setRole]=useState<RoleName>('accountable'),[subject,setSubject]=useState(''),[busy,setBusy]=useState(false);
 const [subjects]=useSubjects(onExpired);
 const [sum,setSum]=useState<Record<string,WorklistPage|null>>({}),[tickets,setTickets]=useState<Ticket[]|null>(null);
 useEffect(()=>{for(const [k] of scopes)api.worklist(k).then(p=>setSum(x=>({...x,[k]:p}))).catch(e=>{setSum(x=>({...x,[k]:null}));expired(e,onExpired)});api.tickets({mine:true}).then(p=>setTickets(p.items.filter(t=>t.state!=='closed'&&t.state!=='resolved'))).catch(e=>expired(e,onExpired))},[n]);
 async function load(cursor:string|null){setLoading(true);setError(null);try{const p=await api.worklist(scope,cursor);setItems(x=>cursor?[...x,...p.items]:p.items);setNext(p.next_cursor)}catch(e){setError(e);expired(e,onExpired)}finally{setLoading(false)}}
 useEffect(()=>{setSelected([]);void load(null)},[scope,n]);
 async function bulk(){
  const chosen=items.filter(i=>selected.includes(i.asset_uid));if(!chosen.length||!subject||!confirmAction('назначить роль «'+roleNames[role]+'» для '+chosen.length+' актив(ов)'))return;
  setBusy(true);setError(null);setNotice('');
  try{const r=await api.bulkAssign(csrf,{role,subject_id:subject,items:chosen.map(i=>({asset_uid:i.asset_uid,expected_version:i.version}))});setNotice('Назначено: '+r.applied+(r.unchanged?', уже было так: '+r.unchanged:'')+'.');setSubject('');setN(x=>x+1)}
  catch(e){if(e instanceof ApiError&&e.status===412){setNotice('Некоторые активы изменились, пока вы выбирали: ничего не изменено, список обновлён — повторите.');setN(x=>x+1)}else{setError(e);expired(e,onExpired)}}
  finally{setBusy(false)}
 }
 const accountable=(i:WorklistItem)=>i.assignments.find(a=>a.role==='accountable');
 const count=(k:string)=>sum[k]===undefined?'…':sum[k]===null?'—':sum[k]!.items.length+(sum[k]!.next_cursor?'+':'');
 const kpiNote:Record<string,string>={mine:'вы — ответственный',team:'на ваших командах',unassigned:'без ответственного',attention:'ответственный выбыл'};
 const name=(i:WorklistItem)=>i.display_name??i.observed_hostname??'Без имени';
 return <>
  <div className="kpi-cards">{scopes.map(([k,v])=><button key={k} className={(k==='attention'?'amber':'')+(scope===k?' active':'')} aria-pressed={scope===k} onClick={()=>setScope(k)}><small>{v}</small><b>{count(k)}</b><span>{kpiNote[k]}</span></button>)}
   <button className={tickets?.length?'warn':''} onClick={()=>onNavigate?.('tickets')}><small>Обращения на мне</small><b>{tickets?tickets.length:'…'}</b><span>открытые</span></button></div>
  <div className="two-col">
   <Panel title={'Обращения на мне · '+(tickets?.length??'…')} right={<button className="link" onClick={()=>onNavigate?.('tickets')}>все →</button>} flush>{tickets&&tickets.length?<ul className="task-list">{tickets.slice(0,5).map(t=><li key={t.ticket_id}><StateDot tone={t.priority<=2?'red':t.priority===3?'amber':'grey'}/><b>{t.number}</b><span className="muted">{t.title}</span><span className="right"><button className="link" onClick={()=>onNavigate?.('tickets')}>Открыть</button></span></li>)}</ul>:<p className="muted pad">{tickets?'Открытых обращений на вас нет.':'Загрузка…'}</p>}</Panel>
   <Panel title={'Требует передачи · '+count('attention')} right={<button className="link" onClick={()=>setScope('attention')}>все →</button>} flush>{sum.attention&&sum.attention.items.length?<ul className="task-list">{sum.attention.items.slice(0,5).map(i=><li key={i.asset_uid}><StateDot tone="amber"/><b>{name(i)}</b><span className="muted">{accountable(i)?.subject_name??'нет ответственного'}{reasonNames[accountable(i)?.reason_code??'']?' · '+reasonNames[accountable(i)!.reason_code]:''}</span><span className="right"><button className="link" onClick={()=>onOpenAsset(i.asset_uid)}>Карточка</button></span></li>)}</ul>:<p className="muted pad">{sum.attention===undefined?'Загрузка…':'Передавать нечего.'}</p>}</Panel>
  </div>
  <Panel title={(scopes.find(s=>s[0]===scope)?.[1]??'')+' · '+count(scope)} right={<div className="scope-tabs" role="tablist">{scopes.map(([k,v])=><button key={k} role="tab" aria-selected={scope===k} className={scope===k?'active':''} onClick={()=>setScope(k)}>{v}</button>)}</div>} flush>
  {error?<div className="error" role="alert">{errorMessage(error)}</div>:null}
  {notice?<div className="notice" role="status">{notice}</div>:null}
  {canWrite&&items.length?<div className="bulk-bar"><span>Выбрано: {selected.length}</span><select aria-label="Роль для назначения" value={role} onChange={e=>{setRole(e.target.value as RoleName);setSubject('')}}>{(Object.keys(roleNames) as RoleName[]).map(r=><option key={r} value={r}>{roleNames[r]}</option>)}</select><SubjectSelect subjects={subjects} role={role} value={subject} onChange={setSubject} label="Назначить на"/><button className="button small primary-lite" disabled={busy||!selected.length||!subject} onClick={()=>void bulk()}>Назначить выбранным</button></div>:null}
  {!items.length&&!loading?<div className="empty"><span>✓</span><h3>Список пуст</h3><p>{scope==='mine'?'На вас не назначено активов — или ваш вход ещё не связан с человеком в оргструктуре.':'Здесь пока ничего нет.'}</p></div>:null}
  {items.length?<div className="table-scroll"><table className="panel-table"><thead><tr>{canWrite?<th><input type="checkbox" aria-label="Выбрать все" checked={selected.length===items.length} onChange={e=>setSelected(e.target.checked?items.map(i=>i.asset_uid):[])}/></th>:null}<th>Актив</th><th>Ответственный</th><th>Другие роли</th></tr></thead><tbody>{items.map(i=><tr key={i.asset_uid}>{canWrite?<td><input type="checkbox" aria-label={'Выбрать '+(i.display_name??i.observed_hostname??i.asset_uid)} checked={selected.includes(i.asset_uid)} onChange={e=>setSelected(s=>e.target.checked?[...s,i.asset_uid]:s.filter(x=>x!==i.asset_uid))}/></td>:null}<td><button className="link plain" onClick={()=>onOpenAsset(i.asset_uid)}><b>{name(i)}</b></button></td><td>{accountable(i)?.subject_name??'—'}<small className="muted"> {reasonNames[accountable(i)?.reason_code??'']??''}</small></td><td>{i.assignments.filter(a=>a.role!=='accountable').map(a=>roleNames[a.role]+': '+a.subject_name).join('; ')||'—'}</td></tr>)}</tbody></table></div>:null}
  {next?<div className="pager"><button className="button small" disabled={loading} onClick={()=>void load(next)}>Показать ещё</button></div>:null}
  </Panel>
 </>;
}

export function OrgView({csrf,onExpired}:{csrf:string;onExpired:()=>void}){
 // C53.07 (макет «Оргструктура»): команды слева, состав и нагрузка в центре, карточка сотрудника справа.
 const [inactive,setInactive]=useState(false);
 const [subjects,reload]=useSubjects(onExpired,inactive);
 const [org,setOrg]=useState<OrgOverview|null>(null),[n,setN]=useState(0);
 useEffect(()=>{api.orgOverview().then(setOrg).catch(e=>expired(e,onExpired))},[n]);
 const refresh=()=>{reload();setN(x=>x+1)};
 const [group,setGroup]=useState<string>('all'),[sel,setSel]=useState<string|null>(null),[q,setQ]=useState('');
 const [kind,setKind]=useState<'person'|'team'>('person'),[name,setName]=useState(''),[contact,setContact]=useState(''),[username,setUsername]=useState(''),[busy,setBusy]=useState(false),[error,setError]=useState<unknown>(null),[notice,setNotice]=useState(''),[addTo,setAddTo]=useState('');
 async function act(fn:()=>Promise<unknown>,what:string,done?:(r:unknown)=>void){if(!confirmAction(what))return;setBusy(true);setError(null);setNotice('');try{const r=await fn();done?.(r);refresh()}catch(e){setError(e);expired(e,onExpired)}finally{setBusy(false)}}
 const teams=subjects.filter(s=>s.kind==='team'),people=subjects.filter(s=>s.kind==='person');
 const members=org?.members??{},inTeam=new Set(Object.values(members).flat());
 const team=teams.find(t=>t.subject_id===group);
 const list=(group==='all'?people:group==='teams'?teams:group==='none'?people.filter(p=>!inTeam.has(p.subject_id)):people.filter(p=>(members[group]??[]).includes(p.subject_id))).filter(s=>!q||s.name.toLowerCase().includes(q.toLowerCase())||(s.directory_login??s.username??'').toLowerCase().includes(q.toLowerCase()));
 const person=subjects.find(s=>s.subject_id===sel)??null;
 const teamsOf=(id:string)=>teams.filter(t=>(members[t.subject_id]??[]).includes(id));
 const cnt=(m:Record<string,number>|undefined,id:string)=>m?.[id]??0;
 const item=(key:string,label:string,count:number,indent=0)=><button key={key} className={'tree-item'+(group===key?' active':'')} style={{paddingLeft:8+indent*16}} onClick={()=>{setGroup(key);setSel(null)}}><span>{label}</span><span className="muted">{count}</span></button>;
 const side=person?<>
  <div><h2>{person.name}</h2><p className="sub">{person.kind==='team'?'Команда · '+person.members+' сотрудн.':'Сотрудник'}{person.origin==='ldap'?' · AD'+(person.directory_login?': '+person.directory_login:''):''}</p></div>
  <dl className="kv"><dt>Контакт</dt><dd>{person.contact||'—'}</dd><dt>Вход в ТАКТ</dt><dd className="mono">{person.username??'—'}</dd><dt>Отвечает за</dt><dd>{cnt(org?.assets,person.subject_id)} активов · {cnt(org?.systems,person.subject_id)} систем</dd>
   {person.kind==='person'?<><dt>Команды</dt><dd>{teamsOf(person.subject_id).map(t=>t.name).join(', ')||'не состоит'}</dd></>:null}
   <dt>Состояние</dt><dd>{person.active?(person.site_fallback?<Pill tone="blue">резервная команда площадки</Pill>:<Pill tone="green">действует</Pill>):<Pill>выбыл</Pill>}</dd></dl>
  {person.kind==='person'&&person.active?<Panel title="Состав команд"><div className="form-row"><select aria-label="Команда" value={addTo} onChange={e=>setAddTo(e.target.value)}><option value="">Команда…</option>{teams.filter(t=>t.active&&t.origin==='local').map(t=><option key={t.subject_id} value={t.subject_id}>{t.name}</option>)}</select>
   <button className="button small" disabled={busy||!addTo||(members[addTo]??[]).includes(person.subject_id)} onClick={()=>void act(()=>api.member(addTo,person.subject_id,csrf,true),'включить в команду')}>Включить</button><button className="button small" disabled={busy||!addTo||!(members[addTo]??[]).includes(person.subject_id)} onClick={()=>void act(()=>api.member(addTo,person.subject_id,csrf,false),'исключить из команды')}>Исключить</button></div></Panel>:null}
  {person.active&&!person.site_fallback&&person.origin==='local'?<Panel title="Выбытие"><p className="muted">Его активы ({cnt(org?.assets,person.subject_id)}) перейдут резервной команде площадки; история передач сохраняется.</p><button className="button primary-sm" disabled={busy} onClick={()=>void act(()=>api.patchSubject(person.subject_id,csrf,{revision:person.revision,deactivate:true}),'отметить «'+person.name+'» выбывшим: его активы перейдут резервной команде площадки',r=>setNotice('Переназначено ролей: '+(r as {reassigned_assignments:number}).reassigned_assignments+'.'))}>Отметить выбывшим</button></Panel>
   :!person.active&&person.origin==='local'?<button className="button" disabled={busy} onClick={()=>void act(()=>api.patchSubject(person.subject_id,csrf,{revision:person.revision,reactivate:true}),'вернуть «'+person.name+'» в работу (прежние назначения не восстанавливаются)')}>Вернуть в работу</button>
   :person.origin==='ldap'?<p className="muted">Ведётся каталогом AD: переименование и выбытие — там.</p>:null}
 </>:<>
  <div><h2>Добавить</h2><p className="sub">Человека или команду, которые отвечают за активы</p></div>
  <form className="form-grid" onSubmit={e=>{e.preventDefault();void act(()=>api.createSubject(csrf,{kind,name:name.trim(),contact:contact.trim(),username:kind==='person'&&username.trim()?username.trim():undefined}),'добавить '+(kind==='team'?'команду':'человека')+' «'+name.trim()+'»',()=>{setName('');setContact('');setUsername('')})}}>
   <label>Вид<select aria-label="Вид" value={kind} onChange={e=>setKind(e.target.value as 'person'|'team')}><option value="person">Человек</option><option value="team">Команда</option></select></label>
   <label>Имя<input aria-label="Имя" placeholder="ФИО или название команды" value={name} onChange={e=>setName(e.target.value)}/></label>
   <label>Контакт<input aria-label="Контакт" placeholder="Почта или телефон" value={contact} onChange={e=>setContact(e.target.value)}/></label>
   {kind==='person'?<label>Логин входа<input aria-label="Логин" placeholder="необязательно" value={username} onChange={e=>setUsername(e.target.value)}/></label>:null}
   <div className="form-row"><button className="button primary-sm" disabled={busy||!name.trim()||!contact.trim()}>Добавить</button></div></form>
  <p className="muted">Выберите сотрудника в списке — здесь появится его карточка: нагрузка, команды, выбытие.</p>
 </>;
 return <Split side={side}>
  <div className="org-cols">
   <Panel title="Подразделения и команды" flush><div className="tree">{item('all','Все сотрудники',people.length)}{item('teams','Все команды',teams.length)}{teams.filter(t=>t.active).map(t=>item(t.subject_id,t.name+(t.site_fallback?' — резерв площадки':''),(members[t.subject_id]??[]).length,1))}{item('none','Без команды',people.filter(p=>!inTeam.has(p.subject_id)).length)}</div>
    <label className="inline-check pad"><input type="checkbox" checked={inactive} onChange={e=>setInactive(e.target.checked)}/> показывать выбывших</label></Panel>
   <div className="col">
    <div><h2 className="h2">{team?team.name:group==='teams'?'Команды':group==='none'?'Без команды':'Все сотрудники'}</h2><p className="muted">{team?'Команда · '+(members[team.subject_id]??[]).length+' сотрудн.'+(team.origin==='ldap'?' · из AD':''):list.length+' в списке'}</p></div>
    {error?<div className="error" role="alert">{errorMessage(error)}</div>:null}{notice?<div className="notice" role="status">{notice}</div>:null}
    <input className="toolbar-search" aria-label="Фильтр сотрудников" placeholder="Имя или логин" value={q} onChange={e=>setQ(e.target.value)}/>
    <div className="panel table-scroll"><table className="panel-table"><thead><tr><th>{group==='teams'?'Команда':'Сотрудник'}</th><th>Логин</th><th className="num">Активов</th><th className="num">Систем</th><th>Состояние</th></tr></thead><tbody>
     {list.map(s=><tr key={s.subject_id} className={s.subject_id===sel?'selected':''}><td><button className="link plain" onClick={()=>setSel(s.subject_id)}>{s.name}</button>{s.origin==='ldap'?<small className="muted"> AD</small>:null}</td><td className="mono">{s.directory_login??s.username??'—'}</td><td className="num">{cnt(org?.assets,s.subject_id)}</td><td className="num">{cnt(org?.systems,s.subject_id)}</td><td>{s.active?(s.site_fallback?<StateDot tone="blue">резерв площадки</StateDot>:<StateDot tone="green">действует</StateDot>):<StateDot tone="grey">выбыл</StateDot>}</td></tr>)}
    </tbody></table>{!list.length?<p className="muted pad">Никого нет.</p>:null}</div>
    <Panel title="Синхронизация с AD"><DirectorySyncPanel csrf={csrf} onExpired={onExpired} onSynced={refresh}/></Panel>
   </div>
  </div>
 </Split>;
}
