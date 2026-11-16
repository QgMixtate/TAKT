import {useEffect,useState} from 'react';
import {api,ApiError,errorMessage,type Subject,type Ticket,type TicketDetail,type TicketKind} from './api';

// Волна 3 (C47): обращения — очередь, регистрация, карточка с переходами, назначением, журналом и связями.
// Заявки из каталога, изменения, портал заявителя и SLA — следующие пакеты (C48–C50).

export const kindName:Record<TicketKind,string>={incident:'Инцидент',request:'Заявка',change:'Изменение',problem:'Проблема'};
const stateName:Record<string,[string,string]>={new:['новый','state-pending'],assigned:['назначен','state-pending'],in_progress:['в работе','state-active'],waiting_customer:['ждём заявителя','state-partial'],resolved:['решён','state-ok'],closed:['закрыт','state-ok'],cancelled:['отменён','state-unavailable'],investigating:['расследование','state-active'],known_error:['известная ошибка','state-partial']};
const actionName:Record<string,string>={in_progress:'В работу',waiting_customer:'Ждём заявителя',resolved:'Решён…',closed:'Закрыть',cancelled:'Отменить',investigating:'Расследовать',known_error:'Известная ошибка…'};
const prio=(p:number)=>'P'+p;
const fmt=(v:string)=>new Date(v).toLocaleString('ru-RU');

export function TicketsView({csrf,canWrite,onOpenAsset,onExpired}:{csrf:string;canWrite:boolean;onOpenAsset:(uid:string)=>void;onExpired:()=>void}){
 const [kind,setKind]=useState(''),[state,setState]=useState('open'),[mine,setMine]=useState(false),[q,setQ]=useState(''),[items,setItems]=useState<Ticket[]|null>(null),[open,setOpen]=useState<string|null>(null),[creating,setCreating]=useState(false),[subjects,setSubjects]=useState<Subject[]>([]),[error,setError]=useState<unknown>(null),[n,setN]=useState(0);
 const fail=(e:unknown)=>{setError(e);if(e instanceof ApiError&&e.status===401)onExpired()};
 useEffect(()=>{api.subjects().then(p=>setSubjects(p.items)).catch(fail)},[]);
 useEffect(()=>{const t=setTimeout(()=>api.tickets({kind,state,mine,q}).then(p=>{setItems(p.items);setError(null)}).catch(fail),250);return()=>clearTimeout(t)},[kind,state,mine,q,n]);
 const name=(id:string|null)=>id?(subjects.find(s=>s.subject_id===id)?.name??id.slice(0,8)):'—';
 return <div className="stack">
  {error?<div className="error" role="alert">{errorMessage(error)}</div>:null}
  <div className="table-panel"><div className="table-toolbar"><h2>Обращения <span>{items?.length??'…'}</span></h2><div className="filters">
   <label className="search-field"><span>⌕</span><input aria-label="Поиск обращения" placeholder="Номер или тема…" value={q} onChange={e=>setQ(e.target.value)}/></label>
   <select aria-label="Вид обращения" value={kind} onChange={e=>setKind(e.target.value)}><option value="">Все виды</option>{(['incident','problem'] as TicketKind[]).map(k=><option key={k} value={k}>{kindName[k]}</option>)}</select>
   <select aria-label="Состояние обращения" value={state} onChange={e=>setState(e.target.value)}><option value="open">Открытые</option><option value="">Все</option><option value="resolved">Решённые</option><option value="closed">Закрытые</option></select>
   <label className="check"><input type="checkbox" checked={mine} onChange={e=>setMine(e.target.checked)}/> мои</label>
   {canWrite?<button className="button small" onClick={()=>setCreating(true)}>+ Обращение</button>:null}</div></div>
   {items&&items.length===0?<div className="empty"><span>☏</span><h3>Обращений нет</h3><p>Зарегистрируйте инцидент или проблему.</p></div>:
   <div className="table-scroll"><table><thead><tr><th>Номер</th><th>Тема</th><th>Приоритет</th><th>Состояние</th><th>Исполнитель / команда</th><th>Создано</th></tr></thead><tbody>{(items??[]).map(t=><tr key={t.ticket_id}>
    <td><button className="asset-link" onClick={()=>setOpen(t.ticket_id)}><span><strong className="mono">{t.number}</strong><small>{kindName[t.kind]}</small></span></button></td><td>{t.title}</td>
    <td><span className={'badge '+(t.priority<=2?'state-unavailable':'state-pending')}><i/>{prio(t.priority)}</span></td><td><span className={'badge '+(stateName[t.state]?.[1]??'')}><i/>{stateName[t.state]?.[0]??t.state}</span></td>
    <td>{name(t.assignee_id)}{t.team_id?<small>{name(t.team_id)}</small>:null}</td><td className="time">{fmt(t.created_at)}</td></tr>)}</tbody></table></div>}
  </div>
  {creating?<CreateTicket csrf={csrf} subjects={subjects} onFail={fail} onClose={()=>setCreating(false)} onCreated={d=>{setCreating(false);setN(x=>x+1);setOpen(d.ticket_id)}}/>:null}
  {open?<TicketCard id={open} csrf={csrf} canWrite={canWrite} subjects={subjects} onOpenAsset={onOpenAsset} onFail={fail} onClose={()=>{setOpen(null);setN(x=>x+1)}}/>:null}
 </div>;
}

function CreateTicket({csrf,subjects,onFail,onClose,onCreated}:{csrf:string;subjects:Subject[];onFail:(e:unknown)=>void;onClose:()=>void;onCreated:(d:TicketDetail)=>void}){
 const [kind,setKind]=useState<TicketKind>('incident'),[title,setTitle]=useState(''),[desc,setDesc]=useState(''),[impact,setImpact]=useState(2),[urgency,setUrgency]=useState(2),[requester,setRequester]=useState(''),[asset,setAsset]=useState(''),[busy,setBusy]=useState(false);
 async function save(){setBusy(true);try{onCreated(await api.createTicket(csrf,{kind,title:title.trim(),description:desc.trim(),impact,urgency,requester_id:requester||undefined,asset_uid:asset.trim()||undefined}))}catch(e){onFail(e)}finally{setBusy(false)}}
 const level=['высокое','среднее','низкое'];
 return <div className="drawer-shade" onClick={onClose}><aside className="drawer" role="dialog" aria-label="Новое обращение" onClick={e=>e.stopPropagation()}><header><span className="eyebrow muted">Обращения</span><button className="text-button" onClick={onClose}>Закрыть</button></header><h2>Новое обращение</h2>
  <div className="wh-form">
   <label>Вид<select value={kind} onChange={e=>setKind(e.target.value as TicketKind)}><option value="incident">Инцидент</option><option value="problem">Проблема</option></select></label>
   <label className="wide">Тема<input value={title} onChange={e=>setTitle(e.target.value)} maxLength={256}/></label>
   <label className="wide">Описание<textarea rows={4} value={desc} onChange={e=>setDesc(e.target.value)} maxLength={8000}/></label>
   <label>Влияние<select value={impact} onChange={e=>setImpact(Number(e.target.value))}>{[1,2,3].map(v=><option key={v} value={v}>{level[v-1]}</option>)}</select></label>
   <label>Срочность<select value={urgency} onChange={e=>setUrgency(Number(e.target.value))}>{[1,2,3].map(v=><option key={v} value={v}>{level[v-1]}</option>)}</select></label>
   <label>Заявитель<select value={requester} onChange={e=>setRequester(e.target.value)}><option value="">—</option>{subjects.filter(s=>s.active&&s.kind==='person').map(s=><option key={s.subject_id} value={s.subject_id}>{s.name}</option>)}</select></label>
   <label>Актив (UID, необязательно)<input className="mono" value={asset} onChange={e=>setAsset(e.target.value)} placeholder="из карточки актива"/></label>
  </div>
  <button className="button primary" disabled={busy||!title.trim()} onClick={()=>void save()}>Зарегистрировать <span>→</span></button></aside></div>;
}

function TicketCard({id,csrf,canWrite,subjects,onOpenAsset,onFail,onClose}:{id:string;csrf:string;canWrite:boolean;subjects:Subject[];onOpenAsset:(uid:string)=>void;onFail:(e:unknown)=>void;onClose:()=>void}){
 const [d,setD]=useState<TicketDetail|null>(null),[busy,setBusy]=useState(false),[text,setText]=useState(''),[internal,setInternal]=useState(false),[team,setTeam]=useState(''),[link,setLink]=useState(''),[linkKind,setLinkKind]=useState<'asset'|'ticket'|'service'>('asset');
 useEffect(()=>{api.ticket(id).then(setD).catch(onFail)},[id]);
 const name=(ref:string|null)=>ref?(subjects.find(s=>s.subject_id===ref)?.name??ref.slice(0,8)):'—';
 async function act(action:'transition'|'assign'|'comments'|'links',b:Record<string,unknown>){if(!d)return;setBusy(true);try{setD(await api.ticketAction(csrf,d.ticket_id,action,b))}catch(e){onFail(e);api.ticket(id).then(setD).catch(()=>{})}finally{setBusy(false)}}
 function transition(to:string){if(!d)return;let t='';if(to==='resolved'||to==='known_error'){t=(window.prompt(to==='resolved'?'Решение (обязательно):':'Обходное решение (обязательно):')??'').trim();if(!t)return}else if(to==='in_progress'&&d.state==='resolved'){t=(window.prompt('Причина повторного открытия:')??'').trim()}void act('transition',{revision:d.revision,to,text:t})}
 if(!d)return null;
 return <div className="drawer-shade" onClick={onClose}><aside className="drawer ticket-card" role="dialog" aria-label={'Обращение '+d.number} onClick={e=>e.stopPropagation()}><header><span className="eyebrow muted">{kindName[d.kind]} · {d.number}</span><button className="text-button" aria-label="Закрыть обращение" onClick={onClose}>Закрыть</button></header>
  <h2>{d.title}</h2>
  <p><span className={'badge '+(stateName[d.state]?.[1]??'')}><i/>{stateName[d.state]?.[0]??d.state}</span> <span className="badge"><i/>{prio(d.priority)}</span>{d.reopen_count?<small> · открыт повторно: {d.reopen_count}</small>:null}</p>
  {d.description?<p>{d.description}</p>:null}
  {d.workarounds.length?<div className="map-notice ok" role="status">Обходное решение: {d.workarounds.join('; ')}</div>:null}
  <dl><dt>Заявитель</dt><dd>{name(d.requester_id)}</dd><dt>Исполнитель</dt><dd>{name(d.assignee_id)}</dd><dt>Команда</dt><dd>{name(d.team_id)}</dd><dt>Создано</dt><dd>{fmt(d.created_at)}</dd>{d.resolution?<><dt>Решение</dt><dd>{d.resolution}</dd></>:null}{d.workaround?<><dt>Обходное решение</dt><dd>{d.workaround}</dd></>:null}</dl>
  {canWrite&&d.state!=='closed'&&d.state!=='cancelled'?<div className="ticket-actions">
   <button className="button small" disabled={busy} onClick={()=>void act('assign',{revision:d.revision,me:true})}>Взять себе</button>
   {d.allowed_transitions.map(to=><button key={to} className="button small" disabled={busy} onClick={()=>transition(to)}>{actionName[to]??to}</button>)}
   <select aria-label="Команда" value={team} onChange={e=>setTeam(e.target.value)}><option value="">команда…</option>{subjects.filter(s=>s.active&&s.kind==='team').map(s=><option key={s.subject_id} value={s.subject_id}>{s.name}</option>)}</select>
   <button className="text-link" disabled={busy||!team} onClick={()=>{const reason=window.prompt('Причина эскалации / передачи:')??'';void act('assign',{revision:d.revision,team_id:team,reason})}}>Передать команде</button></div>:null}
  <h3>Связи</h3><ul className="ticket-links">{d.links.map(l=><li key={l.target_kind+l.target_id}>{l.target_kind==='asset'?<button className="text-link" onClick={()=>onOpenAsset(l.target_id)}>актив {l.label||l.target_id.slice(0,8)} ↗</button>:<span>{({ticket:'обращение',service:'сервис',movement:'склад'} as Record<string,string>)[l.target_kind]} {l.label||l.target_id.slice(0,8)}</span>}</li>)}</ul>
  {canWrite?<div className="wh-line"><select aria-label="Вид связи" value={linkKind} onChange={e=>setLinkKind(e.target.value as 'asset'|'ticket'|'service')}><option value="asset">актив</option><option value="ticket">обращение</option><option value="service">сервис</option></select><input aria-label="UID для связи" className="mono" value={link} onChange={e=>setLink(e.target.value)} placeholder="UID"/><button className="text-link" disabled={busy||!/^[0-9a-f-]{36}$/.test(link.trim())} onClick={()=>{void act('links',{target_kind:linkKind,target_id:link.trim()});setLink('')}}>Связать</button></div>:null}
  <h3>Журнал</h3><ul className="ticket-feed">{d.events.map(e=><li key={e.event_id} className={e.public?'':'internal'}><small>{fmt(e.occurred_at)} · {e.actor_ref.replace(/^user:/,'').slice(0,8)}{e.public?'':' · внутренний'}</small><span>{e.kind==='state'?'Состояние: '+(stateName[String(e.detail.to)]?.[0]??String(e.detail.to)):e.kind==='assigned'?'Назначение'+(e.detail.team_id?' команде '+name(String(e.detail.team_id)):'')+(e.detail.assignee_id?' исполнителю '+name(String(e.detail.assignee_id)):''):e.kind==='created'?'Создано':e.kind==='linked'?'Связь: '+String(e.detail.target_kind):e.kind==='comment'?'':e.kind}{e.text?(e.kind==='comment'?'':' — ')+e.text:''}</span></li>)}</ul>
  {canWrite?<div className="ticket-comment"><textarea aria-label="Комментарий" rows={3} value={text} onChange={e=>setText(e.target.value)} placeholder="Комментарий"/><label className="check"><input type="checkbox" checked={internal} onChange={e=>setInternal(e.target.checked)}/> внутренний (заявитель не увидит)</label><button className="button small" disabled={busy||!text.trim()} onClick={()=>{void act('comments',{text:text.trim(),internal});setText('')}}>Добавить</button></div>:null}
 </aside></div>;
}
