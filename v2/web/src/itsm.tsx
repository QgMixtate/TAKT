import {useEffect,useState} from 'react';
import {PageTabs,Pct,Split,Strip} from './ui';
import {api,ApiError,errorMessage,type CalendarEntry,type CatalogField,type CatalogItem,type ChangeWindow,type SlaSettings,type SlaTimer,type Subject,type Ticket,type TicketDetail,type TicketKind,type WItem,type WLocation,type WUnit} from './api';

// Волна 3 (C47): обращения — очередь, регистрация, карточка с переходами, назначением, журналом и связями.
// C48: каталог услуг (администратор), заявки — согласование и исполнение со склада. C49: изменения — окно, риск,
// согласование администратором, предупреждение о пересечении окон, календарь. C50: SLA — сроки в рабочих часах.

export const kindName:Record<TicketKind,string>={incident:'Инцидент',request:'Заявка',change:'Изменение',problem:'Проблема'};
const stateName:Record<string,[string,string]>={new:['новый','state-pending'],assigned:['назначен','state-pending'],in_progress:['в работе','state-active'],waiting_customer:['ждём заявителя','state-partial'],resolved:['решён','state-ok'],closed:['закрыт','state-ok'],cancelled:['отменён','state-unavailable'],investigating:['расследование','state-active'],known_error:['известная ошибка','state-partial'],pending_approval:['на согласовании','state-pending'],in_fulfillment:['в исполнении','state-active'],fulfilled:['исполнена','state-ok'],rejected:['отклонена','state-unavailable'],draft:['черновик','state-pending'],submitted:['на согласовании','state-pending'],approved:['согласовано','state-active'],scheduled:['запланировано','state-active'],completed:['выполнено','state-ok'],rolled_back:['откат','state-partial']};
const actionName:Record<string,string>={in_progress:'В работу',waiting_customer:'Ждём заявителя',resolved:'Решён…',closed:'Закрыть',cancelled:'Отменить',investigating:'Расследовать',known_error:'Известная ошибка…',fulfilled:'Исполнено…',in_fulfillment:'Вернуть в исполнение',submitted:'На согласование',scheduled:'Запланировать',completed:'Выполнено…',rolled_back:'Откат…'};
const slaName:Record<SlaTimer['status'],[string,string]>={running:['идёт','state-active'],paused:['пауза','state-pending'],warning:['скоро срок','state-partial'],breached:['нарушен','state-unavailable'],met:['в срок','state-ok'],missed:['просрочен','state-unavailable']};
const metricName:Record<SlaTimer['metric'],string>={response:'Реакция',resolution:'Решение'};
const span=(m:number)=>m>=60?Math.floor(m/60)+' ч'+(m%60?' '+m%60+' мин':''):m+' мин';
const riskName:Record<ChangeWindow['risk'],string>={low:'низкий',medium:'средний',high:'высокий'};
const prio=(p:number)=>'P'+p;
const fmt=(v:string)=>new Date(v).toLocaleString('ru-RU');

export function TicketsView({csrf,canWrite,canAdmin,onOpenAsset,onExpired}:{csrf:string;canWrite:boolean;canAdmin:boolean;onOpenAsset:(uid:string)=>void;onExpired:()=>void}){
 const [kind,setKind]=useState(''),[state,setState]=useState('open'),[mine,setMine]=useState(false),[q,setQ]=useState(''),[items,setItems]=useState<Ticket[]|null>(null),[open,setOpen]=useState<string|null>(null),[creating,setCreating]=useState(false),[subjects,setSubjects]=useState<Subject[]>([]),[error,setError]=useState<unknown>(null),[n,setN]=useState(0),[tab,setTab]=useState<'queue'|'catalog'|'calendar'|'sla'>('queue');
 const fail=(e:unknown)=>{setError(e);if(e instanceof ApiError&&e.status===401)onExpired()};
 useEffect(()=>{api.subjects().then(p=>setSubjects(p.items)).catch(fail)},[]);
 useEffect(()=>{const t=setTimeout(()=>api.tickets({kind,state,mine,q}).then(p=>{setItems(p.items);setError(null)}).catch(fail),250);return()=>clearTimeout(t)},[kind,state,mine,q,n]);
 const name=(id:string|null)=>id?(subjects.find(s=>s.subject_id===id)?.name??id.slice(0,8)):'—';
 // C53.07 (макет «Обращения»): вкладки раздела, сводка по открытым, очередь с расходом SLA и карточка обращения справа.
 const [all,setAll]=useState<Ticket[]|null>(null);
 useEffect(()=>{api.tickets({state:'open'}).then(p=>setAll(p.items)).catch(fail)},[n]);
 const worst=(t:Ticket)=>t.sla.reduce((m,x)=>Math.max(m,x.target_minutes?Math.round(100*x.elapsed_minutes/x.target_minutes):0),0);
 const cnt=(f:(t:Ticket)=>boolean)=>all?all.filter(f).length:null;
 const tabs:[typeof tab,string][]=[['queue','Очередь'],['catalog','Каталог услуг'],['calendar','Календарь изменений'],['sla','SLA']];
 const queue=<>
  <div className="systems-toolbar"><select aria-label="Состояние обращения" value={state} onChange={e=>setState(e.target.value)}><option value="open">Открытые</option><option value="">Все</option><option value="pending_approval">На согласовании</option><option value="in_fulfillment">В исполнении</option><option value="resolved">Решённые</option><option value="fulfilled">Исполненные</option><option value="closed">Закрытые</option></select>
   <select aria-label="Вид обращения" value={kind} onChange={e=>setKind(e.target.value)}><option value="">Вид: все</option>{(['incident','request','change','problem'] as TicketKind[]).map(k=><option key={k} value={k}>{kindName[k]}</option>)}</select>
   <label className="check"><input type="checkbox" checked={mine} onChange={e=>setMine(e.target.checked)}/> мои</label>
   <input className="toolbar-search" aria-label="Поиск обращения" placeholder="Номер или тема" value={q} onChange={e=>setQ(e.target.value)}/>
   <span className="spacer"/>{canWrite?<button className="button primary-sm" onClick={()=>setCreating(true)}>+ Обращение</button>:null}</div>
  {items&&items.length===0?<div className="empty"><span>☏</span><h3>Обращений нет</h3><p>Зарегистрируйте инцидент или проблему.</p></div>:
  <div className="panel table-scroll"><table className="panel-table"><thead><tr><th>Номер</th><th>Вид</th><th>Тема</th><th>Приоритет</th><th>Состояние</th><th>Исполнитель / команда</th><th>SLA израсходовано</th></tr></thead><tbody>{(items??[]).map(t=><tr key={t.ticket_id} className={open===t.ticket_id?'selected':''}>
   <td><button className="link plain mono" onClick={()=>setOpen(t.ticket_id)}><b>{t.number}</b></button></td><td>{kindName[t.kind]}</td><td>{t.title}</td>
   <td><span className={'badge '+(t.priority<=2?'state-unavailable':'state-pending')}><i/>{prio(t.priority)}</span></td><td><span className={'badge '+(stateName[t.state]?.[1]??'')}><i/>{stateName[t.state]?.[0]??t.state}</span></td>
   <td>{name(t.assignee_id)}{t.team_id?<small className="muted"> · {name(t.team_id)}</small>:null}</td><td>{t.sla.length?<span title={slaTitle(t.sla)} className="sla-cell"><Pct value={worst(t)}/><small className="muted">{slaText(t.sla)}</small></span>:<span className="muted">—</span>}</td></tr>)}</tbody></table></div>}
 </>;
 return <>
  {tab==='queue'?<Strip label="Сводка обращений" items={[{key:'open',n:cnt(()=>true),label:'открытых',active:state==='open'&&!mine,onClick:()=>{setState('open');setMine(false)}},{key:'breached',n:cnt(t=>t.sla.some(x=>x.status==='breached'||x.status==='missed')),label:'нарушают SLA',tone:'warn'},{key:'warning',n:cnt(t=>t.sla.some(x=>x.status==='warning')),label:'близко к сроку',tone:'amber'},{key:'noassignee',n:cnt(t=>!t.assignee_id),label:'не назначены'},{key:'approval',n:cnt(t=>t.state==='pending_approval'),label:'ждут согласования',onClick:()=>setState('pending_approval')}]}/>:null}
  <PageTabs label="Разделы обращений" tabs={tabs} value={tab} onChange={t=>{setOpen(null);setTab(t)}}/>
  {error?<div className="error" role="alert">{errorMessage(error)}</div>:null}
  {tab==='catalog'?<div className="page-pad"><CatalogAdmin csrf={csrf} canAdmin={canAdmin} subjects={subjects} onFail={fail}/></div>:tab==='calendar'?<div className="page-pad"><ChangeCalendar onOpen={setOpen} onFail={fail}/></div>:tab==='sla'?<div className="page-pad"><SlaAdmin csrf={csrf} canAdmin={canAdmin} onFail={fail}/></div>:
   <Split wide side={open?<TicketCard key={open} embedded id={open} csrf={csrf} canWrite={canWrite} canAdmin={canAdmin} subjects={subjects} onOpenAsset={onOpenAsset} onFail={fail} onClose={()=>{setOpen(null);setN(x=>x+1)}}/>:<div className="empty"><span>☏</span><h3>Выберите обращение</h3><p>Карточка откроется здесь: статус, SLA, связи с системой и хостом, журнал и действия.</p></div>}>{queue}</Split>}
  {tab!=='queue'&&open?<TicketCard id={open} csrf={csrf} canWrite={canWrite} canAdmin={canAdmin} subjects={subjects} onOpenAsset={onOpenAsset} onFail={fail} onClose={()=>{setOpen(null);setN(x=>x+1)}}/>:null}
  {creating?<CreateTicket csrf={csrf} subjects={subjects} onFail={fail} onClose={()=>setCreating(false)} onCreated={d=>{setCreating(false);setN(x=>x+1);setOpen(d.ticket_id)}}/>:null}
 </>;
}

// худший таймер: нарушение важнее предупреждения, идущий — с ближайшим сроком
function slaText(list:SlaTimer[]){const rank={breached:0,missed:1,warning:2,running:3,paused:4,met:5};const t=[...list].sort((a,b)=>rank[a.status]-rank[b.status])[0];if(!t)return '';return t.status==='running'&&t.due_at?'до '+new Date(t.due_at).toLocaleString('ru-RU',{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'}):slaName[t.status][0]}
const slaTitle=(list:SlaTimer[])=>list.map(x=>metricName[x.metric]+': '+slaName[x.status][0]+', '+span(x.elapsed_minutes)+' из '+span(x.target_minutes)).join('; ');

function CreateTicket({csrf,subjects,onFail,onClose,onCreated}:{csrf:string;subjects:Subject[];onFail:(e:unknown)=>void;onClose:()=>void;onCreated:(d:TicketDetail)=>void}){
 const [kind,setKind]=useState<TicketKind>('incident'),[title,setTitle]=useState(''),[desc,setDesc]=useState(''),[impact,setImpact]=useState(2),[urgency,setUrgency]=useState(2),[requester,setRequester]=useState(''),[asset,setAsset]=useState(''),[busy,setBusy]=useState(false);
 async function save(){setBusy(true);try{onCreated(await api.createTicket(csrf,{kind,title:title.trim(),description:desc.trim(),impact,urgency,requester_id:requester||undefined,asset_uid:asset.trim()||undefined}))}catch(e){onFail(e)}finally{setBusy(false)}}
 const level=['высокое','среднее','низкое'];
 return <div className="drawer-shade" onClick={onClose}><aside className="drawer" role="dialog" aria-label="Новое обращение" onClick={e=>e.stopPropagation()}><header><span className="eyebrow muted">Обращения</span><button className="text-button" onClick={onClose}>Закрыть</button></header><h2>Новое обращение</h2>
  <div className="wh-form">
   <label>Вид<select value={kind} onChange={e=>setKind(e.target.value as TicketKind)}><option value="incident">Инцидент</option><option value="change">Изменение</option><option value="problem">Проблема</option></select></label>
   <label className="wide">Тема<input value={title} onChange={e=>setTitle(e.target.value)} maxLength={256}/></label>
   <label className="wide">Описание<textarea rows={4} value={desc} onChange={e=>setDesc(e.target.value)} maxLength={8000}/></label>
   <label>Влияние<select value={impact} onChange={e=>setImpact(Number(e.target.value))}>{[1,2,3].map(v=><option key={v} value={v}>{level[v-1]}</option>)}</select></label>
   <label>Срочность<select value={urgency} onChange={e=>setUrgency(Number(e.target.value))}>{[1,2,3].map(v=><option key={v} value={v}>{level[v-1]}</option>)}</select></label>
   <label>Заявитель<select value={requester} onChange={e=>setRequester(e.target.value)}><option value="">—</option>{subjects.filter(s=>s.active&&s.kind==='person').map(s=><option key={s.subject_id} value={s.subject_id}>{s.name}</option>)}</select></label>
   <label>Актив (UID, необязательно)<input className="mono" value={asset} onChange={e=>setAsset(e.target.value)} placeholder="из карточки актива"/></label>
  </div>
  <button className="button primary" disabled={busy||!title.trim()} onClick={()=>void save()}>Зарегистрировать <span>→</span></button></aside></div>;
}

function TicketCard({id,csrf,canWrite,canAdmin,subjects,onOpenAsset,onFail,onClose,embedded}:{embedded?:boolean;id:string;csrf:string;canWrite:boolean;canAdmin:boolean;subjects:Subject[];onOpenAsset:(uid:string)=>void;onFail:(e:unknown)=>void;onClose:()=>void}){
 const [d,setD]=useState<TicketDetail|null>(null),[busy,setBusy]=useState(false),[text,setText]=useState(''),[internal,setInternal]=useState(false),[team,setTeam]=useState(''),[link,setLink]=useState(''),[linkKind,setLinkKind]=useState<'asset'|'ticket'|'service'>('asset');
 useEffect(()=>{api.ticket(id).then(setD).catch(onFail)},[id]);
 useEffect(()=>{const k=(e:KeyboardEvent)=>{if(e.key==='Escape')onClose()};window.addEventListener('keydown',k);return ()=>window.removeEventListener('keydown',k)},[onClose]);
 const name=(ref:string|null)=>ref?(subjects.find(s=>s.subject_id===ref)?.name??ref.slice(0,8)):'—';
 async function act(action:'transition'|'assign'|'comments'|'links'|'approve'|'fulfill'|'window',b:Record<string,unknown>){if(!d)return;setBusy(true);try{setD(await api.ticketAction(csrf,d.ticket_id,action,b))}catch(e){onFail(e);api.ticket(id).then(setD).catch(()=>{})}finally{setBusy(false)}}
 function transition(to:string){if(!d)return;let t='';if(to==='scheduled'&&d.change?.conflicts.length){if(!window.confirm('Окно пересекается с изменениями: '+d.change.conflicts.map(c=>c.number).join(', ')+'. Запланировать всё равно?'))return;void act('transition',{revision:d.revision,to,confirm_conflicts:true});return}if(to==='resolved'||to==='known_error'||to==='fulfilled'||to==='completed'||to==='rolled_back'){t=(window.prompt(to==='resolved'?'Решение (обязательно):':to==='fulfilled'?'Что сделано (обязательно):':to==='completed'?'Результат проверки (обязательно):':to==='rolled_back'?'Причина отката (обязательно):':'Обходное решение (обязательно):')??'').trim();if(!t)return}else if((to==='in_progress'||to==='in_fulfillment')&&(d.state==='resolved'||d.state==='fulfilled')){t=(window.prompt('Причина повторного открытия:')??'').trim()}void act('transition',{revision:d.revision,to,text:t})}
 if(!d)return null;
 const body=<><header><span className="eyebrow muted">{kindName[d.kind]} · {d.number}</span><button className="text-button" aria-label="Закрыть обращение" onClick={onClose}>Закрыть</button></header>
  <h2>{d.title}</h2>
  <p><span className={'badge '+(stateName[d.state]?.[1]??'')}><i/>{stateName[d.state]?.[0]??d.state}</span> <span className="badge"><i/>{prio(d.priority)}</span>{d.reopen_count?<small> · открыт повторно: {d.reopen_count}</small>:null}</p>
  {d.description?<p>{d.description}</p>:null}
  {d.sla.length?<div className="request-block" aria-label="SLA">{d.sla.map(x=><p key={x.metric}><strong>{metricName[x.metric]}:</strong> <span className={'badge '+slaName[x.status][1]}><i/>{slaName[x.status][0]}</span> {span(x.elapsed_minutes)} из {span(x.target_minutes)} рабочего времени{x.due_at?' · срок '+fmt(x.due_at):''}</p>)}</div>:null}
  {d.change?<ChangeBlock d={d} canWrite={canWrite} canAdmin={canAdmin} busy={busy} onAct={act}/>:null}
  {d.request?<RequestBlock d={d} csrf={csrf} canWrite={canWrite} busy={busy} name={name} onAct={act}/>:null}
  {d.workarounds.length?<div className="map-notice ok" role="status">Обходное решение: {d.workarounds.join('; ')}</div>:null}
  <dl><dt>Заявитель</dt><dd>{name(d.requester_id)}</dd><dt>Исполнитель</dt><dd>{name(d.assignee_id)}</dd><dt>Команда</dt><dd>{name(d.team_id)}</dd><dt>Создано</dt><dd>{fmt(d.created_at)}</dd>{d.resolution?<><dt>Решение</dt><dd>{d.resolution}</dd></>:null}{d.workaround?<><dt>Обходное решение</dt><dd>{d.workaround}</dd></>:null}</dl>
  {canWrite&&d.state!=='closed'&&d.state!=='cancelled'?<div className="ticket-actions">
   <button className="button small" disabled={busy} onClick={()=>void act('assign',{revision:d.revision,me:true})}>Взять себе</button>
   {d.allowed_transitions.map(to=><button key={to} className="button small" disabled={busy} onClick={()=>transition(to)}>{actionName[to]??to}</button>)}
   <select aria-label="Команда" value={team} onChange={e=>setTeam(e.target.value)}><option value="">команда…</option>{subjects.filter(s=>s.active&&s.kind==='team').map(s=><option key={s.subject_id} value={s.subject_id}>{s.name}</option>)}</select>
   <button className="text-link" disabled={busy||!team} onClick={()=>{const reason=window.prompt('Причина эскалации / передачи:')??'';void act('assign',{revision:d.revision,team_id:team,reason})}}>Передать команде</button></div>:null}
  <h3>Связи</h3><ul className="ticket-links">{d.links.map(l=><li key={l.target_kind+l.target_id}>{l.target_kind==='asset'?<button className="text-link" onClick={()=>onOpenAsset(l.target_id)}>актив {l.label||l.target_id.slice(0,8)} ↗</button>:<span>{({ticket:'обращение',service:'сервис',movement:'склад'} as Record<string,string>)[l.target_kind]} {l.label||l.target_id.slice(0,8)}</span>}</li>)}</ul>
  {canWrite?<div className="wh-line"><select aria-label="Вид связи" value={linkKind} onChange={e=>setLinkKind(e.target.value as 'asset'|'ticket'|'service')}><option value="asset">актив</option><option value="ticket">обращение</option><option value="service">сервис</option></select><input aria-label="UID для связи" className="mono" value={link} onChange={e=>setLink(e.target.value)} placeholder="UID"/><button className="text-link" disabled={busy||!/^[0-9a-f-]{36}$/.test(link.trim())} onClick={()=>{void act('links',{target_kind:linkKind,target_id:link.trim()});setLink('')}}>Связать</button></div>:null}
  <h3>Журнал</h3><ul className="ticket-feed">{d.events.map(e=><li key={e.event_id} className={e.public?'':'internal'}><small>{fmt(e.occurred_at)} · {e.actor_ref.replace(/^user:/,'').slice(0,8)}{e.public?'':' · внутренний'}</small><span>{e.kind==='state'?'Состояние: '+(stateName[String(e.detail.to)]?.[0]??String(e.detail.to)):e.kind==='assigned'?'Назначение'+(e.detail.team_id?' команде '+name(String(e.detail.team_id)):'')+(e.detail.assignee_id?' исполнителю '+name(String(e.detail.assignee_id)):''):e.kind==='created'?'Создано':e.kind==='linked'?({asset:'Привязан актив',service:'Привязан сервис',ticket:'Связано с обращением',movement:'Привязан акт склада'} as Record<string,string>)[String(e.detail.target_kind)]??'Добавлена связь':e.kind==='approval'?(e.detail.decision==='approved'?'Согласовано':'Отклонено'):e.kind==='sla'?'SLA '+(e.detail.metric==='response'?'реакции':'решения')+': '+(e.detail.mark==='breached'?'срок нарушен':'скоро срок'):e.kind==='window'?'Окно изменения задано':e.kind==='fulfilled'?'Выдано со склада, акт '+String(e.detail.act_no):e.kind==='comment'?'':e.kind}{e.text?(e.kind==='comment'?'':' — ')+e.text:''}</span></li>)}</ul>
  {canWrite?<div className="ticket-comment"><textarea aria-label="Комментарий" rows={3} value={text} onChange={e=>setText(e.target.value)} placeholder="Комментарий"/><label className="check"><input type="checkbox" checked={internal} onChange={e=>setInternal(e.target.checked)}/> внутренний (заявитель не увидит)</label><button className="button small" disabled={busy||!text.trim()} onClick={()=>{void act('comments',{text:text.trim(),internal});setText('')}}>Добавить</button></div>:null}
 </>;
 return embedded?<section className="ticket-card embedded" role="dialog" aria-label={'Обращение '+d.number}>{body}</section>:<div className="drawer-shade" onClick={onClose}><aside className="drawer ticket-card" role="dialog" aria-label={'Обращение '+d.number} onClick={e=>e.stopPropagation()}>{body}</aside></div>;
}

type Act=(action:'transition'|'assign'|'comments'|'links'|'approve'|'fulfill'|'window',b:Record<string,unknown>)=>Promise<void>;

const local=(v:string)=>{const d=new Date(v);d.setMinutes(d.getMinutes()-d.getTimezoneOffset());return d.toISOString().slice(0,16)};

// Изменение: окно (черновик или согласованное), пересечения с другими окнами, согласование администратором.
function ChangeBlock({d,canWrite,canAdmin,busy,onAct}:{d:TicketDetail;canWrite:boolean;canAdmin:boolean;busy:boolean;onAct:Act}){
 const c=d.change!,w=c.window;
 const [from,setFrom]=useState(w?local(w.starts_at):''),[to,setTo]=useState(w?local(w.ends_at):''),[risk,setRisk]=useState<ChangeWindow['risk']>(w?.risk??'medium'),[plan,setPlan]=useState(w?.plan??''),[back,setBack]=useState(w?.rollback_plan??'');
 const editable=canWrite&&(d.state==='draft'||d.state==='approved');
 const valid=from&&to&&new Date(to)>new Date(from)&&plan.trim()&&back.trim();
 return <div className="request-block">
  {w?<p><strong>Окно:</strong> {fmt(w.starts_at)} — {fmt(w.ends_at)} · риск {riskName[w.risk]}{w.conflicts_confirmed?' · пересечение подтверждено':''}</p>:<p className="muted">Окно не задано</p>}
  {w&&!editable?<><p><strong>План:</strong> {w.plan}</p><p><strong>Откат:</strong> {w.rollback_plan}</p></>:null}
  {c.conflicts.length?<div className="error" role="status">Пересекается с: {c.conflicts.map(x=>x.number+' «'+x.title+'» ('+fmt(x.starts_at)+' — '+fmt(x.ends_at)+')').join('; ')}</div>:null}
  {c.approval?<p className={c.approval.decision==='approved'?'muted':'error'}>{c.approval.decision==='approved'?'Согласовано':'Отклонено'} · {new Date(c.approval.decided_at).toLocaleString('ru-RU')}{c.approval.comment?' — '+c.approval.comment:''}</p>:null}
  {editable?<div className="wh-form" aria-label="Окно изменения">
   <label>Начало<input aria-label="Начало окна" type="datetime-local" value={from} onChange={e=>setFrom(e.target.value)}/></label>
   <label>Конец<input aria-label="Конец окна" type="datetime-local" value={to} onChange={e=>setTo(e.target.value)}/></label>
   <label>Риск<select aria-label="Риск изменения" value={risk} onChange={e=>setRisk(e.target.value as ChangeWindow['risk'])}>{(['low','medium','high'] as const).map(r=><option key={r} value={r}>{riskName[r]}</option>)}</select></label>
   <label className="wide">План работ<textarea aria-label="План работ" rows={2} value={plan} onChange={e=>setPlan(e.target.value)} maxLength={8000}/></label>
   <label className="wide">План отката<textarea aria-label="План отката" rows={2} value={back} onChange={e=>setBack(e.target.value)} maxLength={8000}/></label>
   <div className="wh-submit"><button className="button small" disabled={busy||!valid} onClick={()=>void onAct('window',{revision:d.revision,starts_at:new Date(from).toISOString(),ends_at:new Date(to).toISOString(),risk,plan:plan.trim(),rollback_plan:back.trim()})}>Сохранить окно</button></div></div>:null}
  {canAdmin&&d.state==='submitted'?<div className="ticket-actions"><button className="button small" disabled={busy} onClick={()=>void onAct('approve',{revision:d.revision,approve:true,comment:''})}>Согласовать изменение</button><button className="button small" disabled={busy} onClick={()=>{const r=(window.prompt('Причина отклонения (обязательно):')??'').trim();if(r)void onAct('approve',{revision:d.revision,approve:false,comment:r})}}>Отклонить</button></div>:d.state==='submitted'?<p className="muted">Ждёт согласования администратором</p>:null}
 </div>;
}

// Календарь окон изменений на две недели вперёд (с сегодняшнего дня).
function ChangeCalendar({onOpen,onFail}:{onOpen:(id:string)=>void;onFail:(e:unknown)=>void}){
 const [start,setStart]=useState(()=>{const d=new Date();d.setHours(0,0,0,0);d.setDate(d.getDate()-((d.getDay()+6)%7));return d}),[items,setItems]=useState<CalendarEntry[]|null>(null);
 useEffect(()=>{const end=new Date(start.getTime()+14*864e5);api.changeCalendar(start.toISOString(),end.toISOString()).then(p=>setItems(p.items)).catch(onFail)},[start]);
 const shift=(days:number)=>setStart(s=>new Date(s.getTime()+days*864e5));
 const days=new Map<string,CalendarEntry[]>();for(const it of items??[]){const k=new Date(it.starts_at).toLocaleDateString('ru-RU',{weekday:'short',day:'numeric',month:'long'});days.set(k,[...(days.get(k)??[]),it])}
 return <div className="table-panel"><div className="table-toolbar"><h2>Окна изменений <span>{items?.length??'…'}</span></h2><div className="filters"><button className="button small" onClick={()=>shift(-14)}>← 2 недели</button><span>{start.toLocaleDateString('ru-RU')} — {new Date(start.getTime()+13*864e5).toLocaleDateString('ru-RU')}</span><button className="button small" onClick={()=>shift(14)}>2 недели →</button></div></div>
  <div className="week-grid" aria-label="Неделя">{Array.from({length:14},(_,i)=>{const d=new Date(start.getTime()+i*864e5),k=d.toDateString(),list=(items??[]).filter(it=>new Date(it.starts_at).toDateString()===k);const wk=d.getDay()===0||d.getDay()===6;return <div key={i} className={'day'+(wk?' weekend':'')+(new Date().toDateString()===k?' today':'')}><small>{d.toLocaleDateString('ru-RU',{weekday:'short',day:'numeric'})}</small>{list.map(it=><button key={it.ticket_id} className={'ev risk-'+it.risk} onClick={()=>onOpen(it.ticket_id)} title={it.title}><b>{it.number}</b><span>{it.title}</span></button>)}</div>})}</div>
  <p className="muted pad">Цвет — риск изменения: синий — низкий, жёлтый — средний, пурпурный — высокий. Пересечения окон по одной цели показываются в карточке изменения.</p>
  {items&&items.length===0?<div className="empty"><span>▤</span><h3>Окон в этом периоде нет</h3></div>:
  <div className="table-scroll"><table><thead><tr><th>День</th><th>Изменение</th><th>Окно</th><th>Риск</th><th>Состояние</th><th>Затрагивает</th></tr></thead><tbody>{[...days].flatMap(([day,list])=>list.map((it,i)=><tr key={it.ticket_id}>
   <td>{i===0?<strong>{day}</strong>:null}</td><td><button className="asset-link" onClick={()=>onOpen(it.ticket_id)}><span><strong className="mono">{it.number}</strong><small>{it.title}</small></span></button></td>
   <td className="time">{fmt(it.starts_at)} — {fmt(it.ends_at)}</td><td>{riskName[it.risk]}</td><td><span className={'badge '+(stateName[it.state]?.[1]??'')}><i/>{stateName[it.state]?.[0]??it.state}</span></td>
   <td>{it.targets.map(t=>(t.target_kind==='service'?'сервис ':'актив ')+(t.label||t.target_id.slice(0,8))).join(', ')||'—'}</td></tr>))}</tbody></table></div>}
 </div>;
}

// Заявка: услуга, значения формы, согласование; складская услуга исполняется выдачей экземпляра (или количества) заявителю.
function RequestBlock({d,csrf,canWrite,busy,name,onAct}:{d:TicketDetail;csrf:string;canWrite:boolean;busy:boolean;name:(id:string|null)=>string;onAct:Act}){
 const r=d.request!;
 const [items,setItems]=useState<WItem[]>([]),[units,setUnits]=useState<WUnit[]>([]),[locations,setLocations]=useState<WLocation[]>([]),[unit,setUnit]=useState(''),[loc,setLoc]=useState(''),[qty,setQty]=useState('1');
 const fulfil=canWrite&&d.state==='in_fulfillment'&&r.warehouse_item_id!==null;
 useEffect(()=>{if(!fulfil)return;Promise.all([api.wItems(),api.wUnits({state:'in_stock'}),api.wLocations()]).then(([i,u,l])=>{setItems(i.items);setUnits(u.items.filter(x=>x.item_id===r.warehouse_item_id));setLocations(l.items.filter(x=>x.active&&x.kind!=='repair'))}).catch(()=>{})},[fulfil,r.warehouse_item_id,csrf]);
 const item=items.find(i=>i.item_id===r.warehouse_item_id);
 const chosen=units.find(u=>u.unit_id===unit);
 return <div className="request-block">
  <p><strong>Услуга:</strong> {r.catalog_name}</p>
  {r.approval?<p className={r.approval.decision==='approved'?'muted':'error'}>{r.approval.decision==='approved'?'Согласовано':'Отклонено'} · {name(r.approval.approver_id)} · {new Date(r.approval.decided_at).toLocaleString('ru-RU')}{r.approval.comment?' — '+r.approval.comment:''}</p>:r.approver_id?<p className="muted">Согласующий: {name(r.approver_id)}</p>:null}
  {canWrite&&d.state==='pending_approval'?<div className="ticket-actions"><button className="button small" disabled={busy} onClick={()=>void onAct('approve',{revision:d.revision,approve:true,comment:''})}>Согласовать</button><button className="button small" disabled={busy} onClick={()=>{const c=(window.prompt('Причина отклонения (обязательно):')??'').trim();if(c)void onAct('approve',{revision:d.revision,approve:false,comment:c})}}>Отклонить</button></div>:null}
  {fulfil?<div className="wh-line" aria-label="Выдача со склада"><span>Выдать со склада{item?': '+item.name:''}</span>
   {item?.kind==='quantity'?<><select aria-label="Место выдачи" value={loc} onChange={e=>setLoc(e.target.value)}><option value="">место…</option>{locations.map(l=><option key={l.location_id} value={l.location_id}>{l.name}</option>)}</select><input aria-label="Количество" type="number" min="0" step="any" value={qty} onChange={e=>setQty(e.target.value)}/></>:
   <select aria-label="Экземпляр" value={unit} onChange={e=>setUnit(e.target.value)}><option value="">экземпляр…</option>{units.map(u=><option key={u.unit_id} value={u.unit_id}>{u.serial}{u.inventory_no?' · '+u.inventory_no:''}{u.location_id?' · '+(locations.find(l=>l.location_id===u.location_id)?.name??''):''}</option>)}</select>}
   <button className="button small" disabled={busy||(item?.kind==='quantity'?!loc||!(Number(qty)>0):!chosen)} onClick={()=>void onAct('fulfill',item?.kind==='quantity'?{revision:d.revision,from_location:loc,quantity:Number(qty)}:{revision:d.revision,from_location:chosen!.location_id,unit_id:unit})}>Выдать и исполнить</button></div>:null}
 </div>;
}

const blankField=():CatalogField=>({key:'',label:'',type:'text',required:false,options:[]});

// Каталог услуг: что сотрудники могут заказать на портале. Изменяет администратор.
function CatalogAdmin({csrf,canAdmin,subjects,onFail}:{csrf:string;canAdmin:boolean;subjects:Subject[];onFail:(e:unknown)=>void}){
 const [items,setItems]=useState<CatalogItem[]|null>(null),[wItems,setWItems]=useState<WItem[]>([]),[edit,setEdit]=useState<Partial<CatalogItem>|null>(null),[busy,setBusy]=useState(false),[n,setN]=useState(0);
 useEffect(()=>{api.catalog().then(p=>setItems(p.items)).catch(onFail)},[n]);
 useEffect(()=>{if(canAdmin)api.wItems().then(p=>setWItems(p.items)).catch(()=>{})},[canAdmin]);
 const name=(id:string|null)=>id?(subjects.find(s=>s.subject_id===id)?.name??id.slice(0,8)):'—';
 async function save(){if(!edit)return;setBusy(true);try{const form=(edit.form??[]).map(f=>({...f,key:f.key.trim(),label:f.label.trim(),options:f.type==='select'?f.options.map(o=>o.trim()).filter(Boolean):[]}));
  await api.saveCatalog(csrf,{name:(edit.name??'').trim(),description:(edit.description??'').trim(),form,approver_id:edit.approver_id||null,team_id:edit.team_id||null,warehouse_item_id:edit.warehouse_item_id||null,active:edit.active??true,revision:edit.revision},edit.item_id);setEdit(null);setN(x=>x+1)}catch(e){onFail(e)}finally{setBusy(false)}}
 const setField=(i:number,f:Partial<CatalogField>)=>setEdit(e=>({...e,form:(e?.form??[]).map((x,j)=>j===i?{...x,...f}:x)}));
 return <div className="table-panel"><div className="table-toolbar"><h2>Каталог услуг <span>{items?.length??'…'}</span></h2>{canAdmin?<button className="button small" onClick={()=>setEdit({name:'',description:'',form:[],active:true})}>+ Услуга</button>:null}</div>
  {items&&items.length===0?<div className="empty"><span>☰</span><h3>Услуг пока нет</h3><p>Добавьте услугу — сотрудники закажут её на портале.</p></div>:
  <div className="table-scroll"><table><thead><tr><th>Услуга</th><th>Поля формы</th><th>Согласующий</th><th>Исполнитель</th><th>Склад</th><th>Состояние</th></tr></thead><tbody>{(items??[]).map(it=><tr key={it.item_id}>
   <td>{canAdmin?<button className="asset-link" onClick={()=>setEdit(it)}><strong>{it.name}</strong></button>:<strong>{it.name}</strong>}<small>{it.description}</small></td><td>{it.form.map(f=>f.label).join(', ')||'—'}</td><td>{name(it.approver_id)}</td><td>{name(it.team_id)}</td>
   <td>{it.warehouse_item_id?(wItems.find(w=>w.item_id===it.warehouse_item_id)?.name??'позиция склада'):'—'}</td><td>{it.active?'доступна':'отключена'}</td></tr>)}</tbody></table></div>}
  {edit?<div className="drawer-shade" onClick={()=>setEdit(null)}><aside className="drawer" role="dialog" aria-label="Услуга каталога" onClick={e=>e.stopPropagation()}><header><span className="eyebrow muted">Каталог услуг</span><button className="text-button" onClick={()=>setEdit(null)}>Закрыть</button></header><h2>{edit.item_id?edit.name:'Новая услуга'}</h2>
   <div className="wh-form">
    <label className="wide">Название<input aria-label="Название услуги" value={edit.name??''} onChange={e=>setEdit({...edit,name:e.target.value})} maxLength={128}/></label>
    <label className="wide">Описание<textarea rows={2} value={edit.description??''} onChange={e=>setEdit({...edit,description:e.target.value})} maxLength={4000}/></label>
    <label>Согласующий<select aria-label="Согласующий" value={edit.approver_id??''} onChange={e=>setEdit({...edit,approver_id:e.target.value||null})}><option value="">без согласования</option>{subjects.filter(s=>s.active).map(s=><option key={s.subject_id} value={s.subject_id}>{s.name}{s.kind==='team'?' (команда)':''}</option>)}</select></label>
    <label>Команда-исполнитель<select aria-label="Команда-исполнитель" value={edit.team_id??''} onChange={e=>setEdit({...edit,team_id:e.target.value||null})}><option value="">—</option>{subjects.filter(s=>s.active&&s.kind==='team').map(s=><option key={s.subject_id} value={s.subject_id}>{s.name}</option>)}</select></label>
    <label>Выдача со склада<select aria-label="Позиция склада" value={edit.warehouse_item_id??''} onChange={e=>setEdit({...edit,warehouse_item_id:e.target.value||null})}><option value="">не складская</option>{wItems.filter(w=>w.active).map(w=><option key={w.item_id} value={w.item_id}>{w.name}</option>)}</select></label>
    {edit.item_id?<label className="check"><input type="checkbox" checked={edit.active??true} onChange={e=>setEdit({...edit,active:e.target.checked})}/> доступна на портале</label>:null}
   </div>
   <h3>Поля формы</h3>
   {(edit.form??[]).map((f,i)=><div className="wh-line" key={i}><input aria-label="Ключ поля" className="mono" placeholder="key" value={f.key} onChange={e=>setField(i,{key:e.target.value})}/><input aria-label="Подпись поля" placeholder="Подпись" value={f.label} onChange={e=>setField(i,{label:e.target.value})}/>
    <select aria-label="Тип поля" value={f.type} onChange={e=>setField(i,{type:e.target.value as CatalogField['type']})}><option value="text">строка</option><option value="textarea">текст</option><option value="select">выбор</option></select>
    {f.type==='select'?<input aria-label="Варианты" placeholder="варианты через ;" value={f.options.join(';')} onChange={e=>setField(i,{options:e.target.value.split(';')})}/>:null}
    <label className="check"><input type="checkbox" checked={f.required} onChange={e=>setField(i,{required:e.target.checked})}/> обязательное</label><button className="text-link" onClick={()=>setEdit({...edit,form:(edit.form??[]).filter((_,j)=>j!==i)})}>убрать</button></div>)}
   <button className="text-link" disabled={(edit.form??[]).length>=20} onClick={()=>setEdit({...edit,form:[...(edit.form??[]),blankField()]})}>+ поле</button>
   <button className="button primary" disabled={busy||!(edit.name??'').trim()} onClick={()=>void save()}>Сохранить <span>→</span></button></aside></div>:null}
 </div>;
}

const hm=(m:number)=>String(Math.floor(m/60)).padStart(2,'0')+':'+String(m%60).padStart(2,'0');
const mins=(v:string)=>{const [h,m]=v.split(':').map(Number);return h*60+m};
const dayNames=['пн','вт','ср','чт','пт','сб','вс'];

// SLA: рабочие часы организации и сроки реакции/решения по приоритету (в рабочих часах). Изменяет администратор.
function SlaAdmin({csrf,canAdmin,onFail}:{csrf:string;canAdmin:boolean;onFail:(e:unknown)=>void}){
 const [s,setS]=useState<SlaSettings|null>(null),[busy,setBusy]=useState(false),[saved,setSaved]=useState(false);
 useEffect(()=>{api.sla().then(setS).catch(onFail)},[]);
 if(!s)return null;
 const h=s.hours;
 const setHours=(p:Partial<SlaSettings['hours']>)=>{setSaved(false);setS({...s,hours:{...h,...p}})};
 const setPolicy=(i:number,p:Partial<SlaSettings['policies'][number]>)=>{setSaved(false);setS({...s,policies:s.policies.map((x,j)=>j===i?{...x,...p}:x)})};
 async function save(){if(!s)return;setBusy(true);try{setS(await api.saveSla(csrf,s));setSaved(true)}catch(e){onFail(e)}finally{setBusy(false)}}
 const hours=(m:number)=>Math.round(m/6)/10;
 return <div className="table-panel"><div className="table-toolbar"><h2>SLA</h2>{saved?<span className="muted" role="status">Сохранено</span>:null}</div>
  <div className="wh-form" aria-label="Рабочие часы">
   <label>Часовой пояс<input aria-label="Часовой пояс" disabled={!canAdmin} value={h.timezone} onChange={e=>setHours({timezone:e.target.value})}/></label>
   <label>Начало дня<input aria-label="Начало рабочего дня" type="time" disabled={!canAdmin} value={hm(h.start_minute)} onChange={e=>setHours({start_minute:mins(e.target.value)})}/></label>
   <label>Конец дня<input aria-label="Конец рабочего дня" type="time" disabled={!canAdmin} value={h.end_minute===1440?'23:59':hm(h.end_minute)} onChange={e=>{const v=mins(e.target.value);setHours({end_minute:v===1439?1440:v})}}/></label>
   <label>Предупреждать на, %<input aria-label="Порог предупреждения" type="number" min={50} max={99} disabled={!canAdmin} value={h.warn_percent} onChange={e=>setHours({warn_percent:Number(e.target.value)})}/></label>
   <div className="wide">{dayNames.map((n,i)=><label key={n} className="check"><input type="checkbox" disabled={!canAdmin} checked={h.days.includes(i+1)} onChange={e=>setHours({days:e.target.checked?[...h.days,i+1].sort():h.days.filter(d=>d!==i+1)})}/> {n}</label>)}</div>
  </div>
  <div className="table-scroll"><table><thead><tr><th>Вид</th><th>Приоритет</th><th>Реакция, раб. ч</th><th>Решение, раб. ч</th></tr></thead><tbody>{s.policies.map((p,i)=><tr key={p.kind+p.priority}>
   <td>{p.kind==='incident'?'Инцидент':'Заявка'}</td><td>P{p.priority}</td>
   <td><input aria-label={'Реакция '+p.kind+' P'+p.priority} type="number" min={0.1} step={0.1} disabled={!canAdmin} value={hours(p.response_minutes)} onChange={e=>setPolicy(i,{response_minutes:Math.max(1,Math.round(Number(e.target.value)*60))})}/></td>
   <td><input aria-label={'Решение '+p.kind+' P'+p.priority} type="number" min={0.1} step={0.1} disabled={!canAdmin} value={hours(p.resolution_minutes)} onChange={e=>setPolicy(i,{resolution_minutes:Math.max(1,Math.round(Number(e.target.value)*60))})}/></td></tr>)}</tbody></table></div>
  <p className="muted">Сроки считаются только в рабочие часы; пауза «ждём заявителя» и согласование заявки не считаются. Новые сроки действуют для новых обращений.</p>
  {canAdmin?<button className="button primary" disabled={busy||h.days.length===0} onClick={()=>void save()}>Сохранить SLA <span>→</span></button>:null}
 </div>;
}
