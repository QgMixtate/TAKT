import {useEffect,useState} from 'react';
import {api,ApiError,errorMessage,type CatalogItem,type Ticket,type TicketDetail} from './api';

// Портал заявителя (W3, вход учёткой AD): свои обращения — список, новое, карточка с перепиской и подтверждением
// решения; каталог услуг с формой заявки (C48); заявки, ждущие решения сотрудника как согласующего. Реестр, склад и очереди операторов заявителю недоступны (проверяется на сервере).

const stateName:Record<string,string>={new:'зарегистрировано',assigned:'назначено',in_progress:'в работе',waiting_customer:'ждём вашего ответа',resolved:'решено — подтвердите',closed:'закрыто',cancelled:'отменено',pending_approval:'на согласовании',in_fulfillment:'выполняется',fulfilled:'выполнено — подтвердите',rejected:'отклонено'};
const fmt=(v:string)=>new Date(v).toLocaleString('ru-RU');

export function PortalView({csrf,onLogout}:{csrf:string;onLogout:()=>void}){
 const [items,setItems]=useState<Ticket[]|null>(null),[open,setOpen]=useState<TicketDetail|null>(null),[error,setError]=useState<unknown>(null),[n,setN]=useState(0);
 const [title,setTitle]=useState(''),[desc,setDesc]=useState(''),[urgency,setUrgency]=useState(2),[busy,setBusy]=useState(false),[text,setText]=useState('');
 const [catalog,setCatalog]=useState<CatalogItem[]>([]),[service,setService]=useState<CatalogItem|null>(null),[values,setValues]=useState<Record<string,string>>({}),[approvals,setApprovals]=useState<Ticket[]>([]);
 const fail=(e:unknown)=>{setError(e);if(e instanceof ApiError&&e.status===401)onLogout()};
 useEffect(()=>{api.portalTickets().then(p=>setItems(p.items)).catch(fail);api.portalApprovals().then(p=>setApprovals(p.items)).catch(fail)},[n]);
 useEffect(()=>{api.portalCatalog().then(p=>setCatalog(p.items)).catch(fail)},[]);
 async function decide(t:Ticket,approve:boolean){let comment='';if(!approve){comment=(window.prompt('Причина отклонения (обязательно):')??'').trim();if(!comment)return}setBusy(true);setError(null);try{await api.portalApprove(csrf,t.ticket_id,{revision:t.revision,approve,comment});setN(x=>x+1)}catch(e){fail(e);setN(x=>x+1)}finally{setBusy(false)}}
 const missing=service?service.form.some(f=>f.required&&!(values[f.key]??'').trim()):true;
 async function run(fn:()=>Promise<TicketDetail>){setBusy(true);setError(null);try{setOpen(await fn());setN(x=>x+1)}catch(e){fail(e)}finally{setBusy(false)}}
 return <main className="portal">
  <header className="portal-head"><strong>Обращения в ИТ</strong><button className="text-button" onClick={onLogout}>Выйти</button></header>
  {error?<div className="error" role="alert">{errorMessage(error)}</div>:null}
  {open?<section className="table-panel portal-card"><div className="table-toolbar"><h2>{open.number} · {open.title}</h2><button className="text-button" onClick={()=>setOpen(null)}>к списку</button></div>
   <p className="portal-state">{stateName[open.state]??open.state}</p>{open.description?<p>{open.description}</p>:null}
   {open.resolution?<p><strong>Решение:</strong> {open.resolution}</p>:null}
   {open.request?.approval?<p className="muted">{open.request.approval.decision==='approved'?'Согласовано':'Отклонено'}{open.request.approval.comment?': '+open.request.approval.comment:''}</p>:null}
   {open.state==='resolved'||open.state==='fulfilled'?<div className="portal-confirm"><button className="button small" disabled={busy} onClick={()=>void run(()=>api.portalAction(csrf,open.ticket_id,'confirm',{revision:open.revision,solved:true}))}>{open.state==='fulfilled'?'Получено, спасибо':'Решено, спасибо'}</button>
    <button className="button small" disabled={busy} onClick={()=>{const t=(window.prompt('Что не так?')??'').trim();void run(()=>api.portalAction(csrf,open.ticket_id,'confirm',{revision:open.revision,solved:false,text:t}))}}>{open.state==='fulfilled'?'Не выполнено':'Не решено'}</button></div>:null}
   <ul className="ticket-feed">{open.events.filter(e=>e.kind==='comment'||e.kind==='created'||e.kind==='state'||e.kind==='approval').map(e=><li key={e.event_id}><small>{fmt(e.occurred_at)}</small><span>{e.kind==='comment'?e.text:e.kind==='created'?'Обращение зарегистрировано':e.kind==='approval'?(e.detail.decision==='approved'?'Согласовано':'Отклонено')+(e.text?' — '+e.text:''):'Состояние: '+(stateName[String(e.detail.to)]??String(e.detail.to))+(e.text?' — '+e.text:'')}</span></li>)}</ul>
   {open.state!=='closed'&&open.state!=='cancelled'?<div className="ticket-comment"><textarea aria-label="Сообщение" rows={3} value={text} onChange={e=>setText(e.target.value)} placeholder="Сообщение для ИТ"/><button className="button small" disabled={busy||!text.trim()} onClick={()=>{const t=text.trim();setText('');void run(()=>api.portalAction(csrf,open.ticket_id,'comments',{text:t}))}}>Отправить</button></div>:null}
  </section>:service?<section className="table-panel portal-card"><div className="table-toolbar"><h2>{service.name}</h2><button className="text-button" onClick={()=>setService(null)}>к списку</button></div>
   {service.description?<p>{service.description}</p>:null}
   <div className="wh-form">{service.form.map(f=><label key={f.key} className={f.type==='textarea'?'wide':''}>{f.label}{f.required?' *':''}
    {f.type==='select'?<select aria-label={f.label} value={values[f.key]??''} onChange={e=>setValues({...values,[f.key]:e.target.value})}><option value="">—</option>{f.options.map(o=><option key={o} value={o}>{o}</option>)}</select>:
    f.type==='textarea'?<textarea aria-label={f.label} rows={3} value={values[f.key]??''} onChange={e=>setValues({...values,[f.key]:e.target.value})} maxLength={1000}/>:<input aria-label={f.label} value={values[f.key]??''} onChange={e=>setValues({...values,[f.key]:e.target.value})} maxLength={1000}/>}</label>)}
    <label>Насколько срочно<select aria-label="Срочность заявки" value={urgency} onChange={e=>setUrgency(Number(e.target.value))}><option value={1}>очень срочно</option><option value={2}>в ближайшие дни</option><option value={3}>не срочно</option></select></label>
    <div className="wh-submit"><button className="button" disabled={busy||missing} onClick={()=>void run(async()=>{const form_values=Object.fromEntries(Object.entries(values).map(([k,v])=>[k,v.trim()]).filter(([,v])=>v));const d=await api.portalRequest(csrf,{catalog_item_id:service.item_id,form_values,urgency});setService(null);setValues({});return d})}>Отправить заявку</button></div></div>
  </section>:<>
   {approvals.length?<section className="table-panel"><div className="table-toolbar"><h2>Ждут вашего согласования <span>{approvals.length}</span></h2></div><div className="table-scroll"><table><thead><tr><th>Номер</th><th>Заявка</th><th>Создано</th><th><span className="sr-only">Решение</span></th></tr></thead><tbody>{approvals.map(t=><tr key={t.ticket_id}><td className="mono">{t.number}</td><td><strong>{t.title}</strong><small style={{whiteSpace:'pre-line'}}>{t.description}</small></td><td className="time">{fmt(t.created_at)}</td>
    <td><button className="button small" disabled={busy} onClick={()=>void decide(t,true)}>Согласовать</button> <button className="button small" disabled={busy} onClick={()=>void decide(t,false)}>Отклонить</button></td></tr>)}</tbody></table></div></section>:null}
   {catalog.length?<section className="table-panel"><div className="table-toolbar"><h2>Заказать услугу</h2></div><div className="table-scroll"><table><tbody>{catalog.map(c=><tr key={c.item_id}><td><button className="asset-link" onClick={()=>{setService(c);setValues({});setUrgency(3)}}><span><strong>{c.name}</strong><small>{c.description}</small></span></button></td></tr>)}</tbody></table></div></section>:null}
   <section className="table-panel"><div className="table-toolbar"><h2>Сообщить о проблеме</h2></div><div className="wh-form">
    <label className="wide">Что случилось<input aria-label="Тема обращения" value={title} onChange={e=>setTitle(e.target.value)} maxLength={256} placeholder="Например: не работает VPN"/></label>
    <label className="wide">Подробности<textarea aria-label="Подробности" rows={3} value={desc} onChange={e=>setDesc(e.target.value)} maxLength={8000}/></label>
    <label>Насколько срочно<select aria-label="Срочность" value={urgency} onChange={e=>setUrgency(Number(e.target.value))}><option value={1}>не могу работать</option><option value={2}>мешает работе</option><option value={3}>не срочно</option></select></label>
    <div className="wh-submit"><button className="button" disabled={busy||!title.trim()} onClick={()=>void run(async()=>{const d=await api.portalCreate(csrf,{title:title.trim(),description:desc.trim(),urgency});setTitle('');setDesc('');return d})}>Отправить в ИТ</button></div></div></section>
   <section className="table-panel"><div className="table-toolbar"><h2>Мои обращения <span>{items?.length??'…'}</span></h2></div>
    {items&&items.length===0?<div className="empty"><span>☏</span><h3>Обращений пока нет</h3></div>:<div className="table-scroll"><table><thead><tr><th>Номер</th><th>Тема</th><th>Состояние</th><th>Создано</th></tr></thead><tbody>{(items??[]).map(t=><tr key={t.ticket_id}><td><button className="asset-link" onClick={()=>void api.portalTicket(t.ticket_id).then(setOpen).catch(fail)}><strong className="mono">{t.number}</strong></button></td><td>{t.title}</td><td>{stateName[t.state]??t.state}</td><td className="time">{fmt(t.created_at)}</td></tr>)}</tbody></table></div>}</section>
  </>}
 </main>;
}
