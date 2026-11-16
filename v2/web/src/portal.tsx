import {useEffect,useState} from 'react';
import {api,ApiError,errorMessage,type Ticket,type TicketDetail} from './api';

// Портал заявителя (W3, вход учёткой AD): свои обращения — список, новое, карточка с перепиской и подтверждением
// решения. Реестр, склад и очереди операторов заявителю недоступны (проверяется на сервере).

const stateName:Record<string,string>={new:'зарегистрировано',assigned:'назначено',in_progress:'в работе',waiting_customer:'ждём вашего ответа',resolved:'решено — подтвердите',closed:'закрыто',cancelled:'отменено'};
const fmt=(v:string)=>new Date(v).toLocaleString('ru-RU');

export function PortalView({csrf,onLogout}:{csrf:string;onLogout:()=>void}){
 const [items,setItems]=useState<Ticket[]|null>(null),[open,setOpen]=useState<TicketDetail|null>(null),[error,setError]=useState<unknown>(null),[n,setN]=useState(0);
 const [title,setTitle]=useState(''),[desc,setDesc]=useState(''),[urgency,setUrgency]=useState(2),[busy,setBusy]=useState(false),[text,setText]=useState('');
 const fail=(e:unknown)=>{setError(e);if(e instanceof ApiError&&e.status===401)onLogout()};
 useEffect(()=>{api.portalTickets().then(p=>setItems(p.items)).catch(fail)},[n]);
 async function run(fn:()=>Promise<TicketDetail>){setBusy(true);setError(null);try{setOpen(await fn());setN(x=>x+1)}catch(e){fail(e)}finally{setBusy(false)}}
 return <main className="portal">
  <header className="portal-head"><strong>Обращения в ИТ</strong><button className="text-button" onClick={onLogout}>Выйти</button></header>
  {error?<div className="error" role="alert">{errorMessage(error)}</div>:null}
  {open?<section className="table-panel portal-card"><div className="table-toolbar"><h2>{open.number} · {open.title}</h2><button className="text-button" onClick={()=>setOpen(null)}>к списку</button></div>
   <p className="portal-state">{stateName[open.state]??open.state}</p>{open.description?<p>{open.description}</p>:null}
   {open.resolution?<p><strong>Решение:</strong> {open.resolution}</p>:null}
   {open.state==='resolved'?<div className="portal-confirm"><button className="button small" disabled={busy} onClick={()=>void run(()=>api.portalAction(csrf,open.ticket_id,'confirm',{revision:open.revision,solved:true}))}>Решено, спасибо</button>
    <button className="button small" disabled={busy} onClick={()=>{const t=(window.prompt('Что не так?')??'').trim();void run(()=>api.portalAction(csrf,open.ticket_id,'confirm',{revision:open.revision,solved:false,text:t}))}}>Не решено</button></div>:null}
   <ul className="ticket-feed">{open.events.filter(e=>e.kind==='comment'||e.kind==='created'||e.kind==='state').map(e=><li key={e.event_id}><small>{fmt(e.occurred_at)}</small><span>{e.kind==='comment'?e.text:e.kind==='created'?'Обращение зарегистрировано':'Состояние: '+(stateName[String(e.detail.to)]??String(e.detail.to))+(e.text?' — '+e.text:'')}</span></li>)}</ul>
   {open.state!=='closed'&&open.state!=='cancelled'?<div className="ticket-comment"><textarea aria-label="Сообщение" rows={3} value={text} onChange={e=>setText(e.target.value)} placeholder="Сообщение для ИТ"/><button className="button small" disabled={busy||!text.trim()} onClick={()=>{const t=text.trim();setText('');void run(()=>api.portalAction(csrf,open.ticket_id,'comments',{text:t}))}}>Отправить</button></div>:null}
  </section>:<>
   <section className="table-panel"><div className="table-toolbar"><h2>Новое обращение</h2></div><div className="wh-form">
    <label className="wide">Что случилось<input aria-label="Тема обращения" value={title} onChange={e=>setTitle(e.target.value)} maxLength={256} placeholder="Например: не работает VPN"/></label>
    <label className="wide">Подробности<textarea aria-label="Подробности" rows={3} value={desc} onChange={e=>setDesc(e.target.value)} maxLength={8000}/></label>
    <label>Насколько срочно<select aria-label="Срочность" value={urgency} onChange={e=>setUrgency(Number(e.target.value))}><option value={1}>не могу работать</option><option value={2}>мешает работе</option><option value={3}>не срочно</option></select></label>
    <div className="wh-submit"><button className="button" disabled={busy||!title.trim()} onClick={()=>void run(async()=>{const d=await api.portalCreate(csrf,{title:title.trim(),description:desc.trim(),urgency});setTitle('');setDesc('');return d})}>Отправить в ИТ</button></div></div></section>
   <section className="table-panel"><div className="table-toolbar"><h2>Мои обращения <span>{items?.length??'…'}</span></h2></div>
    {items&&items.length===0?<div className="empty"><span>☏</span><h3>Обращений пока нет</h3></div>:<div className="table-scroll"><table><thead><tr><th>Номер</th><th>Тема</th><th>Состояние</th><th>Создано</th></tr></thead><tbody>{(items??[]).map(t=><tr key={t.ticket_id}><td><button className="asset-link" onClick={()=>void api.portalTicket(t.ticket_id).then(setOpen).catch(fail)}><strong className="mono">{t.number}</strong></button></td><td>{t.title}</td><td>{stateName[t.state]??t.state}</td><td className="time">{fmt(t.created_at)}</td></tr>)}</tbody></table></div>}</section>
  </>}
 </main>;
}
