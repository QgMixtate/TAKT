import {useEffect,useState} from 'react';
import {api,ApiError,errorMessage,type PortableScope,type RegistrationCode,type Source} from './api';

// C52.01: установка на площадке — код регистрации (показывается один раз) и отпечаток центра; готовые команды для
// collector (Linux/Windows) и агента (Linux/Windows, MSI для GPO). Файлы установки — раздел «Скачать» (C52.04).
const stateName:Record<RegistrationCode['state'],[string,string]>={active:['действует','state-ok'],exhausted:['исчерпан','state-pending'],expired:['истёк','state-unavailable'],revoked:['отозван','state-unavailable']};
const time=(v:string)=>new Date(v).toLocaleString('ru-RU');

export function InstallPanel({csrf,sources,onExpired,embedded}:{csrf:string;sources:Source[];onExpired:()=>void;embedded?:boolean}){
 const [open,setOpen]=useState(!!embedded),[items,setItems]=useState<RegistrationCode[]>([]),[fp,setFp]=useState(''),[sites,setSites]=useState<PortableScope[]>([]),[error,setError]=useState<unknown>(null),[busy,setBusy]=useState(false),[n,setN]=useState(0);
 const [kind,setKind]=useState<'collector'|'agent'>('collector'),[site,setSite]=useState(''),[collector,setCollector]=useState(''),[platform,setPlatform]=useState<'windows/amd64'|'linux/amd64'>('windows/amd64'),[uses,setUses]=useState(1),[hours,setHours]=useState(24),[comment,setComment]=useState(''),[created,setCreated]=useState<RegistrationCode|null>(null),[centerURL,setCenterURL]=useState(location.origin),[collectorURL,setCollectorURL]=useState('https://collector:8443');
 const [usesOf,setUsesOf]=useState<{id:string;items:{source_id:string;hostname:string;registered_at:string}[]}|null>(null);
 const fail=(e:unknown)=>{setError(e);if(e instanceof ApiError&&e.status===401)onExpired()};
 useEffect(()=>{if(!open)return;api.registrationCodes().then(p=>{setItems(p.items);setFp(p.center_fingerprint)}).catch(fail)},[open,n]);
 useEffect(()=>{if(!open)return;api.portableScopes().then(p=>{setSites(p.items);if(p.items[0]&&!site)setSite(p.items[0].site_id)}).catch(fail)},[open]);
 const collectors=sources.filter(s=>s.source_kind==='collector'&&s.state==='active'&&s.site_id===site);
 useEffect(()=>{setCollector(collectors[0]?.source_id??'')},[site,sources.length]);
 const siteName=(id:string)=>sites.find(s=>s.site_id===id)?.site_name??id.slice(0,8);
 async function create(){setBusy(true);setError(null);try{const c=await api.createRegistrationCode(csrf,{source_kind:kind,site_id:site,collector_source_id:kind==='agent'?collector:undefined,inventory_platform:kind==='agent'?platform:undefined,max_uses:uses,ttl_hours:hours,comment:comment.trim()});setCreated(c);setN(x=>x+1)}catch(e){fail(e)}finally{setBusy(false)}}
 async function revoke(id:string){if(!window.confirm('Отозвать код? Новые установки по нему будут отклонены; уже установленные продолжат работать.'))return;setBusy(true);try{await api.revokeRegistrationCode(csrf,id);setN(x=>x+1)}catch(e){fail(e)}finally{setBusy(false)}}
 const code=created?.code??'КОД',f=created?.center_fingerprint??fp;
 const commands=created?(created.source_kind==='collector'?[
  ['Linux (deb/rpm или архив)',`sudo SURVEYSCAN_REGISTRATION_CODE=${code} surveyscan-collector register --center ${centerURL} --fingerprint ${f} \\\n  --dir /etc/surveyscan-collector --state /var/lib/surveyscan-collector\nsudo systemctl enable --now surveyscan-collector`],
  ['Windows (MSI, тихая установка; установщики — со следующим выпуском C52)',`msiexec /i surveyscan-collector.msi /qn CENTER_URL=${centerURL} REG_CODE=${code} CENTER_FINGERPRINT=${f}`]]:[
  ['Linux (deb/rpm или архив)',`sudo SURVEYSCAN_REGISTRATION_CODE=${code} surveyscan-agent register --collector ${collectorURL} --fingerprint ${f} \\\n  --config /etc/surveyscan-agent/agent.json --state /var/lib/surveyscan-agent\nsudo systemctl enable --now surveyscan-agent`],
  ['Windows (MSI, тихая установка или GPO; установщики — со следующим выпуском C52)',`msiexec /i surveyscan-agent.msi /qn COLLECTOR_URL=${collectorURL} REG_CODE=${code} CENTER_FINGERPRINT=${f}`]]):[];
 return <section className={embedded?'install-panel embedded':'table-panel install-panel'}><div className="table-toolbar"><h2>Установка {embedded?'по коду':<span>коды регистрации</span>}</h2>{embedded?null:<button className="button small" aria-expanded={open} onClick={()=>setOpen(!open)}>{open?'Свернуть':'Открыть'}</button>}</div>{embedded?<p className="muted">Код показывается один раз; в центре хранится только его хеш.</p>:null}
  {open?<div className="portable-body">
   {error?<div className="error" role="alert">{errorMessage(error)}</div>:null}
   <p className="panel-note">Отпечаток центра (проверяется при установке): <span className="mono">{fp||'—'}</span></p>
   <div className="wh-form" aria-label="Новый код регистрации">
    <label>Что ставим<select aria-label="Вид установки" value={kind} onChange={e=>setKind(e.target.value as 'collector'|'agent')}><option value="collector">collector площадки</option><option value="agent">агент на ПК/сервер</option></select></label>
    <label>Площадка<select aria-label="Площадка установки" value={site} onChange={e=>setSite(e.target.value)}>{[...new Map(sites.map(s=>[s.site_id,s])).values()].map(s=><option key={s.site_id} value={s.site_id}>{s.site_name}</option>)}</select></label>
    {kind==='agent'?<><label>Через collector<select aria-label="Collector площадки" value={collector} onChange={e=>setCollector(e.target.value)}>{collectors.length?collectors.map(c=><option key={c.source_id} value={c.source_id}>{c.source_id.slice(0,8)}</option>):<option value="">нет активного collector</option>}</select></label>
     <label>ОС агента<select aria-label="ОС агента" value={platform} onChange={e=>setPlatform(e.target.value as 'windows/amd64'|'linux/amd64')}><option value="windows/amd64">Windows</option><option value="linux/amd64">Linux</option></select></label></>:null}
    <label>Установок по коду<input aria-label="Число установок" type="number" min={1} max={10000} value={uses} onChange={e=>setUses(Number(e.target.value))}/></label>
    <label>Действует, часов<input aria-label="Срок кода" type="number" min={1} max={720} value={hours} onChange={e=>setHours(Number(e.target.value))}/></label>
    <label className="wide">Комментарий<input aria-label="Комментарий к коду" value={comment} maxLength={256} onChange={e=>setComment(e.target.value)} placeholder="например: бухгалтерия, GPO"/></label>
    <div className="wh-submit"><button className="button" disabled={busy||!site||(kind==='agent'&&!collector)||uses<1||hours<1} onClick={()=>void create()}>Создать код</button></div>
   </div>
   {created?<div className="map-notice ok" role="status"><p><strong>Код: <span className="mono">{created.code}</span></strong> — показывается один раз, сохраните его сейчас. Действует до {time(created.expires_at)}, установок: {created.max_uses}.</p>
    {created.source_kind==='collector'?<label>Адрес центра для collector<input aria-label="Адрес центра" className="mono" value={centerURL} onChange={e=>setCenterURL(e.target.value)}/></label>:<label>Адрес collector площадки<input aria-label="Адрес collector" className="mono" value={collectorURL} onChange={e=>setCollectorURL(e.target.value)}/></label>}
    {commands.map(([t,c])=><div key={t}><p className="panel-note">{t}:</p><pre className="mono cmd">{c}</pre></div>)}
    <button className="text-link" onClick={()=>setCreated(null)}>Скрыть код</button></div>:null}
   <div className="table-scroll"><table><thead><tr><th>Создан</th><th>Что</th><th>Площадка</th><th>Установок</th><th>Действует до</th><th>Состояние</th><th>Комментарий</th><th><span className="sr-only">Действия</span></th></tr></thead><tbody>{items.map(c=><tr key={c.code_id}>
    <td className="time">{time(c.created_at)}</td><td>{c.source_kind==='collector'?'collector':'агент'+(c.inventory_platform?(c.inventory_platform.startsWith('windows')?' (Windows)':' (Linux)'):'')}</td><td>{siteName(c.site_id)}</td>
    <td><button className="text-link" onClick={()=>void api.registrationUses(c.code_id).then(p=>setUsesOf({id:c.code_id,items:p.items})).catch(fail)}>{c.used} из {c.max_uses}</button></td>
    <td className="time">{time(c.expires_at)}</td><td><span className={'badge '+stateName[c.state][1]}><i/>{stateName[c.state][0]}</span></td><td>{c.comment||'—'}</td>
    <td>{c.state==='active'?<button className="text-link" disabled={busy} onClick={()=>void revoke(c.code_id)}>Отозвать</button>:null}</td></tr>)}</tbody></table></div>
   {usesOf?<div className="map-notice" role="status">Установки по коду: {usesOf.items.length?usesOf.items.map(u=>u.hostname+' ('+time(u.registered_at)+')').join(', '):'пока нет'} <button className="text-link" onClick={()=>setUsesOf(null)}>скрыть</button></div>:null}
  </div>:null}
 </section>;
}
