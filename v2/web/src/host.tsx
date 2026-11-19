import {useEffect,useLayoutEffect,useRef,useState,type ReactNode} from 'react';
import {api,ApiError,errorMessage,type Asset,type HostOverview,type InventoryDetail} from './api';
import {TicketDialog,TicketsPanel} from './cards';
import {SoftwareTab,ComponentsTab,RelationsTab,AssetClassBlock} from './cmdb';
import {AssignmentsTab} from './ownership';
import {AssetOperations} from './assetops';
import {PresenceBlock} from './presence';
import {AssetWarehouseBlock} from './warehouse';
import {Inventory12} from './inventory12';
import {AssetRSMBlock} from './rsm';

// C53.03 — карточка хоста по макету C53-mockups/9: шапка (состояние данных, «в сети», разделы), кнопки «Создать
// обращение», «Открыть на схеме», «Собрать сейчас», показатели, вкладки Обзор / Разделы / ПО / Сеть / Пользователи /
// История / Источники / Обращения; «Почему устарело» — из состояния хоста, контакта источников, целей сбора и того,
// что видит обследование сети. Прежние функции карточки (класс, вывод из учёта, ответственность, связи, компоненты,
// склад, разбор сопоставления) — во вкладках «Источники» и «Учёт и связи».

const sectionName:Record<string,string>={identity:'Идентификация',os:'ОС',network:'Сеть',hardware:'Оборудование',software:'ПО',updates:'Обновления',services:'Службы',users_groups:'Пользователи и группы',routes_ports:'Маршруты и порты',resources:'Ресурсы',protection:'Средства защиты',neighbors:'Сетевые соседи'};
const historyName:Record<string,string>={HOSTNAME_CHANGED:'Сменилось имя ПК',ASSET_MERGE:'Слияние карточек',MERGED_INTO_ASSET:'Поглощён другой карточкой',ASSET_SPLIT:'Разделение карточки',AUTO_STRONG_MATCH:'Автопривязка по сильному признаку',BUSINESS_FIELDS_CHANGED:'Изменены поля карточки',ASSET_CLASS_CHANGED:'Изменён класс',ASSET_RETIRED:'Выведен из учёта',ASSET_RESTORED:'Возвращён в учёт',CSV_IMPORT:'Импорт CSV',MANUAL_RECONCILIATION:'Разбор конфликта оператором',RELATION_CHANGED:'Изменены связи',SITE_FALLBACK:'Назначен ответственный площадки',SOURCE_MAPPING:'Привязан источник'};
const when=(v:string|null|undefined)=>v?new Date(v).toLocaleString('ru-RU',{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'}).replace(',',''):'—';
const daysAgo=(v:string|null|undefined)=>v?Math.floor((Date.now()-Date.parse(v))/86400000):null;
const fmt=(n:number)=>n.toLocaleString('ru-RU');
function Kpi({label,children}:{label:string;children:ReactNode}){return <div className="kpi"><small>{label}</small><strong>{children}</strong></div>}
const Err=({e}:{e:unknown})=>e?<div className="error" role="alert">{errorMessage(e)}</div>:null;
function sectionState(s:HostOverview['sections'][number]):[string,string]{
 if(s.status==='unknown'||!s.collected_at)return ['grey','нет данных'];
 if(s.status==='unsupported')return ['grey','не поддерживается'];
 if(s.status==='unavailable')return ['red','недоступен'];
 if(s.status==='not_requested')return ['grey','не запрошен'];
 const d=daysAgo(s.collected_at)!;return d>=1?['red','устарел']:['green','актуален'];
}
const sourceLabel=(kind:string|null,acq:string|null)=>kind==='portable'?'Portable-аудит':kind==='collector'?'Collector':acq==='ssh'?'SSH через collector':acq==='winrm'?'WinRM через collector':acq==='snmp'?'SNMP через collector':'Агент';

type Tab='overview'|'sections'|'software'|'network'|'users'|'history'|'sources'|'tickets'|'accounting';
export function HostCardPage({asset:a,inventory,csrf,canWrite,onClose,onOpenAsset,onOpenTopology,onOpenSystem,onOpenComponent,onExpired}:{asset:Asset;inventory:InventoryDetail|null;csrf:string;canWrite:boolean;onClose:()=>void;onOpenAsset:(uid:string)=>void;onOpenTopology:(focus:string)=>void;onOpenSystem:(uid:string)=>void;onOpenComponent:(id:string,system:string)=>void;onExpired:()=>void}){
 const [tab,setTab]=useState<Tab>('overview'),[d,setD]=useState<HostOverview|null>(null),[error,setError]=useState<unknown>(null),[n,setN]=useState(0),[ticket,setTicket]=useState(false),[note,setNote]=useState(''),[busy,setBusy]=useState(false),[sq,setSq]=useState(''),[hq,setHq]=useState('');
 const close=useRef<HTMLButtonElement>(null);const closeRef=useRef(onClose);closeRef.current=onClose;
 useLayoutEffect(()=>{const previous=document.activeElement as HTMLElement|null;close.current?.focus();function key(e:KeyboardEvent){if(e.key==='Escape')closeRef.current()}document.addEventListener('keydown',key);return()=>{document.removeEventListener('keydown',key);previous?.focus()}},[]);
 useEffect(()=>{let live=true;setError(null);api.hostOverview(a.asset_uid).then(x=>{if(live)setD(x)}).catch(e=>{if(live){setError(e);if(e instanceof ApiError&&e.status===401)onExpired()}});return()=>{live=false}},[a.asset_uid,n]);
 useEffect(()=>{if(!note)return;const t=setTimeout(()=>setNote(''),6000);return()=>clearTimeout(t)},[note]);
 const name=d?.name||a.business.display_name||a.observed_hostname||'Без имени';
 const st=d?.state,reasons=st?.reasons??[],stale=reasons.find(r=>r.code==='INVENTORY_STALE'||r.code==='INVENTORY_LOST');
 const lastInv=a.last_inventory_at??st?.last_inventory_at??null;const ago=daysAgo(lastInv);
 const presence=d?.presence[0];const missing=reasons.some(r=>r.code==='HOST_MISSING')||presence?.state==='missing';
 const collected=d?.sections.filter(s=>s.status==='ok'||s.status==='partial').length??0;
 const primary=d?.bindings.find(b=>b.binding.status==='active'&&b.binding.is_primary)??d?.bindings.find(b=>b.binding.status==='active');
 const sources=inventory?.sources??[];
 async function collect(){setBusy(true);try{const r=await api.assetCollect(a.asset_uid,csrf);setNote(r.requested?'Сбор запрошен: целей сбора — '+r.requested:r.recent?'Сбор уже запрошен недавно — подождите пару минут':r.agents?'У хоста агент — он соберёт данные по своему расписанию':'У хоста нет цели сбора: заведите её в «Обследования сети» или соберите portable-аудитом')}catch(e){setNote(errorMessage(e));if(e instanceof ApiError&&e.status===401)onExpired()}finally{setBusy(false)}}
 // «Почему устарело»: что видно по источникам, целям и сети
 const why:{color:string;text:string;right:string}[]=[];
 for(const s of sources){if(s.source_kind==='agent'&&!s.acquisition||s.acquisition==='agent'){if(s.contact_status!=='recently_seen')why.push({color:'red',text:'Агент не выходит на связь'+(s.last_contact_at?' с '+when(s.last_contact_at):''),right:s.last_contact_at?'последний контакт':'контакта не было'})}}
 for(const t of d?.targets??[]){if(t.last_error)why.push({color:'red',text:'Цель '+t.kind.toUpperCase()+' '+t.address+': ошибка сбора ('+t.last_error+')',right:when(t.last_collected_at)});else if(t.state==='disabled')why.push({color:'yellow',text:'Цель '+t.kind.toUpperCase()+' '+t.address+' отключена',right:''})}
 for(const p of d?.presence??[]){why.push(p.state==='present'?{color:'yellow',text:'Обследование сети видит хост'+(p.ports.length?': порты '+p.ports.join(', ')+' открыты':''),right:when(p.last_seen)}:{color:'red',text:'Обследование сети «'+p.network_name+'» не видит хост',right:when(p.last_seen)})}
 const agentSilent=sources.some(s=>(s.source_kind==='agent'&&(!s.acquisition||s.acquisition==='agent'))&&s.contact_status!=='recently_seen');
 const hint=agentSilent&&presence?.state==='present'?'Вероятно, остановлена служба агента или закрыт порт до collector — хост в сети, но агент не присылает данные.':missing?'Хост не найден в подсети: выключен, переехал или сменил адрес.':(d?.targets??[]).some(t=>t.last_error)?'Проверьте учётку сбора и доступность порта на хосте.':stale?'Источники давно не присылали данные; запросите сбор.':'';
 const winrm=d?.targets.find(t=>t.kind==='winrm'&&t.state!=='disabled');
 const history=[...(lastInv?[{at:lastInv,text:'Последний полный сбор'}]:[]),...(inventory?.history??[]).map(h=>{const det=h.details as {from?:string[];to?:string[]};return {at:h.occurred_at,text:(historyName[h.reason_code]??h.reason_code)+(h.reason_code==='HOSTNAME_CHANGED'&&det.from&&det.to?': '+det.from.join(', ')+' → '+det.to.join(', '):'')}})].sort((x,y)=>y.at.localeCompare(x.at));
 const tabs:[Tab,string][]=[['overview','Обзор'],['sections','Разделы · '+(d?.sections.length??12)],['software','ПО · '+fmt(d?.software_count??0)],['network','Сеть'],['users','Пользователи'],['history','История'],['sources','Источники · '+sources.length],['tickets','Обращения · '+(d?.tickets_total??0)],['accounting','Учёт и связи']];
 const sourcesPanel=<section className="panel"><header><h3>Источники</h3></header><ul className="src-list">{sources.map(s=>{const silent=s.contact_status!=='recently_seen';const dd=daysAgo(s.last_contact_at);return <li key={s.source_id}><span className="src-badge">{s.source_kind==='portable'?'P':s.source_kind==='collector'?'C':s.acquisition&&s.acquisition!=='agent'?s.acquisition[0].toUpperCase():'A'}</span><span>{sourceLabel(s.source_kind,s.acquisition??null)}</span><span className={'src-right'+(silent&&s.source_kind==='agent'?' problem-text':'')}>{silent&&dd!==null&&dd>=1?'нет связи '+dd+' дн':s.last_contact_at?when(s.last_contact_at):'контакта не было'}</span></li>})}{(d?.presence??[]).map(p=><li key={p.network_name+p.ip}><span className="src-badge">D</span><span>Обследование сети {p.network_name}</span><span className="src-right">{when(p.last_seen)}</span></li>)}{sources.length+(d?.presence.length??0)===0?<li className="muted">Источников нет</li>:null}</ul></section>;
 const sectionsTable=(filter:string)=><table className="panel-table"><thead><tr><th>Раздел</th><th>Источник</th><th>Собран</th><th>Состояние</th></tr></thead><tbody>{(d?.sections??[]).filter(s=>!filter||(sectionName[s.name]??s.name).toLowerCase().includes(filter.toLowerCase())).map(s=>{const [c,l]=sectionState(s);return <tr key={s.name}><td>{sectionName[s.name]??s.name}</td><td className="muted">{s.source_kind?sourceLabel(s.source_kind,s.acquisition):'—'}</td><td className="muted">{when(s.collected_at)}</td><td><span className={'hdot h-'+c}/> {l}</td></tr>})}</tbody></table>;
 return <section className="host-page" role="dialog" aria-modal="true" aria-labelledby="card-title">
  <button className="sr-close" ref={close} aria-label="Закрыть карточку" onClick={onClose}>×</button>
  <header className="card-header">
   <small className="kicker">Хост{primary?<> · <button className="link plain" onClick={()=>onOpenSystem(primary.service_uid)}>{primary.system_name}</button> / {primary.environment_name.toLowerCase()} / <button className="link plain" onClick={()=>onOpenComponent(primary.binding.component_id,primary.service_uid)}>{primary.component_name}</button></>:' · вне систем'}</small>
   <div className="card-title"><h1 id="card-title">{name}</h1>
    {stale||a.freshness==='stale'||ago!==null&&ago>=1?<span className="pill pill-bad">данные устарели{ago!==null?' '+ago+' дн':''}</span>:lastInv?<span className="pill pill-ok">данные актуальны</span>:<span className="pill">нет инвентаризации</span>}
    {presence?(missing?<span className="pill pill-bad">не в сети</span>:<span className="pill pill-blue">в сети</span>):null}
    {d?<span className="pill">{collected}/{d.sections.length} разделов</span>:null}
    <span className="title-actions">{canWrite?<button className="button" onClick={()=>setTicket(true)}>Создать обращение</button>:null}<button className="button" onClick={()=>onOpenTopology(d?.ip||name)}>Открыть на схеме</button>{canWrite?<button className="button primary-sm" disabled={busy} onClick={()=>void collect()}>Собрать сейчас</button>:null}</span></div>
   <div className="kpis"><Kpi label="ОС">{d?.os??a.observed_os??<span className="muted">нет сведений</span>}</Kpi><Kpi label="IP / MAC">{[d?.ip,d?.mac].filter(Boolean).join(' · ')||<span className="muted">нет сведений</span>}</Kpi><Kpi label="Домен">{d?.domain||<span className="muted">—</span>}</Kpi><Kpi label="Площадка">{d?.site||<span className="muted">—</span>}</Kpi><Kpi label="Оборудование">{d?.hardware||<span className="muted">нет сведений</span>}</Kpi><Kpi label="Ответственный">{inventory?.accountable.name??<span className="muted">не задан</span>}</Kpi></div>
  </header>
  <div className="card-tabs-bar" role="tablist" aria-label="Разделы карточки">{tabs.map(([k,l])=><button key={k} role="tab" aria-selected={tab===k} className={tab===k?'active':''} onClick={()=>setTab(k)}>{l}</button>)}</div>
  <Err e={error}/>
  {tab==='overview'?<div className="card-grid">
   <div className="card-col">
    <section className="panel"><header><h3>{missing?'Почему пропал':stale||(ago!==null&&ago>=1)?'Почему устарело':'Состояние данных'}</h3></header>
     {why.length===0&&!hint?<p className="pad">{lastInv?'Данные актуальны: последний сбор '+when(lastInv)+'.':'Инвентаризации ещё не было — запросите сбор или соберите portable-аудитом.'}</p>:<ul className="why">{why.map((w,i)=><li key={i}><span className={'hdot h-'+w.color}/><span>{w.text}</span><span className="src-right muted">{w.right}</span></li>)}{hint?<li className="muted hint">{hint}</li>:null}</ul>}
     <div className="why-actions">{winrm&&canWrite?<button className="link" disabled={busy} onClick={()=>void collect()}>Проверить по WinRM</button>:null}{winrm&&canWrite?' · ':''}{canWrite?<button className="link" onClick={()=>setTicket(true)}>Создать обращение</button>:null}</div>
    </section>
    <section className="panel"><header><h3>Разделы профиля</h3><input className="panel-filter" placeholder="Фильтр по разделам" aria-label="Фильтр по разделам" value={sq} onChange={e=>setSq(e.target.value)}/></header>{d?sectionsTable(sq):<p className="muted pad">Загрузка…</p>}</section>
   </div>
   <div className="card-col">{sourcesPanel}
    <section className="panel"><header><h3>История</h3><input className="panel-filter" placeholder="Фильтр" aria-label="Фильтр истории" value={hq} onChange={e=>setHq(e.target.value)}/><button className="link" onClick={()=>setTab('history')}>вся →</button></header>
     {history.length===0?<p className="muted pad">Событий нет.</p>:<table className="panel-table"><thead><tr><th>Когда</th><th>Что</th></tr></thead><tbody>{history.filter(h=>!hq||h.text.toLowerCase().includes(hq.toLowerCase())).slice(0,6).map((h,i)=><tr key={i}><td>{when(h.at)}</td><td>{h.text}</td></tr>)}</tbody></table>}
    </section>
   </div>
  </div>:null}
  {tab==='sections'?<div className="card-pad"><section className="panel"><header><h3>Разделы профиля</h3></header>{d?sectionsTable(''):null}</section><section className="panel"><header><h3>Данные разделов</h3></header><div className="pad"><Inventory12 asset={a.asset_uid} onExpired={onExpired} bare/></div></section></div>:null}
  {tab==='software'?<div className="card-pad"><section className="panel"><header><h3>ПО · {fmt(d?.software_count??0)}</h3></header><div className="pad"><SoftwareTab asset={a.asset_uid} onExpired={onExpired}/></div></section></div>:null}
  {tab==='network'?<div className="card-pad"><section className="panel"><header><h3>Сеть</h3></header><div className="pad"><PresenceBlock asset={a.asset_uid} onExpired={onExpired}/><Inventory12 asset={a.asset_uid} onExpired={onExpired} only={['network','routes_ports','neighbors']} bare/></div></section></div>:null}
  {tab==='users'?<div className="card-pad"><section className="panel"><header><h3>Пользователи и группы</h3></header><div className="pad"><Inventory12 asset={a.asset_uid} onExpired={onExpired} only={['users_groups']} bare/></div></section></div>:null}
  {tab==='history'?<div className="card-pad"><section className="panel"><header><h3>История</h3><input className="panel-filter" placeholder="Фильтр" aria-label="Фильтр истории" value={hq} onChange={e=>setHq(e.target.value)}/></header><table className="panel-table"><thead><tr><th>Когда</th><th>Что</th></tr></thead><tbody>{history.filter(h=>!hq||h.text.toLowerCase().includes(hq.toLowerCase())).map((h,i)=><tr key={i}><td>{when(h.at)}</td><td>{h.text}</td></tr>)}</tbody></table></section>
   {inventory?.hostnames?.length?<section className="panel"><header><h3>Имена ПК</h3></header><table className="panel-table"><tbody>{inventory.hostnames.map((h,i)=><tr key={i}><td className="mono-link">{h.value}</td><td className="muted">{h.valid_to?'было: '+when(h.valid_from)+' — '+when(h.valid_to):'сейчас, с '+when(h.valid_from)}</td></tr>)}</tbody></table></section>:null}</div>:null}
  {tab==='sources'?<div className="card-pad">{sourcesPanel}{(d?.targets.length??0)>0?<section className="panel"><header><h3>Цели сбора</h3></header><table className="panel-table"><thead><tr><th>Вид</th><th>Адрес</th><th>Состояние</th><th>Последний сбор</th><th>Ошибка</th></tr></thead><tbody>{d!.targets.map(t=><tr key={t.target_id}><td>{t.kind.toUpperCase()}</td><td>{t.address}</td><td>{t.state==='active'?'работает':t.state==='pending'?'регистрируется':'отключена'}</td><td className="muted">{when(t.last_collected_at)}</td><td className={t.last_error?'problem-text':'muted'}>{t.last_error??'—'}</td></tr>)}</tbody></table></section>:null}
   <section className="panel"><header><h3>Сопоставление записей источников</h3></header><div className="pad"><AssetOperations asset={a.asset_uid} csrf={csrf} onOpenAsset={onOpenAsset} onExpired={onExpired}/></div></section></div>:null}
  {tab==='tickets'?<div className="card-pad"><TicketsPanel kind="assets" id={a.asset_uid} onCreate={canWrite?()=>setTicket(true):undefined} onExpired={onExpired}/></div>:null}
  {tab==='accounting'?<div className="card-pad"><section className="panel"><div className="pad"><AssetRSMBlock asset={a.asset_uid} onExpired={onExpired}/></div></section><section className="panel"><header><h3>Класс и учёт</h3></header><div className="pad"><AssetClassBlock asset={a.asset_uid} csrf={csrf} onExpired={onExpired}/><AssetWarehouseBlock asset={a.asset_uid} onExpired={onExpired}/></div></section>
   <section className="panel"><header><h3>Ответственность</h3></header><div className="pad"><AssignmentsTab asset={a.asset_uid} csrf={csrf} onExpired={onExpired}/></div></section>
   <section className="panel"><header><h3>Связи</h3></header><div className="pad"><RelationsTab asset={a.asset_uid} csrf={csrf} onOpenAsset={onOpenAsset} onExpired={onExpired}/></div></section>
   <section className="panel"><header><h3>Компоненты (по данным инвентаризации)</h3></header><div className="pad"><ComponentsTab asset={a.asset_uid} onExpired={onExpired}/></div></section></div>:null}
  {ticket?<TicketDialog csrf={csrf} title={name+': '} assetUid={a.asset_uid} onClose={()=>setTicket(false)} onCreated={num=>{setTicket(false);setNote('Создано обращение '+num);setN(x=>x+1)}} onExpired={onExpired}/>:null}
  {note?<p className="rsm-note" role="status">{note} <button className="link" onClick={()=>setNote('')}>скрыть</button></p>:null}
 </section>;
}
