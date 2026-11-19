import {useEffect,useState} from 'react';
import {api,ApiError,type Conflict,type InventoryDetail} from './api';
import {Err,Panel,Pill,Split,StateDot,Strip,fmt} from './ui';

// C25.02 + C53.07 (макет «Разбор конфликтов»): очередь записей источников, которые не сопоставились с активом
// автоматически. Справа — сравнение признаков записи (из её последнего наблюдения) с карточкой-кандидатом и решение.
const reasons:Record<string,[string,string]>={IDENTITY_CONFLICT:['Признаки совпадают с несколькими активами','Сильные признаки записи указывают на существующие карточки, но свести автоматически нельзя — решает оператор.']};
const states:[Conflict['state'],string][]=[['open','открытых'],['resolved','разобрано'],['dismissed','отложено']];
const idNames:Record<string,string>={hostname:'Имя ПК',fqdn:'FQDN',mac:'MAC',machine_uuid:'Machine UUID',bios_uuid:'BIOS UUID',serial:'Серийный номер',serial_number:'Серийный номер',ip:'IP'};
type Cand={detail:InventoryDetail|null;error:unknown};

function candidateValues(d:InventoryDetail,kind:string):string[]{
 const a=d.asset;
 if(kind==='hostname'||kind==='fqdn')return [...new Set([a.observed_hostname,...(d.hostnames??[]).filter(h=>!h.valid_to).map(h=>h.value)].filter((x):x is string=>!!x))];
 if(kind==='mac')return d.facts.filter(f=>f.key.endsWith('.mac')).map(f=>f.value);
 if(kind==='ip')return d.facts.filter(f=>f.key.endsWith('.addresses')).flatMap(f=>{try{return (JSON.parse(f.value) as {ip:string}[]).map(x=>x.ip)}catch{return []}});
 return [];
}
const norm=(v:string)=>v.toLowerCase().replace(/[-:.]/g,'');

export function ReconciliationView({csrf,onOpenAsset,onExpired}:{csrf:string;onOpenAsset:(uid:string)=>void;onExpired:()=>void}){
 const [state,setState]=useState<Conflict['state']>('open'),[items,setItems]=useState<Conflict[]>([]),[counts,setCounts]=useState<Record<string,string>>({}),[loading,setLoading]=useState(true),[error,setError]=useState<unknown>(null),[notice,setNotice]=useState(''),[busy,setBusy]=useState(false),[refresh,setRefresh]=useState(0),[sel,setSel]=useState<string|null>(null),[q,setQ]=useState(''),[cand,setCand]=useState<Record<string,Cand>>({}),[pick,setPick]=useState<string|null>(null);
 useEffect(()=>{let active=true;setLoading(true);setError(null);
  Promise.all(states.map(([s])=>api.conflicts(s))).then(ps=>{if(!active)return;const c:Record<string,string>={};ps.forEach((p,i)=>{c[states[i][0]]=p.items.length+(p.next_cursor?'+':'')});setCounts(c);const cur=ps[states.findIndex(s=>s[0]===state)];setItems(cur.items);setSel(x=>cur.items.some(i=>i.conflict_id===x)?x:cur.items[0]?.conflict_id??null)})
  .catch(e=>{if(active){setError(e);if(e instanceof ApiError&&e.status===401)onExpired()}}).finally(()=>{if(active)setLoading(false)});return()=>{active=false}},[state,refresh]);
 const c=items.find(i=>i.conflict_id===sel)??null;
 const uids=c?[...new Set([...(c.asset_uid?[c.asset_uid]:[]),...c.candidate_asset_uids])]:[];
 useEffect(()=>{setPick(uids[0]??null);for(const uid of uids)if(!cand[uid])api.inventory(uid).then(d=>setCand(x=>({...x,[uid]:{detail:d,error:null}}))).catch(e=>{setCand(x=>({...x,[uid]:{detail:null,error:e}}));if(e instanceof ApiError&&e.status===401)onExpired()})},[sel]);
 async function act(action:string,asset?:string){
  if(!c)return;const what=action==='attach'?'привязать запись к выбранной карточке':action==='create_asset'?'создать для записи новый актив':action==='confirm'?'подтвердить текущую привязку':'отложить конфликт';
  if(!window.confirm('Подтвердите: '+what+'. Решение попадёт в историю и аудит.'))return;
  setBusy(true);setError(null);setNotice('');
  try{const r=await api.resolveConflict(c.conflict_id,csrf,{action,...(asset?{asset_uid:asset}:{}),revision:c.revision});setNotice(action==='dismiss'?'Конфликт отложен.':`Готово: запись привязана к активу${r.asset_uid?' '+r.asset_uid.slice(0,8):''}, применено наблюдений: ${r.replayed_observations}.`);setRefresh(n=>n+1)}
  catch(e){setError(e);if(e instanceof ApiError&&e.status===401)onExpired()}finally{setBusy(false)}
 }
 const shown=items.filter(i=>!q||[i.observed_hostname,i.source_local_id,i.namespace,...(i.identifiers??[]).map(x=>x.value)].some(v=>v&&v.toLowerCase().includes(q.toLowerCase())));
 const pd=pick?cand[pick]?.detail:null;
 const ids=c?.identifiers??(c?.observed_hostname?[{kind:'hostname',value:c.observed_hostname}]:[]);
 const side=c?<>
  <div><h2>{reasons[c.reason_code]?.[0]??c.reason_code}</h2><p className="sub">{reasons[c.reason_code]?.[1]??''}</p></div>
  {uids.length>1?<label className="form-grid"><span className="muted">Сравнить с карточкой</span><select value={pick??''} onChange={e=>setPick(e.target.value)}>{uids.map(u=><option key={u} value={u}>{cand[u]?.detail?.asset.observed_hostname??u.slice(0,8)}{u===c.asset_uid?' (текущая)':''}</option>)}</select></label>:null}
  <Panel title="Сравнение" flush>{!ids.length?<p className="muted pad">У записи нет признаков в ожидающих наблюдениях.</p>:<table className="panel-table"><thead><tr><th>Признак</th><th>Запись источника</th><th/><th>{pick?<button className="link" onClick={()=>onOpenAsset(pick)}>Карточка {pd?.asset.observed_hostname??pick.slice(0,8)}</button>:'Карточка'}</th></tr></thead><tbody>
   {ids.map((x,i)=>{const vals=pd?candidateValues(pd,x.kind):[];const same=vals.some(v=>norm(v)===norm(x.value));const known=vals.length>0;return <tr key={i}><td className="muted">{idNames[x.kind]??x.kind}</td><td className="mono">{x.value}</td><td className={same?'eq':known?'neq':'muted'}>{same?'=':known?'≠':'?'}</td><td className={known?'':'muted'}>{pd?(known?vals.slice(0,2).join(', '):'нет в карточке'):cand[pick??'']?.error?'недоступна':'…'}</td></tr>})}
   <tr><td className="muted">Источник</td><td>{c.namespace} · {c.source_local_id}</td><td/><td className="muted">{pd?pd.sources.length+' источн.':''}</td></tr></tbody></table>}</Panel>
  <Panel title="Что будет"><ul className="plain-list">{c.state!=='open'?<li>Конфликт {c.state==='resolved'?'разобран':'отложен'}.</li>:c.asset_uid?<><li>Запись уже привязана к карточке; подтверждение снимет её из очереди</li></>:<><li>Ожидающие наблюдения ({c.pending_observations}) применятся к выбранной карточке</li><li>Источник будет писать в эту карточку и дальше</li><li>Решение записывается в историю актива и аудит</li></>}</ul></Panel>
  {c.state==='open'?<div className="form-row">{!c.asset_uid&&pick?<button className="button primary-sm" disabled={busy} onClick={()=>void act('attach',pick)}>Привязать к карточке {pd?.asset.observed_hostname??pick.slice(0,8)}</button>:null}
   {c.asset_uid?<button className="button primary-sm" disabled={busy} onClick={()=>void act('confirm')}>Подтвердить текущую привязку</button>:<button className="button" disabled={busy||!c.pending_observations} title={c.pending_observations?'':'Нет ожидающих наблюдений, по которым можно создать актив'} onClick={()=>void act('create_asset')}>Это другое устройство — новый актив</button>}
   <button className="link" disabled={busy} onClick={()=>void act('dismiss')}>Отложить</button></div>:null}
 </>:<div className="empty"><span>✓</span><h3>{state==='open'?'Разбирать нечего':'Пусто'}</h3><p>{state==='open'?'Все записи источников сопоставлены с активами автоматически.':'В этом состоянии конфликтов нет.'}</p></div>;
 return <>
  <Strip label="Сводка конфликтов" items={states.map(([k,l])=>({key:k,n:counts[k]??null,label:l,tone:k==='open'?'warn':'muted',active:state===k,onClick:()=>setState(k)}))} right={<button className="button" disabled={loading} onClick={()=>setRefresh(n=>n+1)}>Обновить</button>}/>
  <Split wide side={side}>
   <div className="systems-toolbar"><input className="toolbar-search" aria-label="Фильтр конфликтов" placeholder="Хост, MAC, серийный, источник" value={q} onChange={e=>setQ(e.target.value)}/></div>
   <Err e={error}/>{notice?<div className="notice" role="status">{notice}</div>:null}
   {loading?<div className="empty" role="status">Загружаем очередь…</div>:<div className="table-scroll panel"><table className="panel-table"><thead><tr><th/><th>Конфликт</th><th>Объект</th><th>Источник</th><th className="num">Ожидает</th><th className="num">Кандидатов</th></tr></thead><tbody>
    {shown.map(i=><tr key={i.conflict_id} className={i.conflict_id===sel?'selected':''} onClick={()=>setSel(i.conflict_id)}><td><StateDot tone={i.state==='open'?(i.asset_uid?'amber':'red'):'grey'}/></td><td><button className="link plain" onClick={()=>setSel(i.conflict_id)}>{reasons[i.reason_code]?.[0]??i.reason_code}</button></td><td className="mono">{i.observed_hostname||i.source_local_id}</td><td>{i.namespace}</td><td className="num">{fmt(i.pending_observations)}</td><td className="num">{i.candidate_asset_uids.length}{i.asset_uid?<> <Pill>привязана</Pill></>:null}</td></tr>)}
   </tbody></table>{!shown.length?<p className="muted pad">{items.length?'Нет совпадений с фильтром.':'Конфликтов в этом состоянии нет.'}</p>:null}</div>}
   <p className="muted">Автоматически сводятся только записи разных источников с единственным надёжным сильным признаком (machine UUID, BIOS UUID, серийный номер). Остальное — сюда: решение оператора записывается в историю актива и аудит.</p>
  </Split></>;
}
