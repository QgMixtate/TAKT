import {useEffect,useState} from 'react';
import {createPortal} from 'react-dom';
import {api,ApiError,UserError,errorMessage,type Subject,type WLocation,type WItem,type WUnit,type WStock,type WMovement,type WOperation,type WReservation,type WInventory,type WInventoryDetail} from './api';

// Волна 2: склад и жизненный цикл оборудования (decisions/C41-w2-scope-and-model.md). Операции — одной записью журнала
// с номером акта; акт печатается из браузера («Печать» → «Сохранить как PDF»).

const stateName:Record<WUnit['state'],[string,string]>={in_stock:['на складе','state-ok'],reserved:['в резерве','state-partial'],issued:['выдан','state-active'],installed:['установлен','state-active'],in_repair:['в ремонте','state-partial'],written_off:['списан','state-unavailable'],lost:['утерян','state-unavailable']};
export const kindName:Record<WMovement['kind'],string>={receive:'Приход',issue:'Выдача',return:'Возврат',transfer:'Перемещение',repair_out:'В ремонт',repair_in:'Из ремонта',install:'Установка на актив',remove:'Снятие с актива',write_off:'Списание',adjust:'Корректировка',reverse:'Сторно'};
const actTitle:Partial<Record<WMovement['kind'],string>>={receive:'Акт приёма на склад',issue:'Акт выдачи',return:'Акт возврата',transfer:'Акт перемещения',repair_out:'Акт передачи в ремонт',repair_in:'Акт приёма из ремонта',install:'Акт установки комплектующего',remove:'Акт снятия комплектующего',write_off:'Акт списания'};
const fmt=(v:string)=>new Date(v).toLocaleString('ru-RU');
type Tab='units'|'stock'|'reservations'|'inventory'|'operation'|'journal'|'catalog';
type Ref={locations:WLocation[];items:WItem[];subjects:Subject[]};

export function WarehouseView({csrf,canWrite,isAdmin,onOpenAsset,onExpired}:{csrf:string;canWrite:boolean;isAdmin:boolean;onOpenAsset:(uid:string)=>void;onExpired:()=>void}){
 const [tab,setTab]=useState<Tab>('units'),[ref,setRef]=useState<Ref|null>(null),[error,setError]=useState<unknown>(null),[act,setAct]=useState<WMovement|null>(null),[version,setVersion]=useState(0);
 const fail=(e:unknown)=>{setError(e);if(e instanceof ApiError&&e.status===401)onExpired()};
 useEffect(()=>{Promise.all([api.wLocations(),api.wItems(),api.subjects()]).then(([l,i,s])=>setRef({locations:l.items,items:i.items,subjects:s.items})).catch(fail)},[version]);
 if(!ref)return error?<div className="error" role="alert">{errorMessage(error)}</div>:<p className="muted">Загрузка…</p>;
 const openAct=(id:string)=>api.wMovement(id).then(setAct).catch(fail);
 return <div className="stack warehouse">
  {error?<div className="error" role="alert">{errorMessage(error)}</div>:null}
  <div className="tabs" role="tablist">{([['units','Экземпляры'],['stock','Остатки'],['reservations','Резервы'],['inventory','Инвентаризация'],['operation','Операция'],['journal','Журнал и акты'],['catalog','Справочники']] as [Tab,string][]).filter(([t])=>t!=='operation'||canWrite).map(([t,n])=><button key={t} role="tab" aria-selected={tab===t} className={tab===t?'active':''} onClick={()=>setTab(t)}>{n}</button>)}</div>
  {tab==='units'?<Units ref_={ref} onOpenAsset={onOpenAsset} onFail={fail}/>:tab==='stock'?<Stock ref_={ref} onFail={fail}/>:tab==='reservations'?<Reservations ref_={ref} csrf={csrf} canWrite={canWrite} onFail={fail}/>:tab==='inventory'?<InventoryTab ref_={ref} csrf={csrf} canWrite={canWrite} isAdmin={isAdmin} onAct={id=>void openAct(id)} onFail={fail}/>:tab==='operation'?<OperationForm ref_={ref} csrf={csrf} isAdmin={isAdmin} onFail={fail} onDone={m=>{setAct(m);setVersion(v=>v+1)}}/>:tab==='journal'?<Journal ref_={ref} csrf={csrf} canWrite={canWrite} onOpen={id=>void openAct(id)} onReversed={m=>setAct(m)} onFail={fail}/>:<Catalog ref_={ref} csrf={csrf} isAdmin={isAdmin} onFail={fail} onChanged={()=>setVersion(v=>v+1)}/>}
  {act?<ActView act={act} ref_={ref} onClose={()=>setAct(null)}/>:null}
 </div>;
}

const locName=(r:Ref,id:string|null)=>{if(!id)return '—';const l=r.locations.find(x=>x.location_id===id);if(!l)return id.slice(0,8);const p=l.parent_id?r.locations.find(x=>x.location_id===l.parent_id):null;return (p?p.name+' / ':'')+l.name};
const subjName=(r:Ref,id:string|null)=>id?(r.subjects.find(s=>s.subject_id===id)?.name??id.slice(0,8)):'—';

function Units({ref_:r,onOpenAsset,onFail}:{ref_:Ref;onOpenAsset:(uid:string)=>void;onFail:(e:unknown)=>void}){
 const [state,setState]=useState(''),[q,setQ]=useState(''),[holder,setHolder]=useState(''),[items,setItems]=useState<WUnit[]|null>(null);
 useEffect(()=>{const t=setTimeout(()=>api.wUnits({state,q,holder}).then(p=>setItems(p.items)).catch(onFail),250);return()=>clearTimeout(t)},[state,q,holder]);
 // отчёт C45.02: текущая выборка в CSV (Excel открывает UTF-8 с BOM; разделитель «;»)
 function csv(){const cell=(v:string)=>'"'+v.replace(/"/g,'""')+'"';const rows=[['Модель','Серийный','Инв. №','Состояние','Где / у кого','Актив'],...(items??[]).map(u=>[u.item_name,u.serial,u.inventory_no??'',stateName[u.state][0],u.location_id?locName(r,u.location_id):u.holder_id?subjName(r,u.holder_id):u.installed_on?'на активе '+u.installed_on:'',u.asset_uid??''])];
  const blob=new Blob(['\ufeff'+rows.map(x=>x.map(cell).join(';')).join('\r\n')],{type:'text/csv;charset=utf-8'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='склад-экземпляры.csv';a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000)}
 return <div className="table-panel"><div className="table-toolbar"><h2>Серийные экземпляры <span>{items?.length??'…'}</span></h2><div className="filters">
  <label className="search-field"><span>⌕</span><input aria-label="Поиск экземпляра" placeholder="Серийный, инвентарный, модель…" value={q} onChange={e=>setQ(e.target.value)}/></label>
  <select aria-label="Состояние" value={state} onChange={e=>setState(e.target.value)}><option value="">Все состояния</option>{Object.entries(stateName).map(([k,[n]])=><option key={k} value={k}>{n}</option>)}</select>
  <select aria-label="За кем числится" value={holder} onChange={e=>setHolder(e.target.value)}><option value="">За всеми</option>{r.subjects.map(s=><option key={s.subject_id} value={s.subject_id}>{s.name}</option>)}</select>
  <button className="button small" disabled={!items?.length} onClick={csv}>CSV</button></div></div>
  {items&&items.length===0?<div className="empty"><span>▦</span><h3>Экземпляров нет</h3><p>Оформите приход на вкладке «Операция».</p></div>:
  <div className="table-scroll"><table><thead><tr><th>Модель</th><th>Серийный / инв.</th><th>Состояние</th><th>Где / у кого</th><th>Актив</th></tr></thead><tbody>{(items??[]).map(u=><tr key={u.unit_id}>
   <td>{u.item_name}</td><td className="mono">{u.serial}{u.inventory_no?<small>{u.inventory_no}</small>:null}</td><td><span className={'badge '+stateName[u.state][1]}><i/>{stateName[u.state][0]}</span></td>
   <td>{u.location_id?locName(r,u.location_id):u.holder_id?subjName(r,u.holder_id):u.installed_on?<button className="text-link" onClick={()=>onOpenAsset(u.installed_on!)}>на активе {u.installed_on.slice(0,8)}</button>:'—'}</td>
   <td>{u.asset_uid?<button className="text-link" onClick={()=>onOpenAsset(u.asset_uid!)}>карточка ↗</button>:'—'}</td></tr>)}</tbody></table></div>}
 </div>;
}

function Stock({ref_:r,onFail}:{ref_:Ref;onFail:(e:unknown)=>void}){
 const [loc,setLoc]=useState(''),[items,setItems]=useState<WStock[]|null>(null);
 useEffect(()=>{api.wStock(loc).then(p=>setItems(p.items)).catch(onFail)},[loc]);
 return <div className="table-panel"><div className="table-toolbar"><h2>Остатки количественных позиций</h2><div className="filters"><select aria-label="Место" value={loc} onChange={e=>setLoc(e.target.value)}><option value="">Все места</option>{r.locations.filter(l=>l.kind!=='repair').map(l=><option key={l.location_id} value={l.location_id}>{locName(r,l.location_id)}</option>)}</select></div></div>
  {items&&items.length===0?<div className="empty"><span>▦</span><h3>Остатков нет</h3></div>:<div className="table-scroll"><table><thead><tr><th>Позиция</th><th>Место</th><th>Остаток</th><th>В резерве</th></tr></thead><tbody>{(items??[]).map(s=><tr key={s.item_id+s.location_id}><td>{s.item_name}</td><td>{locName(r,s.location_id)}</td><td>{s.quantity} {s.unit}</td><td>{s.reserved?s.reserved+' '+s.unit:'—'}</td></tr>)}</tbody></table></div>}
 </div>;
}

// какие поля нужны виду операции
const need:Record<string,{from?:'loc'|'holder'|'either';to?:'loc'|'holder'|'repair';asset?:boolean}>={receive:{to:'loc'},issue:{from:'loc',to:'holder'},return:{from:'holder',to:'loc'},transfer:{from:'loc',to:'loc'},repair_out:{from:'either',to:'repair'},repair_in:{from:'loc',to:'loc'},install:{from:'loc',asset:true},remove:{to:'loc',asset:true},write_off:{from:'either'}};
type LineDraft={unit_id:string;item_id:string;quantity:string;serial:string;inventory_no:string};
const blank:LineDraft={unit_id:'',item_id:'',quantity:'',serial:'',inventory_no:''};

function OperationForm({ref_:r,csrf,isAdmin,onFail,onDone}:{ref_:Ref;csrf:string;isAdmin:boolean;onFail:(e:unknown)=>void;onDone:(m:WMovement)=>void}){
 const [kind,setKind]=useState<WOperation['kind']>('issue'),[basis,setBasis]=useState(''),[note,setNote]=useState(''),[fromLoc,setFromLoc]=useState(''),[toLoc,setToLoc]=useState(''),[fromH,setFromH]=useState(''),[toH,setToH]=useState(''),[asset,setAsset]=useState('');
 const [override,setOverride]=useState(false),[compat,setCompat]=useState<{compatible:boolean|null;asset_model:string}[]>([]);
 const [lines,setLines]=useState<LineDraft[]>([{...blank}]),[units,setUnits]=useState<WUnit[]>([]),[busy,setBusy]=useState(false),[fromMode,setFromMode]=useState<'loc'|'holder'>('loc');
 const n=need[kind]??{};const stockLocs=r.locations.filter(l=>l.kind!=='repair'&&l.active),repairLocs=r.locations.filter(l=>l.kind==='repair'&&l.active);
 const fromIsLoc=n.from==='loc'||(n.from==='either'&&fromMode==='loc'),fromIsHolder=n.from==='holder'||(n.from==='either'&&fromMode==='holder');
 // кандидаты-экземпляры по «откуда»: на месте, у держателя или на активе
 useEffect(()=>{const f=fromIsLoc&&fromLoc?{location:fromLoc}:fromIsHolder&&fromH?{holder:fromH}:kind==='remove'&&asset?{asset}:kind==='repair_in'&&fromLoc?{location:fromLoc}:null;if(!f){setUnits([]);return}api.wUnits(f).then(p=>setUnits(p.items.filter(u=>kind!=='remove'||u.installed_on===asset))).catch(onFail)},[kind,fromLoc,fromH,asset,fromMode]);
 // установка: проверка совместимости каждого выбранного экземпляра с моделью актива (C44.01)
 useEffect(()=>{if(kind!=='install'||!/^[0-9a-f-]{36}$/.test(asset.trim())){setCompat([]);return}const ids=lines.map(l=>units.find(u=>u.unit_id===l.unit_id)?.item_id).filter((x):x is string=>!!x);Promise.all(ids.map(i=>api.wCompatibility(i,asset.trim()))).then(setCompat).catch(onFail)},[kind,asset,lines,units]);
 const incompatible=compat.some(c=>c.compatible===false);
 const set=(i:number,p:Partial<LineDraft>)=>setLines(ls=>ls.map((l,j)=>j===i?{...l,...p}:l));
 const serialItems=r.items.filter(i=>i.kind==='serial'&&i.active),qtyItems=r.items.filter(i=>i.kind==='quantity'&&i.active);
 const qtyAllowed=['receive','issue','return','transfer','write_off'].includes(kind);
 async function submit(){
  const op:WOperation={kind,basis:basis.trim(),note:note.trim()||undefined,lines:lines.filter(l=>l.unit_id||l.item_id).map(l=>l.unit_id?{unit_id:l.unit_id}:kind==='receive'&&l.serial?{item_id:l.item_id,serial:l.serial.trim(),inventory_no:l.inventory_no.trim()||undefined}:{item_id:l.item_id,quantity:Number(l.quantity)})};
  if(fromIsLoc)op.from_location=fromLoc;if(fromIsHolder)op.from_holder=fromH;
  if(n.to==='loc'||n.to==='repair')op.to_location=toLoc;if(n.to==='holder')op.to_holder=toH;if(n.asset)op.asset_uid=asset.trim();if(kind==='install'&&override)op.compat_override=true;
  setBusy(true);try{const m=await api.wMove(csrf,op);setLines([{...blank}]);setBasis('');setNote('');onDone(m)}catch(e){
   // стенд №14: «зарезервирован за … до …» вместо общего отказа
   if(e instanceof ApiError&&e.code==='UNIT_RESERVED'){const res=(await api.wReservations().catch(()=>({items:[] as WReservation[]}))).items.find(x=>op.lines.some(l=>l.unit_id&&l.unit_id===x.unit_id));if(res){onFail(new UserError('Экземпляр «'+res.label+'» зарезервирован за '+subjName(r,res.holder_id)+' до '+fmt(res.expires_at)+': выдать можно только ему или после отмены резерва.'));return}}
   onFail(e)}finally{setBusy(false)}
 }
 const valid=(!incompatible||override)&&basis.trim()&&lines.some(l=>l.unit_id||l.item_id)&&(!fromIsLoc||fromLoc)&&(!fromIsHolder||fromH)&&(!n.to||(n.to==='holder'?toH:toLoc))&&(!n.asset||/^[0-9a-f-]{36}$/.test(asset.trim()));
 return <div className="table-panel"><div className="table-toolbar"><h2>Складская операция</h2></div><div className="form-grid wh-form">
  <label>Вид<select value={kind} onChange={e=>{setKind(e.target.value as WOperation['kind']);setLines([{...blank}])}}>{Object.keys(need).filter(k=>k!=='write_off'||isAdmin).map(k=><option key={k} value={k}>{kindName[k as WMovement['kind']]}</option>)}</select></label>
  {n.from==='either'?<label>Откуда<select value={fromMode} onChange={e=>setFromMode(e.target.value as 'loc'|'holder')}><option value="loc">со склада</option><option value="holder">от сотрудника/команды</option></select></label>:null}
  {fromIsLoc?<label>Со склада<select value={fromLoc} onChange={e=>setFromLoc(e.target.value)}><option value="">выберите…</option>{(kind==='repair_in'?repairLocs:stockLocs).map(l=><option key={l.location_id} value={l.location_id}>{locName(r,l.location_id)}</option>)}</select></label>:null}
  {fromIsHolder?<label>От кого<select value={fromH} onChange={e=>setFromH(e.target.value)}><option value="">выберите…</option>{r.subjects.filter(s=>s.active).map(s=><option key={s.subject_id} value={s.subject_id}>{s.name}</option>)}</select></label>:null}
  {n.to==='holder'?<label>Кому<select value={toH} onChange={e=>setToH(e.target.value)}><option value="">выберите…</option>{r.subjects.filter(s=>s.active).map(s=><option key={s.subject_id} value={s.subject_id}>{s.name}{s.kind==='team'?' (команда)':''}</option>)}</select></label>:null}
  {n.to==='loc'||n.to==='repair'?<label>{n.to==='repair'?'В ремонт (место)':'На склад'}<select value={toLoc} onChange={e=>setToLoc(e.target.value)}><option value="">выберите…</option>{(n.to==='repair'?repairLocs:stockLocs).map(l=><option key={l.location_id} value={l.location_id}>{locName(r,l.location_id)}</option>)}</select></label>:null}
  {n.asset?<label>Актив (UID)<input className="mono" value={asset} onChange={e=>setAsset(e.target.value)} placeholder="UID из карточки актива"/></label>:null}
  <label className="wide">Основание<input value={basis} onChange={e=>setBasis(e.target.value)} placeholder="Заявка, накладная, акт ТС…" maxLength={256}/></label>
  <label className="wide">Примечание<input value={note} onChange={e=>setNote(e.target.value)} maxLength={1024}/></label>
 </div>
 <div className="wh-lines"><h3>Позиции</h3>{lines.map((l,i)=><div key={i} className="wh-line">
  {kind==='receive'?<>
   <select aria-label="Позиция" value={l.item_id} onChange={e=>set(i,{item_id:e.target.value,unit_id:''})}><option value="">позиция…</option>{[...serialItems,...qtyItems].map(it=><option key={it.item_id} value={it.item_id}>{it.name}{it.kind==='quantity'?' ('+it.unit+')':''}</option>)}</select>
   {r.items.find(it=>it.item_id===l.item_id)?.kind==='quantity'?<input aria-label="Количество" type="number" min="0" step="any" value={l.quantity} onChange={e=>set(i,{quantity:e.target.value})} placeholder="кол-во"/>:<><input aria-label="Серийный номер" value={l.serial} onChange={e=>set(i,{serial:e.target.value})} placeholder="серийный №"/><input aria-label="Инвентарный номер" value={l.inventory_no} onChange={e=>set(i,{inventory_no:e.target.value})} placeholder="инв. № (необяз.)"/></>}
  </>:<>
   <select aria-label="Экземпляр или позиция" value={l.unit_id||(l.item_id?'q:'+l.item_id:'')} onChange={e=>{const v=e.target.value;v.startsWith('q:')?set(i,{item_id:v.slice(2),unit_id:''}):set(i,{unit_id:v,item_id:''})}}>
    <option value="">экземпляр…</option>{units.filter(u=>!lines.some((x,j)=>j!==i&&x.unit_id===u.unit_id)).map(u=><option key={u.unit_id} value={u.unit_id}>{u.item_name} · {u.serial}{u.inventory_no?' · '+u.inventory_no:''} ({stateName[u.state][0]})</option>)}
    {qtyAllowed&&!(n.from==='either'&&fromMode==='holder')?<optgroup label="Количество">{qtyItems.map(it=><option key={it.item_id} value={'q:'+it.item_id}>{it.name} ({it.unit})</option>)}</optgroup>:null}
   </select>
   {l.item_id?<input aria-label="Количество" type="number" min="0" step="any" value={l.quantity} onChange={e=>set(i,{quantity:e.target.value})} placeholder="кол-во"/>:null}
  </>}
  {lines.length>1?<button className="text-link" onClick={()=>setLines(ls=>ls.filter((_,j)=>j!==i))}>убрать</button>:null}
 </div>)}
 <button className="text-link" onClick={()=>setLines(ls=>[...ls,{...blank}])}>+ позиция</button></div>
 {incompatible?<div className="error" role="alert">Комплектующее не подходит к модели актива «{compat.find(c=>c.compatible===false)?.asset_model}» по каталогу. <label><input type="checkbox" checked={override} onChange={e=>setOverride(e.target.checked)}/> Установить под мою ответственность (отметка останется в журнале)</label></div>:null}
 <div className="wh-submit"><button className="button" disabled={!valid||busy} onClick={()=>void submit()}>{busy?'Проводим…':'Провести и сформировать акт'}</button><small className="muted">Операция попадает в журнал; исправление — только обратной операцией.</small></div>
 </div>;
}

const reversible=new Set(['issue','return','transfer','repair_in','repair_out','install','remove','receive']);
function Journal({ref_:r,csrf,canWrite,onOpen,onReversed,onFail}:{ref_:Ref;csrf:string;canWrite:boolean;onOpen:(id:string)=>void;onReversed:(m:WMovement)=>void;onFail:(e:unknown)=>void}){
 const [items,setItems]=useState<WMovement[]|null>(null),[n,setN]=useState(0);
 useEffect(()=>{api.wMovements().then(p=>setItems(p.items)).catch(onFail)},[n]);
 const reversed=new Set((items??[]).filter(m=>m.reverses).map(m=>m.reverses));
 async function reverse(m:WMovement){const basis=window.prompt('Сторно акта '+m.act_no+'. Основание:');if(!basis?.trim())return;try{onReversed(await api.wReverse(csrf,m.movement_id,basis.trim()));setN(x=>x+1)}catch(e){onFail(e)}}
 return <div className="table-panel"><div className="table-toolbar"><h2>Журнал движений <span>{items?.length??'…'}</span></h2></div>
  {items&&items.length===0?<div className="empty"><span>▤</span><h3>Операций пока нет</h3></div>:<div className="table-scroll"><table><thead><tr><th>Акт</th><th>Операция</th><th>Когда</th><th>Откуда → куда</th><th>Основание</th><th/></tr></thead><tbody>{(items??[]).map(m=><tr key={m.movement_id}>
   <td className="mono">{m.act_no}</td><td>{kindName[m.kind]}</td><td className="time">{fmt(m.occurred_at)}</td>
   <td>{m.from_location?locName(r,m.from_location):m.from_holder?subjName(r,m.from_holder):m.asset_uid&&m.kind==='remove'?'актив '+m.asset_uid.slice(0,8):'—'} → {m.to_location?locName(r,m.to_location):m.to_holder?subjName(r,m.to_holder):m.asset_uid&&m.kind==='install'?'актив '+m.asset_uid.slice(0,8):m.kind==='write_off'?'списано':'—'}</td>
   <td>{m.basis}{m.reverses?<small>сторно</small>:reversed.has(m.movement_id)?<small>сторнирован</small>:null}</td><td className="actions"><button className="button small" onClick={()=>onOpen(m.movement_id)}>Акт</button>{canWrite&&reversible.has(m.kind)&&!reversed.has(m.movement_id)?<button className="text-link" onClick={()=>void reverse(m)}>Сторно</button>:null}</td></tr>)}</tbody></table></div>}
 </div>;
}

// Печать акта (стенд №16: модальное окно печаталось на 2 полупустые страницы): при печати акт выводится отдельным
// узлом прямо в <body> (#act-print-root), всё остальное скрыто правилом печати — обычный поток страницы A4.
function printAct(){document.documentElement.classList.add('print-act');const done=()=>{document.documentElement.classList.remove('print-act');window.removeEventListener('afterprint',done)};window.addEventListener('afterprint',done);window.print();setTimeout(done,60000)}

function ActBody({m,r}:{m:WMovement;r:Ref}){
 const from=m.from_location?locName(r,m.from_location):m.from_holder?subjName(r,m.from_holder):m.kind==='remove'&&m.asset_uid?'актив '+m.asset_uid:'—';
 const to=m.to_location?locName(r,m.to_location):m.to_holder?subjName(r,m.to_holder):m.kind==='install'&&m.asset_uid?'актив '+m.asset_uid:'—';
 return <div className="act-print">
   <h2>{actTitle[m.kind]??kindName[m.kind]} № {m.act_no}</h2><p>от {new Date(m.occurred_at).toLocaleDateString('ru-RU')}</p>
   <dl><dt>Операция</dt><dd>{kindName[m.kind]}</dd><dt>Откуда</dt><dd>{from}</dd><dt>Куда</dt><dd>{to}</dd><dt>Основание</dt><dd>{m.basis}</dd>{m.note?<><dt>Примечание</dt><dd>{m.note}</dd></>:null}</dl>
   <table><thead><tr><th>№</th><th>Наименование</th><th>Серийный №</th><th>Инв. №</th><th>Кол-во</th></tr></thead><tbody>{(m.lines??[]).map(l=><tr key={l.line_no}><td>{l.line_no}</td><td>{l.item_name}</td><td>{l.serial??'—'}</td><td>{l.inventory_no??'—'}</td><td>{l.quantity} {l.unit}</td></tr>)}</tbody></table>
   <div className="act-signs"><div>Сдал: ______________________ {m.from_holder?'/'+subjName(r,m.from_holder)+'/':'(склад: '+from+')'}</div><div>Принял: ______________________ {m.to_holder?'/'+subjName(r,m.to_holder)+'/':'(склад: '+to+')'}</div><div>Оформил: {m.actor_name??'—'}</div></div>
  </div>;
}

function ActView({act:m,ref_:r,onClose}:{act:WMovement;ref_:Ref;onClose:()=>void}){
 return <><div className="drawer-shade act-shade" onClick={onClose}><div className="act-sheet" role="dialog" aria-label={'Акт '+m.act_no} onClick={e=>e.stopPropagation()}>
  <div className="act-actions"><button className="button small" onClick={printAct}>Печать / PDF</button><button className="text-button" onClick={onClose}>Закрыть</button></div>
  <ActBody m={m} r={r}/></div></div>
  {createPortal(<div id="act-print-root"><ActBody m={m} r={r}/></div>,document.body)}</>;
}

function Catalog({ref_:r,csrf,isAdmin,onFail,onChanged}:{ref_:Ref;csrf:string;isAdmin:boolean;onFail:(e:unknown)=>void;onChanged:()=>void}){
 const [sites,setSites]=useState<{site_id:string;site_name:string}[]>([]),[loc,setLoc]=useState({name:'',kind:'warehouse' as WLocation['kind'],site_id:'',parent_id:''}),[item,setItem]=useState({name:'',kind:'serial' as WItem['kind'],unit:'шт',category:''}),[busy,setBusy]=useState(false);
 useEffect(()=>{if(!isAdmin)return;api.portableScopes().then(p=>{const seen=new Map<string,string>();p.items.forEach(s=>seen.set(s.site_id,s.site_name));setSites([...seen].map(([site_id,site_name])=>({site_id,site_name})))}).catch(onFail)},[isAdmin]);
 async function act(fn:()=>Promise<unknown>){setBusy(true);try{await fn();onChanged()}catch(e){onFail(e)}finally{setBusy(false)}}
 const parentSite=loc.parent_id?r.locations.find(l=>l.location_id===loc.parent_id)?.site_id??'':loc.site_id;
 return <div className="stack"><div className="table-panel"><div className="table-toolbar"><h2>Склады и места <span>{r.locations.length}</span></h2></div>
  <div className="table-scroll"><table><thead><tr><th>Название</th><th>Вид</th></tr></thead><tbody>{r.locations.map(l=><tr key={l.location_id}><td>{locName(r,l.location_id)}</td><td>{l.kind==='warehouse'?'склад':l.kind==='bin'?'ячейка':'ремонт'}</td></tr>)}</tbody></table></div>
  {isAdmin?<div className="wh-line"><select aria-label="Вид места" value={loc.kind} onChange={e=>setLoc({...loc,kind:e.target.value as WLocation['kind'],parent_id:''})}><option value="warehouse">склад</option><option value="bin">ячейка склада</option><option value="repair">ремонт (сервис)</option></select>
   {loc.kind==='bin'?<select aria-label="Склад" value={loc.parent_id} onChange={e=>setLoc({...loc,parent_id:e.target.value})}><option value="">склад…</option>{r.locations.filter(l=>l.kind==='warehouse').map(l=><option key={l.location_id} value={l.location_id}>{l.name}</option>)}</select>:<select aria-label="Площадка" value={loc.site_id} onChange={e=>setLoc({...loc,site_id:e.target.value})}><option value="">площадка…</option>{sites.map(s=><option key={s.site_id} value={s.site_id}>{s.site_name}</option>)}</select>}
   <input aria-label="Название места" value={loc.name} onChange={e=>setLoc({...loc,name:e.target.value})} placeholder="Название"/>
   <button className="button small" disabled={busy||!loc.name.trim()||!parentSite} onClick={()=>void act(async()=>{await api.wCreateLocation(csrf,{site_id:parentSite,kind:loc.kind,name:loc.name.trim(),parent_id:loc.parent_id||undefined});setLoc({...loc,name:''})})}>Добавить</button></div>:null}
 </div>
 <div className="table-panel"><div className="table-toolbar"><h2>Каталог позиций <span>{r.items.length}</span></h2></div>
  <div className="table-scroll"><table><thead><tr><th>Название</th><th>Учёт</th><th>Категория</th><th>Подходит к моделям</th></tr></thead><tbody>{r.items.map(i=><tr key={i.item_id}><td>{i.name}</td><td>{i.kind==='serial'?'по серийным номерам':'количеством, '+i.unit}</td><td>{i.category??'—'}</td><td>{i.compatible_models.length?i.compatible_models.join(', '):<span className="muted">ко всем</span>}{isAdmin&&i.kind==='serial'?<button className="text-link" onClick={()=>{const v=window.prompt('Модели, к которым подходит (через запятую; пусто — ко всем):',i.compatible_models.join(', '));if(v!==null)void act(()=>api.wSetCompatibility(csrf,i.item_id,v.split(',').map(x=>x.trim()).filter(Boolean)))}}>изменить</button>:null}</td></tr>)}</tbody></table></div>
  {isAdmin?<div className="wh-line"><input aria-label="Название позиции" value={item.name} onChange={e=>setItem({...item,name:e.target.value})} placeholder="Модель / номенклатура"/>
   <select aria-label="Учёт" value={item.kind} onChange={e=>setItem({...item,kind:e.target.value as WItem['kind'],unit:'шт'})}><option value="serial">по серийным номерам</option><option value="quantity">количеством</option></select>
   {item.kind==='quantity'?<input aria-label="Единица" value={item.unit} onChange={e=>setItem({...item,unit:e.target.value})} placeholder="ед." size={5}/>:null}
   <input aria-label="Категория" value={item.category} onChange={e=>setItem({...item,category:e.target.value})} placeholder="Категория (необяз.)"/>
   <button className="button small" disabled={busy||!item.name.trim()} onClick={()=>void act(async()=>{await api.wCreateItem(csrf,{name:item.name.trim(),kind:item.kind,unit:item.unit,category:item.category.trim()||undefined});setItem({...item,name:''})})}>Добавить</button></div>:<p className="panel-note">Справочники ведёт администратор.</p>}
 </div></div>;
}

function Reservations({ref_:r,csrf,canWrite,onFail}:{ref_:Ref;csrf:string;canWrite:boolean;onFail:(e:unknown)=>void}){
 const [items,setItems]=useState<WReservation[]|null>(null),[n,setN]=useState(0),[units,setUnits]=useState<WUnit[]>([]),[busy,setBusy]=useState(false);
 const [what,setWhat]=useState(''),[loc,setLoc]=useState(''),[qty,setQty]=useState(''),[holder,setHolder]=useState(''),[basis,setBasis]=useState(''),[days,setDays]=useState('7');
 useEffect(()=>{api.wReservations().then(p=>setItems(p.items)).catch(onFail);api.wUnits({state:'in_stock'}).then(p=>setUnits(p.items)).catch(onFail)},[n]);
 const qtyItem=what.startsWith('q:')?what.slice(2):'';
 async function reserve(){setBusy(true);try{const exp=new Date(Date.now()+Number(days)*86400000).toISOString();await api.wReserve(csrf,qtyItem?{item_id:qtyItem,location_id:loc,quantity:Number(qty),holder_id:holder,basis:basis.trim(),expires_at:exp}:{unit_id:what,holder_id:holder,basis:basis.trim(),expires_at:exp});setWhat('');setQty('');setBasis('');setN(x=>x+1)}catch(e){onFail(e)}finally{setBusy(false)}}
 async function cancel(id:string){try{await api.wCancelReservation(csrf,id);setN(x=>x+1)}catch(e){onFail(e)}}
 return <div className="table-panel"><div className="table-toolbar"><h2>Действующие резервы <span>{items?.length??'…'}</span></h2></div>
  {items&&items.length===0?<div className="empty"><span>◇</span><h3>Резервов нет</h3><p>Резерв закрепляет экземпляр или количество за сотрудником до срока; выдать его другому нельзя.</p></div>:
  <div className="table-scroll"><table><thead><tr><th>Что</th><th>За кем</th><th>Основание</th><th>До</th><th/></tr></thead><tbody>{(items??[]).map(x=><tr key={x.reservation_id}><td>{x.label}{x.quantity?' — '+x.quantity:''}{x.location_id?<small>{locName(r,x.location_id)}</small>:null}</td><td>{subjName(r,x.holder_id)}</td><td>{x.basis}</td><td className="time">{fmt(x.expires_at)}</td><td>{canWrite?<button className="text-link" onClick={()=>void cancel(x.reservation_id)}>Отменить</button>:null}</td></tr>)}</tbody></table></div>}
  {canWrite?<div className="wh-line">
   <select aria-label="Что резервировать" value={what} onChange={e=>setWhat(e.target.value)}><option value="">экземпляр или позиция…</option>{units.map(u=><option key={u.unit_id} value={u.unit_id}>{u.item_name} · {u.serial}</option>)}<optgroup label="Количество">{r.items.filter(i=>i.kind==='quantity').map(i=><option key={i.item_id} value={'q:'+i.item_id}>{i.name} ({i.unit})</option>)}</optgroup></select>
   {qtyItem?<><select aria-label="Место резерва" value={loc} onChange={e=>setLoc(e.target.value)}><option value="">склад…</option>{r.locations.filter(l=>l.kind!=='repair').map(l=><option key={l.location_id} value={l.location_id}>{locName(r,l.location_id)}</option>)}</select><input aria-label="Количество резерва" type="number" min="0" step="any" value={qty} onChange={e=>setQty(e.target.value)} placeholder="кол-во"/></>:null}
   <select aria-label="За кем" value={holder} onChange={e=>setHolder(e.target.value)}><option value="">за кем…</option>{r.subjects.filter(s=>s.active).map(s=><option key={s.subject_id} value={s.subject_id}>{s.name}</option>)}</select>
   <input aria-label="Основание резерва" value={basis} onChange={e=>setBasis(e.target.value)} placeholder="Основание"/>
   <select aria-label="Срок" value={days} onChange={e=>setDays(e.target.value)}>{['1','3','7','14','30','90'].map(d=><option key={d} value={d}>на {d} дн.</option>)}</select>
   <button className="button small" disabled={busy||!what||!holder||!basis.trim()||(!!qtyItem&&(!loc||!(Number(qty)>0)))} onClick={()=>void reserve()}>Зарезервировать</button></div>:null}
 </div>;
}

// Складская история актива в карточке: экземпляр (если актив учтён на складе), установленные комплектующие, операции.
export function AssetWarehouseBlock({asset,onExpired}:{asset:string;onExpired:()=>void}){
 const [units,setUnits]=useState<WUnit[]|null>(null),[moves,setMoves]=useState<WMovement[]>([]);
 useEffect(()=>{let live=true;Promise.all([api.wUnits({asset}),api.wMovements({asset})]).then(([u,m])=>{if(live){setUnits(u.items);setMoves(m.items)}}).catch(e=>{if(e instanceof ApiError&&e.status===401)onExpired()});return()=>{live=false}},[asset]);
 if(!units||(units.length===0&&moves.length===0))return null;
 const self=units.find(u=>u.asset_uid===asset),parts=units.filter(u=>u.installed_on===asset);
 return <div className="presence-block"><h3>Склад {self?<span className={'badge '+stateName[self.state][1]}><i/>{stateName[self.state][0]}</span>:null}</h3>
  {self?<p className="muted">Экземпляр {self.item_name} · {self.serial}{self.inventory_no?' · '+self.inventory_no:''}</p>:null}
  {parts.length?<p className="muted">Установлено: {parts.map(p=>p.item_name+' · '+p.serial).join('; ')}</p>:null}
  <ul>{moves.slice(0,8).map(m=><li key={m.movement_id}><span className="mono">{m.act_no}</span> · {kindName[m.kind]} · {new Date(m.occurred_at).toLocaleDateString('ru-RU')} · {m.basis}</li>)}</ul></div>;
}

const resultName:Record<WInventoryDetail['lines'][number]['result'],[string,string]>={ok:['сходится','state-ok'],shortage:['недостача','state-unavailable'],surplus:['излишек','state-partial'],elsewhere:['числится в другом месте','state-partial']};

// Инвентаризация места (C45.01): снимок учёта → ввод факта (серийные номера списком, количества) → сверка → закрытие
// актом (администратор): недостача/излишек проводятся корректирующими движениями. Пока открыта — движения по месту запрещены.
function InventoryTab({ref_:r,csrf,canWrite,isAdmin,onAct,onFail}:{ref_:Ref;csrf:string;canWrite:boolean;isAdmin:boolean;onAct:(id:string)=>void;onFail:(e:unknown)=>void}){
 const [items,setItems]=useState<WInventory[]|null>(null),[cur,setCur]=useState<WInventoryDetail|null>(null),[n,setN]=useState(0),[busy,setBusy]=useState(false);
 const [loc,setLoc]=useState(''),[basis,setBasis]=useState(''),[serialItem,setSerialItem]=useState(''),[serials,setSerials]=useState(''),[qty,setQty]=useState<Record<string,string>>({});
 useEffect(()=>{api.wInventories().then(p=>setItems(p.items)).catch(onFail)},[n]);
 const open=(id:string)=>api.wInventory(id).then(d=>{setCur(d);const q:Record<string,string>={};d.lines.filter(l=>!l.serial&&l.counted!==null).forEach(l=>q[l.item_id]=String(l.counted));setQty(q);setSerials(d.lines.filter(l=>l.serial&&l.counted).map(l=>l.serial).join('\n'))}).catch(onFail);
 async function run<T>(fn:()=>Promise<T>,after?:(v:T)=>void){setBusy(true);try{const v=await fn();after?.(v);setN(x=>x+1)}catch(e){onFail(e)}finally{setBusy(false)}}
 const serialKinds=r.items.filter(i=>i.kind==='serial'),qtyKinds=r.items.filter(i=>i.kind==='quantity');
 function save(){if(!cur)return;
  // серийные: «позиция: номер» по строкам; позиция по умолчанию — выбранная; известные номера сопоставляются с позицией из сверки
  const known=new Map(cur.lines.filter(l=>l.serial).map(l=>[l.serial!.toLowerCase(),l.item_id]));
  const list=serials.split(/\n|,|;/).map(x=>x.trim()).filter(Boolean).map(sn=>({item_id:known.get(sn.toLowerCase())??serialItem,serial:sn}));
  if(list.some(x=>!x.item_id)){onFail(new UserError('Выберите позицию для серийных номеров, которых нет в учёте места'));return}
  const quantities=Object.entries(qty).filter(([,v])=>v!=='').map(([item_id,v])=>({item_id,quantity:Number(v)}));
  void run(()=>api.wCount(csrf,cur.inventory_id,{serials:list,quantities}),setCur)}
 return <div className="stack">
  {cur?<div className="table-panel"><div className="table-toolbar"><h2>Инвентаризация {cur.act_no} · {locName(r,cur.location_id)} <span>{cur.state==='open'?'идёт':cur.state==='closed'?'закрыта':'отменена'}</span></h2><button className="text-button" onClick={()=>setCur(null)}>к списку</button></div>
   {cur.state==='open'&&canWrite?<div className="wh-form">
    <label className="wide">Найденные серийные номера (по одному в строке; сканер штрихкода вводит как текст)<textarea aria-label="Найденные серийные номера" className="mono" rows={5} value={serials} onChange={e=>setSerials(e.target.value)}/></label>
    <label>Позиция для неучтённых номеров<select value={serialItem} onChange={e=>setSerialItem(e.target.value)}><option value="">—</option>{serialKinds.map(i=><option key={i.item_id} value={i.item_id}>{i.name}</option>)}</select></label>
    {qtyKinds.map(i=><label key={i.item_id}>{i.name}, {i.unit}<input aria-label={'Посчитано: '+i.name} type="number" min="0" step="any" value={qty[i.item_id]??''} onChange={e=>setQty({...qty,[i.item_id]:e.target.value})} placeholder="не считали"/></label>)}
    <div className="wide wh-submit"><button className="button small" disabled={busy} onClick={save}>Сохранить факт и сверить</button>
     {isAdmin?<button className="button small" disabled={busy||!cur.lines.some(l=>l.counted!==null)} onClick={()=>{if(window.confirm('Закрыть инвентаризацию и провести расхождения?'))void run(()=>api.wInventoryAction(csrf,cur.inventory_id,'close'),setCur)}}>Закрыть и провести</button>:<small className="muted">Закрывает администратор.</small>}
     <button className="text-link" disabled={busy} onClick={()=>void run(()=>api.wInventoryAction(csrf,cur.inventory_id,'cancel'),setCur)}>Отменить</button></div>
   </div>:null}
   <div className="table-scroll"><table><thead><tr><th>Позиция</th><th>Серийный</th><th>По учёту</th><th>Факт</th><th>Итог</th></tr></thead><tbody>{cur.lines.map((l,i)=><tr key={i}><td>{l.item_name}</td><td className="mono">{l.serial??'—'}</td><td>{l.serial?(l.expected?'да':'нет'):l.expected+' '+l.unit}</td><td>{l.counted===null?<span className="muted">не вводилось</span>:l.serial?(l.counted?'найден':'не найден'):l.counted+' '+l.unit}</td><td><span className={'badge '+resultName[l.result][1]}><i/>{resultName[l.result][0]}</span>{l.where?<small>{l.where.split(':')[0]==='issued'?'выдан: '+subjName(r,l.where.split(':')[1]??null):'место: '+locName(r,l.where.split(':')[1]??null)}</small>:null}</td></tr>)}</tbody></table></div>
   {cur.state==='closed'?<p className="panel-note">Проведено: {cur.shortage_movement?<button className="text-link" onClick={()=>onAct(cur.shortage_movement!)}>акт недостачи</button>:'недостачи нет'} · {cur.surplus_movement?<button className="text-link" onClick={()=>onAct(cur.surplus_movement!)}>акт излишка</button>:'излишка нет'}. Найденные «в другом месте» не перемещены — оформите перемещение или возврат.</p>:null}
  </div>:<div className="table-panel"><div className="table-toolbar"><h2>Инвентаризации <span>{items?.length??'…'}</span></h2></div>
   {items&&items.length===0?<div className="empty"><span>☑</span><h3>Инвентаризаций не было</h3></div>:<div className="table-scroll"><table><thead><tr><th>Акт</th><th>Место</th><th>Начата</th><th>Состояние</th><th/></tr></thead><tbody>{(items??[]).map(v=><tr key={v.inventory_id}><td className="mono">{v.act_no}</td><td>{locName(r,v.location_id)}</td><td className="time">{fmt(v.started_at)}</td><td>{v.state==='open'?'идёт':v.state==='closed'?'закрыта':'отменена'}</td><td><button className="button small" onClick={()=>void open(v.inventory_id)}>Открыть</button></td></tr>)}</tbody></table></div>}
   {canWrite?<div className="wh-line"><select aria-label="Место инвентаризации" value={loc} onChange={e=>setLoc(e.target.value)}><option value="">склад или ячейка…</option>{r.locations.filter(l=>l.kind!=='repair').map(l=><option key={l.location_id} value={l.location_id}>{locName(r,l.location_id)}</option>)}</select>
    <input aria-label="Основание инвентаризации" value={basis} onChange={e=>setBasis(e.target.value)} placeholder="Основание (приказ, плановая)"/>
    <button className="button small" disabled={busy||!loc||!basis.trim()} onClick={()=>void run(()=>api.wStartInventory(csrf,loc,basis.trim()),d=>{setCur(d);setBasis('');setSerials('');setQty({})})}>Начать инвентаризацию</button></div>:null}
  </div>}
 </div>;
}
