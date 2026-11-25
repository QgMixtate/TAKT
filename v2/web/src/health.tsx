import {createContext,useContext,useEffect,useState,type ReactNode} from 'react';
import {api,ApiError,errorMessage,type RSMColor,type RSMNodeState,type RSMOverview,type RSMReason,type RSMSystemDetail,type RSMSystemState} from './api';
import {reasonText} from './rsm';
import {fmt,useLoad} from './ui';

// Правая панель (макет 12): выбранная строка дерева — показатель, «как цвет поднимается вверх», «что делать».
type Step={level:string;name:string;color:RSMColor};
type Sel={path:Step[];reasons:RSMReason[];counts?:Counts;asset_uid?:string;service_uid?:string;component_id?:string;system?:string;last_inventory_at?:string|null};
const SelCtx=createContext<{sel:Sel|null;pick:(s:Sel)=>void}>({sel:null,pick:()=>{}});
const pathKey=(p:Step[])=>p.map(x=>x.level+':'+x.name).join('/');

// C53.06 (макет «Здоровье — дерево до метрики»): дерево направление (или площадка) → система → среда → компонент →
// хост → показатели. Цвет — из состояния РСМ (свежесть инвентаризации, присутствие в сети, эталон, конфликты); метрики
// мониторинга (CPU, диск, службы) появятся с C55 — до тех пор у хоста показываются причины цвета, а не выдуманные числа.
type Mode='direction'|'site';
const plural=(n:number,a:string,b:string,c:string)=>n%10===1&&n%100!==11?a:n%10>=2&&n%10<=4&&(n%100<10||n%100>=20)?b:c;
const systems_=(n:number)=>n+' '+plural(n,'система','системы','систем');
const hosts_=(n:number)=>fmt(n)+' '+plural(n,'хост','хоста','хостов');
const colorWord:Record<RSMColor,string>={red:'красный',yellow:'жёлтый',green:'норма',grey:'нет данных'};
const critWord:Record<string,string>={unknown:'не задана',low:'низкая',medium:'средняя',high:'высокая',critical:'критичная'};
type Counts={green:number;yellow:number;red:number;grey:number};
const colorOf=(c:Counts):RSMColor=>c.red?'red':c.yellow?'yellow':c.green?'green':'grey';
function Mix({c}:{c:Counts}){return <span className="mix">{c.green?<span className="m-green">{fmt(c.green)}</span>:null}{c.yellow?<span className="m-yellow">{fmt(c.yellow)}</span>:null}{c.red?<span className="m-red">{fmt(c.red)}</span>:null}{c.grey?<span className="m-grey">{fmt(c.grey)}</span>:null}</span>}
const why=(reasons:RSMReason[],color:RSMColor)=>color==='green'?'норма':reasons.length?colorWord[color]+': '+reasons.slice(0,2).map(reasonText).join(' · ')+(reasons.length>2?' · ещё '+(reasons.length-2):''):colorWord[color];

function Row({level,depth,color,name,sub,counts,reason,children,onOpen,load,onlyBad,trail,extra}:{level:string;depth:number;color:RSMColor;name:string;sub?:string;counts?:Counts;reason:string;children?:ReactNode;onOpen?:()=>void;load?:()=>void;onlyBad:boolean;trail:Step[];extra?:Omit<Sel,'path'|'counts'>}){
 const [open,setOpen]=useState(depth===0);
 const {sel,pick}=useContext(SelCtx);const path=[...trail,{level,name,color}];const on=!!sel&&pathKey(sel.path)===pathKey(path);
 useEffect(()=>{if(open)load?.()},[open]);
 if(onlyBad&&color==='green'&&depth>0)return null;
 const can=!!(children!==undefined||load);
 return <><tr className={'h-row d'+depth+(on?' h-sel':'')} onClick={e=>{if(!(e.target as HTMLElement).closest('button'))pick({reasons:[],...extra,path,counts})}}><td className="lvl"><span style={{paddingLeft:depth*18}}>{can?<button className="tree-toggle" aria-expanded={open} aria-label={open?'Свернуть':'Развернуть'} onClick={()=>setOpen(!open)}>{open?'−':'+'}</button>:<span className="tree-toggle"/>}{level}</span></td>
  <td><span className={'hdot h-'+(color==='yellow'?'yellow':color)}/> {onOpen?<button className="link plain" onClick={onOpen}><b>{name}</b></button>:<b>{name}</b>}{sub?<small className="muted"> {sub}</small>:null}</td>
  <td>{counts?<Mix c={counts}/>:null}</td><td className={color==='red'?'problem-text':color==='yellow'?'amber-text':'muted'}>{reason}</td></tr>{open?children:null}</>;
}

type Nav={onOpenSystem:(uid:string)=>void;onOpenComponent:(id:string,sys:string)=>void;onOpenAsset:(uid:string)=>void;onExpired:()=>void};

function SystemBranch({uid,depth,onlyBad,site,trail,nav}:{uid:string;depth:number;onlyBad:boolean;site?:string;trail:Step[];nav:Nav}){
 const [d,setD]=useState<RSMSystemDetail|null>(null),[err,setErr]=useState<unknown>(null);
 useEffect(()=>{api.rsmSystem(uid).then(setD).catch(e=>{setErr(e);if(e instanceof ApiError&&e.status===401)nav.onExpired()})},[uid]);
 if(err)return <tr><td colSpan={4}><div className="error" role="alert">{errorMessage(err)}</div></td></tr>;
 if(!d)return <tr><td colSpan={4} className="muted">Загрузка…</td></tr>;
 return <>{d.environments.map(e=>{const s=e.state;const envStep:Step={level:'среда',name:e.name,color:s?.color??'grey'};return <Row key={e.environment_id} level="среда" depth={depth} color={envStep.color} name={e.name} sub={s?hosts_(s.hosts):''} counts={s??undefined} reason={s?why(s.reasons,s.color):'не рассчитано'} onlyBad={onlyBad} trail={trail} extra={{reasons:s?.reasons??[],service_uid:uid}}>
  {e.components.map(c=>{const cs=c.state;return <Row key={c.component_id} level="компонент" depth={depth+1} color={cs?.color??'grey'} name={c.name} sub={cs?hosts_(cs.hosts):''} counts={cs??undefined} reason={cs?why(cs.reasons,cs.color):'не рассчитано'} onOpen={()=>nav.onOpenComponent(c.component_id,uid)} onlyBad={onlyBad} trail={[...trail,envStep]} extra={{reasons:cs?.reasons??[],service_uid:uid,component_id:c.component_id}}>
   <ComponentHosts id={c.component_id} sys={uid} depth={depth+2} site={site} onlyBad={onlyBad} trail={[...trail,envStep,{level:'компонент',name:c.name,color:cs?.color??'grey'}]} nav={nav}/></Row>})}</Row>})}
  <tr className="h-row"><td/><td colSpan={3}><button className="link" onClick={()=>nav.onOpenSystem(uid)}>Карточка системы →</button></td></tr></>;
}

function ComponentHosts({id,sys,depth,site,onlyBad,trail,nav}:{id:string;sys:string;depth:number;site?:string;onlyBad:boolean;trail:Step[];nav:Nav}){
 const [card,err]=useLoad(()=>api.rsmComponentCard(id,{site,color:undefined}),[id,site],nav.onExpired);
 if(err)return <tr><td colSpan={4}><div className="error" role="alert">{errorMessage(err)}</div></td></tr>;
 if(!card)return <tr><td colSpan={4} className="muted">Загрузка…</td></tr>;
 const bad=card.hosts.filter(h=>h.color!=='green'),good=card.hosts.length-bad.length;
 return <>{(onlyBad?bad:card.hosts).map(h=><Row key={h.asset_uid} level="хост" depth={depth} color={h.color} name={h.name} sub={h.ip} reason={why(h.reasons,h.color)} onOpen={()=>nav.onOpenAsset(h.asset_uid)} onlyBad={onlyBad} trail={trail} extra={{reasons:h.reasons,asset_uid:h.asset_uid,service_uid:sys,component_id:id,last_inventory_at:h.last_inventory_at}}>
   {h.reasons.length?h.reasons.map((r,i)=><tr key={i} className="h-row metric"><td className="lvl"><span style={{paddingLeft:(depth+1)*18}}><span className="tree-toggle"/>показатель</span></td><td>{reasonText(r)}</td><td/><td className={h.color==='red'?'problem-text':'amber-text'}>красит хост: {colorWord[h.color]}</td></tr>):<tr className="h-row metric"><td/><td colSpan={3} className="muted">Показателей с отклонением нет. Метрики мониторинга (CPU, диск, службы) — после подключения мониторинга (C55).</td></tr>}</Row>)}
  {onlyBad&&good?<tr className="h-row"><td className="lvl"><span style={{paddingLeft:depth*18}}><span className="tree-toggle"/>хосты</span></td><td className="muted">{fmt(good)} в норме</td><td/><td/></tr>:null}
  {card.matched>card.hosts.length?<tr className="h-row"><td/><td colSpan={3} className="muted">Показаны {card.hosts.length} из {fmt(card.matched)} — все в карточке компонента.</td></tr>:null}</>;
}

const ageDays=(t?:string|null)=>t?Math.floor((Date.now()-new Date(t).getTime())/86400000):null;
const dot=(c:RSMColor)=><span className={'hdot h-'+c}/>;

// Правая панель: только то, что есть в данных РСМ. График метрики из макета — с C55 (мониторинг), до тех пор не рисуется.
function HealthSide({sel,company,csrf,canWrite,nav}:{sel:Sel|null;company:RSMColor;csrf:string;canWrite:boolean;nav:Nav}){
 const [note,setNote]=useState(''),[busy,setBusy]=useState(false),[confirm,setConfirm]=useState(false);
 useEffect(()=>{setNote('');setConfirm(false)},[sel&&pathKey(sel.path)]);
 if(!sel)return <aside className="health-side"><section className="panel"><header><h3>Выберите строку</h3></header><p className="muted pad">Нажмите на площадку, систему, компонент или хост — здесь появятся показатель, путь цвета вверх и что делать.</p></section></aside>;
 const me=sel.path[sel.path.length-1],system=sel.path.find(x=>x.level==='система');
 const age=ageDays(sel.last_inventory_at);
 const chain:{c:RSMColor;text:string;right?:string}[]=[];
 if(me.level==='хост'&&sel.reasons.length)chain.push({c:me.color,text:reasonText(sel.reasons[0])+' → хост '+me.name+' ('+colorWord[me.color]+')'});
 for(let i=sel.path.length-1;i>0;i--){const a=sel.path[i],b=sel.path[i-1];chain.push({c:b.color,text:a.level+' '+a.name+' ('+colorWord[a.color]+') → '+b.level+' '+b.name+' ('+colorWord[b.color]+')'})}
 if(sel.path.length)chain.push({c:company,text:sel.path[0].level+' '+sel.path[0].name+' ('+colorWord[sel.path[0].color]+') → компания ('+colorWord[company]+')'});
 async function collect(){if(!sel?.asset_uid)return;setBusy(true);try{const r=await api.assetCollect(sel.asset_uid,csrf);setNote(r.requested?'Сбор запрошен: целей сбора — '+r.requested:r.recent?'Сбор уже запрошен недавно':r.agents?'У хоста агент — соберёт по расписанию':'У хоста нет цели сбора')}catch(e){setNote(errorMessage(e));if(e instanceof ApiError&&e.status===401)nav.onExpired()}finally{setBusy(false)}}
 const title='Здоровье: '+(system?system.name+' — ':'')+me.name+(sel.reasons.length?' ('+reasonText(sel.reasons[0])+')':'');
 async function incident(){setBusy(true);try{const t=await api.createTicket(csrf,{kind:'incident',title,description:'Создано из раздела «Здоровье». Путь: '+sel!.path.map(x=>x.level+' '+x.name+' — '+colorWord[x.color]).join(' → ')+(sel!.reasons.length?'\nПричины: '+sel!.reasons.map(reasonText).join('; '):''),impact:me.color==='red'?1:2,urgency:me.color==='red'?1:2,asset_uid:sel!.asset_uid,service_uid:sel!.service_uid});setNote('Создан инцидент '+t.number);setConfirm(false)}catch(e){setNote(errorMessage(e));if(e instanceof ApiError&&e.status===401)nav.onExpired()}finally{setBusy(false)}}
 return <aside className="health-side">
  <section className="panel"><header><h3>{me.level} · {me.name}</h3></header><div className="pad">
   <p className="side-big">{dot(me.color)} <b className={me.color==='red'?'problem-text':me.color==='yellow'?'amber-text':''}>{colorWord[me.color]}</b></p>
   {sel.counts?<p>дочерние: <Mix c={sel.counts}/></p>:null}
   {me.level==='хост'?<p className="muted">Свежесть инвентаризации: {age===null?'нет сведений':age<1?'сегодня':age+' дн'}</p>:null}
   {sel.reasons.length?<ul className="side-list">{sel.reasons.map((r,i)=><li key={i}>{dot(me.color)} {reasonText(r)}</li>)}</ul>:<p className="muted">Причин отклонения нет.</p>}
   <p className="muted small">Метрики CPU, диск, службы и их график — после подключения мониторинга (C55).</p></div></section>
  <section className="panel"><header><h3>Как цвет поднимается вверх</h3></header><ul className="side-list pad">{chain.map((x,i)=><li key={i}>{dot(x.c)} {x.text}</li>)}</ul></section>
  <section className="panel"><header><h3>Что делать</h3></header><div className="pad side-actions">
   {sel.asset_uid?<button className="link" onClick={()=>nav.onOpenAsset(sel.asset_uid!)}>Открыть хост</button>:null}
   {sel.component_id&&sel.service_uid?<button className="link" onClick={()=>nav.onOpenComponent(sel.component_id!,sel.service_uid!)}>Карточка компонента</button>:null}
   {sel.service_uid?<button className="link" onClick={()=>nav.onOpenSystem(sel.service_uid!)}>Карточка системы{system?' '+system.name:''}</button>:null}
   {canWrite&&sel.asset_uid?<button className="link" disabled={busy} onClick={()=>void collect()}>Собрать сейчас</button>:null}
   {canWrite&&sel.service_uid&&me.color!=='green'?(confirm?<span>Создать инцидент «{title}»? <button className="button compact" disabled={busy} onClick={()=>void incident()}>Создать</button> <button className="text-button" onClick={()=>setConfirm(false)}>Отмена</button></span>:<button className="link" onClick={()=>setConfirm(true)}>Создать инцидент{system?' по '+system.name:''}</button>):null}
   {!sel.service_uid?<span className="muted">Раскройте строку до системы или хоста.</span>:null}
   {note?<p className="muted" role="status">{note}</p>:null}</div></section>
 </aside>;
}

export function HealthScreen({csrf,canWrite,onOpenSystem,onOpenComponent,onOpenAsset,onExpired}:{csrf:string;canWrite:boolean}&Nav){
 const nav:Nav={onOpenSystem,onOpenComponent,onOpenAsset,onExpired};
 const [mode,setMode]=useState<Mode>('direction'),[onlyBad,setOnlyBad]=useState(true),[q,setQ]=useState(''),[sel,setSel]=useState<Sel|null>(null);
 const [ov,ovErr]=useLoad<RSMOverview>(()=>api.rsmOverview(),[],onExpired);
 const [systems,setSystems]=useState<RSMSystemState[]|null>(null);
 useEffect(()=>{let live=true;(async()=>{const all:RSMSystemState[]=[];for(let off=0;off<10000;off+=500){const p=await api.rsmSystems({limit:500,offset:off});all.push(...p.items);if(p.next_offset==null)break}if(live)setSystems(all)})().catch(e=>{if(e instanceof ApiError&&e.status===401)onExpired()});return()=>{live=false}},[]);
 const [sites,sitesErr]=useLoad(()=>mode==='site'?api.rsmSiteHealth():Promise.resolve(null),[mode],onExpired);
 useEffect(()=>setSel(null),[mode]);
 const cnt={green:0,yellow:0,red:0,grey:0} as Counts;for(const s of systems??[])cnt[s.state.color]++;
 const st=ov?.state;const company=st?st.color:'grey';
 const rank:Record<string,number>={grey:0,green:1,yellow:2,red:3};
 // фильтр — по имени системы (дерево ниже системы загружается по раскрытию)
 const ql=q.trim().toLowerCase();const match=(s:RSMSystemState)=>!ql||s.name.toLowerCase().includes(ql);
 // №78/№90: на площадке система не «краснее», чем по правилам РСМ (цвет хоста → компонент → среда → система)
 const capped=(s:RSMSystemState,c?:Counts):RSMColor=>{const own=c?colorOf(c):s.state.color;return c&&own!=='grey'&&rank[own]>rank[s.state.color]&&s.state.color!=='grey'?s.state.color:own};
 const siteColor=(st:{systems:(Counts&{service_uid:string})[]}&Counts):RSMColor=>{const cs=st.systems.map(x=>{const full=(systems??[]).find(y=>y.service_uid===x.service_uid);return full?capped(full,x):colorOf(x)});return cs.length?cs.reduce((a,b)=>rank[b]>rank[a]?b:a,'grey' as RSMColor):colorOf(st)};
 const sysRow=(s:RSMSystemState,depth:number,top:Step,site?:string,c?:Counts)=>{const color=capped(s,c);
 return <Row key={s.service_uid+(site??'')} level="система" depth={depth} color={color} name={s.name} sub={'критичность '+(critWord[s.criticality]??s.criticality)} counts={c??s.state} reason={why(s.state.reasons,color)} onOpen={()=>onOpenSystem(s.service_uid)} onlyBad={onlyBad} trail={[top]} extra={{reasons:s.state.reasons,service_uid:s.service_uid}}>
  <SystemBranch uid={s.service_uid} depth={depth+1} onlyBad={onlyBad} site={site} trail={[top,{level:'система',name:s.name,color}]} nav={nav}/></Row>};
 const dirRows=(ov?.directions??[]).map(d=>{const s=d.state as RSMNodeState|null|undefined;const list=(systems??[]).filter(x=>x.direction_uid===d.direction_uid&&match(x));if(ql&&!list.length)return null;const top:Step={level:'направление',name:d.name,color:s?.color??'grey'};return <Row key={d.direction_uid} level="направление" depth={0} color={top.color} name={d.name} sub={s?hosts_(s.hosts)+' · '+systems_(list.length):''} counts={s??undefined} reason={s?why(s.reasons,s.color):'не рассчитано'} onlyBad={onlyBad} trail={[]} extra={{reasons:s?.reasons??[]}}>{list.map(x=>sysRow(x,1,top))}</Row>});
 const noDir=(systems??[]).filter(x=>!x.direction_uid&&match(x));
 const noDirTop:Step={level:'направление',name:'Без направления',color:noDir.some(x=>x.state.color==='red')?'red':noDir.some(x=>x.state.color==='yellow')?'yellow':'green'};
 const siteRows=(sites?.items??[]).map(s=>{const list=s.systems.filter(x=>!ql||x.name.toLowerCase().includes(ql));if(ql&&!list.length)return null;const color=siteColor(s);const top:Step={level:'площадка',name:s.name,color};
  return <Row key={s.site_id} level="площадка" depth={0} color={color} name={s.name} sub={hosts_(s.hosts)+' · '+systems_(s.systems.length)} counts={s} reason={color==='green'?'норма':colorWord[color]+': '+s.systems.filter(x=>x.red||x.yellow).slice(0,3).map(x=>x.name).join(', ')} onlyBad={onlyBad} trail={[]}>
   {list.map(x=>{const full=(systems??[]).find(y=>y.service_uid===x.service_uid);return full?sysRow(full,1,top,s.name,x):null})}</Row>});
 // №100: в шапке — хосты, в счётчиках — системы; подписи явно разные
 const headline=st?(st.red?'хостов в аварии: '+fmt(st.red)+' · ':'')+(st.yellow?'хостов с предупреждением: '+fmt(st.yellow)+' · ':'')+(cnt.red?fmt(cnt.red)+' '+plural(cnt.red,'система красная','системы красные','систем красные')+' · ':'')+'расчёт '+new Date(st.computed_at).toLocaleTimeString('ru-RU',{hour:'2-digit',minute:'2-digit'}):'Состояние ещё не рассчитано';
 return <SelCtx.Provider value={{sel,pick:setSel}}><div className="health">
  <div className="health-top"><div className={'health-company hc-'+company}><span className={'hdot big h-'+company}/><div><h2>Компания: {company==='green'?'всё в норме':company==='grey'?'нет данных':'есть проблемы'}</h2><p>{headline}</p></div></div>
   <div className="health-kpi"><div><b className="ok-text">{fmt(cnt.green)}</b><span>систем в норме</span></div><div><b className="amber-text">{fmt(cnt.yellow)}</b><span>систем с предупреждением</span></div><div><b className="problem-text">{fmt(cnt.red)}</b><span>систем в аварии</span></div></div></div>
  <div className="systems-toolbar health-tools"><span className="spacer"/>
   <select aria-label="Разрез дерева" value={mode} onChange={e=>setMode(e.target.value as Mode)}><option value="direction">Направление → система → компонент → хост → показатель</option><option value="site">Площадка → система → компонент → хост → показатель</option></select>
   <select aria-label="Показывать" value={onlyBad?'bad':'all'} onChange={e=>setOnlyBad(e.target.value==='bad')}><option value="bad">Показывать: только не зелёные</option><option value="all">Показывать: все</option></select>
   <input type="search" aria-label="Фильтр по системе" placeholder="Фильтр: система" value={q} onChange={e=>setQ(e.target.value)}/></div>
  {ovErr?<div className="error" role="alert">{errorMessage(ovErr)}</div>:null}{sitesErr?<div className="error" role="alert">{errorMessage(sitesErr)}</div>:null}
  <div className="health-grid"><div className="panel table-scroll"><table className="panel-table health-table"><thead><tr><th>уровень</th><th>объект</th><th>дочерние по цвету</th><th>почему такой цвет</th></tr></thead><tbody>
   {mode==='direction'?<>{dirRows}{noDir.length?<Row level="направление" depth={0} color={noDirTop.color} name="Без направления" sub={systems_(noDir.length)} reason="" onlyBad={onlyBad} trail={[]}>{noDir.map(x=>sysRow(x,1,noDirTop))}</Row>:null}</>:siteRows}
  </tbody></table>{systems&&!systems.length?<p className="muted pad">Систем пока нет — заведите первую в разделе «Системы».</p>:null}{systems&&systems.length&&ql&&!systems.some(match)?<p className="muted pad">Нет систем по фильтру «{q}».</p>:null}</div>
  <HealthSide sel={sel} company={company} csrf={csrf} canWrite={canWrite} nav={nav}/></div>
  <p className="muted">Цвет поднимается снизу вверх: хост → компонент → среда → система → {mode==='site'?'площадка':'направление'} → компания. В разрезе по площадкам у системы показаны её хосты на этой площадке; среды и компоненты — целиком.</p>
 </div></SelCtx.Provider>;
}
