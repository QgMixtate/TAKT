import {useEffect,useState,type ReactNode} from 'react';
import {api,ApiError,errorMessage,type RSMColor,type RSMNodeState,type RSMOverview,type RSMReason,type RSMSystemDetail,type RSMSystemState} from './api';
import {reasonText} from './rsm';
import {fmt,useLoad} from './ui';

// C53.06 (макет «Здоровье — дерево до метрики»): дерево направление (или площадка) → система → среда → компонент →
// хост → показатели. Цвет — из состояния РСМ (свежесть инвентаризации, присутствие в сети, эталон, конфликты); метрики
// мониторинга (CPU, диск, службы) появятся с C55 — до тех пор у хоста показываются причины цвета, а не выдуманные числа.
type Mode='direction'|'site';
const colorWord:Record<RSMColor,string>={red:'красный',yellow:'жёлтый',green:'норма',grey:'нет данных'};
const critWord:Record<string,string>={unknown:'не задана',low:'низкая',medium:'средняя',high:'высокая',critical:'критичная'};
type Counts={green:number;yellow:number;red:number;grey:number};
const colorOf=(c:Counts):RSMColor=>c.red?'red':c.yellow?'yellow':c.green?'green':'grey';
function Mix({c}:{c:Counts}){return <span className="mix">{c.green?<span className="m-green">{fmt(c.green)}</span>:null}{c.yellow?<span className="m-yellow">{fmt(c.yellow)}</span>:null}{c.red?<span className="m-red">{fmt(c.red)}</span>:null}{c.grey?<span className="m-grey">{fmt(c.grey)}</span>:null}</span>}
const why=(reasons:RSMReason[],color:RSMColor)=>color==='green'?'норма':reasons.length?colorWord[color]+': '+reasons.slice(0,2).map(reasonText).join(' · ')+(reasons.length>2?' · ещё '+(reasons.length-2):''):colorWord[color];

function Row({level,depth,color,name,sub,counts,reason,children,onOpen,load,onlyBad}:{level:string;depth:number;color:RSMColor;name:ReactNode;sub?:string;counts?:Counts;reason:string;children?:ReactNode;onOpen?:()=>void;load?:()=>void;onlyBad:boolean}){
 const [open,setOpen]=useState(depth===0);
 useEffect(()=>{if(open)load?.()},[open]);
 if(onlyBad&&color==='green'&&depth>0)return null;
 const can=!!(children!==undefined||load);
 return <><tr className={'h-row d'+depth}><td className="lvl"><span style={{paddingLeft:depth*18}}>{can?<button className="tree-toggle" aria-expanded={open} aria-label={open?'Свернуть':'Развернуть'} onClick={()=>setOpen(!open)}>{open?'−':'+'}</button>:<span className="tree-toggle"/>}{level}</span></td>
  <td><span className={'hdot h-'+(color==='yellow'?'yellow':color)}/> {onOpen?<button className="link plain" onClick={onOpen}><b>{name}</b></button>:<b>{name}</b>}{sub?<small className="muted"> {sub}</small>:null}</td>
  <td>{counts?<Mix c={counts}/>:null}</td><td className={color==='red'?'problem-text':color==='yellow'?'amber-text':'muted'}>{reason}</td></tr>{open?children:null}</>;
}

function SystemBranch({uid,depth,onlyBad,site,onOpenSystem,onOpenComponent,onOpenAsset,onExpired}:{uid:string;depth:number;onlyBad:boolean;site?:string;onOpenSystem:(uid:string)=>void;onOpenComponent:(id:string,sys:string)=>void;onOpenAsset:(uid:string)=>void;onExpired:()=>void}){
 const [d,setD]=useState<RSMSystemDetail|null>(null),[err,setErr]=useState<unknown>(null);
 useEffect(()=>{api.rsmSystem(uid).then(setD).catch(e=>{setErr(e);if(e instanceof ApiError&&e.status===401)onExpired()})},[uid]);
 if(err)return <tr><td colSpan={4}><div className="error" role="alert">{errorMessage(err)}</div></td></tr>;
 if(!d)return <tr><td colSpan={4} className="muted">Загрузка…</td></tr>;
 return <>{d.environments.map(e=>{const s=e.state;return <Row key={e.environment_id} level="среда" depth={depth} color={s?.color??'grey'} name={e.name} sub={s?fmt(s.hosts)+' хост.':''} counts={s??undefined} reason={s?why(s.reasons,s.color):'не рассчитано'} onlyBad={onlyBad}>
  {e.components.map(c=>{const cs=c.state;return <Row key={c.component_id} level="компонент" depth={depth+1} color={cs?.color??'grey'} name={c.name} sub={cs?fmt(cs.hosts)+' хост.':''} counts={cs??undefined} reason={cs?why(cs.reasons,cs.color):'не рассчитано'} onOpen={()=>onOpenComponent(c.component_id,uid)} onlyBad={onlyBad}>
   <ComponentHosts id={c.component_id} depth={depth+2} site={site} onlyBad={onlyBad} onOpenAsset={onOpenAsset} onExpired={onExpired}/></Row>})}</Row>})}
  <tr className="h-row"><td/><td colSpan={3}><button className="link" onClick={()=>onOpenSystem(uid)}>Карточка системы →</button></td></tr></>;
}

function ComponentHosts({id,depth,site,onlyBad,onOpenAsset,onExpired}:{id:string;depth:number;site?:string;onlyBad:boolean;onOpenAsset:(uid:string)=>void;onExpired:()=>void}){
 const [card,err]=useLoad(()=>api.rsmComponentCard(id,{site,color:undefined}),[id,site],onExpired);
 if(err)return <tr><td colSpan={4}><div className="error" role="alert">{errorMessage(err)}</div></td></tr>;
 if(!card)return <tr><td colSpan={4} className="muted">Загрузка…</td></tr>;
 const bad=card.hosts.filter(h=>h.color!=='green'),good=card.hosts.length-bad.length;
 return <>{(onlyBad?bad:card.hosts).map(h=><Row key={h.asset_uid} level="хост" depth={depth} color={h.color} name={h.name} sub={h.ip} reason={why(h.reasons,h.color)} onOpen={()=>onOpenAsset(h.asset_uid)} onlyBad={onlyBad}>
   {h.reasons.length?h.reasons.map((r,i)=><tr key={i} className="h-row metric"><td className="lvl"><span style={{paddingLeft:(depth+1)*18}}><span className="tree-toggle"/>показатель</span></td><td>{reasonText(r)}</td><td/><td className={h.color==='red'?'problem-text':'amber-text'}>красит хост: {colorWord[h.color]}</td></tr>):<tr className="h-row metric"><td/><td colSpan={3} className="muted">Показателей с отклонением нет. Метрики мониторинга (CPU, диск, службы) — после подключения мониторинга (C55).</td></tr>}</Row>)}
  {onlyBad&&good?<tr className="h-row"><td className="lvl"><span style={{paddingLeft:depth*18}}><span className="tree-toggle"/>хосты</span></td><td className="muted">{fmt(good)} в норме</td><td/><td/></tr>:null}
  {card.matched>card.hosts.length?<tr className="h-row"><td/><td colSpan={3} className="muted">Показаны {card.hosts.length} из {fmt(card.matched)} — все в карточке компонента.</td></tr>:null}</>;
}

export function HealthScreen({onOpenSystem,onOpenComponent,onOpenAsset,onExpired}:{onOpenSystem:(uid:string)=>void;onOpenComponent:(id:string,sys:string)=>void;onOpenAsset:(uid:string)=>void;onExpired:()=>void}){
 const [mode,setMode]=useState<Mode>('direction'),[onlyBad,setOnlyBad]=useState(true);
 const [ov,ovErr]=useLoad<RSMOverview>(()=>api.rsmOverview(),[],onExpired);
 const [systems,setSystems]=useState<RSMSystemState[]|null>(null);
 useEffect(()=>{let live=true;(async()=>{const all:RSMSystemState[]=[];for(let off=0;off<10000;off+=500){const p=await api.rsmSystems({limit:500,offset:off});all.push(...p.items);if(p.next_offset==null)break}if(live)setSystems(all)})().catch(e=>{if(e instanceof ApiError&&e.status===401)onExpired()});return()=>{live=false}},[]);
 const [sites,sitesErr]=useLoad(()=>mode==='site'?api.rsmSiteHealth():Promise.resolve(null),[mode],onExpired);
 const cnt={green:0,yellow:0,red:0,grey:0} as Counts;for(const s of systems??[])cnt[s.state.color]++;
 const st=ov?.state;const company=st?st.color:'grey';
 const rank:Record<string,number>={grey:0,green:1,yellow:2,red:3};
 // №78/№90: на площадке система не «краснее», чем по правилам РСМ (цвет хоста → компонент → среда → система)
 const capped=(s:RSMSystemState,c?:Counts):RSMColor=>{const own=c?colorOf(c):s.state.color;return c&&own!=='grey'&&rank[own]>rank[s.state.color]&&s.state.color!=='grey'?s.state.color:own};
 const siteColor=(st:{systems:(Counts&{service_uid:string})[]}&Counts):RSMColor=>{const cs=st.systems.map(x=>{const full=(systems??[]).find(y=>y.service_uid===x.service_uid);return full?capped(full,x):colorOf(x)});return cs.length?cs.reduce((a,b)=>rank[b]>rank[a]?b:a,'grey' as RSMColor):colorOf(st)};
 const sysRow=(s:RSMSystemState,depth:number,site?:string,c?:Counts)=>{const color=capped(s,c);
 return <Row key={s.service_uid+(site??'')} level="система" depth={depth} color={color} name={s.name} sub={'критичность '+(critWord[s.criticality]??s.criticality)} counts={c??s.state} reason={why(s.state.reasons,color)} onOpen={()=>onOpenSystem(s.service_uid)} onlyBad={onlyBad}>
  <SystemBranch uid={s.service_uid} depth={depth+1} onlyBad={onlyBad} site={site} onOpenSystem={onOpenSystem} onOpenComponent={onOpenComponent} onOpenAsset={onOpenAsset} onExpired={onExpired}/></Row>};
 const dirRows=(ov?.directions??[]).map(d=>{const s=d.state as RSMNodeState|null|undefined;const list=(systems??[]).filter(x=>x.direction_uid===d.direction_uid);return <Row key={d.direction_uid} level="направление" depth={0} color={s?.color??'grey'} name={d.name} sub={s?fmt(s.hosts)+' хостов · '+list.length+' систем':''} counts={s??undefined} reason={s?why(s.reasons,s.color):'не рассчитано'} onlyBad={onlyBad}>{list.map(x=>sysRow(x,1))}</Row>});
 const noDir=(systems??[]).filter(x=>!x.direction_uid);
 return <div className="health">
  <div className="health-head"><div><h2><span className={'hdot h-'+(company==='yellow'?'yellow':company)}/> Компания: {company==='green'?'всё в норме':company==='grey'?'нет данных':'есть проблемы'}</h2><p className="muted">{st?fmt(st.red)+' хостов в аварии · '+fmt(st.yellow)+' с предупреждением · расчёт '+new Date(st.computed_at).toLocaleTimeString('ru-RU',{hour:'2-digit',minute:'2-digit'}):'Состояние ещё не рассчитано'}</p></div>
   <div className="kpi-cards inline"><div><b className="ok-text">{fmt(cnt.green)}</b><span>систем в норме</span></div><div className="amber"><b>{fmt(cnt.yellow)}</b><span>с предупреждением</span></div><div className="warn"><b>{fmt(cnt.red)}</b><span>в аварии</span></div></div></div>
  <div className="systems-toolbar"><div className="seg" role="radiogroup" aria-label="Разрез дерева"><button role="radio" aria-checked={mode==='direction'} className={mode==='direction'?'on':''} onClick={()=>setMode('direction')}>Направление → система → хост</button><button role="radio" aria-checked={mode==='site'} className={mode==='site'?'on':''} onClick={()=>setMode('site')}>Площадка → система → хост</button></div>
   <span className="spacer"/><div className="seg" role="radiogroup" aria-label="Показывать"><button role="radio" aria-checked={onlyBad} className={onlyBad?'on':''} onClick={()=>setOnlyBad(true)}>только не зелёные</button><button role="radio" aria-checked={!onlyBad} className={!onlyBad?'on':''} onClick={()=>setOnlyBad(false)}>все</button></div></div>
  {ovErr?<div className="error" role="alert">{errorMessage(ovErr)}</div>:null}{sitesErr?<div className="error" role="alert">{errorMessage(sitesErr)}</div>:null}
  <div className="panel table-scroll"><table className="panel-table health-table"><thead><tr><th>уровень</th><th>объект</th><th>дочерние по цвету</th><th>почему такой цвет</th></tr></thead><tbody>
   {mode==='direction'?<>{dirRows}{noDir.length?<Row level="направление" depth={0} color={noDir.some(x=>x.state.color==='red')?'red':noDir.some(x=>x.state.color==='yellow')?'yellow':'green'} name="Без направления" sub={noDir.length+' систем'} reason="" onlyBad={onlyBad}>{noDir.map(x=>sysRow(x,1))}</Row>:null}</>
   :(sites?.items??[]).map(s=><Row key={s.site_id} level="площадка" depth={0} color={siteColor(s)} name={s.name} sub={fmt(s.hosts)+' хостов · '+s.systems.length+' систем'} counts={s} reason={siteColor(s)==='green'?'норма':colorWord[siteColor(s)]+': '+s.systems.filter(x=>x.red||x.yellow).slice(0,3).map(x=>x.name).join(', ')} onlyBad={onlyBad}>
     {s.systems.map(x=>{const full=(systems??[]).find(y=>y.service_uid===x.service_uid);return full?sysRow(full,1,s.name,x):null})}</Row>)}
  </tbody></table>{systems&&!systems.length?<p className="muted pad">Систем пока нет — заведите первую в разделе «Системы».</p>:null}</div>
  <p className="muted">Цвет поднимается снизу вверх: хост → компонент → среда → система → {mode==='site'?'площадка':'направление'} → компания. В разрезе по площадкам у системы показаны её хосты на этой площадке; среды и компоненты — целиком.</p>
 </div>;
}
