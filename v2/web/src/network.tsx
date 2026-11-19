import {useMemo,useState} from 'react';
import {api,errorMessage,type HostRegistryPage,type HostTree,type RSMSystemPage,type Topology,type TopologyNode} from './api';
import {TopologyView} from './topology';
import {PageTabs,Panel,Pill,fmt,useLoad} from './ui';

// C53.05 (макет «Схема сети»): уровни — площадки, L3 (подсети), L2 (коммутаторы), системы; слева дерево подсетей
// с числом узлов, справа — паспорт выбранной подсети: шлюз, состав по типам, системы, свежесть данных и аномалии
// (неизвестный шлюз, один IP у разных активов, узлы без сбора). Карта L3 — прежняя, с поиском по выбранной подсети.
type Level='sites'|'l3'|'l2'|'systems';
const deviceNames:Record<string,string>={server:'серверы',workstation:'АРМ',virtual_machine:'ВМ',hypervisor:'гипервизоры',router:'маршрутизаторы',switch:'коммутаторы',unknown:'неизвестные'};
const prefixOf=(cidr:string)=>{const [ip,bits]=cidr.split('/');const p=ip.split('.');const n=Number(bits);return n>=24?p.slice(0,3).join('.')+'.':n>=16?p.slice(0,2).join('.')+'.':p[0]+'.'};

export function NetworkScreen({csrf,canWrite,focus,onOpenAsset,onOpenHosts,onExpired}:{csrf:string;canWrite:boolean;focus:string;onOpenAsset:(uid:string)=>void;onOpenHosts:()=>void;onExpired:()=>void}){
 const [level,setLevel]=useState<Level>('l3'),[sel,setSel]=useState<string>(''),[q,setQ]=useState(''),[system,setSystem]=useState('');
 const [topo,topoErr]=useLoad<Topology>(()=>api.topology(),[],onExpired);
 const nodes=useMemo(()=>new Map((topo?.nodes??[]).map(n=>[n.id,n])),[topo]);
 const subnets=useMemo(()=>{const out=new Map<string,{node:TopologyNode;hosts:TopologyNode[];gateways:TopologyNode[];conflicts:number}>();
  for(const n of topo?.nodes??[])if(n.kind==='subnet')out.set(n.id,{node:n,hosts:[],gateways:[],conflicts:0});
  for(const l of topo?.links??[]){const a=nodes.get(l.a),b=nodes.get(l.b);if(!a||!b)continue;const [s,o]=a.kind==='subnet'?[a,b]:b.kind==='subnet'?[b,a]:[null,null];if(!s||!o)continue;const x=out.get(s.id)!;
   if(o.kind==='gateway'||l.role==='gateway')x.gateways.push(o);else if(o.kind==='host')x.hosts.push(o);if(l.conflicts?.length)x.conflicts+=l.conflicts.length}
  return [...out.values()].sort((x,y)=>x.node.label.localeCompare(y.node.label,undefined,{numeric:true}))},[topo,nodes]);
 const cur=subnets.find(s=>s.node.id===sel);
 const [rows]=useLoad<HostRegistryPage|null>(()=>cur?api.hosts({q:prefixOf(cur.node.label),limit:500}):Promise.resolve(null),[sel],onExpired);
 const [sites]=useLoad<HostTree|null>(()=>level==='sites'?api.hostsTree('site'):Promise.resolve(null),[level],onExpired);
 const [systems]=useLoad<RSMSystemPage|null>(()=>level==='systems'?api.rsmSystems({limit:500}):Promise.resolve(null),[level],onExpired);
 const [sysHosts]=useLoad<HostRegistryPage|null>(()=>system?api.hosts({system,limit:500}):Promise.resolve(null),[system],onExpired);
 const l2=(topo?.links??[]).filter(l=>l.layer==='L2');
 const inNet=(rows?.items??[]).filter(h=>cur&&h.ip.startsWith(prefixOf(cur.node.label)));
 const fresh=inNet.length?Math.round(100*inNet.filter(h=>h.freshness==='fresh').length/inNet.length):null;
 const sysCount=new Map<string,number>();for(const h of inNet)if(h.system_name)sysCount.set(h.system_name,(sysCount.get(h.system_name)??0)+1);
 const byType=new Map<string,number>();for(const h of cur?.hosts??[])byType.set(h.device??'unknown',(byType.get(h.device??'unknown')??0)+1);
 const anomalies=cur?[...cur.gateways.filter(g=>!g.asset_uid).map(g=>'Неизвестный шлюз '+g.label+' — не найден в реестре'),...(cur.conflicts?['Один IP у разных активов: '+cur.conflicts+' связ.']:[]),...(inNet.filter(h=>h.freshness!=='fresh').length?[inNet.filter(h=>h.freshness!=='fresh').length+' узлов без свежего сбора']:[])]:[];
 const tree=<Panel title="Подсети" flush><div className="tree"><input className="toolbar-search tree-filter" aria-label="Фильтр подсетей" placeholder="Подсеть" value={q} onChange={e=>setQ(e.target.value)}/>
  {subnets.filter(s=>!q||s.node.label.includes(q)).map(s=><button key={s.node.id} className={'tree-item'+(sel===s.node.id?' active':'')} onClick={()=>setSel(sel===s.node.id?'':s.node.id)}><span className="mono">{s.node.label}</span><span className="muted">{fmt(s.hosts.length)}</span></button>)}
  {topo&&!subnets.length?<p className="muted pad">Подсетей нет: у хостов нет сетевых фактов.</p>:null}</div></Panel>;
 const side=cur?<aside className="net-side panel"><header><h3 className="mono">{cur.node.label}</h3><button className="link" onClick={onOpenHosts}>открыть хосты →</button></header><div className="pad">
  <dl className="kv"><dt>Шлюз</dt><dd>{cur.gateways.length?cur.gateways.map(g=>g.label+(g.asset_uid?'':' (неизвестный)')).join(', '):'—'}</dd>
   <dt>Состав</dt><dd>{[...byType].map(([k,n])=>fmt(n)+' '+(deviceNames[k]??k)).join(' · ')||'—'}</dd>
   <dt>Хостов</dt><dd>{fmt(cur.hosts.length)}{sysCount.size?' · '+sysCount.size+' систем':''}</dd>
   <dt>Системы</dt><dd>{[...sysCount].sort((a,b)=>b[1]-a[1]).slice(0,3).map(([k])=>k).join(', ')||'вне систем'}{sysCount.size>3?' и ещё '+(sysCount.size-3):''}</dd>
   <dt>Данные</dt><dd>{fresh===null?'нет сведений':fresh+'% актуальны'}</dd></dl>
  <h4>Аномалии · {anomalies.length}</h4>{anomalies.length?<ul className="plain-list">{anomalies.map((a,i)=><li key={i} className="problem-text">{a}</li>)}</ul>:<p className="muted">Не найдено.</p>}</div></aside>:null;
 return <div className="network">
  <PageTabs label="Уровень схемы" tabs={[['sites','Площадки'],['l3','L3 — подсети'],['l2','L2 — коммутаторы'],['systems','Системы']]} value={level} onChange={setLevel}/>
  {topoErr?<div className="error" role="alert">{errorMessage(topoErr)}</div>:null}
  {level==='l3'?<div className="net-grid">{tree}<div className="net-map"><TopologyView key={(cur?.node.label??focus)} csrf={csrf} canWrite={canWrite} onOpenAsset={onOpenAsset} onExpired={onExpired} focus={cur?prefixOf(cur.node.label):focus}/></div>{side}</div>:null}
  {level==='sites'?<div className="page-pad"><Panel title="Площадки и сегменты" flush><table className="panel-table"><thead><tr><th>Площадка</th><th>Сегменты</th><th className="num">Хостов</th></tr></thead><tbody>{(sites?.nodes??[]).map(s=><tr key={s.key}><td><b>{s.label||'—'}</b></td><td>{s.children.map(c=>(c.label||'без сегмента')+' · '+fmt(c.count)).join(', ')}</td><td className="num">{fmt(s.count)}</td></tr>)}</tbody></table>{sites&&!sites.nodes.length?<p className="muted pad">Площадок с хостами нет.</p>:null}</Panel></div>:null}
  {level==='l2'?<div className="page-pad"><Panel title={'Связи L2 · '+l2.length} flush>{l2.length?<table className="panel-table"><thead><tr><th>Устройство</th><th>Сосед</th><th>Достоверность</th><th>Основание</th></tr></thead><tbody>{l2.map((l,i)=><tr key={i}><td>{nodes.get(l.a)?.label??l.a}</td><td>{nodes.get(l.b)?.label??l.b}</td><td><Pill tone={l.confidence==='confirmed'?'green':l.confidence==='probable'?'blue':'grey'}>{l.confidence==='confirmed'?'подтверждена':l.confidence==='probable'?'вероятна':'слабая'}</Pill></td><td className="muted">{l.evidence.map(e=>e.detail).join('; ')}</td></tr>)}</tbody></table>:<p className="muted pad">Связей L2 нет: соседи по LLDP/CDP и MAC-таблицы коммутаторов ещё не собраны (SNMP-цели коммутаторов — в «Обследованиях сети»).</p>}</Panel></div>:null}
  {level==='systems'?<div className="page-pad two-col"><Panel title="Подсветить систему"><select aria-label="Система" value={system} onChange={e=>setSystem(e.target.value)}><option value="">выберите систему…</option>{(systems?.items??[]).map(s=><option key={s.service_uid} value={s.service_uid}>{s.name}</option>)}</select>
    <p className="muted">Показывает, в каких подсетях стоят хосты системы; подсеть открывается на карте L3.</p></Panel>
   <Panel title="Подсети системы" flush>{sysHosts?(()=>{const m=new Map<string,number>();for(const h of sysHosts.items){if(!h.ip)continue;const s=subnets.find(x=>h.ip.startsWith(prefixOf(x.node.label)));const k=s?s.node.id:'';m.set(k,(m.get(k)??0)+1)}return <table className="panel-table"><tbody>{[...m].map(([k,n])=><tr key={k||'none'}><td className="mono">{k?nodes.get(k)?.label:'вне известных подсетей'}</td><td className="num">{fmt(n)} хост.</td><td>{k?<button className="link" onClick={()=>{setSel(k);setLevel('l3')}}>на карте →</button>:null}</td></tr>)}</tbody></table>})():<p className="muted pad">Выберите систему.</p>}</Panel></div>:null}
 </div>;
}
