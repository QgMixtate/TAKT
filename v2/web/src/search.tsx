import {useEffect,useState,type FormEvent,type ReactNode} from 'react';
import {api,ApiError,errorMessage,type Product,type RSMComponentRow,type RSMSystemState,type SearchItem,type SearchPage,type Subject,type Ticket} from './api';
import {classNames} from './cmdb';
import {Panel,Pill,fmt} from './ui';

// C29 + C53.07 (макет «Поиск»): один запрос — по системам, компонентам, хостам (полнотекстовый сервис поиска или
// запасной точный режим, о котором говорится прямо), ПО, обращениям и людям. Каждый источник ищется отдельно и с
// учётом прав: недоступный источник не ломает выдачу, а помечается.
const osNames:Record<string,string>={linux:'Linux',windows:'Windows',unknown:'Не определена'};
const critNames:Record<string,string>={unknown:'не задана',low:'низкая',medium:'средняя',high:'высокая',critical:'критичная'};
const stateNames:Record<string,string>={new:'новый',assigned:'назначен',in_progress:'в работе',pending:'ждём',resolved:'решено',closed:'закрыт',approval:'согласование'};
type Kind='systems'|'components'|'hosts'|'software'|'tickets'|'people';
const kindNames:Record<Kind,string>={systems:'Системы',components:'Компоненты',hosts:'Хосты',software:'ПО',tickets:'Обращения',people:'Люди и команды'};
const kindPill:Record<Kind,string>={systems:'система',components:'компонент',hosts:'хост',software:'ПО',tickets:'обращение',people:'сотрудник'};
type Found={systems:RSMSystemState[]|null;components:RSMComponentRow[]|null;componentsTotal:number;hosts:SearchPage|null;hostItems:SearchItem[];software:Product[]|null;tickets:Ticket[]|null;people:Subject[]|null;failed:Kind[]};

function Highlighted({text,ranges}:{text:string;ranges:[number,number][]}){
 const chars=[...text],out:ReactNode[]=[];let at=0;
 ranges.forEach(([a,b],i)=>{if(a>at)out.push(chars.slice(at,a).join(''));out.push(<mark key={i}>{chars.slice(a,b).join('')}</mark>);at=b});
 if(at<chars.length)out.push(chars.slice(at).join(''));
 return <>{out}</>;
}
function Mark({text,q}:{text:string;q:string}){
 const i=text.toLowerCase().indexOf(q.toLowerCase());if(!q||i<0)return <>{text}</>;
 return <>{text.slice(0,i)}<mark>{text.slice(i,i+q.length)}</mark>{text.slice(i+q.length)}</>;
}
export function SearchView({initial='',onOpenAsset,onOpenSystem,onOpenComponent,onNavigate,onExpired}:{initial?:string;onOpenAsset:(uid:string)=>void;onOpenSystem?:(uid:string)=>void;onOpenComponent?:(id:string,system:string)=>void;onNavigate?:(view:string)=>void;onExpired:()=>void}){
 const [q,setQ]=useState(initial),[asked,setAsked]=useState(''),[f,setF]=useState<Found|null>(null),[kinds,setKinds]=useState<Record<Kind,boolean>>({systems:true,components:true,hosts:true,software:true,tickets:true,people:true}),[facet,setFacet]=useState<{os?:string;class?:string;site?:string;freshness?:string}>({}),[siteList,setSiteList]=useState<[string,string][]>([]),[error,setError]=useState<unknown>(null),[loading,setLoading]=useState(false),[more,setMore]=useState(false);
 useEffect(()=>{if(initial.trim().length>=2)void run(initial,{});api.hostsTree('site').then(t=>setSiteList(t.nodes.map(n=>[n.key,n.label]))).catch(()=>{})},[]); // общий поиск из шапки
 async function run(query:string,fc:{os?:string;class?:string;site?:string;freshness?:string}){
  query=query.trim();if(query.length<2)return;setLoading(true);setError(null);setMore(false);
  const r=await Promise.allSettled([api.rsmSystems({q:query,limit:50}),api.rsmComponents(query,0),api.search(query,fc,null),api.products(query),api.tickets({q:query}),api.subjects('',false)]);
  const val=<T,>(i:number)=>r[i].status==='fulfilled'?(r[i] as PromiseFulfilledResult<T>).value:null;
  const expired=r.some(x=>x.status==='rejected'&&x.reason instanceof ApiError&&x.reason.status===401);if(expired){onExpired();setLoading(false);return}
  const failed:Kind[]=(['systems','components','hosts','software','tickets','people'] as Kind[]).filter((_,i)=>r[i].status==='rejected');
  if(failed.includes('hosts'))setError((r[2] as PromiseRejectedResult).reason);
  const comps=val<{items:RSMComponentRow[];total:number}>(1),hosts=val<SearchPage>(2),people=val<{items:Subject[]}>(5);
  const ql=query.toLowerCase();
  setF({systems:val<{items:RSMSystemState[]}>(0)?.items??null,components:comps?.items??null,componentsTotal:comps?.total??0,hosts,hostItems:hosts?.items??[],software:val<{items:Product[]}>(3)?.items??null,tickets:val<{items:Ticket[]}>(4)?.items??null,
   people:people?people.items.filter(s=>s.name.toLowerCase().includes(ql)||(s.username??'').toLowerCase().includes(ql)||s.contact.toLowerCase().includes(ql)):null,failed});
  setAsked(query);setLoading(false);
 }
 async function moreHosts(){if(!f?.hosts?.next_cursor)return;setLoading(true);try{const p=await api.search(asked,facet,f.hosts.next_cursor);setF({...f,hosts:p,hostItems:[...f.hostItems,...p.items]})}catch(e){setError(e);if(e instanceof ApiError&&e.status===401)onExpired()}finally{setLoading(false)}}
 function submit(e:FormEvent){e.preventDefault();setFacet({});void run(q,{})}
 function pickFacet(kind:'os'|'class',value:string){const nf={...facet,[kind]:facet[kind]===value?undefined:value};setFacet(nf);void run(asked||q,nf)}
 const counts:Record<Kind,number|null>=f?{systems:f.systems?.length??null,components:f.components?f.componentsTotal:null,hosts:f.hosts?f.hostItems.length+(f.hosts.next_cursor?1:0):null,software:f.software?.length??null,tickets:f.tickets?.length??null,people:f.people?.length??null}:{systems:null,components:null,hosts:null,software:null,tickets:null,people:null};
 const total=Object.values(counts).reduce<number>((a,b)=>a+(b??0),0);
 const hits:ReactNode[]=[];
 if(f){
  if(kinds.systems)for(const s of f.systems??[])hits.push(<button key={'s'+s.service_uid} className="hit" onClick={()=>onOpenSystem?.(s.service_uid)}><div className="t"><Pill tone="blue">{kindPill.systems}</Pill><Mark text={s.name} q={asked}/></div><div className="s">критичность {critNames[s.criticality]??s.criticality}{s.business_owner?' · владелец ':''}{s.business_owner?<Mark text={s.business_owner} q={asked}/>:null} · хостов {s.state.hosts}</div></button>);
  if(kinds.components)for(const c of f.components??[])hits.push(<button key={'c'+c.component_id} className="hit" onClick={()=>onOpenComponent?.(c.component_id,c.service_uid)}><div className="t"><Pill tone="blue">{kindPill.components}</Pill><Mark text={c.name} q={asked}/></div><div className="s">{c.system_name} / {c.environment_name}{c.role?' · '+c.role:''}{c.state?' · хостов '+c.state.hosts:''}</div></button>);
  if(kinds.hosts)for(const h of f.hostItems)hits.push(<button key={'h'+h.asset_uid} className="hit" onClick={()=>onOpenAsset(h.asset_uid)}><div className="t"><Pill tone="blue">{kindPill.hosts}</Pill><Mark text={h.display_name??h.observed_hostname??'Без имени'} q={asked}/></div><div className="s">{h.observed_os??''}{h.fragment?<> · <Highlighted text={h.fragment} ranges={h.highlights}/></>:null}</div></button>);
  if(kinds.tickets)for(const t of f.tickets??[])hits.push(<button key={'t'+t.ticket_id} className="hit" onClick={()=>onNavigate?.('tickets')}><div className="t"><Pill tone="blue">{kindPill.tickets}</Pill>{t.number}</div><div className="s"><Mark text={t.title} q={asked}/> · {stateNames[t.state]??t.state}</div></button>);
  if(kinds.people)for(const p of f.people??[])hits.push(<button key={'p'+p.subject_id} className="hit" onClick={()=>onNavigate?.('org')}><div className="t"><Pill tone="blue">{p.kind==='team'?'команда':kindPill.people}</Pill><Mark text={p.name} q={asked}/></div><div className="s">{p.contact||p.username||''}{p.active?'':' · неактивен'}</div></button>);
 }
 const shown=more?hits:hits.slice(0,30);
 return <div className="search-page">
  <form className="search-big" role="search" onSubmit={submit}><span aria-hidden="true">⌕</span><input aria-label="Запрос" placeholder="Система, компонент, хост, IP, MAC, серийный номер, ПО, обращение, сотрудник" value={q} onChange={e=>setQ(e.target.value)}/><button className="button primary-sm" disabled={loading||q.trim().length<2}>Найти</button></form>
  {f?<p className="muted">Найдено {fmt(total)}{f.hosts?.next_cursor?'+':''} · с учётом ваших прав доступа{f.failed.filter(k=>k!=='hosts').length?' · не удалось искать: '+f.failed.filter(k=>k!=='hosts').map(k=>kindNames[k].toLowerCase()).join(', '):''}</p>:null}
  {error?<div className="error" role="alert">{errorMessage(error)}</div>:null}
  {f?.hosts?.mode==='fallback_exact'?<div className="error" role="status">{f.hosts.notice}</div>:null}
  {f?.hosts&&f.hosts.mode==='fulltext'&&f.hosts.pending_index_events>0?<p className="card-note search-lag">Индекс догоняет изменения: ожидают индексации {f.hosts.pending_index_events}. Самые свежие правки могут ещё не находиться.</p>:null}
  {f?<div className="search-cols">
   <Panel title="Что искать"><div className="facet">{(Object.keys(kindNames) as Kind[]).map(k=><label key={k}><input type="checkbox" checked={kinds[k]} onChange={e=>setKinds({...kinds,[k]:e.target.checked})}/> {kindNames[k]} <span>{counts[k]===null?'—':counts[k]}</span></label>)}
    {f.hosts?(['class','os'] as const).map(kind=>Object.keys(f.hosts!.facets[kind]).length?<div key={kind}><h4>Хосты · {kind==='os'?'ОС':'класс'}</h4>{Object.entries(f.hosts!.facets[kind]).sort((a,b)=>b[1]-a[1]).map(([v,n])=><label key={v}><input type="checkbox" checked={facet[kind]===v} onChange={()=>pickFacet(kind,v)}/> {kind==='os'?(osNames[v]??v):(classNames[v as keyof typeof classNames]??v)} <span>{n}</span></label>)}</div>:null):null}</div><div className="facet-selects"><label>Площадка<select aria-label="Площадка" value={facet.site??''} onChange={e=>{const fc={...facet,site:e.target.value||undefined};setFacet(fc);if(asked)void run(asked,fc)}}><option value="">все</option>{siteList.map(([k,l])=><option key={k} value={k}>{l}</option>)}</select></label><label>Состояние<select aria-label="Состояние" value={facet.freshness??''} onChange={e=>{const fc={...facet,freshness:e.target.value||undefined};setFacet(fc);if(asked)void run(asked,fc)}}><option value="">любое</option><option value="fresh">данные актуальны</option><option value="stale">данные устарели</option><option value="unknown">нет сведений</option></select></label></div></Panel>
   <div>{shown.length?<div className="hits">{shown}</div>:<div className="empty"><span>⌕</span><h3>Ничего не найдено</h3><p>{f.hosts?.mode==='fallback_exact'?'В запасном режиме хосты ищутся только по точным значениям.':'Проверьте написание или отметьте другие разделы.'}</p></div>}
    {hits.length>shown.length?<button className="link" onClick={()=>setMore(true)}>Показать ещё {hits.length-shown.length}</button>:null}{more&&f.hosts?.next_cursor&&kinds.hosts?<button className="link" disabled={loading} onClick={()=>void moreHosts()}>Ещё хосты</button>:null}</div>
   <Panel title={'ПО: «'+asked+'» — где установлено'} flush>{f.software===null?<p className="muted pad">Поиск ПО недоступен.</p>:!f.software.length||!kinds.software?<p className="muted pad">{kinds.software?'ПО с таким названием в собранных данных нет.':'Раздел «ПО» выключен.'}</p>:<table className="panel-table"><thead><tr><th>Продукт</th><th>Версии</th><th className="num">Хостов</th></tr></thead><tbody>{f.software.slice(0,12).map(p=><tr key={p.name+(p.publisher??'')}><td><b>{p.name}</b>{p.publisher?<small className="muted"> · {p.publisher}</small>:null}</td><td className="muted">{p.versions.slice(0,4).join(', ')||'—'}{p.versions.length>4?' …':''}</td><td className="num"><button className="link" onClick={()=>p.asset_uids[0]&&onOpenAsset(p.asset_uids[0])} title="Открыть первый хост">{p.assets}</button></td></tr>)}</tbody></table>}
    <p className="muted pad">Версии собраны агентами и SSH/WinRM. Все установки — в разделе {onNavigate?<button className="link" onClick={()=>onNavigate('software')}>«Поиск ПО»</button>:'«Поиск ПО»'}.</p></Panel>
  </div>:<div className="empty"><span>⌕</span><h3>Поиск по каталогу</h3><p>Ищет системы, компоненты, хосты (имена, FQDN, IP, MAC, серийные номера, назначение), ПО, обращения и сотрудников. Учитывает словоформы.</p></div>}
 </div>;
}
