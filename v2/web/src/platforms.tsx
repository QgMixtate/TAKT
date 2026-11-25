import {Fragment,useState} from 'react';
import {api,type PlatformInstance,type PlatformObjectView} from './api';
import {Err,Panel,Pill,Split,Strip,fmt,useLoad} from './ui';

// C57: платформы (KVM, VMware, zVirt/oVirt, Redfish, AD…) — что прислали collector и центр: экземпляры, объекты, связи
// с реестром и «в платформе, но не обследованы» (объекты-хосты без актива).
const platformName:Record<string,string>={kvm:'KVM',vsphere:'VMware vSphere',ovirt:'zVirt / oVirt',redfish:'Redfish (BMC)',ad:'Active Directory',hyperv:'Hyper-V',proxmox:'Proxmox'};
const kindName:Record<string,string>={datacenter:'ЦОД',cluster:'Кластеры',host:'Хосты',vm:'ВМ',datastore:'Хранилища',network:'Сети',pool:'Пулы',chassis:'Шасси',bmc:'BMC',computer:'Компьютеры'};
const when=(v:string|null)=>v?new Date(v).toLocaleString('ru-RU',{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'}).replace(',',''):'—';
const attrText=(o:PlatformObjectView)=>Object.entries(o.attrs).filter(([,v])=>v!==null&&v!=='').slice(0,4).map(([k,v])=>k+': '+String(v)).join(' · ');

export function PlatformsView({onOpenAsset,onExpired}:{onOpenAsset:(uid:string)=>void;onExpired:()=>void}){
 const [list,err]=useLoad(()=>api.platforms(),[],onExpired);
 const [sel,setSel]=useState<string>(''),[kind,setKind]=useState(''),[q,setQ]=useState(''),[unmatched,setUnmatched]=useState(false);
 const items=list?.items??[];
 const cur:PlatformInstance|undefined=items.find(i=>i.instance_id===sel)??items[0];
 const [objs,objErr]=useLoad(()=>cur?api.platformObjects(cur.instance_id,{kind,q,unmatched}):Promise.resolve(null),[cur?.instance_id,kind,q,unmatched],onExpired);
 const total=(k:string)=>items.reduce((n,i)=>n+(i.objects[k]??0),0);
 const side=cur?<div className="pad"><h2>{cur.name||cur.instance}</h2><p className="sub">{platformName[cur.platform]??cur.platform} · <span className="mono">{cur.instance}</span></p>
  <dl className="kv"><dt>Последний снимок</dt><dd>{when(cur.last_snapshot_at)}</dd><dt>Полный снимок</dt><dd>{when(cur.last_complete_at)}</dd>
   {Object.entries(cur.objects).map(([k,n])=><Fragment key={k}><dt>{kindName[k]??k}</dt><dd>{fmt(n)}</dd></Fragment>)}
   <dt>Связаны с реестром</dt><dd>{fmt(cur.matched)}</dd><dt>Не обследованы</dt><dd>{cur.unmatched?<button className="link" onClick={()=>setUnmatched(true)}>{fmt(cur.unmatched)}</button>:'0'}</dd><dt>Удалены из платформы</dt><dd>{fmt(cur.removed)}</dd></dl>
  {cur.errors.length?<><h4>Замечания сбора</h4><ul className="plain-list">{cur.errors.map(e=><li key={e} className="mono problem-text">{e}</li>)}</ul></>:null}</div>:null;
 return <div className="platforms">
  <Strip label="Сводка платформ" items={[{key:'i',n:list?items.length:null,label:'платформ',active:!unmatched,onClick:()=>setUnmatched(false)},{key:'h',n:list?total('host'):null,label:'хостов'},{key:'v',n:list?total('vm'):null,label:'ВМ'},{key:'c',n:list?total('computer'):null,label:'компьютеров AD'},{key:'u',n:list?items.reduce((n,i)=>n+i.unmatched,0):null,label:'не обследованы',tone:'amber',active:unmatched,onClick:()=>setUnmatched(true)}]}/>
  <Err e={err}/>
  {list&&!items.length?<div className="empty"><span>⧉</span><h3>Платформ пока нет</h3><p>KVM появится сам после сбора SSH-цели хоста с libvirt (учётке нужно чтение libvirt); компьютеры домена — после полной синхронизации с AD. VMware, zVirt и Redfish — следующими этапами.</p></div>:
  <Split side={side}>
   <div className="systems-toolbar"><select aria-label="Платформа" value={cur?.instance_id??''} onChange={e=>setSel(e.target.value)}>{items.map(i=><option key={i.instance_id} value={i.instance_id}>{(platformName[i.platform]??i.platform)+' · '+(i.name||i.instance)}</option>)}</select>
    <select aria-label="Вид объекта" value={kind} onChange={e=>setKind(e.target.value)}><option value="">Все объекты</option>{Object.entries(kindName).map(([k,l])=><option key={k} value={k}>{l}</option>)}</select>
    <input className="toolbar-search" aria-label="Поиск объекта" placeholder="Имя объекта" value={q} onChange={e=>setQ(e.target.value)}/>
    {unmatched?<span className="chip">Не обследованы <button aria-label="Убрать фильтр" onClick={()=>setUnmatched(false)}>×</button></span>:null}</div>
   <Err e={objErr}/>
   <Panel title={'Объекты · '+fmt(objs?.total??0)} flush>{objs?.items.length?<table className="panel-table"><thead><tr><th>Объект</th><th>Вид</th><th>В реестре</th><th>Параметры</th><th>В снимке</th></tr></thead><tbody>
    {objs.items.map(o=><tr key={o.ref} className={o.removed_at?'muted':''}><td><b>{o.name||o.ref}</b>{o.removed_at?<Pill tone="grey">удалён {when(o.removed_at)}</Pill>:null}</td><td>{kindName[o.kind]??o.kind}</td>
     <td>{o.asset_uid?<button className="link" onClick={()=>onOpenAsset(o.asset_uid!)}>карточка хоста →</button>:['host','vm','computer','chassis'].includes(o.kind)?<span className="amber-text">не обследован</span>:<span className="muted">—</span>}</td>
     <td className="muted">{attrText(o)||'—'}</td><td className="muted">{when(o.last_seen)}</td></tr>)}</tbody></table>:<p className="muted pad">{objs?'Объектов по фильтру нет.':'Загрузка…'}</p>}</Panel>
  </Split>}
 </div>;
}
