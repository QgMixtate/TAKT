import {useEffect,useState} from 'react';
import {api,ApiError,type AssetPresence} from './api';

const fmt=(v:string|null)=>v?new Date(v).toLocaleString('ru-RU'):'—';
const label:Record<AssetPresence['state'],[string,string]>={present:['в сети','state-ok'],missing:['пропал из сети','state-unavailable'],unknown:['нет обследований','state-unknown']};

// C21.02: присутствие актива по обследованиям подсетей — отдельно от свежести данных и пульса агента.
export function PresenceBlock({asset,onExpired}:{asset:string;onExpired:()=>void}){
 const [p,setP]=useState<AssetPresence|null>(null),[error,setError]=useState(false);
 useEffect(()=>{let live=true;setP(null);setError(false);api.assetPresence(asset).then(v=>{if(live)setP(v)}).catch(e=>{if(!live)return;setError(true);if(e instanceof ApiError&&e.status===401)onExpired()});return()=>{live=false}},[asset]);
 if(error)return <p className="muted">Присутствие в сети: не удалось загрузить.</p>;
 if(!p)return null;
 return <div className="presence-block"><h3>Присутствие в сети <span className={'badge '+label[p.state][1]}><i/>{label[p.state][0]}</span></h3>
  {p.items.length===0?<p className="muted">Адресов актива нет в обследованных подсетях. Присутствие не означает свежесть данных.</p>:
  <ul>{p.items.map(h=><li key={h.network_id+h.ip}><span className="mono">{h.ip}</span> · {h.network_name} · {h.state==='present'?(h.misses?'не найден в '+h.misses+' из '+p.miss_after+' последних обследований':'найден '+fmt(h.last_seen)):'пропал с '+fmt(h.missing_since)+' (не найден в '+p.miss_after+' обследованиях подряд)'}</li>)}</ul>}
 </div>;
}
