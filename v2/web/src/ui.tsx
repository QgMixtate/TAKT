import {useEffect,useState,type ReactNode} from 'react';
import {ApiError,errorMessage} from './api';

// C53.07 — общие элементы макетов «Остальные разделы»: полоса счётчиков, раскладка «список + правая панель»,
// вкладки раздела, панели, пилюли, точки состояния, полоса процента. Классы — из theme.css (как у «Систем»).

export type StripItem={key:string;n:number|string|null;label:string;tone?:'warn'|'amber'|'muted';active?:boolean;onClick?:()=>void};
export const fmt=(n:number)=>n.toLocaleString('ru-RU');
export function Strip({items,label,right}:{items:StripItem[];label:string;right?:ReactNode}){
 return <div className="count-strip" role="toolbar" aria-label={label}>{items.map(i=><button key={i.key} className={'count'+(i.active?' active':'')+(i.tone==='warn'?' warn':i.tone==='amber'?' amber':i.tone==='muted'?' muted':'')} disabled={!i.onClick} onClick={i.onClick}><b>{i.n===null?'…':typeof i.n==='number'?fmt(i.n):i.n}</b> {i.label}</button>)}{right?<><span className="spacer"/>{right}</>:null}</div>;
}
export function Split({children,side,wide}:{children:ReactNode;side?:ReactNode;wide?:boolean}){
 return <div className={'systems-grid'+(side?'':' solo')+(wide?' side-wide':'')}><section className="systems-main">{children}</section>{side?<aside className="composition side-panel">{side}</aside>:null}</div>;
}
export function PageTabs<T extends string>({tabs,value,onChange,label}:{tabs:[T,string][];value:T;onChange:(v:T)=>void;label:string}){
 return <div className="card-tabs-bar page-tabs" role="tablist" aria-label={label}>{tabs.map(([k,l])=><button key={k} role="tab" aria-selected={value===k} className={value===k?'active':''} onClick={()=>onChange(k)}>{l}</button>)}</div>;
}
export function Panel({title,right,children,flush}:{title:ReactNode;right?:ReactNode;children:ReactNode;flush?:boolean}){
 return <section className="panel"><header><h3>{title}</h3>{right?<span className="header-actions">{right}</span>:null}</header>{flush?children:<div className="pad">{children}</div>}</section>;
}
export type Tone='red'|'amber'|'green'|'blue'|'grey';
export function Pill({tone='grey',children}:{tone?:Tone;children:ReactNode}){return <span className={'pill pill-'+({red:'bad',amber:'warn',green:'ok',blue:'blue',grey:'grey'} as const)[tone]}>{children}</span>}
export function StateDot({tone,children}:{tone:Tone;children?:ReactNode}){return <span className="state-dot"><span className={'hdot h-'+({red:'red',amber:'yellow',green:'green',blue:'blue',grey:'grey'} as const)[tone]}/>{children}</span>}
export function Pct({value}:{value:number}){const v=Math.max(0,Math.min(100,Math.round(value)));return <span className="fresh"><i className={v>=95?'ok':v>=85?'warn':'bad'}><b style={{width:v+'%'}}/></i>{v}%</span>}
export const Err=({e}:{e:unknown})=>e?<div className="error" role="alert">{errorMessage(e)}</div>:null;
export const when=(v:string|null|undefined)=>v?new Date(v).toLocaleString('ru-RU',{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'}).replace(',',''):'—';
export function useLoad<T>(load:()=>Promise<T>,deps:unknown[],onExpired:()=>void):[T|null,unknown,()=>void]{
 const [data,setData]=useState<T|null>(null),[error,setError]=useState<unknown>(null),[n,setN]=useState(0);
 useEffect(()=>{let live=true;setError(null);load().then(d=>{if(live)setData(d)}).catch(e=>{if(live){setError(e);if(e instanceof ApiError&&e.status===401)onExpired()}});return()=>{live=false}},[...deps,n]);
 return [data,error,()=>setN(x=>x+1)];
}
