import {useEffect,useState} from 'react';
import {api,ApiError,errorMessage,type PortableReport,type PortableScope,type Source} from './api';

// C23: portable-аудит из Web — команда init с подставленными площадкой и сегментом, регистрация открытого ключа
// вставкой вывода init (ключ подписи остаётся на ПК), загрузка пакета и итог импорта.
const fields=['tenant_id','site_id','scope_id','source_id','generation_id','key_id','public_key'] as const;
type Parsed=Partial<Record<typeof fields[number],string>>;
export function parseInit(text:string):Parsed{const out:Parsed={};for(const line of text.split(/\r?\n/)){const m=/^\s*([a-z_]+)=(\S+)\s*$/.exec(line);if(m&&(fields as readonly string[]).includes(m[1]))out[m[1] as typeof fields[number]]=m[2]}return out}
const dispositionName:Record<string,string>={applied:'принято',duplicate:'уже было',rejected:'отклонено',quarantined:'в карантине',recorded_pending_resolution:'ждёт разбора'};

export function PortablePanel({csrf,tenant,sources,onChanged,onExpired}:{csrf:string;tenant:string;sources:Source[];onChanged:()=>void;onExpired:()=>void}){
 const [open,setOpen]=useState(false),[scopes,setScopes]=useState<PortableScope[]>([]),[scope,setScope]=useState(''),[initText,setInitText]=useState(''),[busy,setBusy]=useState(false),[error,setError]=useState<unknown>(null),[note,setNote]=useState<string|null>(null);
 const [source,setSource]=useState(''),[file,setFile]=useState<File|null>(null),[report,setReport]=useState<PortableReport|null>(null);
 const fail=(e:unknown)=>{setError(e);if(e instanceof ApiError&&e.status===401)onExpired()};
 useEffect(()=>{if(!open)return;api.portableScopes().then(p=>{setScopes(p.items);if(p.items[0])setScope(p.items[0].scope_id)}).catch(fail)},[open]);
 const chosen=scopes.find(s=>s.scope_id===scope);
 const args=chosen?`--tenant ${tenant} --site ${chosen.site_id} --scope ${chosen.scope_id}`:'';
 const parsed=parseInit(initText);const ready=!!(parsed.site_id&&parsed.scope_id&&parsed.source_id&&parsed.generation_id&&parsed.public_key);
 const portables=sources.filter(s=>s.source_kind==='portable');
 async function register(){setBusy(true);setError(null);setNote(null);try{const r=await api.registerPortable(csrf,{site_id:parsed.site_id!,scope_id:parsed.scope_id!,source_id:parsed.source_id!,generation_id:parsed.generation_id!,public_key:parsed.public_key!});setNote('Источник зарегистрирован: '+r.source_id.slice(0,8)+'… Теперь соберите пакет и загрузите его ниже.');setSource(r.source_id);setInitText('');onChanged()}catch(e){fail(e)}finally{setBusy(false)}}
 async function upload(){if(!file||!source)return;setBusy(true);setError(null);setReport(null);try{setReport(await api.importPortable(csrf,source,file));onChanged()}catch(e){fail(e)}finally{setBusy(false)}}
 const counts=report?Object.entries(report.records.reduce<Record<string,number>>((a,r)=>{a[r.disposition]=(a[r.disposition]??0)+1;return a},{})):[];
 return <section className="table-panel portable-panel"><div className="table-toolbar"><h2>Portable-аудит <span>офлайн</span></h2><button className="button small" aria-expanded={open} onClick={()=>setOpen(v=>!v)}>{open?'Скрыть':'Открыть'}</button></div>
  {open?<div className="portable-body">
   {error?<div className="error" role="alert">{errorMessage(error)}</div>:null}{note?<div className="map-notice ok" role="status">{note}</div>:null}
   <ol className="portable-steps">
    <li><strong>Подготовка на ПК.</strong> Площадка: <select aria-label="Площадка и сегмент" value={scope} onChange={e=>setScope(e.target.value)}>{scopes.map(s=><option key={s.scope_id} value={s.scope_id}>{s.site_name} · {s.namespace}</option>)}</select>
     {chosen?<><p className="panel-note">Linux (программа <span className="mono">surveyscan-portable</span> из выпуска):</p><pre className="mono cmd">{`./surveyscan-portable init --state ./ss-portable ${args}\n./surveyscan-portable collect --state ./ss-portable --out audit.zip`}</pre>
      <p className="panel-note">Windows («от администратора», <span className="mono">surveyscan-portable.exe</span>):</p><pre className="mono cmd">{`.\\surveyscan-portable.exe init --state C:\\ss-portable ${args}\n.\\surveyscan-portable.exe collect --state C:\\ss-portable --out audit.zip`}</pre></>:null}</li>
    <li><strong>Регистрация ключа.</strong> Вставьте весь вывод команды <span className="mono">init</span> (открытый ключ; ключ подписи остаётся на ПК):
     <textarea aria-label="Вывод init" className="mono" rows={6} value={initText} onChange={e=>setInitText(e.target.value)} placeholder={'tenant_id=…\nsite_id=…\nscope_id=…\nsource_id=…\ngeneration_id=…\nkey_id=…\npublic_key=…'}/>
     {initText&&!ready?<p className="panel-note">Не хватает строк: {['site_id','scope_id','source_id','generation_id','public_key'].filter(k=>!parsed[k as keyof Parsed]).join(', ')}</p>:null}
     <button className="button small" disabled={!ready||busy} onClick={()=>void register()}>Зарегистрировать источник</button></li>
    <li><strong>Загрузка пакета.</strong> Источник: <select aria-label="Portable-источник" value={source} onChange={e=>setSource(e.target.value)}><option value="">выберите…</option>{portables.map(s=><option key={s.source_id} value={s.source_id}>{s.source_id.slice(0,8)}… · {s.state}</option>)}</select>
     <input aria-label="Файл пакета" type="file" accept=".zip,application/zip" onChange={e=>setFile(e.target.files?.[0]??null)}/>
     <button className="button small" disabled={!file||!source||busy} onClick={()=>void upload()}>{busy?'Загружаем…':'Загрузить и импортировать'}</button>
     {report?<p className="panel-note" role="status">Записей: {report.records.length} — {counts.map(([k,n])=>(dispositionName[k]??k)+': '+n).join(', ')}{report.complete?'.':' · обработка не завершена (осталось '+report.remaining+'): отправьте тот же файл ещё раз — продолжится с места остановки.'}</p>:null}</li>
   </ol></div>:null}
 </section>;
}
