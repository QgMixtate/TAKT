import {useEffect,useState} from 'react';
import {Panel} from './ui';
import {api,ApiError,errorMessage,type PortableDiscoveryHost,type PortableEncryption,type PortableReport,type PortableScope,type Source} from './api';

// C23: portable-аудит из Web — команда init с подставленными площадкой и сегментом, регистрация открытого ключа
// вставкой вывода init (ключ подписи остаётся на ПК), загрузка пакета и итог импорта.
const fields=['tenant_id','site_id','scope_id','source_id','generation_id','key_id','public_key'] as const;
type Parsed=Partial<Record<typeof fields[number],string>>;
export function parseInit(text:string):Parsed{const out:Parsed={};for(const line of text.split(/\r?\n/)){const m=/^\s*([a-z_]+)=(\S+)\s*$/.exec(line);if(m&&(fields as readonly string[]).includes(m[1]))out[m[1] as typeof fields[number]]=m[2]}return out}
const dispositionName:Record<string,string>={applied:'принято',duplicate:'уже было',rejected:'отклонено',quarantined:'в карантине',recorded_pending_resolution:'ждёт разбора'};

export function PortablePanel({csrf,tenant,sources,onChanged,onExpired}:{csrf:string;tenant:string;sources:Source[];onChanged:()=>void;onExpired:()=>void}){
 const open=true,[scopes,setScopes]=useState<PortableScope[]>([]),[scope,setScope]=useState(''),[initText,setInitText]=useState(''),[busy,setBusy]=useState(false),[error,setError]=useState<unknown>(null),[note,setNote]=useState<string|null>(null);
 const [source,setSource]=useState(''),[file,setFile]=useState<File|null>(null),[report,setReport]=useState<PortableReport|null>(null),[enc,setEnc]=useState<PortableEncryption|null>(null),[encOK,setEncOK]=useState(false);
 const fail=(e:unknown)=>{setError(e);if(e instanceof ApiError&&e.status===401)onExpired()};
 useEffect(()=>{if(!open)return;api.portableScopes().then(p=>{setScopes(p.items);setEnc(p.encryption);setEncOK(p.encryption_available);if(p.items[0])setScope(p.items[0].scope_id)}).catch(fail)},[open]);
 const chosen=scopes.find(s=>s.scope_id===scope);
 const args=chosen?`--tenant ${tenant} --site ${chosen.site_id} --scope ${chosen.scope_id}`+(enc?` --center-key ${enc.public_key}`:''):'';
 const parsed=parseInit(initText);const ready=!!(parsed.site_id&&parsed.scope_id&&parsed.source_id&&parsed.generation_id&&parsed.public_key);
 const portables=sources.filter(s=>s.source_kind==='portable');
 async function register(){setBusy(true);setError(null);setNote(null);try{const r=await api.registerPortable(csrf,{site_id:parsed.site_id!,scope_id:parsed.scope_id!,source_id:parsed.source_id!,generation_id:parsed.generation_id!,public_key:parsed.public_key!});setNote('Источник зарегистрирован: '+r.source_id.slice(0,8)+'… Теперь соберите пакет и загрузите его ниже.');setSource(r.source_id);setInitText('');onChanged()}catch(e){fail(e)}finally{setBusy(false)}}
 async function encrypt(){setBusy(true);setError(null);try{setEnc(await api.enablePortableEncryption(csrf));setNote('Шифрование включено: команда init ниже содержит ключ центра. Пакеты с таких ПК читаются только центром.')}catch(e){fail(e)}finally{setBusy(false)}}
 async function upload(){if(!file||!source)return;setBusy(true);setError(null);setReport(null);try{setReport(await api.importPortable(csrf,source,file));onChanged()}catch(e){fail(e)}finally{setBusy(false)}}
 const counts=report?Object.entries(report.records.reduce<Record<string,number>>((a,r)=>{a[r.disposition]=(a[r.disposition]??0)+1;return a},{})):[];
 // C53.07 (макет «Portable-аудит»): слева — как провести аудит, справа — загрузка результата; ниже носители и найденные узлы.
 return <div className="portable-page">
  {error?<div className="error" role="alert">{errorMessage(error)}</div>:null}{note?<div className="map-notice ok" role="status">{note}</div>:null}
  <div className="two-col portable-top">
   <Panel title="Как провести аудит без установки"><ol className="steps">
    <li><span className="n">1</span><div><b>Подготовить носитель</b><p className="muted">Площадка и сегмент: <select aria-label="Площадка и сегмент" value={scope} onChange={e=>setScope(e.target.value)}>{scopes.map(s=><option key={s.scope_id} value={s.scope_id}>{s.site_name} · {s.namespace}</option>)}</select></p>
     {chosen?<details className="cmds"><summary>Команды для носителя — Linux и Windows</summary><p className="muted">Linux (<span className="mono">surveyscan-portable</span> из выпуска):</p><pre className="mono cmd">{`./surveyscan-portable init --state "$HOME/ss-portable" ${args}\n./surveyscan-portable collect --state "$HOME/ss-portable" --out "$HOME/ss-portable-audit.zip"\n./surveyscan-portable verify --package "$HOME/ss-portable-audit.zip" --public-key <public_key из вывода init>`}</pre>
      <p className="muted">Windows («от администратора», <span className="mono">surveyscan-portable.exe</span>):</p><pre className="mono cmd">{`.\\surveyscan-portable.exe init --state C:\\ss-portable ${args}\n.\\surveyscan-portable.exe collect --state C:\\ss-portable --out C:\\ss-portable-audit.zip\n.\\surveyscan-portable.exe verify --package C:\\ss-portable-audit.zip --public-key <public_key из вывода init>`}</pre></details>:null}
     <p className="muted"><b>Шифрование пакета:</b> {enc?<span>включено, ключ центра <span className="mono">{enc.key_id.slice(0,16)}</span> — потерянный носитель не прочитать.</span>:encOK?<><span>выключено — пакет читается любым, у кого он окажется. </span><button className="button small" disabled={busy} onClick={()=>void encrypt()}>Включить шифрование</button></>:<span>недоступно: у центра не настроено хранилище секретов.</span>}</p></div></li>
    <li><span className="n">2</span><div><b>Зарегистрировать носитель</b><p className="muted">Вставьте весь вывод <span className="mono">init</span> — открытый ключ; ключ подписи остаётся на носителе.</p>
     <textarea aria-label="Вывод init" className="mono" rows={5} value={initText} onChange={e=>setInitText(e.target.value)} placeholder={'tenant_id=…\nsite_id=…\nscope_id=…\nsource_id=…\ngeneration_id=…\nkey_id=…\npublic_key=…'}/>
     {initText&&!ready?<p className="muted">Не хватает строк: {['site_id','scope_id','source_id','generation_id','public_key'].filter(k=>!parsed[k as keyof Parsed]).join(', ')}</p>:null}
     <button className="button small" disabled={!ready||busy} onClick={()=>void register()}>Зарегистрировать источник</button></div></li>
    <li><span className="n">3</span><div><b>Собрать на ПК и загрузить результат</b><p className="muted">Сбор занимает 1–3 минуты; результат — подписанный архив. Повтор того же архива не создаёт дубль.</p></div></li>
   </ol></Panel>
   <Panel title="Загрузить результат"><div className="form-grid">
    <label>Носитель (portable-источник)<select aria-label="Portable-источник" value={source} onChange={e=>setSource(e.target.value)}><option value="">выберите…</option>{portables.map(s=><option key={s.source_id} value={s.source_id}>{s.source_id.slice(0,8)}… · {s.state}</option>)}</select></label>
    <label className="dropzone" onDragOver={e=>e.preventDefault()} onDrop={e=>{e.preventDefault();setFile(e.dataTransfer.files?.[0]??null)}}>{file?<b>{file.name}</b>:<span>Перетащите архив аудита (.zip) сюда или <u>выберите файл</u></span>}<input className="visually-hidden" aria-label="Файл пакета" type="file" accept=".zip,application/zip" onChange={e=>setFile(e.target.files?.[0]??null)}/><small>Проверяется подпись носителя; архивы с чужой подписью отклоняются</small></label>
    <div className="form-row"><button className="button primary-sm" disabled={!file||!source||busy} onClick={()=>void upload()}>{busy?'Загружаем…':'Загрузить и импортировать'}</button></div>
    {report?<p className="notice" role="status">Записей: {report.records.length} — {counts.map(([k,n])=>(dispositionName[k]??k)+': '+n).join(', ')}{report.encrypted?' · пакет был зашифрован':''}{report.discovery?' · узлов найдено: '+report.discovery.hosts+', собрано: '+report.discovery.collected+', без доступа: '+report.discovery.no_access+', без профиля учётки: '+report.discovery.no_profile+', недоступно: '+report.discovery.unreachable:''}{report.complete?'.':' · обработка не завершена (осталось '+report.remaining+'): отправьте тот же файл ещё раз — продолжится с места остановки.'}</p>:null}
    <dl className="kv"><dt>Носителей зарегистрировано</dt><dd>{portables.length}</dd><dt>Последняя загрузка</dt><dd>{(()=>{const t=portables.map(s=>s.last_successful_inventory_at??s.last_contact_at).filter((x):x is string=>!!x).sort().pop();return t?new Date(t).toLocaleString('ru-RU'):'—'})()}</dd></dl>
   </div></Panel>
  </div>
  <Panel title={'Носители · '+portables.length} flush>{portables.length?<div className="table-scroll"><table className="panel-table"><thead><tr><th>Носитель</th><th>Состояние</th><th>Регистрация / контакт</th><th>Последний импорт</th><th/></tr></thead><tbody>{portables.map(s=><tr key={s.source_id} className={s.source_id===source?'selected':''}><td className="mono">{s.source_id}</td><td>{s.state}</td><td>{s.last_contact_at?new Date(s.last_contact_at).toLocaleString('ru-RU'):'—'}</td><td>{s.last_successful_inventory_at?new Date(s.last_successful_inventory_at).toLocaleString('ru-RU'):'не было'}</td><td><button className="link" onClick={()=>setSource(s.source_id)}>Найденные узлы</button></td></tr>)}</tbody></table></div>:<p className="muted pad">Носителей ещё нет — зарегистрируйте первый (шаг 2).</p>}</Panel>
  {source?<Panel title="Найденные узлы"><PortableDiscovery key={source} source={source} onExpired={onExpired}/></Panel>:null}
 </div>;
}

const outcomeName:Record<string,string>={collected:'собран',no_access:'доступа нет',no_profile:'нет профиля учётки',unreachable:'недоступен',skipped:'пропущен аудитором'};
const kindName:Record<string,string>={linux_ssh:'Linux (SSH)',windows_winrm:'Windows (WinRM)',network_snmp:'сетевое устройство',unknown:'не определён'};

/** C23.04: найденные узлы portable-аудита — исход по каждому, ссылка на актив для собранных. Активы-пустышки не создаются. */
export function PortableDiscovery({source,onOpenAsset,onExpired}:{source:string;onOpenAsset?:(uid:string)=>void;onExpired:()=>void}){
 const [outcome,setOutcome]=useState(''),[hosts,setHosts]=useState<PortableDiscoveryHost[]|null>(null),[error,setError]=useState('');
 const load=async(o:string)=>{setOutcome(o);setError('');try{setHosts((await api.portableDiscovery(source,o)).hosts)}catch(e){if(e instanceof ApiError&&e.status===401){onExpired();return}setError(errorMessage(e))}};
 return <div className="portable-discovery"><h3>Найденные узлы</h3><p className="panel-note">Узлы, найденные обследованием подсети при portable-аудите. «Доступа нет» и «нет профиля» — добавьте профиль учётки или правило привязки и повторите аудит.</p>
  <div className="filters"><select aria-label="Исход" value={outcome} onChange={e=>void load(e.target.value)}><option value="">все исходы</option>{Object.entries(outcomeName).map(([k,v])=><option key={k} value={k}>{v}</option>)}</select><button className="button small" type="button" onClick={()=>void load(outcome)}>Показать</button></div>
  {error?<p className="error" role="alert">{error}</p>:null}
  {hosts?hosts.length?<div className="table-scroll"><table><thead><tr><th>Адрес</th><th>Тип</th><th>Порты</th><th>Исход</th><th>Причина / профиль</th><th>Актив</th></tr></thead><tbody>{hosts.map(h=><tr key={h.ip}><td className="mono">{h.ip}</td><td>{kindName[h.kind]??h.kind}</td><td>{h.ports.join(', ')||'—'}</td><td>{outcomeName[h.outcome]??h.outcome}</td><td>{[h.reason==='LOCAL_HOST'?'этот ПК — собран локально':h.reason,h.profile].filter(Boolean).join(' · ')||'—'}</td><td>{h.asset_uid?(onOpenAsset?<button className="text-button" type="button" onClick={()=>onOpenAsset(h.asset_uid!)}>Открыть</button>:<span className="mono">{h.asset_uid}</span>):'—'}</td></tr>)}</tbody></table></div>:<p className="muted">Узлов нет (пакеты без обследования подсети их не содержат).</p>:null}
 </div>;
}
