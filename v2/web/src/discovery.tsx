import {useEffect,useRef,useState,type ReactNode} from 'react';
import {api,ApiError,errorMessage,type CollectCredential,type CollectKind,type CollectSecret,type DiscoveryHost,type DiscoveryHostEvent,type DiscoveryNetwork,type DiscoveryNetworkPage,type DiscoveryProbe,type DiscoveryRun,type RemoteTarget,type Source,type WinRMTrust} from './api';

// C51 — «Обследования сети» (ADR D13): вкладки «Подсети», «Учётки сбора», «Цели сбора». Подсети и учётки заводит
// администратор, обследование запускает оператор, результаты видят все. Формы — в боковой панели.
const time=(v:string|null)=>v?new Date(v).toLocaleString('ru-RU',{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'}):'—';
const expired=(e:unknown,onExpired:()=>void)=>{if(e instanceof ApiError&&e.status===401)onExpired()};
const runState:{[k in DiscoveryRun['state']]:[string,string]}={queued:['в очереди','state-pending'],running:['идёт','state-pending'],done:['завершено','state-ok'],failed:['ошибка','state-unavailable']};
const probeName:{[k in DiscoveryProbe]:string}={tcp:'TCP-порты',arp:'ARP',icmp:'пинг'};
const kindName:{[k in CollectKind]:string}={ssh:'SSH · Linux',winrm:'WinRM · Windows',snmp:'SNMPv3 · сетевое устройство'};
const errName=(e:string)=>e==='icmp:not_permitted'?'у сборщика нет права на ICMP (CAP_NET_RAW)':e==='collector:timeout'?'сборщик не сдал результат за 2 ч':e==='job:invalid'?'задание вне правил D-13':e==='host_key_changed'?'ключ хоста сменился — проверьте узел и сбросьте ключ':e==='cert_changed'?'сертификат WinRM сменился — проверьте узел и сбросьте сертификат':e==='internal_error'?'внутренняя ошибка сборщика при сборе цели (повтор через минуту; журнал collector)':e.startsWith('winrm:')?winrmErr(e.slice(6)):e.startsWith('ssh:')?sshErr(e.slice(4)):e;
const sshErr=(c:string)=>c.startsWith('unsupported_platform:windows')?'по SSH отвечает Windows — собирайте этот узел по WinRM (отключите эту цель и нажмите «Собирать…» → WinRM)':c.startsWith('unsupported_platform:')?'по SSH отвечает не Linux ('+c.slice(21)+') — этот способ сбора не подходит':c==='second_factor_required'?'узел требует второй фактор входа: разрешите учётке сбора вход только по ключу (руководство: «Узлы с двухфакторным входом»)':c==='auth_failed'?'вход отклонён: логин, пароль или ключ учётки сбора':c==='host_key_changed'?'ключ хоста сменился — проверьте узел и сбросьте ключ':c==='host_unreachable'?'узел недоступен по сети (выключен, порт 22 закрыт, брандмауэр)':c==='command_failed'?'вход прошёл, но команды сбора не выполнились (оболочка или права учётки) — данные не отправлены':'SSH: '+c;
const winrmErr=(c:string)=>c.startsWith('kerberos_login:')?'вход учётки в домен не удался ('+c.slice(15)+'): пароль, блокировка, часы collector/DC, DNS домена':c.startsWith('kerberos_ticket:')?'нет билета Kerberos для ПК ('+c.slice(16)+'): проверьте полное имя ПК и SPN HTTP/<имя>':c==='kerberos_refused'?'ПК отклонил Kerberos: права учётки (группа «Пользователи удалённого управления»), имя ПК':c==='kerberos_mutual'?'ПК не подтвердил свою подлинность (взаимная проверка Kerberos)':c==='kerberos_unencrypted'?'ПК ответил без шифрования — сбор остановлен':c==='kerberos_etype'?'учётка или ПК без шифрования AES (RC4 не поддерживается)':c==='host_unreachable'?'ПК недоступен по сети: выключен, порт WinRM закрыт или брандмауэр':c==='auth_failed'?'вход отклонён: логин или пароль учётки сбора':c==='access_denied'?'вход прошёл, но не хватает прав: группа «Пользователи удалённого управления», права WMI (скрипт подготовки)':c==='tls_unknown_ca'?'сертификат ПК выдан не тем CA, что указан в цели (самоподписанный или другой CA): загрузите нужный «CA домена» или перевыпустите прослушиватель скриптом подготовки':c==='tls_name_mismatch'?'имя в сертификате ПК не совпадает с «Именем ПК в сертификате» цели: укажите полное имя, как в сертификате':c==='tls_expired'?'сертификат ПК просрочен или ещё не действует (проверьте часы)':c==='tls_failed'?'проверка сертификата ПК не прошла (CA, имя ПК или запомненный сертификат)':c.startsWith('kerberos_http_')?'WinRM ответил HTTP '+c.slice(14)+' на вход Kerberos':'WinRM: '+c;
const schedName=(m:number|null)=>!m?'вручную':m%1440===0?(m===1440?'раз в сутки':m===10080?'раз в неделю':'раз в '+m/1440+' сут.'):m%60===0?(m===60?'раз в час':'раз в '+m/60+' ч'):'раз в '+m+' мин';

type Tab='networks'|'credentials'|'targets';

export function DiscoveryView({csrf,isAdmin,canRun,onExpired,onOpenAsset}:{csrf:string;isAdmin:boolean;canRun:boolean;onExpired:()=>void;onOpenAsset?:(uid:string)=>void}){
 const [tab,setTab]=useState<Tab>('networks'),[version,setVersion]=useState(0);
 const tabs:[Tab,string][]=[['networks','Подсети'],...(isAdmin?[['credentials','Учётки сбора'] as [Tab,string]]:[]),['targets','Цели сбора']];
 return <div className="discovery">
  <div className="seg-tabs" role="tablist" aria-label="Разделы обследований">{tabs.map(([k,n])=><button key={k} role="tab" aria-selected={tab===k} className={tab===k?'active':''} onClick={()=>setTab(k)}>{n}</button>)}</div>
  {tab==='networks'?<NetworksTab csrf={csrf} isAdmin={isAdmin} canRun={canRun} onExpired={onExpired} onOpenAsset={onOpenAsset} onTargetCreated={()=>{setVersion(v=>v+1);setTab('targets')}}/>:null}
  {tab==='credentials'&&isAdmin?<CredentialsTab csrf={csrf} onExpired={onExpired}/>:null}
  {tab==='targets'?<TargetsTab csrf={csrf} isAdmin={isAdmin} canRun={canRun} version={version} onExpired={onExpired}/>:null}
 </div>;
}

function Drawer({title,eyebrow,onClose,children}:{title:string;eyebrow:string;onClose:()=>void;children:ReactNode}){
 const close=useRef<HTMLButtonElement>(null);
 useEffect(()=>{close.current?.focus();const k=(e:KeyboardEvent)=>{if(e.key==='Escape')onClose()};window.addEventListener('keydown',k);return ()=>window.removeEventListener('keydown',k)},[]);
 return <div className="drawer-shade" onClick={onClose}><section className="drawer" role="dialog" aria-modal="true" aria-label={title} onClick={e=>e.stopPropagation()}>
  <header><span className="eyebrow muted">{eyebrow}</span><button className="open-card" ref={close} aria-label="Закрыть" onClick={onClose}>×</button></header>
  <h2>{title}</h2>{children}</section></div>;
}

function Field({label,hint,children}:{label:string;hint?:ReactNode;children:ReactNode}){
 return <label className="field"><span>{label}</span>{children}{hint?<small>{hint}</small>:null}</label>;
}

const eventKind:Record<DiscoveryHostEvent['kind'],[string,string]>={appeared:['появился','state-ok'],returned:['вернулся','state-ok'],missing:['пропал','state-unavailable']};

function NetworksTab({csrf,isAdmin,canRun,onExpired,onTargetCreated,onOpenAsset}:{csrf:string;isAdmin:boolean;canRun:boolean;onExpired:()=>void;onTargetCreated:()=>void;onOpenAsset?:(uid:string)=>void}){
 const [page,setPage]=useState<DiscoveryNetworkPage|null>(null),[open,setOpen]=useState(''),[hosts,setHosts]=useState<DiscoveryHost[]>([]),[runs,setRuns]=useState<DiscoveryRun[]>([]),[events,setEvents]=useState<DiscoveryHostEvent[]>([]);
 const [error,setError]=useState<unknown>(null),[busy,setBusy]=useState(false),[creating,setCreating]=useState(false),[collect,setCollect]=useState<DiscoveryHost|null>(null);
 const load=()=>{api.discoveryNetworks().then(p=>{setPage(p);if(!open&&p.items[0])setOpen(p.items[0].network_id)}).catch(e=>{setError(e);expired(e,onExpired)})};
 const loadOne=(id:string)=>{Promise.all([api.discoveryHosts(id),api.discoveryRuns(id),api.discoveryEvents(id)]).then(([h,r,v])=>{setHosts(h.items);setRuns(r.items);setEvents(v.items)}).catch(e=>{setError(e);expired(e,onExpired)})};
 useEffect(load,[]);
 useEffect(()=>{if(open)loadOne(open)},[open]);
 useEffect(()=>{const active=page?.items.some(n=>n.last_run&&(n.last_run.state==='queued'||n.last_run.state==='running'));if(!active)return;const t=setInterval(()=>{load();if(open)loadOne(open)},5000);return ()=>clearInterval(t)},[page,open]);
 async function act(fn:()=>Promise<unknown>){setBusy(true);setError(null);try{await fn();load();if(open)loadOne(open)}catch(e){setError(e);expired(e,onExpired)}finally{setBusy(false)}}
 if(!page)return error?<div className="error" role="alert">{errorMessage(error)}</div>:<p className="muted">Загрузка…</p>;
 const l=page.limits,net=page.items.find(n=>n.network_id===open);
 return <div className="stack">
  {error?<div className="error" role="alert">{errorMessage(error)}</div>:null}
  <div className="table-panel"><div className="table-toolbar"><h2>Подсети <span>{page.items.length}</span></h2>
   {isAdmin?<button className="button small" onClick={()=>setCreating(true)}>+ Новая подсеть</button>:null}</div>
   {page.items.length===0?<div className="empty"><span>⌖</span><h3>Подсетей пока нет</h3><p>{isAdmin?'Добавьте подсеть: сборщик будет искать в ней узлы по TCP-портам, ARP и пингу.':'Подсети заводит администратор.'}</p></div>:
   <div className="table-scroll"><table><thead><tr><th>Подсеть</th><th>Пробы</th><th>Расписание</th><th>Последнее обследование</th><th>Узлы</th><th/></tr></thead><tbody>{page.items.map(n=>{const r=n.last_run;return <tr key={n.network_id} className={(n.network_id===open?'selected ':'')+(n.active?'':'muted')}>
    <td><button className="asset-link" onClick={()=>setOpen(n.network_id)}><span><strong>{n.name}</strong><small className="mono">{n.cidr}</small></span></button></td>
    <td>{n.probes.map(p=>probeName[p]).join(' · ')}</td><td>{schedName(n.schedule_minutes)}</td>
    <td>{r?<><span className={'badge '+runState[r.state][1]}><i/>{runState[r.state][0]}</span><small>{time(r.finished_at??r.requested_at)}{r.found!==null?' · найдено '+r.found+', новых '+r.new_hosts+', пропало '+r.missing:''}</small>{r.errors.length?<small className="error-text">{r.errors.map(errName).join('; ')}</small>:null}{r.state==='queued'&&Date.now()-new Date(r.requested_at).getTime()>10*60000?<small className="error-text">collector не забирает обследование больше 10 мин — площадка недоступна?{canRun?<> <button className="text-link" disabled={busy} onClick={()=>void act(()=>api.cancelDiscovery(n.network_id,r.run_id,csrf))}>Снять из очереди</button></>:null}</small>:null}</>:<span className="muted">ещё не было</span>}</td>
    <td>{n.present_hosts}{n.missing_hosts?<small>пропало {n.missing_hosts}</small>:null}</td>
    <td className="actions">{canRun&&n.active?<button className="button small" disabled={busy||r?.state==='queued'||r?.state==='running'} onClick={()=>void act(()=>api.startDiscovery(n.network_id,csrf))}>Обследовать</button>:null}
     {isAdmin?<button className="text-link" disabled={busy} onClick={()=>{const v=window.prompt('Обследовать по расписанию каждые N минут (не чаще '+page.limits.min_schedule_minutes+'); 0 — только вручную:',String(n.schedule_minutes??0));if(v===null)return;const m=Number(v.trim());if(!Number.isInteger(m)||m<0||(m>0&&m<page.limits.min_schedule_minutes)){window.alert('Нужно 0 или целое не меньше '+page.limits.min_schedule_minutes);return}void act(()=>api.patchDiscoveryNetwork(n.network_id,csrf,{revision:n.revision,schedule_minutes:m}))}}>Расписание…</button>:null}{isAdmin?<button className="text-link" disabled={busy} onClick={()=>void act(()=>api.patchDiscoveryNetwork(n.network_id,csrf,{revision:n.revision,active:!n.active}))}>{n.active?'Отключить':'Включить'}</button>:null}</td>
   </tr>})}</tbody></table></div>}
   <p className="panel-note">Правила: подсеть IPv4 не шире /{l.max_prefix} ({2**(32-l.max_prefix)} адресов), не более {l.rate_per_second} проб в секунду, расписание не чаще раза в {l.min_schedule_minutes} мин. TCP-порты: {l.tcp_ports.join(', ')}. Вне заведённых подсетей ничего не сканируется. Узел считается пропавшим только после {l.miss_after} полных обследований подряд без него; обследование с ошибками пропуском не считается.</p>
  </div>
  {net?<div className="table-panel"><div className="table-toolbar"><h2>Узлы {net.name} <span>{hosts.length}</span></h2><small className="mono muted">{net.cidr}</small></div>
   {hosts.length===0?<div className="empty"><span>◌</span><h3>Узлов пока нет</h3><p>Запустите обследование подсети.</p></div>:<div className="table-scroll"><table><thead><tr><th>Адрес</th><th>MAC</th><th>Открытые порты</th><th>Пинг</th><th>Впервые</th><th>Последний раз</th><th>Состояние</th><th>В реестре</th>{isAdmin?<th/>:null}</tr></thead><tbody>
    {hosts.map(h=><tr key={h.ip}><td className="mono">{h.ip}</td><td className="mono">{h.mac??'—'}</td><td>{h.ports.length?h.ports.join(', '):'—'}</td><td>{h.icmp?'да':'—'}</td><td className="time">{time(h.first_seen)}</td><td className="time">{time(h.last_seen)}</td>
     <td><span className={'badge '+(h.state==='present'?(h.misses?'state-partial':'state-ok'):'state-unavailable')}><i/>{h.state==='present'?(h.misses?'не найден '+h.misses+' из '+l.miss_after:'на месте'):'пропал'}</span>{h.state==='missing'&&h.missing_since?<small>с {time(h.missing_since)}</small>:null}</td><td>{h.asset_uid?(onOpenAsset?<button className="text-link" onClick={()=>onOpenAsset(h.asset_uid!)}>карточка ↗</button>:'да'):<span className="muted" title="Данных с узла нет: присутствие видно только здесь">нет</span>}</td>
     {isAdmin?<td className="actions"><button className="button small" onClick={()=>setCollect(h)}>Собирать…</button></td>:null}</tr>)}
   </tbody></table></div>}
   {events.length?<div className="history"><h3>Изменения присутствия</h3><ul>{events.slice(0,30).map(v=><li key={v.ip+v.run_id+v.kind}><span className={'badge '+eventKind[v.kind][1]}><i/>{eventKind[v.kind][0]}</span> <span className="mono">{v.ip}</span> · {time(v.at)}</li>)}</ul></div>:null}
   {runs.length?<div className="history"><h3>История обследований</h3><ul>{runs.map(r=><li key={r.run_id}><span className={'badge '+runState[r.state][1]}><i/>{runState[r.state][0]}</span> {time(r.requested_at)} · {r.trigger==='manual'?'вручную':'по расписанию'}{r.found!==null?' · найдено '+r.found+' из '+r.addresses+' адресов':''}{r.errors.length?' · '+r.errors.map(errName).join('; '):''}</li>)}</ul></div>:null}
  </div>:null}
  {creating?<Drawer eyebrow="Обследования сети" title="Новая подсеть" onClose={()=>setCreating(false)}><NetworkForm busy={busy} onExpired={onExpired} onCreate={b=>void act(async()=>{const n=await api.createDiscoveryNetwork(csrf,b);setCreating(false);setOpen(n.network_id)})}/>{error?<div className="error" role="alert">{errorMessage(error)}</div>:null}</Drawer>:null}
  {collect&&net?<Drawer eyebrow="Сбор данных с узла" title={'Собирать '+collect.ip} onClose={()=>setCollect(null)}><CollectForm host={collect} network={net} busy={busy} onExpired={onExpired} onCreate={b=>void act(async()=>{await api.createRemoteTarget(csrf,b);setCollect(null);onTargetCreated()})}/>{error?<div className="error" role="alert">{errorMessage(error)}</div>:null}</Drawer>:null}
 </div>;
}

function NetworkForm({busy,onCreate,onExpired}:{busy:boolean;onExpired:()=>void;onCreate:(b:Parameters<typeof api.createDiscoveryNetwork>[1])=>void}){
 const [collectors,setCollectors]=useState<Source[]>([]),[collector,setCollector]=useState(''),[name,setName]=useState(''),[cidr,setCidr]=useState('');
 const [probes,setProbes]=useState<DiscoveryProbe[]>(['tcp','arp','icmp']),[schedule,setSchedule]=useState('');
 useEffect(()=>{api.sources().then(p=>{const c=p.items.filter(s=>s.source_kind==='collector'&&s.state==='active');setCollectors(c);if(c[0])setCollector(c[0].source_id)}).catch(e=>expired(e,onExpired))},[]);
 const chosen=collectors.find(c=>c.source_id===collector);
 const toggle=(p:DiscoveryProbe)=>setProbes(probes.includes(p)?probes.filter(x=>x!==p):[...probes,p]);
 return <form className="form-stack" onSubmit={e=>{e.preventDefault();if(chosen)onCreate({site_id:chosen.site_id,collector_id:chosen.source_id,name:name.trim(),cidr:cidr.trim(),probes,schedule_minutes:schedule?Number(schedule):null})}}>
  <Field label="Название"><input value={name} onChange={e=>setName(e.target.value)} placeholder="Офис, 2 этаж" required maxLength={128}/></Field>
  <Field label="Подсеть (CIDR)" hint="IPv4, не шире /22 — например 10.170.108.0/24"><input className="mono" value={cidr} onChange={e=>setCidr(e.target.value)} placeholder="10.170.108.0/24" required/></Field>
  <Field label="Сборщик (collector)" hint="Обследование выполняет этот сборщик; подсеть должна быть ему доступна">
   <select value={collector} onChange={e=>setCollector(e.target.value)} required>{collectors.length===0?<option value="">нет активных сборщиков</option>:null}{collectors.map(c=><option key={c.source_id} value={c.source_id}>Сборщик {c.source_id.slice(0,8)} · площадка {c.site_id.slice(0,8)}</option>)}</select></Field>
  <fieldset className="field"><span>Пробы</span><div className="checks">{(['tcp','arp','icmp'] as DiscoveryProbe[]).map(p=><label key={p}><input type="checkbox" checked={probes.includes(p)} onChange={()=>toggle(p)}/> {probeName[p]}</label>)}</div></fieldset>
  <Field label="Расписание"><select value={schedule} onChange={e=>setSchedule(e.target.value)}><option value="">только вручную</option><option value="60">раз в час</option><option value="360">раз в 6 часов</option><option value="1440">раз в сутки</option><option value="10080">раз в неделю</option></select></Field>
  <button className="button primary" disabled={busy||!chosen||probes.length===0}>Добавить подсеть <span>→</span></button>
 </form>;
}

function CredentialsTab({csrf,onExpired}:{csrf:string;onExpired:()=>void}){
 const [items,setItems]=useState<CollectCredential[]>([]),[note,setNote]=useState<string|null>(null),[available,setAvailable]=useState(true),[error,setError]=useState<unknown>(null),[busy,setBusy]=useState(false),[creating,setCreating]=useState(false);
 const load=()=>{api.collectCredentials().then(p=>{setItems(p.items);setAvailable(p.secrets_available)}).catch(e=>{setError(e);expired(e,onExpired)})};
 useEffect(load,[]);
 return <div className="stack">
  {!available?<div className="error" role="alert">Хранилище секретов центра не настроено — учётки сохранить нельзя.</div>:null}
  {error&&!creating?<div className="error" role="alert">{errorMessage(error)}</div>:null}
  {note?<div className="map-notice ok" role="status">{note}</div>:null}
  <div className="table-panel"><div className="table-toolbar"><h2>Учётки сбора <span>{items.length}</span></h2><button className="button small" disabled={!available} onClick={()=>setCreating(true)}>+ Новая учётка</button></div>
   {items.length===0?<div className="empty"><span>⚿</span><h3>Учёток пока нет</h3><p>Учётка нужна, чтобы собирать данные с найденных узлов по SSH, WinRM или SNMPv3. Пароли и ключи хранятся в хранилище секретов центра и больше нигде не показываются.</p></div>:
   <div className="table-scroll"><table><thead><tr><th>Название</th><th>Способ</th><th>Логин</th><th>Целей</th><th>Секрет сменён</th><th/></tr></thead><tbody>{items.map(c=><tr key={c.credential_id} className={c.active?'':'muted'}><td><strong>{c.name}</strong>{c.public_key?<small className="pubkey"><span className="mono" title={c.public_key}>{c.public_key.slice(0,32)}…</span> <button className="text-link" onClick={()=>{const k=c.public_key!;if(navigator.clipboard&&window.isSecureContext)void navigator.clipboard.writeText(k).then(()=>setNote('Открытый ключ «'+c.name+'» скопирован: добавьте его в authorized_keys на узлах'),()=>window.prompt('Открытый ключ для authorized_keys:',k));else window.prompt('Открытый ключ для authorized_keys (скопируйте):',k)}}>копировать открытый ключ</button></small>:null}</td><td>{kindName[c.kind]}</td><td className="mono">{c.username}</td><td>{c.targets}</td><td className="time">{time(c.secret_changed_at)}</td><td className="actions"><span className={'badge '+(c.active?'state-ok':'state-unavailable')}><i/>{c.active?'включена':'отключена'}</span> <button className="text-link" disabled={busy} onClick={()=>{
     // стенд №13: переключатель без подтверждения незаметно возвращался двойным щелчком — подтверждение в обе стороны,
     // кнопка заблокирована до ответа центра и ещё на секунду после него
     const q=c.active?'Отключить учётку «'+c.name+'»?'+(c.targets?' Её цели ('+c.targets+') перестанут собираться, пока учётка выключена.':''):'Включить учётку «'+c.name+'»?'+(c.targets?' Её цели ('+c.targets+') снова начнут собираться.':'');
     if(!confirm(q))return;setBusy(true);setNote(null);api.patchCollectCredential(c.credential_id,csrf,{revision:c.revision,active:!c.active}).then(()=>{setNote('Учётка «'+c.name+'» '+(c.active?'отключена':'включена'));load()}).catch(e=>{setError(e);expired(e,onExpired)}).finally(()=>setTimeout(()=>setBusy(false),1000))}}>{c.active?'Отключить':'Включить'}</button></td></tr>)}</tbody></table></div>}
   <p className="panel-note">Сборщик получает учётку у центра по защищённому каналу перед каждым сбором и держит её только в памяти.</p>
  </div>
  <DomainCAPanel csrf={csrf} onExpired={onExpired}/>
  {creating?<Drawer eyebrow="Учётки сбора" title="Новая учётка" onClose={()=>setCreating(false)}><CredentialForm busy={busy} onSave={b=>{setBusy(true);setError(null);api.createCollectCredential(csrf,b).then(()=>{setCreating(false);load()}).catch(e=>{setError(e);expired(e,onExpired)}).finally(()=>setBusy(false))}}/>{error?<div className="error" role="alert">{errorMessage(error)}</div>:null}</Drawer>:null}
 </div>;
}

// C51.03 шаг 2: корневой сертификат CA домена (AD CS) — один раз для всех WinRM-целей с проверкой «CA домена»
function DomainCAPanel({csrf,onExpired}:{csrf:string;onExpired:()=>void}){
 const [trust,setTrust]=useState<WinRMTrust|null>(null),[editing,setEditing]=useState(false),[pem,setPem]=useState(''),[busy,setBusy]=useState(false),[error,setError]=useState<unknown>(null);
 const load=()=>{api.winrmTrust().then(setTrust).catch(e=>{setError(e);expired(e,onExpired)})};
 useEffect(load,[]);
 const save=(value:string|null)=>{if(!trust)return;setBusy(true);setError(null);api.setWinrmTrust(csrf,trust.revision,value).then(t=>{setTrust(t);setEditing(false);setPem('')}).catch(e=>{setError(e);expired(e,onExpired)}).finally(()=>setBusy(false))};
 return <div className="table-panel"><div className="table-toolbar"><h2>CA домена для WinRM <span>{trust?.configured?'задан':'не задан'}</span></h2>{trust?<button className="button small" onClick={()=>setEditing(true)}>{trust.configured?'Заменить':'+ Загрузить сертификат CA'}</button>:null}</div>
  {error?<div className="error" role="alert">{errorMessage(error)}</div>:null}
  {trust?.configured?<div className="table-scroll"><table><thead><tr><th>Сертификат</th><th>Действует до</th><th>SHA-256</th></tr></thead><tbody>{trust.certificates.map(c=><tr key={c.sha256}><td><strong>{c.subject}</strong>{c.issuer!==c.subject?<small>выдан: {c.issuer}</small>:<small>корневой</small>}</td><td className="time">{time(c.not_after)}</td><td className="mono" title={c.sha256}>{c.sha256.slice(0,16)}…</td></tr>)}</tbody></table></div>:null}
  <p className="panel-note">Корневой сертификат AD CS (открытый, без ключа) загружается один раз: WinRM-цели с проверкой «CA домена» проверяют сертификат ПК по нему и по имени ПК — PEM каждого ПК не нужен. Выгрузить на контроллере домена: <span className="mono">certutil -ca.cert C:\awm-root-ca.cer</span>, затем <span className="mono">certutil -encode C:\awm-root-ca.cer C:\awm-root-ca.pem</span>.{trust?.targets?` Используют целей: ${trust.targets}.`:''}</p>
  {trust?.configured&&!trust.targets?<p className="panel-note"><button className="text-link" disabled={busy} onClick={()=>{if(confirm('Удалить сертификат CA домена?'))save(null)}}>Удалить сертификат CA</button></p>:null}
  {editing?<Drawer eyebrow="Учётки сбора" title="Сертификат CA домена" onClose={()=>setEditing(false)}><form className="form-stack" onSubmit={e=>{e.preventDefault();save(pem)}}>
   <Field label="Сертификат CA (PEM)" hint="Корневой и при необходимости промежуточные сертификаты, до 10. Только сертификаты CA."><textarea className="mono" rows={10} value={pem} onChange={e=>setPem(e.target.value)} required placeholder="-----BEGIN CERTIFICATE-----"/></Field>
   <button className="button primary" disabled={busy||!pem.trim()}>Сохранить <span>→</span></button></form></Drawer>:null}
 </div>;
}

function CredentialForm({busy,onSave}:{busy:boolean;onSave:(b:{name:string;kind:CollectKind;username:string;secret:CollectSecret})=>void}){
 const [name,setName]=useState(''),[kind,setKind]=useState<CollectKind>('ssh'),[username,setUsername]=useState(''),[mode,setMode]=useState<'password'|'key'|'generate'>('generate'),[password,setPassword]=useState(''),[key,setKey]=useState('');
 const [authProto,setAuthProto]=useState('SHA256'),[authKey,setAuthKey]=useState(''),[privProto,setPrivProto]=useState('AES'),[privKey,setPrivKey]=useState('');
 const secret=():CollectSecret=>kind==='snmp'?{auth_protocol:authProto,auth_key:authKey,priv_protocol:privProto,priv_key:privKey}:kind==='ssh'&&mode==='key'?{private_key:key}:kind==='ssh'&&mode==='generate'?{generate:true}:{password};
 return <form className="form-stack" autoComplete="off" onSubmit={e=>{e.preventDefault();onSave({name:name.trim(),kind,username:username.trim(),secret:secret()})}}>
  <Field label="Название" hint="Как учётка будет называться в списке"><input value={name} onChange={e=>setName(e.target.value)} placeholder="Linux только чтение" required maxLength={128}/></Field>
  <Field label="Способ"><select value={kind} onChange={e=>setKind(e.target.value as CollectKind)}>{(['ssh','winrm','snmp'] as CollectKind[]).map(k=><option key={k} value={k}>{kindName[k]}</option>)}</select></Field>
  <Field label={kind==='snmp'?'Пользователь SNMPv3':'Логин'} hint={kind==='winrm'?'Доменная учётка: AWM\\scanwinrm':undefined}><input value={username} onChange={e=>setUsername(e.target.value)} placeholder={kind==='winrm'?'AWM\\scanwinrm':kind==='snmp'?'surveyscan':'scanprobe'} required/></Field>
  {kind==='snmp'?<>
   <Field label="Аутентификация"><select value={authProto} onChange={e=>setAuthProto(e.target.value)}><option>SHA</option><option>SHA256</option><option>SHA512</option></select></Field>
   <Field label="Ключ аутентификации" hint="Не короче 8 символов"><input type="password" value={authKey} onChange={e=>setAuthKey(e.target.value)} required minLength={8} autoComplete="new-password"/></Field>
   <Field label="Шифрование"><select value={privProto} onChange={e=>setPrivProto(e.target.value)}><option>AES</option><option>AES256</option></select></Field>
   <Field label="Ключ шифрования" hint="Не короче 8 символов"><input type="password" value={privKey} onChange={e=>setPrivKey(e.target.value)} required minLength={8} autoComplete="new-password"/></Field>
  </>:<>
   {kind==='ssh'?<fieldset className="field"><span>Вход</span><div className="checks"><label><input type="radio" checked={mode==='generate'} onChange={()=>setMode('generate')}/> ключ, созданный центром (рекомендуется)</label><label><input type="radio" checked={mode==='password'} onChange={()=>setMode('password')}/> по паролю</label><label><input type="radio" checked={mode==='key'} onChange={()=>setMode('key')}/> по закрытому ключу</label></div></fieldset>:null}
   {kind==='ssh'&&mode==='key'?<Field label="Закрытый ключ" hint="Выберите файл ключа или вставьте его содержимое целиком; ключ уходит только в хранилище секретов центра"><input type="file" aria-label="Файл закрытого ключа" onChange={e=>{const f=e.target.files?.[0];if(f&&f.size<=16384)void f.text().then(setKey);e.target.value=''}}/><textarea className="mono" value={key} onChange={e=>setKey(e.target.value)} rows={6} required placeholder={'-----BEGIN OPENSSH PRIVATE KEY-----\n…\n-----END OPENSSH PRIVATE KEY-----'}/></Field>:
    kind==='ssh'&&mode==='generate'?<p className="panel-note">Центр создаст пару ключей ed25519: закрытый ключ сразу уйдёт в хранилище секретов и никуда не выдаётся, открытый появится в списке учёток — добавьте его в <span className="mono">~/.ssh/authorized_keys</span> учётки сбора на узлах.</p>:
    <Field label="Пароль"><input type="password" value={password} onChange={e=>setPassword(e.target.value)} required autoComplete="new-password"/></Field>}
  </>}
  <p className="panel-note">После сохранения пароль и ключ не показываются: сменить их можно, только введя заново.</p>
  <button className="button primary" disabled={busy}>Сохранить учётку <span>→</span></button>
 </form>;
}

function CollectForm({host,network,busy,onCreate,onExpired}:{host:DiscoveryHost;network:DiscoveryNetwork;busy:boolean;onExpired:()=>void;onCreate:(b:Parameters<typeof api.createRemoteTarget>[1])=>void}){
 const guess:CollectKind=host.ports.includes(5986)||host.ports.includes(5985)?'winrm':host.ports.includes(22)?'ssh':host.ports.includes(3389)?'winrm':'ssh'; // открыт WinRM — скорее всего Windows (OpenSSH на Windows по SSH не собирается)
 const [creds,setCreds]=useState<CollectCredential[]>([]),[kind,setKind]=useState<CollectKind>(guess),[cred,setCred]=useState('');
 const [hostKey,setHostKey]=useState(''),[ca,setCa]=useState(''),[trustMode,setTrustMode]=useState<'first_use'|'domain_ca'|'pem'>('first_use'),[transport,setTransport]=useState<'https'|'http_kerberos'>(host.ports.includes(5985)&&!host.ports.includes(5986)?'http_kerberos':'https'),[domainCA,setDomainCA]=useState(false),[serverName,setServerName]=useState(''),[interval,setInterval_]=useState('3600');
 useEffect(()=>{api.collectCredentials().then(p=>setCreds(p.items.filter(c=>c.active))).catch(e=>expired(e,onExpired));api.winrmTrust().then(t=>{setDomainCA(t.configured);if(t.configured)setTrustMode('domain_ca')}).catch(()=>setDomainCA(false))},[]);
 const usable=creds.filter(c=>c.kind===kind);
 useEffect(()=>{setCred(usable[0]?.credential_id??'')},[kind,creds.length]);
 return <form className="form-stack" onSubmit={e=>{e.preventDefault();onCreate({collector_id:network.collector_id,network_id:network.network_id,address:host.ip,kind,credential_id:cred,interval_seconds:Number(interval),...(kind==='ssh'?(hostKey.trim()?{host_key_sha256:hostKey.trim()}:{}):kind==='winrm'?(transport==='http_kerberos'?{winrm_transport:transport,tls_server_name:serverName.trim()}:{...(trustMode==='pem'?{tls_ca_pem:ca}:{tls_trust:trustMode}),...(serverName.trim()?{tls_server_name:serverName.trim()}:{})}):{})})}}>
  <p className="muted">Открытые порты: {host.ports.length?host.ports.join(', '):'нет данных'}.</p>
  <Field label="Способ"><select value={kind} onChange={e=>setKind(e.target.value as CollectKind)}>{(['ssh','winrm','snmp'] as CollectKind[]).map(k=><option key={k} value={k}>{kindName[k]}</option>)}</select></Field>
  <Field label="Учётка" hint={usable.length===0?'Нет учёток этого способа — добавьте на вкладке «Учётки сбора».':undefined}><select value={cred} onChange={e=>setCred(e.target.value)} required>{usable.length===0?<option value="">—</option>:null}{usable.map(c=><option key={c.credential_id} value={c.credential_id}>{c.name} ({c.username})</option>)}</select></Field>
  {kind==='ssh'?<Field label="Отпечаток ключа хоста (необязательно)" hint="Если пусто — ключ запомнится при первом подключении (тот, что предложит узел, часто ECDSA). Сверка на узле: for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf $f; done. Если ключ потом сменится, сбор остановится до проверки.">
   <input className="mono" value={hostKey} onChange={e=>setHostKey(e.target.value)} placeholder="SHA256:…" pattern="SHA256:[A-Za-z0-9+/]{43}"/></Field>:null}
  {kind==='winrm'?<>
   <p className="panel-note">Подготовка ПК (один раз, «от администратора»): <a href="downloads/prepare-winrm-target.ps1" download>скачать скрипт</a>, затем <span className="mono">powershell -ExecutionPolicy Bypass -File prepare-winrm-target.ps1 -Account &lt;учётка сбора&gt; -Collector &lt;адрес collector&gt;{transport==='http_kerberos'?' -Kerberos':''}</span>. Для многих ПК — групповая политика (руководство, раздел 11).</p>
   <Field label="Подключение" hint={transport==='http_kerberos'?'Kerberos по полному имени ПК и доменной учётке; сообщения шифруются Kerberos. NTLM не используется: без Kerberos сбор не начнётся.':'HTTPS с проверкой сертификата ПК.'}>
    <select value={transport} onChange={e=>setTransport(e.target.value as typeof transport)}><option value="http_kerberos">HTTP 5985 + Kerberos (по имени ПК)</option><option value="https">HTTPS 5986</option></select></Field>
   {transport==='http_kerberos'?<Field label="Полное имя ПК" hint="Как в домене, например win-ar.awm.local: по нему запрашивается билет Kerberos (HTTP/<имя>)."><input value={serverName} onChange={e=>setServerName(e.target.value)} placeholder="например, pc01.domain.local" required pattern="[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+"/></Field>:<>
   <Field label="Проверка сертификата ПК" hint={trustMode==='first_use'?'Сертификат запомнится при первом подключении; если он потом сменится, сбор остановится до проверки.':trustMode==='domain_ca'?'Сертификат ПК проверяется по CA домена (вкладка «Учётки сбора») и по имени ПК.':'Сертификат проверяется по этому PEM (C:\\surveyscan-winrm-<ИМЯ>.pem) и по имени ПК.'}>
    <select value={trustMode} onChange={e=>setTrustMode(e.target.value as typeof trustMode)}><option value="domain_ca" disabled={!domainCA}>CA домена{domainCA?'':' (не задан)'}</option><option value="first_use">Запомнить при первом подключении</option><option value="pem">PEM этого ПК</option></select></Field>
   {trustMode==='pem'?<Field label="Сертификат WinRM (PEM)"><textarea className="mono" value={ca} onChange={e=>setCa(e.target.value)} rows={4} required placeholder="-----BEGIN CERTIFICATE-----"/></Field>:null}
   <Field label={trustMode==='first_use'?'Имя ПК (необязательно)':'Имя ПК в сертификате'} hint={trustMode==='first_use'?undefined:'Полное имя, как в сертификате: оно проверяется.'}><input value={serverName} onChange={e=>setServerName(e.target.value)} placeholder="например, pc01.domain.local" required={trustMode!=='first_use'}/></Field></>}</>:null}
  {kind==='snmp'?<p className="panel-note">SNMPv3 authPriv: подлинность и шифрование обеспечивают ключи учётки. Передаются имя устройства, интерфейсы с адресами и таблица ARP.</p>:null}
  <Field label="Как часто собирать"><select value={interval} onChange={e=>setInterval_(e.target.value)}><option value="3600">раз в час</option><option value="21600">раз в 6 часов</option><option value="86400">раз в сутки</option></select></Field>
  <button className="button primary" disabled={busy||!cred}>Создать цель сбора <span>→</span></button>
 </form>;
}

function TargetsTab({csrf,isAdmin,canRun,version,onExpired}:{csrf:string;isAdmin:boolean;canRun:boolean;version:number;onExpired:()=>void}){
 const [items,setItems]=useState<RemoteTarget[]>([]),[error,setError]=useState<unknown>(null),[loaded,setLoaded]=useState(false);
 const load=()=>{api.remoteTargets().then(p=>{setItems(p.items);setLoaded(true)}).catch(e=>{setError(e);expired(e,onExpired)})};
 useEffect(load,[version]);
 useEffect(()=>{if(!items.some(t=>t.state==='pending'||(t.state==='active'&&!t.last_collected_at)||(t.collect_requested_at&&(!t.last_collected_at||t.collect_requested_at>t.last_collected_at))))return;const t=setInterval(load,5000);return ()=>clearInterval(t)},[items]);
 const act=(t:RemoteTarget,body:{disabled:boolean;reset_host_key?:boolean;reset_tls_cert?:boolean})=>void api.patchRemoteTarget(t.target_id,csrf,{revision:t.revision,...body}).then(load).catch(e=>{setError(e);expired(e,onExpired)});
 const state=(t:RemoteTarget):[string,string]=>t.state==='disabled'?['отключена','']:t.last_error?['ошибка','state-unavailable']:t.state==='pending'?['регистрируется','state-pending']:t.last_collected_at?['работает','state-ok']:['ждёт первого сбора','state-pending'];
 return <div className="stack">{error?<div className="error" role="alert">{errorMessage(error)}</div>:null}
  <div className="table-panel"><div className="table-toolbar"><h2>Цели сбора <span>{items.length}</span></h2></div>
   {loaded&&items.length===0?<div className="empty"><span>◎</span><h3>Целей пока нет</h3><p>Откройте подсеть на вкладке «Подсети» и нажмите «Собирать…» у найденного узла.</p></div>:
   <div className="table-scroll"><table><thead><tr><th>Узел</th><th>Способ</th><th>Состояние</th><th>Последний сбор</th><th>Ключ / сертификат</th>{isAdmin||canRun?<th/>:null}</tr></thead><tbody>{items.map(t=>{const [label,cls]=state(t);return <tr key={t.target_id} className={t.state==='disabled'?'muted':''}>
    <td className="mono">{t.address}:{t.port}</td><td>{kindName[t.kind]}</td>
    <td><span className={'badge '+cls}><i/>{label}</span>{t.last_error?<small className="error-text">{errName(t.last_error)}</small>:null}</td>
    <td className="time">{time(t.last_collected_at)}{t.state!=='disabled'&&t.last_collected_at?<small>следующий ≈ {new Date(new Date(t.last_collected_at).getTime()+t.interval_seconds*1000).toLocaleTimeString('ru-RU',{hour:'2-digit',minute:'2-digit'})}</small>:null}</td>
    <td>{t.kind==='winrm'?(t.winrm_transport==='http_kerberos'?<small>Kerberos · {t.tls_server_name}</small>:t.tls_cert_origin==='admin'?<small>сертификат задан администратором{t.tls_server_name?' · '+t.tls_server_name:''}</small>:t.tls_cert_origin==='domain_ca'?<small>по CA домена · {t.tls_server_name}</small>:t.tls_cert_sha256?<><span className="mono" title={'SHA-256 '+t.tls_cert_sha256}>{t.tls_cert_sha256.slice(0,16)}…</span><small>сертификат запомнен при первом подключении</small></>:<small>сертификат запомнится при первом подключении</small>):t.kind!=='ssh'?'—':t.host_key_sha256?<><span className="mono" title={t.host_key_sha256}>{t.host_key_sha256.slice(0,18)}…</span><small>{t.host_key_origin==='first_use'?'запомнен при первом подключении':'введён вручную'}</small></>:<small>запомнится при первом подключении</small>}</td>
    {isAdmin||canRun?<td className="actions">{canRun&&t.state!=='disabled'?(t.collect_requested_at&&(!t.last_collected_at||t.collect_requested_at>t.last_collected_at)?<small>сбор запрошен…</small>:<button className="text-link" onClick={()=>void api.collectTargetNow(t.target_id,csrf).then(load).catch(e=>{setError(e);expired(e,onExpired)})}>Собрать сейчас</button>):null}
     {isAdmin&&t.kind==='ssh'&&t.host_key_sha256?<button className="text-link" onClick={()=>{if(confirm('Сбросить запомненный ключ хоста '+t.address+'? Делайте это, только если ключ сменился законно (например, после переустановки ОС).'))act(t,{disabled:t.state==='disabled',reset_host_key:true})}}>Сбросить ключ</button>:null}
     {isAdmin&&t.kind==='winrm'&&t.tls_cert_origin==='first_use'?<button className="text-link" onClick={()=>{if(confirm('Сбросить запомненный сертификат WinRM '+t.address+'? Делайте это, только если сертификат сменился законно (перевыпуск, переустановка ОС).'))act(t,{disabled:t.state==='disabled',reset_tls_cert:true})}}>Сбросить сертификат</button>:null}
     {isAdmin?<button className="text-link" onClick={()=>act(t,{disabled:t.state!=='disabled'})}>{t.state==='disabled'?'Включить':'Отключить'}</button>:null}</td>:null}
   </tr>})}</tbody></table></div>}
  </div>
 </div>;
}
