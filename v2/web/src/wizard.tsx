import {useState} from 'react';

const DRAFT='takt.system-wizard.draft';
type Draft={step:number;name:string;dir:string;crit:string;envs:string[];comps:unknown[];deps:string[];owner:string;it:string;onCall:string;backup:string;window_:string};
function loadDraft():Partial<Draft>{try{return JSON.parse(localStorage.getItem(DRAFT)??'{}') as Partial<Draft>}catch{return {}}}
import {api,ApiError,errorMessage,type RSMEnvKind,type RSMOverview,type Subject} from './api';
import {Panel,Pill,Split,useLoad} from './ui';

// C53.07 (макет «Новая система — мастер»): описание → среды → компоненты и правила → зависимости → ответственные →
// проверка. Создаёт систему теми же вызовами API, что и ручное заведение; справа — что получится. После создания можно
// сразу применить правила ко всем хостам и увидеть, сколько привязано и предложено.
const envKinds:[RSMEnvKind,string][]=[['prod','Продуктив'],['test','Тест'],['dev','Разработка'],['stage','Препрод'],['dr','Резервная площадка (DR)']];
const critNames:[string,string][]=[['high','высокая'],['medium','средняя'],['low','низкая'],['critical','критичная']];
const ruleKinds:[string,string][]=[['','вручную'],['hostname_glob','маска имени'],['subnet','подсеть'],['software','установлено ПО'],['asset_class','класс актива']];
type Comp={name:string;env:RSMEnvKind;role:string;critical:boolean;ruleKind:string;rule:string;mode:'propose'|'auto'};
const steps=['Описание','Среды','Компоненты и правила','Зависимости','Ответственные','Проверка'];

export function SystemWizard({csrf,onDone,onCancel,onExpired}:{csrf:string;onDone:(uid:string)=>void;onCancel:()=>void;onExpired:()=>void}){
 const [draft]=useState(loadDraft);
 const [step,setStep]=useState(draft.step??0),[name,setName]=useState(draft.name??''),[dir,setDir]=useState(draft.dir??''),[crit,setCrit]=useState(draft.crit??'high'),[envs,setEnvs]=useState<RSMEnvKind[]>((draft.envs as RSMEnvKind[]|undefined)??['prod','test']);
 const [comps,setComps]=useState<Comp[]>((draft.comps as Comp[]|undefined)??[{name:'',env:'prod',role:'',critical:true,ruleKind:'',rule:'',mode:'propose'}]);
 const [deps,setDeps]=useState<string[]>(draft.deps??[]),[owner,setOwner]=useState(draft.owner??''),[it,setIt]=useState(draft.it??''),[onCall,setOnCall]=useState(draft.onCall??''),[backup,setBackup]=useState(draft.backup??''),[window_,setWindow]=useState(draft.window_??''),[saved,setSaved]=useState(!!draft.name);
 function saveDraft(){try{localStorage.setItem(DRAFT,JSON.stringify({step,name,dir,crit,envs,comps,deps,owner,it,onCall,backup,window_}));setSaved(true)}catch{/* хранилище недоступно */}}
 function dropDraft(){try{localStorage.removeItem(DRAFT)}catch{/* нет */}}
 const [busy,setBusy]=useState(false),[error,setError]=useState<unknown>(null),[log,setLog]=useState<string[]>([]),[created,setCreated]=useState<string|null>(null),[applied,setApplied]=useState<string>('');
 const [ov]=useLoad<RSMOverview>(()=>api.rsmOverview(),[],onExpired);
 const [systems]=useLoad(()=>api.rsmSystems({limit:500}),[],onExpired);
 const [subjects]=useLoad(()=>api.subjects(),[],onExpired);
 const people:Subject[]=(subjects?.items??[]).filter(s=>s.active);
 const set=(i:number,p:Partial<Comp>)=>setComps(c=>c.map((x,j)=>j===i?{...x,...p}:x));
 const valid=[name.trim().length>0,envs.length>0,comps.every(c=>c.name.trim()&&envs.includes(c.env)&&(!c.ruleKind||c.rule.trim())),true,true,true];
 const envName=(k:RSMEnvKind)=>envKinds.find(e=>e[0]===k)?.[1]??k;
 async function create(){
  setBusy(true);setError(null);const out:string[]=[];
  try{
   const sv=await api.createService(csrf,{name:name.trim(),criticality:crit});out.push('Система «'+sv.name+'» создана');
   const sys=await api.rsmSystem(sv.service_uid);
   if(dir||owner.trim()||it||onCall.trim()||backup||window_.trim()){await api.rsmPatchSystem(sv.service_uid,csrf,{revision:sys.system.revision,...(dir?{direction_uid:dir}:{}),...(owner.trim()?{business_owner:owner.trim()}:{}),...(it?{it_subject_id:it}:{}),...(onCall.trim()?{on_call:onCall.trim()}:{}),...(backup?{backup_subject_id:backup}:{}),...(window_.trim()?{maintenance_window:window_.trim()}:{})});out.push('Ответственные и направление заданы')}
   const envIds:Record<string,string>={};
   for(const k of envs){const e=await api.rsmCreateEnvironment(sv.service_uid,csrf,{kind:k,name:envName(k)});envIds[k]=e.environment_id}
   out.push('Сред: '+envs.length);
   for(const c of comps){const x=await api.rsmCreateComponent(envIds[c.env],csrf,{name:c.name.trim(),critical:c.critical});
    if(c.role.trim())await api.rsmPatchComponent(x.component_id,csrf,{revision:x.revision,role:c.role.trim()});
    if(c.ruleKind&&c.rule.trim())await api.rsmCreateRule(x.component_id,csrf,{kind:c.ruleKind,pattern:c.rule.trim(),mode:c.mode})}
   out.push('Компонентов: '+comps.length+', правил: '+comps.filter(c=>c.ruleKind).length);
   for(const d of deps)await api.createRelation(csrf,{relation_type:'depends_on',from:{kind:'service',id:sv.service_uid},to:{kind:'service',id:d}});
   if(deps.length)out.push('Зависимостей: '+deps.length);
   setCreated(sv.service_uid);setLog(out);dropDraft();
  }catch(e){setError(e);setLog(out);if(e instanceof ApiError&&e.status===401)onExpired()}finally{setBusy(false)}
 }
 async function apply(){setBusy(true);setError(null);try{const r=await api.rsmApplyRules(csrf);setApplied('Правила применены ко всем хостам: привязано '+r.bound+', предложено '+r.proposed+(r.conflicts?', конфликтов '+r.conflicts:''))}catch(e){setError(e);if(e instanceof ApiError&&e.status===401)onExpired()}finally{setBusy(false)}}
 const sysName=(uid:string)=>systems?.items.find(s=>s.service_uid===uid)?.name??uid.slice(0,8);
 const subj=(id:string)=>people.find(p=>p.subject_id===id)?.name??'не задан';
 const side=<>
  <div><h2>Что получится</h2><p className="sub">Проверьте перед созданием</p></div>
  <Panel title={name.trim()||'Новая система'} right={<Pill tone={crit==='high'||crit==='critical'?'red':crit==='medium'?'amber':'grey'}>{critNames.find(c=>c[0]===crit)?.[1]}</Pill>}>
   <dl className="kv"><dt>Направление</dt><dd>{ov?.directions.find(d=>d.direction_uid===dir)?.name??'не задано'}</dd><dt>Среды</dt><dd>{envs.map(envName).join(', ')||'—'}</dd><dt>Компонентов</dt><dd>{comps.filter(c=>c.name.trim()).length}</dd><dt>Правил</dt><dd>{comps.filter(c=>c.ruleKind&&c.rule.trim()).length}</dd></dl></Panel>
  <Panel title="Зависимости">{deps.length?<div className="form-row">{deps.map(d=><Pill key={d} tone="blue">{sysName(d)}</Pill>)}</div>:<p className="muted">Не заданы</p>}</Panel>
  <Panel title="Ответственные"><dl className="kv"><dt>Владелец (бизнес)</dt><dd>{owner||'не задан'}</dd><dt>ИТ</dt><dd>{it?subj(it):'не задан'}</dd><dt>Дежурные</dt><dd>{onCall||'не заданы'}</dd><dt>Резерв</dt><dd>{backup?subj(backup):'не задан'}</dd></dl></Panel>
  <p className="muted">Правила «предлагать» кладут подходящие хосты в «Предложения» на подтверждение; «автоматически» — привязывают сразу.</p>
 </>;
 return <Split side={side}>
  <div className="stepper">{steps.map((s,i)=><button key={s} className={i===step?'on':i<step?'done':''} disabled={created!==null||(i>step&&!valid.slice(0,i).every(Boolean))} onClick={()=>setStep(i)}><b>{i+1}</b>{s}</button>)}</div>
  {error?<div className="error" role="alert">{errorMessage(error)}</div>:null}
  {created?<Panel title="Система создана"><ul className="plain-list">{log.map((l,i)=><li key={i}>{l}</li>)}</ul>{applied?<p className="notice" role="status">{applied}</p>:null}
   <div className="form-row"><button className="button primary-sm" onClick={()=>onDone(created)}>Открыть карточку системы</button>{comps.some(c=>c.ruleKind)?<button className="button" disabled={busy||!!applied} onClick={()=>void apply()}>Применить правила сейчас</button>:null}</div></Panel>:<>
  {step===0?<div className="form-grid wizard-grid"><label>Название<input value={name} onChange={e=>setName(e.target.value)} placeholder="например, Кадровый портал"/></label>
   <label>Направление<select value={dir} onChange={e=>setDir(e.target.value)}><option value="">не задано</option>{(ov?.directions??[]).map(d=><option key={d.direction_uid} value={d.direction_uid}>{d.name}</option>)}</select></label>
   <label>Критичность<select value={crit} onChange={e=>setCrit(e.target.value)}>{critNames.map(([k,v])=><option key={k} value={k}>{v}</option>)}</select></label></div>:null}
  {step===1?<div><p className="muted">Среды системы</p><div className="form-row">{envKinds.map(([k,v])=><label key={k} className="env-check"><input type="checkbox" checked={envs.includes(k)} onChange={e=>setEnvs(x=>e.target.checked?[...x,k]:x.filter(y=>y!==k))}/> {v}</label>)}</div></div>:null}
  {step===2?<Panel title="Компоненты и правила привязки" right={<button className="button small" onClick={()=>setComps(c=>[...c,{name:'',env:envs[0]??'prod',role:'',critical:false,ruleKind:'',rule:'',mode:'propose'}])}>+ Компонент</button>} flush>
   <div className="table-scroll"><table className="panel-table wizard-table"><colgroup><col style={{width:"21%"}}/><col style={{width:"14%"}}/><col style={{width:"15%"}}/><col style={{width:"8%"}}/><col/><col style={{width:"64px"}}/></colgroup><thead><tr><th>Компонент</th><th>Среда</th><th>Роль</th><th>Критичный</th><th>Правило привязки</th><th/></tr></thead><tbody>{comps.map((c,i)=><tr key={i}>
    <td><input aria-label="Имя компонента" value={c.name} onChange={e=>set(i,{name:e.target.value})} placeholder="Веб-фронт"/></td>
    <td><select aria-label="Среда компонента" value={c.env} onChange={e=>set(i,{env:e.target.value as RSMEnvKind})}>{envs.map(k=><option key={k} value={k}>{envName(k)}</option>)}</select></td>
    <td><input aria-label="Роль" value={c.role} onChange={e=>set(i,{role:e.target.value})} placeholder="веб"/></td>
    <td><input type="checkbox" aria-label="Критичный" checked={c.critical} onChange={e=>set(i,{critical:e.target.checked})}/></td>
    <td><div className="form-row"><select aria-label="Вид правила" value={c.ruleKind} onChange={e=>set(i,{ruleKind:e.target.value})}>{ruleKinds.map(([k,v])=><option key={k} value={k}>{v}</option>)}</select>{c.ruleKind?<>{c.ruleKind==='asset_class'?<select aria-label="Шаблон правила" value={c.rule} onChange={e=>set(i,{rule:e.target.value})}><option value="">класс…</option>{[['server','сервер'],['virtual_machine','виртуальная машина'],['workstation','рабочая станция'],['laptop','ноутбук'],['network','сетевое устройство'],['printer','принтер']].map(([k,l])=><option key={k} value={k}>{l}</option>)}</select>:<input aria-label="Шаблон правила" className="mono" value={c.rule} onChange={e=>set(i,{rule:e.target.value})} placeholder={c.ruleKind==='subnet'?'10.12.8.0/24':c.ruleKind==='hostname_glob'?'srv-hr-web*':c.ruleKind==='software'?'PostgreSQL':'server'}/>}<select aria-label="Режим правила" value={c.mode} onChange={e=>set(i,{mode:e.target.value as Comp['mode']})}><option value="propose">предлагать</option><option value="auto">автоматически</option></select></>:null}</div></td>
    <td>{comps.length>1?<button className="link" onClick={()=>setComps(x=>x.filter((_,j)=>j!==i))}>убрать</button>:null}</td></tr>)}</tbody></table></div></Panel>:null}
  {step===3?<div className="form-grid"><label>Зависит от систем<select multiple size={8} value={deps} onChange={e=>setDeps([...e.target.selectedOptions].map(o=>o.value))}>{(systems?.items??[]).map(s=><option key={s.service_uid} value={s.service_uid}>{s.name}</option>)}</select></label><p className="muted">Ctrl/Cmd — выбрать несколько. Связь «зависит от» видна в карточках обеих систем.</p></div>:null}
  {step===4?<div className="form-grid wizard-grid"><label>Владелец (бизнес)<input value={owner} onChange={e=>setOwner(e.target.value)} placeholder="Директор по персоналу"/></label>
   <label>Ответственный ИТ<select value={it} onChange={e=>setIt(e.target.value)}><option value="">не задан</option>{people.map(p=><option key={p.subject_id} value={p.subject_id}>{p.kind==='team'?'Команда: ':''}{p.name}</option>)}</select></label>
   <label>Дежурные<input value={onCall} onChange={e=>setOnCall(e.target.value)} placeholder="дежурная смена ИТ"/></label>
   <label>Резерв<select value={backup} onChange={e=>setBackup(e.target.value)}><option value="">не задан</option>{people.map(p=><option key={p.subject_id} value={p.subject_id}>{p.kind==='team'?'Команда: ':''}{p.name}</option>)}</select></label>
   <label>Окно обслуживания<input value={window_} onChange={e=>setWindow(e.target.value)} placeholder="вс 02:00–05:00"/></label></div>:null}
  {step===5?<Panel title="Проверка"><ul className="plain-list"><li>Система «{name}», критичность {critNames.find(c=>c[0]===crit)?.[1]}</li><li>Среды: {envs.map(envName).join(', ')}</li>{comps.map((c,i)=><li key={i}>{c.name||'—'} / {envName(c.env)}{c.role?' · '+c.role:''}{c.critical?' · критичный':''}{c.ruleKind?' · правило «'+(ruleKinds.find(r=>r[0]===c.ruleKind)?.[1])+' '+c.rule+'», '+(c.mode==='auto'?'автоматически':'предлагать'):''}</li>)}{deps.length?<li>Зависит от: {deps.map(sysName).join(', ')}</li>:null}</ul></Panel>:null}
  <div className="form-row"><button className="button" disabled={busy} onClick={()=>step?setStep(step-1):onCancel()}>{step?'← Назад':'Отмена'}</button><span className="spacer"/>{created?null:<button className="button" disabled={busy||!name.trim()} onClick={saveDraft}>{saved?'Черновик сохранён':'Сохранить черновик'}</button>}
   {step<5?<button className="button primary-sm" disabled={!valid[step]} onClick={()=>setStep(step+1)}>Далее: {steps[step+1].toLowerCase()} →</button>:<button className="button primary-sm" disabled={busy||!valid.every(Boolean)} onClick={()=>void create()}>{busy?'Создаём…':'Создать систему'}</button>}</div>
  </>}
 </Split>;
}
