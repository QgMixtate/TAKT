#!/usr/bin/env python3
"""C52.02: Rust-агент на настоящих центре и collector (обвязка C07): установка по коду из Web (отпечаток центра,
регистрация через collector, enroll), затем Go-агент работает на каталоге состояния, созданном Rust (совместимость
формата — замена без перерегистрации). Отказы: неверный отпечаток, исчерпанный код. Отчёт .local/c52-rust-agent-smoke.json."""
import hashlib,json,os,ssl,subprocess,time
from pathlib import Path
from machine_smoke import main as machine_harness
from dev import ROOT,STATE

RUST=ROOT/'agent-rs'

def scenario(**s):
 checks=s['checks'];request=s['request'];sql=s['sql'];start=s['start']
 subprocess.run(['cargo','build','--release','--locked','--quiet'],cwd=RUST,check=True,timeout=900)
 rust=str(RUST/'target/release/surveyscan-agent')
 headers={'Origin':s['origin'],'Cookie':s['cookie'],'X-CSRF-Token':s['session']['csrf_token']}
 body={'source_kind':'agent','site_id':s['site'],'collector_source_id':s['collector_source'],'inventory_platform':'linux/amd64','max_uses':1,'ttl_hours':1,'comment':'rust smoke'}
 status,code,_=request(s['tls_port'],s['plain'],'POST','/api/v1/registration-codes',body,headers);assert status==201,('code',status,code)
 fp=hashlib.sha256(ssl.PEM_cert_to_DER_cert(Path(s['ca_file']).read_text())).hexdigest();assert code['center_fingerprint']==fp
 collector=f"https://127.0.0.1:{s['collector_port']}";base=Path(s['directory'])
 def register(name,fingerprint,expect):
  env=dict(os.environ,SURVEYSCAN_REGISTRATION_CODE=code['code'])
  p=subprocess.run([rust,'register','--collector',collector,'--fingerprint',fingerprint,'--config',str(base/name/'agent.json'),'--state',str(base/name/'state')],env=env,capture_output=True,text=True,timeout=120)
  assert p.returncode==expect,(name,p.returncode,p.stdout[-300:],p.stderr[-300:]);return p
 p=register('wrong','ab'*32,1);assert 'отпечаток' in p.stderr and not (base/'wrong'/'state'/'preparation.json').exists();checks.append('rust agent refuses an unpinned centre before sending the code')
 register('rust',fp,0);cfg=json.loads((base/'rust'/'agent.json').read_text())
 source=json.loads((base/'rust'/'state'/'preparation.json').read_text())['source_id']
 assert sql(f"SELECT state FROM sources.sources WHERE source_id='{source}'")=='active';assert not (base/'rust'/'state'/'registration-grant.json').exists()
 checks.append('rust agent installs by registration code through the site collector: pinned CA, prepare, register, enroll')
 p=register('again',fp,1);assert 'код не принят' in p.stderr;checks.append('single-use code is exhausted for a second machine')
 # Go-агент работает на каталоге состояния Rust-агента: формат совпадает (замена без перерегистрации)
 go=str(ROOT/'.dist/surveyscan-agent');process=start('go-agent-on-rust-state',[go,'run','--config',str(base/'rust'/'agent.json')]);deadline=time.monotonic()+120
 while time.monotonic()<deadline:
  assert process.poll() is None,'go agent exited on rust state'
  if int(sql(f"SELECT count(*) FROM inventory.observations o WHERE o.source_id='{source}'"))>=1:break
  time.sleep(.5)
 else:raise RuntimeError('no observation from rust-registered identity')
 process.terminate();process.wait(timeout=8)
 checks.append('go agent runs on the state created by the rust agent and delivers signed inventory')
 report={'package':'C52.02','status':'passed','checks':checks,'count':len(checks),'target':'rust agent register + real compiled collector/center + PostgreSQL'}
 (STATE/'c52-rust-agent-smoke.json').write_text(json.dumps(report,ensure_ascii=False,indent=1)+'\n');print(json.dumps(report,ensure_ascii=False))

if __name__=='__main__':machine_harness(agent_scenario=scenario)
