#!/usr/bin/env python3
"""C52-01 (Windows): разделы сбора Rust-агента против Go (тот же хост, CI windows-2022).
Сравниваются устойчивые поля; изменчивые (состояние служб, время) — не сравниваются."""
import json,subprocess,sys

go,rust=sys.argv[1],sys.argv[2]

def section(cmd):
    p=subprocess.run(cmd,capture_output=True,text=True,timeout=120)
    if p.returncode!=0:raise SystemExit(f'{cmd}: {p.returncode} {p.stderr[-400:]}')
    return json.loads(p.stdout.strip().splitlines()[-1])

def key(name,row):
    if name=='services':return row['name']
    if name=='resources':return (row['name'],row.get('total_bytes'),row.get('filesystem'))
    if name=='neighbors':return (row['address'],row['interface_index'],row.get('mac'))
    if name=='software':return (row['name'],row.get('registry_key'),row.get('registry_view'),row.get('scope'))
    return json.dumps(row,sort_keys=True)

checks=[]
for name in ['identity','os','network','hardware','software','services','users_groups','routes_ports','resources','neighbors']:
    g=section([go,'inventory-worker',name]);r=section([rust,'inventory-section',name])
    if name=='neighbors':  # кэш ARP/NDP меняется между вызовами — сравниваются только постоянные записи
        g['records']=[x for x in g['records'] if x.get('state')=='permanent'];r['records']=[x for x in r['records'] if x.get('state')=='permanent']
    assert g['status']==r['status'] and g['reason_code']==r['reason_code'],(name,g['status'],r['status'],g['reason_code'],r['reason_code'])
    gk=sorted(map(str,(key(name,x) for x in g['records'])));rk=sorted(map(str,(key(name,x) for x in r['records'])))
    if gk!=rk:
        only_go=[x for x in gk if x not in rk][:5];only_rust=[x for x in rk if x not in gk][:5]
        raise SystemExit(f'{name}: records differ; only go={only_go} only rust={only_rust}')
    checks.append(f'{name}: {len(gk)} records identical')
print(json.dumps({'package':'C52-01 windows','status':'passed','checks':checks},ensure_ascii=False))
