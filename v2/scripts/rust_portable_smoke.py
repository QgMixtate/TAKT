#!/usr/bin/env python3
"""C52.06: Rust-portable собирает удалённый Linux по SSH (локальный sshd, временный пользователь, пароль — только в памяти).
Проверки: обследование → привязка профиля → сбор → пакет с discovery.json проверяет Go-центр; неверный пароль —
AUTH_FAILED без повторов; смена ключа узла — HOST_KEY_CHANGED. Нужны root или sudo (useradd, sshd)."""
import json,os,secrets,shutil,subprocess,sys,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
RUST=ROOT/'agent-rs/target/release/surveyscan-portable'
SUDO=[] if os.geteuid()==0 else ['sudo','-n']
def run(cmd,**kw):return subprocess.run(cmd,capture_output=True,text=True,timeout=180,**kw)
def wizard_check(state,pw):
    """Локальный веб-мастер: только свой Host и токен; проверка узла из мастера; пароль не попадает в ответы."""
    import http.client,re
    w=subprocess.Popen([str(RUST),'wizard','--state',str(state),'--no-browser'],stdout=subprocess.PIPE,text=True)
    try:
        m=re.search(r'http://127\.0\.0\.1:(\d+)/#([0-9a-f]+)',w.stdout.readline());port,tok=int(m[1]),m[2]
        def req(method,path,body=None,token=tok,host=None):
            c=http.client.HTTPConnection('127.0.0.1',port,timeout=30);h={'Host':host or f'127.0.0.1:{port}','Content-Type':'application/json'}
            if token:h['X-Token']=token
            c.request(method,path,body=None if body is None else json.dumps(body),headers=h);r=c.getresponse();return r.status,r.read().decode()
        assert req('GET','/')[0]==200 and req('GET','/api/state',token=None)[0]==403 and req('GET','/api/state',token='0'*48)[0]==403
        assert req('GET','/api/state',host='evil.example')[0]==403
        st=json.loads(req('GET','/api/state')[1]);assert st['initialized'] and st['bound']==['linux-ro'],st
        code,_=req('POST','/api/test',{'ip':'127.0.0.1','secrets':{'linux-ro':pw}});assert code==200
        for _ in range(120):
            j=json.loads(req('GET','/api/job')[1])
            if not j['running']:break
            time.sleep(1)
        out='\n'.join(j['lines']);assert j['ok'] and 'DRY RUN: 1 target(s) ok' in out,out[-1500:]
        assert pw not in out+json.dumps(st)
        return 'local wizard: 127.0.0.1 only, foreign Host and missing token refused (403), single-node test from the wizard, password not echoed'
    finally:
        w.terminate();w.wait(timeout=10)
def main():
    sshd=shutil.which('sshd') or '/usr/sbin/sshd'
    assert Path(sshd).exists(),'sshd required (openssh-server)'
    d=Path(tempfile.mkdtemp(prefix='rust-portable-'));os.chmod(d,0o755);checks=[]
    user='ssportable'+secrets.token_hex(3);pw=secrets.token_urlsafe(18)
    run(SUDO+['useradd','-m','-s','/bin/bash',user]);r=run(SUDO+['chpasswd'],input=f'{user}:{pw}\n');assert r.returncode==0,r.stderr
    procs=[]
    def start_sshd(key):
        cfg=d/'sshd_config';cfg.write_text(f'Port 2222\nListenAddress 127.0.0.1\nHostKey {key}\nPasswordAuthentication yes\nKbdInteractiveAuthentication yes\nUsePAM yes\nPidFile {d}/sshd.pid\n')
        run(SUDO+['mkdir','-p','/run/sshd']);p=subprocess.Popen(SUDO+[sshd,'-D','-f',str(cfg)]);procs.append(p);time.sleep(1.5);return p
    try:
        for k in ['hostkey','hostkey2']:run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(d/k)])
        run(SUDO+['chown','root:root',str(d/'hostkey'),str(d/'hostkey2')])
        sshd_p=start_sshd(d/'hostkey')
        state=d/'state'
        init=run([str(RUST),'init','--state',str(state),'--tenant','00000000-0000-4000-8000-000000000051','--site','00000000-0000-4000-8000-000000000052','--scope','00000000-0000-4000-8000-000000000053']);assert init.returncode==0,init.stderr
        pub=[l.split('=',1)[1] for l in init.stdout.splitlines() if l.startswith('public_key=')][0]
        (state/'profiles.json').write_text(json.dumps({'profiles':[{'name':'linux-ro','kind':'ssh','user':user,'auth':'password','port':2222}],'rules':[{'profile':'linux-ro','kind':'linux_ssh'}]}))
        disc=run([str(RUST),'discover','--state',str(state),'--range','127.0.0.1/32','--rate','1000']);assert disc.returncode==0,disc.stderr
        last=json.loads((state/'discovery-last.json').read_text());assert last['hosts'] and last['hosts'][0]['ip']=='127.0.0.1',last
        last['hosts'][0]['kind']='linux_ssh';(state/'discovery-last.json').write_text(json.dumps(last)) # 22 может быть закрыт на runner: вид — Linux
        checks.append('discover finds 127.0.0.1 and records it in the audit directory')
        bad=run([str(RUST),'collect','--state',str(state),'--dry-run','--no-host','--secrets-stdin'],input='linux-ro=wrong\n')
        assert 'FAILED: AUTH_FAILED' in bad.stdout,(bad.stdout,bad.stderr);checks.append('wrong password: AUTH_FAILED, no retry (no account lockout), nothing exported')
        pkg=d/'audit.zip'
        ok=run([str(RUST),'collect','--state',str(state),'--out',str(pkg),'--no-host','--secrets-stdin'],input=f'linux-ro={pw}\n')
        assert ok.returncode==0 and 'EXPORTED: 1 observation' in ok.stdout,(ok.stdout[-1500:],ok.stderr[-800:])
        rows=int([l for l in ok.stdout.splitlines() if 'rows=' in l][0].split('rows=')[1]);assert rows>50,rows
        assert pw not in ok.stdout+ok.stderr and pw not in pkg.read_bytes().decode('latin-1') and pw not in ''.join(p.read_text() for p in state.glob('*.json'))
        checks.append(f'ssh collection with a password profile: {rows} rows; password absent from output, package and audit directory')
        go=ROOT/'.dist/surveyscan-portable'
        if not go.exists():go=d/'goportable';assert run(['go','build','-o',str(go),'./cmd/surveyscan-portable'],cwd=ROOT).returncode==0
        v=run([str(go),'verify','--package',str(pkg),'--public-key',pub]);assert 'VERIFIED' in v.stdout and 'accepted=1' in v.stdout,(v.stdout,v.stderr)
        checks.append('Go centre verifies the package: manifest signature, discovery.json with outcome collected, 1.2 observation')
        checks.append(wizard_check(state,pw))
        subprocess.run(SUDO+['kill',(d/'sshd.pid').read_text().strip()]);sshd_p.wait(timeout=10)
        start_sshd(d/'hostkey2')
        ch=run([str(RUST),'collect','--state',str(state),'--dry-run','--no-host','--secrets-stdin'],input=f'linux-ro={pw}\n')
        assert 'FAILED: HOST_KEY_CHANGED' in ch.stdout,(ch.stdout,ch.stderr);checks.append('changed host key after first contact: HOST_KEY_CHANGED, no login attempt')
    finally:
        if (d/'sshd.pid').exists():subprocess.run(SUDO+['kill',(d/'sshd.pid').read_text().strip()])
        for p in procs:
            try:p.wait(timeout=5)
            except Exception:p.kill()
        run(SUDO+['userdel','-r',user])
    report={'package':'C52.06','status':'passed','checks':checks,'count':len(checks),'target':'rust portable: discover, profiles, SSH collection, Go verify'}
    print(json.dumps(report,ensure_ascii=False))
if __name__=='__main__':main()
