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
