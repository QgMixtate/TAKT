#!/usr/bin/env python3
"""C52.04 (C52-05): пакеты deb агента и collector под настоящим systemd на настоящих центре и collector (обвязка C07):
register.env → служба регистрации → служба агента (heartbeat в центре) → обновление пакета сохраняет регистрацию и
служба продолжает работать → collector из пакета регистрируется по коду в центре и запущен → purge убирает всё.

Где systemd: на CI-раннере — прямо на машине (SURVEYSCAN_PACKAGE_HOST=1, через sudo); в песочнице — привилегированный
контейнер с systemd (SURVEYSCAN_PACKAGE_SYSTEMD_IMAGE, сеть хоста). Отчёт .local/c52-package-service-smoke.json."""
import hashlib, json, os, shlex, ssl, subprocess, tempfile, time
from pathlib import Path
from machine_smoke import main as machine_harness
from dev import ROOT, STATE
import packages

VERSION = os.environ.get('SURVEYSCAN_PACKAGE_VERSION', '0.0.0-c13')


class Target:
    """Команды на машине с systemd: хост (sudo) или контейнер."""

    def __init__(self, files):
        self.files = files
        self.container = None
        if os.environ.get('SURVEYSCAN_PACKAGE_HOST') != '1':
            image = os.environ.get('SURVEYSCAN_PACKAGE_SYSTEMD_IMAGE', 'ss-systemd:24.04')
            self.container = subprocess.run(['docker', 'run', '-d', '--rm', '--privileged', '--cgroupns=host', '--network', 'host',
                                             '-v', '/sys/fs/cgroup:/sys/fs/cgroup:rw', '-v', f'{files}:/pkgs:ro', '--tmpfs', '/run', '--tmpfs', '/run/lock',
                                             image, '/sbin/init'], capture_output=True, text=True, check=True).stdout.strip()
            self.wait(lambda: self.sh('systemctl is-system-running', check=False).stdout.strip() in ('running', 'degraded'), 90, 'systemd in container')

    def path(self, name):
        return f'/pkgs/{name}' if self.container else str(self.files / name)

    def sh(self, command, check=True, input=None):
        argv = ['docker', 'exec', '-i', self.container, 'sh', '-c', command] if self.container else ['sudo', 'sh', '-c', command]
        p = subprocess.run(argv, capture_output=True, text=True, timeout=300, input=input)
        if check and p.returncode != 0:
            raise RuntimeError(f'{command}: {p.returncode}\n{p.stdout[-1500:]}\n{p.stderr[-1500:]}')
        return p

    def write_secret(self, path, text):
        self.sh(f'umask 077; cat > {shlex.quote(path)}', input=text)

    def wait(self, predicate, seconds, what):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(1)
        raise RuntimeError(f'timeout: {what() if callable(what) else what}')

    def active(self, unit):
        return self.sh(f'systemctl is-active {unit}', check=False).stdout.strip() == 'active'

    def journal(self, unit):
        return self.sh(f'journalctl -u {unit} --no-pager -n 40', check=False).stdout

    def close(self):
        if self.container:
            subprocess.run(['docker', 'rm', '-f', self.container], capture_output=True)
        else:
            self.sh('dpkg -P surveyscan-agent surveyscan-collector >/dev/null 2>&1 || true', check=False)


def scenario(**s):
    checks, request, sql = s['checks'], s['request'], s['sql']
    headers = {'Origin': s['origin'], 'Cookie': s['cookie'], 'X-CSRF-Token': s['session']['csrf_token']}
    fp = hashlib.sha256(ssl.PEM_cert_to_DER_cert(Path(s['ca_file']).read_text())).hexdigest()

    def code(kind, **extra):
        body = {'source_kind': kind, 'site_id': s['site'], 'max_uses': 1, 'ttl_hours': 1, 'comment': f'package {kind} smoke', **extra}
        status, c, _ = request(s['tls_port'], s['plain'], 'POST', '/api/v1/registration-codes', body, headers)
        assert status == 201, (kind, status, c)
        assert c['center_fingerprint'] == fp
        return c['code']

    files = Path(tempfile.mkdtemp(prefix='c52-pkg-'))
    packages.build(VERSION, ROOT / '.dist', files / 'v1', with_windows=False)
    packages.build(VERSION + '.1', ROOT / '.dist', files / 'v2', with_windows=False)
    deb = lambda v, kind: next((files / v).glob(f'surveyscan-{kind}_*.deb')).relative_to(files)
    t = Target(files)
    try:
        # агент: register.env до установки пакета → регистрация и запуск службы без ручных шагов
        t.sh('install -d -m 0700 /etc/surveyscan-agent')
        t.write_secret('/etc/surveyscan-agent/register.env', f"COLLECTOR_URL=https://127.0.0.1:{s['collector_port']}\nCENTER_FINGERPRINT={fp}\n"
                       f"REG_CODE={code('agent', collector_source_id=s['collector_source'], inventory_platform='linux/amd64')}\n")
        t.sh(f'dpkg -i {t.path(deb("v1", "agent"))}')
        t.wait(lambda: t.active('surveyscan-agent'), 120, lambda: 'agent service after register.env:\n' + t.journal('surveyscan-agent-register') + t.journal('surveyscan-agent'))
        source = json.loads(t.sh('cat /var/lib/surveyscan-agent/preparation.json').stdout)['source_id']
        assert t.sh('test -e /etc/surveyscan-agent/register.env', check=False).returncode == 1, 'register.env with the code left on disk'
        assert t.sh('stat -c %U /var/lib/surveyscan-agent/identity.json').stdout.strip() == 'surveyscan-agent'
        pid = t.sh('systemctl show -p MainPID --value surveyscan-agent').stdout.strip()
        assert t.sh(f'ps -o user= -p {pid}').stdout.strip() == 'surveyscan-agent'
        # unit-файлы пакета разбирает настоящий systemd без ошибок
        t.sh('systemd-analyze verify /usr/lib/systemd/system/surveyscan-agent.service /usr/lib/systemd/system/surveyscan-agent-register.service')
        fresh = lambda: sql(f"SELECT count(*) FROM sources.heartbeat_state WHERE source_id='{source}' AND last_contact_at>now()-interval '20 seconds'") == '1'
        t.wait(fresh, 120, lambda: 'agent heartbeat from the packaged service:\n' + t.journal('surveyscan-agent') + t.journal('surveyscan-agent'))
        assert sql(f"SELECT state FROM sources.sources WHERE source_id='{source}'") == 'active'
        checks.append('deb agent + register.env: registration service registers once by code through the collector, deletes the code file, '
                      'agent service starts as surveyscan-agent and the centre sees its heartbeat')
        before = t.sh('systemctl show -p MainPID --value surveyscan-agent').stdout.strip()
        agents = sql("SELECT count(*) FROM sources.sources WHERE source_kind='agent'")
        t.sh(f'dpkg -i {t.path(deb("v2", "agent"))}')
        assert t.sh("dpkg-query -W -f '${Version}' surveyscan-agent").stdout.endswith('.1-1')
        t.wait(lambda: t.active('surveyscan-agent') and t.sh('systemctl show -p MainPID --value surveyscan-agent').stdout.strip() not in ('', '0', before), 60,
               'agent restarted after upgrade')
        assert json.loads(t.sh('cat /var/lib/surveyscan-agent/preparation.json').stdout)['source_id'] == source
        time.sleep(21)
        t.wait(fresh, 120, lambda: 'heartbeat after upgrade:\n' + t.journal('surveyscan-agent') + t.journal('surveyscan-agent'))
        assert sql("SELECT count(*) FROM sources.sources WHERE source_kind='agent'") == agents, 'upgrade created a second agent source'
        checks.append('deb agent upgrade: service restarted on the new version, same source and identity, heartbeat continues, no second source')
        # collector: интерактивная установка через setup (код — в stdin, не в аргументах)
        port = int(s['collector_port']) + 17
        t.sh(f'dpkg -i {t.path(deb("v1", "collector"))}')
        assert not t.active('surveyscan-collector'), 'collector service started before registration'
        out = t.sh(f"surveyscan-collector-setup --center https://127.0.0.1:{s['tls_port']} --fingerprint {fp} --listen 127.0.0.1:{port}",
                   input=code('collector') + '\n').stdout
        assert 'запущена' in out, out
        t.wait(lambda: t.active('surveyscan-collector'), 60, lambda: 'collector service:\n' + t.journal('surveyscan-collector') + t.journal('surveyscan-agent'))
        collector = json.loads(t.sh('cat /etc/surveyscan-collector/collector.json').stdout)['source_id']
        assert sql(f"SELECT state FROM sources.sources WHERE source_id='{collector}'") == 'active'
        t.wait(lambda: t.sh(f"bash -c 'exec 3<>/dev/tcp/127.0.0.1/{port}'", check=False).returncode == 0, 60,
               lambda: 'collector listens:\n' + t.journal('surveyscan-collector') + t.journal('surveyscan-agent'))
        assert t.sh('stat -c %U:%a /etc/surveyscan-collector/collector.key').stdout.strip() == 'surveyscan-collector:600'
        checks.append('deb collector: service does not start before registration; surveyscan-collector-setup (code on stdin) registers in the centre, '
                      'keys 0600 owned by the service user, service listens for agents')
        t.sh('dpkg -P surveyscan-agent surveyscan-collector >/dev/null')
        assert t.sh('test -e /etc/surveyscan-agent -o -e /var/lib/surveyscan-agent -o -e /etc/surveyscan-collector', check=False).returncode == 1
        assert not t.active('surveyscan-agent') and not t.active('surveyscan-collector')
        checks.append('dpkg purge: services stopped and disabled, registration, keys and queue removed')
    finally:
        t.close()
    report = {'package': 'C52.04', 'status': 'passed', 'checks': checks, 'count': len(checks),
              'target': 'deb packages under real systemd + real compiled collector/center + PostgreSQL'}
    (STATE / 'c52-package-service-smoke.json').write_text(json.dumps(report, ensure_ascii=False, indent=1) + '\n')
    print(json.dumps(report, ensure_ascii=False))


if __name__ == '__main__':
    machine_harness(agent_scenario=scenario, inventory12=True, collector_inventory12=True)
