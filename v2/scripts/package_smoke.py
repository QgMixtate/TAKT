#!/usr/bin/env python3
"""C52.04 (C52-05, часть «пакеты»): deb/rpm агента и collector ставятся, обновляются с сохранением регистрации и
удаляются в контейнерах поддерживаемых дистрибутивов (scripts/package_install_check.sh). Без systemd в контейнере —
служба и регистрация по коду проверяются отдельно (package_service_smoke.py). Нужны docker и собранные бинарники
(make build, make rust). Отчёт .local/c52-package-smoke.json.

  python3 scripts/package_smoke.py [--version 0.0.0-c13] [--images debian:12,rockylinux:9]
Образы по умолчанию — ниже; дополнительные (например, РЕД ОС из реестра вендора) — SURVEYSCAN_PACKAGE_IMAGES_EXTRA."""
import argparse, json, os, subprocess, sys, tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import packages  # noqa: E402

ROOT = packages.ROOT
STATE = ROOT / '.local'
# образ → формат пакета (решение пользователя C52.05: Debian 11+, Ubuntu 20.04+, RHEL-совместимые 8+, Альт, РЕД ОС)
IMAGES = {'debian:11': 'deb', 'debian:12': 'deb', 'ubuntu:20.04': 'deb', 'ubuntu:24.04': 'deb',
          'rockylinux:8': 'rpm', 'rockylinux:9': 'rpm', 'almalinux:9': 'rpm', 'alt:p10': 'rpm'}


def run_image(image, fmt, v1, v2):
    script = ROOT / 'scripts/package_install_check.sh'
    cmd = ['docker', 'run', '--rm', '--network', 'none', '-v', f'{v1}:/v1:ro', '-v', f'{v2}:/v2:ro', '-v', f'{script}:/check.sh:ro',
           image, 'sh', '/check.sh', fmt, '/v1', '/v2']
    for attempt in range(3):  # docker hub иногда отвечает отказом на HEAD — повтор
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if p.returncode == 0 or 'failed to resolve reference' not in p.stderr:
            break
    return p


def main():
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument('--version', default='0.0.0-c13')
    a.add_argument('--images', help='через запятую; формат — по IMAGES или суффиксу =deb/=rpm')
    o = a.parse_args()
    images = dict(IMAGES)
    if o.images:
        images = {}
        for item in o.images.split(','):
            name, _, fmt = item.partition('=')
            images[name] = fmt or IMAGES.get(name) or sys.exit(f'формат для {name}: укажите {name}=deb|rpm')
    for item in filter(None, os.environ.get('SURVEYSCAN_PACKAGE_IMAGES_EXTRA', '').split(',')):
        name, _, fmt = item.partition('=')
        images[name] = fmt or 'rpm'
    checks, failed = [], []
    with tempfile.TemporaryDirectory() as tmp:
        v1, v2 = Path(tmp, 'v1'), Path(tmp, 'v2')
        packages.build(o.version, ROOT / '.dist', v1, with_windows=False)
        packages.build(o.version + '.1', ROOT / '.dist', v2, with_windows=False)
        for image, fmt in images.items():
            p = run_image(image, fmt, v1, v2)
            if p.returncode == 0 and p.stdout.strip().endswith('PASS'):
                checks.append(f'{image} ({fmt}): install, service user and 0700 directories, binary runs, setup refuses non-root and '
                              'unknown register.env keys without executing it, upgrade keeps registration, remove keeps data'
                              + (', purge removes data and user' if fmt == 'deb' else ', reinstall picks up registration'))
            else:
                failed.append({'image': image, 'code': p.returncode, 'stdout': p.stdout[-1500:], 'stderr': p.stderr[-1500:]})
    report = {'package': 'C52.04', 'status': 'failed' if failed else 'passed', 'checks': checks, 'count': len(checks), 'failed': failed,
              'target': 'deb/rpm in distribution containers without systemd (service and registration — package_service_smoke)'}
    STATE.mkdir(exist_ok=True)
    (STATE / 'c52-package-smoke.json').write_text(json.dumps(report, ensure_ascii=False, indent=1) + '\n')
    print(json.dumps(report, ensure_ascii=False, indent=1))
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
