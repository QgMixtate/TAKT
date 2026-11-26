#!/usr/bin/env python3
"""C52.04: пакеты агента (Rust) и collector (Go) — deb, rpm, tar.gz (Linux), MSI и zip (Windows x64) — из уже собранных
бинарников.

  python3 scripts/packages.py --version 0.0.0-c13 [--dist .dist] [--output .dist/packages]

Агент берётся из .dist/rust/linux/surveyscan-agent (`make rust`), collector — из .dist/surveyscan-collector
(`make build`), их Windows-версии — .dist/rust/windows/surveyscan-agent.exe и .dist/surveyscan-collector.exe.
Пакеты Linux собирает nfpm (из PATH, $NFPM или `go run` закреплённой версии), MSI — wixl (msitools).
Версия deb/rpm — версия выпуска, «-» заменяется на «~» (rpm не допускает «-»; «~» сортируется раньше финальной).
Версия MSI — числовая (msi_version). В каталоге результата — SHA256SUMS. --no-windows — только Linux."""
import argparse, hashlib, io, os, re, shutil, subprocess, sys, tarfile, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGING = ROOT / 'packaging/linux'
NFPM_VERSION = 'v2.41.1'
COMPONENTS = {  # компонент → бинарник в --dist
    'agent': 'rust/linux/surveyscan-agent',
    'collector': 'surveyscan-collector',
}
WINDOWS = {  # компонент → .exe в --dist и переменная WiX с путём к нему
    'agent': ('rust/windows/surveyscan-agent.exe', 'AgentExe'),
    'collector': ('surveyscan-collector.exe', 'CollectorExe'),
}


def nfpm_command():
    explicit = os.environ.get('NFPM')
    if explicit:
        return [explicit]
    found = shutil.which('nfpm') or (str(Path.home() / 'go/bin/nfpm') if (Path.home() / 'go/bin/nfpm').exists() else None)
    if found:
        return [found]
    return [os.environ.get('GO', 'go'), 'run', f'github.com/goreleaser/nfpm/v2/cmd/nfpm@{NFPM_VERSION}']


def package_version(version):
    if not version or any(c.isspace() for c in version) or version[0] not in '0123456789':
        raise SystemExit(f'неверная версия выпуска: {version!r}')
    return version.replace('-', '~')


def msi_version(version):
    """MSI допускает только a.b.c[.d] (a,b ≤ 255, c ≤ 65535). X.Y.Z-<буквы>N[.M] → X.Y.(Z*1000+N).M: сборки одного
    выпуска различаются, MajorUpgrade с AllowSameVersionUpgrades заменяет и одинаковую по трём полям версию."""
    m = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)(?:-[A-Za-z]*(\d+)(?:\.(\d+))?)?', version)
    if not m:
        raise SystemExit(f'версия выпуска не приводится к версии MSI: {version!r}')
    x, y, z, n, b = (int(g) if g else 0 for g in m.groups())
    if x > 255 or y > 255 or z * 1000 + n > 65535 or b > 65535:
        raise SystemExit(f'версия MSI вне пределов: {version!r}')
    return f'{x}.{y}.{z * 1000 + n}.{b}'


def windows(kind, dist, version, out):
    """MSI (wixl) и zip (только .exe) для Windows x64."""
    rel, var = WINDOWS[kind]
    exe = (dist / rel).resolve()
    if not exe.is_file():
        raise SystemExit(f'нет {exe} (make build / make rust)')
    name = f'surveyscan-{kind}'
    msi = out / f'{name}_{version}_windows_x64.msi'
    p = subprocess.run([os.environ.get('WIXL', 'wixl'), '-a', 'x64', '-D', f'MsiVersion={msi_version(version)}', '-D', f'Version={version}',
                        '-D', f'{var}={exe}', '-o', str(msi), str(ROOT / f'packaging/windows/{kind}.wxs')], capture_output=True, text=True, timeout=600)
    if p.returncode != 0 or not msi.is_file():
        sys.stderr.write(p.stdout + p.stderr)
        raise SystemExit(f'wixl {kind}: код {p.returncode}')
    with zipfile.ZipFile(out / f'{name}_{version}_windows_x64.zip', 'w', zipfile.ZIP_DEFLATED) as z:
        info = zipfile.ZipInfo(f'{name}.exe', date_time=(2026, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(info, exe.read_bytes())


def epoch():
    if os.environ.get('SOURCE_DATE_EPOCH'):
        return int(os.environ['SOURCE_DATE_EPOCH'])
    p = subprocess.run(['git', 'log', '-1', '--format=%ct'], cwd=ROOT, capture_output=True, text=True)
    return int(p.stdout.strip()) if p.returncode == 0 and p.stdout.strip() else 0


def tarball(kind, binary, version, out, mtime):
    """tar.gz для установки без менеджера пакетов: бинарник, setup, unit-файлы, пример register.env."""
    name = f'surveyscan-{kind}'
    files = [(binary, f'bin/{name}', 0o755), (PACKAGING / kind / f'{name}-setup', f'sbin/{name}-setup', 0o755),
             (PACKAGING / kind / f'{name}.service', f'systemd/{name}.service', 0o644),
             (PACKAGING / kind / f'{name}-register.service', f'systemd/{name}-register.service', 0o644),
             (PACKAGING / kind / 'register.env.example', 'register.env.example', 0o644)]
    target = out / f'{name}_{version}_linux_amd64.tar.gz'
    prefix = f'{name}-{version}'
    with tarfile.open(target, 'w:gz', format=tarfile.PAX_FORMAT) as t:
        for src, dst, mode in files:
            data = Path(src).read_bytes()
            info = tarfile.TarInfo(f'{prefix}/{dst}')
            info.size, info.mode, info.mtime, info.uname, info.gname = len(data), mode, mtime, 'root', 'root'
            t.addfile(info, io.BytesIO(data))
    return target


def build(version, dist, out, with_windows=True, only_windows=False):
    pv = package_version(version)
    out.mkdir(parents=True, exist_ok=True)
    for old in out.iterdir():
        if old.is_file():
            old.unlink()
    mtime = epoch()
    produced = []
    for kind, rel in COMPONENTS.items():
        if only_windows:
            windows(kind, dist, version, out)
            continue
        binary = (dist / rel).resolve()
        if not binary.is_file():
            raise SystemExit(f'нет бинарника {binary} (сначала make build / make rust)')
        env = dict(os.environ, SOURCE_DATE_EPOCH=str(mtime))
        # подстановка ${…} — здесь: nfpm раскрывает переменные не во всех полях (contents.src — нет)
        config = (PACKAGING / kind / 'nfpm.yaml').read_text()
        for key, value in {'VERSION': pv, 'ARCH': 'amd64', 'BINARY': str(binary), 'PACKAGING': str(PACKAGING)}.items():
            config = config.replace('${' + key + '}', value)
        rendered = out / f'.nfpm-{kind}.yaml'
        rendered.write_text(config)
        for packager in ('deb', 'rpm'):
            p = subprocess.run(nfpm_command() + ['package', '--config', str(rendered), '--packager', packager, '--target', str(out)],
                               env=env, capture_output=True, text=True, timeout=600)
            if p.returncode != 0:
                sys.stderr.write(p.stdout + p.stderr)
                raise SystemExit(f'nfpm {kind} {packager}: код {p.returncode}')
        rendered.unlink()
        produced.append(tarball(kind, binary, version, out, mtime))
        if with_windows:
            windows(kind, dist, version, out)
    sums = []
    for f in sorted(out.iterdir()):
        if f.is_file() and f.name != 'SHA256SUMS':
            sums.append(f'{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.name}')
    (out / 'SHA256SUMS').write_text('\n'.join(sums) + '\n')
    print('\n'.join(sums))


def main():
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument('--version', required=True)
    a.add_argument('--dist', type=Path, default=ROOT / '.dist')
    a.add_argument('--output', type=Path)
    a.add_argument('--no-windows', action='store_true', help='без MSI и zip')
    a.add_argument('--only-windows', action='store_true', help='только MSI и zip (сборка без Linux-бинарников)')
    o = a.parse_args()
    build(o.version, o.dist, o.output or o.dist / 'packages', not o.no_windows, o.only_windows)


if __name__ == '__main__':
    main()
