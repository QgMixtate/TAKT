#!/usr/bin/env python3
"""Package an operator-quiesced PG/Bao/files checkpoint; extract only to a new private root.

Does not stop services or restore a running DB/Bao. Custody/recovery keys stay separate.
Input must come from one frozen application checkpoint, never independently timed live copies.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import uuid

from release import digest, read_json, require

# Предел набора: дамп БД стенда перерос 2 GiB (стенд №20) — по умолчанию 64 GiB, переопределяется
# SURVEYSCAN_CHECKPOINT_MAX_GIB (целое, 1..1024).
MAX_BYTES = max(1, min(1024, int(os.environ.get('SURVEYSCAN_CHECKPOINT_MAX_GIB', '64')))) * 1024 * 1024 * 1024


def files(root, known=None):
    require(root.is_dir() and not root.is_symlink(), 'regular directory required')
    result = {}
    size = 0
    for path in sorted(root.rglob('*')):
        mode = path.lstat().st_mode
        require(stat.S_ISDIR(mode) or stat.S_ISREG(mode), 'symlink/special state entry refused')
        name = path.relative_to(root).as_posix()
        require(all(32 <= ord(c) < 127 for c in name) and '\\' not in name, 'unsupported state filename')
        if stat.S_ISREG(mode):
            size += path.stat().st_size
            require(size <= MAX_BYTES and len(result) < 20000, 'checkpoint exceeds bound (SURVEYSCAN_CHECKPOINT_MAX_GIB)')
            if known and name in known and known[name]['bytes'] == path.stat().st_size:
                result[name] = dict(known[name])  # сумма из описания компонента; verify пересчитает её
            else:
                result[name] = {'bytes': path.stat().st_size, 'sha256': digest(path)}
    return result


def privatize(root):
    root.chmod(0o700)
    for path in root.rglob('*'):
        path.chmod(0o700 if path.is_dir() else 0o600)


def pack(output, postgres, raft, states, quiesced, pg_online=False):
    require(quiesced, 'all selected application writers must be stopped/fenced before capture')
    require(not output.exists() and not output.is_symlink(), 'new checkpoint directory required')
    require(states and all(re.fullmatch('[a-z][a-z0-9-]{0,47}', label) for label in states), 'named state roots required')
    require(raft.is_file() and not raft.is_symlink(), 'regular Raft snapshot required')
    pg = read_json(postgres / 'backup.json')
    require(pg.get('format') == 'surveyscan-pg-backup-v1', 'PG component backup required')
    for source in (postgres, *states.values()):
        # Validate source before copying; never follow symlinks into private custody. Дамп при --pg-online не хешируется
        # здесь (№86): его сумма — в описании pg_backup, проверка — verify после запуска центра.
        files(source, known={'postgres.dump': {'bytes': pg.get('bytes'), 'sha256': pg.get('sha256')}} if pg_online and source == postgres else None)
        require(not output.absolute().is_relative_to(source.resolve()), 'output must be outside selected state roots')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.checkpoint-', dir=output.parent) as temp:
        root = Path(temp) / 'checkpoint'
        payload = root / 'payload'
        payload.mkdir(parents=True)
        if pg_online and os.stat(postgres).st_dev == os.stat(payload).st_dev:
            # ISSUES №86: дамп снят до остановки писателей — переносится переименованием (секунды вместо минут при
            # остановленном центре); сумма дампа — из его описания pg_backup; полную проверку делает verify после запуска
            os.rename(postgres, payload / 'postgres')
            archive = payload / 'postgres/postgres.dump'
            require(archive.is_file() and archive.stat().st_size == pg.get('bytes'), 'PG archive mismatch')
        else:
            shutil.copytree(postgres, payload / 'postgres', symlinks=True)
            archive = payload / 'postgres/postgres.dump'
            require(digest(archive) == pg.get('sha256') and archive.stat().st_size == pg.get('bytes'), 'PG archive mismatch')
        shutil.copyfile(raft, payload / 'bao.snapshot')
        for label, source in states.items():
            shutil.copytree(source, payload / 'state' / label, symlinks=True)
        copied = files(payload, known={'postgres/postgres.dump': {'bytes': pg.get('bytes'), 'sha256': pg.get('sha256')}} if pg_online else None)
        require(digest(payload / 'bao.snapshot') == digest(raft), 'snapshot changed during copy')
        for label, source in states.items():
            require(files(payload / 'state' / label) == files(source), 'state changed while copying')
        privatize(root)
        manifest = {'format': 'surveyscan-offline-checkpoint-v1', 'checkpoint_id': str(uuid.uuid4()),
                    'completed_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                    'writers_quiesced_by_operator': True, 'states': sorted(states), 'files': copied,
                    # ISSUES №77: дамп PG снят до остановки писателей (pg_dump согласован сам по себе); Bao и файлы
                    # состояния — при остановленных писателях. После восстановления центр догоняет PG по агентам/collector.
                    'postgres_captured_online': bool(pg_online), 'postgres_completed_at': pg.get('completed_at'),
                    'scope': 'selected PG/Bao/application files; operator is responsible for complete coverage and separate custody',
                    'production_dr_validated': False}
        (root / 'checkpoint.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
        (root / 'checkpoint.json').chmod(0o600)
        os.rename(root, output)
    return manifest


def verify(root):
    require(root.is_dir() and not root.is_symlink() and root.stat().st_mode & 0o077 == 0, 'private checkpoint directory required')
    require({p.name for p in root.iterdir()} == {'checkpoint.json', 'payload'}, 'unexpected checkpoint entries')
    manifest = read_json(root / 'checkpoint.json')
    require(manifest.get('format') == 'surveyscan-offline-checkpoint-v1', 'unsupported checkpoint')
    require(files(root / 'payload') == manifest.get('files'), 'checkpoint digest/size/set mismatch')
    for path in (root, *root.rglob('*')):
        require(path.stat().st_uid == os.getuid() and path.stat().st_mode & 0o077 == 0, 'checkpoint must stay owner-only')
    return manifest


def extract(source, target):
    require(not target.exists() and not target.is_symlink(), 'new private restore directory required')
    manifest = verify(source)
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.restore-checkpoint-', dir=target.parent) as temp:
        copy = Path(temp) / 'checkpoint'
        shutil.copytree(source, copy, symlinks=True)
        require(verify(copy) == manifest, 'checkpoint changed during extraction')
        os.rename(copy, target)
    return {'extracted': True, 'checkpoint_id': manifest['checkpoint_id'], 'services_started': False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    commands = p.add_subparsers(dest='command', required=True)
    build = commands.add_parser('pack')
    build.add_argument('--output', required=True, type=Path)
    build.add_argument('--postgres', required=True, type=Path)
    build.add_argument('--bao-snapshot', required=True, type=Path)
    build.add_argument('--state', action='append', default=[], metavar='LABEL=DIR')
    build.add_argument('--writers-quiesced', action='store_true')
    build.add_argument('--pg-online', action='store_true', help='дамп PG снят без остановки центра (ISSUES №77)')
    for command in ('verify', 'extract'):
        sub = commands.add_parser(command)
        sub.add_argument('--checkpoint', required=True, type=Path)
        if command == 'extract':
            sub.add_argument('--target', required=True, type=Path)
    args = p.parse_args()
    if args.command == 'pack':
        states = {}
        for item in args.state:
            label, path = item.split('=', 1)
            require(label not in states, 'duplicate state label')
            states[label] = Path(path)
        result = pack(args.output, args.postgres, args.bao_snapshot, states, args.writers_quiesced, args.pg_online)
    elif args.command == 'verify':
        result = verify(args.checkpoint)
    else:
        result = extract(args.checkpoint, args.target)
    print(json.dumps({k: v for k, v in result.items() if k not in ('files', 'states')}))


if __name__ == '__main__':
    try:
        main()
    except ValueError as e:  # тексты require() фиксированы и без секретов — причина видна оператору
        raise SystemExit('checkpoint operation refused: ' + str(e))
    except (OSError, KeyError, TypeError) as e:
        raise SystemExit('checkpoint operation refused (' + type(e).__name__ + '); inspect protected source, quiescence and destination')
