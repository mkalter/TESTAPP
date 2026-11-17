#!/usr/bin/env python3
"""Offline watchface archive experiment: create a separate forMigration=true candidate.

Never opens a device, modifies a system file or replaces the source archive.
This does not establish that any Apple Watch will accept the resulting archive.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import sys
import zipfile

MAX_ENTRIES = 1024
MAX_JSON = 2 * 1024 * 1024
MAX_UNCOMPRESSED = 128 * 1024 * 1024


def sha256(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1048576), b''):
            h.update(chunk)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path, help='Existing local genuine .watchface file')
    parser.add_argument('--output', type=Path, help='New output path; default: NAME-migration-test.watchface')
    parser.add_argument('--inspect-only', action='store_true', help='Read and print manifest only; do not create a file')
    args = parser.parse_args()

    src = args.source.expanduser().resolve(strict=True)
    if not src.is_file() or not zipfile.is_zipfile(src):
        parser.error('Source is not a valid .watchface ZIP archive')
    out = (args.output.expanduser().absolute() if args.output else src.with_name(src.stem + '-migration-test.watchface'))
    if not args.inspect_only and (out.exists() or os.path.samefile(src, out) if out.exists() else False):
        parser.error('Output already exists. Choose a new name; overwriting is disabled.')

    with zipfile.ZipFile(src, 'r') as original:
        entries = original.infolist()
        if len(entries) > MAX_ENTRIES or sum(e.file_size for e in entries) > MAX_UNCOMPRESSED:
            parser.error('Archive exceeds safety limits')
        names = [e.filename for e in entries]
        if names.count('face.json') != 1:
            parser.error('Exactly one top-level face.json is required')
        for e in entries:
            p = PurePosixPath(e.filename)
            if e.filename.startswith('/') or '\\' in e.filename or '..' in p.parts:
                parser.error('Archive has unsafe entry paths')
        if original.getinfo('face.json').file_size > MAX_JSON:
            parser.error('face.json is too large')
        data = original.read('face.json')
        manifest = json.loads(data.decode('utf-8'))
        if not isinstance(manifest, dict) or manifest.get('face type') != 'bundle':
            parser.error('Expected a bundled watch face')
        if not isinstance(manifest.get('bundle id'), str):
            parser.error('Missing bundle id')
        old = manifest.get('forMigration')
        print('Source:', src)
        print('SHA-256 source:', sha256(src))
        print('Bundle ID:', manifest.get('bundle id'))
        print('Face type:', manifest.get('face type'))
        print('Old forMigration:', repr(old))
        print('File entries:', len(entries))
        if args.inspect_only:
            return 0
        if old is True:
            parser.error('Already marked forMigration=true; no change necessary')
        manifest['forMigration'] = True
        new_data = (json.dumps(manifest, ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')
        with zipfile.ZipFile(out, 'x') as target:
            target.comment = original.comment
            for info in entries:
                payload = new_data if info.filename == 'face.json' else original.read(info.filename)
                target.writestr(info, payload)
    with zipfile.ZipFile(out, 'r') as check:
        if check.testzip() is not None:
            raise RuntimeError('Output failed ZIP CRC validation')
        new_manifest = json.loads(check.read('face.json'))
        if new_manifest['forMigration'] is not True:
            raise RuntimeError('Output manifest mismatch')
    print('New candidate:', out)
    print('SHA-256 candidate:', sha256(out))
    print('Original untouched:', sha256(src))
    print('Status: OFFLINE ZIP CANDIDATE ONLY, no watchOS compatibility claim')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, zipfile.BadZipFile, UnicodeDecodeError, json.JSONDecodeError) as exc:
        print('Error:', exc, file=sys.stderr)
        sys.exit(2)