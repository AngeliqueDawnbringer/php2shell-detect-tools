#!/usr/bin/env python3
"""Inspect local Docker images or docker-save archives for PHP. Never runs images.
Python 3.10+, standard library only. See README.md for scope and limitations.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tempfile

RUNTIME = re.compile(r'(?:php(?:(?:-cgi|-fpm)?(?:[-.]?\d+(?:\.\d+)*)?|(?:[-.]?\d+(?:\.\d+)*)(?:-cgi|-fpm))|lsphp\d*)$', re.I)
MODULE = re.compile(r'(?:libphp|mod_php).*\.so(?:\.\d+)*$', re.I)
PHPDIR = re.compile(r'(?:^|/)(?:php[^/]*|lsphp[^/]*|ea-php[^/]*|alt-php[^/]*|rh-php[^/]*)(?:/|$)', re.I)
VERSION = re.compile(rb'\bPHP(?:/|[ \t]+)(\d+\.\d+\.\d+(?:[-+~._A-Za-z0-9]*))')
SOURCE = re.compile(r'\.(?:php\d*|phtml|phps)$', re.I)


PACKAGE_FILES = {'var/lib/dpkg/status': 'dpkg', 'lib/apk/db/installed': 'apk'}

def branch_hint(path):
    match = re.search(r'(?:php|lsphp)[-/.]?(\d+)\.(\d+)', path, re.I)
    if match:
        return '.'.join(match.groups())
    match = re.search(r'(?:php|lsphp)[-/]?(\d)(\d)(?=[^0-9]|$)', path, re.I)
    return '.'.join(match.groups()) if match else None


def parse_packages(text, format_name):
    evidence = []
    for paragraph in re.split(r'\n\s*\n', text.strip()):
        fields = {}
        for line in paragraph.splitlines():
            if ':' in line and not line.startswith((' ', '\t')):
                key, value = line.split(':', 1)
                fields[key] = value.strip()
        if format_name == 'dpkg':
            if fields.get('Status') != 'install ok installed':
                continue
            name, version = fields.get('Package', ''), fields.get('Version', '')
        else:
            name, version = fields.get('P', ''), fields.get('V', '')
        # Exclude PECL/library package versions: e.g. php-redis 6.x is not PHP 6.x.
        if not re.fullmatch(r'(?:php(?:\d+(?:\.\d+)?)?|php(?:\d+(?:\.\d+)?)?-(?:cli|fpm|cgi|common|core)|libapache2-mod-php(?:\d+(?:\.\d+)?)?)', name):
            continue
        match = re.match(r'(?:\d+:)?(\d+\.\d+\.\d+(?:(?:RC|alpha|beta)\d*)?)', version, re.I)
        if match:
            evidence.append({'version': match[1], 'package': name, 'package_version': version})
    return evidence


def version_assessment(findings, config, tags):
    candidates = {}
    def add(version, source, score, detail):
        if not version:
            return
        item = candidates.setdefault(version, {'version':version, 'score':score, 'evidence':[]})
        item['score'] = max(item['score'], score)
        evidence = {'source':source, 'detail':detail}
        if evidence not in item['evidence']:
            item['evidence'].append(evidence)
    for f in findings:
        if f['visibility'] != 'final_image_path':
            continue
        if f['kind'] in ('runtime_candidate', 'apache_php_module'):
            hints = f['version_hints']
            if hints:
                for version in hints:
                    add(version, 'runtime_embedded_string', 90 if len(hints)==1 else 55, f['path'])
                f['version_guess'] = {'version':hints[0] if len(hints)==1 else None,
                                      'confidence':'high' if len(hints)==1 else 'ambiguous', 'alternatives':hints}
            else:
                branch = branch_hint(f['path'])
                f['version_guess'] = {'version':branch, 'confidence':'low' if branch else 'unknown',
                                      'precision':'branch' if branch else None}
                add(branch, 'runtime_path', 25, f['path'])
        if f['kind'] == 'php_version_header':
            for version in f.get('metadata_versions', []):
                add(version, 'development_header', 65, f['path'])
        for package in f.get('package_versions', []):
            add(package['version'], 'installed_package_record', 75,
                f"{f['path']}: {package['package']}={package['package_version']}")
    # Retain only the named version value, never the image's full environment.
    for value in (config.get('config') or {}).get('Env') or []:
        if value.startswith('PHP_VERSION='):
            version = value.split('=', 1)[1]
            if re.fullmatch(r'\d+\.\d+(?:\.\d+)?(?:[-+~._A-Za-z0-9]*)', version):
                add(version, 'image_environment', 45, 'PHP_VERSION=' + version)
    for tag in tags:
        match = re.search(r'(?:^|/)php:(\d+\.\d+(?:\.\d+)?)(?:-|$)', tag)
        if match:
            add(match[1], 'php_image_tag', 20, tag)
    ordered = sorted(candidates.values(), key=lambda c:(-c['score'], c['version']))
    for c in ordered:
        c['confidence'] = 'high' if c['score'] >= 90 else 'medium' if c['score'] >= 65 else 'low'
        c['precision'] = 'branch' if re.fullmatch(r'\d+\.\d+', c['version']) else 'release'
    top = [c for c in ordered if c['score']==ordered[0]['score']] if ordered else []
    # Branch-only evidence agrees with releases in that branch; do not invent a patch.
    def agrees(a,b):
        return a==b or (re.fullmatch(r'\d+\.\d+', a) and b.startswith(a+'.')) or (re.fullmatch(r'\d+\.\d+', b) and a.startswith(b+'.'))
    conflict = any(not agrees(a['version'],b['version']) for a in ordered for b in ordered)
    best = top[0] if len(top)==1 else None
    return {'best_guess':best['version'] if best else None,
            'confidence':best['confidence'] if best else ('ambiguous' if top else 'unknown'),
            'precision':best['precision'] if best else None,
            'multiple_or_conflicting_versions':conflict,
            'candidates':ordered,
            'note':'Heuristic evidence ranking, not probabilities or proof of the active runtime. Multiple runtimes may coexist; package/header/environment evidence can be stale.'}


def clean(name):
    p = PurePosixPath(name)
    if p.is_absolute() or '..' in p.parts or '\x00' in name:
        raise ValueError(f'Unsafe archive path: {name!r}')
    return str(p).removeprefix('./')


def kind(path):
    name = PurePosixPath(path).name
    if path in PACKAGE_FILES:
        return 'package_database'
    if name == 'php_version.h':
        return 'php_version_header'
    if RUNTIME.fullmatch(name):
        return 'runtime_candidate'
    if MODULE.fullmatch(name):
        return 'apache_php_module'
    if re.search(r'\.so(?:\.\d+)*$', name) and PHPDIR.search(path):
        return 'php_library_or_extension'
    if SOURCE.search(name):
        return 'php_source_candidate'
    if name in ('php.ini', 'php-fpm.conf') or (name.endswith('.conf') and '/pool.d/' in '/' + path):
        return 'php_configuration_candidate'
    return None


def read_json(archive, name, limit=16 * 1024 * 1024):
    member = archive.getmember(clean(name))
    if not member.isfile() or member.size > limit:
        raise ValueError('Invalid or oversized JSON member: ' + name)
    with archive.extractfile(member) as f:
        return json.load(f)


def remove_tree(state, path, children_only=False):
    for key in list(state):
        if (not children_only and key == path) or key.startswith(path + '/') or path == '.':
            del state[key]


def inspect_layers(archive, layers, max_bytes):
    state, records, warnings = {}, [], []
    for index, layer_name in enumerate(layers):
        outer = archive.getmember(clean(layer_name))
        if not outer.isfile():
            raise ValueError('Layer is not a regular archive member')
        pending, whiteouts, seen = [], [], set()
        with archive.extractfile(outer) as stream, tarfile.open(fileobj=stream, mode='r|*') as layer:
            for entry in layer:
                path = clean(entry.name)
                if path == '.':
                    continue
                if path in seen:
                    raise ValueError('Duplicate layer path: ' + path)
                seen.add(path)
                base = PurePosixPath(path).name
                parent = str(PurePosixPath(path).parent)
                if base == '.wh..wh..opq':
                    whiteouts.append((parent, True))
                    continue
                if base.startswith('.wh.'):
                    whiteouts.append((str(PurePosixPath(parent) / base[4:]), False))
                    continue
                record_id = None
                classification = kind(path)
                if classification and not entry.isdir():
                    record = dict(path='/' + path, kind=classification, layer=index,
                                  layer_archive=layer_name, size=entry.size, version_hints=[])
                    if entry.issym() or entry.islnk():
                        record.update(file_type='symlink' if entry.issym() else 'hardlink',
                                      link_target=entry.linkname, note='Target not followed; inspect target findings separately.')
                    elif entry.isfile():
                        record['file_type'] = 'regular'
                        if classification in ('package_database', 'php_version_header'):
                            if entry.size > 16 * 1024 * 1024:
                                record['metadata_scan_skipped'] = 'Metadata exceeds 16 MiB cap'
                                warnings.append(f'Metadata skipped: /{path}')
                            else:
                                with layer.extractfile(entry) as f:
                                    content = f.read().decode('utf-8', errors='replace')
                                if classification == 'package_database':
                                    record['package_versions'] = parse_packages(content, PACKAGE_FILES[path])
                                else:
                                    record['metadata_versions'] = re.findall(r'^\s*#\s*define\s+PHP_VERSION\s+"(\d+\.\d+\.\d+[^"]*)"', content, re.M)
                        if classification in ('runtime_candidate', 'apache_php_module', 'php_library_or_extension'):
                            with layer.extractfile(entry) as f:
                                head = f.read(4)
                                record['elf'] = head == b'\x7fELF'
                                if record['elf']:
                                    hints, tail, remaining = set(), head, max_bytes - 4
                                    while remaining > 0:
                                        chunk = f.read(min(1024 * 1024, remaining))
                                        if not chunk:
                                            break
                                        data = tail + chunk
                                        hints.update(m.group(1).decode('ascii') for m in VERSION.finditer(data))
                                        tail = data[-256:]
                                        remaining -= len(chunk)
                                    record['version_hints'] = sorted(hints)
                                    record['content_scan_limited'] = entry.size > max_bytes
                                else:
                                    record['note'] = 'Name match only; not an ELF binary.'
                    else:
                        record['file_type'] = 'special'
                    record_id = len(records)
                    records.append(record)
                pending.append((path, entry.isdir(), record_id))
        # Whiteouts affect lower layers only, regardless of tar entry ordering.
        for path, opaque in whiteouts:
            remove_tree(state, path, children_only=opaque)
        for path, directory, record_id in pending:
            # Do not emulate writes through symlink ancestors: fail closed rather than
            # presenting a guessed final filesystem for unusual/malformed layers.
            for parent in PurePosixPath(path).parents:
                key = str(parent)
                if key in state and not state[key][0]:
                    raise ValueError('Non-directory ancestor in layer: ' + key)
            if not directory or (path in state and not state[path][0]):
                remove_tree(state, path)
            state[path] = (directory, record_id)
    visible = {value[1] for value in state.values() if value[1] is not None}
    for i, record in enumerate(records):
        record['visibility'] = 'final_image_path' if i in visible else 'historical_layer_only'
    return records, warnings


def inspect_archive(path, max_bytes):
    results = []
    with tarfile.open(path, 'r:*') as archive:
        # Supports docker-save's manifest.json layout, not arbitrary OCI-only layouts.
        try:
            manifest = read_json(archive, 'manifest.json')
        except KeyError:
            raise ValueError('No manifest.json: use a docker image save archive; OCI-only layouts are unsupported.')
        if not isinstance(manifest, list) or not manifest:
            raise ValueError('Empty or invalid Docker save manifest')
        for item in manifest:
            config = read_json(archive, item['Config'])
            findings, warnings = inspect_layers(archive, item['Layers'], max_bytes)
            final = [f for f in findings if f['visibility'] == 'final_image_path']
            results.append(dict(tags=item.get('RepoTags') or [], config_archive=item['Config'],
                                os=config.get('os'), architecture=config.get('architecture'),
                                layer_count=len(item['Layers']),
                                final_php_related_paths=len(final),
                                historical_php_related_paths=len(findings) - len(final),
                                runtime_version_hints=sorted({v for f in final if f['kind'] in ('runtime_candidate','apache_php_module') for v in f['version_hints']}),
                                php_version_guess=version_assessment(findings, config, item.get('RepoTags') or []),
                                findings=findings, warnings=warnings))
    return results


def docker(*args):
    return subprocess.run(['docker', *args], check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True).stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('images', nargs='*', help='Local Docker image names or IDs; never pulled automatically')
    parser.add_argument('--all', action='store_true', help='Inspect all local image IDs reported by docker image ls -aq')
    parser.add_argument('--archive', action='append', type=Path, default=[], help='Inspect a docker-save tar or tar.gz; repeatable, no Docker needed')
    parser.add_argument('--output', type=Path, default=Path('docker-php-report.json'))
    parser.add_argument('--max-file-mib', type=int, default=64, help='Max ELF bytes inspected per candidate (default 64 MiB)')
    args = parser.parse_args()
    if args.max_file_mib < 1:
        parser.error('--max-file-mib must be positive')
    if not (args.images or args.all or args.archive):
        parser.error('Supply image names, --all, or --archive')
    report = dict(timestamp_utc=datetime.now(timezone.utc).isoformat(), images=[], errors=[], limitations=[
        'PHP version guesses from ranked evidence; no CVE, patch-status or integrity verdict.',
        'No image processes are executed. No images are pulled, modified, loaded or deleted.',
        'Only docker-save manifest.json archives are supported; OCI-only layouts are not.',
        'Linux ELF version inspection only; renamed runtimes, unusual paths and non-ELF builds can be missed.',
        'Links are listed but not followed. Hidden layer files are not automatically active or remotely exposed.',
        'Source/configuration candidates are listed by filename only; their contents are not inspected.',
        'Container writable layers, volumes, bind mounts, runtime downloads and other image platforms are outside scope.',
        'Resource limits are per candidate ELF read, not overall archive, disk or execution limits.'
    ])
    sources = [(str(p), p) for p in args.archive]
    with tempfile.TemporaryDirectory(prefix='docker-php-inspect-') as tmp:
        refs = list(args.images)
        if args.all:
            try:
                refs.extend(docker('image', 'ls', '-aq', '--no-trunc').splitlines())
            except (OSError, subprocess.CalledProcessError) as exc:
                report['errors'].append({'source':'--all', 'error':str(exc)})
        ids = set()
        for ref in refs:
            try:
                info = json.loads(docker('image', 'inspect', '--', ref))[0]
                image_id = info['Id']
                if image_id in ids:
                    continue
                ids.add(image_id)
                target = Path(tmp) / 'image.tar'
                print(f'Inspecting {ref} ({image_id})', flush=True)
                docker('image', 'save', '--output', str(target), image_id)
                for result in inspect_archive(target, args.max_file_mib * 1024 * 1024):
                    result['php_version_guess'] = version_assessment(result['findings'],
                        {'config':info.get('Config') or {}}, info.get('RepoTags') or [])
                    result.update(source=ref, image_id=image_id, local_tags=info.get('RepoTags') or [])
                    report['images'].append(result)
                target.unlink()
            except (OSError, subprocess.CalledProcessError, ValueError, KeyError, TypeError, IndexError, tarfile.TarError) as exc:
                report['errors'].append({'source':ref,'error':str(exc)})
        for source, path in sources:
            try:
                for result in inspect_archive(path, args.max_file_mib * 1024 * 1024):
                    result['source'] = source
                    report['images'].append(result)
            except (OSError, ValueError, KeyError, TypeError, IndexError, tarfile.TarError) as exc:
                report['errors'].append({'source':source, 'error':str(exc)})
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    for item in report['images']:
        print(f"{item['source']}: {item['final_php_related_paths']} final PHP-related paths; "
              f"{item['historical_php_related_paths']} historical; runtime hints: "
              + (', '.join(item['runtime_version_hints']) or 'unknown'))
        guess = item['php_version_guess']
        print(f"  PHP best guess: {guess['best_guess'] or 'unknown/ambiguous'} ({guess['confidence']}); multiple/conflicting clues: {guess['multiple_or_conflicting_versions']}")
        for candidate in guess['candidates']:
            print(f"    {candidate['version']} [{candidate['confidence']}, {candidate['precision']}]: " + ', '.join(sorted({e['source'] for e in candidate['evidence']})))
    for error in report['errors']:
        print(f"ERROR {error['source']}: {error['error']}", file=sys.stderr)
    print(f'Report: {args.output}; manual package/build verification required.')
    return 2 if report['errors'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
