#!/usr/bin/env python3
"""Read-only PHP binary/library inventory. Python 3.9+. No binaries executed."""
import argparse
import os
import re
import stat
from collections import Counter

FIXED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
BINARY = re.compile(r'(?:php(?:(?:-cgi|-fpm)?(?:[-.]?\d+(?:\.\d+)*)?|(?:[-.]?\d+(?:\.\d+)*)(?:-cgi|-fpm))|lsphp\d*)$', re.I)
MODULE = re.compile(r'(?:libphp|mod_php).*\.so(?:\.\d+)*$', re.I)
SHARED = re.compile(r'.*\.so(?:\.\d+)*$', re.I)
PHP_DIR = re.compile(r'(?:^|/)(?:php[^/]*|lsphp[^/]*|ea-php[^/]*|alt-php[^/]*|rh-php[^/]*)(?:/|$)', re.I)
VERSION = re.compile(rb'\bPHP(?:/|[ \t]+)(\d+\.\d+\.\d+(?:[-+~._A-Za-z0-9]*))')
SKIP = {'/proc', '/sys', '/dev'}


def classify(path):
    name = os.path.basename(path)
    if BINARY.fullmatch(name):
        return 'runtime'
    if MODULE.fullmatch(name):
        return 'Apache PHP module'
    if SHARED.fullmatch(name) and PHP_DIR.search(path):
        return 'PHP extension/library'
    return None


def assess(kind, hints):
    if kind == 'PHP extension/library':
        return 'VERIFY', 'Check the owning runtime and package.'
    if len(hints) != 1:
        return 'UNKNOWN', 'No unique embedded PHP version; verify package/build metadata.'
    version = hints[0]
    if re.search(r'alpha|beta|rc|dev', version, re.I):
        return 'UNKNOWN', 'Prerelease/development version string.'
    match = re.match(r'(\d+)\.(\d+)\.(\d+)', version)
    if not match:
        return 'UNKNOWN', 'Unrecognised version string.'
    major, minor, patch = map(int, match.groups())
    floor = FIXED.get((major, minor))
    if floor is not None:
        if patch < floor:
            return 'POTENTIALLY VULNERABLE', f'Below {major}.{minor}.{floor}; update or verify vendor backports.'
        return 'FIXED-VERSION HINT', 'Meets upstream threshold; verify installed package/build.'
    if major == 7 or (major == 8 and minor <= 1) or (major == 5 and minor >= 4):
        return 'POTENTIALLY VULNERABLE', 'Legacy branch; upgrade or verify a supported backport.'
    return 'UNKNOWN', 'Outside this checker\'s release matrix.'


class Inventory:
    def __init__(self):
        self.records = {}
        self.errors = Counter()
        self.stale = set()

    def error(self, exc):
        self.errors[type(exc).__name__] += 1

    def add(self, access_path, source, display_path=None):
        display_path = display_path or access_path
        kind = classify(display_path)
        if not kind:
            return
        try:
            info = os.stat(access_path)
            if not stat.S_ISREG(info.st_mode):
                return
            with open(access_path, 'rb') as stream:
                if stream.read(4) != b'\x7fELF':
                    return
        except (OSError, ValueError) as exc:
            self.error(exc)
            return
        key = info.st_dev, info.st_ino
        record = self.records.setdefault(key, {
            'path': display_path, 'access': access_path, 'kind': kind,
            'aliases': set(), 'sources': set()
        })
        record['aliases'].add(display_path)
        record['sources'].add(source)

    def scan_filesystem(self, root):
        for directory, dirs, files in os.walk(root, followlinks=False, onerror=self.error):
            dirs[:] = [n for n in dirs if os.path.join(directory, n) not in SKIP]
            for name in files:
                path = os.path.join(directory, name)
                if classify(path):
                    self.add(path, 'filesystem')

    def scan_processes(self):
        try:
            pids = os.listdir('/proc')
        except OSError as exc:
            self.error(exc)
            return
        for pid in pids:
            if not pid.isdigit():
                continue
            proc = f'/proc/{pid}'
            try:
                target = os.readlink(f'{proc}/exe')
                clean = target.removesuffix(' (deleted)')
                if classify(clean):
                    if target.endswith(' (deleted)'):
                        self.stale.add((pid, target))
                    else:
                        # Inspect the actual process executable, including namespaces.
                        self.add(f'{proc}/exe', f'running PID {pid}', clean)
            except PermissionError as exc:
                self.error(exc)
            except OSError:
                pass  # A process can exit while being inspected.
            try:
                with open(f'{proc}/maps', encoding='utf-8', errors='replace') as stream:
                    for line in stream:
                        parts = line.rstrip('\n').split(None, 5)
                        if len(parts) != 6:
                            continue
                        path = parts[5]
                        clean = path.removesuffix(' (deleted)')
                        if not clean.startswith('/') or not classify(clean):
                            continue
                        if path.endswith(' (deleted)'):
                            self.stale.add((pid, path))
                        else:
                            self.add(f'{proc}/root{clean}', f'mapped by PID {pid}', clean)
            except PermissionError as exc:
                self.error(exc)
            except OSError:
                pass

    def hints(self, path):
        found, tail = set(), b''
        try:
            with open(path, 'rb') as stream:
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    data = tail + chunk
                    found.update(m.group(1).decode('ascii') for m in VERSION.finditer(data))
                    tail = data[-256:]
        except OSError as exc:
            self.error(exc)
        return sorted(found)

    def report(self):
        totals = Counter()
        for record in sorted(self.records.values(), key=lambda r: r['path']):
            hints = self.hints(record['access'])
            status, explanation = assess(record['kind'], hints)
            totals[status] += 1
            print('\n' + '-' * 72)
            print(f"Path:    {record['path']}")
            print(f"Type:    {record['kind']}")
            print(f"Version: {', '.join(hints) if hints else 'Not established'}")
            print(f'Result:  {status}\nDetail:  {explanation}')
            print(f"Found:   {', '.join(sorted(record['sources']))}")
            for alias in sorted(record['aliases'] - {record['path']}):
                print(f'Alias:   {alias}')
        for pid, path in sorted(self.stale):
            print(f'\nSTALE PROCESS: PID {pid}: {path}')
            print('Restart/replace the affected process and verify its runtime.')
        print('\n' + '=' * 72)
        print(f'Distinct PHP-related ELF files found: {len(self.records)}')
        for status, count in sorted(totals.items()):
            print(f'{status}: {count}')
        print(f'Stale process mappings/executables: {len(self.stale)}')
        print(f'Scan/read errors: {sum(self.errors.values())}')
        for name, count in sorted(self.errors.items()):
            print(f'  {name}: {count}')
        print('\nVersion strings are hints; verify vendor backports and package/build provenance.')
        print('Extensions do not establish runtime patch status. No server-wide all-clear is provided.')
        print('Renamed files, inaccessible paths and isolated runtimes may be missed.')
        print('Run inside each container/chroot. Remove obsolete versions after dependency migration.')
        if totals['POTENTIALLY VULNERABLE']:
            print('\nVERDICT: Potentially vulnerable installations require action.')
            return 1
        print('\nVERDICT: Inventory finished; manual package/build verification required.')
        return 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('roots', nargs='*', default=['/'], help='Scan roots; default: /')
    parser.add_argument('--no-processes', action='store_true', help='Skip the separate /proc inspection')
    args = parser.parse_args()
    print('PHP runtime and library inventory')
    print('PHP2Shell release matrix: 22 October 2026')
    print('Read-only scan; discovered binaries are not executed.')
    print('Scanning visible storage, including mounted storage, may take time.', flush=True)
    if os.geteuid() != 0:
        print('NOTICE: Root access improves filesystem and process visibility.')
    inventory = Inventory()
    for root in args.roots:
        root = os.path.abspath(root)
        if root in SKIP or not os.path.isdir(root):
            print(f'Cannot scan root: {root}')
            inventory.errors['InvalidRoot'] += 1
        else:
            inventory.scan_filesystem(root)
    if not args.no_processes:
        inventory.scan_processes()
    return inventory.report()


if __name__ == '__main__':
    raise SystemExit(main())
