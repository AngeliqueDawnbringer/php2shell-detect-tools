# PHP runtime and library inventory

Read-only Linux inventory for multiple PHP installations and PHP2Shell version evidence (CVE-2026-109618 / CVE-2026-109619). Requires Python 3.9+; no third-party packages.

## Run

```bash
sudo python3 php_inventory.py
```

The default scans the visible filesystem automatically, excluding `/proc`, `/sys` and `/dev` from traversal. Running processes and mapped PHP libraries are inspected separately through `/proc`.

Scan selected directories:

```bash
sudo python3 php_inventory.py /usr /usr/local /opt
```

Skip process inspection (useful for offline directories):

```bash
python3 php_inventory.py --no-processes /path/to/rootfs
```

Save output and capture its exit status:

```bash
sudo python3 php_inventory.py > php-inventory.txt 2>&1
result=$?
printf 'Scanner exit code: %s\n' "$result"
```

## Discovery

Finds conventional PHP CLI, CGI, FPM and lsphp executable names; Apache libphp/mod_php shared modules; shared libraries inside recognisable PHP directories; visible running PHP executables and mapped libraries; and removed/replaced PHP executables/libraries still mapped by processes. Symlinks and hard links are deduplicated by device and inode. Directory symlinks are not traversed; explicitly supply their target if it lies outside scanned roots.

It reads ELF files and searches for PHP-labelled version strings. It does not execute discovered files, change configuration, exploit applications or send network requests. Files on mounted network storage may nevertheless cause filesystem network I/O. A full scan can take time and consume I/O. Stop with Ctrl+C if needed.

## Results

| Result | Meaning |
|---|---|
| POTENTIALLY VULNERABLE | Embedded version evidence is below the upstream threshold, or identifies a legacy branch. Verify vendor backports. |
| FIXED-VERSION HINT | Embedded version evidence meets the upstream threshold. Not proof of package integrity or patch status. |
| UNKNOWN | No unique usable version, prerelease, or release outside the matrix. |
| VERIFY | Extension/library whose hosting runtime must be checked separately. |
| STALE PROCESS | Process still references a removed/replaced executable or library. Restart/replace and verify it. |

Exit code 1 means potentially vulnerable evidence was found. Exit code 2 means manual verification is required, including when no PHP was found or all version hints meet the thresholds. This scanner deliberately never issues a server-wide all-clear. Argparse usage errors also return 2.

## Release matrix

As of 22 October 2026: PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12 are upstream fixed releases. Later stable patch versions in those same branches meet the threshold. Other branches require manual verification. Vendor/source backports can fix a build without increasing its upstream version number.

Sources:
- https://www.php.net/ (security announcement dated 21 October 2026)
- https://www.php2shell.com/

## Limits and follow-up

Embedded strings are only hints; builds may omit them or contain multiple historical strings. Extension version numbers are not PHP runtime versions. Renamed binaries, unusual directory layouts, inaccessible paths, rapidly exiting processes and isolated runtimes can be missed. Scan each container/chroot separately. An offline rootfs's symlinks may resolve against the scanning host; use a properly isolated environment for authoritative runtime inventory.

The tool does not query package-manager security metadata or map every website, cron task or queue worker to its configured runtime. Confirm patch status with the package vendor/build owner and check those mappings independently. A patched CLI does not establish that FPM, CGI or Apache uses patched PHP. Merely retaining an old CLI executable does not mean it is remotely exposed through these web-request vulnerabilities.

Patching is the only complete fix. After testing and migrating dependencies, remove obsolete CLI/CGI/FPM binaries, Apache modules, services and deployment images; restart workers. Patching does not remove a pre-existing compromise.

## Examples and validation

Files in `examples/` are SIMULATED demonstrations generated from synthetic ELF-like fixtures, not actual server findings. The fixtures are not included as executable programs. Validation covered patch thresholds, mixed-version discovery, extension handling, symlink deduplication and the CLI exit code. No production-system scan was performed.
