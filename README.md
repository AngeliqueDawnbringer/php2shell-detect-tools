# PHP discovery: website crawler and Linux inventory kit

These two tools help you find PHP usage and locate PHP-related installations and files from two complementary viewpoints:

- **`php_site_audit.py`** checks websites from the outside for publicly visible PHP clues and advertised versions.
- **`php-inventory-kit.zip`** contains `php_inventory.py`, which runs on a Linux server to find PHP runtimes, modules, shared libraries and process references, including multiple installed versions.

Use them together to investigate which websites appear to use PHP, where PHP-related files exist on the server, and which installations need further verification or removal. Neither tool automatically maps every website to its runtime, guarantees complete discovery, or proves that a system is patched.

## What each tool can find

| Capability | Website crawler | Linux inventory kit |
| --- | --- | --- |
| Public PHP version headers | Yes, when exposed | Not applicable |
| PHP session-cookie names and PHP-style URLs | Yes | No |
| WordPress and selected PHP CMS clues | Yes | No |
| DNS records for specified hosts | Yes | No |
| Installed CLI, CGI, FPM and lsphp runtimes | No | Conventional file names and visible process references |
| Multiple installed PHP versions | Only versions advertised by responses | Yes, where discoverable |
| Apache PHP modules | No | Recognised `libphp`/`mod_php` ELF files |
| PHP shared libraries/extensions | No | Recognised shared files in PHP-related directories |
| Removed/replaced files still referenced by processes | No | Detects visible references marked deleted |
| Application source files such as `index.php` | May find public references, not filesystem paths | No; use the separate file search below |
| Confirmed vulnerability or patch status | No | No; reports version hints against a bundled matrix |

**A URL is not a filesystem path.** A reference to `/json/blog.php` does not reveal where that file is stored, prove that a corresponding file exists, or establish that PHP executes it. URL rewriting, proxies and static exports can obscure the implementation.

## Files

Keep the crawler alongside the extracted inventory kit:

```text
php_site_audit.py
php-inventory-kit.zip
php-inventory-kit/
    php_inventory.py
    README.md
    examples/
        multiple-versions-output.txt
        vulnerable-output.txt
```

The ZIP contains the Linux inventory tool, its original documentation and simulated output examples. The crawler is a separate download. This combined README does not modify either script.

## 1. Website crawler

### Requirements and installation

Python 3.10 or later, with `requests` and `dnspython`:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install requests dnspython
```

On Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install requests dnspython
```

Use `.\.venv\Scripts\python.exe` instead of `python` for the following examples on Windows.

### Run

```bash
python php_site_audit.py example.com www.example.com --output website-report.json
```

Include a separately hosted blog explicitly:

```bash
python php_site_audit.py example.com https://blog.example.com/blog/ \
  --max-pages 30 --max-depth 2 --output website-report.json
```

Bare hostnames use HTTPS. For an HTTP-only service, supply `http://legacy.example.com` explicitly.

For multiple hosts, create `hosts.txt` with one hostname or URL per line. Blank lines and `#` comments are accepted:

```text
example.com
www.example.com
blog.example.com
https://portal.example.com:8443/
```

```bash
python php_site_audit.py --hosts-file hosts.txt --output website-report.json
```

### Options

| Option | Default | Purpose |
| --- | --- | --- |
| `--hosts-file` | None | Read explicit targets from a file |
| `--output` | `php-audit.json` | JSON output; overwrites an existing file |
| `--max-pages` | `30` | Maximum scheduled URLs per seed, including redirects/skips; robots requests are additional |
| `--max-depth` | `2` | Link discovery depth; redirect hops also increment depth |
| `--delay` | `1.0` | Minimum seconds between request starts |
| `--timeout` | `10.0` | DNS and HTTP timeout settings; not an overall runtime deadline |
| `--max-bytes` | `1048576` | Maximum response bytes retained for inspection |

### Evidence and interpretation

The crawler queries A, AAAA, CNAME, NS and MX records for supplied hostnames. **DNS cannot identify PHP or its version.** It supplies infrastructure context; DNS errors are not proof that a domain is faulty.

The crawler inspects PHP mentions in `X-Powered-By`, `Server` and `X-Generator`; cookie names such as `PHPSESSID` and `laravel_session`; PHP-style URLs; WordPress asset paths; and selected CMS generator metadata.

| Assessment | Meaning |
| --- | --- |
| `PHP advertised` | A response header explicitly names PHP |
| `PHP indicated` | A moderate indicator, such as a session-cookie name or requested PHP-style URL, was found |
| `PHP ecosystem clues` | Only weaker clues, such as PHP links or WordPress assets, were found |
| `PHP not detected` | No recognised evidence was collected; this also occurs when crawling fails or is skipped |

Review each page's `status`, `error`, `skipped` and `truncated` fields before interpreting the summary. Advertised versions are claims made by a response, not verified installed package versions. A CMS version is not a PHP version.

### Scope and limitations

- Only explicitly listed hosts/services are crawled. Subdomains are not automatically discovered.
- Standard ports 80 and 443 share a host scope; nonstandard service ports must be listed.
- Links elsewhere on an allowed host can be followed, even when the seed starts at a specific path.
- `robots.txt` is honoured. Redirected or unsuccessful robots responses block that origin; 404/410 allows crawling.
- Query-string links and common static asset extensions are skipped. An explicit seed can include a query string.
- HTML references can provide evidence, but only anchor links populate the ordinary crawl queue.
- JavaScript is not executed, forms are not submitted and hidden diagnostic paths are not guessed.
- Cookies are cleared before each request; values are not saved in the report.
- TLS verification is enabled. Proxy settings inherited by Requests can affect the observed responses.
- Duplicate seeds can revisit the same pages; limits apply per seed.

Use within your authorised assessment scope. GET-only crawling can still trigger side effects on poorly designed endpoints.

## 2. Linux PHP inventory kit

### Requirements and extraction

Linux and Python 3.9 or later. No third-party Python packages are required.

```bash
unzip php-inventory-kit.zip
cd php-inventory-kit
```

### Scan the server

```bash
sudo python3 php_inventory.py
```

By default the script traverses the visible filesystem from `/`, excluding `/proc`, `/sys` and `/dev` from that traversal. It inspects running processes and mapped libraries separately through `/proc`.

Root access improves visibility. Full scans can produce substantial filesystem I/O, including on mounted network storage. Permission errors and inaccessible paths reduce coverage.

### Scan selected locations

```bash
sudo python3 php_inventory.py /usr /usr/local /opt /var/www
```

The roots above are examples, not an exhaustive installation list. Without `--no-processes`, process inspection remains enabled even when directory roots are restricted.

For an offline filesystem or directory-only inventory:

```bash
python3 php_inventory.py --no-processes /path/to/rootfs
```

Directory symlinks are not traversed. Explicitly include their targets when needed. Offline filesystem symlinks may resolve against the scanning host; use a properly isolated environment when authoritative results are required.

### Save results and exit status

```bash
sudo python3 php_inventory.py > php-inventory.txt 2>&1
result=$?
printf 'Inventory exit code: %s\n' "$result"
```

| Exit code | Meaning |
| --- | --- |
| `1` | Potentially vulnerable version evidence was found |
| `2` | Manual verification is required; also returned for command-line usage errors |

The inventory does not return a server-wide all-clear. Exit code 2 can occur when no PHP was found or when all discovered version hints meet the bundled thresholds. Read the output to distinguish these situations. Unhandled runtime failures can also terminate execution; do not rely on an exit code alone.

### How file discovery works

The script recognises conventional PHP runtime names, Apache PHP module names, and shared libraries inside recognisable PHP directories. It checks that candidates are ELF files, reads embedded PHP-labelled version strings and correlates visible process references. Symlinks and hard links to the same device/inode are deduplicated.

It does not execute discovered binaries, modify configuration, delete files, install patches or send application-level network requests. Reading mounted network storage may still generate filesystem network traffic.

### Result labels

| Result | Interpretation |
| --- | --- |
| `POTENTIALLY VULNERABLE` | Version evidence is below the bundled threshold or matches a legacy branch; verify the advisory and vendor backports |
| `FIXED-VERSION HINT` | Version evidence meets a bundled threshold; this does not prove patch status or integrity |
| `UNKNOWN` | No unique usable version, a prerelease, or a version outside the matrix |
| `VERIFY` | An extension/library whose owning runtime and package must be checked |
| `STALE PROCESS` | A process still references a file marked deleted; investigate, restart/replace as appropriate and verify |

The kit contains a static release matrix dated 22 October 2026. It does not retrieve current advisories or package-manager security metadata. **Validate the bundled vulnerability identifiers and thresholds against authoritative PHP and distribution/vendor advisories before relying on its classification.** This combined README documents the implementation; it does not independently validate that matrix.

Embedded strings can be missing, ambiguous or historical. Extension versions are not runtime versions. Vendor backports may fix a package without changing the upstream version number.

## 3. Finding application PHP source files

The inventory tool finds runtime and library ELF files. It does not enumerate application source files such as `index.php`, `config.php` or template files.

To locate source-file candidates in known deployment roots, run this separate command and adjust the paths to your environment:

```bash
sudo find /var/www /srv /opt -type f \
  \( -iname '*.php' -o -iname '*.php[0-9]' -o -iname '*.phtml' -o -iname '*.phps' \) \
  -print > php-source-files.txt 2> php-source-search-errors.txt
```

This lists filenames without executing or reading their contents. It does not follow directory symlinks by default. Missing paths and permission errors are recorded separately. The filename patterns can miss extensionless code, backups, unusual extensions, archives and files outside the selected roots. Files found may be unused copies rather than live application code.

## 4. Using the tools together

1. **Identify public PHP clues.** Run the crawler against the main website, blog and other explicitly selected hosts. Preserve the JSON evidence and note failed or skipped checks.
2. **Locate installations and related files.** Run the inventory on each relevant Linux host and within each container or chroot. Check CLI, CGI, FPM, Apache modules, shared libraries and running processes separately.
3. **Locate application source if needed.** Use the separate filename search against known deployment roots.
4. **Map the findings.** Review virtual-host settings, document roots, FastCGI upstreams, FPM pools, service definitions, scheduled tasks and queue workers to establish which application uses which runtime. Neither script performs this mapping automatically.
5. **Verify and remediate.** Confirm package/build provenance and applicable advisories, test the required updates, and migrate dependencies. Remove obsolete runtimes, modules, services and deployment images once they are no longer needed.
6. **Restart and recheck.** Restart affected workers/services where required, repeat the inventory and test the websites and background jobs. Check for stale process references.

A patched CLI does not prove that FPM, CGI or Apache uses the same version. Conversely, an old CLI executable on disk does not by itself establish remote web exposure. Multiple PHP versions can coexist, including unused copies left behind after upgrades.

## 5. What these tools do not establish

Neither tool proves exploitability, detects every compromise, or replaces an authenticated vulnerability assessment. A missing external version is not evidence of patching. An inventory result is not evidence that every container, namespace, inaccessible directory or unusually named binary was inspected.

Where an affected component is confirmed, install a verified fix or retire the affected component. A WAF or request-filtering workaround does not change the installed runtime's patch status. Patching also does not remove an existing compromise.

## Output handling and examples

Reports can reveal hostnames, internal paths, process IDs, software details and seed query strings. Store and share them according to your information classification requirements. Review crawler errors and inventory scan/read errors before treating either report as complete.

The inventory kit's `examples/` files are explicitly simulated demonstrations, not findings from an actual vulnerable server. The crawler's earlier dawnbringer.net and Accigo reports were live HTTP observations from their respective runs, with inconclusive DNS results in the execution environment. They are snapshots, not ongoing assurance.
