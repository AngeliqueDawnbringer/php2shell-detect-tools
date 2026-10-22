# PHP DNS and Site Crawler

A Python command-line tool for collecting DNS records and identifying publicly visible signs of PHP usage on websites. It reports advertised PHP versions where available and preserves the supporting evidence in JSON.

**This is an inventory and fingerprinting tool, not a vulnerability scanner.** A missing PHP header does not establish that PHP is absent, and an advertised version does not establish the installed package's patch status.

## Requirements

- Python 3.10 or later
- `requests` and `dnspython`
- DNS and HTTP(S) access to the hosts being checked
- `php_site_audit.py` in your working directory

## Installation

Linux or macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install requests dnspython
```

Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install requests dnspython
```

On Windows, use `.\.venv\Scripts\python.exe` instead of `python` in the examples below.

## Quick start

Check a domain and its `www` hostname:

```bash
python php_site_audit.py example.com www.example.com --output report.json
```

Bare hostnames use HTTPS. Specify the scheme for HTTP-only sites:

```bash
python php_site_audit.py http://legacy.example.com --output legacy-report.json
```

Start from a particular page:

```bash
python php_site_audit.py https://example.com/blog --max-pages 50 --max-depth 3
```

The starting path is not a scope boundary: the crawler can follow links elsewhere on an allowed host.

### Multiple hosts

Create `hosts.txt` with one hostname or URL per line:

```text
# Explicitly list every host to crawl
example.com
www.example.com
blog.example.com
https://portal.example.com:8443/
```

Then run:

```bash
python php_site_audit.py --hosts-file hosts.txt --max-pages 50 --output inventory.json
```

You can combine positional targets and `--hosts-file`. Duplicate normalised seed URLs are removed. Subdomains are not discovered automatically; list them explicitly.

## Command-line options

| Option | Default | Purpose |
| --- | --- | --- |
| `targets` | None | Zero or more hostnames or HTTP(S) URLs. At least one target is required across arguments and the hosts file. |
| `--hosts-file PATH` | None | Read targets from a text file. Blank lines and `#` comments are ignored. |
| `--output PATH` | `php-audit.json` | Write the JSON report to this file. An existing file is overwritten. The parent directory must exist. |
| `--max-pages N` | `30` | Maximum scheduled URLs per seed, including redirects and skipped URLs. Robots requests are additional. |
| `--max-depth N` | `2` | Maximum depth for discovering ordinary page links. Redirects can continue beyond this depth, within the URL budget. |
| `--delay SECONDS` | `1.0` | Minimum interval between request starts. A recognised robots crawl delay can increase this for page requests. |
| `--timeout SECONDS` | `10.0` | DNS query lifetime and HTTP connection/read timeout. Also used for a best-effort response-reading deadline. |
| `--max-bytes N` | `1048576` | Maximum response bytes retained for inspection, after HTTP content decoding. |
| `-h`, `--help` | — | Show usage information. |

Limits apply per seed where indicated. Multiple seeds can revisit the same pages. Requests are sequential. Timeout settings are not a strict overall execution deadline, especially with multiple DNS queries or slowly arriving response data.

## What the tool checks

### DNS inventory

For each explicitly supplied hostname, the tool queries:

- A and AAAA
- CNAME
- NS
- MX

The report records returned values or the DNS exception category. It does not perform zone transfers, brute-force subdomains, enumerate certificate logs or crawl DNS record targets automatically. NS and MX are queried at the supplied hostname; a subdomain may legitimately have no such records.

**DNS records cannot identify PHP usage or its version.** They provide infrastructure context only. Resolver failures must not be interpreted as evidence that a domain is unavailable or misconfigured.

### PHP fingerprints

| Evidence | Strength | Interpretation |
| --- | --- | --- |
| PHP named in `X-Powered-By`, `Server` or `X-Generator` | Strong | A response explicitly advertises PHP. A version is extracted when its format matches the detector. |
| `PHPSESSID` cookie name | Moderate | A conventional PHP session-cookie indicator. |
| `laravel_session` cookie name | Moderate | A conventional Laravel session-cookie indicator. |
| Requested URL with a PHP-style extension | Moderate | The requested URL resembles a PHP endpoint; this is not proof of execution or a successful response. |
| Same-host HTML reference to a PHP-style path | Weak | The page references a possible PHP endpoint. |
| Same-host `/wp-content/` or `/wp-includes/` reference | Weak | WordPress asset clues; these may be static or stale. |
| WordPress, Drupal, Joomla or TYPO3 generator metadata | Weak | A clue associated with a PHP-based CMS, not its PHP runtime version. |

Recognised path extensions include `.php`, numbered forms such as `.php5`, `.phtml` and `.phps`.

HTML references are inspected in `href`, `src` and `action` attributes. Only anchor links are added to the normal crawl queue; scripts and forms can provide evidence without being fetched or submitted. CMS version numbers are not treated as PHP version numbers.

The tool does not execute JavaScript, inspect local PHP installations, identify every PHP framework, guess hidden diagnostic paths or send exploit payloads.

## Crawl behaviour

- Only explicitly allowed host/service combinations are visited.
- Standard ports 80 and 443 share a host scope, allowing HTTP/HTTPS transitions. Nonstandard ports must be explicitly included.
- Cross-host redirects are followed only if the destination host/service is already in scope.
- `robots.txt` is checked separately for each origin before crawling its pages.
- A `404` or `410` robots response allows crawling. A complete successful robots response is parsed.
- Redirected, inaccessible, truncated or otherwise unsuccessful robots responses block that origin in this implementation.
- Links containing query strings are skipped. An explicitly supplied seed may contain a query string.
- Common static asset extensions are excluded from the crawl queue.
- Ordinary links are discovered only from successful HTML responses.
- Cookies are cleared before each request. Cookie names can supply evidence, but cookie values are not written to the report.
- TLS certificate verification remains enabled. There is no automatic fallback from HTTPS to HTTP.
- Requests uses its normal environment configuration, including configured proxies.

Use the tool within your authorised assessment scope. Although it sends GET requests only and does not submit forms, poorly designed GET endpoints can still change application state.

## Reading the results

The console prints a summary for each seed:

```text
https://example.com/: PHP advertised; advertised versions: 8.2.12
Report: report.json
```

This is an illustrative example, not a live finding.

The assessment is based on the strongest evidence collected:

| Assessment | Meaning |
| --- | --- |
| `PHP advertised` | At least one PHP header was observed. |
| `PHP indicated` | A moderate indicator was observed, without a stronger header indicator. |
| `PHP ecosystem clues` | Only weak indicators were observed. |
| `PHP not detected` | No recognised fingerprints were collected. This includes cases where crawling was skipped or failed. |

**Always review page-level `error`, `skipped`, `status` and `truncated` fields.** The summary alone does not distinguish a successfully inspected site without clues from a site that could not be inspected.

### JSON structure

- `timestamp_utc`: run timestamp in UTC.
- `limitations`: interpretation and coverage limitations.
- `dns`: per-host DNS results, grouped by record type.
- `sites`: results grouped by seed URL.
  - `seed`: starting URL.
  - `php_assessment`: summary assessment.
  - `advertised_versions`: distinct PHP versions extracted from headers.
  - `pages`: requested or skipped URLs and their evidence.

Each page can include its URL, depth, HTTP status, truncation flag, fingerprints, server header, redirect destination, error or skip reason. Fingerprints include a kind, strength, evidence string and, where applicable, an advertised version.

The report does not save full response bodies or cookie values. It can contain internal hostnames, paths, seed query strings and error details; handle it according to your information classification requirements.

## Example: dawnbringer.net

A run on 22 October 2026 used:

```bash
python php_site_audit.py dawnbringer.net www.dawnbringer.net \
  --max-pages 15 --timeout 8 --output dawnbringer-php-audit.json
```

Observed results:

| Check | Result |
| --- | --- |
| URLs checked on `dawnbringer.net` | 10 |
| Homepage | Referenced `/json/blog.php` |
| Blog page | Referenced `/json/search.php` |
| PHP assessment | `PHP ecosystem clues` |
| Advertised PHP version | None detected |
| PHP session-cookie indicators | None detected |
| DNS | Queries returned `NoNameservers` through the execution environment's resolver; inconclusive. |
| `www.dawnbringer.net` | Skipped because its robots response was a redirect. |
| Observed server header | `envoy`; this may describe an intermediary rather than the origin server. |

These results suggest PHP usage but do not establish the installed version, execution of the referenced endpoints or vulnerability status. They describe this particular run and may change.

## Troubleshooting

**No PHP version is reported**

The site may suppress version headers, use a proxy or CDN, expose only static pages, or use indicators the crawler does not recognise. Verify the runtime and installed packages on the server when an authoritative version inventory is required.

**DNS reports `NoNameservers` or timeouts**

Check the resolver configuration and network policy on the machine running the tool. HTTP can still work through a proxy even when direct DNS queries fail. The error does not by itself prove a domain-side DNS fault.

**The site is skipped because robots.txt redirects**

This implementation does not follow robots redirects. Supply the canonical website hostname as a target if appropriate. Listing both a bare and `www` hostname does not override the robots policy for either origin.

**A redirect destination is missing from the crawl**

Check that its hostname and service port were explicitly supplied, that it has no query string, and that the seed's URL budget was not exhausted.

**The report contains a 404 or a template placeholder URL**

The crawler follows HTML anchor references without rendering JavaScript. Unresolved template links can therefore be requested. Check status codes before interpreting URL-based evidence.

**The scan stops at a shallow depth**

Increase `--max-depth` or supply a deeper starting URL. Redirect hops increment depth and consume the URL budget, so canonical starting URLs improve coverage.

**A response is truncated**

Only the retained portion was inspected. Increase `--max-bytes` or `--timeout` if needed; truncated content can omit useful evidence.

## Validation and limitations

The initial implementation was syntax-checked and exercised using simulated responses for version extraction, PHP clues, no-signal results, robots exclusions and failures, off-scope redirects and query exclusions. It was also run against dawnbringer.net as described above.

Fingerprinting cannot confirm server-side execution, installed packages, vendor backports, patch status, or all PHP runtimes used behind load balancers. Headers can be altered or spoofed, assets can be stale, and intermediaries can obscure the origin. Use authenticated server-side inventory and relevant vendor advisories for patch verification.
