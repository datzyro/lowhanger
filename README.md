# 🍑 lowhanger

Template-based low-hanging fruit vulnerability scanner for pentesters.

## Quick start

```bash
pip install -r requirements.txt

# Full scan — all modules
python lowhanger.py -t https://example.com

# Specific modules only
python lowhanger.py -t https://example.com --templates security-headers clickjacking

# Multiple targets from file
python lowhanger.py -l targets.txt --templates all -o results.json --format json

# Through Burp proxy + OOB canary for host-header module
python lowhanger.py -t https://example.com \
  --proxy http://127.0.0.1:8080 \
  --canary your.interactsh.url

# Override crawl depth across all modules
python lowhanger.py -t https://example.com --crawl-depth 5

# Authenticated scan with headers
python lowhanger.py -t https://example.com \
  --header "Authorization: Bearer <token>" \
  --header "Cookie: sessionid=<value>"

# Load headers from file (one Name: Value per line)
python lowhanger.py -t https://example.com --header-file headers.txt
```

## Templates

| ID | Checks | External tool |
|----|--------|---------------|
| `ssl-check` | Deprecated TLS versions, weak ciphers, known vulns (POODLE, BEAST, etc.) | testssl.sh (fallback: Python ssl) |
| `http-redirect` | HTTP→HTTPS enforcement, HSTS presence, max-age, includeSubDomains | — |
| `security-headers` | 8 security headers across ALL crawled endpoints; worst-offender ranking | katana (fallback: built-in BFS) |
| `clickjacking` | XFO + CSP frame-ancestors; detects ALLOW-FROM deprecation gap | katana (fallback: built-in BFS) |
| `host-header-redirect` | 12 injection techniques including custom HTTP→HTTPS redirect abuse | — |

## External tools (optional)

Both tools are auto-detected from `$PATH`. If absent, graceful fallbacks are used.

```bash
# katana (endpoint crawler)
go install github.com/projectdiscovery/katana/cmd/katana@latest

# testssl.sh (TLS scanner)
git clone https://github.com/drwetter/testssl.sh
# add testssl.sh to PATH or set testssl_path in templates/ssl-check.yaml

ln -s ~/testssl.sh/testssl.sh /usr/local/bin/testssl.sh 

# Install playwright and chromium for better Clickjacking check
pip install playwright
playwright install chromium
```

## Adding a new module

1. Create `templates/my-check.yaml` with `id`, `name`, `severity`, `module`, `remediation`
2. Create `modules/my_check.py` with a class matching `module:` that extends `BaseModule`
3. Implement `run(target, client, reporter)` — emit findings via `reporter.add_finding(Finding(...))`
4. Done. No engine changes needed.

## Architecture

```
lowhanger/
├── lowhanger.py              CLI entry point
├── core/
│   ├── engine.py             Template loader + scan orchestrator
│   ├── crawler.py            Katana wrapper + built-in BFS fallback
│   ├── http_client.py        Shared HTTP client (no SSL verify, manual redirect)
│   ├── target.py             Target normalization
│   └── reporter.py           Coloured terminal + JSON/plain output
├── modules/
│   ├── base.py               BaseModule ABC
│   ├── security_headers.py   Missing headers across crawled endpoints
│   ├── clickjacking.py       XFO + CSP frame-ancestors analysis
│   ├── http_redirect.py      HTTPS enforcement + HSTS quality
│   ├── ssl_check.py          testssl.sh wrapper + Python fallback
│   └── host_header_redirect.py  12-technique host header injection
└── templates/
    ├── security-headers.yaml
    ├── clickjacking.yaml
    ├── http-redirect.yaml
    ├── ssl-check.yaml
    └── host-header-redirect.yaml
```
