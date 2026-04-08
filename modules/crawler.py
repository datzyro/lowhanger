"""
core/crawler.py — Endpoint crawler abstraction.

Wraps katana (preferred) with a fallback to a lightweight built-in
link-extractor so the tool works even without katana installed.

Katana options used:
  -u <url>          : target
  -d <depth>        : crawl depth (default 3)
  -jc               : include JS-discovered URLs
  -kf all           : include known files
  -silent           : no banner
  -o <file>         : write URLs one per line
  -timeout <n>      : per-request timeout
  -rl <n>           : rate limit (req/sec)
  -proxy <url>      : optional proxy
"""

import os
import re
import shutil
import subprocess
import tempfile
import urllib.parse
from collections import deque

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def crawl(target, depth=3, timeout=10, rate_limit=50,
          proxy=None, verbose=False, max_urls=500) -> list:
    """
    Crawl the target and return a de-duplicated list of URL strings.

    Tries katana first; falls back to built-in BFS crawler.
    """
    if shutil.which("katana"):
        return _crawl_katana(target, depth, timeout, rate_limit, proxy, verbose, max_urls)
    else:
        if verbose:
            print("[~] katana not found — using built-in crawler (install katana for better coverage)")
        return _crawl_builtin(target, depth, timeout, proxy, max_urls)


# ─────────────────────────────────────────────────────────────────────────────
# katana wrapper
# ─────────────────────────────────────────────────────────────────────────────

def _crawl_katana(target, depth, timeout, rate_limit, proxy, verbose, max_urls) -> list:
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    tmp.close()

    cmd = [
        "katana",
        "-u",       str(target),
        "-d",       str(depth),
        "-jc",                      # JS crawl
        "-kf",      "all",          # known files
        "-silent",
        "-o",       tmp.name,
        "-timeout", str(timeout),
        "-rl",      str(rate_limit),
        "-no-color",
    ]
    if proxy:
        cmd += ["-proxy", proxy]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if verbose and result.stderr:
            print("[katana stderr]", result.stderr[:300])
    except subprocess.TimeoutExpired:
        print("[!] katana timed out")
    except Exception as e:
        print("[!] katana error: {}".format(e))
    finally:
        urls = _read_url_file(tmp.name, max_urls)
        try:
            os.unlink(tmp.name)
        except Exception:
            pass

    # Always include the root target itself
    root = str(target)
    if root not in urls:
        urls.insert(0, root)

    return urls


# ─────────────────────────────────────────────────────────────────────────────
# Built-in BFS link extractor (fallback)
# ─────────────────────────────────────────────────────────────────────────────

_HREF_RE  = re.compile(r'href=["\']([^"\'>\s]+)', re.IGNORECASE)
_SRC_RE   = re.compile(r'src=["\']([^"\'>\s]+)',  re.IGNORECASE)
_ACTION_RE= re.compile(r'action=["\']([^"\'>\s]+)', re.IGNORECASE)

def _crawl_builtin(target, depth, timeout, proxy, max_urls) -> list:
    base_url  = str(target)
    parsed    = urllib.parse.urlparse(base_url)
    base_host = parsed.netloc

    proxies = {"http": proxy, "https": proxy} if proxy else {}
    session = requests.Session()
    session.verify  = False
    session.proxies = proxies
    session.headers["User-Agent"] = (
        "Mozilla/5.0 (compatible; lowhanger-crawler/1.0)"
    )

    visited  = set()
    found    = []
    queue    = deque([(base_url, 0)])

    while queue and len(found) < max_urls:
        url, current_depth = queue.popleft()

        # Normalise
        url = url.rstrip("/") or url
        if url in visited:
            continue
        visited.add(url)

        # Only follow same-host URLs
        p = urllib.parse.urlparse(url)
        if p.netloc and p.netloc != base_host:
            continue

        found.append(url)

        if current_depth >= depth:
            continue

        try:
            resp = session.get(url, timeout=timeout, allow_redirects=True)
            ct   = resp.headers.get("Content-Type", "")
            if "html" not in ct:
                continue
            body = resp.text
        except Exception:
            continue

        for pattern in (_HREF_RE, _SRC_RE, _ACTION_RE):
            for href in pattern.findall(body):
                href = href.strip()
                if href.startswith(("javascript:", "mailto:", "#", "data:")):
                    continue
                resolved = urllib.parse.urljoin(url, href)
                resolved = resolved.split("#")[0].rstrip("/")
                if resolved and resolved not in visited:
                    queue.append((resolved, current_depth + 1))

    return found


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _read_url_file(path: str, max_urls: int) -> list:
    urls = []
    try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if line and line.startswith("http") and len(urls) < max_urls:
                    urls.append(line)
    except Exception:
        pass
    return urls
