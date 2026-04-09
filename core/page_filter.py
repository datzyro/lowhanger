"""
core/page_filter.py — HTML page detection and URL filtering.

Two-stage filtering:
  1. Extension heuristic  — cheap, no network, eliminates obvious non-pages
                            (JS, CSS, images, fonts, docs, archives, etc.)
  2. Content-Type check   — for ambiguous URLs, check the actual response
                            header to confirm the server returns HTML

Used by the engine to turn a raw crawl dump into a list of actual
human-viewable HTML pages worth running multi-check scans on.
"""

import re
from urllib.parse import urlparse


# ─────────────────────────────────────────────────────────────────────────────
# Extensions that are definitively not viewable HTML pages
# ─────────────────────────────────────────────────────────────────────────────

_NOT_HTML_EXTENSIONS = {
    # Scripts / styles
    ".js", ".mjs", ".jsx", ".ts", ".tsx", ".css", ".scss", ".less", ".map",
    # Images
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp", ".tiff", ".avif",
    # Fonts
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    # Documents / data
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".json", ".xml", ".csv", ".txt", ".yaml", ".yml", ".toml",
    # Archives
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    # Media
    ".mp4", ".mp3", ".avi", ".mov", ".webm", ".ogg", ".wav", ".flac",
    # Executables / misc
    ".exe", ".dmg", ".apk", ".bin", ".dll", ".so",
    # Web assets
    ".wasm",
}

# Content-Type values that confirm an HTML response
_HTML_CONTENT_TYPES = ("text/html", "application/xhtml", "text/xhtml")

# Content-Type values that are definitely not viewable pages
_NOT_HTML_CONTENT_TYPES = (
    "application/javascript",
    "text/javascript",
    "text/css",
    "image/",
    "font/",
    "audio/",
    "video/",
    "application/pdf",
    "application/zip",
    "application/octet-stream",
    "application/json",
    "application/xml",
    "text/xml",
    "text/plain",
)


def is_likely_html_url(url: str) -> bool:
    """
    Fast heuristic: decide from the URL path alone whether this is
    likely an HTML page. Returns False for known non-HTML extensions,
    True for everything else (including paths with no extension).

    Examples:
      /about             → True   (no extension)
      /api/v1/users      → True   (no extension — may still be JSON, but we
                                   can't know without fetching; keep it)
      /static/app.js     → False
      /assets/logo.png   → False
      /page.html         → True
    """
    path = urlparse(url).path.lower().rstrip("/")
    if not path:
        return True   # root — always include

    # Extract extension
    dot = path.rfind(".")
    if dot == -1:
        return True   # no extension — assume navigable

    ext = path[dot:]   # includes the dot, e.g. ".js"
    return ext not in _NOT_HTML_EXTENSIONS


def is_html_content_type(content_type: str) -> bool:
    """
    Check a Content-Type header value to confirm HTML.
    Returns True  for text/html, application/xhtml+xml, etc.
    Returns False for JS, CSS, images, JSON, etc.
    Returns None  for ambiguous/unknown types (caller decides).
    """
    if not content_type:
        return None   # can't tell

    ct_lower = content_type.lower()

    for html_ct in _HTML_CONTENT_TYPES:
        if html_ct in ct_lower:
            return True

    for not_html in _NOT_HTML_CONTENT_TYPES:
        if ct_lower.startswith(not_html):
            return False

    return None   # ambiguous — caller may choose to include or skip


def filter_html_urls(urls: list, client, reporter=None) -> list:
    """
    Two-stage filter:
      1. Discard obvious non-HTML URLs by extension (free).
      2. For the remainder, send a HEAD request and check Content-Type.
         If HEAD fails or Content-Type is ambiguous, include the URL
         (better to over-include than silently miss a page).

    Returns a de-duplicated list of URLs that are confirmed or likely HTML.
    """
    # Stage 1: extension heuristic
    candidates = [u for u in urls if is_likely_html_url(u)]

    if reporter:
        reporter.debug("[page-filter] {}/{} URLs pass extension heuristic".format(
            len(candidates), len(urls)))

    # Stage 2: Content-Type confirmation via HEAD
    html_urls = []
    for url in candidates:
        try:
            resp = client.head(url)
            ct   = resp.headers.get("Content-Type") or resp.headers.get("content-type") or ""
            result = is_html_content_type(ct)

            if result is True:
                html_urls.append(url)
            elif result is None:
                # Ambiguous — include it (could be a framework that returns no CT)
                html_urls.append(url)
            else:
                if reporter:
                    reporter.debug("[page-filter] excluded {} (Content-Type: {})".format(url, ct))
        except Exception:
            # HEAD failed — include the URL, GET will sort it out later
            html_urls.append(url)

    if reporter:
        reporter.debug("[page-filter] {} confirmed/likely HTML page(s)".format(len(html_urls)))

    return html_urls
