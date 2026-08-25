from __future__ import annotations
import re
from urllib.parse import urljoin, urlparse, parse_qsl
from typing import Iterable

API_PATTERNS = [
    re.compile(r"[\"'](/(?:api|rest|v\d+|graphql)(?:/[A-Za-z0-9_./:-]*)?)[\"']", re.I),
    re.compile(r"[\"']((?:https?:)?//[^\"']+/(?:api|rest|graphql)/[^\"']*)[\"']", re.I),
]
TECH_PATTERNS = {
    "Next.js": re.compile(r"(?:__NEXT_DATA__|/_next/static/)", re.I),
    "React": re.compile(r"(?:data-reactroot|react-dom|react\.production)", re.I),
    "Angular": re.compile(r"(?:ng-version|angular(?:\.min)?\.js)", re.I),
    "Vue": re.compile(r"(?:data-v-[0-9a-f]+|vue(?:\.runtime)?\.min\.js)", re.I),
    "jQuery": re.compile(r"jquery(?:[-.][0-9.]+)?(?:\.min)?\.js", re.I),
    "Bootstrap": re.compile(r"bootstrap(?:[-.][0-9.]+)?(?:\.min)?\.(?:js|css)", re.I),
}

def discover_parameters(url: str, body: str) -> list[dict[str, str]]:
    result: dict[tuple[str, str], dict[str, str]] = {}
    for name, _ in parse_qsl(urlparse(url).query, keep_blank_values=True):
        result[(name, "query")] = {"name": name, "location": "query", "source": url}
    for form in re.findall(r"<form\b([^>]*)>(.*?)</form>", body or "", re.I | re.S):
        attrs, content = form
        method = re.search(r"\bmethod\s*=\s*[\"']([^\"']+)", attrs, re.I)
        for name in re.findall(r"\bname\s*=\s*[\"']([^\"']+)[\"']", content, re.I):
            result[(name, "form")] = {"name": name, "location": "form", "method": (method.group(1).upper() if method else "GET"), "source": url}
    return sorted(result.values(), key=lambda x: (x["location"], x["name"]))

def discover_api_routes(base_url: str, body: str) -> set[str]:
    out: set[str] = set()
    for pattern in API_PATTERNS:
        for raw in pattern.findall(body or ""):
            candidate = urljoin(base_url, raw)
            if urlparse(candidate).netloc == urlparse(base_url).netloc:
                out.add(candidate)
    return out

def fingerprint_technologies(url: str, headers: dict[str, str], body: str) -> list[dict[str, str]]:
    text = "\n".join([body[:100000], str(headers)])
    result = []
    for name, pattern in TECH_PATTERNS.items():
        if pattern.search(text):
            result.append({"name": name, "evidence": pattern.pattern, "url": url})
    server = headers.get("server") or headers.get("Server")
    if server:
        result.append({"name": "Server", "evidence": server, "url": url})
    return result


def discover_security_artifacts(seed: str, body: str) -> set[str]:
    base = f"{urlparse(seed).scheme}://{urlparse(seed).netloc}"
    paths = {"/robots.txt", "/sitemap.xml", "/.well-known/security.txt"}
    links = {urljoin(base, p) for p in paths}
    for ref in re.findall(r"(?:href|src)\s*=\s*[\"']([^\"']+)[\"']", body or "", re.I):
        if any(token in ref.lower() for token in ("swagger", "openapi", "graphql", ".map")):
            links.add(urljoin(seed, ref))
    return links
