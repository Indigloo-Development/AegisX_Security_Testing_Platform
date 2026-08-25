from __future__ import annotations

from html.parser import HTMLParser
from typing import Iterable
from urllib.parse import urljoin, urlparse, urldefrag
import re


class LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.urls: set[str] = set()
        self.forms: list[dict] = []
        self.scripts: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = dict(attrs)
        if tag in {"a", "link", "area"} and data.get("href"):
            self.urls.add(data["href"] or "")
        elif tag in {"script"} and data.get("src"):
            self.scripts.add(data["src"] or "")
        elif tag == "form":
            self.forms.append({"action": data.get("action", ""), "method": data.get("method", "GET").upper(), "inputs": []})
        elif tag == "input" and self.forms:
            current = self.forms[-1]
            current.setdefault("inputs", []).append({"name": data.get("name", ""), "type": data.get("type", "text")})


def extract_discovery(base_url: str, html: str) -> tuple[set[str], list[dict], set[str]]:
    parser = LinkParser()
    parser.feed(html)
    host = urlparse(base_url).netloc
    urls: set[str] = set()
    for raw in parser.urls:
        absolute = urldefrag(urljoin(base_url, raw))[0]
        if urlparse(absolute).netloc == host:
            urls.add(absolute)
    scripts = {urldefrag(urljoin(base_url, src))[0] for src in parser.scripts}
    forms = []
    for form in parser.forms:
        forms.append({**form, "action": urldefrag(urljoin(base_url, form["action"] or base_url))[0]})
    # Lightweight endpoint discovery from JS bundles and inline scripts.
    js_routes = set(re.findall(r"(?:fetch|axios\.(?:get|post|put|patch|delete)|XMLHttpRequest).*?[\(\'\"]([^\'\") ]{1,300})", html, re.I))
    for route in js_routes:
        absolute = urldefrag(urljoin(base_url, route))[0]
        if urlparse(absolute).netloc == host:
            urls.add(absolute)
    return urls, forms, scripts


def same_origin(seed: str, urls: Iterable[str]) -> list[str]:
    origin = urlparse(seed).netloc
    return [u for u in urls if urlparse(u).netloc == origin]
