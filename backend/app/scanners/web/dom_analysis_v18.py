from __future__ import annotations
import re
from dataclasses import dataclass, asdict

@dataclass(frozen=True)
class DOMFlow:
    source: str
    sink: str
    evidence: str
    confidence: str = "MEDIUM"

SOURCE_PATTERNS = {
    "location.search": r"\blocation\.search\b",
    "location.hash": r"\blocation\.hash\b",
    "location.href": r"\blocation\.href\b",
    "document.referrer": r"\bdocument\.referrer\b",
    "postMessage": r"\b(?:window\.)?addEventListener\s*\(\s*['\"]message['\"]",
    "URLSearchParams": r"\bURLSearchParams\b",
}
SINK_PATTERNS = {
    "innerHTML": r"\.innerHTML\s*=",
    "outerHTML": r"\.outerHTML\s*=",
    "insertAdjacentHTML": r"\.insertAdjacentHTML\s*\(",
    "document.write": r"\bdocument\.write\s*\(",
    "eval": r"\beval\s*\(",
    "setTimeout-string": r"\bsetTimeout\s*\(\s*['\"]",
    "setInterval-string": r"\bsetInterval\s*\(\s*['\"]",
}

def analyze_dom_dataflow(source: str) -> list[DOMFlow]:
    """Static source/sink heuristic; it does not execute JavaScript or claim exploitability."""
    flows: list[DOMFlow] = []
    for src_name, src_pat in SOURCE_PATTERNS.items():
        sm = re.search(src_pat, source, re.I)
        if not sm:
            continue
        window = source[max(0, sm.start()-500): min(len(source), sm.end()+2500)]
        for sink_name, sink_pat in SINK_PATTERNS.items():
            km = re.search(sink_pat, window, re.I)
            if km:
                evidence = f"{src_name} near {sink_name}"
                flows.append(DOMFlow(src_name, sink_name, evidence, "MEDIUM"))
    return flows

def serialize_flows(source: str) -> list[dict]:
    return [asdict(x) for x in analyze_dom_dataflow(source)]
