from __future__ import annotations
import re

OWASP_WEB = {
    "A01:2025": "Broken Access Control",
    "A02:2025": "Security Misconfiguration",
    "A03:2025": "Software Supply Chain Failures",
    "A04:2025": "Cryptographic Failures",
    "A05:2025": "Injection",
    "A06:2025": "Insecure Design",
    "A07:2025": "Authentication Failures",
    "A08:2025": "Software or Data Integrity Failures",
    "A09:2025": "Security Logging & Alerting Failures",
    "A10:2025": "Mishandling of Exceptional Conditions",
}
OWASP_API = {
    "API1:2023": "Broken Object Level Authorization",
    "API2:2023": "Broken Authentication",
    "API3:2023": "Broken Object Property Level Authorization",
    "API4:2023": "Unrestricted Resource Consumption",
    "API5:2023": "Broken Function Level Authorization",
    "API6:2023": "Unrestricted Access to Sensitive Business Flows",
    "API7:2023": "Server Side Request Forgery",
    "API8:2023": "Security Misconfiguration",
    "API9:2023": "Improper Inventory Management",
    "API10:2023": "Unsafe Consumption of APIs",
}
OWASP_LLM = {
    "LLM01:2025": "Prompt Injection",
    "LLM02:2025": "Sensitive Information Disclosure",
    "LLM03:2025": "Supply Chain",
    "LLM04:2025": "Data and Model Poisoning",
    "LLM05:2025": "Improper Output Handling",
    "LLM06:2025": "Excessive Agency",
    "LLM07:2025": "System Prompt Leakage",
    "LLM08:2025": "Vector and Embedding Weaknesses",
    "LLM09:2025": "Misinformation",
    "LLM10:2025": "Unbounded Consumption",
}

SEV_SCORE = {"critical": "9.3", "high": "8.1", "medium": "6.4", "low": "3.1", "info": "0.0"}

# These are deterministic fallback scores used only when a scanner did not provide a CVSS v4 vector.
# They are labeled severity-normalized in cvss_source and should not be represented as an official FIRST calculation.


CWE_MAP = [
    (("csp", "unsafe-inline", "unsafe-eval", "content-security-policy"), "CWE-693"),
    (("open api", "swagger", "api inventory", "shadow api"), "CWE-16"),
    (("graphql introspection", "graphql complexity", "graphql batching"), "CWE-770"),
    (("soap", "xml security"), "CWE-611"),
    (("grpc reflection", "grpc tls"), "CWE-16"),
    (("rate limit", "unrestricted resource", "resource consumption"), "CWE-770"),
    (("mass assignment", "property level", "bopla"), "CWE-915"),
    (("function level", "bfla", "privilege escalation"), "CWE-862"),
    (("prompt injection", "instruction override"), "CWE-74"),
    (("system prompt", "prompt leakage"), "CWE-200"),
    (("vector", "embedding", "retrieval"), "CWE-639"),
    (("tool abuse", "excessive agency", "agent permission"), "CWE-269"),
    (("mcp", "model context protocol"), "CWE-269"),
    (("dependency confusion",), "CWE-427"),
    (("typosquat", "typosquatting"), "CWE-829"),
    (("sql injection", "sqli"), "CWE-89"),
    (("xss", "cross-site scripting", "dom xss"), "CWE-79"),
    (("ssrf",), "CWE-918"),
    (("path traversal", "directory traversal"), "CWE-22"),
    (("command injection", "os command"), "CWE-78"),
    (("xxe", "xml external entity"), "CWE-611"),
    (("ssti", "template injection"), "CWE-1336"),
    (("csrf",), "CWE-352"),
    (("open redirect",), "CWE-601"),
    (("idor", "bola", "broken object level authorization"), "CWE-639"),
    (("broken authentication", "authentication failure"), "CWE-287"),
    (("session fixation",), "CWE-384"),
    (("frame-ancestors", "clickjacking"), "CWE-1021"),
    (("jwt", "token"), "CWE-347"),
    (("cors",), "CWE-942"),
    (("security header", "csp", "misconfiguration"), "CWE-16"),
    (("sensitive information", "information disclosure", "leak"), "CWE-200"),
    (("prompt injection",), "CWE-74"),
    (("excessive agency", "tool permission", "agent"), "CWE-269"),
    (("dependency", "supply chain", "package"), "CWE-1104"),
]

def infer_cwe(title: str, category: str, scanner_family: str) -> str:
    text = f"{title} {category}".lower()
    for keywords, cwe in CWE_MAP:
        if any(k in text for k in keywords):
            return cwe
    return {"api":"CWE-862","ai":"CWE-74","rag":"CWE-200","agent":"CWE-269","mcp":"CWE-269","sca":"CWE-1104"}.get(scanner_family, "CWE-16")

def normalized_cvss(severity: str) -> tuple[str,str]:
    score = SEV_SCORE.get(severity.lower(), "0.0")
    return score, "severity-normalized"


def _text(item: dict) -> str:
    return " ".join(str(item.get(k, "")) for k in ("title", "category", "finding_key", "description")).lower()


def infer_owasp(category: str, title: str, scanner_family: str = "web") -> str:
    text = f"{category} {title}".lower()
    if scanner_family == "api":
        if any(x in text for x in ("bola", "idor", "object level")): return "API1:2023 - Broken Object Level Authorization"
        if "authentication" in text or "auth" in text: return "API2:2023 - Broken Authentication"
        if "property" in text or "mass assignment" in text: return "API3:2023 - Broken Object Property Level Authorization"
        if any(x in text for x in ("rate", "resource", "dos", "consumption")): return "API4:2023 - Unrestricted Resource Consumption"
        if any(x in text for x in ("function level", "bfl", "privilege")): return "API5:2023 - Broken Function Level Authorization"
        if "business flow" in text: return "API6:2023 - Unrestricted Access to Sensitive Business Flows"
        if "ssrf" in text: return "API7:2023 - Server Side Request Forgery"
        if any(x in text for x in ("misconfiguration", "cors", "graphql introspection", "reflection")): return "API8:2023 - Security Misconfiguration"
        if any(x in text for x in ("inventory", "shadow api", "deprecated")): return "API9:2023 - Improper Inventory Management"
        return "API10:2023 - Unsafe Consumption of APIs"
    if scanner_family in {"ai", "rag", "agent", "mcp"}:
        if "prompt injection" in text or "instruction" in text: return "LLM01:2025 - Prompt Injection"
        if any(x in text for x in ("sensitive", "leak", "secret", "pii")): return "LLM02:2025 - Sensitive Information Disclosure"
        if "supply" in text or "dependency" in text: return "LLM03:2025 - Supply Chain"
        if "poison" in text or "data poisoning" in text: return "LLM04:2025 - Data and Model Poisoning"
        if "output" in text or "unsafe html" in text: return "LLM05:2025 - Improper Output Handling"
        if any(x in text for x in ("agency", "tool", "permission", "privilege")): return "LLM06:2025 - Excessive Agency"
        if "system prompt" in text or "instruction leakage" in text: return "LLM07:2025 - System Prompt Leakage"
        if any(x in text for x in ("vector", "embedding", "retrieval")): return "LLM08:2025 - Vector and Embedding Weaknesses"
        if "misinformation" in text or "hallucination" in text: return "LLM09:2025 - Misinformation"
        return "LLM10:2025 - Unbounded Consumption"
    if any(x in text for x in ("access control", "idor", "authorization", "privilege")): return "A01:2025 - Broken Access Control"
    if any(x in text for x in ("configuration", "header", "cors", "cookie", "debug", "directory", "csp", "frame-ancestors", "security policy", "missing security control")): return "A02:2025 - Security Misconfiguration"
    if any(x in text for x in ("dependency", "supply chain", "package", "library", "sbom")): return "A03:2025 - Software Supply Chain Failures"
    if any(x in text for x in ("crypto", "tls", "hash", "cipher")): return "A04:2025 - Cryptographic Failures"
    if any(x in text for x in ("xss", "sql", "injection", "ssrf", "ssti", "xxe", "command", "xpath", "ldap", "crlf")): return "A05:2025 - Injection"
    if any(x in text for x in ("design", "workflow", "business logic")): return "A06:2025 - Insecure Design"
    if any(x in text for x in ("auth", "session", "mfa", "password", "jwt", "token")): return "A07:2025 - Authentication Failures"
    if any(x in text for x in ("integrity", "deserialize", "tamper", "unsigned", "signature")): return "A08:2025 - Software or Data Integrity Failures"
    if any(x in text for x in ("logging", "alert", "audit")): return "A09:2025 - Security Logging & Alerting Failures"
    return "A10:2025 - Mishandling of Exceptional Conditions"


def normalize_finding(item: dict, scanner_family: str, endpoint: str | None = None) -> dict:
    severity = str(item.get("severity", "info")).lower()
    if severity not in SEV_SCORE: severity = "info"
    cvss_source = "provided" if (item.get("cvss_v4") or item.get("cvss")) else "severity-normalized"
    cvss = str(item.get("cvss_v4") or item.get("cvss") or SEV_SCORE[severity])
    if cvss == "-" or not cvss:
        cvss = SEV_SCORE[severity]
    owasp = item.get("owasp_mapping") or item.get("owasp") or infer_owasp(item.get("category", scanner_family), item.get("title", ""), scanner_family)
    if isinstance(owasp, (list, tuple)): owasp = ", ".join(map(str, owasp))
    framework = item.get("framework_mapping") or ({"api":"OWASP API Security Top 10 2023","web":"OWASP Top 10 2025","ai":"OWASP Top 10 for LLM Applications 2025","rag":"OWASP GenAI / LLM + RAG","agent":"OWASP Agentic Security","mcp":"OWASP MCP Security","sca":"OWASP A03:2025 + CWE/CVE"}.get(scanner_family, "OWASP"))
    cwe = item.get("cwe") or item.get("cwe_id") or infer_cwe(item.get("title", ""), item.get("category", ""), scanner_family)
    if isinstance(cwe, (list, tuple)): cwe = ", ".join(map(str, cwe))
    evidence = dict(item.get("evidence") if isinstance(item.get("evidence"), dict) else {})
    refs = item.get("references") or evidence.get("references") or ["https://www.first.org/cvss/calculator/4.0", "https://owasp.org/Top10/2025/"]
    cve = item.get("cve") or evidence.get("cve") or evidence.get("cve_id")
    from urllib.parse import quote_plus
    if cve:
        cve_text = str(cve).strip()
        refs = list(dict.fromkeys(list(refs) + [f"https://nvd.nist.gov/vuln/detail/{cve_text}"]))
    else:
        refs = list(dict.fromkeys(list(refs) + [f"https://nvd.nist.gov/vuln/search/results?query={quote_plus(str(item.get('title',''))[:120])}"]))
    if scanner_family == "api": refs = list(dict.fromkeys(list(refs)+["https://owasp.org/API-Security/"]))
    if scanner_family in {"ai","rag","agent","mcp"}: refs = list(dict.fromkeys(list(refs)+["https://genai.owasp.org/llm-top-10/","https://genai.owasp.org/initiatives/top-10-for-llm-and-genai/","https://avidml.org/database/"]))
    evidence.setdefault("references", refs)
    return {
        **item,
        "severity": severity,
        "cvss_v4": cvss,
        "owasp_mapping": str(owasp),
        "framework_mapping": str(framework),
        "cwe": str(cwe),
        "endpoint": item.get("endpoint") or endpoint,
        "risk_reason": item.get("risk_reason") or f"Classified as {severity.upper()} based on the scanner evidence and current risk taxonomy.",
        "evidence": evidence,
        "affected_parameter": item.get("affected_parameter") or evidence.get("parameter") or evidence.get("affected_parameter") or "-",
        "affected_component": item.get("affected_component") or evidence.get("component") or evidence.get("affected_component") or item.get("category") or "-",
        "test_payload": item.get("test_payload") or evidence.get("payload") or evidence.get("test_payload") or "Not captured (passive analysis)",
        "http_request": item.get("http_request") or evidence.get("request") or evidence.get("http_request") or "Not captured (passive analysis)",
        "http_response": item.get("http_response") or evidence.get("response") or evidence.get("http_response") or "Not captured (passive analysis)",
        "screenshot": item.get("screenshot") or evidence.get("screenshot"),
        "references": refs,
        "cve_id": str(cve) if cve else None,
        "cvss_source": cvss_source,
        "cvss_vector_v4": item.get("cvss_vector_v4") or None,
    }
