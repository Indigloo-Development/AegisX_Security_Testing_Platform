from __future__ import annotations
from .models import RuleDefinition

RULES = [
    RuleDefinition("WEB-CSP-001", "Content Security Policy missing", "Security Headers", "medium", ("A02:2025",), ("CWE-693",), "No Content-Security-Policy enforcement header was observed.", "Define and enforce a restrictive CSP appropriate to the application."),
    RuleDefinition("WEB-CSP-002", "CSP allows unsafe-inline", "Security Headers", "high", ("A02:2025", "A05:2025"), ("CWE-79",), "The effective CSP permits inline script/style behavior that weakens injection defenses.", "Replace unsafe-inline with nonces or hashes where practical."),
    RuleDefinition("WEB-CSP-003", "CSP allows unsafe-eval", "Security Headers", "high", ("A02:2025", "A05:2025"), ("CWE-95",), "The CSP permits string-to-code evaluation patterns.", "Remove unsafe-eval and refactor code that relies on dynamic evaluation."),
    RuleDefinition("WEB-CSP-004", "CSP contains broad wildcard source", "Security Headers", "medium", ("A02:2025",), ("CWE-693",), "A broad wildcard source was observed in a high-impact directive.", "Limit source expressions to the smallest trusted set."),
    RuleDefinition("WEB-HDR-001", "HSTS missing on HTTPS response", "Security Headers", "medium", ("A02:2025", "A04:2025"), ("CWE-319",), "An HTTPS response did not advertise HSTS.", "Enable HSTS after confirming certificate and subdomain readiness."),
    RuleDefinition("WEB-HDR-002", "X-Content-Type-Options missing", "Security Headers", "low", ("A02:2025",), ("CWE-693",), "MIME sniffing protection was not observed.", "Set X-Content-Type-Options: nosniff."),
    RuleDefinition("WEB-HDR-003", "Referrer-Policy missing", "Security Headers", "low", ("A02:2025",), ("CWE-200",), "No explicit referrer policy was observed.", "Set an explicit restrictive Referrer-Policy."),
    RuleDefinition("WEB-HDR-004", "Permissions-Policy missing", "Security Headers", "low", ("A02:2025",), ("CWE-693",), "No Permissions-Policy was observed.", "Restrict browser capabilities not required by the application."),
    RuleDefinition("WEB-HDR-005", "COOP/COEP/CORP protections incomplete", "Security Headers", "low", ("A02:2025",), ("CWE-693",), "Modern browser isolation headers were not comprehensively configured.", "Evaluate Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy and Cross-Origin-Resource-Policy for the application."),
    RuleDefinition("WEB-CLICKJACK-001", "Clickjacking protection missing", "Security Headers", "medium", ("A02:2025",), ("CWE-1021",), "Neither X-Frame-Options nor CSP frame-ancestors was observed.", "Use CSP frame-ancestors and/or X-Frame-Options as appropriate."),
    RuleDefinition("WEB-CORS-001", "Wildcard CORS origin", "Cross-Origin Policy", "medium", ("A02:2025",), ("CWE-942",), "Access-Control-Allow-Origin is wildcarded.", "Allow only trusted origins required by the application."),
    RuleDefinition("WEB-CORS-002", "CORS credential/wildcard conflict", "Cross-Origin Policy", "high", ("A01:2025", "A02:2025"), ("CWE-942",), "Credentials are advertised together with an overly broad origin policy.", "Restrict allowed origins and only enable credentials where necessary."),
    RuleDefinition("WEB-COOKIE-001", "Session cookie missing Secure", "Cookie Security", "medium", ("A02:2025", "A07:2025"), ("CWE-614",), "A session-like cookie was observed without Secure.", "Set Secure on session cookies served over HTTPS."),
    RuleDefinition("WEB-COOKIE-002", "Session cookie missing HttpOnly", "Cookie Security", "medium", ("A07:2025",), ("CWE-1004",), "A session-like cookie was observed without HttpOnly.", "Set HttpOnly on server-managed session cookies."),
    RuleDefinition("WEB-COOKIE-003", "Session cookie has weak SameSite", "Cookie Security", "medium", ("A01:2025", "A07:2025"), ("CWE-352",), "A session-like cookie does not provide an explicit protective SameSite policy.", "Use SameSite=Lax or Strict unless cross-site behavior is required."),
    RuleDefinition("WEB-COOKIE-004", "Cookie missing explicit Path", "Cookie Security", "low", ("A02:2025",), ("CWE-16",), "Cookie scope was not explicitly constrained by Path.", "Set the narrowest Path needed."),
    RuleDefinition("WEB-CACHE-001", "Sensitive response lacks restrictive cache controls", "Data Protection", "medium", ("A02:2025", "A04:2025"), ("CWE-525",), "A response appears sensitive but does not expose restrictive cache controls.", "Use Cache-Control directives appropriate to sensitive responses."),
    RuleDefinition("WEB-ERROR-001", "Verbose server error disclosure", "Error Handling", "medium", ("A10:2025",), ("CWE-209",), "The response contains a stack-trace or framework error pattern.", "Return generic errors while logging diagnostic detail securely server-side."),
    RuleDefinition("WEB-ERROR-002", "Debug mode indicator", "Error Handling", "high", ("A02:2025", "A10:2025"), ("CWE-489",), "The response contains indicators of enabled debug tooling.", "Disable debug mode and developer diagnostics in production."),
    RuleDefinition("WEB-INFO-001", "Server technology disclosure", "Information Disclosure", "info", ("A02:2025",), ("CWE-200",), "Server banner exposes implementation information.", "Minimize unnecessary banner disclosure."),
    RuleDefinition("WEB-INFO-002", "X-Powered-By disclosure", "Information Disclosure", "low", ("A02:2025",), ("CWE-200",), "X-Powered-By reveals framework information.", "Remove or minimize X-Powered-By in production."),
    RuleDefinition("WEB-TRANSPORT-001", "Mixed-content reference", "Transport Security", "medium", ("A04:2025",), ("CWE-319",), "An HTTPS document references an HTTP resource.", "Serve all active and sensitive resources over HTTPS."),
    RuleDefinition("WEB-TRANSPORT-002", "Password form submits over HTTP", "Transport Security", "high", ("A07:2025", "A04:2025"), ("CWE-319",), "A password-bearing form points to an HTTP endpoint.", "Submit credentials only over HTTPS."),
    RuleDefinition("WEB-APP-001", "Source map exposed", "Information Disclosure", "low", ("A02:2025",), ("CWE-200",), "A JavaScript source map reference was detected.", "Avoid publishing source maps where they disclose sensitive implementation detail."),
    RuleDefinition("WEB-APP-002", "Directory listing indicator", "Security Misconfiguration", "medium", ("A02:2025",), ("CWE-548",), "The response resembles an auto-generated directory index.", "Disable directory indexing where not explicitly required."),
    RuleDefinition("WEB-APP-003", "Security.txt missing", "Security Operations", "info", ("A09:2025",), ("CWE-16",), "No security.txt file was observed at the conventional location.", "Publish a security.txt contact and policy if appropriate."),
    RuleDefinition("WEB-APP-004", "Robots exposes sensitive path hints", "Information Disclosure", "low", ("A02:2025",), ("CWE-200",), "robots.txt contains paths that look operationally sensitive.", "Do not rely on robots.txt for access control; avoid exposing sensitive route hints unnecessarily."),
    RuleDefinition("WEB-API-001", "Potential undocumented JSON API endpoint", "Attack Surface", "info", ("A02:2025",), ("CWE-16",), "A JavaScript bundle contains an API-like route.", "Inventory and authorize API endpoints; remove unused routes."),
    RuleDefinition("WEB-API-002", "Potential GraphQL endpoint reference", "Attack Surface", "info", ("A02:2025",), ("CWE-16",), "A GraphQL-style endpoint reference was observed.", "Inventory GraphQL endpoints and enforce authentication and authorization."),
    RuleDefinition("WEB-APP-005", "HTML form missing explicit action", "Application Design", "info", ("A06:2025",), ("CWE-352",), "A form relies on the current document as its action.", "Prefer explicit, reviewed form actions for sensitive workflows."),
]

RULE_INDEX = {rule.key: rule for rule in RULES}

def get_rule(key: str) -> RuleDefinition:
    return RULE_INDEX[key]
