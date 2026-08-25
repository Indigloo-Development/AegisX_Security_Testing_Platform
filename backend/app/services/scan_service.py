from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models import Scan, ScanStatus, ScanLog, Finding, Severity
from app.services.scanner_registry import REGISTRY, ScanContext
from app.services.security_metadata import normalize_finding


def log_scan(db: Session, scan: Scan, message: str, progress: int, level: str = "INFO"):
    scan.progress = max(0, min(100, progress))
    db.add(ScanLog(scan_id=scan.id, timestamp=datetime.now(timezone.utc).replace(tzinfo=None), level=level, message=message, progress=scan.progress))
    db.commit()


def create_scan(db: Session, target, profile: str, scanner_family: str, assessment_name: str | None = None, mode: str = "balanced", auth_mode: str = "none") -> Scan:
    scan = Scan(target=target, profile=profile, scanner_family=scanner_family, status=ScanStatus.queued,
                assessment_name=assessment_name, target_url_snapshot=target.url, mode=mode, auth_mode=auth_mode, progress=0)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    log_scan(db, scan, "Assessment queued", 0)
    return scan


def execute_scan(db: Session, scan: Scan, auth_headers: dict[str,str] | None = None) -> Scan:
    scan.status = ScanStatus.running
    scan.started_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.commit()
    log_scan(db, scan, f"Starting {scan.scanner_family} {scan.mode} scan against {scan.target_url_snapshot or scan.target.url}", 5)
    scanner = REGISTRY.get(scan.scanner_family)
    if scanner and scanner.run:
        log_scan(db, scan, "Discovery phase started", 15)
        context = ScanContext(target_url=scan.target.url, profile=scan.profile, scanner_family=scan.scanner_family, auth_headers=auth_headers)
        findings = scanner.run(context) or []
        log_scan(db, scan, f"Detection engine returned {len(findings)} findings", 70)
        valid_severities = {x.value: x for x in Severity}
        for item in findings:
            item = normalize_finding(item, scan.scanner_family, context.target_url)
            now=datetime.now(timezone.utc).replace(tzinfo=None)
            severity = valid_severities.get(str(item.get("severity", "info")).lower(), Severity.info)
            evidence = dict(item.get("evidence") or {})
            evidence.setdefault("references", item.get("references") or ["https://www.first.org/cvss/calculator/4.0", "https://owasp.org/Top10/2025/"])
            evidence.setdefault("risk_reason", item.get("risk_reason"))
            evidence.setdefault("parameter", item.get("affected_parameter"))
            evidence.setdefault("component", item.get("affected_component"))
            evidence.setdefault("payload", item.get("test_payload"))
            evidence.setdefault("request", item.get("http_request"))
            evidence.setdefault("response", item.get("http_response"))
            evidence.setdefault("screenshot", item.get("screenshot"))
            scan.findings.append(Finding(
                finding_key=item.get("finding_key", "GENERIC"),
                title=item.get("title", "Security finding"),
                severity=severity,
                confidence=item.get("confidence", "potential"),
                category=item.get("category", "Security"),
                endpoint=item.get("endpoint") or context.target_url,
                description=item.get("description", ""),
                evidence=evidence,
                remediation=item.get("remediation"),
                cvss_v4=str(item.get("cvss_v4", item.get("cvss", "-"))),
                owasp_mapping=item.get("owasp_mapping", item.get("owasp", "")),
                framework_mapping=item.get("framework_mapping", ""),
                cwe=item.get("cwe", ""),
                status="open", created_at=now, updated_at=now,
            ))
        screenshot=capture_target_screenshot(context.target_url, scan.id)
        if screenshot:
            for f in scan.findings:
                ev=dict(f.evidence or {}); ev.setdefault("screenshot", screenshot); f.evidence=ev
            db.commit()
        else:
            db.commit()
    else:
        log_scan(db, scan, f"No scanner registered for family '{scan.scanner_family}'", 95, "WARN")
    scan.status = ScanStatus.completed
    scan.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
    scan.progress = 100
    db.commit()
    log_scan(db, scan, "Assessment completed", 100)
    db.refresh(scan)
    return scan


def capture_target_screenshot(target_url: str, scan_id: int) -> str | None:
    try:
        from pathlib import Path
        from playwright.sync_api import sync_playwright
        root=Path(__file__).resolve().parents[2]/"runtime"/"artifacts"
        root.mkdir(parents=True, exist_ok=True)
        path=root/f"scan-{scan_id}.png"
        with sync_playwright() as p:
            browser=p.chromium.launch(headless=True)
            page=browser.new_page(viewport={"width":1440,"height":900})
            page.goto(target_url, wait_until="domcontentloaded", timeout=15000)
            page.screenshot(path=str(path), full_page=True)
            browser.close()
        return f"/artifacts/scan-{scan_id}.png"
    except Exception:
        return None
