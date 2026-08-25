from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.api.deps import get_local_operator
from app.db.session import get_db
from app.models import Finding, Scan, Target, Project, User
from app.intelligence.brain import analyze, build_scan_plan, risk_assessment, deduplicate
from app.intelligence.attack_graph import build_attack_graph
from app.intelligence.risk import advanced_risk, remediation_priorities

router = APIRouter(prefix="/api/intelligence", tags=["security-intelligence"])


def _org_findings(db: Session, user: User):
    return (db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .join(Target, Scan.target_id == Target.id)
        .join(Project, Target.project_id == Project.id)
        .filter(Project.organization_id == user.organization_id)
        .order_by(Finding.id.desc()).all())


@router.post("/plan")
def plan(payload: dict, user: User = Depends(get_local_operator)):
    return build_scan_plan(str(payload.get("target_type", "web")), str(payload.get("profile", "standard")))


@router.get("/summary")
def summary(db: Session = Depends(get_db), user: User = Depends(get_local_operator)):
    findings = _org_findings(db, user)
    return analyze(findings)


@router.post("/analyze")
def analyze_findings(payload: dict, db: Session = Depends(get_db), user: User = Depends(get_local_operator)):
    findings = _org_findings(db, user)
    target_type = str(payload.get("target_type", "web"))
    profile = str(payload.get("profile", "standard"))
    return analyze(findings, target_type, profile)


@router.get("/attack-graph")
def attack_graph(db: Session = Depends(get_db), user: User = Depends(get_local_operator)):
    findings = _org_findings(db, user)
    return build_attack_graph(findings)


@router.get("/advanced-risk")
def advanced_risk_summary(db: Session = Depends(get_db), user: User = Depends(get_local_operator)):
    findings = _org_findings(db, user)
    graph = build_attack_graph(findings)
    risk = advanced_risk(findings, graph)
    return {"risk": risk, "priorities": remediation_priorities(findings, graph), "attack_graph": graph}
