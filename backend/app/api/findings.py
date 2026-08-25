from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.api.deps import get_local_operator
from app.db.session import get_db
from app.models import Finding, Scan, Target, Project, User

router = APIRouter(prefix="/api/findings", tags=["findings"])


@router.get("")
def list_findings(db: Session = Depends(get_db), user: User = Depends(get_local_operator)):
    rows = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .join(Target, Scan.target_id == Target.id)
        .join(Project, Target.project_id == Project.id)
        .filter(Project.organization_id == user.organization_id)
        .order_by(Finding.id.desc())
        .all()
    )
    return [{"id": f.id, "finding_key": f.finding_key, "title": f.title, "severity": f.severity.value,
             "confidence": f.confidence, "category": f.category, "endpoint": f.endpoint,
             "description": f.description, "remediation": f.remediation} for f in rows]
