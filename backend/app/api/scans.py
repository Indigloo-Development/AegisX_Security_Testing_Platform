from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from app.api.deps import get_local_operator
from app.db.session import get_db, SessionLocal
from app.models import Project, Target, Scan, User, ScanLog
from app.schemas.scan import ScanCreate, ScanRead
from app.services.scan_service import create_scan, execute_scan

router = APIRouter(prefix="/api/scans", tags=["scans"])

def _run_scan(scan_id: int, auth_headers: dict[str,str] | None = None):
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan:
            execute_scan(db, scan, auth_headers)
    finally:
        db.close()

@router.post("/target/{target_id}", response_model=ScanRead)
def start_scan(target_id: int, body: ScanCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db), user: User = Depends(get_local_operator)):
    target = db.query(Target).join(Project).filter(Target.id == target_id, Project.organization_id == user.organization_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    scan = create_scan(db, target, body.profile, body.scanner_family, body.assessment_name, body.mode, body.auth_mode)
    background_tasks.add_task(_run_scan, scan.id)
    return scan

@router.get("", response_model=list[ScanRead])
def list_scans(db: Session = Depends(get_db), user: User = Depends(get_local_operator)):
    return db.query(Scan).join(Target).join(Project).filter(Project.organization_id == user.organization_id).order_by(Scan.id.desc()).all()

@router.get("/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db), user: User = Depends(get_local_operator)):
    scan = db.query(Scan).join(Target).join(Project).filter(Scan.id == scan_id, Project.organization_id == user.organization_id).first()
    if not scan: raise HTTPException(404, "Scan not found")
    return {"id":scan.id,"status":scan.status.value,"progress":scan.progress,"profile":scan.profile,"mode":scan.mode,"assessment_name":scan.assessment_name,"target_url":scan.target_url_snapshot or scan.target.url,"scanner_family":scan.scanner_family,"started_at":scan.started_at,"completed_at":scan.completed_at}

@router.get("/{scan_id}/logs")
def get_scan_logs(scan_id: int, db: Session = Depends(get_db), user: User = Depends(get_local_operator)):
    scan = db.query(Scan).join(Target).join(Project).filter(Scan.id == scan_id, Project.organization_id == user.organization_id).first()
    if not scan: raise HTTPException(404, "Scan not found")
    logs=db.query(ScanLog).filter(ScanLog.scan_id==scan_id).order_by(ScanLog.id.asc()).all()
    return [{"id":l.id,"timestamp":l.timestamp,"level":l.level,"message":l.message,"progress":l.progress} for l in logs]
