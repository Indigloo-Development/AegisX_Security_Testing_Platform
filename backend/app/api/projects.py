from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.api.deps import get_local_operator
from app.db.session import get_db
from app.models import Project, Target, User
from app.schemas.project import ProjectCreate, ProjectRead, TargetCreate, TargetRead

router = APIRouter(prefix="/api/projects", tags=["projects"])


@router.post("", response_model=ProjectRead)
def create_project(body: ProjectCreate, db: Session = Depends(get_db), user: User = Depends(get_local_operator)):
    project = Project(name=body.name, description=body.description, organization_id=user.organization_id)
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


@router.get("", response_model=list[ProjectRead])
def list_projects(db: Session = Depends(get_db), user: User = Depends(get_local_operator)):
    return db.query(Project).filter(Project.organization_id == user.organization_id).all()


@router.post("/{project_id}/targets", response_model=TargetRead)
def create_target(project_id: int, body: TargetCreate, db: Session = Depends(get_db), user: User = Depends(get_local_operator)):
    project = db.query(Project).filter(Project.id == project_id, Project.organization_id == user.organization_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    target = Target(name=body.name, target_type=body.target_type, url=body.url, project=project)
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


@router.get("/{project_id}/targets", response_model=list[TargetRead])
def list_targets(project_id: int, db: Session = Depends(get_db), user: User = Depends(get_local_operator)):
    project = db.query(Project).filter(Project.id == project_id, Project.organization_id == user.organization_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project.targets
