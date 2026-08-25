from fastapi import Depends
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models import User, Organization, Role

LOCAL_EMAIL = "local@aegisx.local"

def get_local_operator(db: Session = Depends(get_db)) -> User:
    """Return the local direct-access operator used for persistence scoping.

    This is not an authentication mechanism. AegisX standalone mode intentionally
    exposes the console directly and uses this deterministic principal only to keep
    tenant-aware database relationships consistent.
    """
    user = db.query(User).filter(User.email == LOCAL_EMAIL).first()
    if user:
        return user
    org = db.query(Organization).filter(Organization.name == "__aegisx_local__").first()
    if not org:
        org = Organization(name="__aegisx_local__")
        db.add(org); db.flush()
    user = User(
        email=LOCAL_EMAIL,
        first_name="AegisX",
        last_name="Local Operator",
        role=Role.admin,
        organization=org,
    )
    db.add(user); db.commit(); db.refresh(user)
    return user
