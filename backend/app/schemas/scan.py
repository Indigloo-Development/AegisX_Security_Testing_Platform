from pydantic import BaseModel
class ScanCreate(BaseModel):
    profile: str = "balanced"
    scanner_family: str = "web"
    assessment_name: str | None = None
    mode: str = "balanced"
    auth_mode: str = "none"
class ScanRead(BaseModel):
    id: int
    status: str
    profile: str
    scanner_family: str
    target_id: int
    assessment_name: str | None = None
    target_url_snapshot: str | None = None
    mode: str | None = None
    auth_mode: str | None = None
    progress: int = 0
    model_config={"from_attributes":True}
