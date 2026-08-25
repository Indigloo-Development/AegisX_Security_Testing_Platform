from pydantic import BaseModel, ConfigDict


class ProjectCreate(BaseModel):
    name: str
    description: str | None = None


class ProjectRead(ProjectCreate):
    id: int
    model_config = ConfigDict(from_attributes=True)


class TargetCreate(BaseModel):
    name: str
    target_type: str
    url: str | None = None


class TargetRead(TargetCreate):
    id: int
    project_id: int
    model_config = ConfigDict(from_attributes=True)
