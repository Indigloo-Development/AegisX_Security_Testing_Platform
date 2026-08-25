from typing import Dict, List, Optional
from pydantic import BaseModel, Field, HttpUrl, SecretStr

class AuthWorkflow(BaseModel):
    login_url: HttpUrl
    username_selector: str = Field(min_length=1, max_length=256)
    password_selector: str = Field(min_length=1, max_length=256)
    submit_selector: str = Field(min_length=1, max_length=256)
    username: str = Field(min_length=1, max_length=256)
    password: SecretStr
    success_indicator: str = Field(default="", max_length=256)

class RoleProfile(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    headers: Dict[str, str] = Field(default_factory=dict)
    cookies: List[Dict[str, str]] = Field(default_factory=list)

class DeepDASTRequest(BaseModel):
    target_url: HttpUrl
    max_pages: int = Field(default=25, ge=1, le=100)
    max_concurrency: int = Field(default=3, ge=1, le=8)
    navigation_timeout_ms: int = Field(default=15000, ge=2000, le=60000)
    same_origin_only: bool = True
    auth_workflow: Optional[AuthWorkflow] = None
    roles: List[RoleProfile] = Field(default_factory=list, max_length=4)
    enable_safe_validators: bool = True

class RetestRequest(BaseModel):
    target_url: HttpUrl
    finding_type: str = Field(min_length=1, max_length=128)
    test_url: Optional[HttpUrl] = None
    original_status: Optional[int] = Field(default=None, ge=100, le=599)
    headers: Dict[str, str] = Field(default_factory=dict)

class DeepDASTResult(BaseModel):
    target_url: str
    authenticated: bool
    roles_tested: List[str] = Field(default_factory=list)
    pages_scanned: int = 0
    endpoints_discovered: List[str] = Field(default_factory=list)
    findings: List[dict] = Field(default_factory=list)
    retest: Optional[dict] = None
