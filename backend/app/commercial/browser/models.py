from typing import Dict, List, Optional
from pydantic import BaseModel, Field, HttpUrl

class BrowserAuthProfile(BaseModel):
    headers: Dict[str, str] = Field(default_factory=dict)
    cookies: List[Dict[str, str]] = Field(default_factory=list)
    storage_state_path: Optional[str] = None

class BrowserScanRequest(BaseModel):
    target_url: HttpUrl
    max_pages: int = Field(default=20, ge=1, le=100)
    max_concurrency: int = Field(default=3, ge=1, le=8)
    navigation_timeout_ms: int = Field(default=15000, ge=2000, le=60000)
    same_origin_only: bool = True
    capture_screenshots: bool = False
    capture_har: bool = False
    auth: BrowserAuthProfile = Field(default_factory=BrowserAuthProfile)

class BrowserPageEvidence(BaseModel):
    url: str
    status: Optional[int] = None
    title: str = ""
    links: List[str] = Field(default_factory=list)
    scripts: List[str] = Field(default_factory=list)
    forms: List[str] = Field(default_factory=list)
    api_requests: List[str] = Field(default_factory=list)
    screenshot_path: Optional[str] = None

class BrowserScanResult(BaseModel):
    target_url: str
    pages_scanned: int
    requests_captured: int
    discovered_urls: List[str]
    pages: List[BrowserPageEvidence]
    resumed: bool = False
    cancelled: bool = False
