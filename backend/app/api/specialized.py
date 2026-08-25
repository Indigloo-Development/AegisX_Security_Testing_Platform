from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from app.api.deps import get_local_operator
from app.scanners.specialized.analyzers import analyze_csp, audit_jwt, analyze_cors, analyze_headers, analyze_cookies, analyze_oauth_oidc, fetch_url

router = APIRouter(prefix="/api/specialized", tags=["specialized-security"])

class UrlRequest(BaseModel):
    target_url: str = Field(min_length=8, max_length=2000)

class JwtRequest(BaseModel):
    token: str = Field(min_length=10, max_length=20000)

@router.post("/csp")
async def csp(req: UrlRequest, _=Depends(get_local_operator)):
    if not req.target_url.lower().startswith(("http://", "https://")):
        raise HTTPException(400, "Only HTTP/HTTPS URLs are supported")
    data=await fetch_url(req.target_url)
    headers={k.lower():v for k,v in data["headers"].items()}
    result=analyze_csp(headers.get("content-security-policy"), headers.get("content-security-policy-report-only"))
    result.update({"target_url":data["url"],"status_code":data["status_code"]})
    return result

@router.post("/jwt")
def jwt(req: JwtRequest, _=Depends(get_local_operator)):
    return audit_jwt(req.token)

@router.post("/cors")
async def cors(req: UrlRequest, _=Depends(get_local_operator)):
    data=await fetch_url(req.target_url)
    result=analyze_cors({k.lower():v for k,v in data["headers"].items()})
    result.update({"target_url":data["url"],"status_code":data["status_code"]})
    return result

@router.post("/headers")
async def headers(req: UrlRequest, _=Depends(get_local_operator)):
    data=await fetch_url(req.target_url)
    result=analyze_headers(data["headers"])
    result.update({"target_url":data["url"],"status_code":data["status_code"]})
    return result

@router.post("/cookies")
async def cookies(req: UrlRequest, _=Depends(get_local_operator)):
    data=await fetch_url(req.target_url)
    result=analyze_cookies({k.lower():v for k,v in data["headers"].items()})
    result.update({"target_url":data["url"],"status_code":data["status_code"]})
    return result

@router.post("/oauth-oidc")
def oauth(req: UrlRequest, _=Depends(get_local_operator)):
    return analyze_oauth_oidc(req.target_url)
