from __future__ import annotations
import base64
from dataclasses import asdict
from .models import AuthProfile

def build_auth_headers(profile: AuthProfile | None) -> dict[str, str]:
    if not profile:
        return {}
    headers = dict(profile.headers)
    if profile.bearer_token and "Authorization" not in headers:
        headers["Authorization"] = f"Bearer {profile.bearer_token}"
    if profile.basic_username is not None and profile.basic_password is not None and "Authorization" not in headers:
        raw = f"{profile.basic_username}:{profile.basic_password}".encode()
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode()
    return headers

def build_cookies(profile: AuthProfile | None) -> dict[str, str]:
    return dict(profile.cookies) if profile else {}
