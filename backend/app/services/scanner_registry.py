from dataclasses import dataclass
from typing import Any

from app.scanners.web.scanner import WebScanner
from app.scanners.api.scanner import APIScanner as APIEngine
from app.scanners.sca.scanner import SCAScanner as SCAEngine
from app.scanners.rag.scanner import RAGSecurityScanner as RAGEngine
from app.scanners.agent.scanner import AgentSecurityScanner as AgentEngine


@dataclass
class ScanContext:
    target_url: str | None
    profile: str
    scanner_family: str
    auth_headers: dict[str,str] | None = None


class BaseScanner:
    name = "base"

    def run(self, context: ScanContext) -> list[dict[str, Any]]:
        return []


class WebScannerAdapter(BaseScanner):
    name = "web"

    def __init__(self) -> None:
        self.engine = WebScanner()

    def run(self, context: ScanContext) -> list[dict[str, Any]]:
        if not context.target_url:
            return []
        result = self.engine.run(context.target_url, context.profile, context.auth_headers or {})
        return result.findings


class APIScanner(BaseScanner):
    name = "api"

    def __init__(self) -> None:
        self.engine = APIEngine()

    def run(self, context: ScanContext) -> list[dict[str, Any]]:
        if not context.target_url:
            return []
        result = self.engine.run(context.target_url, context.profile)
        return result.findings


class AIScanner(BaseScanner):
    name = "ai"


class SCAScanner(BaseScanner):
    name = "sca"

    def __init__(self) -> None:
        self.engine = SCAEngine()

    def run(self, context: ScanContext) -> list[dict[str, Any]]:
        if not context.target_url:
            return []
        # Scanner registry uses target_url as a path for SCA targets.
        result = self.engine.scan_path(context.target_url, context.profile)
        return result.findings


class CSPAnalyzer(BaseScanner):
    name = "csp"


class JWTTokenAuditor(BaseScanner):
    name = "jwt"


class RAGScanner(BaseScanner):
    name = "rag"


class AgentScanner(BaseScanner):
    name = "agent"


REGISTRY = {x.name: x() for x in [WebScannerAdapter, APIScanner, AIScanner, SCAScanner, CSPAnalyzer, JWTTokenAuditor, RAGScanner, AgentScanner]}
