from __future__ import annotations

import hashlib
from typing import Any

from .models import FuzzAnalysis, FuzzCase, ResponseObservation


SAFE_MUTATIONS = {
    "string": ["", "AegisX-CANARY", "A" * 32],
    "integer": [-1, 0, 1, 999999],
    "number": [-1.0, 0.0, 1.0, 999999.0],
    "boolean": [True, False],
    "array": [[], ["AegisX-CANARY"]],
    "object": [{}, {"unexpected": "AegisX-CANARY"}],
}


def _fingerprint(body: str | None) -> str | None:
    if body is None:
        return None
    return hashlib.sha256(body.encode("utf-8", "ignore")).hexdigest()[:16]


def _schema_type(schema: dict[str, Any]) -> str:
    t = schema.get("type")
    if t in SAFE_MUTATIONS:
        return t
    if "enum" in schema:
        return "string"
    if "properties" in schema:
        return "object"
    return "string"


class APIFuzzEngine:
    """Schema-aware, safe fuzz-case generator and response differential analyzer.

    It creates bounded, non-destructive mutations for authorized testing. It does
    not execute arbitrary state-changing operations automatically.
    """

    def generate_openapi_cases(self, document: dict[str, Any], max_cases: int = 120) -> FuzzAnalysis:
        result = FuzzAnalysis()
        count = 0
        for path, item in (document.get("paths") or {}).items():
            if not isinstance(item, dict):
                continue
            for method, operation in item.items():
                if method.lower() not in {"get", "post", "put", "patch", "delete", "options", "head"}:
                    continue
                if not isinstance(operation, dict):
                    continue
                params = list(operation.get("parameters") or [])
                for param in params:
                    if not isinstance(param, dict) or not param.get("name"):
                        continue
                    schema = param.get("schema") or {"type": "string"}
                    kind = _schema_type(schema)
                    for index, value in enumerate(SAFE_MUTATIONS[kind]):
                        if count >= max_cases:
                            return result
                        cid = f"API-FUZZ-{count + 1:04d}"
                        result.cases.append(
                            FuzzCase(
                                case_id=cid,
                                method=method.upper(),
                                path=path,
                                parameter=str(param["name"]),
                                location=str(param.get("in") or "query"),
                                mutation=f"{kind}-boundary-{index + 1}",
                                value=value,
                                rationale="Bounded schema-aware mutation for validation, authorization, and input handling review.",
                            )
                        )
                        count += 1
        return result

    def compare_observations(
        self,
        observations: list[ResponseObservation],
        minimum_status_delta: int = 1,
    ) -> dict[str, Any]:
        if len(observations) < 2:
            return {"differential": False, "findings": [], "reason": "At least two observations are required."}

        baseline = observations[0]
        findings: list[dict[str, Any]] = []
        for other in observations[1:]:
            status_delta = None
            if baseline.status is not None and other.status is not None:
                status_delta = abs(baseline.status - other.status)
            fingerprint_changed = baseline.body_fingerprint != other.body_fingerprint
            if status_delta is not None and status_delta >= minimum_status_delta:
                findings.append({
                    "rule": "API-FUZZ-DIFF-STATUS",
                    "severity": "medium",
                    "confidence": "potential",
                    "identity_a": baseline.identity,
                    "identity_b": other.identity,
                    "status_a": baseline.status,
                    "status_b": other.status,
                    "status_delta": status_delta,
                    "description": "Authorized differential observation found a response-status difference; manual authorization/business-logic validation is required.",
                })
            if fingerprint_changed and (baseline.status == other.status):
                findings.append({
                    "rule": "API-FUZZ-DIFF-BODY",
                    "severity": "low",
                    "confidence": "informational",
                    "identity_a": baseline.identity,
                    "identity_b": other.identity,
                    "description": "Responses differ while status is unchanged; inspect for field-level authorization or data-exposure differences.",
                })
        return {"differential": bool(findings), "findings": findings}

    def build_workflow(self, steps: list[dict[str, Any]]) -> dict[str, Any]:
        normalized: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        previous_state: str | None = None
        for index, step in enumerate(steps):
            state = str(step.get("state") or f"state-{index + 1}")
            method = str(step.get("method") or "GET").upper()
            path = str(step.get("path") or "/")
            requires = step.get("requires") or []
            missing = [x for x in requires if x != previous_state]
            normalized.append({"index": index + 1, "state": state, "method": method, "path": path, "requires": requires, "missing_prerequisites": missing})
            if missing:
                findings.append({
                    "rule": "API-FLOW-STATE-001",
                    "severity": "medium",
                    "confidence": "potential",
                    "step": index + 1,
                    "path": path,
                    "description": "Workflow step declares prerequisites that are not represented by the preceding state; validate server-side state enforcement.",
                })
            previous_state = state
        return {"steps": normalized, "findings": findings}


def observation(identity: str, status: int | None, content_type: str | None, content_length: int | None, body: str | None, markers: list[str] | None = None) -> ResponseObservation:
    return ResponseObservation(
        identity=identity,
        status=status,
        content_type=content_type,
        content_length=content_length,
        body_fingerprint=_fingerprint(body),
        markers=tuple(markers or []),
    )
