from __future__ import annotations
import httpx
from typing import Any
from .models import CampaignConfig, CampaignResult, StepResult
from .probes import ATTACK_STEPS
from ..ai_v2.providers import provider_for, build_payload, extract_text
from .classifier import classify


def _excerpt(text: str, size: int = 1200) -> str:
    return " ".join(text.split())[:size]


def _choose_next(labels: list[str], seen_categories: set[str]) -> str | None:
    if "secret-like-pattern" in labels and "leakage" not in seen_categories:
        return "leakage"
    if "internal-instruction-marker" in labels and "boundary" not in seen_categories:
        return "boundary"
    if "instruction-like-content-echo" in labels and "output" not in seen_categories:
        return "output"
    return None

async def run_adaptive_campaign(cfg: CampaignConfig, client: httpx.AsyncClient | None = None) -> CampaignResult:
    provider_for(cfg.provider)
    own = client is None
    if own:
        client = httpx.AsyncClient(timeout=cfg.timeout, follow_redirects=True)
    steps: list[StepResult] = []
    findings: list[dict[str, Any]] = []
    conversation: list[dict[str, str]] = []
    selected = list(ATTACK_STEPS)
    seen_categories: set[str] = set()
    completed = 0
    try:
        for turn in range(1, cfg.max_turns + 1):
            if completed >= cfg.max_steps:
                break
            # Baseline-first, then adaptive selection based on observed labels.
            candidates = [s for s in selected if s.category not in seen_categories]
            if not candidates:
                break
            step = candidates[0]
            payload = build_payload(cfg_to_v2(cfg), step.prompt, conversation)
            try:
                response = await client.request(cfg.method, cfg.target_url, json=payload, headers=cfg.headers)
                raw = response.text
                try:
                    data = response.json()
                except Exception:
                    data = None
                text = extract_text(data, raw)
                labels, severity, confidence, meta = classify(step.category, text)
                next_strategy = _choose_next(labels, seen_categories)
                steps.append(StepResult(step.id, step.category, turn, response.status_code, _excerpt(text), labels, severity, confidence, next_strategy))
                conversation.extend([{"role":"user","content":step.prompt},{"role":"assistant","content":text}])
                seen_categories.add(step.category)
                completed += 1
                if labels and severity != "info":
                    findings.append({
                        "finding_key": step.id,
                        "title": f"AI security issue: {step.category.replace('_',' ').title()}",
                        "severity": severity,
                        "confidence": confidence,
                        "category": "AI/LLM Security v3",
                        "endpoint": cfg.target_url,
                        "description": "; ".join(meta["rationale"]) or "Security indicator observed.",
                        "evidence": {"step_id": step.id, "turn": turn, "labels": labels, "response_excerpt": _excerpt(text)},
                        "remediation": "Enforce instruction hierarchy, minimize sensitive context, isolate untrusted data, validate outputs and apply least-privilege tool/policy controls.",
                    })
                if next_strategy:
                    nxt = next((x for x in ATTACK_STEPS if x.category == next_strategy and x.category not in seen_categories), None)
                    if nxt:
                        selected.remove(nxt)
                        selected.insert(0, nxt)
            except Exception as exc:
                steps.append(StepResult(step.id, step.category, turn, None, "", ["request_error"], "info", "unknown", None))
                completed += 1
    finally:
        if own:
            await client.aclose()
    return CampaignResult(cfg.target_url, cfg.provider, "completed", steps, findings, {"steps_executed":len(steps),"max_turns":cfg.max_turns,"adaptive":True,"mode":"bounded-defensive"})


def cfg_to_v2(cfg: CampaignConfig):
    from ..ai_v2.models import CampaignRequest
    return CampaignRequest(cfg.target_url, cfg.provider, cfg.method, cfg.prompt_field, cfg.headers, cfg.body_template, cfg.timeout, cfg.max_turns)
