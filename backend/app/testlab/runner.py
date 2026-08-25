from __future__ import annotations
from app.rules import RuleEngine, ScanContext
from .models import FixtureResult, LabFixture
from .registry import all_fixtures

class TestLabRunner:
    def __init__(self) -> None:
        self.engine = RuleEngine()

    def run_fixture(self, fixture: LabFixture) -> FixtureResult:
        context = fixture.context
        ctx = ScanContext(
            url=context.get("url", "https://lab.local/fixture"),
            method=context.get("method", "GET"),
            status_code=int(context.get("status_code", 200)),
            headers={str(k).lower(): str(v) for k, v in context.get("headers", {}).items()},
            body=str(context.get("body", "")),
            request_headers={str(k).lower(): str(v) for k, v in context.get("request_headers", {}).items()},
            request_body=str(context.get("request_body", "")),
            content_type=str(context.get("content_type", "")),
            parameters=list(context.get("parameters", [])),
            metadata=dict(context.get("metadata", {})),
            protocol=fixture.protocol,
            role=context.get("role"),
        )
        findings = self.engine.evaluate(ctx)
        detected = tuple(sorted({f.rule_key for f in findings}))
        expected = tuple(sorted(set(fixture.expected_rules)))
        forbidden = set(fixture.forbidden_rules)
        missing = tuple(sorted(set(expected) - set(detected)))
        unexpected = tuple(sorted(set(detected) & forbidden))
        passed = not missing and not unexpected
        return FixtureResult(fixture.fixture_id, passed, expected, detected, unexpected, missing)

    def run_all(self) -> list[FixtureResult]:
        return [self.run_fixture(f) for f in all_fixtures()]

    def coverage(self) -> dict[str, object]:
        fixtures = all_fixtures()
        rule_counts: dict[str, int] = {}
        for fixture in fixtures:
            for key in fixture.expected_rules:
                rule_counts[key] = rule_counts.get(key, 0) + 1
        return {
            "fixtures": len(fixtures),
            "positive": sum(not f.negative for f in fixtures),
            "negative": sum(f.negative for f in fixtures),
            "covered_rules": len(rule_counts),
            "rules": dict(sorted(rule_counts.items())),
        }
