from __future__ import annotations
import json
from pathlib import Path
from typing import Iterable
from .models import LabFixture

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"

def _load_file(path: Path) -> LabFixture:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return LabFixture(
        fixture_id=raw["fixture_id"], title=raw["title"], category=raw["category"],
        protocol=raw.get("protocol", "web"), expected_rules=tuple(raw.get("expected_rules", [])),
        forbidden_rules=tuple(raw.get("forbidden_rules", [])), context=raw.get("context", {}),
        negative=bool(raw.get("negative", False)),
    )

def all_fixtures() -> list[LabFixture]:
    return sorted((_load_file(p) for p in FIXTURE_DIR.glob("*.json")), key=lambda x: x.fixture_id)

def get_fixture(fixture_id: str) -> LabFixture:
    for fixture in all_fixtures():
        if fixture.fixture_id == fixture_id:
            return fixture
    raise KeyError(f"Unknown lab fixture: {fixture_id}")

def categories() -> list[str]:
    return sorted({f.category for f in all_fixtures()})


def fixture_counts() -> dict[str, int]:
    fixtures = all_fixtures()
    return {
        "total": len(fixtures),
        "positive": sum(not f.negative for f in fixtures),
        "negative": sum(f.negative for f in fixtures),
        "categories": len({f.category for f in fixtures}),
    }
