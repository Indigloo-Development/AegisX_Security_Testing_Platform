from __future__ import annotations
from fastapi import APIRouter, HTTPException
from app.testlab import TestLabRunner as LabRunner, all_fixtures, categories, fixture_counts, get_fixture

router = APIRouter(prefix="/api/security-test-lab", tags=["Security Test Lab"])

@router.get("/summary")
def summary():
    return {**fixture_counts(), "categories": categories()}

@router.get("/fixtures")
def fixtures(category: str | None = None, negative: bool | None = None):
    rows = all_fixtures()
    if category:
        rows = [f for f in rows if f.category.lower() == category.lower()]
    if negative is not None:
        rows = [f for f in rows if f.negative == negative]
    return {"total": len(rows), "fixtures": [
        {"fixture_id": f.fixture_id, "title": f.title, "category": f.category, "protocol": f.protocol,
         "expected_rules": list(f.expected_rules), "forbidden_rules": list(f.forbidden_rules), "negative": f.negative}
        for f in rows
    ]}

@router.post("/run/{fixture_id}")
def run_fixture(fixture_id: str):
    try:
        fixture = get_fixture(fixture_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return LabRunner().run_fixture(fixture).as_dict()

@router.post("/run-all")
def run_all():
    results = LabRunner().run_all()
    return {
        "total": len(results),
        "passed": sum(r.passed for r in results),
        "failed": sum(not r.passed for r in results),
        "results": [r.as_dict() for r in results],
    }

@router.get("/coverage")
def coverage():
    return LabRunner().coverage()
