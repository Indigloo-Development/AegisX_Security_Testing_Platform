import json
from pathlib import Path
from app.scanners.sca_v2.engine import SCAIntelligenceEngine
from app.scanners.sca_v2.intel import ThreatIntelProvider


def test_sca_v2_enriches_priority_and_supply_policy(tmp_path: Path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"lodash": "4.17.20"}}))
    result = SCAIntelligenceEngine().analyze(str(tmp_path), policy={"max_severity_counts": {"high": 0}})
    assert result.intelligence
    assert result.intelligence[0]["cvss"] == 7.4
    assert result.intelligence[0]["kev"] is True
    assert result.policy["passed"] is False
    assert any(f["finding_key"].startswith("SCA2-POLICY-") for f in result.findings)


def test_sca_v2_license_and_graph(tmp_path: Path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"express": "4.18.3"}}))
    result = SCAIntelligenceEngine().analyze(str(tmp_path))
    assert "nodes" in result.graph
    assert len(result.graph["nodes"]) == 1
    assert result.license_assessments[0]["classification"] == "unknown"


def test_sca_v2_sbom_diff():
    old={"components":[{"purl":"pkg:npm/lodash@4.17.20","version":"4.17.20"},{"purl":"pkg:npm/a@1.0.0","version":"1.0.0"}]}
    new={"components":[{"purl":"pkg:npm/lodash@4.17.21","version":"4.17.21"},{"purl":"pkg:npm/b@1.0.0","version":"1.0.0"}]}
    diff=SCAIntelligenceEngine.sbom_diff(old,new)
    assert diff["added"]
    assert diff["removed"]


def test_sca_v2_import_intel():
    provider=ThreatIntelProvider()
    added=provider.import_records([{"advisory_id":"AX-IMPORT-1","package":"demo","ecosystem":"npm","severity":"low","cvss":2.1}])
    assert added == 1
    assert any(r.advisory_id == "AX-IMPORT-1" for r in provider.lookup("demo","npm","1.0.0"))
