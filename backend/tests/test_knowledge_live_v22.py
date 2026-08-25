from app.knowledge.live import parse_nvd, parse_osv, parse_kev, TTLCache, _severity_from_score

def test_score_to_severity():
    assert _severity_from_score(9.8) == "critical"
    assert _severity_from_score(8.0) == "high"
    assert _severity_from_score(5.0) == "medium"
    assert _severity_from_score(2.0) == "low"

def test_parse_nvd():
    data = {
      "vulnerabilities": [{
        "cve": {
          "id": "CVE-TEST-1",
          "descriptions": [{"lang": "en", "value": "test"}],
          "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.1}}]},
          "weaknesses": [{"description": [{"value": "CWE-79"}]}],
          "references": [{"url": "https://example.test"}]
        }
      }]
    }
    rows = parse_nvd(data)
    assert rows[0].advisory_id == "CVE-TEST-1"
    assert rows[0].severity == "critical"

def test_parse_osv():
    rows = parse_osv({"vulns": [{"id": "GHSA-test", "summary": "bad", "database_specific": {"cwe": ["CWE-79"], "severity": "HIGH"}}]})
    assert rows[0].advisory_id == "GHSA-test"
    assert rows[0].severity == "high"

def test_parse_kev():
    rows = parse_kev({"vulnerabilities": [{"cveID": "CVE-TEST-2", "shortDescription": "known exploited", "dateAdded": "2026-01-01"}]}, "CVE-TEST-2")
    assert rows[0].kev is True
    assert rows[0].advisory_id == "CVE-TEST-2"

def test_ttl_cache():
    c = TTLCache(ttl_seconds=60)
    c.set("k", {"v": 1})
    assert c.get("k")["v"] == 1
