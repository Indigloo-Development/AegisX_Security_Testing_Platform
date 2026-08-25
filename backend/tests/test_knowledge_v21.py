from app.knowledge.store import KnowledgeBase
from app.knowledge.catalog import ADVISORIES
from app.knowledge.providers import OfflineKnowledgeProvider

def test_summary_and_provider_registry():
    kb=KnowledgeBase()
    s=kb.summary()
    assert s['advisories'] == len(ADVISORIES)
    assert 'offline-knowledge' in s['providers']

def test_search_maps_cwe_to_owasp():
    kb=KnowledgeBase()
    r=kb.search(advisory_id='AX-CVE-2025-0001')
    assert len(r.advisories)==1
    assert any(m['target_id']=='OWASP-A05-2025' for m in r.mappings)

def test_package_search_is_case_insensitive():
    kb=KnowledgeBase()
    r=kb.search(package='DEMO-SQLI', ecosystem='npm')
    assert r.advisories[0]['advisory_id']=='AX-CVE-2025-0001'

def test_import_is_deduplicated():
    kb=KnowledgeBase()
    row={'advisory_id':'AX-NEW-1','summary':'test','severity':'medium','affected':[{'package':'demo','ecosystem':'npm'}]}
    assert kb.import_advisories([row])==1
    assert kb.import_advisories([row])==0

def test_offline_provider_search():
    kb=KnowledgeBase()
    provider=OfflineKnowledgeProvider([ADVISORIES[0]])
    result=provider.search(package='demo-sqli', ecosystem='npm')
    assert result.ok and result.advisories
