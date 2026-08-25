from typing import Any

def analyze_rag_fixture(documents: list[dict[str, Any]]) -> dict[str, Any]:
    findings=[]
    for doc in documents:
        text=str(doc.get('content','')).lower()
        if any(marker in text for marker in ['ignore previous instructions','system prompt','do not follow application policy']):
            findings.append({'key':'RAG2-POISON-001','title':'Potential prompt injection in retrieved content','severity':'high','confidence':'likely','document_id':doc.get('id'),'evidence':{'marker':'instruction-like content'},'remediation':'Treat retrieved content as untrusted data and enforce a strict instruction/data boundary.'})
        if doc.get('tenant_id') is not None and doc.get('authorized_tenant_id') is not None and doc['tenant_id'] != doc['authorized_tenant_id']:
            findings.append({'key':'RAG2-ISO-001','title':'Cross-tenant retrieval mismatch in fixture','severity':'critical','confidence':'confirmed','document_id':doc.get('id'),'evidence':{'tenant_id':doc.get('tenant_id'),'authorized_tenant_id':doc.get('authorized_tenant_id')},'remediation':'Enforce tenant-aware ACLs at retrieval time and validate document authorization before context assembly.'})
        if any(x in text for x in ['c:\\users\\','/home/','/var/lib/','internal hostname']):
            findings.append({'key':'RAG2-META-001','title':'Potential internal metadata leakage','severity':'medium','confidence':'potential','document_id':doc.get('id'),'evidence':{'indicator':'internal path/host-like content'},'remediation':'Remove internal filesystem paths and infrastructure metadata from retrievable context.'})
    return {'document_count':len(documents),'findings':findings}
