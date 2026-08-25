from .models import Advisory, Mapping

ADVISORIES = [
    Advisory('AX-CVE-2025-0001', 'Example SQL injection advisory for a legacy package.', 'critical', 9.8, 0.71, True, ('CWE-89',), ('CAPEC-66',), ('OWASP-A05-2025',), ('T1059',), ({'package':'demo-sqli','ecosystem':'npm','introduced':'0','fixed':'1.4.0'},), ('1.4.0',), ('https://example.invalid/advisory/AX-CVE-2025-0001',), source='offline-demo'),
    Advisory('AX-CVE-2025-0002', 'Example path traversal advisory for a legacy package.', 'high', 8.1, 0.32, False, ('CWE-22',), ('CAPEC-126',), ('OWASP-A01-2025',), (), ({'package':'demo-path','ecosystem':'PyPI','introduced':'0','fixed':'2.2.0'},), ('2.2.0',), ('https://example.invalid/advisory/AX-CVE-2025-0002',), source='offline-demo'),
    Advisory('AX-CVE-2025-0003', 'Example supply-chain advisory used for knowledge graph regression.', 'high', 7.5, 0.55, False, ('CWE-1395',), (), ('OWASP-A03-2025',), (), ({'package':'demo-supply','ecosystem':'Maven','introduced':'0','fixed':'5.0.1'},), ('5.0.1',), (), source='offline-demo'),
]

MAPPINGS = [
    Mapping('CWE-89','maps-to','OWASP-A05-2025','OWASP Web 2025'),
    Mapping('CWE-22','maps-to','OWASP-A01-2025','OWASP Web 2025'),
    Mapping('CWE-1395','maps-to','OWASP-A03-2025','OWASP Web 2025'),
    Mapping('CAPEC-66','related-to','CWE-89','CWE/CAPEC'),
    Mapping('CAPEC-126','related-to','CWE-22','CWE/CAPEC'),
]
