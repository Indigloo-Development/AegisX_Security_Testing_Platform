'use client';
import Link from 'next/link';
import AppShell from '../../components/AppShell';
const cards=[
 ['REST API','/api-security/rest','REST endpoint testing, response analysis and API Security Top 10 mapping.','REST'],
 ['GraphQL','/api-security/graphql','Introspection, schema, resolver and query-complexity analysis.','GRAPHQL'],
 ['gRPC','/api-security/grpc','Proto/service, reflection, TLS and method-security analysis.','GRPC'],
 ['SOAP','/api-security/soap','WSDL/XML/WS-Security and parser-hardening analysis.','SOAP'],
 ['Swagger / OpenAPI','/api-security/openapi','Schema, security requirements, parameters and inventory analysis.','OPENAPI'],
 ['JSON / Code','/api-security/json','Paste JSON/config/source and inspect API security indicators.','CODE'],
 ['Endpoint Discovery','/api-security/discovery','Discover API endpoints and persist inventory into Findings and Reports.','DISCOVERY'],
];
export default function APIHub(){return <AppShell><div className="page-stack"><section className="hero-strip"><div><span className="eyebrow">API SECURITY</span><h2>API Security Assessment Center</h2><p>Protocol-specific testing, discovery and schema analysis with evidence, risk and OWASP API Security mapping.</p></div><span className="mode-chip">7 API WORKSPACES</span></section><div className="security-card-grid">{cards.map(([t,h,d,k])=><Link href={h} className="security-card" key={h}><span className="card-kicker">{k}</span><h3>{t}</h3><p>{d}</p><span className="text-link">Open workspace →</span></Link>)}</div></div></AppShell>}
