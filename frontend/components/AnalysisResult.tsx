
'use client';
import {useState} from 'react';
import {API} from '../lib/api';
export default function AnalysisResult({result,title='Security Analysis Result',scannerFamily='security'}:{result:any;title?:string;scannerFamily?:string}){
 const [open,setOpen]=useState<number|null>(null);
 const findings=Array.isArray(result?.findings)?result.findings:[];
 const meta=result?.metadata||result?.metrics||{};
 return <section className="panel result-panel">
  <div className="panel-head"><div><span className="eyebrow">{scannerFamily.toUpperCase()} SECURITY</span><h3>{title}</h3><p className="muted">Evidence-first result view. Heuristics are labeled as potential unless validated.</p></div><span className="mode-chip">{result?.status||'COMPLETED'}</span></div>
  <div className="result-summary rich"><div><span>Target</span><strong>{result?.target_url||result?.target||'—'}</strong></div><div><span>Total Findings</span><strong>{findings.length}</strong></div><div><span>Critical / High</span><strong>{findings.filter((f:any)=>f.severity==='critical').length} / {findings.filter((f:any)=>f.severity==='high').length}</strong></div><div><span>Evidence Steps</span><strong>{result?.observations?.length||result?.steps?.length||result?.probes?.length||0}</strong></div></div>
  {meta&&Object.keys(meta).length>0&&<div className="meta-chip-grid">{Object.entries(meta).slice(0,8).map(([k,v]:any)=><div key={k}><span>{k.replaceAll('_',' ')}</span><b>{String(v)}</b></div>)}</div>}
  {result?.headers&&<details className="detail-block" open><summary><b>HTTP Response Headers</b></summary><div className="header-grid">{Object.entries(result.headers).map(([k,v]:any)=><div key={k}><span>{k}</span><code>{String(v)}</code></div>)}</div></details>}
  {!findings.length&&<div className="empty-state good"><b>No findings were produced by this assessment.</b><span>This is not proof of absence of vulnerabilities; review scope and evidence.</span></div>}
  <div className="finding-stack">{findings.map((f:any,i:number)=><article className="finding-detail" key={f.finding_key||i}>
    <button className="finding-detail-head finding-button" onClick={()=>setOpen(open===i?null:i)}><div><span className="finding-key">{f.finding_key||`F-${i+1}`}</span><b>{f.title||'Security finding'}</b><small>{f.category||scannerFamily} · {f.confidence||'potential'}</small></div><span className={`sev ${f.severity||'info'}`}>{f.severity||'info'}</span></button>
    {open===i&&<div className="finding-expanded"><div className="finding-meta"><span>CWE {f.cwe||'—'}</span><span>CVSS v4.0 {f.cvss_v4||'—'}</span><span>{f.owasp_mapping||f.framework_mapping||'Framework review required'}</span></div><p>{f.description||'No description supplied.'}</p><div className="finding-two"><div><small>Why this risk</small><p>{f.risk_reason||'Risk classification is based on available scanner evidence.'}</p></div><div><small>Remediation</small><p>{f.remediation||'Review and apply the recommended security control.'}</p></div></div><div className="detail-grid four"><div><span>Affected URL</span><b>{f.endpoint||result?.target_url||'—'}</b></div><div><span>Parameter</span><b>{f.affected_parameter||f.evidence?.parameter||'—'}</b></div><div><span>Component</span><b>{f.affected_component||f.evidence?.component||'—'}</b></div><div><span>Payload</span><b>{f.test_payload||f.evidence?.payload||'—'}</b></div></div><div className="evidence-grid"><div><span>HTTP Request</span><pre>{f.http_request||f.evidence?.request||'Not captured'}</pre></div><div><span>HTTP Response</span><pre>{f.http_response||f.evidence?.response||'Not captured'}</pre></div></div>{(f.screenshot||f.evidence?.screenshot)&&<div className="detail-block"><b>Proof of Concept</b><a className="text-link" href={`${API}${f.screenshot||f.evidence?.screenshot}`} target="_blank" rel="noreferrer">Open screenshot ↗</a></div>}</div>}
  </article>)}</div>
 </section>
}
