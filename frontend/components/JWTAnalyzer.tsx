'use client';
import {useState} from 'react';
import AppShell from './AppShell';
import {api} from '../lib/api';

export default function JWTAnalyzer(){
 const [token,setToken]=useState(''); const [res,setRes]=useState<any>(null); const [payload,setPayload]=useState(''); const [busy,setBusy]=useState(false); const [err,setErr]=useState('');
 async function run(){setBusy(true);setErr('');setRes(null);try{const d=await api('/api/console/jwt',{method:'POST',body:JSON.stringify({content:token})});setRes(d);setPayload(JSON.stringify(d.payload||{},null,2));}catch(e:any){setErr(e.message||'JWT analysis failed.')}finally{setBusy(false)}}
 const findings=Array.isArray(res?.findings)?res.findings:[];
 return <AppShell><div className="page-stack">
  <section className="hero-strip"><div><span className="eyebrow">WEB SECURITY / JWT</span><h2>JWT Token Analyzer</h2><p>Human-readable token audit with separate Header, Payload, Signature, Algorithm, claims and security-finding views.</p></div><span className="mode-chip">TOKEN STRUCTURE + CLAIMS</span></section>
  <section className="panel"><label className="field"><span>Encoded JWT Token</span><textarea value={token} onChange={e=>setToken(e.target.value)} placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.…"/></label>{err&&<div className="notice error">{err}</div>}<button className="btn primary" disabled={busy||!token} onClick={run}>{busy?'Decoding…':'Decode & Analyze'}</button></section>
  {res&&<>
   <div className="jwt-grid"><section className="panel"><div className="panel-head"><h3>Header</h3><span className="mode-chip">{res.algorithm||'—'}</span></div><div className="claims-grid">{Object.entries(res.header||{}).map(([k,v]:any)=><div key={k}><span>{k}</span><b>{String(v)}</b></div>)}</div></section>
   <section className="panel"><div className="panel-head"><h3>Signature</h3><span className={`status-badge ${res.signature_present?'closed':'open'}`}>{res.signature_present?'Present':'Missing'}</span></div><div className="claims-grid"><div><span>Algorithm</span><b>{res.algorithm||'—'}</b></div><div><span>Signature</span><b>{res.signature_segment_length||0} chars</b></div><div><span>Secret Key</span><b>Not derivable from token</b></div><div><span>Structure</span><b>{res.valid_structure?'Valid':'Invalid'}</b></div></div></section>
   <section className="panel wide"><div className="panel-head"><h3>Payload</h3><span className="muted">Decoded claims are displayed as structured fields.</span></div><div className="claims-grid">{Object.entries(res.payload||{}).map(([k,v]:any)=><div key={k}><span>{k}</span><b>{typeof v==='object'?JSON.stringify(v):String(v)}</b></div>)}</div></section>
   <section className="panel wide"><div className="panel-head"><h3>Payload Editor</h3><span className="muted">Local analysis only; editing does not forge or sign a token.</span></div><textarea className="code-editor" value={payload} onChange={e=>setPayload(e.target.value)}/><button className="btn ghost" onClick={()=>{try{setPayload(JSON.stringify(JSON.parse(payload),null,2))}catch{}}}>Format Payload</button></section></div>
   <section className="panel"><div className="panel-head"><div><span className="eyebrow">AUDIT RESULTS</span><h3>Security Findings</h3></div><span className="mode-chip">{findings.length} findings</span></div><div className="finding-stack">{findings.map((f:any,i:number)=><article className="finding-detail" key={f.finding_key||i}><div className="finding-detail-head"><div><span className="finding-key">{f.finding_key||`JWT-${i+1}`}</span><b>{f.title}</b></div><span className={`sev ${f.severity||'info'}`}>{f.severity||'info'}</span></div><div className="finding-expanded"><p>{f.description||'No description supplied.'}</p><div className="detail-block"><b>Remediation</b><p>{f.remediation||'Review token validation, algorithm allow-list, lifetime and key management.'}</p></div></div></article>)}</div></section>
  </>}
 </div></AppShell>
}
