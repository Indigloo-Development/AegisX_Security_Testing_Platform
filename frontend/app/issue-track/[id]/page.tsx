'use client';
import {useEffect,useState} from 'react';
import {useParams,useRouter,useSearchParams} from 'next/navigation';
import AppShell from '../../../components/AppShell';
import {api,API} from '../../../lib/api';

const statuses=['open','closed','risk_accepted','ignored'];
const classifications=['false_positive','exploitable','need_further_investigate'];

export default function IssueTrackDetail(){
 const {id}=useParams(); const sp=useSearchParams(); const router=useRouter();
 const editMode=sp.get('edit')==='1';
 const [f,setF]=useState<any>(null); const [form,setForm]=useState<any>(null); const [saving,setSaving]=useState(false); const [err,setErr]=useState('');
 useEffect(()=>{api(`/api/console/findings/${id}`).then(x=>{setF(x);setForm({...x})}).catch(e=>setErr(e.message))},[id]);
 if(err)return <AppShell><div className="notice error">{err}</div></AppShell>;
 if(!f||!form)return <AppShell><div className="boot-card">Loading issue…</div></AppShell>;
 async function save(){setSaving(true);try{await api(`/api/console/findings/${id}`,{method:'PATCH',body:JSON.stringify(form)});localStorage.setItem('aegisx:data-change',String(Date.now()));const next=await api(`/api/console/findings/${id}`);setF(next);setForm({...next});}catch(e:any){setErr(e.message)}finally{setSaving(false)}}
 async function del(){if(!confirm('Delete this issue permanently?'))return;await api(`/api/console/findings/${id}`,{method:'DELETE'});localStorage.setItem('aegisx:data-change',String(Date.now()));router.push('/issue-track')}
 const refs=Array.isArray(f.references)?f.references:[];
 return <AppShell><div className="page-stack">
  <section className="hero-strip"><div><span className="eyebrow">ISSUE TRACK BASE</span><h2>AX-{f.id} · {f.title}</h2><p>{f.endpoint||'No affected endpoint captured'}</p></div><div className="action-row"><button className="btn ghost" onClick={()=>router.back()}>← Back</button>{!editMode&&<button className="btn primary" onClick={()=>router.push(`/issue-track/${id}?edit=1`)}>Edit Issue</button>}{editMode&&<button className="btn primary" disabled={saving} onClick={save}>{saving?'Saving…':'Save All Changes'}</button>}<button className="btn danger" onClick={del}>Delete</button></div></section>
  <section className="panel"><div className="detail-grid six"><div><span>Issue ID</span><b>AX-{f.id}</b></div><div><span>Severity</span><b className={`sev ${f.severity}`}>{f.severity}</b></div><div><span>CVSS V4.0</span><b>{f.cvss_v4||'Not calculated'}</b></div><div><span>CVSS Vector</span><b>{f.cvss_vector_v4||'Not provided'}</b></div><div><span>CWE</span><b>{f.cwe||'Not mapped'}</b></div><div><span>OWASP</span><b>{f.owasp_mapping||'Not mapped'}</b></div></div><div className="detail-grid four lower"><div><span>Risk Category</span><b>{f.severity}</b></div><div><span>Affected URL</span><b>{f.endpoint||'—'}</b></div><div><span>Affected Parameter</span><b>{f.affected_parameter||'—'}</b></div><div><span>Affected Component</span><b>{f.affected_component||f.category}</b></div></div></section>
  {editMode ? <section className="panel"><div className="panel-head"><h3>Edit Issue Details</h3><span className="muted">All changes are persisted and reflected in Findings, Issue Track Base, Overview and Reports.</span></div><div className="form-grid two">
   <label className="field"><span>Issue Name</span><input value={form.title||''} onChange={e=>setForm({...form,title:e.target.value})}/></label>
   <label className="field"><span>Severity</span><select value={form.severity} onChange={e=>setForm({...form,severity:e.target.value})}>{['critical','high','medium','low','info'].map(x=><option key={x}>{x}</option>)}</select></label>
   <label className="field"><span>Status</span><select value={form.status} onChange={e=>setForm({...form,status:e.target.value})}>{statuses.map(x=><option key={x}>{x}</option>)}</select></label>
   <label className="field"><span>Verification</span><select value={form.verification||'unreviewed'} onChange={e=>setForm({...form,verification:e.target.value})}><option value="reviewed">Reviewed</option><option value="unreviewed">Unreviewed</option></select></label>
   <label className="field"><span>Classification</span><select value={form.classification||'need_further_investigate'} onChange={e=>setForm({...form,classification:e.target.value})}>{classifications.map(x=><option key={x} value={x}>{x.replace(/_/g,' ')}</option>)}</select></label>
   <label className="field"><span>CVSS V4.0 Score</span><input value={form.cvss_v4||''} onChange={e=>setForm({...form,cvss_v4:e.target.value})}/></label>
   <label className="field"><span>CVSS V4.0 Vector</span><input value={form.cvss_vector_v4||''} onChange={e=>setForm({...form,cvss_vector_v4:e.target.value})}/></label>
   <label className="field"><span>CWE-ID</span><input value={form.cwe||''} onChange={e=>setForm({...form,cwe:e.target.value})}/></label>
   <label className="field"><span>OWASP / Framework</span><input value={form.owasp_mapping||form.framework_mapping||''} onChange={e=>setForm({...form,owasp_mapping:e.target.value})}/></label>
   <label className="field wide"><span>Affected URL / Endpoint</span><input value={form.endpoint||''} onChange={e=>setForm({...form,endpoint:e.target.value})}/></label>
   <label className="field"><span>Affected Parameter</span><input value={form.affected_parameter||''} onChange={e=>setForm({...form,affected_parameter:e.target.value})}/></label>
   <label className="field"><span>Affected Component</span><input value={form.affected_component||''} onChange={e=>setForm({...form,affected_component:e.target.value})}/></label>
   <label className="field wide"><span>Test Payload</span><textarea value={form.test_payload||''} onChange={e=>setForm({...form,test_payload:e.target.value})}/></label>
   <label className="field wide"><span>Issue Description</span><textarea value={form.description||''} onChange={e=>setForm({...form,description:e.target.value})}/></label>
   <label className="field wide"><span>Business Impact</span><textarea value={form.business_impact||form.risk_reason||''} onChange={e=>setForm({...form,business_impact:e.target.value})}/></label>
   <label className="field wide"><span>Remediation</span><textarea value={form.remediation||''} onChange={e=>setForm({...form,remediation:e.target.value})}/></label>
   <label className="field wide"><span>References (one URL per line)</span><textarea value={(form.references||[]).join('\n')} onChange={e=>setForm({...form,references:e.target.value.split(/\n+/).map((x:string)=>x.trim()).filter(Boolean)})}/></label>
  </div><div className="action-row"><button className="btn primary" disabled={saving} onClick={save}>{saving?'Saving…':'Save All Changes'}</button><button className="btn ghost" onClick={()=>router.push(`/issue-track/${id}`)}>Cancel Edit</button></div></section>:
  <section className="panel"><div className="panel-head"><h3>Issue Details</h3><span className="mode-chip">VIEW ONLY</span></div><h3>Description</h3><p className="long-copy">{f.description||'No description captured.'}</p><h3>Business Impact</h3><p className="long-copy">{f.business_impact||f.risk_reason||'Business impact requires contextual validation.'}</p><h3>Remediation</h3><p className="long-copy">{f.remediation||'—'}</p></section>}
  <section className="panel"><h3>Proof of Concept & Evidence</h3><div className="evidence-grid"><div><span>HTTP Request</span><pre>{f.http_request||'Not captured'}</pre></div><div><span>HTTP Response</span><pre>{f.http_response||'Not captured'}</pre></div><div><span>Test Payload</span><pre>{f.test_payload||'Not captured'}</pre></div></div>{f.screenshot&&<div className="detail-block"><b>Evidence Screenshot</b><p><a href={`${API}${f.screenshot}`} target="_blank" rel="noreferrer" className="text-link">Open screenshot ↗</a></p><img src={`${API}${f.screenshot}`} alt="Finding evidence" className="evidence-image"/></div>}</section>
  <section className="panel"><h3>References</h3><ul className="reference-list">{refs.map((r:any,i:number)=><li key={i}><a href={String(r)} target="_blank" rel="noreferrer">{String(r)}</a></li>)}</ul></section>
 </div></AppShell>
}
