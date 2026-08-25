'use client';
import Link from 'next/link';
import type {ReactNode} from 'react';
import {usePathname} from 'next/navigation';
import {useState} from 'react';

const groups=[
 {label:'Overview',href:'/dashboard',icon:'◈'},
 {label:'Web Security',href:'/web-security',icon:'◉',children:[['Scan · New Assessment','/web-security/new-assessment'],['Scan · Authenticated','/web-security/authenticated-scan'],['CSP Analyzer','/web-security/csp-analyzer'],['JWT Analyzer','/web-security/jwt-analyzer']]},
 {label:'API Security',href:'/api-security',icon:'⌁',children:[['REST API Scan','/api-security/rest'],['GraphQL Scan','/api-security/graphql'],['gRPC Scan','/api-security/grpc'],['SOAP Scan','/api-security/soap'],['Swagger / OpenAPI','/api-security/openapi'],['JSON / Code','/api-security/json'],['Endpoint Discovery','/api-security/discovery']]},
 {label:'SCA / SBOM',href:'/sca',icon:'◇'},
 {label:'AI Security',href:'/ai-security',icon:'✦',children:[['LLM Security','/ai-security/llm-security'],['RAG Security','/ai-security/rag-security'],['Agent / MCP Security','/ai-security/agent-mcp'],['AI Red Team','/ai-security/ai-red-team']]},
 {label:'Findings',href:'/findings',icon:'▣'},
 {label:'Issue Track Base',href:'/issue-track',icon:'☷'},
 {label:'Reports',href:'/reports',icon:'▤'},
];
export default function AppShell({children}:{children:ReactNode}){
 const path=usePathname(); const [collapsed,setCollapsed]=useState<Record<string,boolean>>({});
 return <div className="console-shell">
  <aside className="sidebar">
   <div className="side-brand"><div className="brand-mark">A</div><div><div className="brand">Aegis<span>X</span></div><div className="brand-sub">Enterprise Security Platform</div></div></div>
   <div className="side-status"><span className="status-dot online-dot"/> Engine Online <span className="side-version">v55</span></div>
   <nav className="side-nav">
    {groups.map(g=>{const active=path===g.href||Boolean(g.children?.some(x=>path===x[1]||path.startsWith(`${x[1]}/`))); const expanded=collapsed[g.href]??active; return <div key={g.href} className="nav-group">
      <div className={`nav-row ${active?'active':''}`}><Link href={g.href} className="nav-item"><span className="nav-icon">{g.icon}</span><span>{g.label}</span></Link>{g.children&&<button className="nav-toggle" aria-label={`Toggle ${g.label}`} onClick={()=>setCollapsed(x=>({...x,[g.href]:!expanded}))}>{expanded?'⌃':'⌄'}</button>}</div>
      {g.children&&expanded&&<div className="sub-nav">{g.children.map(([label,href])=><Link key={href} href={href} className={path===href||path.startsWith(`${href}/`)?'sub-item active':'sub-item'}>{label}</Link>)}</div>}
    </div>})}
   </nav>
   <div className="side-footer"><Link href="/reports" className="side-link">Export Center</Link><span className="side-link muted">Direct Access Mode</span></div>
  </aside>
  <main className="console-main">
   <header className="topbar"><div className="topbar-left"><button className="back-button" onClick={()=>window.history.length>1?window.history.back():null}>← Back</button><div><span className="eyebrow">AEGISX COMMAND CENTER</span><div className="top-title">Application, API & AI Security</div></div></div><div className="top-actions"><button className="top-refresh" onClick={()=>window.dispatchEvent(new Event('aegisx:data-change'))}>↻ Refresh</button><span className="live-chip online"><span className="status-dot online-dot"/> Connected</span><div className="avatar">AX</div></div></header>
   {children}
  </main>
 </div>
}
