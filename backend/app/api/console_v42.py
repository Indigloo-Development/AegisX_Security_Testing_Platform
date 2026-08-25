from __future__ import annotations
import csv, io, json, math, html as html_lib
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy.orm import Session
from app.api.deps import get_local_operator
from app.db.session import get_db, SessionLocal
from app.models import User, Project, Target, Scan, Finding, ScanStatus, Severity
from app.services.scan_service import create_scan, execute_scan, log_scan
from app.scanners.sca.scanner import SCAScanner
from app.scanners.specialized.analyzers import fetch_url, analyze_csp, audit_jwt
from app.services.security_metadata import normalize_finding, infer_owasp, infer_cwe, SEV_SCORE
from app.scanners.api.scanner import APIScanner

router=APIRouter(prefix="/api/console", tags=["console"])

class WebAssessment(BaseModel):
    assessment_name: str = Field(min_length=2,max_length=300)
    target_url: HttpUrl
    mode: str = Field(default="balanced", pattern="^(fast|balanced|deep)$")
class AuthAssessment(WebAssessment):
    username: str = Field(min_length=1,max_length=320)
    password: str = Field(min_length=1,max_length=1000)
class TextAnalyze(BaseModel):
    content: str = Field(min_length=1,max_length=5_000_000)
class TargetAnalyze(BaseModel):
    target_url: HttpUrl
class SCARepo(BaseModel):
    source_path: str = Field(min_length=1,max_length=2000)
class SCAUrl(BaseModel):
    target_url: HttpUrl
class SCACombined(BaseModel):
    source_path: str | None = None
    content: str | None = None
    filename: str = "package.json"
class ApiEndpoint(BaseModel):
    endpoint: HttpUrl
class ApiText(BaseModel):
    content: str = Field(min_length=1,max_length=5_000_000)

MODE_PROFILE={"fast":"quick","balanced":"standard","deep":"deep"}

def _system_project(db,user):
    project=db.query(Project).filter(Project.organization_id==user.organization_id, Project.name=="AegisX Security Assessments").first()
    if not project:
        project=Project(name="AegisX Security Assessments",description="Internal assessment container",organization_id=user.organization_id); db.add(project); db.commit(); db.refresh(project)
    return project

def _create_and_start(db,user,name,url,mode,background_tasks,scanner_family="web",auth_mode="none", auth_headers=None):
    project=_system_project(db,user)
    target=db.query(Target).filter(Target.project_id==project.id,Target.url==url,Target.target_type==scanner_family).first()
    if not target:
        target=Target(name=url.split('/')[2],target_type=scanner_family,url=url,project=project); db.add(target); db.commit(); db.refresh(target)
    scan=create_scan(db,target,MODE_PROFILE.get(mode,mode),scanner_family,name,mode,auth_mode)
    background_tasks.add_task(_run,scan.id,auth_headers)
    return scan

def _run(scan_id, auth_headers=None):
    db=SessionLocal()
    try:
        scan=db.get(Scan, scan_id)
        if not scan:
            return
        try:
            execute_scan(db, scan, auth_headers)
        except Exception as exc:
            scan.status = ScanStatus.failed
            scan.progress = min(max(scan.progress or 0, 0), 99)
            db.commit()
            try:
                log_scan(db, scan, f"Assessment failed: {type(exc).__name__}: {exc}", scan.progress, "ERROR")
            except Exception:
                db.rollback()
    finally:
        db.close()

def _persist_failed_analysis(db, user, assessment_name: str, target_url: str, scanner_family: str, error: str):
    project=_system_project(db,user)
    target=db.query(Target).filter(Target.project_id==project.id, Target.url==target_url, Target.target_type==scanner_family).first()
    if not target:
        safe_name=target_url.split('/')[2] if '://' in target_url and len(target_url.split('/'))>2 else target_url[:190]
        target=Target(name=safe_name,target_type=scanner_family,url=target_url,project=project)
        db.add(target); db.commit(); db.refresh(target)
    scan=create_scan(db,target,'standard',scanner_family,assessment_name,'standard','none')
    scan.status=ScanStatus.failed; scan.progress=0; scan.completed_at=datetime.now(timezone.utc).replace(tzinfo=None); db.commit()
    try: log_scan(db,scan,f'Analysis failed: {error}',0,'ERROR')
    except Exception: db.rollback()
    db.refresh(scan)
    return scan

def capture_target_screenshot(target_url: str, scan_id: int) -> str | None:
    """Capture a best-effort screenshot for HTTP targets when Playwright/Chromium is available."""
    try:
        from pathlib import Path
        from playwright.sync_api import sync_playwright
        root = Path(__file__).resolve().parents[2] / "runtime" / "artifacts"
        root.mkdir(parents=True, exist_ok=True)
        filename = root / f"finding-{scan_id}-evidence.png"
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            page = browser.new_page(ignore_https_errors=True, viewport={"width": 1440, "height": 900})
            page.goto(target_url, wait_until="domcontentloaded", timeout=15000)
            page.screenshot(path=str(filename), full_page=True)
            browser.close()
        return f"/artifacts/{filename.name}"
    except Exception:
        return None

def _persist_completed_analysis(db, user, assessment_name: str, target_url: str, scanner_family: str, result: dict):
    project=_system_project(db,user)
    target=db.query(Target).filter(Target.project_id==project.id, Target.url==target_url, Target.target_type==scanner_family).first()
    if not target:
        safe_name=target_url.split('/')[2] if '://' in target_url and len(target_url.split('/'))>2 else target_url[:190]
        target=Target(name=safe_name,target_type=scanner_family,url=target_url,project=project)
        db.add(target); db.commit(); db.refresh(target)
    scan=create_scan(db,target,'standard',scanner_family,assessment_name,'balanced','none')
    scan.status=ScanStatus.running; db.commit(); log_scan(db,scan,'Analysis started',15)
    findings=result.get('findings') if isinstance(result,dict) else None
    if not isinstance(findings,list):
        findings=result.get('flags') if isinstance(result,dict) else None
    if not isinstance(findings,list): findings=[]
    valid={x.value:x for x in Severity}
    for item in findings:
        if not isinstance(item,dict): continue
        item = normalize_finding(item, scanner_family, target_url)
        sev=valid.get(str(item.get('severity','info')).lower(),Severity.info)
        owasp=item.get('owasp_mapping',item.get('owasp',''))
        framework=item.get('framework_mapping','')
        cwe=item.get('cwe','')
        if isinstance(owasp,(list,tuple)): owasp=', '.join(map(str,owasp))
        if isinstance(framework,(list,tuple)): framework=', '.join(map(str,framework))
        if isinstance(cwe,(list,tuple)): cwe=', '.join(map(str,cwe))
        evidence = dict(item.get("evidence") or {})
        evidence.setdefault("references", item.get("references") or ["https://www.first.org/cvss/calculator/4.0","https://owasp.org/Top10/2025/"])
        evidence.setdefault("risk_reason", item.get("risk_reason") or f"The scanner classified this as {item.get('severity','info').upper()} based on the captured evidence.")
        evidence.setdefault("parameter", item.get("affected_parameter"))
        evidence.setdefault("component", item.get("affected_component"))
        evidence.setdefault("payload", item.get("test_payload") or "Not captured (passive analysis)")
        evidence.setdefault("request", item.get("http_request"))
        evidence.setdefault("response", item.get("http_response"))
        evidence.setdefault("screenshot", item.get("screenshot"))
        scan.findings.append(Finding(
            finding_key=item.get('finding_key','ANALYSIS'), title=item.get('title','Security finding'), severity=sev,
            confidence=item.get('confidence','potential'), category=item.get('category',scanner_family),
            endpoint=item.get('endpoint') or target_url, description=item.get('description') or "No description was captured by the analyzer; manual validation is recommended.", evidence=evidence,
            remediation=item.get('remediation') or "Review the mapped control, confirm the evidence in the application context, and implement the recommended remediation.", cvss_v4=str(item.get('cvss_v4',item.get('cvss',SEV_SCORE.get(str(item.get('severity','info')).lower(),'0.0')))),
            cvss_vector_v4=item.get('cvss_vector_v4'), cvss_source=item.get('cvss_source','severity-normalized'),
            owasp_mapping=owasp, framework_mapping=framework, cwe=cwe or infer_cwe(item.get('title',''), item.get('category',scanner_family), scanner_family), status='open', verification='unreviewed', classification='need_further_investigate',
            created_at=datetime.now(timezone.utc).replace(tzinfo=None), updated_at=datetime.now(timezone.utc).replace(tzinfo=None)))
    try:
        if target_url.startswith(('http://','https://')) and scan.findings:
            shot=capture_target_screenshot(target_url, scan.id)
            if shot:
                for ff in scan.findings:
                    ev=dict(ff.evidence or {}); ev.setdefault('screenshot', shot); ff.evidence=ev
    except Exception:
        pass
    db.commit(); log_scan(db,scan,f'Analysis completed with {len(scan.findings)} findings',100); scan.status=ScanStatus.completed; scan.progress=100; scan.completed_at=datetime.now(timezone.utc).replace(tzinfo=None); db.commit(); db.refresh(scan)
    return scan

@router.post("/web/assessment")
def web_assessment(body:WebAssessment, bg:BackgroundTasks, db:Session=Depends(get_db), user:User=Depends(get_local_operator)):
    scan=_create_and_start(db,user,body.assessment_name,str(body.target_url),body.mode,bg,"web","none")
    return {"scan_id":scan.id,"assessment_name":scan.assessment_name,"status":scan.status.value}

@router.post("/web/authenticated")
def web_auth(body:AuthAssessment, bg:BackgroundTasks, db:Session=Depends(get_db), user:User=Depends(get_local_operator)):
    # Credentials are accepted for an authorized authenticated assessment. The current engine stores only mode metadata, never the password.
    import base64
    basic=base64.b64encode(f"{body.username}:{body.password}".encode()).decode()
    scan=_create_and_start(db,user,body.assessment_name,str(body.target_url),body.mode,bg,"web","authenticated", {"Authorization":f"Basic {basic}"})
    return {"scan_id":scan.id,"assessment_name":scan.assessment_name,"status":scan.status.value,"auth_user":body.username}

@router.get("/assessments")
def assessments(db:Session=Depends(get_db), user:User=Depends(get_local_operator)):
    rows=db.query(Scan).join(Target).join(Project).filter(Project.organization_id==user.organization_id).order_by(Scan.id.desc()).limit(300).all()
    return [{"id":s.id,"assessment_name":s.assessment_name or f"Assessment #{s.id}","status":s.status.value,"mode":s.mode,"auth_mode":s.auth_mode,"target_url":s.target_url_snapshot or s.target.url,"scanner_family":s.scanner_family,"progress":s.progress} for s in rows]

@router.get("/overview")
def overview(scan_id:int|None=None, db:Session=Depends(get_db), user:User=Depends(get_local_operator)):
    scans=db.query(Scan).join(Target).join(Project).filter(Project.organization_id==user.organization_id).all()
    findings_q=db.query(Finding).join(Scan,Finding.scan_id==Scan.id).join(Target,Scan.target_id==Target.id).join(Project,Target.project_id==Project.id).filter(Project.organization_id==user.organization_id)
    if scan_id: findings_q=findings_q.filter(Finding.scan_id==scan_id)
    findings=findings_q.all()
    counts={k:0 for k in ["critical","high","medium","low","info"]}
    status_counts={k:0 for k in ["open","closed","risk_accepted","ignored","false_positive","reopened"]}
    family_counts={}
    for f in findings:
        counts[f.severity.value]+=1
        status_counts[f.status]=status_counts.get(f.status,0)+1
        family_counts[f.scan.scanner_family]=family_counts.get(f.scan.scanner_family,0)+1
    by_date={}
    for f in findings:
        key=f.created_at.date().isoformat() if f.created_at else "unknown"
        by_date[key]=by_date.get(key,0)+1
    return {"total_scans":len(scans),"completed_scans":sum(1 for s in scans if s.status.value=="completed"),"total_findings":len(findings),"open_issues":sum(1 for f in findings if f.status in {"open","reopened"}),"closed_issues":status_counts.get("closed",0),"risk":counts,"status":status_counts,"family":family_counts,"by_date":by_date,"selected_scan_id":scan_id}

@router.get("/findings")
def console_findings(scan_id:int|None=None, severity:str|None=None, scanner_family:str|None=None, status:str|None=None, finding:int|None=None, db:Session=Depends(get_db), user:User=Depends(get_local_operator)):
    q=db.query(Finding).join(Scan,Finding.scan_id==Scan.id).join(Target,Scan.target_id==Target.id).join(Project,Target.project_id==Project.id).filter(Project.organization_id==user.organization_id)
    if scan_id: q=q.filter(Finding.scan_id==scan_id)
    if severity: q=q.filter(Finding.severity==severity.lower())
    if scanner_family: q=q.filter(Scan.scanner_family==scanner_family)
    if status: q=q.filter(Finding.status==status.lower())
    if finding: q=q.filter(Finding.id==finding)
    rows=q.order_by(Finding.id.desc()).all()
    return [{"id":f.id,"scan_id":f.scan_id,"finding_key":f.finding_key,"title":f.title,"severity":f.severity.value,"confidence":f.confidence,"verification":f.verification or "unreviewed","classification":f.classification or "need_further_investigate","category":f.category,"endpoint":f.endpoint,"description":f.description,"remediation":f.remediation,"cvss_v4":f.cvss_v4 or SEV_SCORE.get(f.severity.value,"0.0"),"cvss_vector_v4":f.cvss_vector_v4,"cvss_source":f.cvss_source or "severity-normalized","owasp_mapping":_effective_owasp(f),"framework_mapping":f.framework_mapping or "-","cwe":_effective_cwe(f),"status":f.status,"affected_parameter":(f.evidence or {}).get("parameter") or (f.evidence or {}).get("affected_parameter") or "-","affected_component":(f.evidence or {}).get("component") or (f.evidence or {}).get("affected_component") or f.category,"test_payload":(f.evidence or {}).get("payload") or (f.evidence or {}).get("test_payload") or "-","scanner_family":f.scan.scanner_family,"created_at":f.created_at} for f in rows]

@router.get("/findings/{finding_id}")
def finding_detail(finding_id:int, db:Session=Depends(get_db), user:User=Depends(get_local_operator)):
    f=db.query(Finding).join(Scan,Finding.scan_id==Scan.id).join(Target,Scan.target_id==Target.id).join(Project,Target.project_id==Project.id).filter(Finding.id==finding_id,Project.organization_id==user.organization_id).first()
    if not f: raise HTTPException(404,"Finding not found")
    return {"id":f.id,"scan_id":f.scan_id,"finding_key":f.finding_key,"title":f.title,"severity":f.severity.value,"confidence":f.confidence,"category":f.category,"endpoint":f.endpoint,"description":f.description,"remediation":f.remediation,"cvss_v4":f.cvss_v4 or SEV_SCORE.get(f.severity.value,"0.0"),"owasp_mapping":_effective_owasp(f),"framework_mapping":f.framework_mapping,"cwe":_effective_cwe(f),"status":f.status,"verification":f.verification or "unreviewed","classification":f.classification or "need_further_investigate","cvss_vector_v4":f.cvss_vector_v4 or "Not calculated from vector evidence","cvss_source":f.cvss_source or "severity-normalized","risk_reason":(f.evidence or {}).get("business_impact") or (f.evidence or {}).get("risk_reason"),"business_impact":(f.evidence or {}).get("business_impact") or (f.evidence or {}).get("risk_reason"),"affected_parameter":(f.evidence or {}).get("parameter") or (f.evidence or {}).get("affected_parameter") or "-","affected_component":(f.evidence or {}).get("component") or (f.evidence or {}).get("affected_component") or f.category,"test_payload":(f.evidence or {}).get("payload") or (f.evidence or {}).get("test_payload") or "-","http_request":(f.evidence or {}).get("request") or (f.evidence or {}).get("http_request") or "Not captured","http_response":(f.evidence or {}).get("response") or (f.evidence or {}).get("http_response") or "Not captured","screenshot":(f.evidence or {}).get("screenshot"),"references":(f.evidence or {}).get("references") or [],"affected_url":f.endpoint,"test_payload":(f.evidence or {}).get("payload") or (f.evidence or {}).get("test_payload") or "-","evidence":f.evidence}

@router.patch("/findings/{finding_id}")
def update_finding(finding_id:int, body:dict, db:Session=Depends(get_db), user:User=Depends(get_local_operator)):
    f=db.query(Finding).join(Scan,Finding.scan_id==Scan.id).join(Target,Scan.target_id==Target.id).join(Project,Target.project_id==Project.id).filter(Finding.id==finding_id,Project.organization_id==user.organization_id).first()
    if not f: raise HTTPException(404,"Finding not found")
    for key in ["title","severity","status","verification","classification","description","remediation","cvss_v4","cvss_vector_v4","cvss_source","owasp_mapping","framework_mapping","cwe","endpoint","category"]:
        if key in body and body[key] is not None:
            if key=="severity": setattr(f,key,Severity(str(body[key]).lower()))
            else: setattr(f,key,body[key])
    evidence=dict(f.evidence or {})
    for key in ["affected_parameter","affected_component","test_payload","business_impact","risk_reason","http_request","http_response","screenshot","references"]:
        if key in body and body[key] is not None:
            target_key={"affected_parameter":"parameter","affected_component":"component","test_payload":"payload","business_impact":"business_impact","risk_reason":"risk_reason","http_request":"request","http_response":"response"}.get(key,key)
            evidence[target_key]=body[key]
    f.evidence=evidence
    f.updated_at=datetime.now(timezone.utc).replace(tzinfo=None); db.commit(); return {"ok":True,"id":f.id,"updated_at":f.updated_at.isoformat() if f.updated_at else None,"event":"finding-updated"}

@router.delete("/findings/{finding_id}")
def delete_finding(finding_id:int, db:Session=Depends(get_db), user:User=Depends(get_local_operator)):
    f=db.query(Finding).join(Scan,Finding.scan_id==Scan.id).join(Target,Scan.target_id==Target.id).join(Project,Target.project_id==Project.id).filter(Finding.id==finding_id,Project.organization_id==user.organization_id).first()
    if not f: raise HTTPException(404,"Finding not found")
    db.delete(f); db.commit(); return {"ok":True,"deleted":finding_id,"event":"finding-deleted"}

@router.post("/api/rest")
def rest_scan(body:ApiEndpoint, db:Session=Depends(get_db), user:User=Depends(get_local_operator)):
    result=__import__('app.api.api_security',fromlist=['_engine'])._engine.run(str(body.endpoint),"standard").__dict__
    payload={"findings":result.get("findings",[]),"inventory":result.get("inventory",[]),"type":"REST","target_url":str(body.endpoint)}
    scan=_persist_completed_analysis(db,user,'REST API Security Analysis',str(body.endpoint),'api',payload); payload['scan_id']=scan.id; return payload

@router.post("/api/graphql")
def graphql_scan(body:ApiText, db:Session=Depends(get_db), user:User=Depends(get_local_operator)):
    from app.scanners.api.deep.engine import APIDeepEngine
    try: obj=json.loads(body.content)
    except Exception as e: raise HTTPException(400,"GraphQL schema must be valid JSON introspection output") from e
    result=APIDeepEngine().analyze_graphql(obj); scan=_persist_completed_analysis(db,user,'GraphQL Security Analysis','inline://graphql','api',result); result['scan_id']=scan.id; return result

@router.post("/api/soap")
def soap_scan(body:ApiText, db:Session=Depends(get_db), user:User=Depends(get_local_operator)):
    from app.scanners.api.deep.engine import APIDeepEngine
    result=APIDeepEngine().analyze_soap(body.content); scan=_persist_completed_analysis(db,user,'SOAP Security Analysis','inline://soap','api',result); result['scan_id']=scan.id; return result

@router.post("/api/grpc")
def grpc_scan(body:ApiText, db:Session=Depends(get_db), user:User=Depends(get_local_operator)):
    from app.scanners.api.deep.engine import APIDeepEngine
    result=APIDeepEngine().analyze_grpc(body.content, False); scan=_persist_completed_analysis(db,user,'gRPC Security Analysis','inline://grpc','api',result); result['scan_id']=scan.id; return result

@router.post("/api/swagger")
def swagger_scan(body:ApiText, db:Session=Depends(get_db), user:User=Depends(get_local_operator)):
    from app.scanners.api.deep.engine import APIDeepEngine
    try: obj=json.loads(body.content)
    except Exception as e: raise HTTPException(400,"Swagger/OpenAPI must be valid JSON") from e
    result=APIDeepEngine().analyze_openapi(obj, []); scan=_persist_completed_analysis(db,user,'OpenAPI Security Analysis','inline://openapi','api',result); result['scan_id']=scan.id; return result

@router.post("/api/json-code")
def json_code_scan(body:ApiText, db:Session=Depends(get_db), user:User=Depends(get_local_operator)):
    text=body.content.lower()
    hits=[]
    for term,label in [("password","Sensitive credential field"),("secret","Potential secret field"),("http://","Insecure HTTP reference"),("debug","Debug configuration indicator")]:
        if term in text: hits.append({"indicator":term,"title":label,"severity":"medium"})
    result={"findings":hits,"summary":f"Detected {len(hits)} code/config indicators"}; scan=_persist_completed_analysis(db,user,'JSON / Code Security Analysis','inline://json-code','api',result); result['scan_id']=scan.id; return result

@router.post("/api/discover")
def api_discover(body: ApiEndpoint, db: Session = Depends(get_db), user: User = Depends(get_local_operator)):
    endpoint = str(body.endpoint)
    try:
        result = APIScanner().run(endpoint, "deep")
        payload = {"findings": result.findings, "inventory": result.inventory, "target_url": endpoint, "type": "API Discovery"}
        scan = _persist_completed_analysis(db, user, "API Endpoint Discovery", endpoint, "api", payload)
        payload["scan_id"] = scan.id
        return payload
    except Exception as exc:
        scan = _persist_failed_analysis(db, user, "API Endpoint Discovery", endpoint, "api", f"discovery failed: {type(exc).__name__}: {exc}")
        return {"status":"failed","target_url":endpoint,"scan_id":scan.id,"error":"API discovery could not complete."}

@router.post("/sca/repository")
def sca_repo(body:SCARepo, db:Session=Depends(get_db), user:User=Depends(get_local_operator)):
    result=SCAScanner().scan_path(body.source_path,"deep").__dict__; scan=_persist_completed_analysis(db,user,'SCA Repository Analysis',f'file://{body.source_path}','sca',result); result['scan_id']=scan.id; return result

@router.post("/sca/manifest")
def sca_manifest(body:SCACombined, db:Session=Depends(get_db), user:User=Depends(get_local_operator)):
    import tempfile, pathlib
    filename=pathlib.Path(body.filename).name
    with tempfile.TemporaryDirectory() as td:
        path=pathlib.Path(td)/filename
        path.write_text(body.content or "",encoding="utf-8")
        result=SCAScanner().scan_path(str(path),"standard").__dict__; scan=_persist_completed_analysis(db,user,f'SCA {filename} Analysis',f'inline://{filename}','sca',result); result['scan_id']=scan.id; return result

@router.post("/sca/url")
async def sca_url(body:SCAUrl, db:Session=Depends(get_db), user:User=Depends(get_local_operator)):
    target_url=str(body.target_url)
    try:
        data=await fetch_url(target_url)
    except Exception as exc:
        scan=_persist_failed_analysis(db,user,'SCA Remote Technology Analysis',target_url,'sca',f'target fetch failed: {type(exc).__name__}: {exc}')
        return {"status":"failed","target_url":target_url,"error":"Target could not be fetched for SCA technology analysis.","reason":str(exc),"scan_id":scan.id}
    headers={k.lower():v for k,v in data["headers"].items()}
    tech=[]
    for k in ["server","x-powered-by","x-aspnet-version"]:
        if headers.get(k): tech.append({"header":k,"value":headers[k]})
    text_prefix=data.get('text_prefix','').lower()
    patterns=[('next.js','__next_data__','Next.js'),('react','react','React'),('vue','vue','Vue.js'),('angular','ng-version','Angular'),('nuxt','__nuxt__','Nuxt'),('django','csrfmiddlewaretoken','Django'),('laravel','laravel_session','Laravel'),('spring','whitelabel error page','Spring Boot'),('express','x-powered-by','Express')]
    frameworks=[]
    for key,needle,label in patterns:
        if needle in text_prefix or needle in str(headers).lower(): frameworks.append(label)
    result={"status":"completed","target_url":data["url"],"status_code":data["status_code"],"technology_headers":tech,"framework_indicators":frameworks,"disclaimer":"Remote URL framework/package enumeration is heuristic unless source or package metadata is exposed."}; scan=_persist_completed_analysis(db,user,'SCA Remote Technology Analysis',target_url,'sca',result); result['scan_id']=scan.id; return result

@router.post("/csp")
async def csp(body:TargetAnalyze, db:Session=Depends(get_db), user:User=Depends(get_local_operator)):
    target_url=str(body.target_url)
    try:
        data=await fetch_url(target_url)
    except Exception as exc:
        scan=_persist_failed_analysis(db,user,'CSP Analyzer',target_url,'specialized',f'target fetch failed: {type(exc).__name__}: {exc}')
        return {"status":"failed","target_url":target_url,"error":"Target could not be fetched for CSP analysis.","reason":str(exc),"headers":{},"findings":[],"scan_id":scan.id}
    h={k.lower():v for k,v in data["headers"].items()}; r=analyze_csp(h.get("content-security-policy"),h.get("content-security-policy-report-only")); r.update({"status":"completed","target_url":data["url"],"status_code":data["status_code"],"headers":data.get("headers",{})}); scan=_persist_completed_analysis(db,user,'CSP Analyzer',target_url,'specialized',r); r['scan_id']=scan.id; return r

@router.post("/csp/directives")
def csp_directives(body:ApiText, db:Session=Depends(get_db), user:User=Depends(get_local_operator)):
    r=analyze_csp(body.content,None); r["target_url"]="directive-only"; scan=_persist_completed_analysis(db,user,'CSP Directive Analysis','inline://csp','specialized',r); r['scan_id']=scan.id; return r

@router.post("/jwt")
def jwt(body:ApiText, db:Session=Depends(get_db), user:User=Depends(get_local_operator)):
    r=audit_jwt(body.content); scan=_persist_completed_analysis(db,user,'JWT Token Analysis','inline://jwt','specialized',r); r['scan_id']=scan.id; return r


class AIConsoleRequest(BaseModel):
    target_url: HttpUrl
    provider: str = "generic-json"
    headers: dict[str,str] = {}
    prompt_field: str = "prompt"
    query_field: str = "query"
    message_field: str = "message"
    method: str = "POST"
    max_turns: int = Field(default=3, ge=1, le=5)


class AIStartRequest(BaseModel):
    kind: str = Field(pattern="^(llm|rag|agent|redteam)$")
    target_url: HttpUrl
    provider: str = "generic-json"
    headers: dict[str,str] = {}
    prompt_field: str = "prompt"
    query_field: str = "query"
    message_field: str = "message"
    max_turns: int = Field(default=3, ge=1, le=5)


def _run_ai_assessment(scan_id: int, req: dict):
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            return
        scan.status = ScanStatus.running; scan.progress = 5; db.commit()
        log_scan(db, scan, "AI security assessment started", 5)
        kind=req.get("kind"); url=req.get("target_url"); headers=req.get("headers") or {}
        import asyncio
        async def execute():
            if kind in {"llm","redteam"}:
                from app.scanners.ai_v3.campaign import run_adaptive_campaign
                from app.scanners.ai_v3.models import CampaignConfig
                result=await run_adaptive_campaign(CampaignConfig(url,req.get("provider","generic-json"),"POST",req.get("prompt_field","prompt"),headers,{},15.0,req.get("max_turns",3)))
                return {"target":result.target,"provider":result.provider,"metadata":result.metrics,"findings":result.findings,"observations":[o.__dict__ for o in result.steps]}
            if kind=="rag":
                from app.scanners.rag import RAGSecurityScanner, RAGTarget
                r=await RAGSecurityScanner().run(RAGTarget(url,"POST",req.get("query_field","query"),headers,{},15.0,None,None))
                return {"target":r.target,"metadata":r.metadata,"findings":r.findings,"probes":[p.__dict__ for p in r.probes]}
            from app.scanners.agent import AgentSecurityScanner, AgentTarget
            r=await AgentSecurityScanner().run(AgentTarget(url,"POST",req.get("message_field","message"),headers,{},15.0))
            return {"target":r.target,"metadata":r.metadata,"findings":r.findings,"probes":[p.__dict__ for p in r.probes]}
        result=asyncio.run(execute())
        # replace any findings created by stale state only for this scan
        for item in (result.get("findings") or []):
            if isinstance(item,dict):
                item=normalize_finding(item, scan.scanner_family, url)
                sev=Severity(str(item.get("severity","info")).lower()) if str(item.get("severity","info")).lower() in {x.value for x in Severity} else Severity.info
                ev=dict(item.get("evidence") or {}); ev.setdefault("references",item.get("references") or [])
                ev.setdefault("request",item.get("http_request")); ev.setdefault("response",item.get("http_response")); ev.setdefault("payload",item.get("test_payload")); ev.setdefault("parameter",item.get("affected_parameter")); ev.setdefault("component",item.get("affected_component"))
                scan.findings.append(Finding(finding_key=item.get("finding_key","AI"),title=item.get("title","AI security finding"),severity=sev,confidence=item.get("confidence","potential"),category=item.get("category",kind),endpoint=item.get("endpoint") or url,description=item.get("description") or "AI security indicator requiring contextual validation.",evidence=ev,remediation=item.get("remediation") or "Review model policy, data boundary and least-privilege controls.",cvss_v4=str(item.get("cvss_v4") or SEV_SCORE[sev.value]),cvss_vector_v4=item.get("cvss_vector_v4"),cvss_source=item.get("cvss_source","severity-normalized"),owasp_mapping=item.get("owasp_mapping"),framework_mapping=item.get("framework_mapping"),cwe=item.get("cwe") or infer_cwe(item.get("title",""),item.get("category",kind),kind),status="open",verification="unreviewed",classification="need_further_investigate",created_at=datetime.now(timezone.utc).replace(tzinfo=None),updated_at=datetime.now(timezone.utc).replace(tzinfo=None)))
        scan.progress=100;scan.status=ScanStatus.completed;scan.completed_at=datetime.now(timezone.utc).replace(tzinfo=None);db.commit();log_scan(db,scan,f"AI security assessment completed with {len(scan.findings)} findings",100);db.commit()
    except Exception as exc:
        scan=db.get(Scan, scan_id) if 'scan' in locals() else None
        if scan:
            scan.status=ScanStatus.failed;scan.completed_at=datetime.now(timezone.utc).replace(tzinfo=None);db.commit()
            try: log_scan(db,scan,f"AI assessment failed: {type(exc).__name__}: {exc}",scan.progress or 0,"ERROR")
            except Exception: db.rollback()
    finally: db.close()

@router.post("/ai/start")
def ai_start(body:AIStartRequest,bg:BackgroundTasks,db:Session=Depends(get_db),user:User=Depends(get_local_operator)):
    project=_system_project(db,user); target_url=str(body.target_url)
    family={"llm":"ai","redteam":"ai","rag":"rag","agent":"agent"}[body.kind]
    target=db.query(Target).filter(Target.project_id==project.id,Target.url==target_url,Target.target_type==family).first()
    if not target:
        target=Target(name=target_url.split('/')[2],target_type=family,url=target_url,project=project);db.add(target);db.commit();db.refresh(target)
    scan=create_scan(db,target,"standard",family, f"{body.kind.upper()} Security Assessment", "balanced","none")
    bg.add_task(_run_ai_assessment,scan.id,body.model_dump())
    log_scan(db,scan,"Assessment queued",0);db.commit()
    return {"scan_id":scan.id,"status":scan.status.value,"scanner_family":family}

@router.post("/ai/llm")
async def console_ai_llm(body: AIConsoleRequest, db:Session=Depends(get_db), user:User=Depends(get_local_operator)):
    from app.scanners.ai_v2 import CampaignRequest, run_campaign, provider_for
    from app.scanners.ai_v3.campaign import run_adaptive_campaign
    from app.scanners.ai_v3.models import CampaignConfig
    try: provider_for(body.provider)
    except ValueError as exc: raise HTTPException(400,str(exc))
    result=await run_adaptive_campaign(CampaignConfig(str(body.target_url),body.provider,body.method,body.prompt_field,body.headers,{},15.0,body.max_turns))
    payload={"target":result.target,"provider":result.provider,"metadata":result.metrics,"findings":result.findings,"observations":[o.__dict__ for o in result.steps]}
    scan=_persist_completed_analysis(db,user,"LLM Security Assessment",str(body.target_url),"ai",payload); payload["scan_id"]=scan.id; return payload

@router.post("/ai/rag")
async def console_ai_rag(body: AIConsoleRequest, db:Session=Depends(get_db), user:User=Depends(get_local_operator)):
    from app.scanners.rag import RAGSecurityScanner, RAGTarget
    result=await RAGSecurityScanner().run(RAGTarget(str(body.target_url),body.method,body.query_field,body.headers,{},15.0,None,None))
    payload={"target":result.target,"metadata":result.metadata,"findings":result.findings,"probes":[p.__dict__ for p in result.probes]}
    scan=_persist_completed_analysis(db,user,"RAG Security Assessment",str(body.target_url),"rag",payload); payload["scan_id"]=scan.id; return payload

@router.post("/ai/agent")
async def console_ai_agent(body: AIConsoleRequest, db:Session=Depends(get_db), user:User=Depends(get_local_operator)):
    from app.scanners.agent import AgentSecurityScanner, AgentTarget
    result=await AgentSecurityScanner().run(AgentTarget(str(body.target_url),body.method,body.message_field,body.headers,{},15.0))
    payload={"target":result.target,"metadata":result.metadata,"findings":result.findings,"probes":[p.__dict__ for p in result.probes]}
    scan=_persist_completed_analysis(db,user,"Agent Security Assessment",str(body.target_url),"agent",payload); payload["scan_id"]=scan.id; return payload

@router.post("/ai/redteam")
async def console_ai_redteam(body: AIConsoleRequest, db:Session=Depends(get_db), user:User=Depends(get_local_operator)):
    from app.scanners.ai_v3 import CampaignConfig, run_adaptive_campaign
    result=await run_adaptive_campaign(CampaignConfig(str(body.target_url),body.provider,body.method,body.prompt_field,body.headers,{},15.0,body.max_turns))
    payload={"target":result.target,"provider":result.provider,"metadata":result.metrics,"findings":result.findings,"observations":[o.__dict__ for o in result.steps]}
    scan=_persist_completed_analysis(db,user,"AI Red Team Assessment",str(body.target_url),"ai",payload); payload["scan_id"]=scan.id; return payload


class MCPConsoleRequest(BaseModel):
    config: dict

@router.post("/ai/mcp")
def console_ai_mcp(body: MCPConsoleRequest, db:Session=Depends(get_db), user:User=Depends(get_local_operator)):
    from app.scanners.agent import AgentSecurityScanner
    result=AgentSecurityScanner().analyze_mcp(body.config)
    scan=_persist_completed_analysis(db,user,"MCP Security Analysis","inline://mcp","mcp",result)
    result["scan_id"]=scan.id
    return result

@router.get("/reports/{scan_id}")
def report_data(scan_id:int, db:Session=Depends(get_db), user:User=Depends(get_local_operator)):
    scan=db.query(Scan).join(Target).join(Project).filter(Scan.id==scan_id,Project.organization_id==user.organization_id).first()
    if not scan: raise HTTPException(404,"Assessment not found")
    rows=[]
    for f in scan.findings:
        ev=f.evidence or {}
        rows.append({
            "issue_id":f.id,"issue_name":f.title,"severity":f.severity.value,
            "cvss_v4":f.cvss_v4 or SEV_SCORE.get(f.severity.value,"0.0"),
            "owasp":f.owasp_mapping or infer_owasp(f.category,f.title,scan.scanner_family),
            "framework":f.framework_mapping or "OWASP / CWE","cwe":(f.cwe if f.cwe and f.cwe != "CWE-693" else infer_cwe(f.title,f.category,scan.scanner_family)),
            "category":f.category,"status":f.status,"confidence":f.confidence,"verification":f.verification or "unreviewed","classification":f.classification or "need_further_investigate","cvss_vector_v4":f.cvss_vector_v4 or "Not calculated from vector evidence","cvss_source":f.cvss_source or "severity-normalized","endpoint":f.endpoint,
            "affected_parameter":ev.get("parameter") or ev.get("affected_parameter") or "-",
            "affected_component":ev.get("component") or ev.get("affected_component") or f.category,
            "test_payload":ev.get("payload") or ev.get("test_payload") or "-",
            "description":f.description,"impact":ev.get("business_impact") or ev.get("risk_reason") or ev.get("impact") or "Review the issue in the business and application context.",
            "remediation":f.remediation or "Review and apply the recommended security control.",
            "http_request":ev.get("request") or ev.get("http_request") or "Not captured",
            "http_response":ev.get("response") or ev.get("http_response") or "Not captured",
            "screenshot":ev.get("screenshot"),
            "references":ev.get("references") or ["https://www.first.org/cvss/calculator/4.0","https://owasp.org/Top10/2025/"],
        })
    return {"assessment":{"id":scan.id,"name":scan.assessment_name,"target":scan.target_url_snapshot or scan.target.url,"mode":scan.mode,"status":scan.status.value,"scanner_family":scan.scanner_family,"started_at":scan.started_at,"completed_at":scan.completed_at},"findings":rows}

def _effective_cwe(f):
    family=f.scan.scanner_family if getattr(f,'scan',None) else 'web'
    inferred=infer_cwe(f.title or '', f.category or '', family)
    current=(f.cwe or '').strip()
    # Always repair generic/legacy CWE assignments using the finding family/title.
    if not current or current in {'CWE-693','CWE-16','CWE-862','CWE-74','CWE-200','CWE-269','CWE-1104'}:
        return inferred
    title=(f.title or '').lower()
    if any(x in title for x in ('jwt','json web token')):
        return 'CWE-347'
    return current

def _effective_owasp(f):
    current=f.owasp_mapping
    inferred=infer_owasp(f.category or '', f.title or '', f.scan.scanner_family if getattr(f,'scan',None) else 'web')
    if not current or current in {'OWASP','OWASP / CWE','-'}:
        return inferred
    title=(f.title or '').lower()
    # Correct legacy generic mappings for strongly identifiable issue families.
    if any(x in title for x in ('csp','content-security-policy','frame-ancestors','cors','security header','clickjacking')):
        return 'A02:2025 - Security Misconfiguration'
    if any(x in title for x in ('sql injection','xss','cross-site scripting','ssrf','ssti','xxe','command injection','path traversal','ldap injection','xpath injection','crlf','header injection')):
        return 'A05:2025 - Injection'
    if any(x in title for x in ('access control','idor','bola','authorization','privilege escalation')):
        return 'A01:2025 - Broken Access Control'
    if any(x in title for x in ('dependency','supply chain','package','library','sbom')):
        return 'A03:2025 - Software Supply Chain Failures'
    if any(x in title for x in ('crypto','tls','weak cipher','hash')):
        return 'A04:2025 - Cryptographic Failures'
    if any(x in title for x in ('workflow','business logic','insecure design')):
        return 'A06:2025 - Insecure Design'
    if any(x in title for x in ('authentication','session','mfa','password','jwt','token')):
        return 'A07:2025 - Authentication Failures'
    if any(x in title for x in ('logging','alerting','audit log')):
        return 'A09:2025 - Security Logging & Alerting Failures'
    if f.scan.scanner_family == 'api' and current.startswith('A'):
        return inferred
    if f.scan.scanner_family in {'ai','rag','agent','mcp'} and current.startswith('A'):
        return inferred
    return current

def _report_rows(rows):
    headers=["Issue ID","Issue Name","Severity","CVSS v4.0","CVSS Source","CVSS Vector V4","OWASP","Framework","CWE","Category","Status","Verification","Classification","Affected URL","Affected Parameter","Affected Component","Description","Impact","Remediation","Test Payload","HTTP Request","HTTP Response","PoC Screenshot","References"]
    values=[[r["issue_id"],r["issue_name"],r["severity"],r["cvss_v4"],r.get("cvss_source",""),r.get("cvss_vector_v4") or "Not provided",r["owasp"],r["framework"],r["cwe"],r["category"],r["status"],r.get("verification","unreviewed"),r.get("classification","need_further_investigate"),r["endpoint"],r["affected_parameter"],r["affected_component"],r["description"],r["impact"],r["remediation"],r["test_payload"],r["http_request"],r["http_response"],r.get("screenshot") or "", " | ".join(str(x) for x in r.get("references",[]))] for r in rows]
    return headers, values

@router.get("/reports/{scan_id}/export/{fmt}")
def report_export(scan_id:int, fmt:str, db:Session=Depends(get_db), user:User=Depends(get_local_operator)):
    data=report_data(scan_id,db,user); rows=data["findings"]; headers,values=_report_rows(rows)
    filename=f'aegisx-assessment-{scan_id}'
    if fmt=="json": return Response(json.dumps(data,default=str,indent=2),media_type="application/json",headers={"Content-Disposition":f'attachment; filename="{filename}.json"'})
    if fmt=="csv":
        buf=io.StringIO(); w=csv.writer(buf); w.writerow(headers); w.writerows(values); return Response(buf.getvalue(),media_type="text/csv",headers={"Content-Disposition":f'attachment; filename="{filename}.csv"'})
    if fmt=="xls":
        def cell(v): return f'<Cell><Data ss:Type="String">{html_lib.escape(str(v or ""))}</Data></Cell>'
        xml='<?xml version="1.0"?><Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet" xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet"><Styles><Style ss:ID="hdr"><Font ss:Bold="1"/></Style></Styles><Worksheet ss:Name="Findings"><Table><Row ss:StyleID="hdr">'+''.join(cell(h) for h in headers)+'</Row>'
        for row in values: xml+='<Row>'+''.join(cell(v) for v in row)+'</Row>'
        xml+='</Table></Worksheet></Workbook>'
        return Response(xml,media_type="application/vnd.ms-excel",headers={"Content-Disposition":f'attachment; filename="{filename}.xls"'})
    if fmt=="html":
        parts=['<!doctype html><html><head><meta charset="utf-8"><title>AegisX Security Assessment</title><style>body{font-family:Inter,Arial;background:#07111f;color:#e8f1f5;padding:36px}h1,h2{margin:0 0 8px}.cover,.finding{background:#0b1826;border:1px solid #28445d;border-radius:14px;padding:18px;margin:0 0 14px}.meta{color:#91a8ba;font-size:12px}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}.box{background:#07121e;border:1px solid #18334a;border-radius:9px;padding:10px}.box span{display:block;color:#7190a6;font-size:9px;text-transform:uppercase}.box b{display:block;margin-top:4px}.sev{font-weight:800;text-transform:uppercase}.sev.critical{color:#ff6b7e}.sev.high{color:#ff8290}.sev.medium{color:#e3ca4e}.sev.low{color:#52d78d}.sev.info{color:#63bdf1}pre{background:#040a11;border:1px solid #182f45;padding:10px;white-space:pre-wrap;overflow:auto;font-size:10px}details{margin-top:10px}</style></head><body>']
        parts.append(f'<section class="cover"><h1>{html_lib.escape(data["assessment"]["name"] or "AegisX Security Assessment")}</h1><div class="meta">{html_lib.escape(data["assessment"]["target"])}</div><div class="grid" style="margin-top:14px"><div class="box"><span>Status</span><b>{html_lib.escape(data["assessment"]["status"])}</b></div><div class="box"><span>Mode</span><b>{html_lib.escape(data["assessment"]["mode"])}</b></div><div class="box"><span>Security Domain</span><b>{html_lib.escape(data["assessment"].get("scanner_family","security"))}</b></div><div class="box"><span>Findings</span><b>{len(rows)}</b></div></div></section>')
        for r in rows:
            parts.append(f'<section class="finding"><div style="display:flex;justify-content:space-between;gap:10px"><h2>AX-{r["issue_id"]} · {html_lib.escape(r["issue_name"])}</h2><strong class="sev {r["severity"]}">{r["severity"]}</strong></div><div class="grid"><div class="box"><span>CVSS v4.0</span><b>{html_lib.escape(str(r["cvss_v4"]))}</b></div><div class="box"><span>CVSS Source</span><b>{html_lib.escape(str(r.get("cvss_source","unknown")))}</b></div><div class="box"><span>CWE</span><b>{html_lib.escape(str(r["cwe"]))}</b></div><div class="box"><span>OWASP</span><b>{html_lib.escape(str(r["owasp"]))}</b></div><div class="box"><span>Status</span><b>{html_lib.escape(str(r["status"]))}</b></div><div class="box"><span>Verification</span><b>{html_lib.escape(str(r.get("verification","unreviewed")))}</b></div><div class="box"><span>Classification</span><b>{html_lib.escape(str(r.get("classification","need_further_investigate")))}</b></div></div><p>{html_lib.escape(str(r["description"]))}</p><p><b>Impact:</b> {html_lib.escape(str(r["impact"]))}</p><p><b>Remediation:</b> {html_lib.escape(str(r["remediation"]))}</p><details><summary>Evidence & Proof</summary><p><b>Affected URL:</b> {html_lib.escape(str(r["endpoint"]))}</p><p><b>Parameter:</b> {html_lib.escape(str(r["affected_parameter"]))}</p><p><b>Component:</b> {html_lib.escape(str(r["affected_component"]))}</p><p><b>Test Payload:</b></p><pre>{html_lib.escape(str(r["test_payload"]))}</pre><p><b>HTTP Request:</b></p><pre>{html_lib.escape(str(r["http_request"]))}</pre><p><b>HTTP Response:</b></p><pre>{html_lib.escape(str(r["http_response"]))}</pre><p><b>References:</b> {' | '.join(f'<a href="{html_lib.escape(str(x), quote=True)}" target="_blank">{html_lib.escape(str(x))}</a>' for x in r["references"])}</p><p><b>CVSS Vector V4:</b> {html_lib.escape(str(r.get("cvss_vector_v4") or "Not provided"))}</p>{f'<p><b>Proof of Concept Screenshot:</b><br><a href="{html_lib.escape(str(r["screenshot"]), quote=True)}" target="_blank"><img src="{html_lib.escape(str(r["screenshot"]), quote=True)}" alt="PoC screenshot" style="max-width:760px;border:1px solid #29445d;border-radius:10px"></a></p>' if r.get("screenshot") else ''}</details></section>')
        parts.append('</body></html>')
        return Response(''.join(parts),media_type="text/html",headers={"Content-Disposition":f'attachment; filename="{filename}.html"'})
    if fmt=="pdf":
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image, KeepTogether
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_CENTER
        from pathlib import Path
        out=io.BytesIO(); doc=SimpleDocTemplate(out,pagesize=A4,rightMargin=32,leftMargin=32,topMargin=32,bottomMargin=32); styles=getSampleStyleSheet();
        title_style=ParagraphStyle('AegisTitle', parent=styles['Title'], fontSize=22, leading=26, textColor=colors.HexColor('#0b2940'), alignment=TA_CENTER, spaceAfter=8)
        sub_style=ParagraphStyle('AegisSub', parent=styles['Normal'], fontSize=9, textColor=colors.HexColor('#466477'), alignment=TA_CENTER)
        h_style=ParagraphStyle('AegisH', parent=styles['Heading2'], fontSize=15, leading=18, textColor=colors.HexColor('#0b2940'), spaceAfter=6)
        body_style=ParagraphStyle('AegisBody', parent=styles['BodyText'], fontSize=9, leading=13)
        elems=[]
        counts={s:sum(1 for r in rows if r['severity']==s) for s in ('critical','high','medium','low','info')}
        elems += [Paragraph('AEGISX SECURITY ASSESSMENT',title_style),Paragraph(html_lib.escape(data['assessment']['name'] or 'Security Assessment'),h_style),Paragraph(html_lib.escape(data['assessment']['target']),sub_style),Spacer(1,14)]
        cover=[['CRITICAL','HIGH','MEDIUM','LOW','INFO'],[str(counts['critical']),str(counts['high']),str(counts['medium']),str(counts['low']),str(counts['info'])]]
        ct=Table(cover,colWidths=[100]*5,rowHeights=[20,32]); ct.setStyle(TableStyle([('BACKGROUND',(0,0),(0,1),colors.HexColor('#8b101f')),('BACKGROUND',(1,0),(1,1),colors.HexColor('#d92f3f')),('BACKGROUND',(2,0),(2,1),colors.HexColor('#d4b529')),('BACKGROUND',(3,0),(3,1),colors.HexColor('#2eae63')),('BACKGROUND',(4,0),(4,1),colors.HexColor('#3b9bd4')),('TEXTCOLOR',(0,0),(-1,-1),colors.white),('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),('FONTNAME',(0,1),(-1,1),'Helvetica-Bold'),('FONTSIZE',(0,0),(-1,0),7),('FONTSIZE',(0,1),(-1,1),15),('ALIGN',(0,0),(-1,-1),'CENTER'),('VALIGN',(0,0),(-1,-1),'MIDDLE'),('BOX',(0,0),(-1,-1),1,colors.HexColor('#d8e7ee'))]))
        elems += [ct,Spacer(1,12),Paragraph(f"<b>Assessment Status:</b> {html_lib.escape(data['assessment']['status'])} &nbsp;&nbsp; <b>Mode:</b> {html_lib.escape(data['assessment']['mode'])} &nbsp;&nbsp; <b>Total Findings:</b> {len(rows)}",body_style),Spacer(1,16)]
        for idx,r in enumerate(rows):
            elems += [Paragraph(f"AX-{r['issue_id']} · {html_lib.escape(r['issue_name'])}",h_style)]
            meta=[["Severity",r['severity'].upper(),"CVSS v4.0",str(r['cvss_v4'])],["CVSS Source",str(r.get('cvss_source','unknown')),"CVSS Vector",str(r.get('cvss_vector_v4') or 'Not provided')],["CWE",str(r['cwe']),"OWASP",str(r['owasp'])],["Status",str(r['status']),"Verification",str(r.get('verification','unreviewed'))],["Classification",str(r.get('classification','need_further_investigate')),"Category",str(r['category'])]]
            sev_color={'critical':'#8b101f','high':'#d92f3f','medium':'#d4b529','low':'#2eae63','info':'#3b9bd4'}.get(str(r['severity']).lower(),'#607d8b')
            t=Table(meta,colWidths=[75,120,75,240]);t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),colors.HexColor('#eef3f7')),('BACKGROUND',(1,0),(1,0),colors.HexColor(sev_color)),('TEXTCOLOR',(1,0),(1,0),colors.white),('GRID',(0,0),(-1,-1),.35,colors.HexColor('#aebdc7')),('FONTNAME',(0,0),(-1,-1),'Helvetica'),('FONTNAME',(0,0),(0,-1),'Helvetica-Bold'),('FONTSIZE',(0,0),(-1,-1),8),('VALIGN',(0,0),(-1,-1),'TOP')]))
            block=[t,Spacer(1,8),Paragraph('<b>Description</b> '+html_lib.escape(str(r['description'])),body_style),Paragraph('<b>Business Impact</b> '+html_lib.escape(str(r['impact'])),body_style),Paragraph('<b>Remediation</b> '+html_lib.escape(str(r['remediation'])),body_style),Paragraph('<b>Affected URL / Endpoint</b> '+html_lib.escape(str(r['endpoint'])),body_style),Paragraph('<b>Affected Parameter</b> '+html_lib.escape(str(r['affected_parameter'])),body_style),Paragraph('<b>Affected Component</b> '+html_lib.escape(str(r['affected_component'])),body_style),Paragraph('<b>Test Payload</b> '+html_lib.escape(str(r['test_payload'])),styles['Code']),Paragraph('<b>HTTP Request</b><br/>'+html_lib.escape(str(r['http_request']))[:5000],styles['Code']),Paragraph('<b>HTTP Response</b><br/>'+html_lib.escape(str(r['http_response']))[:5000],styles['Code']),Paragraph('<b>References</b> '+' | '.join(f'<link href="{html_lib.escape(str(x), quote=True)}" color="#0b6eaa">{html_lib.escape(str(x))}</link>' for x in r.get('references',[])),body_style)]
            shot=r.get('screenshot')
            if shot:
                candidate=Path(__file__).resolve().parents[1]/'runtime'/'artifacts'/Path(str(shot)).name
                if candidate.exists():
                    try:
                        img=Image(str(candidate)); img.drawHeight=180; img.drawWidth=290; block += [Spacer(1,6),Paragraph('<b>Proof of Concept Screenshot</b>',body_style),img]
                    except Exception:
                        pass
            elems.append(KeepTogether(block))
            if idx<len(rows)-1: elems.append(PageBreak())
        doc.build(elems); out.seek(0); return Response(out.read(),media_type='application/pdf',headers={'Content-Disposition':f'attachment; filename="{filename}.pdf"'})
    raise HTTPException(400,"Unsupported export format")
