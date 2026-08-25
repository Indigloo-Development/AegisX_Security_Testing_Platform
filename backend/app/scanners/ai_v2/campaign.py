import json
import httpx
from .models import CampaignRequest, CampaignResult, ProbeObservation, RetestRequest
from .providers import provider_for, build_payload, extract_text
from .probes import BASE_PROBES
from .classifier import classify


def _excerpt(text: str, size=1000):
    return ' '.join(text.split())[:size]

async def run_campaign(request: CampaignRequest, client: httpx.AsyncClient | None = None) -> CampaignResult:
    provider_for(request.provider)
    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(timeout=request.timeout, follow_redirects=True)
    observations=[]; findings=[]; conversation=[]
    try:
        for probe in BASE_PROBES:
            if probe.turn > request.max_turns: continue
            payload = build_payload(request, probe.prompt, conversation)
            try:
                response = await client.request(request.method, request.target_url, json=payload, headers=request.headers)
                raw=response.text
                try: data=response.json()
                except Exception: data=None
                text=extract_text(data, raw)
                indicators, severity, confidence, notes = classify(probe.category,text)
                observations.append(ProbeObservation(probe.id,probe.category,probe.turn,response.status_code,_excerpt(text),indicators,severity,confidence,notes))
                conversation.extend([{'role':'user','content':probe.prompt},{'role':'assistant','content':text}])
                if indicators and severity != 'info':
                    findings.append({'finding_key':probe.id,'title':f'AI security issue: {probe.category.replace("_"," ").title()}','severity':severity,'confidence':confidence,'category':'AI/LLM Security v2','endpoint':request.target_url,'description':notes,'evidence':{'probe_id':probe.id,'turn':probe.turn,'indicators':indicators,'response_excerpt':_excerpt(text)},'remediation':'Use explicit instruction hierarchy, minimize sensitive context, apply output validation, authorization, and provider-specific safety controls.'})
            except Exception as exc:
                observations.append(ProbeObservation(probe.id,probe.category,probe.turn,None,'',['request_error'],'info','unknown',str(exc)))
    finally:
        if own_client: await client.aclose()
    return CampaignResult(request.target_url,request.provider,observations,findings,{'probe_count':len(observations),'mode':'adaptive-bounded','multi_turn':request.max_turns>1})

async def run_retest(request: RetestRequest, client: httpx.AsyncClient | None=None):
    campaign=await run_campaign(CampaignRequest(request.target_url,request.provider,'POST',request.prompt_field,request.headers,request.body_template,request.timeout,2), client)
    prior=request.original_finding.get('finding_key') or request.original_finding.get('id')
    matching=[f for f in campaign.findings if f.get('finding_key')==prior] if prior else []
    return {'original_finding':request.original_finding,'retest_status':'still_indicated' if matching else 'not_reproduced','matching_findings':matching,'observations':[o.__dict__ for o in campaign.observations]}
