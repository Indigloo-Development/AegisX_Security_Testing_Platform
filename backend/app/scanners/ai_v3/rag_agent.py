from typing import Any


def analyze_rag_access(records: list[dict[str, Any]]) -> dict[str, Any]:
    findings=[]
    for r in records:
        if r.get("tenant_id") is not None and r.get("authorized_tenant_id") is not None and r["tenant_id"] != r["authorized_tenant_id"]:
            findings.append({"key":"AI3-RAG-AUTH-001","severity":"critical","confidence":"confirmed","title":"Cross-tenant retrieval mismatch","evidence":{"tenant_id":r.get("tenant_id"),"authorized_tenant_id":r.get("authorized_tenant_id"),"document_id":r.get("document_id")}})
        if r.get("source_authorized") is False:
            findings.append({"key":"AI3-RAG-AUTH-002","severity":"high","confidence":"confirmed","title":"Retrieval source not authorized","evidence":{"document_id":r.get("document_id")}})
    return {"record_count":len(records),"findings":findings}


def evaluate_agent_tool_graph(tools: list[dict[str, Any]]) -> dict[str, Any]:
    findings=[]
    edges=[]
    for tool in tools:
        name=tool.get("name","unknown")
        actions=set(tool.get("actions",[]) or [])
        calls=tool.get("calls",[]) or []
        for c in calls:
            edges.append({"from":name,"to":c})
        if "credential.read" in actions and ("network.admin" in actions or "shell.execute" in actions):
            findings.append({"key":"AI3-AGENT-PRIV-001","severity":"critical","confidence":"likely","title":"High-privilege agent tool combination","evidence":{"tool":name,"actions":sorted(actions)},"remediation":"Separate credential access from privileged execution and require explicit policy approvals."})
        if "filesystem.write" in actions and "shell.execute" in actions:
            findings.append({"key":"AI3-AGENT-PRIV-002","severity":"high","confidence":"likely","title":"Agent tool combination permits write-and-execute capabilities","evidence":{"tool":name,"actions":sorted(actions)}})
    return {"tool_count":len(tools),"edges":edges,"findings":findings}
