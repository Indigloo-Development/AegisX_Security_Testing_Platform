from typing import Any

def evaluate_agent_policy(tools: list[dict[str, Any]], allowed_actions: set[str] | None=None) -> dict[str, Any]:
    allowed_actions = allowed_actions or set()
    findings=[]
    for tool in tools:
        name=tool.get('name','unknown')
        actions=set(tool.get('actions',[]) or [])
        dangerous={'filesystem.write','shell.execute','credential.read','network.admin'} & actions
        if dangerous and not dangerous.issubset(allowed_actions):
            findings.append({'key':'AGENT2-TOOL-001','title':f'Agent tool {name} exceeds declared allowlist','severity':'high','confidence':'likely','evidence':{'actions':sorted(dangerous)},'remediation':'Use explicit least-privilege tool scopes and deny undeclared capabilities by default.'})
    return {'tool_count':len(tools),'findings':findings}
