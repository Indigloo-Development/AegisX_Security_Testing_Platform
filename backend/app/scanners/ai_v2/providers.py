from typing import Any
from .models import CampaignRequest, LLMProvider, PROVIDERS


def provider_for(name: str) -> LLMProvider:
    key = name.lower().strip()
    if key not in PROVIDERS:
        raise ValueError(f'Unsupported provider: {name}')
    return PROVIDERS[key]


def build_payload(request: CampaignRequest, prompt: str, conversation: list[dict[str, str]]) -> dict[str, Any]:
    provider = provider_for(request.provider)
    payload = dict(request.body_template)
    if provider.request_style == 'chat_completions':
        payload.setdefault('model', 'configured-by-target')
        payload['messages'] = [{'role':'user','content': prompt}] if not conversation else conversation + [{'role':'user','content': prompt}]
    elif provider.request_style == 'messages':
        payload.setdefault('model', 'configured-by-target')
        payload['messages'] = [{'role':'user','content': prompt}] if not conversation else conversation + [{'role':'user','content': prompt}]
        payload.setdefault('max_tokens', 512)
    elif provider.request_style == 'generate_content':
        payload['contents'] = [{'parts': [{'text': prompt}]}]
    else:
        payload[request.prompt_field] = prompt
    return payload


def extract_text(data: Any, raw: str) -> str:
    if isinstance(data, dict):
        choices = data.get('choices')
        if isinstance(choices, list) and choices:
            msg = choices[0].get('message') if isinstance(choices[0], dict) else None
            if isinstance(msg, dict) and isinstance(msg.get('content'), str):
                return msg['content']
            if isinstance(choices[0], dict) and isinstance(choices[0].get('text'), str):
                return choices[0]['text']
        content = data.get('content')
        if isinstance(content, list):
            parts = [x.get('text') for x in content if isinstance(x, dict) and isinstance(x.get('text'), str)]
            if parts: return '\n'.join(parts)
        candidates = data.get('candidates')
        if isinstance(candidates, list) and candidates:
            c = candidates[0]
            if isinstance(c, dict):
                parts = c.get('content', {}).get('parts', []) if isinstance(c.get('content'), dict) else []
                texts = [x.get('text') for x in parts if isinstance(x, dict) and isinstance(x.get('text'), str)]
                if texts: return '\n'.join(texts)
        for key in ('response','output','text','answer'):
            if isinstance(data.get(key), str): return data[key]
    return raw
