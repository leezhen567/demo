"""Discover the selected service's real context capacity and decode SSE replies."""
from __future__ import annotations
import json
import os
import re
import time
from functools import lru_cache
from urllib import request
from urllib.parse import urlsplit
from .http_client import api_endpoint
from .context_policy import ASSISTANT_DEFAULT, ASSISTANT_MAX, positive_int, local_service_state, admission_budgets


@lru_cache(maxsize=16)
def _capacity(api_base, model, api_key, bucket):
    local = (urlsplit(api_base).hostname or '').lower() in {'localhost', '127.0.0.1', '::1'}
    opener = request.build_opener(request.ProxyHandler({})) if local else request.build_opener()
    req = request.Request(api_endpoint(api_base, 'models'), headers={'Authorization': 'Bearer ' + (api_key or 'EMPTY')})
    try:
        with opener.open(req, timeout=5) as response:
            values = json.loads(response.read()).get('data', [])
        item = next((item for item in values if item.get('id') == model), None)
        if item:
            for key in ('max_model_len', 'context_length', 'max_context_length'):
                if item.get(key):
                    return int(item[key])
    except (OSError, ValueError, TypeError):
        pass
    return None


def context_profile(api_base, model, api_key='', requested='auto', *, refresh=False, root=None):
    if refresh:
        _capacity.cache_clear()
    capacity = _capacity(api_base, model, api_key, int(time.monotonic() // 30))
    automatic = requested in (None, '', 0, 'auto')
    # Legacy 'max' selections are bounded too; they cannot consume the pool.
    target = positive_int(os.getenv('TARA_ASSISTANT_CONTEXT'), ASSISTANT_DEFAULT) if automatic else (
        ASSISTANT_MAX if requested == 'max' else int(requested))
    target = max(2048, min(ASSISTANT_MAX, target))
    # Unknown cloud metadata is not proof of a large context window.
    effective = min(target, capacity or 8192)
    from pathlib import Path
    state = local_service_state(api_base,model,root or Path(__file__).resolve().parents[1])
    if state:
        effective = min(effective,admission_budgets(state)['assistant'])
    return {'requested': target, 'preference': 'auto' if automatic else target,
            'service_capacity': capacity, 'effective': effective,
            'includes_input_and_output': True,
            'notice': '助手独立预算，受当前服务容量约束' if capacity else '服务未公布容量，保守使用8K；不继承本地其他模型的容量'}


def task_context_profile(api_base, model, api_key='', *, requested=None, root=None):
    from .context_policy import local_service_state, task_budget, TASK_DEFAULT
    from pathlib import Path
    root = Path(root or Path(__file__).resolve().parents[1])
    capacity = _capacity(api_base, model, api_key, int(time.monotonic() // 30))
    state = local_service_state(api_base,model,root)
    capacity = capacity or state.get('max_model_len')
    budget = task_budget(capacity,requested if requested is not None else os.getenv('TARA_TASK_CONTEXT_TOKENS'))
    if state:
        budget = min(budget,admission_budgets(state)['tara'])
    return {'effective':budget,
            'requested':positive_int(requested or os.getenv('TARA_TASK_CONTEXT_TOKENS'),TASK_DEFAULT),
            'service_capacity':capacity}


def visible_answer(partial):
    """Decode the completed prefix of JSON's answer string, never raw JSON/CoT."""
    match = re.search(r'"answer"\s*:\s*"', partial)
    if not match:
        return ''
    tail = partial[match.end():]
    pieces, index = [], 0
    while index < len(tail):
        char = tail[index]
        if char == '"':
            break
        if char == '\\':
            if index + 1 >= len(tail):
                break
            escape = tail[index + 1]
            length = 6 if escape == 'u' else 2
            if index + length > len(tail):
                break
            try:
                pieces.append(json.loads('"' + tail[index:index + length] + '"'))
            except ValueError:
                break
            index += length
        else:
            pieces.append(char)
            index += 1
    value = ''.join(pieces)
    if value and 0xD800 <= ord(value[-1]) <= 0xDBFF:
        value = value[:-1]
    return value.encode('utf-16', errors='surrogatepass').decode('utf-16', errors='replace')


def read_sse(response, on_text=None, cancel_event=None):
    pieces, last = [], ''
    for raw in response:
        if cancel_event is not None and cancel_event.is_set():
            break
        line = raw.decode('utf-8', errors='replace').strip()
        if not line.startswith('data:'):
            continue
        value = line[5:].strip()
        if value == '[DONE]':
            break
        data = json.loads(value)
        if data.get('error'):
            raise ValueError(str(data['error']))
        for choice in data.get('choices', []):
            text = choice.get('delta', {}).get('content')
            if isinstance(text, str):
                pieces.append(text)
        content = ''.join(pieces)
        answer = visible_answer(content)
        if not answer and content.strip() and not content.lstrip().startswith(('{', '[', '```', '<think')):
            answer = content
        if answer and answer != last:
            last = answer
            if on_text:
                on_text(answer)
    return ''.join(pieces)
