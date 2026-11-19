"""LLM 请求载荷、响应提取与严格 JSON Schema 基础组件。"""

from __future__ import annotations

import http.client
import re
from typing import Any


PROMPT_CACHE_METRIC_KEYS = (
    'prompt_cache_hit_tokens', 'prompt_cache_miss_tokens',
    'prompt_cache_input_tokens', 'prompt_cache_reported_requests',
)


def extract_prompt_cache_usage(usage: Any) -> dict[str, int]:
    """Normalize provider-reported input-cache tokens, never infer a hit.

    DeepSeek reports hit/miss explicitly; some compatible services report
    prompt_tokens_details.cached_tokens. Missing or inconsistent evidence is
    unknown, rather than a reported zero-percent hit rate.
    """
    if not isinstance(usage, dict):
        return {}

    def number(value):
        if isinstance(value, bool):
            return None
        try:
            parsed = int(value)
            return parsed if parsed >= 0 and str(parsed) == str(value).strip() else None
        except (TypeError, ValueError):
            return None

    total = number(usage.get('prompt_tokens'))
    hit = number(usage.get('prompt_cache_hit_tokens'))
    miss = number(usage.get('prompt_cache_miss_tokens'))
    if hit is None:
        details = usage.get('prompt_tokens_details')
        hit = number(details.get('cached_tokens')) if isinstance(details, dict) else None
    if hit is None:
        return {}
    if miss is None and total is not None and total >= hit:
        miss = total - hit
    if miss is None or (total is not None and hit + miss != total):
        return {}
    return {'prompt_cache_hit_tokens': hit, 'prompt_cache_miss_tokens': miss,
            'prompt_cache_input_tokens': hit + miss, 'prompt_cache_reported_requests': 1}


def build_chat_payload(
    *,
    model: str,
    system_prompt: str,
    user_prompt: str,
    temperature: float,
    max_tokens: int,
    n: int = 1,
    enable_thinking: bool = False,
    response_format: dict | None = None,
    seed: int | None = None,
    top_p: float | None = None,
    top_k: int | None = None,
    frequency_penalty: float | None = None,
    presence_penalty: float | None = None,
) -> dict[str, Any]:
    if n < 1:
        raise ValueError("n 必须大于等于 1")
    payload: dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
        "chat_template_kwargs": {"enable_thinking": enable_thinking},
    }
    if n > 1:
        payload["n"] = n
    if response_format is not None:
        payload["response_format"] = response_format
    # vLLM 支持 OpenAI 兼容接口中的请求级采样参数。仅在显式提供时发送，
    # 以保持对其他 OpenAI 兼容服务的兼容性。
    if seed is not None:
        payload["seed"] = int(seed)
    if top_p is not None:
        payload["top_p"] = float(top_p)
    if top_k is not None:
        payload["top_k"] = int(top_k)
    if frequency_penalty is not None:
        payload["frequency_penalty"] = float(frequency_penalty)
    if presence_penalty is not None:
        payload["presence_penalty"] = float(presence_penalty)
    return payload


def extract_choice_contents(response: Any) -> list[str]:
    choices = response.get("choices", []) if isinstance(response, dict) else []
    contents: list[str] = []
    for choice in choices:
        message = (
            choice.get("message", {})
            if isinstance(choice, dict)
            else {}
        )
        content = (
            message.get("content")
            or message.get("reasoning")
            or message.get("thinking")
            or ""
        )
        contents.append(str(content) if content is not None else "")
    return contents


def is_connection_refused(error: BaseException) -> bool:
    return (
        isinstance(error, ConnectionRefusedError)
        or getattr(error, "errno", None) == 111
    )


def is_stale_connection_error(error: BaseException) -> bool:
    if isinstance(
        error,
        (
            BrokenPipeError,
            ConnectionResetError,
            http.client.RemoteDisconnected,
        ),
    ):
        return True
    normalized = str(error).lower()
    return any(
        marker in normalized
        for marker in (
            "broken pipe",
            "connection reset",
            "remote end closed",
        )
    )


def is_non_retryable_http_error(error: BaseException) -> bool:
    """Return whether the provider rejected the request permanently.

    A retry cannot repair malformed payloads, unsupported response formats,
    invalid model names or authentication errors.  Retrying those requests
    only burns inference time and makes the UI look as if the Agent is stuck.
    ``http_post_json`` intentionally raises a small ``RuntimeError`` instead
    of exposing a provider-specific exception, so inspect both common
    ``status/code`` attributes and its rendered message.
    """
    status = getattr(error, "status", None)
    if status is None:
        status = getattr(error, "code", None)
    try:
        if int(status) in {400, 401, 403, 404, 405, 409, 415, 422}:
            return True
    except (TypeError, ValueError):
        pass
    match = re.search(r"\b(?:HTTP(?:\s+Error)?|status)\s*[:=]?\s*(\d{3})\b", str(error), re.I)
    if not match:
        return False
    return int(match.group(1)) in {400, 401, 403, 404, 405, 409, 415, 422}


def strict_array_response_format(
    *,
    schema_name: str,
    array_name: str,
    count: int,
    item_properties: dict[str, dict],
    required: list[str],
) -> dict:
    """构造严格等长、禁止额外字段的 OpenAI JSON Schema。"""
    return {
        "type": "json_schema",
        "json_schema": {
            "name": schema_name,
            "strict": True,
            "schema": {
                "type": "object",
                "properties": {
                    array_name: {
                        "type": "array",
                        "minItems": count,
                        "maxItems": count,
                        "items": {
                            "type": "object",
                            "properties": item_properties,
                            "required": required,
                            "additionalProperties": False,
                        },
                    }
                },
                "required": [array_name],
                "additionalProperties": False,
            },
        },
    }
