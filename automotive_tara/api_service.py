"""Shared, credential-safe OpenAI-compatible service checks."""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Iterable
from urllib import request
from urllib.error import HTTPError, URLError

from automotive_tara.http_client import api_endpoint, normalize_api_base


class APIServiceError(ConnectionError):
    def __init__(self, message: str, *, status: int | None = None):
        super().__init__(message)
        self.status = status


def _request_json(
    url: str, api_key: str, *, timeout: float,
    body: dict[str, Any] | None = None, open_url: Callable | None = None,
) -> dict[str, Any]:
    headers = {"Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = request.Request(
        url, headers=headers,
        data=json.dumps(body).encode("utf-8") if body is not None else None,
        method="POST" if body is not None else "GET",
    )
    try:
        with (open_url or request.urlopen)(req, timeout=timeout) as response:
            payload = json.loads(response.read())
    except HTTPError as exc:
        hints = {
            401: "鉴权失败：请核对该平台的 API Key、有效期和 Bearer 认证方式",
            403: "访问被拒绝：请检查账号与模型调用权限",
            404: "接口或模型不存在：请核对 API Base 的路径前缀及服务模型名",
            405: "接口不支持该请求方式",
            429: "调用受到限流或额度限制，请检查云端配额与并发数",
        }
        detail = ""
        try:
            error_payload = json.loads(exc.read(8192))
            error = error_payload.get("error", {})
            detail = str(error.get("message") or "") if isinstance(error, dict) else ""
        except (OSError, ValueError, TypeError, AttributeError):
            pass
        if api_key:
            detail = detail.replace(api_key, "[已隐藏]")
        detail = re.sub(r"(?i)Bearer\s+\S+|\bsk-[\w-]+", "[已隐藏]", detail)
        hint = hints.get(exc.code, "模型服务拒绝请求，请核对模型名与接口参数")
        raise APIServiceError(
            f"HTTP {exc.code} · {hint} · {url}" + (f" · {detail[:300]}" if detail else ""),
            status=exc.code,
        ) from exc
    except (URLError, OSError) as exc:
        raise APIServiceError(f"模型服务连接失败或超时：{url}（{type(exc).__name__}）") from exc
    except (ValueError, TypeError) as exc:
        raise APIServiceError(f"模型服务没有返回有效 JSON，请核对 API Base：{url}") from exc
    if not isinstance(payload, dict):
        raise APIServiceError(f"模型服务返回结构不兼容：{url}")
    return payload


def _service_catalog(
    api_base: str, api_key: str = "", *, timeout: float = 5,
    open_url: Callable | None = None,
) -> list[dict[str, Any]]:
    payload = _request_json(
        api_endpoint(api_base, "models"), api_key,
        timeout=timeout, open_url=open_url,
    )
    if not isinstance(payload.get("data"), list):
        raise APIServiceError("服务未提供兼容的模型列表；请填写服务模型名", status=405)
    return [item for item in payload["data"] if isinstance(item, dict) and item.get("id")]


def list_service_models(
    api_base: str, api_key: str = "", *, timeout: float = 5,
    open_url: Callable | None = None,
) -> list[str]:
    return [str(item["id"]) for item in _service_catalog(api_base, api_key, timeout=timeout, open_url=open_url)]


def check_api_service(
    api_base: str, api_key: str = "", model_names: Iterable[str] = (), *,
    timeout: float = 15, open_url: Callable | None = None,
) -> dict[str, Any]:
    """Check advertised models, or a minimal chat for catalog-less providers.

    Authentication failures remain failures. Only an unsupported catalog may
    fall through to chat, using explicit model names and a one-token probe.
    No project input is included in that probe.
    """
    base = normalize_api_base(api_base)
    required = list(dict.fromkeys(str(name).strip() for name in model_names if str(name).strip()))
    try:
        catalog = _service_catalog(base, api_key, timeout=timeout, open_url=open_url)
        available = [str(item["id"]) for item in catalog]
    except APIServiceError as exc:
        if exc.status not in {404, 405, 501}:
            raise
        available = []
    if available:
        missing = [model for model in required if model not in available]
        if missing:
            raise APIServiceError(f"模型服务未提供模型 {missing}；请填写该云端服务实际支持的模型名。可用：{available[:8]}")
        return {"api_base": base, "model_ids": available, "model_roots": {str(item["id"]): str(item.get("root") or "") for item in catalog}, "checked_by": "models"}
    if not required:
        raise APIServiceError("此服务不提供可用模型列表，请填写“服务模型名”后再测试或启动")
    for model in required:
        payload = _request_json(
            api_endpoint(base, "chat/completions"), api_key, timeout=timeout,
            body={"model": model, "messages": [{"role": "user", "content": "Reply OK."}],
                  "max_tokens": 1, "stream": False},
            open_url=open_url,
        )
        if not isinstance(payload.get("choices"), list) or not payload["choices"]:
            raise APIServiceError("聊天接口未返回 choices，当前服务不兼容 Chat Completions 协议")
    return {"api_base": base, "model_ids": required, "checked_by": "chat"}
