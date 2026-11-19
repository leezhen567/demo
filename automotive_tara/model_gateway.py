"""OpenAI-compatible model gateway, retries, metrics and JSON caching."""

from __future__ import annotations

import hashlib
import logging
import re
import time
from threading import Lock, Semaphore
from typing import Any, Callable, Mapping

import orjson

from automotive_tara.http_client import HTTPConnectionPool, normalize_api_base, parse_api_url
from automotive_tara.json_utils import safe_parse_json
from automotive_tara.llm import (
    build_chat_payload,
    extract_choice_contents,
    extract_prompt_cache_usage,
    is_connection_refused,
    is_non_retryable_http_error,
    is_stale_connection_error,
)
from automotive_tara.storage import SemanticCache
from automotive_tara.token_budget import clamp_output_tokens_to_context

logger = logging.getLogger(__name__)


class ModelRequestRejected(RuntimeError):
    """A model request was rejected by the service before a usable reply."""


def _context_rejection_budget(message: str, current_tokens: int) -> int | None:
    """Use the service's tokenizer count to fit a rejected request once."""
    if not re.search(r"(?:maximum context length|max_model_len|context window)", message, re.I):
        return None
    limit_match = re.search(r"(?:maximum context length is|maximum context length|max_model_len(?:=|:))\s*(\d+)", message, re.I)
    input_match = re.search(r"(?:at least|contains|prompt_tokens(?:=|:))\s*(\d+)\s*(?:input\s*)?tokens", message, re.I)
    if not limit_match or not input_match:
        return None
    available = int(limit_match.group(1)) - int(input_match.group(1)) - 128
    return max(0, min(current_tokens - 1, available))


def get_http_pool(
    get_current_pool: Callable[[], HTTPConnectionPool | None],
    *,
    lock: Lock,
    api_base: str,
    max_size: int,
    timeout: int,
    idle_ttl: float,
    set_pool: Callable[[HTTPConnectionPool], None],
) -> HTTPConnectionPool:
    """获取或创建连接池；实际所有权仍由一次 pipeline 运行持有。"""
    current_pool = get_current_pool()
    if current_pool is not None:
        return current_pool
    with lock:
        current_pool = get_current_pool()
        if current_pool is None:
            host, port, _ = parse_api_url(api_base)
            use_https = api_base.lower().startswith("https://")
            current_pool = HTTPConnectionPool(
                host,
                port,
                max_size=max_size,
                timeout=timeout,
                use_https=use_https,
                idle_ttl=idle_ttl,
            )
            set_pool(current_pool)
            logger.info(
                "HTTP 连接池已初始化: %s://%s:%d "
                "(max_size=%d, idle_ttl=%.1fs)",
                "https" if use_https else "http",
                host,
                port,
                max_size,
                idle_ttl,
            )
    return current_pool


def _http_post_json_unadmitted(
    path: str,
    body: bytes,
    *,
    get_pool: Callable[[], HTTPConnectionPool],
    api_base: str,
    api_key: str,
) -> dict:
    """使用 Keep-Alive 连接池发送 POST 请求并返回 JSON。"""
    pool = get_pool()
    _, _, base_path = parse_api_url(normalize_api_base(api_base))
    connection = pool.get()
    try:
        connection.request(
            "POST",
            base_path + path,
            body=body,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
        )
        response = connection.getresponse()
        raw = response.read()
        if not 200 <= response.status < 300:
            connection.close()
            raise RuntimeError(
                f"LLM HTTP {response.status}: "
                f"{raw.decode('utf-8', errors='replace')[:500]}"
            )
        data = orjson.loads(raw)
        if (response.getheader("Connection") or "").lower() == "close":
            connection.close()
        else:
            pool.put(connection)
        return data
    except Exception:
        try:
            connection.close()
        except Exception:
            pass
        raise


def http_post_json(path, body, *, get_pool, api_base, api_key):
    from .request_admission import reserve_request
    from .token_budget import estimate_prompt_tokens
    data = orjson.loads(body) if path == '/chat/completions' else {}
    messages = data.get('messages', [])
    prompt = '\n'.join(str(item.get('content', '')) for item in messages)
    tokens = estimate_prompt_tokens('', prompt) + int(data.get('max_tokens') or 0) * int(data.get('n') or 1) + 384
    with reserve_request(api_base, data.get('model',''), tokens):
        return _http_post_json_unadmitted(path, body, get_pool=get_pool, api_base=api_base, api_key=api_key)


def inject_function_descriptions(
    system_prompt: str,
    user_prompt: str,
    descriptions: Mapping[str, str],
) -> str:
    if not descriptions:
        return system_prompt
    names: list[str] = []
    for name in re.findall(r"(?m)^-\s*function:\s*(.+?)\s*$", user_prompt):
        name = name.strip()
        if name and name not in names and name in descriptions:
            names.append(name)
    if not names:
        return system_prompt
    selected = "\n".join(f"- {name}：{descriptions[name]}" for name in names)
    return system_prompt + "\n\n## 当前功能说明\n" + selected


def call_model(
    system_prompt: str,
    user_prompt: str,
    *,
    model: str,
    temperature: float,
    context_tokens: int,
    skip_chat_template: bool,
    descriptions: Mapping[str, str],
    token_budget: Callable[..., int],
    post_json: Callable[[str, bytes], dict],
    semaphore: Semaphore,
    respect_call_interval: Callable[[], None],
    metrics: dict[str, int | float],
    metrics_lock: Lock,
    stage_metrics: dict[str, int | float] | None = None,
    retries: int = 2,
    max_tokens: int | None = None,
    response_format: dict | None = None,
    n: int = 1,
    return_all_choices: bool = False,
    seed: int | None = None,
    top_p: float | None = None,
    top_k: int | None = None,
    frequency_penalty: float | None = None,
    presence_penalty: float | None = None,
    capture_call: Callable[[Mapping[str, Any]], None] | None = None,
    raise_on_rejection: bool = False,
    sleep: Callable[[float], None] = time.sleep,
) -> str | list[str]:
    if n < 1:
        raise ValueError("n 必须大于等于 1")
    system_prompt = inject_function_descriptions(
        system_prompt, user_prompt, descriptions
    )
    requested_tokens = (
        max_tokens
        if max_tokens is not None
        else token_budget(
            "default",
            1,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            record=True,
        )
    )
    effective_tokens = clamp_output_tokens_to_context(
        requested_tokens,
        context_limit=context_tokens,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
    )
    with metrics_lock:
        metrics["max_tokens_requested"] += requested_tokens
        metrics["max_tokens_effective"] += effective_tokens
        if effective_tokens < requested_tokens:
            metrics["context_clamped_requests"] += 1

    context_adjusted = False
    format_adjusted = False
    ordinary_failures = 0
    for attempt in range(retries + 3):
        request_started: float | None = None
        request_succeeded = False
        retry_without_delay = False
        stop_after_error = False
        payload: dict[str, Any] | None = None
        try:
            payload = build_chat_payload(
                model=model,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                temperature=temperature,
                max_tokens=effective_tokens,
                n=n,
                enable_thinking=False,
                response_format=response_format,
                seed=seed,
                top_p=top_p,
                top_k=top_k,
                frequency_penalty=frequency_penalty,
                presence_penalty=presence_penalty,
            )
            if skip_chat_template:
                payload.pop("chat_template_kwargs", None)
            with semaphore:
                respect_call_interval()
                request_started = time.perf_counter()
                with metrics_lock:
                    metrics["http_requests"] += 1
                    if stage_metrics is not None:
                        stage_metrics["http_requests"] = (
                            stage_metrics.get("http_requests", 0) + 1
                        )
                    if attempt > 0:
                        metrics["retry_requests"] += 1
                        if stage_metrics is not None:
                            stage_metrics["retry_requests"] = (
                                stage_metrics.get("retry_requests", 0) + 1
                            )
                data = post_json("/chat/completions", orjson.dumps(payload))
                request_succeeded = True
                usage = data.get("usage", {}) if isinstance(data, dict) else {}
                if not isinstance(usage, dict):
                    usage = {}
                with metrics_lock:
                    reported_usage_fields = 0
                    for source_key in (
                        "prompt_tokens", "completion_tokens", "total_tokens"
                    ):
                        try:
                            if source_key not in usage:
                                continue
                            value = int(usage.get(source_key, 0) or 0)
                        except (TypeError, ValueError):
                            continue
                        metrics[source_key] += value
                        reported_usage_fields += 1
                        if stage_metrics is not None:
                            stage_metrics[source_key] = (
                                stage_metrics.get(source_key, 0) + value
                            )
                            stage_metrics[f"{source_key}_usage_requests"] = (
                                stage_metrics.get(
                                    f"{source_key}_usage_requests", 0
                                ) + 1
                            )
                    if stage_metrics is not None and reported_usage_fields:
                        stage_metrics["usage_reported_requests"] = (
                            stage_metrics.get("usage_reported_requests", 0) + 1
                        )
                    for key, value in extract_prompt_cache_usage(usage).items():
                        metrics[key] += value
                        if stage_metrics is not None:
                            stage_metrics[key] = stage_metrics.get(key, 0) + value
            contents = extract_choice_contents(data)
            if capture_call is not None:
                try:
                    nonempty_contents = [
                        content
                        for content in contents
                        if isinstance(content, str)
                        and content.strip() not in {"", "{}"}
                    ]
                    parseable_choices = 0
                    for content in nonempty_contents:
                        try:
                            safe_parse_json(content)
                            parseable_choices += 1
                        except Exception:
                            pass
                    capture_status = (
                        "empty"
                        if not nonempty_contents
                        else (
                            "success"
                            if parseable_choices
                            else "invalid_json"
                        )
                    )
                    capture_call(
                        {
                            "status": capture_status,
                            "attempt": attempt + 1,
                            "max_attempts": retries + 1,
                            "request": payload,
                            "choices": contents,
                            "parseable_choices": parseable_choices,
                            "usage": usage,
                            "elapsed_seconds": round(
                                time.perf_counter() - request_started, 6
                            ),
                        }
                    )
                except Exception:
                    logger.exception("训练数据调用轨迹采集失败，已忽略")
            return (
                contents
                if return_all_choices
                else (contents[0] if contents else "")
            )
        except Exception as exc:
            if capture_call is not None:
                try:
                    capture_call(
                        {
                            "status": "failed",
                            "attempt": attempt + 1,
                            "max_attempts": retries + 1,
                            "request": payload,
                            "error_type": type(exc).__name__,
                            "error": str(exc)[:1000],
                            "elapsed_seconds": (
                                round(time.perf_counter() - request_started, 6)
                                if request_started is not None
                                else None
                            ),
                        }
                    )
                except Exception:
                    logger.exception("训练数据失败轨迹采集失败，已忽略")
            if is_connection_refused(exc):
                logger.warning(
                    "LLM服务拒绝连接，立即停止当前调用: %s | prompt长度=%d",
                    exc,
                    len(system_prompt) + len(user_prompt),
                )
                if raise_on_rejection:
                    raise ModelRequestRejected("connection_refused") from exc
                return [] if return_all_choices else "{}"
            if is_non_retryable_http_error(exc):
                revised_tokens = (
                    _context_rejection_budget(str(exc), effective_tokens)
                    if not context_adjusted else None
                )
                if revised_tokens is not None and revised_tokens >= 64:
                    effective_tokens = revised_tokens
                    context_adjusted = True
                    retry_without_delay = True
                    with metrics_lock:
                        metrics["context_service_adjusted_requests"] += 1
                    logger.info(
                        "模型服务实际 token 数高于预估，按服务端窗口收紧输出至 %d tokens 后重试",
                        effective_tokens,
                    )
                    continue
                if (
                    response_format is not None
                    and not format_adjusted
                    and re.search(
                        r"response_format|json_schema|guided.decoding",
                        str(exc), re.I,
                    )
                ):
                    # A gateway without structured-output support can still
                    # generate the requested JSON from the same system/user
                    # prompt.  This is one bounded model retry, not a
                    # deterministic replacement for model content.
                    response_format = None
                    format_adjusted = True
                    retry_without_delay = True
                    with metrics_lock:
                        metrics["schema_compat_retry_requests"] += 1
                    logger.warning(
                        "模型服务不支持结构化输出参数，改用文本 JSON 约定重试一次"
                    )
                    continue
                logger.warning(
                    "LLM请求被服务端拒绝，停止重试: %s | prompt长度=%d",
                    exc,
                    len(system_prompt) + len(user_prompt),
                )
                retry_without_delay = True
                stop_after_error = True
                if raise_on_rejection:
                    raise ModelRequestRejected(
                        "context_overflow" if revised_tokens is not None else "http_rejected"
                    ) from exc
            else:
                retry_without_delay = is_stale_connection_error(exc)
            if not stop_after_error:
                logger.warning(
                    "LLM调用异常 (attempt %d/%d): %s | prompt长度=%d",
                    attempt + 1,
                    retries + 1,
                    exc,
                    len(system_prompt) + len(user_prompt),
                )
        finally:
            if request_started is not None:
                with metrics_lock:
                    key = (
                        "successful_requests"
                        if request_succeeded
                        else "failed_requests"
                    )
                    metrics[key] += 1
                    elapsed = time.perf_counter() - request_started
                    metrics["http_seconds"] += elapsed
                    if stage_metrics is not None:
                        stage_key = (
                            "successful_requests"
                            if request_succeeded
                            else "failed_requests"
                        )
                        stage_metrics[stage_key] = (
                            stage_metrics.get(stage_key, 0) + 1
                        )
                        stage_metrics["http_seconds"] = (
                            stage_metrics.get("http_seconds", 0.0) + elapsed
                        )
        if stop_after_error:
            break
        ordinary_failures += 1
        if ordinary_failures > retries:
            break
        if not retry_without_delay:
            sleep(2 ** (ordinary_failures - 1))
    return [] if return_all_choices else "{}"


def build_cache_key(
    cache_key: Any,
    system_prompt: str,
    user_prompt: str,
    *,
    model: str,
    temperature: float,
    descriptions: Mapping[str, str],
    token_budget: Callable[..., int],
    max_tokens: int | None = None,
    seed: int | None = None,
    top_p: float | None = None,
    top_k: int | None = None,
    frequency_penalty: float | None = None,
    presence_penalty: float | None = None,
) -> dict:
    scoped_descriptions = {
        name: descriptions[name]
        for name in re.findall(r"(?m)^-\s*function:\s*(.+?)\s*$", user_prompt)
        if name in descriptions
    }
    return {
        "schema": "llm-json-v2",
        "model": model,
        "temperature": temperature,
        "seed": seed,
        "top_p": top_p,
        "top_k": top_k,
        "frequency_penalty": frequency_penalty,
        "presence_penalty": presence_penalty,
        "max_tokens": (
            max_tokens
            if max_tokens is not None
            else token_budget(
                "default",
                1,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )
        ),
        "system_prompt_sha256": hashlib.sha256(
            system_prompt.encode("utf-8")
        ).hexdigest(),
        "user_prompt_sha256": hashlib.sha256(
            user_prompt.encode("utf-8")
        ).hexdigest(),
        "function_descriptions": scoped_descriptions,
        "key": cache_key,
    }


def cached_json(
    *,
    bucket: str,
    cache_key: Any,
    system_prompt: str,
    user_prompt: str,
    default: Any,
    semantic_cache: SemanticCache,
    build_key: Callable[..., dict],
    call_llm: Callable[..., str | list[str]],
    token_budget: Callable[..., int],
    max_tokens: int | None = None,
    validator: Callable[[Any], bool] | None = None,
    log_validation_failure: bool = True,
    response_format: dict | None = None,
) -> tuple[Any, bool]:
    effective_tokens = (
        max_tokens
        if max_tokens is not None
        else token_budget(
            "default",
            1,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )
    )
    versioned_key = build_key(
        cache_key, system_prompt, user_prompt, effective_tokens
    )

    def _passes_validator(value: Any) -> bool:
        if validator is None:
            return True
        try:
            return bool(validator(value))
        except Exception as exc:
            # A validator is a quality gate, not part of the model transport
            # contract.  Treat an implementation error as an invalid result
            # so the caller can use its bounded retry path instead of turning
            # one malformed response into an uncaught MODEL_FAILED exception.
            logger.warning(
                "LLM JSON校验器异常，按无效结果处理: bucket=%s error=%s",
                bucket,
                exc,
            )
            return False

    cached = semantic_cache.get(bucket, versioned_key)
    if cached is not None:
        if _passes_validator(cached):
            return cached, True
        semantic_cache.delete(bucket, versioned_key)
        logger.warning("语义缓存内容校验失败并已删除: bucket=%s", bucket)

    raw = call_llm(
        system_prompt,
        user_prompt,
        max_tokens=effective_tokens,
        response_format=response_format,
    )
    if not isinstance(raw, str) or raw.strip() in ("", "{}"):
        return default, False
    try:
        parsed = safe_parse_json(raw)
    except Exception:
        logger.warning(
            "cached_llm_json parse failed bucket=%s key=%s raw[:200]=%s",
            bucket,
            str(cache_key)[:80],
            raw[:200],
        )
        return default, False
    if not _passes_validator(parsed):
        if log_validation_failure:
            logger.warning(
                "LLM JSON内容校验失败，不写入缓存: bucket=%s", bucket
            )
        return default, False
    semantic_cache.set(bucket, versioned_key, parsed)
    return parsed, False
