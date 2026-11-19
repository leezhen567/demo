"""针对 LLM 常见输出偏差的严格 JSON 解析工具。"""

from __future__ import annotations

import re
from typing import Any

import orjson


_UNQUOTED_ZERO_PADDED_TASK_ID_RE = re.compile(
    r'("task_id"\s*:\s*)(-?0\d+)(?=\s*[,}])'
)


def repair_unquoted_zero_padded_task_ids(text: str) -> str:
    """只修复 ``task_id`` 的非法前导零数字，避免改动正文数值。"""
    return _UNQUOTED_ZERO_PADDED_TASK_ID_RE.sub(r'\1"\2"', text)


def canonical_task_id(value: Any, expected_ids: set[str]) -> str:
    """将模型返回的字符串或数字安全映射到请求中的原始任务 ID。"""
    raw = str(value if value is not None else "").strip()
    if raw in expected_ids:
        return raw
    if not raw.isdigit():
        return ""
    numeric = int(raw)
    matches = [
        task_id
        for task_id in expected_ids
        if task_id.isdigit() and int(task_id) == numeric
    ]
    return matches[0] if len(matches) == 1 else ""


def _unwrap_single_object(value: Any) -> Any:
    if (
        isinstance(value, list)
        and len(value) == 1
        and isinstance(value[0], dict)
    ):
        return value[0]
    return value


def safe_parse_json(text: Any) -> Any:
    if text is None:
        raise ValueError("输入为空")
    cleaned = text.strip() if isinstance(text, str) else str(text).strip()
    if len(cleaned) < 2:
        raise ValueError(f"JSON输入过短: '{cleaned}'")
    if cleaned in ("{}", "[]"):
        return orjson.loads(cleaned.encode("utf-8"))

    think_start = cleaned.find("<think")
    if think_start != -1:
        think_end = cleaned.find("</think>", think_start)
        cleaned = (
            cleaned[:think_start] + cleaned[think_end + 8:]
            if think_end != -1
            else cleaned[:think_start]
        ).strip()

    markdown_start = cleaned.find("```")
    if markdown_start != -1:
        first_newline = cleaned.find("\n", markdown_start)
        if first_newline != -1:
            content_start = first_newline + 1
            markdown_end = cleaned.find("```", content_start)
            if markdown_end != -1:
                cleaned = cleaned[content_start:markdown_end].strip()

    try:
        return _unwrap_single_object(
            orjson.loads(cleaned.encode("utf-8"))
        )
    except Exception:
        pass

    repaired = repair_unquoted_zero_padded_task_ids(cleaned)
    if repaired != cleaned:
        cleaned = repaired
        try:
            return _unwrap_single_object(
                orjson.loads(cleaned.encode("utf-8"))
            )
        except Exception:
            pass

    for opening in ("{", "["):
        position = cleaned.find(opening)
        if position == -1:
            continue
        depth = 0
        closing = "}" if opening == "{" else "]"
        in_string = False
        string_char = None
        index = position
        while index < len(cleaned):
            character = cleaned[index]
            if in_string:
                if character == "\\":
                    index += 2
                    continue
                if character == string_char:
                    in_string = False
                    string_char = None
            elif character in ('"', "'"):
                in_string = True
                string_char = character
            elif character == opening:
                depth += 1
            elif character == closing:
                depth -= 1
                if depth == 0:
                    try:
                        return _unwrap_single_object(
                            orjson.loads(
                                cleaned[position:index + 1].encode("utf-8")
                            )
                        )
                    except Exception:
                        break
            index += 1

    raise ValueError(f"JSON解析失败，原文前200字: {cleaned[:200]}")
