"""评级理由字段、长度约束与 Prompt 策略。"""

from __future__ import annotations

from typing import Any


IMPACT_REASON_KEYS = (
    "Safety_reason",
    "Finance_reason",
    "Operation_reason",
    "Privacy_reason",
)
AP_REASON_KEYS = (
    "Exposure_time_reason",
    "Professional_experience_reason",
    "Required_information_reason",
    "Opportunity_window_reason",
    "Required_equipment_reason",
)
# The window and its explanation are derived by code, not model outputs.
AP_MODEL_REASON_KEYS = tuple(key for key in AP_REASON_KEYS if key != "Opportunity_window_reason")
HEAVENS_REASON_KEYS = (
    "Expertise_reason",
    "Knowledge_about_TOE_reason",
    "Window_of_Opportunity_reason",
    "Equipment_reason",
)
CVSS_REASON_KEYS = (
    "complexity_reason",
    "privileges_reason",
    "user_interaction_reason",
)
RATING_REASON_MAX_CHARS = 48

REASON_PLACEHOLDERS = {
    "",
    "-",
    "无",
    "理由",
    "简述",
    "none",
    "null",
    "n/a",
    "na",
}


def append_reason_policy(
    prompt: str,
    fields: tuple[str, ...],
    *,
    enabled: bool,
) -> str:
    if enabled:
        return (
            prompt
            + "\n\n## 评级理由输出协议（最高优先级）\n"
            + "评级理由开关已开启。每条结果都必须输出以下字段，且必须为"
              "结合当前输入和评级标准的非空字符串：\n- "
            + "\n- ".join(fields)
            + "\n每个理由只生成一个简短重点依据：直接说明当前维度为何对应"
              "该分值，硬性限制为 12～32 个汉字（英文不超过 48 个字符）。"
              "禁止复述完整场景、输出分析过程、堆叠多个论点或扩展无关背景。"
              "\n缺少、留空、过长或使用无意义占位文本均视为无效结果。"
        )
    prompt = "\n".join(
        line
        for line in prompt.splitlines()
        if "评分理由" not in line and "SR/FR/OR/PR" not in line
    )
    return (
        prompt
        + "\n\n## 评级理由输出协议（最高优先级）\n"
        + "评级理由开关已关闭。禁止输出任何评级理由、解释、分析过程，"
          "禁止输出字段名包含 reason、Reason、理由 的字段；仅输出要求的评级值。"
    )


def reason_fields_valid(
    params: Any,
    expected_keys: tuple[str, ...],
    *,
    enabled: bool,
) -> bool:
    if not isinstance(params, dict):
        return False
    if not enabled:
        return True
    return all(
        isinstance(params.get(key), str)
        and params[key].strip().lower() not in REASON_PLACEHOLDERS
        and len(params[key].strip()) <= RATING_REASON_MAX_CHARS
        and "\n" not in params[key].strip()
        for key in expected_keys
    )


def sanitize_reason_fields(
    params: Any,
    expected_keys: tuple[str, ...],
    *,
    enabled: bool = True,
) -> dict | None:
    """返回 reason 修正后的 params；仅超长截断保留，其余无效形式返回 None。

    不能在 JSON Schema 里用 maxLength 硬截断（vLLM 会填充制表符直到 max_tokens，
    使整批 JSON 尾部不完整）。超长理由在这里截断到 RATING_REASON_MAX_CHARS，
    评级参数不受影响；缺失/占位符/换行仍视为无效，交给调用方重试。
    """
    if not isinstance(params, dict):
        return None
    if not enabled:
        return params
    sanitized = dict(params)
    for key in expected_keys:
        value = sanitized.get(key)
        if not isinstance(value, str):
            return None
        stripped = value.strip()
        if stripped.lower() in REASON_PLACEHOLDERS or "\n" in stripped:
            return None
        if len(stripped) > RATING_REASON_MAX_CHARS:
            sanitized[key] = stripped[:RATING_REASON_MAX_CHARS]
    return sanitized
