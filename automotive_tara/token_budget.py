"""按输出结构和上下文容量计算 LLM 动态输出预算。"""

from __future__ import annotations

from dataclasses import dataclass
from math import ceil


@dataclass(frozen=True)
class TokenProfile:
    base: int
    per_item: int
    per_item_with_reasons: int


TOKEN_PROFILES: dict[str, TokenProfile] = {
    "default": TokenProfile(192, 128, 192),
    "dst": TokenProfile(160, 180, 180),
    "attack_path": TokenProfile(192, 220, 220),
    "attack_entry": TokenProfile(96, 72, 72),
    "attack_target": TokenProfile(96, 96, 96),
    # 每项是带路线事实的完整攻击路径文本，而不是入口/目标短动作。
    # 以路径数为单位估算，避免 16 条路径共享一段不足的输出预算。
    "attack_path_direct": TokenProfile(160, 240, 240),
    "impact_single": TokenProfile(128, 56, 560),
    # 维持历史 8 项批次的 2048 上限，避免理由开启时极端场景被截断；
    # Stage C 可行性预算才是主要耗时来源，那里使用更短理由和自适应装箱。
    "impact_batch": TokenProfile(160, 52, 240),
    "impact_numeric": TokenProfile(96, 52, 52),
    "impact_reason": TokenProfile(128, 48, 320),
    "feasibility_ap": TokenProfile(256, 96, 220),
    "feasibility_heavens": TokenProfile(256, 88, 205),
    "feasibility_cvss": TokenProfile(256, 80, 180),
}


class PromptContextOverflow(ValueError):
    """The request cannot fit its minimum response and safety reserve."""


def estimate_prompt_tokens(system_prompt: str, user_prompt: str) -> int:
    """Conservatively estimate mixed Chinese/ASCII ChatML tokens.

    Chinese text and JSON punctuation are substantially denser than ordinary
    English prose.  The former ``characters / 2`` approximation could
    underestimate a Qwen prompt near the context boundary, causing vLLM to
    reject an otherwise valid request by one or two tokens.  Keep this helper
    tokenizer-free, but count non-ASCII characters separately and reserve
    space for the provider's chat template.
    """
    value = str(system_prompt or "") + str(user_prompt or "")
    ascii_chars = sum(1 for char in value if ord(char) < 128)
    dense_chars = len(value) - ascii_chars
    return max(64, ceil(ascii_chars / 3.2 + dense_chars * 1.08) + 128)


def fit_user_prompt_to_context(
    system_prompt: str,
    user_prompt: str,
    *,
    context_limit: int,
    output_tokens: int,
    context_reserve: int = 384,
    marker: str = "\n\n【上下文已压缩；仅依据保留内容作答】\n\n",
) -> str:
    """Trim the middle of a user prompt until the whole request safely fits.

    The beginning normally contains the task and field contract while the end
    contains the newest tool evidence, so both sides are retained.  Binary
    search uses the same conservative estimator as output-budget clamping.
    """
    prompt = str(user_prompt or "")
    target = max(256, int(context_limit) - max(64, int(output_tokens)) - int(context_reserve))
    if estimate_prompt_tokens(system_prompt, prompt) <= target:
        return prompt

    def candidate(usable: int) -> str:
        available = max(0, usable - len(marker))
        head = int(available * 0.62)
        tail = available - head
        return prompt[:head] + marker + (prompt[-tail:] if tail else "")

    low, high = 0, len(prompt)
    best = marker
    while low <= high:
        middle = (low + high) // 2
        value = candidate(middle)
        if estimate_prompt_tokens(system_prompt, value) <= target:
            best = value
            low = middle + 1
        else:
            high = middle - 1
    return best


def clamp_output_tokens_to_context(
    requested_tokens: int,
    *,
    context_limit: int,
    system_prompt: str,
    user_prompt: str,
    context_reserve: int = 384,
) -> int:
    """将既定输出预算收紧到模型上下文可容纳的范围。"""
    available = (
        context_limit
        - estimate_prompt_tokens(system_prompt, user_prompt)
        - context_reserve
    )
    if available < 64:
        raise PromptContextOverflow(
            f"输入约 {estimate_prompt_tokens(system_prompt, user_prompt)} tokens，"
            f"输出至少 64 tokens，余量 {context_reserve} tokens，"
            f"超过 {context_limit} tokens 上下文窗口"
        )
    return max(64, min(requested_tokens, available))


def dynamic_output_tokens(
    stage: str,
    item_count: int,
    *,
    include_reasons: bool,
    global_cap: int,
    stage_cap: int,
    context_limit: int,
    minimum_output_tokens: int = 64,
    system_prompt: str = "",
    user_prompt: str = "",
    context_reserve: int = 384,
) -> int:
    """返回本次调用的实际 ``max_tokens``。

    预算同时受输出结构、批大小、阶段上限、全局上限和模型上下文约束；
    长文本阶段可通过 ``minimum_output_tokens`` 保留足够的 JSON 输出空间。
    """
    if item_count < 1:
        raise ValueError("item_count 必须大于等于 1")
    profile = TOKEN_PROFILES.get(stage, TOKEN_PROFILES["default"])
    per_item = (
        profile.per_item_with_reasons
        if include_reasons
        else profile.per_item
    )
    desired = max(
        int(minimum_output_tokens),
        profile.base + per_item * item_count,
    )
    hard_cap = max(64, min(global_cap, stage_cap))
    budget = min(desired, hard_cap)
    if system_prompt or user_prompt:
        budget = clamp_output_tokens_to_context(
            budget,
            context_limit=context_limit,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            context_reserve=context_reserve,
        )
    return max(64, budget)
