"""Impact prompt layouts shared by inference and supervised training."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


def _value(item: Any, key: str) -> str:
    raw = item.get(key, "") if isinstance(item, Mapping) else getattr(item, key, "")
    return str(raw or "").strip()


def _signal_context_lines(item: Any) -> list[str]:
    """Use semantic DFD endpoints to distinguish same-named signal flows."""
    if _value(item, "asset_type") != "信号":
        return []
    lines: list[str] = []
    for key in ("source", "target", "flow_protocol"):
        value = _value(item, key)
        if value:
            lines.append(f"- {key}: {value}")
    return lines


def build_impact_single_user_prompt(
    item: Any,
    *,
    damage_scenario: str | None = None,
    asset_details: str | None = None,
) -> str:
    damage = _value(item, "damage_scenario") if damage_scenario is None else str(damage_scenario)
    details = _value(item, "asset_details") if asset_details is None else str(asset_details)
    lines = [
        "输入：",
        f"- function: {_value(item, 'function')}",
        f"- asset_name: {_value(item, 'asset_name')}",
        f"- asset_type: {_value(item, 'asset_type')}",
        f"- attribute_name: {_value(item, 'attribute_name')}",
        f"- threat_type: {_value(item, 'threat_type')}",
        *_signal_context_lines(item),
        f"- damage_scenario: {damage}",
        f"- asset_details: {details}",
    ]
    return (
        "\n".join(lines)
        + "\n\n请只返回一个 JSON 对象，字段为 influence_parameters；四个维度必须为 1~4 整数。"
        "不要输出 Markdown、解释或思考过程。"
    )


def build_impact_batch_user_prompt(batch: Sequence[Any]) -> str:
    if not batch:
        raise ValueError("impact batch must not be empty")
    lines: list[str] = []
    for index, item in enumerate(batch):
        lines.extend(
            (
                f"## 损害场景 {index}",
                f"- task_id: {_value(item, 'task_id')}",
                f"- function: {_value(item, 'function')}",
                f"- asset_name: {_value(item, 'asset_name')}",
                f"- asset_type: {_value(item, 'asset_type')}",
                f"- attribute_name: {_value(item, 'attribute_name')}",
                f"- threat_type: {_value(item, 'threat_type')}",
            )
        )
        lines.extend(_signal_context_lines(item))
        lines.append(f"- damage_scenario: {_value(item, 'damage_scenario')}")
    return (
        f"请为以下 {len(batch)} 个损害场景分别进行影响评级。\n\n"
        + "\n".join(lines)
        + '\n\n请返回JSON对象 {"items":[...]}；每项必须原样返回task_id和influence_parameters，禁止省略、合并或改变顺序。'
    )
