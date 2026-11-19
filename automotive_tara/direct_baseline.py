"""Direct-LLM paper baseline; never used by the production TARA pipeline.

The baseline deliberately gives the model the same frozen engineering facts
but does not use TraceTARA's route composition or staged generation.  All
deterministic checks live here so experiment metrics can distinguish a valid
model response from a fluent but structurally invalid one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence

from automotive_tara.domain import (
    AP_ALLOWED_VALUES,
    CVSS_C,
    CVSS_P,
    CVSS_U,
    HEAVENS_AP_ALLOWED_VALUES,
    HEAVENS_TL_TO_FEASIBILITY,
    TaskUnit,
    calculate_attack_potential_level,
    calculate_attack_potential_score,
    calculate_attack_vector_level,
    calculate_cvss_level,
    calculate_cvss_score,
    calculate_heavens_ap_level,
    calculate_heavens_ap_score,
    calculate_heavens_risk_value,
    calculate_risk_value,
    compute_impact_for_method,
    normalize_attack_vector,
    task_analysis_reference,
)
from automotive_tara.json_utils import safe_parse_json
from automotive_tara.prompts import DIRECT_LLM_BASELINE_SYSTEM_PROMPT
from automotive_tara.reason_policy import (
    AP_REASON_KEYS,
    CVSS_REASON_KEYS,
    HEAVENS_REASON_KEYS,
    IMPACT_REASON_KEYS,
    reason_fields_valid,
    sanitize_reason_fields,
)
from automotive_tara.topology import TopologyChannelIndex, normalize_text


SUPPORTED_FEASIBILITY_METHODS = {
    "attack_potential",
    "attack_vector",
    "cvss",
    "heavens",
}
SUPPORTED_IMPACT_METHODS = {"21434", "heavens", "heavens_4level"}


@dataclass(frozen=True)
class BaselineTopologyContext:
    """An anonymisation-free in-memory view of frozen engineering input."""

    channels: tuple[dict[str, Any], ...]
    alias_to_channel: Mapping[str, str]
    channel_to_alias: Mapping[str, str]
    interface_to_components: Mapping[str, tuple[str, ...]]
    interface_attack_vectors: Mapping[str, str]
    component_name_to_id: Mapping[str, str]

    def prompt_payload(self) -> dict[str, Any]:
        return {
            "communication_channels": list(self.channels),
            "external_interfaces": [
                {
                    "interface": interface,
                    "entry_components": list(components),
                    "attack_vector": self.interface_attack_vectors.get(
                        interface, ""
                    ),
                }
                for interface, components in sorted(
                    self.interface_to_components.items()
                )
            ],
        }


@dataclass
class DirectBaselineValidation:
    analysis_ref: str
    valid: bool
    issues: list[dict[str, Any]] = field(default_factory=list)
    normalized_result: dict[str, Any] = field(default_factory=dict)


def analysis_reference(task: TaskUnit) -> str:
    """Compatibility wrapper for the shared experiment reference."""

    return task_analysis_reference(task)


def build_baseline_topology_context(
    channel_index: TopologyChannelIndex,
    external_interfaces: Sequence[Mapping[str, Any]],
) -> BaselineTopologyContext:
    """Create stable aliases while retaining raw channel IDs internally."""

    sorted_channels = sorted(channel_index.channel_to_components)
    channel_to_alias = {
        channel_id: f"C{position:02d}"
        for position, channel_id in enumerate(sorted_channels, start=1)
    }
    alias_to_channel = {
        alias: channel_id for channel_id, alias in channel_to_alias.items()
    }
    channels: list[dict[str, Any]] = []
    for channel_id in sorted_channels:
        member_names = sorted(
            channel_index.component_by_id[component_id].name
            for component_id in channel_index.channel_to_components[channel_id]
        )
        channels.append(
            {
                "channel": channel_to_alias[channel_id],
                "protocol": channel_index.channel_to_protocol.get(
                    channel_id, ""
                ),
                "members": member_names,
                "direction": "bidirectional",
            }
        )

    interface_to_components: dict[str, set[str]] = {}
    interface_attack_vectors: dict[str, str] = {}
    for item in external_interfaces:
        component_name = normalize_text(item.get("related_component"))
        interfaces = item.get("all_interfaces") or [
            item.get("external_interface")
        ]
        for raw_interface in interfaces:
            interface = normalize_text(raw_interface)
            if interface and component_name:
                interface_to_components.setdefault(interface, set()).add(
                    component_name
                )
                vector = normalize_attack_vector(item.get("attack_vector"))
                if vector:
                    interface_attack_vectors[interface] = vector

    component_name_to_id = {
        component.name: component_id
        for component_id, component in channel_index.component_by_id.items()
        if component.name
    }
    return BaselineTopologyContext(
        channels=tuple(channels),
        alias_to_channel=alias_to_channel,
        channel_to_alias=channel_to_alias,
        interface_to_components={
            key: tuple(sorted(value))
            for key, value in interface_to_components.items()
        },
        interface_attack_vectors=interface_attack_vectors,
        component_name_to_id=component_name_to_id,
    )


def expected_route_target(task: TaskUnit) -> str:
    """Return the internal vehicle endpoint the route must reach."""

    source = normalize_text(task.source)
    target = normalize_text(task.target)
    if task.asset_type == "信号":
        if task.target_is_external and not task.source_is_external:
            return source
        if task.source_is_external and not task.target_is_external:
            return target
        return target or source
    if task.asset_type == "部件":
        return target or normalize_text(task.asset_name)
    return target or normalize_text(task.asset_name)


def _feasibility_properties(
    method: str,
    *,
    include_reasons: bool,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    if method == "attack_potential":
        properties = {
            key: {"type": "integer", "enum": values}
            for key, values in AP_ALLOWED_VALUES.items()
        }
        reason_keys = AP_REASON_KEYS
    elif method == "heavens":
        properties = {
            key: {"type": "integer", "enum": values}
            for key, values in HEAVENS_AP_ALLOWED_VALUES.items()
        }
        reason_keys = HEAVENS_REASON_KEYS
    elif method == "cvss":
        properties = {
            "complexity": {"type": "string", "enum": sorted(CVSS_C)},
            "privileges": {"type": "string", "enum": sorted(CVSS_P)},
            "user_interaction": {
                "type": "string",
                "enum": sorted(CVSS_U),
            },
        }
        reason_keys = CVSS_REASON_KEYS
    elif method == "attack_vector":
        properties = {}
        reason_keys = ("feasibility_reason",)
    else:
        raise ValueError(f"不支持的 Direct-LLM 可行性方法: {method}")
    required = list(properties)
    if include_reasons:
        for key in reason_keys:
            properties[key] = {"type": "string", "minLength": 1}
        required.extend(reason_keys)
    return properties, required


def direct_baseline_response_format(
    feasibility_method: str,
    *,
    include_reasons: bool,
) -> dict[str, Any]:
    """Strict one-unit schema used equally by all compared models."""

    feasibility_properties, feasibility_required = _feasibility_properties(
        feasibility_method,
        include_reasons=include_reasons,
    )
    impact_properties: dict[str, dict[str, Any]] = {
        key: {"type": "integer", "minimum": 1, "maximum": 4}
        for key in ("Safety", "Finance", "Operation", "Privacy")
    }
    impact_required = list(impact_properties)
    if include_reasons:
        for key in IMPACT_REASON_KEYS:
            impact_properties[key] = {"type": "string", "minLength": 1}
        impact_required.extend(IMPACT_REASON_KEYS)

    schema = {
        "type": "object",
        "properties": {
            "analysis_ref": {"type": "string", "minLength": 1},
            "damage_scenario": {"type": "string", "minLength": 1},
            "threat_scenario": {"type": "string", "minLength": 1},
            "impact": {
                "type": "object",
                "properties": impact_properties,
                "required": impact_required,
                "additionalProperties": False,
            },
            "attack_paths": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "properties": {
                        "external_interface": {
                            "type": "string",
                            "minLength": 1,
                        },
                        "route_components": {
                            "type": "array",
                            "minItems": 1,
                            "items": {"type": "string", "minLength": 1},
                        },
                        "route_channels": {
                            "type": "array",
                            "minItems": 0,
                            "items": {"type": "string", "minLength": 1},
                        },
                        "attack_vector": {
                            "type": "string",
                            "enum": [
                                "network",
                                "adjacent",
                                "local",
                                "physical",
                            ],
                        },
                        "attack_path": {
                            "type": "string",
                            "minLength": 1,
                        },
                        "feasibility": {
                            "type": "object",
                            "properties": feasibility_properties,
                            "required": feasibility_required,
                            "additionalProperties": False,
                        },
                    },
                    "required": [
                        "external_interface",
                        "route_components",
                        "route_channels",
                        "attack_vector",
                        "attack_path",
                        "feasibility",
                    ],
                    "additionalProperties": False,
                },
            },
        },
        "required": [
            "analysis_ref",
            "damage_scenario",
            "threat_scenario",
            "impact",
            "attack_paths",
        ],
        "additionalProperties": False,
    }
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "tara_direct_llm_baseline",
            "strict": True,
            "schema": schema,
        },
    }


def build_direct_baseline_prompt(
    task: TaskUnit,
    topology_context: BaselineTopologyContext,
    *,
    impact_method: str,
    feasibility_method: str,
    include_reasons: bool,
) -> str:
    if impact_method not in SUPPORTED_IMPACT_METHODS:
        raise ValueError(f"不支持的影响方法: {impact_method}")
    if feasibility_method not in SUPPORTED_FEASIBILITY_METHODS:
        raise ValueError(f"不支持的可行性方法: {feasibility_method}")
    if impact_method == "heavens" and feasibility_method != "heavens":
        raise ValueError("HEAVENS 五级影响必须与 HEAVENS 五级可行性配对")

    payload = {
        "analysis_ref": analysis_reference(task),
        "asset_context": {
            "function": task.function,
            "asset_name": task.asset_name,
            "asset_type": task.asset_type,
            "security_attribute": task.attribute_name,
            "threat_type": task.threat_type,
            "asset_details": task.asset_details or "（无）",
        },
        "dfd_context": {
            "element": task.element_index or "（无）",
            "source": task.source or "（无）",
            "target": task.target or "（无）",
            "protocol": task.flow_protocol or "（无）",
            "source_is_external": task.source_is_external,
            "target_is_external": task.target_is_external,
        },
        "required_internal_route_target": expected_route_target(task),
        "rating_configuration": {
            "impact_method": impact_method,
            "feasibility_method": feasibility_method,
            "rating_reasons": "required" if include_reasons else "forbidden",
        },
        "topology_context": topology_context.prompt_payload(),
    }
    import orjson

    return (
        "请对以下一个分析单元直接生成完整 TARA 对照结果。"
        "analysis_ref 必须原样返回。\n"
        + orjson.dumps(payload).decode("utf-8")
    )


def _issue(
    issues: list[dict[str, Any]],
    code: str,
    message: str,
    *,
    path_index: int | None = None,
) -> None:
    item: dict[str, Any] = {"code": code, "message": message}
    if path_index is not None:
        item["path_index"] = path_index
    issues.append(item)


def _validate_impact(
    impact: Any,
    *,
    include_reasons: bool,
    issues: list[dict[str, Any]],
) -> dict[str, Any]:
    if not isinstance(impact, dict):
        _issue(issues, "IMPACT_MISSING", "影响评级对象缺失")
        return {}
    normalized: dict[str, Any] = {}
    for key in ("Safety", "Finance", "Operation", "Privacy"):
        value = impact.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 4:
            _issue(issues, "IMPACT_VALUE_INVALID", f"{key}评级必须为1至4")
        else:
            normalized[key] = value
    if include_reasons:
        sanitized = sanitize_reason_fields(
            impact,
            IMPACT_REASON_KEYS,
            enabled=True,
        )
        if sanitized is None:
            _issue(issues, "IMPACT_REASON_INVALID", "影响评级理由缺失或无效")
        else:
            for key in IMPACT_REASON_KEYS:
                normalized[key] = sanitized[key]
    elif any("reason" in str(key).lower() for key in impact):
        _issue(issues, "IMPACT_REASON_FORBIDDEN", "关闭理由时返回了影响评级理由")
    return normalized


def _validate_feasibility(
    value: Any,
    method: str,
    *,
    include_reasons: bool,
    issues: list[dict[str, Any]],
    path_index: int,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        _issue(
            issues,
            "FEASIBILITY_MISSING",
            "攻击可行性评级对象缺失",
            path_index=path_index,
        )
        return {}
    if method == "attack_potential":
        allowed = AP_ALLOWED_VALUES
        reason_keys = AP_REASON_KEYS
    elif method == "heavens":
        allowed = HEAVENS_AP_ALLOWED_VALUES
        reason_keys = HEAVENS_REASON_KEYS
    elif method == "cvss":
        allowed = {
            "complexity": set(CVSS_C),
            "privileges": set(CVSS_P),
            "user_interaction": set(CVSS_U),
        }
        reason_keys = CVSS_REASON_KEYS
    else:
        allowed = {}
        reason_keys = ("feasibility_reason",)

    normalized: dict[str, Any] = {}
    for key, allowed_values in allowed.items():
        raw = value.get(key)
        candidate = raw.lower().strip() if isinstance(raw, str) else raw
        if candidate not in allowed_values:
            _issue(
                issues,
                "FEASIBILITY_VALUE_INVALID",
                f"{key}取值不在所选方法允许范围内",
                path_index=path_index,
            )
        else:
            normalized[key] = candidate
    if include_reasons:
        if not reason_fields_valid(value, reason_keys, enabled=True):
            _issue(
                issues,
                "FEASIBILITY_REASON_INVALID",
                "攻击可行性评级理由缺失或无效",
                path_index=path_index,
            )
        else:
            sanitized = sanitize_reason_fields(
                value, reason_keys, enabled=True
            ) or {}
            for key in reason_keys:
                normalized[key] = sanitized[key]
    elif any("reason" in str(key).lower() for key in value):
        _issue(
            issues,
            "FEASIBILITY_REASON_FORBIDDEN",
            "关闭理由时返回了攻击可行性评级理由",
            path_index=path_index,
        )
    return normalized


def _route_link_evidence(
    channel_index: TopologyChannelIndex,
    channel_id: str,
    source_id: str,
    target_id: str,
) -> list[str]:
    pair = (source_id, target_id) if source_id <= target_id else (target_id, source_id)
    direct = channel_index.pair_link_ids.get(
        (channel_id, pair[0], pair[1]), set()
    )
    if direct:
        return sorted(direct)
    evidence = set(
        channel_index.endpoint_link_ids.get((channel_id, source_id), set())
    )
    evidence.update(
        channel_index.endpoint_link_ids.get((channel_id, target_id), set())
    )
    return sorted(evidence)


def _normalize_path_result(
    path: Mapping[str, Any],
    task: TaskUnit,
    topology_context: BaselineTopologyContext,
    channel_index: TopologyChannelIndex,
    *,
    feasibility_method: str,
    include_reasons: bool,
    issues: list[dict[str, Any]],
    path_index: int,
) -> dict[str, Any]:
    components = [
        normalize_text(item)
        for item in path.get("route_components", [])
        if normalize_text(item)
    ] if isinstance(path.get("route_components"), list) else []
    channel_aliases = [
        normalize_text(item)
        for item in path.get("route_channels", [])
        if normalize_text(item)
    ] if isinstance(path.get("route_channels"), list) else []
    interface = normalize_text(path.get("external_interface"))
    attack_text = normalize_text(path.get("attack_path"))
    attack_vector = normalize_attack_vector(path.get("attack_vector"))

    if len(channel_aliases) != max(0, len(components) - 1):
        _issue(
            issues,
            "ROUTE_LENGTH_MISMATCH",
            "route_channels数量必须比route_components少1",
            path_index=path_index,
        )
    if interface not in topology_context.interface_to_components:
        _issue(
            issues,
            "ROUTE_INTERFACE_UNKNOWN",
            f"外部接口[{interface or '空'}]不在冻结输入中",
            path_index=path_index,
        )
    elif not components or components[0] not in topology_context.interface_to_components[interface]:
        _issue(
            issues,
            "ROUTE_ENTRY_COMPONENT_INVALID",
            f"路线首节点未与外部接口[{interface}]映射部件一致",
            path_index=path_index,
        )

    expected_target = expected_route_target(task)
    if not components or components[-1] != expected_target:
        _issue(
            issues,
            "ROUTE_TARGET_INVALID",
            f"路线末节点必须为[{expected_target}]",
            path_index=path_index,
        )
    if len({normalize_text(item).casefold() for item in components}) != len(components):
        _issue(
            issues,
            "ROUTE_CYCLE",
            "路线部件不能重复，检测到回环",
            path_index=path_index,
        )
    component_ids: list[str] = []
    for name in components:
        component_id = topology_context.component_name_to_id.get(name, "")
        if not component_id:
            _issue(
                issues,
                "ROUTE_COMPONENT_UNKNOWN",
                f"路线部件[{name}]不在冻结拓扑中",
                path_index=path_index,
            )
        component_ids.append(component_id)

    evidence: list[dict[str, Any]] = []
    resolved_channels: list[str] = []
    for hop_index, channel_alias in enumerate(channel_aliases):
        channel_id = topology_context.alias_to_channel.get(channel_alias, "")
        resolved_channels.append(channel_id)
        if not channel_id:
            _issue(
                issues,
                "ROUTE_CHANNEL_UNKNOWN",
                f"通信信道[{channel_alias}]不在冻结拓扑中",
                path_index=path_index,
            )
            continue
        if hop_index + 1 >= len(component_ids):
            continue
        source_id = component_ids[hop_index]
        target_id = component_ids[hop_index + 1]
        members = channel_index.channel_to_components.get(channel_id, set())
        if not source_id or not target_id or source_id not in members or target_id not in members:
            _issue(
                issues,
                "ROUTE_CHANNEL_MEMBERSHIP_INVALID",
                f"路线第{hop_index + 1}跳的两个ECU未共同挂接[{channel_alias}]",
                path_index=path_index,
            )
        evidence.append(
            {
                "hop": hop_index + 1,
                "channel": channel_alias,
                "topology_link_ids": _route_link_evidence(
                    channel_index, channel_id, source_id, target_id
                ) if source_id and target_id else [],
            }
        )

    for transition_index in range(1, len(resolved_channels)):
        previous_channel = resolved_channels[transition_index - 1]
        current_channel = resolved_channels[transition_index]
        if not previous_channel or not current_channel or previous_channel == current_channel:
            continue
        transition_id = component_ids[transition_index] if transition_index < len(component_ids) else ""
        component = channel_index.component_by_id.get(transition_id)
        attached = channel_index.component_to_channels.get(transition_id, set())
        if not component or not {previous_channel, current_channel}.issubset(attached):
            _issue(
                issues,
                "ROUTE_GATEWAY_TRANSITION_INVALID",
                "跨信道位置缺少同时挂接两个信道的网关或控制器",
                path_index=path_index,
            )

    feasibility = _validate_feasibility(
        path.get("feasibility"),
        feasibility_method,
        include_reasons=include_reasons,
        issues=issues,
        path_index=path_index,
    )
    if not attack_text:
        _issue(
            issues,
            "ATTACK_PATH_EMPTY",
            "攻击路径自然语言为空",
            path_index=path_index,
        )
    if not attack_vector:
        _issue(
            issues,
            "ATTACK_VECTOR_INVALID",
            "攻击向量不是network/adjacent/local/physical",
            path_index=path_index,
        )
    expected_vector = topology_context.interface_attack_vectors.get(interface)
    if expected_vector and attack_vector and attack_vector != expected_vector:
        _issue(
            issues,
            "ATTACK_VECTOR_MISMATCH",
            f"攻击向量[{attack_vector}]与外部接口映射[{expected_vector}]不一致",
            path_index=path_index,
        )
    return {
        "external_interface": interface,
        "route_components": components,
        "route_channels": channel_aliases,
        "attack_vector": attack_vector,
        "attack_path": attack_text,
        "feasibility": feasibility,
        "route_evidence": evidence,
    }


def _add_derived_ratings(
    normalized: dict[str, Any],
    *,
    impact_method: str,
    feasibility_method: str,
) -> None:
    impact = normalized.get("impact", {})
    if len({"Safety", "Finance", "Operation", "Privacy"} - set(impact)):
        return
    impact_value, impact_level = compute_impact_for_method(
        impact, impact_method
    )
    normalized["impact_value"] = impact_value
    normalized["impact_level"] = impact_level
    for path in normalized.get("attack_paths", []):
        params = path.get("feasibility", {})
        vector = path.get("attack_vector", "")
        if feasibility_method == "attack_potential":
            score = calculate_attack_potential_score(params)
            level = calculate_attack_potential_level(score)
        elif feasibility_method == "heavens":
            score = calculate_heavens_ap_score(params)
            level = calculate_heavens_ap_level(score)
        elif feasibility_method == "cvss":
            score = calculate_cvss_score({**params, "attack_vector": vector})
            level = calculate_cvss_level(score)
        else:
            score = None
            level = calculate_attack_vector_level(vector)
        path["feasibility_score"] = score
        path["feasibility_level"] = level
        if impact_method == "heavens" and feasibility_method == "heavens":
            risk_label, risk_value = calculate_heavens_risk_value(
                impact_level, level
            )
            path["risk_label"] = risk_label
            path["risk_value"] = risk_value
        else:
            matrix_level = (
                HEAVENS_TL_TO_FEASIBILITY.get(level, "Very Low")
                if feasibility_method == "heavens"
                else level
            )
            path["risk_value"] = calculate_risk_value(
                max(1, min(4, int(impact_value))), matrix_level
            )


def validate_direct_baseline_response(
    response: str | Mapping[str, Any],
    task: TaskUnit,
    topology_context: BaselineTopologyContext,
    channel_index: TopologyChannelIndex,
    *,
    impact_method: str,
    feasibility_method: str,
    include_reasons: bool,
) -> DirectBaselineValidation:
    analysis_ref = analysis_reference(task)
    issues: list[dict[str, Any]] = []
    try:
        parsed = safe_parse_json(response) if isinstance(response, str) else dict(response)
    except Exception as exc:
        return DirectBaselineValidation(
            analysis_ref,
            False,
            [{"code": "JSON_INVALID", "message": str(exc)}],
            {},
        )
    if not isinstance(parsed, dict):
        return DirectBaselineValidation(
            analysis_ref,
            False,
            [{"code": "ROOT_INVALID", "message": "根对象必须是JSON对象"}],
            {},
        )
    if normalize_text(parsed.get("analysis_ref")) != analysis_ref:
        _issue(issues, "ANALYSIS_REF_MISMATCH", "analysis_ref未原样返回")
    damage = normalize_text(parsed.get("damage_scenario"))
    threat = normalize_text(parsed.get("threat_scenario"))
    if not damage:
        _issue(issues, "DAMAGE_SCENARIO_EMPTY", "损害场景为空")
    if not threat:
        _issue(issues, "THREAT_SCENARIO_EMPTY", "威胁场景为空")
    impact = _validate_impact(
        parsed.get("impact"),
        include_reasons=include_reasons,
        issues=issues,
    )
    raw_paths = parsed.get("attack_paths")
    if not isinstance(raw_paths, list) or len(raw_paths) < 1:
        _issue(issues, "ATTACK_PATH_COUNT_INVALID", "攻击路径数量必须至少为1")
        raw_paths = raw_paths if isinstance(raw_paths, list) else []
    normalized_paths: list[dict[str, Any]] = []
    seen_routes: set[tuple[Any, ...]] = set()
    seen_texts: set[str] = set()
    for index, raw_path in enumerate(raw_paths):
        if not isinstance(raw_path, Mapping):
            _issue(
                issues,
                "ATTACK_PATH_ITEM_INVALID",
                "攻击路径项必须为对象",
                path_index=index,
            )
            continue
        normalized_path = _normalize_path_result(
            raw_path,
            task,
            topology_context,
            channel_index,
            feasibility_method=feasibility_method,
            include_reasons=include_reasons,
            issues=issues,
            path_index=index,
        )
        signature = (
            tuple(normalized_path["route_components"]),
            tuple(normalized_path["route_channels"]),
            normalized_path["external_interface"],
        )
        if signature in seen_routes:
            _issue(
                issues,
                "ROUTE_DUPLICATE",
                "返回了重复的拓扑路线",
                path_index=index,
            )
        seen_routes.add(signature)
        text_key = normalized_path["attack_path"].lower()
        if text_key in seen_texts:
            _issue(
                issues,
                "ATTACK_PATH_TEXT_DUPLICATE",
                "返回了完全重复的攻击路径文本",
                path_index=index,
            )
        seen_texts.add(text_key)
        normalized_paths.append(normalized_path)

    normalized = {
        "analysis_ref": analysis_ref,
        "damage_scenario": damage,
        "threat_scenario": threat,
        "impact": impact,
        "attack_paths": normalized_paths,
    }
    _add_derived_ratings(
        normalized,
        impact_method=impact_method,
        feasibility_method=feasibility_method,
    )
    return DirectBaselineValidation(
        analysis_ref=analysis_ref,
        valid=not issues,
        issues=issues,
        normalized_result=normalized,
    )


def run_direct_baseline_unit(
    task: TaskUnit,
    topology_context: BaselineTopologyContext,
    channel_index: TopologyChannelIndex,
    *,
    llm_call: Callable[..., str],
    impact_method: str,
    feasibility_method: str,
    include_reasons: bool,
    max_tokens: int = 2048,
) -> tuple[str, DirectBaselineValidation]:
    """Run one independent baseline request without hidden retries."""

    user_prompt = build_direct_baseline_prompt(
        task,
        topology_context,
        impact_method=impact_method,
        feasibility_method=feasibility_method,
        include_reasons=include_reasons,
    )
    raw = llm_call(
        DIRECT_LLM_BASELINE_SYSTEM_PROMPT,
        user_prompt,
        retries=0,
        max_tokens=max_tokens,
        response_format=direct_baseline_response_format(
            feasibility_method,
            include_reasons=include_reasons,
        ),
    )
    validation = validate_direct_baseline_response(
        raw,
        task,
        topology_context,
        channel_index,
        impact_method=impact_method,
        feasibility_method=feasibility_method,
        include_reasons=include_reasons,
    )
    return raw, validation
