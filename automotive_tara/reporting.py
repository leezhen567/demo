"""TARA JSON 报告组装与 Excel 文本安全处理。"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .domain import (
    STATUS_NOT_APPLICABLE,
    STATUS_VALID,
    TaskUnit,
    calculate_heavens_dimension_values,
    calculate_heavens_impact_value,
)
from .reason_policy import IMPACT_REASON_KEYS
from .security_requirements import (
    flatten_security_requirements,
    match_security_requirements,
)


FEASIBILITY_REASON_KEYS = {
    "attack_vector_reason",
    "complexity_reason",
    "privileges_reason",
    "user_interaction_reason",
    "Exposure_time_reason",
    "Professional_experience_reason",
    "Required_information_reason",
    "Opportunity_window_reason",
    "Required_equipment_reason",
    "Expertise_reason",
    "Knowledge_about_TOE_reason",
    "Window_of_Opportunity_reason",
    "Equipment_reason",
}


def strip_feasibility_reasons(
    attack_details: list[dict],
    *,
    enable_reason: bool,
    attack_path_cleaner: Callable[[Any], str] | None = None,
) -> list[dict]:
    result = []
    for attack_detail in attack_details:
        detail = dict(attack_detail)
        if "attack_path" in detail and attack_path_cleaner is not None:
            detail["attack_path"] = attack_path_cleaner(
                detail["attack_path"]
            )
        if "attack_parameters" in detail:
            parameters = dict(detail["attack_parameters"] or {})
            if not enable_reason:
                parameters = {
                    key: value
                    for key, value in parameters.items()
                    if key not in FEASIBILITY_REASON_KEYS
                    and "reason" not in str(key).lower()
                    and "理由" not in str(key)
                }
            detail["attack_parameters"] = parameters
        result.append(detail)
    return result


def strip_impact_reasons(
    influence_parameters: dict,
    *,
    enable_reason: bool,
) -> dict:
    if enable_reason:
        return influence_parameters
    return {
        key: value
        for key, value in influence_parameters.items()
        if key not in IMPACT_REASON_KEYS
        and "reason" not in str(key).lower()
        and "理由" not in str(key)
    }


def impact_parameters_for_report(
    influence_parameters: dict,
    impact_method: str,
    *,
    enable_reason: bool,
) -> dict:
    parameters = strip_impact_reasons(
        influence_parameters,
        enable_reason=enable_reason,
    )
    if impact_method in {"heavens", "heavens_4level"}:
        return calculate_heavens_dimension_values(parameters)
    return parameters


def report_element_index(task: TaskUnit) -> str:
    """报告元素编号：信号保留 DFD flow，其他资产直接使用资产名称。"""
    if str(task.asset_type).strip() == "信号":
        return str(task.element_index).strip()
    return str(task.asset_name).strip()


def build_tara_report(
    tasks: list[TaskUnit],
    feasibility_method: str,
    impact_method: str = "",
    *,
    enable_reason: bool,
    enable_asset_details: bool = True,
    attack_path_cleaner: Callable[[Any], str] | None = None,
    security_requirement_matcher: Callable[..., list[dict[str, Any]]] | None = None,
) -> list[dict]:
    requirement_matcher = security_requirement_matcher or match_security_requirements
    function_map: dict[str, dict] = {}
    for task in tasks:
        element_index = report_element_index(task)
        function_entry = function_map.setdefault(
            task.function,
            {"function": task.function, "assets": {}},
        )
        asset_key = (
            task.element_index,
            task.asset_name,
            task.asset_type,
            task.target,
            task.source,
        )
        asset_base = {
            "element_id": task.element_id,
            "element_index": element_index,
            "dfd_element_type": task.dfd_element_type,
            "asset_name": task.asset_name,
            "asset_type": task.asset_type,
            "source": task.source,
            "target": task.target,
            "security_attributes": [],
        }
        # These fields are machine-readable mapping evidence.  They are kept
        # in JSON (the Excel layout remains unchanged) so a requirement
        # matcher/auditor can distinguish a signal category from its concrete
        # DFD signal value without parsing display text.
        if task.signal_category:
            asset_base["signal_category"] = task.signal_category
        if task.data_type:
            asset_base["data_type"] = task.data_type
        if enable_asset_details:
            asset_base["asset_details"] = task.asset_details
        asset_entry = function_entry["assets"].setdefault(
            asset_key,
            asset_base,
        )
        treatment_fields = cybersecurity_fields_for_treatment(
            risk_treatment=task.risk_treatment,
            asset_name=task.asset_name,
            attribute_name=task.attribute_name,
            threat_type=task.threat_type,
            function_name=task.function,
        )
        cleaned_attack = strip_feasibility_reasons(
            task.attack_details,
            enable_reason=enable_reason,
            attack_path_cleaner=attack_path_cleaner,
        )
        # Older Stage-C checkpoints can contain attack_details without the
        # newer audit fields. Never silently label those paths as model-made.
        for path_index, attack_detail in enumerate(cleaned_attack):
            if "attack_path_source" in attack_detail:
                continue
            provenance = (
                task.attack_path_provenance[path_index]
                if path_index < len(task.attack_path_provenance or [])
                else {}
            )
            provenance = provenance if isinstance(provenance, dict) else {}
            generation = str(provenance.get("generation_source") or "")
            model_generated = generation in {"llm_complete", "cache_llm_complete"}
            attack_detail["attack_path_source"] = (
                "模型生成" if model_generated else
                "模板兜底" if generation == "template_fallback"
                else "来源待核验"
            )
            attack_detail["attack_path_generation_source"] = generation or "unknown"
            attack_detail["attack_path_fallback_reason"] = (
                "" if model_generated else
                str(provenance.get("fallback_reason") or "missing_generation_record")
            )
            attack_detail["review_required"] = bool(
                attack_detail.get("review_required") or not model_generated
            )
            attack_detail["review_reasons"] = [
                *list(attack_detail.get("review_reasons") or []),
                *([] if model_generated else [
                    f"攻击路径来源待复核：{attack_detail['attack_path_fallback_reason']}"
                ]),
            ]
        path_requirements: list[list[dict[str, Any]]] = []
        for path_index, attack_detail in enumerate(cleaned_attack):
            attack_treatment = attack_detail.get(
                "risk_treatment", task.risk_treatment
            )
            attack_detail.update(
                cybersecurity_fields_for_treatment(
                    risk_treatment=attack_treatment,
                    asset_name=task.asset_name,
                    attribute_name=task.attribute_name,
                    threat_type=task.threat_type,
                    function_name=task.function,
                )
            )
            # A preceding residual-risk stage may have already selected and
            # frozen the exact workbook rows for this path.  Reuse those rows
            # even when the implemented controls lower the residual treatment
            # to risk acceptance; rematching here would both waste an LLM call
            # and erase the audit trail of controls that produced the result.
            if "security_requirements" in attack_detail:
                attack_requirements = list(
                    attack_detail.get("security_requirements") or []
                )
            else:
                attack_requirements = (
                    requirement_matcher(
                        task,
                        attack_detail=attack_detail,
                        path_index=path_index,
                    )
                    if str(attack_treatment or "").strip().casefold()
                    in {"风险缓解", "risk mitigation", "mitigation"}
                    else []
                )
            path_requirements.append(attack_requirements)
            attack_detail["security_requirements"] = attack_requirements
            attack_detail["security_requirement_match_status"] = (
                "implemented"
                if attack_detail.get("security_requirements_implemented")
                and attack_requirements
                else "matched" if attack_requirements else (
                    "no_template_match"
                    if str(attack_treatment or "").strip().casefold()
                    in {"风险缓解", "risk mitigation", "mitigation"}
                    else "not_applicable"
                )
            )
            attack_detail.update(
                flatten_security_requirements(attack_requirements)
            )
        detail = {
            "attribute_name": task.attribute_name,
            "cache_dependencies": task.cache_dependencies,
            "threat_type": task.threat_type,
            "damage_scenario": task.damage_scenario,
            "threat_scenarios": task.threat_scenarios,
            "r155_references": task.r155_references,
            "influence_parameters": impact_parameters_for_report(
                task.influence_parameters,
                impact_method,
                enable_reason=enable_reason,
            ),
            "impact_value": (
                None
                if task.analysis_status == STATUS_NOT_APPLICABLE
                else (
                    calculate_heavens_impact_value(
                        task.influence_parameters
                    )
                    if impact_method == "heavens"
                    else task.impact_value
                )
            ),
            "impact_level": (
                ""
                if task.analysis_status == STATUS_NOT_APPLICABLE
                else task.impact_level
            ),
            "impact_method": impact_method,
            "feasibility_method": feasibility_method,
            "analysis_status": task.analysis_status,
            "status_reasons": task.status_reasons,
            "input_mapping_conflicts": task.input_mapping_conflicts,
            "task_risk_value": task.risk_value,
            "task_risk_treatment": task.risk_treatment,
            **treatment_fields,
            "attack": cleaned_attack,
            "influence_confidence": task.influence_confidence,
            "impact_confidence": task.impact_confidence,
            "feasibility_confidence": task.feasibility_confidence,
        }
        if task.low_confidence_flags:
            detail["low_confidence_flags"] = task.low_confidence_flags
        if task.errors:
            detail["errors"] = task.errors
        # Security requirements are deterministic workbook mappings and are
        # only applicable to risk mitigation. Acceptance, not-applicable and
        # undecided rows intentionally keep all three cells empty.
        # Attribute-level cells are an aggregate convenience for JSON
        # consumers.  When path-level results exist, aggregate only the
        # requirements of paths whose own treatment is mitigation; never
        # re-run a task-wide interface-union match and leak it into another
        # path.  For legacy/no-path reports retain the task-level fallback.
        if cleaned_attack:
            matched_requirements = []
            seen_requirement_ids: set[str] = set()
            for requirements in path_requirements:
                for requirement in requirements:
                    key = str(
                        requirement.get("requirement_id")
                        or requirement.get("requirement")
                        or requirement.get("name")
                        or ""
                    )
                    if key and key in seen_requirement_ids:
                        continue
                    if key:
                        seen_requirement_ids.add(key)
                    matched_requirements.append(requirement)
        else:
            matched_requirements = (
                requirement_matcher(task)
                if str(task.risk_treatment or "").strip().casefold()
                in {"风险缓解", "risk mitigation", "mitigation"}
                else []
            )
        detail["security_requirements"] = matched_requirements
        detail["security_requirement_match_status"] = (
            "matched" if matched_requirements else (
                "no_template_match"
                if str(task.risk_treatment or "").strip().casefold()
                in {"风险缓解", "risk mitigation", "mitigation"}
                else "not_applicable"
            )
        )
        detail.update(flatten_security_requirements(matched_requirements))
        asset_entry["security_attributes"].append(detail)
    return [
        {
            "function": function_entry["function"],
            "assets": list(function_entry["assets"].values()),
        }
        for function_entry in function_map.values()
    ]


def _fallback_review_items(task: TaskUnit) -> list[dict]:
    items = [
        {
            "path_index": index + 1,
            "path_id": str(item.get("path_id") or ""),
            "generation_source": str(item.get("generation_source") or ""),
            "fallback_reason": str(item.get("fallback_reason") or "missing_generation_record"),
            "review_required": True,
        }
        for index, item in enumerate(task.attack_path_provenance or [])
        if isinstance(item, dict)
        and item.get("generation_source") not in {"llm_complete", "cache_llm_complete"}
    ]
    for index in range(len(task.attack_path_provenance or []), len(task.attack_details or [])):
        items.append({
            "path_index": index + 1,
            "path_id": "",
            "generation_source": "unknown",
            "fallback_reason": "missing_generation_record",
            "review_required": True,
        })
    return items


def build_error_report(tasks: list[TaskUnit]) -> list[dict]:
    return [
        {
            "task_id": task.task_id,
            "element_id": task.element_id,
            "element_index": report_element_index(task),
            "dfd_element_type": task.dfd_element_type,
            "function": task.function,
            "asset_name": task.asset_name,
            "asset_type": task.asset_type,
            "attribute_name": task.attribute_name,
            "threat_type": task.threat_type,
            "analysis_status": task.analysis_status,
            "status_reasons": task.status_reasons,
            "input_mapping_conflicts": task.input_mapping_conflicts,
            "errors": task.errors,
            "review_paths": _fallback_review_items(task),
        }
        for task in tasks
        if task.errors or task.analysis_status != STATUS_VALID or _fallback_review_items(task)
    ]


def format_confidence(value: float | None) -> str:
    if value is None:
        return ""
    try:
        return f"{float(value):.0%}"
    except (TypeError, ValueError):
        return ""


def format_risk_value(attack: dict, is_heavens: bool) -> str:
    value = attack.get("risk_value", "")
    if value is None:
        return ""
    if is_heavens:
        numeric_value = attack.get("risk_value_num", "")
        if value and numeric_value:
            return f"{value} ({numeric_value})"
        return str(value)
    return str(value) if value != "" else ""


def sanitize_excel_text(value: str) -> str:
    value = value.lstrip()
    if value and value[0] in ("=", "+", "-", "@"):
        return "'" + value
    return value


def excel_cell_value(value: Any) -> Any:
    if value is None:
        return "None"
    if isinstance(value, str):
        return sanitize_excel_text(value)
    return value


def normalize_excel_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return sanitize_excel_text(
            "\n".join(
                str(item).strip()
                for item in value
                if item is not None
            )
        )
    return sanitize_excel_text(str(value).strip())


def generate_cybersecurity_goal(
    asset_name: str,
    attribute_name: str,
    threat_type: str,
    function_name: str = "",
) -> str:
    """Generate the fixed cybersecurity-goal template.

    ``threat_type`` and ``function_name`` remain accepted for API/checkpoint
    compatibility but are intentionally not interpolated into the goal.
    """
    del threat_type, function_name
    return f"应保障{asset_name}的{attribute_name}不受侵害。"


def generate_cybersecurity_claim(
    asset_name: str,
    attribute_name: str,
    threat_type: str,
) -> str:
    """Generate the fixed risk-acceptance claim template."""
    del attribute_name
    return (
        f"基于{asset_name}资产的风险等级，声明对该资产的"
        f"{threat_type}类型威胁执行接受策略。"
    )


def cybersecurity_fields_for_treatment(
    *,
    risk_treatment: Any,
    asset_name: str,
    attribute_name: str,
    threat_type: str,
    function_name: str = "",
) -> dict[str, str]:
    """按风险处置互斥生成网络安全目标或网络安全声明。

    风险缓解对应 cybersecurity goal，风险接受对应 cybersecurity claim；
    未决、未覆盖或不适用的项目不生成任何一类文本，避免报告同时出现两种
    互相矛盾的处置结论。
    """
    treatment = str(risk_treatment or "").strip().casefold()
    if treatment in {"风险缓解", "risk mitigation", "mitigation"}:
        return {
            "cybersecurity_goal": generate_cybersecurity_goal(
                asset_name=asset_name,
                attribute_name=attribute_name,
                threat_type=threat_type,
                function_name=function_name,
            ),
            "cybersecurity_claim": "",
        }
    if treatment in {"风险接受", "risk acceptance", "acceptance"}:
        return {
            "cybersecurity_goal": "",
            "cybersecurity_claim": generate_cybersecurity_claim(
                asset_name=asset_name,
                attribute_name=attribute_name,
                threat_type=threat_type,
            ),
        }
    return {"cybersecurity_goal": "", "cybersecurity_claim": ""}
