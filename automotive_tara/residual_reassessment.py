"""Conservative first stage of implemented-control reassessment."""

from __future__ import annotations

from typing import Any

import orjson

POST_CONTROL_TARGET_RISK_MAX = 2


POST_CONTROL_PATH_SYSTEM_PROMPT = """你是汽车网络安全 TARA 攻击路径分析员。
给定原攻击路径及已经实现且有效运行的安全需求，判断原路径能否继续达成同一威胁目标。
若原步骤被控制阻断，只能在有具体、合理的绕过步骤时提出新的实施后攻击路径。
不得假定安全需求失效、密钥泄露、未知漏洞或新增入口；除非输入提供了相应证据。
新路径必须保持原资产、威胁目标、可信攻击入口和攻击向量，并逐项说明如何绕过适用控制。
若无法提出有依据的新路径，返回 blocked 或 uncertain，不得编造低风险路径。
仅输出符合 schema 的 JSON；不要给出可行性分值。"""


def _control_rows(requirements: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [
        {
            "requirement_id": str(item.get("requirement_id") or "").strip(),
            "requirement": str(
                item.get("requirement") or item.get("security_requirement")
                or item.get("name") or ""
            ).strip()[:800],
        }
        for item in requirements
    ]


def build_post_control_path_prompt(
    task: Any, detail: dict[str, Any], requirements: list[dict[str, Any]]
) -> tuple[str, str]:
    trace = detail.get("topology_trace") or {}
    payload = {
        "function": task.function,
        "asset": task.asset_name,
        "attribute": task.attribute_name,
        "threat_scenario": task.threat_scenarios,
        "original_attack_path": str(detail.get("attack_path") or ""),
        "trusted_external_interface": str(trace.get("external_interface") or ""),
        "trusted_attack_vector": str(detail.get("attack_vector") or ""),
        "implemented_controls": _control_rows(requirements),
    }
    return (
        POST_CONTROL_PATH_SYSTEM_PROMPT,
        "输入：" + orjson.dumps(payload).decode("utf-8") + "\n"
        "请逐项给出 control_analysis：effect 写该控制挡住的原步骤，"
        "bypass 写具体绕过动作；没有可信绕过时 bypass 留空。"
        "status=viable 时 post_control_path 须写清新攻击步骤；"
        "status=blocked/uncertain 时 post_control_path 留空。"
        "basis 写出判断依据，不要只是重复控制文本。",
    )


def post_control_path_response_format() -> dict[str, Any]:
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "post_control_attack_path",
            "strict": True,
            "schema": {
                "type": "object",
                "properties": {
                    "status": {"type": "string", "enum": ["viable", "blocked", "uncertain"]},
                    "post_control_path": {"type": "string"},
                    "basis": {"type": "string"},
                    "control_analysis": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "requirement_id": {"type": "string"},
                                "effect": {"type": "string"},
                                "bypass": {"type": "string"},
                            },
                            "required": ["requirement_id", "effect", "bypass"],
                            "additionalProperties": False,
                        },
                    },
                },
                "required": ["status", "post_control_path", "basis", "control_analysis"],
                "additionalProperties": False,
            },
        },
    }


def validate_post_control_path(
    response: Any, requirements: list[dict[str, Any]], original_path: str
) -> bool:
    """Reject incomplete bypass claims; never turn them into scored paths."""
    if not isinstance(response, dict) or response.get("status") not in {
        "viable", "blocked", "uncertain"
    }:
        return False
    basis = response.get("basis")
    controls = response.get("control_analysis")
    if not isinstance(basis, str) or len(basis.strip()) < 12 or not isinstance(controls, list):
        return False
    expected = [str(item.get("requirement_id") or "").strip() for item in requirements]
    if not expected or not all(expected) or len(expected) != len(set(expected)):
        return False
    ids = [item.get("requirement_id") for item in controls if isinstance(item, dict)]
    if len(ids) != len(expected) or set(ids) != set(expected):
        return False
    for item in controls:
        if not isinstance(item, dict) or not isinstance(item.get("effect"), str):
            return False
        if len(item["effect"].strip()) < 6 or not isinstance(item.get("bypass"), str):
            return False
        if response["status"] == "viable" and len(item["bypass"].strip()) < 8:
            return False
    path = response.get("post_control_path")
    if not isinstance(path, str):
        return False
    if response["status"] == "viable":
        return len(path.strip()) >= 30 and path.strip() != original_path.strip()
    return not path.strip()


def build_post_control_rating_input(
    path_result: dict[str, Any], baseline: dict[str, Any], method: str,
    requirements: list[dict[str, Any]] | None = None,
    rating_constraints: dict[str, Any] | None = None,
) -> str:
    from .domain import AP_ALLOWED_VALUES, HEAVENS_AP_ALLOWED_VALUES

    keys = (("complexity", "privileges", "user_interaction") if method == "cvss"
            else HEAVENS_AP_ALLOWED_VALUES if method == "heavens" else AP_ALLOWED_VALUES)
    parameters = baseline.get("attack_parameters") or {}
    bounds = rating_constraints or {}
    ranges = bounds.get("dimension_ranges") or {}
    if method == "cvss":
        prompt_bounds = {
            "fixed_attack_vector": bounds.get("fixed_attack_vector"),
            "fixed_attack_vector_coefficient": bounds.get("fixed_attack_vector_coefficient"),
            "allowed_C_P_U_labels": {
                key: rule.get("allowed_values") for key, rule in ranges.items()
            },
            "required_feasibility_score_range": bounds.get("feasible_total_score_range"),
            "allowed_feasibility_levels": bounds.get("allowed_feasibility_levels"),
            "target_risk_value": bounds.get("target_risk_value"),
            "candidate_dimension_combinations": bounds.get("candidate_dimension_combinations"),
        }
        numeric_instruction = (
            "CVSS 的攻击向量系数已固定。仅对 C、P、U 选允许的等级；"
            "可行性分数=8.22×攻击向量系数×C系数×P系数×U系数（保留两位小数），"
            f"必须落入给定分数范围，使风险值等于{bounds.get('target_risk_value')}。"
            "CVSS 是乘法，不能按维度求和。"
        )
    else:
        fixed_key = bounds.get("fixed_dimension")
        fixed_value = bounds.get("fixed_dimension_value")
        intervals = bounds.get("feasible_variable_score_intervals") or []
        interval_text = "、".join(
            str(low) if low == high else f"{low}～{high}"
            for low, high in intervals
        )
        prompt_bounds = {
            "fixed_dimension": fixed_key,
            "fixed_value_from_attack_vector": fixed_value,
            "variable_dimension_allowed_values": {
                key: rule.get("allowed_values")
                for key, rule in ranges.items() if key != fixed_key
            },
            "required_variable_score_sum_range": bounds.get("feasible_variable_score_range"),
            "required_variable_score_sum_intervals": intervals,
            "resulting_total_score_range": bounds.get("feasible_total_score_range"),
            "allowed_feasibility_levels": bounds.get("allowed_feasibility_levels"),
            "target_risk_value": bounds.get("target_risk_value"),
            "candidate_dimension_combinations": bounds.get("candidate_dimension_combinations"),
        }
        symbols = (
            "E=Expertise、K=Knowledge_about_TOE、Q=Equipment"
            if method == "heavens" else
            "T=Exposure_time、X=Professional_experience、I=Required_information、Q=Required_equipment"
        )
        numeric_instruction = (
            f"攻击向量已决定固定维度 {fixed_key}={fixed_value}，无需模型选择，也不得改变。"
            f"只对其余维度评分（{symbols}）；这些维度的分值之和必须在 {interval_text}，"
            f"总分=该和+{fixed_value}，最终可行性等级必须属于"
            f"{bounds.get('allowed_feasibility_levels')}，风险值等于"
            f"{bounds.get('target_risk_value')}。"
        )
    context = {
        "original_attack_path": baseline.get("attack_path", ""),
        "post_control_path_status": path_result.get("status", "uncertain"),
        "post_control_path": path_result.get("post_control_path", ""),
        "path_assessment_basis": path_result.get("basis", ""),
        "control_analysis": path_result.get("control_analysis", []),
        "implemented_security_requirements": _control_rows(requirements or []),
        "baseline_dimensions": {key: parameters[key] for key in keys if key in parameters},
        "baseline_feasibility_score": baseline.get("feasibility_score"),
        "baseline_feasibility_level": baseline.get("feasibility_level"),
        "baseline_risk_value": baseline.get("risk_value_num", baseline.get("risk_value")),
    }
    return (
        "【安全需求实施后评级输入】" + orjson.dumps(context).decode("utf-8")
        + "\n【本路径数值硬约束】" + orjson.dumps(prompt_bounds).decode("utf-8")
        + "\n" + numeric_instruction
        + "安全需求按输入假定已实现；依据实施后攻击路径和控制效果逐维给出评分理由。"
        "只能选择合法维度分值，程序会复算得分、等级和风险矩阵。"
    )


def build_target_rating_constraints(
    baseline: dict[str, Any], method: str, impact_index: int,
    impact_level: str, impact_method: str,
) -> dict[str, Any] | None:
    """Compute legal dimension and total-score ranges that can reach risk <= 2."""
    from itertools import product

    from .domain import (
        AP_ALLOWED_VALUES, HEAVENS_AP_ALLOWED_VALUES, CVSS_C, CVSS_P, CVSS_U, CVSS_V,
        OPPORTUNITY_WINDOW_MAP, HEAVENS_WINDOW_BY_VECTOR,
        HEAVENS_TL_TO_FEASIBILITY, calculate_attack_potential_level,
        calculate_cvss_level, calculate_heavens_ap_level, calculate_heavens_risk_value,
        calculate_risk_value, normalize_attack_vector,
    )

    original = baseline.get("attack_parameters") or {}
    vector = normalize_attack_vector(baseline.get("attack_vector") or original.get("attack_vector"))
    baseline_score = baseline.get("feasibility_score")
    if not isinstance(baseline_score, (int, float)):
        return None
    if method == "attack_potential":
        keys = tuple(AP_ALLOWED_VALUES)
        choices = {key: list(AP_ALLOWED_VALUES[key]) for key in keys}
        fixed = {"Opportunity_window"}
        fixed_values = OPPORTUNITY_WINDOW_MAP
        is_cvss = False
    elif method == "heavens":
        keys = tuple(HEAVENS_AP_ALLOWED_VALUES)
        choices = {key: list(HEAVENS_AP_ALLOWED_VALUES[key]) for key in keys}
        fixed = {"Window_of_Opportunity"}
        fixed_values = HEAVENS_WINDOW_BY_VECTOR
        is_cvss = False
    elif method == "cvss":
        labels = {
            "complexity": CVSS_C,
            "privileges": CVSS_P,
            "user_interaction": CVSS_U,
        }
        keys = tuple(labels)
        choices = {
            key: [
                {"label": label, "coefficient": value}
                for label, value in labels[key].items()
            ]
            for key in keys
        }
        fixed = set()
        fixed_values = {}
        is_cvss = True
    else:
        return None

    for key in keys:
        if key not in original:
            return None
        if key in fixed:
            mapped = fixed_values.get(vector)
            if mapped is None or original[key] != mapped:
                return None
            choices[key] = [mapped]
        elif is_cvss:
            choices[key] = [
                item for item in choices[key]
                if item["coefficient"] <= original[key]
            ]
        else:
            choices[key] = [value for value in choices[key] if value >= original[key]]
        if not choices[key]:
            return None

    def evaluate(values: dict[str, Any]) -> tuple[int | float, str, int]:
        if is_cvss:
            score = round(
                8.22 * CVSS_V.get(vector, 0.55)
                * values["complexity"]["coefficient"]
                * values["privileges"]["coefficient"]
                * values["user_interaction"]["coefficient"], 2,
            )
            level = calculate_cvss_level(score)
            return score, level, calculate_risk_value(impact_index, level)
        score = sum(values.values())
        if method == "heavens":
            level = calculate_heavens_ap_level(score)
            if impact_method == "heavens":
                _, risk_num = calculate_heavens_risk_value(impact_level, level)
            else:
                risk_num = calculate_risk_value(
                    impact_index, HEAVENS_TL_TO_FEASIBILITY.get(level, "Very Low")
                )
        else:
            level = calculate_attack_potential_level(score)
            risk_num = calculate_risk_value(impact_index, level)
        return score, level, risk_num

    feasible = []
    for combination in product(*(choices[key] for key in keys)):
        values = dict(zip(keys, combination))
        score, level, risk_num = evaluate(values)
        improved = score < baseline_score if is_cvss else score > baseline_score
        if risk_num <= POST_CONTROL_TARGET_RISK_MAX and improved:
            feasible.append((values, score, level, risk_num))
    if not feasible:
        return None
    # Use the least optimistic risk band that reaches the acceptance target.
    # This avoids pushing every adjustable dimension to an extreme value.
    target_risk = max(item[3] for item in feasible)
    feasible = [item for item in feasible if item[3] == target_risk]

    dimensions = {}
    for key in keys:
        if is_cvss:
            labels_in_range = sorted({
                item[0][key]["label"] for item in feasible
            })
            coefficients = [item[0][key]["coefficient"] for item in feasible]
            dimensions[key] = {
                "allowed_values": labels_in_range,
                "coefficient_range": [min(coefficients), max(coefficients)],
            }
        else:
            values = sorted({item[0][key] for item in feasible})
            dimensions[key] = {
                "allowed_values": values,
                "range": [min(values), max(values)],
            }
    scores = sorted({item[1] for item in feasible})
    levels = sorted({item[2] for item in feasible})
    equipment_key = "Required_equipment" if method == "attack_potential" else "Equipment"
    candidates = sorted(
        feasible,
        key=lambda item: (
            item[0].get(equipment_key, 0),
            abs(item[1] - baseline_score),
            str(item[0]),
        ),
    )[:6]
    candidate_combinations = []
    for values, score, level, risk_num in candidates:
        if is_cvss:
            dimensions_for_prompt = {
                key: values[key]["label"] for key in keys
            }
        else:
            dimensions_for_prompt = {
                key: values[key] for key in keys if key not in fixed
            }
        candidate_combinations.append({
            "dimensions": dimensions_for_prompt, "score": score,
            "level": level, "risk": risk_num,
        })
    variable_rule = {}
    if fixed:
        fixed_key = next(iter(fixed))
        fixed_value = choices[fixed_key][0]
        variable_scores = sorted({score - fixed_value for score in scores})
        intervals = []
        for subtotal in variable_scores:
            if intervals and subtotal == intervals[-1][1] + 1:
                intervals[-1][1] = subtotal
            else:
                intervals.append([subtotal, subtotal])
        variable_rule = {
            "fixed_dimension": fixed_key,
            "fixed_dimension_value": fixed_value,
            "variable_dimensions": [key for key in keys if key not in fixed],
            "feasible_variable_score_range": [min(variable_scores), max(variable_scores)],
            "feasible_variable_score_intervals": intervals,
        }
    return {
        "target_risk_max": POST_CONTROL_TARGET_RISK_MAX,
        "target_risk_value": target_risk,
        "baseline_score": baseline_score,
        "baseline_level": baseline.get("feasibility_level"),
        "dimension_ranges": dimensions,
        "feasible_total_score_range": [min(scores), max(scores)],
        "feasible_total_scores": scores,
        "allowed_feasibility_levels": levels,
        "candidate_dimension_combinations": candidate_combinations,
        **variable_rule,
        "fixed_attack_vector": vector,
        "fixed_attack_vector_coefficient": CVSS_V.get(vector, 0.55) if is_cvss else None,
        "risk_matrix_validation_required": True,
    }


def synthesize_target_rating(
    baseline: dict[str, Any], constraints: dict[str, Any], method: str,
    impact_index: int, impact_level: str, impact_method: str,
) -> dict[str, Any] | None:
    """Build a disclosed target-scenario rating from a legal combination."""
    from .domain import CVSS_C, CVSS_P, CVSS_U, calculate_heavens_risk_value

    coefficients = {
        "complexity": CVSS_C, "privileges": CVSS_P,
        "user_interaction": CVSS_U,
    }
    for candidate in constraints.get("candidate_dimension_combinations") or []:
        dimensions = candidate.get("dimensions") or {}
        if method == "cvss":
            params = {
                key: coefficients[key][dimensions[key]]
                for key in coefficients
                if dimensions.get(key) in coefficients[key]
            }
        else:
            params = dict(dimensions)
            params[constraints["fixed_dimension"]] = constraints["fixed_dimension_value"]
        if len(params) != len(constraints.get("dimension_ranges") or {}):
            continue
        vector = baseline.get("attack_vector") or (baseline.get("attack_parameters") or {}).get("attack_vector")
        if vector:
            params["attack_vector"] = vector
        for key in constraints["dimension_ranges"]:
            params[f"{key}_reason"] = (
                "由原攻击向量固定，实施后保持不变"
                if key == constraints.get("fixed_dimension") else
                "目标情景组合分值，控制效果与维度依据待核验"
            )
        risk_num = candidate["risk"]
        risk_value = (
            calculate_heavens_risk_value(impact_level, candidate["level"])[0]
            if method == "heavens" and impact_method == "heavens" else risk_num
        )
        rating = {
            "attack_parameters": params,
            "feasibility_score": candidate["score"],
            "feasibility_level": candidate["level"],
            "risk_value": risk_value,
            "risk_value_num": risk_num,
            "risk_treatment": "风险接受",
            "feasibility_confidence": {},
        }
        if validate_target_rating(
            rating, baseline, constraints, method,
            impact_index, impact_level, impact_method,
        ):
            return rating
    return None


def validate_target_rating(
    generated: dict[str, Any], baseline: dict[str, Any],
    constraints: dict[str, Any], method: str, impact_index: int,
    impact_level: str, impact_method: str,
) -> bool:
    """Accept only model ratings inside computed ranges and consistent with the matrix."""
    from .domain import (
        CVSS_C, CVSS_P, CVSS_U, CVSS_V, HEAVENS_TL_TO_FEASIBILITY,
        calculate_attack_potential_level, calculate_cvss_level,
        calculate_heavens_ap_level, calculate_heavens_risk_value,
        calculate_risk_value, normalize_attack_vector,
    )

    params = generated.get("attack_parameters") or {}
    baseline_params = baseline.get("attack_parameters") or {}
    ranges = constraints.get("dimension_ranges") or {}
    values: dict[str, Any] = {}
    for key, rule in ranges.items():
        value = params.get(key)
        if method == "cvss":
            allowed_coefficients = {
                "complexity": CVSS_C, "privileges": CVSS_P,
                "user_interaction": CVSS_U,
            }[key]
            if isinstance(value, (int, float)):
                candidates = [label for label, coeff in allowed_coefficients.items() if coeff == value]
                label = candidates[0] if candidates else None
                coefficient = value
            else:
                label = str(value or "").strip().lower()
                coefficient = allowed_coefficients.get(label)
            if label not in rule["allowed_values"] or coefficient is None:
                return False
            if coefficient > baseline_params.get(key, coefficient):
                return False
            values[key] = coefficient
        else:
            if value not in rule["allowed_values"]:
                return False
            if method == "attack_potential" and key == "Opportunity_window":
                if value != baseline_params.get(key):
                    return False
            elif method == "heavens" and key == "Window_of_Opportunity":
                if value != baseline_params.get(key):
                    return False
            elif value < baseline_params.get(key, value):
                return False
            values[key] = value

    if method == "cvss":
        vector = normalize_attack_vector(baseline.get("attack_vector") or baseline_params.get("attack_vector"))
        score = round(
            8.22 * CVSS_V.get(vector, 0.55)
            * values["complexity"] * values["privileges"] * values["user_interaction"], 2,
        )
        level = calculate_cvss_level(score)
        risk_num = calculate_risk_value(impact_index, level)
        score_matches = abs(float(generated.get("feasibility_score", -1)) - score) < 0.011
    else:
        score = sum(values.values())
        level = (
            calculate_heavens_ap_level(score) if method == "heavens"
            else calculate_attack_potential_level(score)
        )
        if method == "heavens" and impact_method == "heavens":
            _, risk_num = calculate_heavens_risk_value(impact_level, level)
        else:
            mapped_level = (
                HEAVENS_TL_TO_FEASIBILITY.get(level, "Very Low")
                if method == "heavens" else level
            )
            risk_num = calculate_risk_value(impact_index, mapped_level)
        score_matches = generated.get("feasibility_score") == score

    expected_risk = generated.get("risk_value_num")
    return (
        score in constraints.get("feasible_total_scores", [])
        and level in constraints.get("allowed_feasibility_levels", [])
        and score_matches
        and generated.get("feasibility_level") == level
        and isinstance(expected_risk, (int, float))
        and expected_risk == risk_num
        and risk_num == constraints.get("target_risk_value")
        and risk_num <= constraints.get("target_risk_max", POST_CONTROL_TARGET_RISK_MAX)
    )
