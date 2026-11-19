"""TARA JSON 报告的 Excel 导出。"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass

from openpyxl import Workbook
from openpyxl.formatting.rule import CellIsRule
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

from automotive_tara.domain import STATUS_NOT_APPLICABLE, STATUS_VALID
from automotive_tara.reporting import (
    excel_cell_value as _excel_cell_value,
    format_confidence as _fmt_conf,
    format_risk_value as _fmt_risk_value,
    cybersecurity_fields_for_treatment as _cybersecurity_fields_for_treatment,
    normalize_excel_text as _normalize_text,
    sanitize_excel_text as _sanitize_excel_text,
)
from automotive_tara.security_requirements import flatten_security_requirements


@dataclass(frozen=True, slots=True)
class ExcelExportOptions:
    impact_method: str = "21434"
    enable_reason: bool = True
    enable_consistency: bool = False
    enable_r155: bool = False
    enable_rag: bool = False
    enable_asset_details: bool = True


_SECURITY_ATTR_MAP_EXCEL = {
    "机密性": "Confidentiality",
    "完整性": "Integrity",
    "可用性": "Availability",
    "真实性": "Authenticity",
    "不可抵赖性": "Non-repudiation",
    "权限属性": "Authorization",
}


_THREAT_TYPE_MAP_EXCEL = {
    "篡改": "Tampering",
    "信息泄露": "Information disclosure",
    "欺骗": "Spoofing",
    "抵赖": "Repudiation",
    "越权": "Elevation of privilege",
    "拒绝服务": "Denial of service",
}


def _build_excel_rows(
    data, method="attack_potential", impact_method="", *,
    options: ExcelExportOptions = ExcelExportOptions(),
):
    rows = []
    risk_idx = 1
    _is_heavens_risk = (impact_method == "heavens" and method == "heavens")
    for function_item in data:
        function_name = _normalize_text(function_item.get("function"))
        for asset in function_item.get("assets", []):
            asset_name = _normalize_text(asset.get("asset_name"))
            asset_type = _normalize_text(asset.get("asset_type"))
            element_index = (
                _normalize_text(asset.get("element_index"))
                if asset_type == "信号"
                else asset_name
            )
            for sec_attr in asset.get("security_attributes", []):
                # 从数据中读取 feasibility_method，若没有则使用函数参数
                attr_method = sec_attr.get("feasibility_method", method)
                attribute_name = _normalize_text(sec_attr.get("attribute_name"))
                threat_type = _normalize_text(sec_attr.get("threat_type"))
                security_category = _SECURITY_ATTR_MAP_EXCEL.get(attribute_name, "")
                threat_type_en = _THREAT_TYPE_MAP_EXCEL.get(threat_type, "")
                damage_scenario = _normalize_text(sec_attr.get("damage_scenario"))
                threat_scenario = _normalize_text(sec_attr.get("threat_scenarios", []))
                influence = sec_attr.get("influence_parameters", {}) or {}
                safety = influence.get("Safety", None)
                safety_reason = _normalize_text(influence.get("Safety_reason"))
                finance = influence.get("Finance", None)
                finance_reason = _normalize_text(influence.get("Finance_reason"))
                operation = influence.get("Operation", None)
                operation_reason = _normalize_text(influence.get("Operation_reason"))
                privacy = influence.get("Privacy", None)
                privacy_reason = _normalize_text(influence.get("Privacy_reason"))
                # 报告构建阶段已完成方法转换：HEAVENS 为权重总和，
                # 21434 为四维原始等级最大值。
                impact_value = sec_attr.get("impact_value", None)
                impact_level = _normalize_text(sec_attr.get("impact_level")) or None
                analysis_status = sec_attr.get("analysis_status", STATUS_VALID)
                task_risk_treatment = _normalize_text(
                    sec_attr.get("task_risk_treatment")
                )
                requirement_cells = {
                    "security_requirement": _normalize_text(
                        sec_attr.get("security_requirement")
                    ),
                    "national_standard_code": _normalize_text(
                        sec_attr.get("national_standard_code")
                    ),
                    "annex5_partbc_mapping": _normalize_text(
                        sec_attr.get("annex5_partbc_mapping")
                    ),
                }
                if not any(requirement_cells.values()):
                    requirement_cells = flatten_security_requirements(
                        sec_attr.get("security_requirements", []) or []
                    )
                treatment_fields = (
                    {"cybersecurity_goal": "", "cybersecurity_claim": ""}
                    if analysis_status == STATUS_NOT_APPLICABLE
                    else _cybersecurity_fields_for_treatment(
                        risk_treatment=task_risk_treatment,
                        asset_name=asset_name,
                        attribute_name=attribute_name,
                        threat_type=threat_type,
                        function_name=function_name,
                    )
                )
                for field in ("cybersecurity_goal", "cybersecurity_claim"):
                    if field in sec_attr and analysis_status != STATUS_NOT_APPLICABLE:
                        treatment_fields[field] = _normalize_text(sec_attr[field])

                # 置信度数据
                inf_conf = sec_attr.get("influence_confidence", {}) or {}
                impact_conf = sec_attr.get("impact_confidence", None)
                if impact_conf is not None:
                    impact_conf_str = f"{impact_conf:.0%}"
                else:
                    impact_conf_str = ""

                base_row = {
                    "risk_id": f"R{risk_idx:03d}",
                    "function_name": function_name,
                    "element_index": element_index,
                    "asset_name": asset_name,
                    "asset_details": _normalize_text(asset.get("asset_details")),
                    "asset_type": asset_type,
                    "security_category": security_category,
                    "security_attribute": attribute_name,
                    "analysis_status": analysis_status,
                    "status_reasons": "；".join(sec_attr.get("status_reasons", [])),
                    "damage_scenario": damage_scenario,
                    "safety": safety, "safety_reason": safety_reason,
                    "finance": finance, "finance_reason": finance_reason,
                    "operation": operation, "operation_reason": operation_reason,
                    "privacy": privacy, "privacy_reason": privacy_reason,
                    "impact_value": impact_value, "impact_level": impact_level,
                    "impact_confidence": impact_conf_str,
                    "safety_confidence": _fmt_conf(inf_conf.get("Safety")),
                    "finance_confidence": _fmt_conf(inf_conf.get("Finance")),
                    "operation_confidence": _fmt_conf(inf_conf.get("Operation")),
                    "privacy_confidence": _fmt_conf(inf_conf.get("Privacy")),
                    "threat_type": f"{threat_type}\n{threat_type_en}" if threat_type_en else threat_type,
                    "threat_scenario": threat_scenario,
                    "r155_references": ",".join(sec_attr.get("r155_references", [])) if options.enable_r155 else "",
                    "feasibility_score": None, "feasibility_level": None,
                    "feasibility_confidence": "",
                    "risk_value": sec_attr.get("task_risk_value"),
                    "risk_treatment": task_risk_treatment,
                    **requirement_cells,
                    **treatment_fields,
                }

                attacks = sec_attr.get("attack", [])
                if not attacks:
                    row = dict(base_row)
                    row["attack_path"] = None
                    row.update(_get_attack_field_values({}, attr_method, options=options))
                    for k in ("feasibility_score", "feasibility_level"):
                        row[k] = None
                    rows.append(row)
                    risk_idx += 1
                    continue

                for attack in attacks:
                    attack_path = _normalize_text(attack.get("attack_path"))
                    attack_params = attack.get("attack_parameters", {}) or {}
                    fea_conf = attack.get("feasibility_confidence", {}) or {}
                    attack_risk_treatment = (
                        _normalize_text(attack.get("risk_treatment"))
                        or task_risk_treatment
                    )
                    reassessment_baseline = (
                        attack.get("security_requirement_reassessment_baseline")
                        or {}
                    )
                    reassessment_model_rating = (
                        attack.get("security_requirement_reassessment_model_rating") or {}
                    )
                    reassessment_constraints = (
                        attack.get("security_requirement_reassessment_constraints") or {}
                    )
                    feasible_score_range = reassessment_constraints.get(
                        "feasible_total_score_range"
                    )
                    row = dict(base_row)
                    row.update({
                        "attack_path": attack_path,
                        "post_control_attack_path": _normalize_text(attack.get("security_requirement_reassessment_path")),
                        "post_control_status": _normalize_text(attack.get("security_requirement_reassessment_status")),
                        "post_control_basis": _normalize_text(attack.get("security_requirement_reassessment_path_basis")),
                        "post_control_mode": _normalize_text(attack.get("security_requirement_reassessment_mode")),
                        "post_control_baseline_risk": reassessment_baseline.get(
                            "基线风险值", "",
                        ),
                        "post_control_model_risk": reassessment_model_rating.get(
                            "risk_value_num", "",
                        ),
                        "post_control_score_range": (
                            f"{feasible_score_range[0]}–{feasible_score_range[1]}"
                            if isinstance(feasible_score_range, list) and len(feasible_score_range) == 2
                            else ""
                        ),
                        "attack_path_source": attack.get("attack_path_source", "来源待核验"),
                        "attack_path_fallback_reason": attack.get("attack_path_fallback_reason", ""),
                        "review_required": (
                            "是" if attack.get(
                                "review_required", "attack_path_source" not in attack
                            ) else "否"
                        ),
                        "feasibility_score": attack.get("feasibility_score", ""),
                        "feasibility_level": _normalize_text(attack.get("feasibility_level")),
                        "feasibility_confidence": _fmt_conf(fea_conf.get("_overall")),
                        "risk_value": _fmt_risk_value(attack, _is_heavens_risk),
                        "risk_treatment": attack_risk_treatment,
                    })
                    # Requirements follow the row's (path-level) treatment.
                    # A task may contain both accepted and mitigated attack
                    # paths, so do not blindly reuse the task-level cells.
                    attack_requirement_cells = {
                        "security_requirement": _normalize_text(
                            attack.get("security_requirement")
                        ),
                        "national_standard_code": _normalize_text(
                            attack.get("national_standard_code")
                        ),
                        "annex5_partbc_mapping": _normalize_text(
                            attack.get("annex5_partbc_mapping")
                        ),
                    }
                    if attack_risk_treatment.casefold() not in {
                        "风险缓解", "risk mitigation", "mitigation"
                    } and not attack.get("security_requirements_implemented"):
                        attack_requirement_cells = {
                            key: "" for key in attack_requirement_cells
                        }
                    elif not any(attack_requirement_cells.values()):
                        # Compatibility with JSON generated before flattened
                        # path-level cells were added.
                        attack_requirement_cells = flatten_security_requirements(
                            attack.get("security_requirements", []) or []
                        )
                    # Always overwrite the task-level aggregate for a path
                    # row, including an empty mitigation match.  Otherwise a
                    # path with a different interface (or no template match)
                    # inherits requirements from the task-wide interface
                    # union and appears incorrectly covered.
                    row.update(attack_requirement_cells)
                    row.update(
                        _cybersecurity_fields_for_treatment(
                            risk_treatment=attack_risk_treatment,
                            asset_name=asset_name,
                            attribute_name=attribute_name,
                            threat_type=threat_type,
                            function_name=function_name,
                        )
                    )
                    for field in ("cybersecurity_goal", "cybersecurity_claim"):
                        if field in attack:
                            row[field] = _normalize_text(attack[field])
                    # 方法相关的置信度列
                    if attr_method == "heavens":
                        row.update({
                            "expertise_confidence": _fmt_conf(fea_conf.get("Expertise")),
                            "knowledge_about_toe_confidence": _fmt_conf(fea_conf.get("Knowledge_about_TOE")),
                            "window_of_opportunity_confidence": _fmt_conf(fea_conf.get("Window_of_Opportunity")),
                            "equipment_confidence": _fmt_conf(fea_conf.get("Equipment")),
                        })
                    else:  # attack_potential / cvss / attack_vector
                        row.update({
                            "exposure_time_confidence": _fmt_conf(fea_conf.get("Exposure_time")),
                            "professional_experience_confidence": _fmt_conf(fea_conf.get("Professional_experience")),
                            "required_information_confidence": _fmt_conf(fea_conf.get("Required_information")),
                            "opportunity_window_confidence": _fmt_conf(fea_conf.get("Opportunity_window")),
                            "required_equipment_confidence": _fmt_conf(fea_conf.get("Required_equipment")),
                        })
                    row.update(_get_attack_field_values(attack_params, attr_method, options=options))
                    rows.append(row)
                    risk_idx += 1
    return rows


def export_tara_report_to_excel(json_path: str, xlsx_path: str, rag_cache: dict | None = None,
                               rag_queries: dict | None = None, *,
                               options: ExcelExportOptions = ExcelExportOptions()) -> int:
    """将 TARA JSON 报告转换为横向宽表 Excel。返回生成的行数。"""
    with open(json_path, "r", encoding="utf-8-sig") as f:
        data = json.load(f)
    # 从数据中检测可行性和影响评估方法
    fea_method = "attack_potential"
    imp_method = options.impact_method
    for func_item in data:
        for asset in func_item.get("assets", []):
            for sec_attr in asset.get("security_attributes", []):
                m = sec_attr.get("feasibility_method", "")
                if m in ("attack_potential", "attack_vector", "cvss", "heavens"):
                    fea_method = m
                im = sec_attr.get("impact_method", "")
                if im:
                    imp_method = im
                break
            break
        break
    columns = _build_columns_excel(fea_method, imp_method, options=options)
    rows = _build_excel_rows(data, method=fea_method, impact_method=imp_method, options=options)
    wb = Workbook()
    ws = wb.active
    ws.title = "TARA分析表"
    ws.append([""] * len(columns))
    ws.append([col_name for _, col_name, _ in columns])
    for row in rows:
        ws.append([_excel_cell_value(row.get(key)) for _, _, key in columns])
    _style_excel(ws, columns=columns, method=fea_method, options=options)

    # ── RAG 上下文工作表 ────────────────────────
    if options.enable_rag and rag_cache:
        rag_ws = wb.create_sheet("RAG上下文")
        rag_ws.append(["阶段", "检索查询", "RAG上下文"])
        seen_contexts: set[tuple[str, str, str]] = set()
        for phase in ("damage", "threat", "attack_path"):
            cache_dict = rag_cache.get(phase, {})
            queries = rag_queries.get(phase, {}) if rag_queries else {}
            for key, ctx in cache_dict.items():
                display_key = queries.get(key, key)
                evidence = (phase, str(display_key), str(ctx))
                if evidence in seen_contexts:
                    continue
                seen_contexts.add(evidence)
                rag_ws.append([
                    _sanitize_excel_text(phase),
                    _sanitize_excel_text(str(display_key)),
                    _sanitize_excel_text(str(ctx)),
                ])
        # 设置列宽
        rag_ws.column_dimensions["A"].width = 16
        rag_ws.column_dimensions["B"].width = 30
        rag_ws.column_dimensions["C"].width = 120

    xlsx_dir = os.path.dirname(os.path.abspath(xlsx_path))
    os.makedirs(xlsx_dir, exist_ok=True)
    temp_xlsx = os.path.join(
        xlsx_dir,
        f".{os.path.basename(xlsx_path)}.{os.getpid()}.{threading.get_ident()}.tmp.xlsx",
    )
    try:
        wb.save(temp_xlsx)
        os.replace(temp_xlsx, xlsx_path)
    finally:
        if os.path.exists(temp_xlsx):
            try:
                os.unlink(temp_xlsx)
            except OSError:
                pass
    return len(rows)


def _style_excel(
    ws, columns=None, method="attack_potential", *,
    options: ExcelExportOptions = ExcelExportOptions(),
):
    if columns is None:
        columns = _build_columns_excel(options=options)
    max_col = ws.max_column
    max_row = ws.max_row

    group_fill_map = {
        "基础信息 Basic Information": PatternFill("solid", fgColor="D9EAF7"),
        "损害场景分析 Damage Scenario Analysis": PatternFill("solid", fgColor="FFF2CC"),
        "影响性评估 Impact Assessment": PatternFill("solid", fgColor="F8CBAD"),
        "威胁场景分析 Threat Scenario Analysis": PatternFill("solid", fgColor="FCE4D6"),
        "攻击可行性评估 Attack Feasibility Rating": PatternFill("solid", fgColor="EADCF8"),
        "风险评估 Risk Value": PatternFill("solid", fgColor="F4CCCC"),
        "风险处置 Risk Treatment": PatternFill("solid", fgColor="D9EAD3"),
        "网络安全目标 Cybersecurity Goal": PatternFill("solid", fgColor="DDEBF7"),
        "网络安全声明 Cybersecurity Claim": PatternFill("solid", fgColor="E2F0D9"),
    }

    thin_gray = Side(style="thin", color="BFBFBF")
    medium_gray = Side(style="medium", color="808080")
    border = Border(left=thin_gray, right=thin_gray, top=thin_gray, bottom=thin_gray)

    # Row 1: merged group headers
    current_group = None
    start_col = 1
    for col_idx, (group, _, _) in enumerate(columns, start=1):
        if current_group is None:
            current_group = group
            start_col = col_idx
        elif group != current_group:
            ws.merge_cells(start_row=1, start_column=start_col, end_row=1, end_column=col_idx - 1)
            cell = ws.cell(row=1, column=start_col)
            cell.value = current_group
            cell.fill = group_fill_map.get(current_group, PatternFill("solid", fgColor="D9EAF7"))
            cell.font = Font(bold=True, size=11)
            cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
            cell.border = Border(left=medium_gray, right=medium_gray, top=medium_gray, bottom=medium_gray)
            current_group = group
            start_col = col_idx
    ws.merge_cells(start_row=1, start_column=start_col, end_row=1, end_column=len(columns))
    cell = ws.cell(row=1, column=start_col)
    cell.value = current_group
    cell.fill = group_fill_map.get(current_group, PatternFill("solid", fgColor="D9EAF7"))
    cell.font = Font(bold=True, size=11)
    cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
    cell.border = Border(left=medium_gray, right=medium_gray, top=medium_gray, bottom=medium_gray)

    # Row 2: field headers
    for col_idx, (group, col_name, _) in enumerate(columns, start=1):
        cell = ws.cell(row=2, column=col_idx)
        cell.value = col_name
        cell.fill = group_fill_map.get(group, PatternFill("solid", fgColor="D9EAF7"))
        cell.font = Font(bold=True, size=10)
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        cell.border = border

    # Data rows
    for row in ws.iter_rows(min_row=3, max_row=max_row, min_col=1, max_col=max_col):
        for cell in row:
            cell.alignment = Alignment(vertical="top", horizontal="left", wrap_text=True)
            cell.border = border
            cell.font = Font(size=10)

    center_keys = {
        "safety", "finance", "operation", "privacy", "impact_value",
        "exposure_time", "professional_experience", "required_information",
        "opportunity_window", "required_equipment", "feasibility_score", "risk_value",
        "attack_vector_field", "complexity", "privileges", "user_interaction",
        "expertise", "knowledge_about_toe", "window_of_opportunity", "equipment",
    }
    for col_idx, (_, _, key) in enumerate(columns, start=1):
        if key in center_keys:
            for row_idx in range(3, max_row + 1):
                ws.cell(row=row_idx, column=col_idx).alignment = Alignment(
                    horizontal="center", vertical="center", wrap_text=True)

    ws.freeze_panes = "A3"
    ws.auto_filter.ref = f"A2:{get_column_letter(max_col)}{max_row}"
    ws.row_dimensions[1].height = 28
    ws.row_dimensions[2].height = 45
    for row_idx in range(3, max_row + 1):
        ws.row_dimensions[row_idx].height = 95

    width_map = {
        "risk_id": 14, "function_name": 16, "element_index": 18,
        "asset_name": 16, "asset_details": 20, "asset_type": 12,
        "security_category": 18, "security_attribute": 16, "threat_type": 20,
        "damage_scenario": 55, "safety": 10, "safety_reason": 40,
        "finance": 10, "finance_reason": 40, "operation": 10,
        "operation_reason": 40, "privacy": 10, "privacy_reason": 40,
        "impact_value": 12, "impact_level": 15,
        "threat_scenario": 55, "attack_path": 60,
        "exposure_time": 14, "exposure_time_reason": 40,
        "professional_experience": 18, "professional_experience_reason": 40,
        "required_information": 18, "required_information_reason": 40,
        "opportunity_window": 18, "opportunity_window_reason": 40,
        "required_equipment": 18, "required_equipment_reason": 40,
        "feasibility_score": 16, "feasibility_level": 18,
        "risk_value": 12, "risk_treatment": 16,
        "cybersecurity_goal": 45, "cybersecurity_claim": 50,
        "security_requirement": 55, "national_standard_code": 28,
        "annex5_partbc_mapping": 28,
        "attack_vector_field": 18, "attack_vector_reason": 40,
        "complexity": 14, "complexity_reason": 40,
        "privileges": 14, "privileges_reason": 40,
        "user_interaction": 16, "user_interaction_reason": 40,
        "expertise": 14, "expertise_reason": 40,
        "knowledge_about_toe": 14, "knowledge_about_toe_reason": 40,
        "window_of_opportunity": 14, "window_of_opportunity_reason": 40,
        "equipment": 14, "equipment_reason": 40,
    }
    for col_idx, (_, _, key) in enumerate(columns, start=1):
        ws.column_dimensions[get_column_letter(col_idx)].width = width_map.get(key, 18)

    # conditional formatting
    risk_col = None
    impact_col = None
    for col_idx, (_, _, key) in enumerate(columns, start=1):
        if key == "risk_value":
            risk_col = get_column_letter(col_idx)
        if key == "impact_value":
            impact_col = get_column_letter(col_idx)
    if risk_col:
        risk_range = f"{risk_col}3:{risk_col}{max_row}"
        if method == "heavens":
            ws.conditional_formatting.add(risk_range, CellIsRule(
                operator="equal", formula=['"严重"'],
                fill=PatternFill("solid", fgColor="FF9999")))
            ws.conditional_formatting.add(risk_range, CellIsRule(
                operator="equal", formula=['"高"'],
                fill=PatternFill("solid", fgColor="FFD966")))
        else:
            ws.conditional_formatting.add(risk_range, CellIsRule(
                operator="greaterThanOrEqual", formula=["5"],
                fill=PatternFill("solid", fgColor="FF9999")))
            ws.conditional_formatting.add(risk_range, CellIsRule(
                operator="equal", formula=["4"],
                fill=PatternFill("solid", fgColor="FFD966")))
    if impact_col:
        impact_range = f"{impact_col}3:{impact_col}{max_row}"
        ws.conditional_formatting.add(impact_range, CellIsRule(
            operator="greaterThanOrEqual", formula=["4"],
            fill=PatternFill("solid", fgColor="F4B183")))


def _get_attack_field_values(
    attack_params: dict, method: str, *,
    options: ExcelExportOptions = ExcelExportOptions(),
) -> dict:
    """根据方法类型从 attack_parameters 提取可行性评估字段。"""
    if method == "attack_vector":
        result = {
            "attack_vector_field": _normalize_text(attack_params.get("attack_vector")),
        }
        if options.enable_reason:
            result["attack_vector_reason"] = _normalize_text(
                attack_params.get("attack_vector_reason")
            )
        return result
    elif method == "cvss":
        return {
            "attack_vector_field": _normalize_text(attack_params.get("attack_vector")),
            "complexity": _normalize_text(attack_params.get("complexity")),
            "complexity_reason": _normalize_text(attack_params.get("complexity_reason")),
            "privileges": _normalize_text(attack_params.get("privileges")),
            "privileges_reason": _normalize_text(attack_params.get("privileges_reason")),
            "user_interaction": _normalize_text(attack_params.get("user_interaction")),
            "user_interaction_reason": _normalize_text(attack_params.get("user_interaction_reason")),
        }
    elif method == "heavens":
        return {
            "attack_vector_field": _normalize_text(attack_params.get("attack_vector")),
            "expertise": attack_params.get("Expertise", ""),
            "expertise_reason": _normalize_text(attack_params.get("Expertise_reason")),
            "knowledge_about_toe": attack_params.get("Knowledge_about_TOE", ""),
            "knowledge_about_toe_reason": _normalize_text(attack_params.get("Knowledge_about_TOE_reason")),
            "window_of_opportunity": attack_params.get("Window_of_Opportunity", ""),
            "window_of_opportunity_reason": _normalize_text(attack_params.get("Window_of_Opportunity_reason")),
            "equipment": attack_params.get("Equipment", ""),
            "equipment_reason": _normalize_text(attack_params.get("Equipment_reason")),
        }
    else:  # attack_potential
        return {
            "attack_vector_field": _normalize_text(attack_params.get("attack_vector")),
            "exposure_time": attack_params.get("Exposure_time", ""),
            "exposure_time_reason": _normalize_text(attack_params.get("Exposure_time_reason")),
            "professional_experience": attack_params.get("Professional_experience", ""),
            "professional_experience_reason": _normalize_text(attack_params.get("Professional_experience_reason")),
            "required_information": attack_params.get("Required_information", ""),
            "required_information_reason": _normalize_text(attack_params.get("Required_information_reason")),
            "opportunity_window": attack_params.get("Opportunity_window", ""),
            "opportunity_window_reason": _normalize_text(attack_params.get("Opportunity_window_reason")),
            "required_equipment": attack_params.get("Required_equipment", ""),
            "required_equipment_reason": _normalize_text(attack_params.get("Required_equipment_reason")),
        }


def _build_columns_excel(
    method: str = "attack_potential", impact_method: str = "", *,
    options: ExcelExportOptions = ExcelExportOptions(),
) -> list[tuple[str, str, str]]:
    """根据可行性和影响评估方法及开关状态动态构建 Excel 列定义。

    当 options.enable_reason=0 时排除理由列，当 options.enable_consistency=0 时排除一致性列。
    一致性列紧邻对应的指标评级列右侧。
    """
    G = "基础信息 Basic Information"
    D = "损害场景分析 Damage Scenario Analysis"
    I = "影响性评估 Impact Assessment"
    T = "威胁场景分析 Threat Scenario Analysis"
    F = "攻击可行性评估 Attack Feasibility Rating"
    R = "风险评估 Risk Value"
    RT = "风险处置 Risk Treatment"
    CG = "网络安全目标 Cybersecurity Goal"
    CC = "网络安全声明 Cybersecurity Claim"

    # HEAVENS 原生方法使用 5 级；heavens_4level 使用传统 4 级矩阵。
    _is_heavens_impact = impact_method == "heavens"
    _is_heavens_feasibility = method == "heavens"
    _impact_level_label = "影响等级 (HEAVENS 5级)\nImpact rating" if _is_heavens_impact else "影响等级\nImpact rating"
    _risk_label = "风险等级\nRisk level" if (_is_heavens_impact and _is_heavens_feasibility) else "风险值\nRisk value"
    if impact_method == "heavens":
        _impact_value_label = "影响参数总和\nImpact parameter sum"
    elif impact_method == "heavens_4level":
        _impact_value_label = "影响等级分值 (1-4)\nImpact level score"
    else:
        _impact_value_label = "影响值（维度最大值）\nImpact value"

    cols = [
        (G, "风险ID\nRisk ID", "risk_id"),
        (G, "功能名称\nFunction name", "function_name"),
        (G, "元素编号\nElement Index", "element_index"),
        (G, "资产\nAsset", "asset_name"),
        *(
            [(G, "资产细项\nAsset details", "asset_details")]
            if options.enable_asset_details
            else []
        ),
        (G, "资产类型\nAsset type", "asset_type"),
        (G, "安全类别\nSecurity category", "security_category"),
        (G, "安全属性\nSecurity attribute", "security_attribute"),
        (G, "分析状态\nAnalysis status", "analysis_status"),
        (G, "状态说明\nStatus reason", "status_reasons"),
        (D, "损害场景\nDamage scenario", "damage_scenario"),
    ]

    # ── 影响性评估 ──
    _impact_dims = [
        ("安全", "Safety", "safety"),
        ("财务", "Financial", "finance"),
        ("操作", "Operational", "operation"),
        ("隐私", "Privacy", "privacy"),
    ]
    for label, label_en, key in _impact_dims:
        cols.append((I, f"{label}\n{label_en}", key))
        if options.enable_consistency:
            cols.append((I, f"{label}一致性\n{label_en} consistency", f"{key}_confidence"))
        if options.enable_reason:
            cols.append((I, f"{label}理由\n{label_en} reason", f"{key}_reason"))
    cols.append((I, _impact_value_label, "impact_value"))
    cols.append((I, _impact_level_label, "impact_level"))
    if options.enable_consistency:
        cols.append((I, "影响一致性\nImpact consistency", "impact_confidence"))

    # ── 威胁场景分析 ──
    cols.append((T, "威胁类型\nThreat type", "threat_type"))
    cols.append((T, "威胁场景\nThreat scenario", "threat_scenario"))
    if options.enable_r155:
        cols.append((T, "R155威胁编号\nR155 ref.", "r155_references"))
    cols.append((T, "攻击路径\nAttack path", "attack_path"))

    if method == "attack_potential":
        cols.append((T, "攻击向量\nAttack vector", "attack_vector_field"))
        _ap_dims = [
            ("暴露时间", "Exposure time", "exposure_time"),
            ("专业经验", "Professional experience", "professional_experience"),
            ("所需信息", "Required information", "required_information"),
            ("机会窗口", "Opportunity window", "opportunity_window"),
            ("所需设备", "Required equipment", "required_equipment"),
        ]
        for label, label_en, key in _ap_dims:
            cols.append((F, f"{label}\n{label_en}", key))
            if options.enable_consistency:
                cols.append((F, f"{label}一致性\n{label_en} consistency", f"{key}_confidence"))
            if options.enable_reason:
                cols.append((F, f"{label}理由\n{label_en} reason", f"{key}_reason"))
        cols.append((F, "可行性得分\nFeasibility score", "feasibility_score"))
        cols.append((F, "可行性等级\nFeasibility rating", "feasibility_level"))
        if options.enable_consistency:
            cols.append((F, "可行性一致性\nFeasibility consistency", "feasibility_confidence"))

    elif method == "attack_vector":
        cols.append((F, "攻击向量\nAttack vector", "attack_vector_field"))
        if options.enable_reason:
            cols.append(
                (F, "攻击向量理由\nAttack vector reason", "attack_vector_reason")
            )
        cols.append((F, "可行性得分\nFeasibility score", "feasibility_score"))
        cols.append((F, "可行性等级\nFeasibility rating", "feasibility_level"))

    elif method == "cvss":
        cols.append((F, "攻击向量\nAttack vector", "attack_vector_field"))
        _cvss_dims = [
            ("攻击复杂度", "Complexity", "complexity"),
            ("权限要求", "Privileges", "privileges"),
            ("用户交互", "User interaction", "user_interaction"),
        ]
        for label, label_en, key in _cvss_dims:
            cols.append((F, f"{label}\n{label_en}", key))
            if options.enable_reason:
                cols.append((F, f"{label}理由\n{label_en} reason", f"{key}_reason"))
        cols.append((F, "可行性得分\nFeasibility score", "feasibility_score"))
        cols.append((F, "可行性等级\nFeasibility rating", "feasibility_level"))

    elif method == "heavens":
        cols.append((F, "攻击向量\nAttack vector", "attack_vector_field"))
        _heavens_dims = [
            ("专业经验", "Expertise", "expertise"),
            ("所需信息", "Knowledge about TOE", "knowledge_about_toe"),
            ("机会窗口", "Window of Opportunity", "window_of_opportunity"),
            ("所需设备", "Equipment", "equipment"),
        ]
        for label, label_en, key in _heavens_dims:
            cols.append((F, f"{label}\n{label_en}", key))
            if options.enable_consistency:
                cols.append((F, f"{label}一致性\n{label_en} consistency", f"{key}_confidence"))
            if options.enable_reason:
                cols.append((F, f"{label}理由\n{label_en} reason", f"{key}_reason"))
        cols.append((F, "可行性得分\nFeasibility score", "feasibility_score"))
        cols.append((F, "可行性等级\nFeasibility rating", "feasibility_level"))
        if options.enable_consistency:
            cols.append((F, "可行性一致性\nFeasibility consistency", "feasibility_confidence"))

    # ── 风险值与处置 ──
    cols.append((R, _risk_label, "risk_value"))
    cols.append((RT, "风险处置\nRisk treatment", "risk_treatment"))
    cols.append((CG, "网络安全目标\nCybersecurity goal", "cybersecurity_goal"))
    cols.append((CG, "安全需求\nSecurity requirement", "security_requirement"))
    cols.append((CG, "国标法规编码\nNational standard/regulatory code", "national_standard_code"))
    cols.append((CG, "附录5 Part B/C映射\nAnnex 5 Part B/C mapping", "annex5_partbc_mapping"))
    cols.append((CC, "网络安全声明\nCybersecurity claim", "cybersecurity_claim"))

    return cols
