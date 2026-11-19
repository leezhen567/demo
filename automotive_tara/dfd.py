"""DFD 输入解析、功能清单读取与 TaskUnit 构建。"""

from __future__ import annotations

import glob
import json
import logging
import os
import re
from collections import defaultdict
from typing import Any

from automotive_tara.domain import (
    ATTRIBUTE_TO_THREAT,
    SECURITY_ATTRIBUTES_MAP,
    STATUS_NOT_APPLICABLE,
    TaskUnit,
)
from automotive_tara.dfd_compat import normalize_dfd_json
from automotive_tara.topology import name_match_key as _name_match_key
from automotive_tara.topology import normalize_text as _normalize_text

logger = logging.getLogger(__name__)


def load_security_asset_facts(
    data_flow_dir: str | None = None,
) -> dict[str, Any]:
    """Load project facts used by workbook applicability columns.

    The facts are deliberately external to DFD semantics: most DFD exports do
    not contain ECU operating-system or critical-component declarations.  A
    configured JSON file wins; otherwise a facts file next to a project DFD
    directory is discovered automatically.
    """
    configured = str(
        os.getenv("TARA_SECURITY_REQUIREMENT_ASSET_FACTS", "") or ""
    ).strip()
    candidates: list[str] = []
    if configured:
        candidates.append(configured)
    if data_flow_dir:
        directory = os.path.abspath(data_flow_dir)
        candidates.extend(
            [
                os.path.join(directory, "security_requirement_asset_facts.json"),
                os.path.join(
                    os.path.dirname(directory),
                    "security_requirement_asset_facts.json",
                ),
            ]
        )
    for candidate in dict.fromkeys(candidates):
        try:
            with open(candidate, "r", encoding="utf-8") as source:
                payload = json.load(source)
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict):
            facts = payload.get("assets", payload)
            defaults = payload.get("defaults", {})
            return {
                "assets": facts if isinstance(facts, dict) else {},
                "defaults": defaults if isinstance(defaults, dict) else {},
                "source": os.path.abspath(candidate),
            }
    return {"assets": {}, "defaults": {}, "source": ""}


def _asset_fact_key(value: Any) -> str:
    return re.sub(r"\s+", "", str(value or "").strip().casefold())


def _security_asset_fact(
    asset_name: Any,
    facts: dict[str, Any],
) -> tuple[bool | None, str]:
    assets = facts.get("assets", {}) if isinstance(facts, dict) else {}
    defaults = facts.get("defaults", {}) if isinstance(facts, dict) else {}
    by_key = {
        _asset_fact_key(name): value
        for name, value in assets.items()
        if isinstance(value, dict)
    }
    value = by_key.get(_asset_fact_key(asset_name), {})
    if not isinstance(value, dict):
        value = {}
    critical = value.get("critical_component", defaults.get("critical_component"))
    if isinstance(critical, str):
        critical_key = _asset_fact_key(critical)
        if critical_key in {"是", "yes", "true", "1"}:
            critical = True
        elif critical_key in {"否", "no", "false", "0"}:
            critical = False
        else:
            critical = None
    elif not isinstance(critical, bool):
        critical = None
    operating_system = str(
        value.get("operating_system", defaults.get("operating_system", ""))
        or ""
    ).strip()
    return critical, operating_system

def parse_dfd_json(input_dir: str, *, strict_inputs: bool = True) -> list[dict]:
    type_mapping = {
        "tm.Flow": "信号",
        "tm.Process": "部件",
        "tm.Store": "数据",
        "tm.Actor": "接口",
    }
    element_prefix = {
        "tm.Flow": "flow",
        "tm.Process": "process",
        "tm.Store": "store",
        "tm.Actor": "actor",
    }

    def _property_value(cell: dict, field_name: str) -> str:
        for key, value in cell.items():
            if not key.startswith("propertyList") or not isinstance(value, dict):
                continue
            field_value = value.get(field_name)
            if field_value not in (None, ""):
                return str(field_value).strip()
        return ""

    def _asset_property_specs(cell: dict) -> list[tuple[str, str]]:
        """一个 flow 可承载多个信号资产：逐 propertyList 取 (finetermval, assetDetails)。

        每个带 finetermval 的 propertyList 都是一个独立信号资产（如 flow9 同时
        承载“状态信号”与“认证信号”），全部返回以便逐个分析。
        """
        specs: list[tuple[str, str]] = []
        for key, value in cell.items():
            if not key.startswith("propertyList") or not isinstance(value, dict):
                continue
            finetermval = str(value.get("finetermval", "") or "").strip()
            if not finetermval:
                continue
            asset_details = str(value.get("assetDetails", "") or "").strip()
            specs.append((finetermval, asset_details))
        return specs

    def _is_out_of_scope(cell: dict) -> bool:
        """兼容导出器将 outOfScope 写成 bool、数字或字符串的情况。"""
        value = cell.get("outOfScope")
        if isinstance(value, bool):
            return value
        return str(value or "").strip().lower() in {"true", "1", "yes", "y"}

    def _cell_name(cell: dict) -> str:
        return (
            _property_value(cell, "finetermval")
            or _normalize_text(
                (cell.get("attrs", {}).get("text", {}) or {}).get("text", "")
            )
        )

    def _node_name(cell: dict) -> str:
        """返回 DFD 节点身份；关系端点优先使用图上可视 text。

        节点的 propertyList.finetermval 有时是资产/功能名称（例如节点
        可视名为“诊断仪”，属性值却写成“云平台”）。端点分类和攻击路径
        必须使用 DFD 图上的节点身份，不能被资产属性值替换。
        """
        visual_name = _normalize_text(
            (cell.get("attrs", {}).get("text", {}) or {}).get("text", "")
        )
        return visual_name or _cell_name(cell)

    def _element_index(
        raw_type: str,
        cell_id: Any,
        cell: dict | None = None,
    ) -> str:
        prefix = element_prefix.get(raw_type, "")
        identity = str(cell_id or "").strip()
        # 保留 DFD 可视标签身份。报告层仅让信号资产使用该 flow 标签；
        # 其他资产的“元素编号”显示资产名称。内部 JSON id 只用于关系绑定。
        if cell:
            for label in cell.get("labels", []) or []:
                label_text = _normalize_text(
                    ((label.get("attrs") or {}).get("text") or {}).get(
                        "text", ""
                    )
                )
                if label_text:
                    return label_text
            # 部分 DFD 的 flow 名称记录在 cell.attrs.text.text（labels 为空），
            # 同样属于可视标签，优先于“flow {id}”内部编号。
            if raw_type == "tm.Flow":
                attrs_text = _normalize_text(
                    ((cell.get("attrs") or {}).get("text") or {}).get(
                        "text", ""
                    )
                )
                if attrs_text:
                    return attrs_text
        return f"{prefix} {identity}".strip() if prefix else identity

    all_results: list[dict] = []
    parse_errors: list[str] = []
    if os.path.isfile(input_dir):
        json_files = [input_dir]
    else:
        json_files = sorted(
            path for path in glob.glob(os.path.join(input_dir, "*"))
            if os.path.isfile(path) and path.lower().endswith(".json")
        )

    for file_path in json_files:
        with open(file_path, "r", encoding="utf-8-sig") as f:
            try:
                data = json.load(f)
            except Exception as e:
                parse_errors.append(f"{os.path.basename(file_path)}: {e}")
                logger.warning("DFD解析失败，跳过: %s (%s)", os.path.basename(file_path), e)
                continue

        # Normalize all supported DFD envelopes in memory so the CLI and web
        # preflight share the same parser. The uploaded file is never modified.
        try:
            data = normalize_dfd_json(data)
        except Exception as exc:
            parse_errors.append(f"{os.path.basename(file_path)}: {exc}")
            logger.warning("DFD图格式转换失败，跳过: %s (%s)", os.path.basename(file_path), exc)
            continue

        current_result = {
            "function": "",
            "assets": [],
            "relations": [],
            "nodes": [],
        }

        if "detail" in data and "diagrams" in data["detail"]:
            for diagram in data["detail"]["diagrams"]:
                if not current_result["function"] and "title" in diagram:
                    current_result["function"] = diagram["title"]

                if "diagramJson" not in diagram or "cells" not in diagram["diagramJson"]:
                    continue

                cells = diagram["diagramJson"]["cells"]
                id_to_cell = {c.get("id"): c for c in cells if c.get("id")}
                node_info: dict[str, dict] = {}
                for raw_cell in cells:
                    raw_id = str(raw_cell.get("id") or "").strip()
                    raw_type = raw_cell.get("type", "")
                    if not raw_id or raw_type in {"tm.Flow", "tm.Boundary"}:
                        continue
                    is_external_interface = raw_type == "tm.Actor"
                    # DFD 中越界的 Process/Store 是系统边界外的设备或系统，
                    # 不是 communication interface。tm.Actor 则保留为外部接口
                    # 候选，之后由 information Excel 校验它是否是真实项目接口。
                    is_external_component = bool(
                        raw_type != "tm.Actor"
                        and _is_out_of_scope(raw_cell)
                    )
                    info = {
                        "element_id": raw_id,
                        "element_index": _element_index(
                            raw_type, raw_id, raw_cell
                        ),
                        "dfd_element_type": raw_type,
                        "name": _node_name(raw_cell),
                        "aliases": [
                            str(alias).strip()
                            for alias in (raw_cell.get("interfaceAliases") or [])
                            if str(alias).strip()
                        ],
                        "out_of_scope": _is_out_of_scope(raw_cell),
                        "is_external_interface": is_external_interface,
                        "is_external_component": is_external_component,
                        "external_entity_type": (
                            "external_interface"
                            if is_external_interface
                            else "external_component"
                            if is_external_component
                            else "internal"
                        ),
                        # 兼容旧字段：两类边界节点均属于 external，但后续路径
                        # 选择必须使用上面的细分类字段。
                        "is_external": bool(
                            is_external_interface or is_external_component
                        ),
                    }
                    node_info[raw_id] = info
                    current_result["nodes"].append(info)

                # 所有 DFD 关系边均保留。无名的 Actor→部件连接不是资产，
                # 但它是后续判断真实入口和输入映射冲突所需的证据。
                for flow_cell in cells:
                    if flow_cell.get("type") != "tm.Flow":
                        continue
                    source_id = str(
                        (flow_cell.get("source") or {}).get("id", "")
                    ).strip()
                    target_id = str(
                        (flow_cell.get("target") or {}).get("id", "")
                    ).strip()
                    source_info = node_info.get(source_id, {})
                    target_info = node_info.get(target_id, {})
                    current_result["relations"].append(
                        {
                            "element_id": str(
                                flow_cell.get("id") or ""
                            ).strip(),
                            "element_index": _element_index(
                                "tm.Flow", flow_cell.get("id"), flow_cell
                            ),
                            "name": _property_value(
                                flow_cell, "finetermval"
                            ),
                            "protocol": _normalize_text(
                                flow_cell.get("protocol", "")
                            ),
                            "source_id": source_id,
                            "source_name": source_info.get("name", ""),
                            "source_type": source_info.get(
                                "dfd_element_type", ""
                            ),
                            "source_is_external": bool(
                                source_info.get("is_external", False)
                            ),
                            "source_is_external_interface": bool(
                                source_info.get("is_external_interface", False)
                            ),
                            "source_is_external_component": bool(
                                source_info.get("is_external_component", False)
                            ),
                            "source_external_entity_type": source_info.get(
                                "external_entity_type", "internal"
                            ),
                            "target_id": target_id,
                            "target_name": target_info.get("name", ""),
                            "target_type": target_info.get(
                                "dfd_element_type", ""
                            ),
                            "target_is_external": bool(
                                target_info.get("is_external", False)
                            ),
                            "target_is_external_interface": bool(
                                target_info.get("is_external_interface", False)
                            ),
                            "target_is_external_component": bool(
                                target_info.get("is_external_component", False)
                            ),
                            "target_external_entity_type": target_info.get(
                                "external_entity_type", "internal"
                            ),
                        }
                    )

                # 预建 source_id → flow_cells 索引，避免 O(n²) 扫描
                source_to_flows: dict[str, list] = {}
                target_to_flows: dict[str, list] = {}
                for fc in cells:
                    if fc.get("type") == "tm.Flow":
                        sid = (fc.get("source") or {}).get("id", "")
                        tid = (fc.get("target") or {}).get("id", "")
                        if sid:
                            source_to_flows.setdefault(sid, []).append(fc)
                        if tid:
                            target_to_flows.setdefault(tid, []).append(fc)

                for cell in cells:
                    raw_type = cell.get("type", "")
                    if raw_type == "tm.Boundary":
                        continue

                    mapped_type = type_mapping.get(raw_type, raw_type)

                    # 一个 flow 名称可能承载多个信号资产（多个 propertyList），
                    # 每个 propertyList 的 finetermval + assetDetails 都是一个
                    # 独立的信号资产，若不 outOfScope 则全部需要分析。
                    # 非 flow 资产仍取第一个 propertyList。
                    if mapped_type == "信号":
                        specs = _asset_property_specs(cell)
                    else:
                        specs = [
                            (
                                _property_value(cell, "finetermval"),
                                _property_value(cell, "assetDetails"),
                            )
                        ]
                        if not specs[0][0]:
                            specs = []
                    if not specs:
                        continue

                    cell_id = str(cell.get("id") or "").strip()
                    # flow 自身 outOfScope（或节点为外部接口/外部实体）→ 不分析
                    cell_is_external = bool(
                        _is_out_of_scope(cell)
                        or node_info.get(cell_id, {}).get("is_external", False)
                    )
                    cell_is_external_interface = bool(
                        node_info.get(cell_id, {}).get(
                            "is_external_interface", False
                        )
                    )
                    cell_is_external_component = bool(
                        node_info.get(cell_id, {}).get(
                            "is_external_component", False
                        )
                    )
                    element_index = _element_index(
                        raw_type, cell.get("id"), cell
                    )

                    # 信号 flow 的端点与协议对同一 flow 的全部资产共享
                    source_id = ""
                    target_id = ""
                    source_value = ""
                    target_value = ""
                    if mapped_type == "信号":
                        target_id = str(
                            (cell.get("target") or {}).get("id", "")
                        ).strip()
                        source_id = str(
                            (cell.get("source") or {}).get("id", "")
                        ).strip()
                        if target_id in id_to_cell:
                            target_value = _node_name(id_to_cell[target_id])
                        if source_id in id_to_cell:
                            source_value = _node_name(id_to_cell[source_id])

                    for (finetermval_value, asset_details) in specs:
                        target_value_asset = target_value
                        if mapped_type == "部件":
                            target_value_asset = finetermval_value
                        elif mapped_type == "数据":
                            # 数据资产的攻击路径终点应是其承载/连接的部件，
                            # 而不是 tm.Store 本身。常见 DFD 语义是
                            # ``部件 -> 数据存储``，此时取入边的 source；兼容
                            # ``数据存储 -> 部件`` 的导出格式，再取出边 target。
                            # 优先选择 tm.Process，避免把外部 Actor 当作车内
                            # 数据承载部件；若没有 Process，再保留其它端点，
                            # 由后续拓扑过滤给出明确状态。
                            connected_candidates: list[tuple[int, str]] = []

                            for flow_cell in target_to_flows.get(cell_id, []):
                                endpoint_id = str(
                                    (flow_cell.get("source") or {}).get("id", "")
                                ).strip()
                                endpoint = id_to_cell.get(endpoint_id)
                                if not endpoint:
                                    continue
                                endpoint_name = _node_name(endpoint)
                                if endpoint_name:
                                    priority = (
                                        0
                                        if endpoint.get("type") == "tm.Process"
                                        else 1
                                    )
                                    connected_candidates.append((priority, endpoint_name))

                            for flow_cell in source_to_flows.get(cell_id, []):
                                endpoint_id = str(
                                    (flow_cell.get("target") or {}).get("id", "")
                                ).strip()
                                endpoint = id_to_cell.get(endpoint_id)
                                if not endpoint:
                                    continue
                                endpoint_name = _node_name(endpoint)
                                if endpoint_name:
                                    priority = (
                                        0
                                        if endpoint.get("type") == "tm.Process"
                                        else 1
                                    )
                                    connected_candidates.append((priority, endpoint_name))

                            if connected_candidates:
                                connected_candidates.sort(key=lambda item: item[0])
                                target_value_asset = connected_candidates[0][1]

                        item = {
                            "asset_type": mapped_type,
                            "asset_name": finetermval_value,
                            "assetDetails": asset_details,
                            # Keep the DFD semantics explicit. A flow's
                            # assetDetails is the signal-category criterion;
                            # for a data store the same field is the data-kind
                            # criterion. finetermval remains asset_name. A
                            # process assetDetails is only component detail.
                            "signal_category": (
                                asset_details if mapped_type == "信号" else ""
                            ),
                            "data_type": (
                                asset_details
                                if mapped_type == "数据"
                                else ""
                            ),
                            "element_id": cell_id,
                            "element_index": element_index,
                            "dfd_element_type": raw_type,
                            "asset_is_external": cell_is_external,
                            "asset_is_external_interface": (
                                cell_is_external_interface
                            ),
                            "asset_is_external_component": (
                                cell_is_external_component
                            ),
                        }
                        if target_value_asset:
                            item["target"] = target_value_asset
                        if source_value:
                            item["source"] = source_value
                        if mapped_type == "信号":
                            source_info = node_info.get(source_id, {})
                            target_info = node_info.get(target_id, {})
                            item.update(
                                {
                                    "source_element_id": source_id,
                                    "target_element_id": target_id,
                                    "source_is_external": bool(
                                        source_info.get("is_external", False)
                                    ),
                                    "source_is_external_interface": bool(
                                        source_info.get(
                                            "is_external_interface", False
                                        )
                                    ),
                                    "source_is_external_component": bool(
                                        source_info.get(
                                            "is_external_component", False
                                        )
                                    ),
                                    "source_external_entity_type": source_info.get(
                                        "external_entity_type", "internal"
                                    ),
                                    "target_is_external": bool(
                                        target_info.get("is_external", False)
                                    ),
                                    "target_is_external_interface": bool(
                                        target_info.get(
                                            "is_external_interface", False
                                        )
                                    ),
                                    "target_is_external_component": bool(
                                        target_info.get(
                                            "is_external_component", False
                                        )
                                    ),
                                    "target_external_entity_type": target_info.get(
                                        "external_entity_type", "internal"
                                    ),
                                    "flow_protocol": _normalize_text(
                                        cell.get("protocol", "")
                                    ),
                                }
                            )
                        if mapped_type == "接口":
                            item["is_external_actor"] = True

                        current_result["assets"].append(item)

        if not current_result["function"]:
            current_result["function"] = os.path.splitext(os.path.basename(file_path))[0]

        if current_result["assets"]:
            all_results.append(current_result)

    if parse_errors and strict_inputs:
        preview = "；".join(parse_errors[:5])
        suffix = f"（另有 {len(parse_errors) - 5} 个）" if len(parse_errors) > 5 else ""
        raise ValueError(f"DFD 存在无法解析的输入: {preview}{suffix}")
    logger.info(f"DFD解析完成: {len(all_results)} 个功能")
    return all_results


def load_function_inventory(excel_path: str) -> dict[str, str]:
    """读取功能清单 Excel，返回 {主功能: 合并描述}。

    将每个子功能的需求描述取第一句（限 100 字符）并按主功能合并。
    """
    import openpyxl
    wb = openpyxl.load_workbook(excel_path, data_only=True)
    ws = wb.active
    raw: dict[str, list[str]] = {}
    for row in ws.iter_rows(min_row=3, values_only=True):
        main_func = str(row[1]).strip() if row[1] else None
        desc = str(row[3]).strip() if row[3] else ''
        if main_func and len(desc) > 10:
            first_sent = desc.split("。")[0].strip()
            if len(first_sent) > 100:
                first_sent = first_sent[:100].rsplit(";", 1)[0] if ";" in first_sent[:100] else first_sent[:100]
            if first_sent:
                raw.setdefault(main_func, []).append(first_sent + "。")
    return {k: "".join(v) for k, v in raw.items()}


def _match_func_description(dfd_name: str, inventory: dict[str, str]) -> str:
    """将 DFD 功能名（可能含多段，如 "蓝牙电话-蓝牙设备连接"）匹配到清单描述。"""
    if not inventory:
        return ""
    if dfd_name in inventory:
        return inventory[dfd_name]
    parts = [p.strip() for p in dfd_name.split("-") if p.strip()]
    matched: list[str] = []
    for part in parts:
        if part in inventory:
            matched.append(inventory[part])
            continue
        best_key, best_len = None, 0
        for key in inventory:
            k = key.replace("（", "(").replace("）", ")")
            p = part.replace("（", "(").replace("）", ")")
            if len(p) <= len(k) and p in k and len(p) > best_len:
                best_len = len(p)
                best_key = key
            elif len(k) < len(p) and k in p and len(k) > best_len:
                best_len = len(k)
                best_key = key
        if best_key:
            matched.append(inventory[best_key])
    return "；".join(matched)


def _truncate_desc(desc: str, max_chars: int = 35) -> str:
    """截断描述到指定长度，优先在句末或逗号断开。"""
    if len(desc) <= max_chars:
        return desc
    cut = desc[:max_chars]
    for ch in ("。", "；", "；", "，", ","):
        idx = cut.rfind(ch)
        if idx > max_chars * 0.4:
            return cut[: idx + 1]
    return cut + "…"


_PURE_DEVICE_RE = re.compile(
    r"传感器|执行器|电机|马达|泵|阀|灯|雨刮|加热丝|风扇|喇叭|扬声器|蜂鸣器|开关"
)
_ACCESS_CONTROL_CAPABILITY_RE = re.compile(
    r"控制器|ECU|域控|网关|系统|模块|主机|终端|账号|账户|用户|权限|认证|授权|"
    r"诊断|日志|审计|存储|升级|更新|安全|密钥|证书", re.IGNORECASE
)

def _attribute_applicability(
    asset_type: str,
    asset_name: str,
    asset_details: str,
    attribute_name: str,
    *,
    enable_filter: bool = True,
) -> tuple[bool, str]:
    """保守确定性规则：仅过滤证据明确的纯传感/执行部件。"""
    if not enable_filter:
        return True, ""
    if asset_type != "部件" or attribute_name not in {"不可抵赖性", "权限属性"}:
        return True, ""
    evidence = f"{asset_name} {asset_details}"
    if _PURE_DEVICE_RE.search(evidence) and not _ACCESS_CONTROL_CAPABILITY_RE.search(evidence):
        capability = "审计/操作留痕" if attribute_name == "不可抵赖性" else "账户/角色/权限控制"
        return False, f"纯传感/执行部件未发现{capability}能力的证据"
    return True, ""


def _topology_filter_reason(
    asset_type: str,
    asset_name: str,
    source: str,
    target: str,
    topology_node_names: set[str],
    *,
    source_is_external: bool = False,
    target_is_external: bool = False,
) -> str:
    """按拓扑图过滤：资产对应的 ECU 不在拓扑图中的不分析。

    - 信号：source 或 target 任一端不在拓扑图 → 不分析；
      但外部接口/外部实体端点豁免——该端不在车内、攻击路径应终止于
      非外部的内部部件（见 attack_path 框架选择），信号本身仍要分析。
    - 部件：资产本身不在拓扑图 → 不分析
    - 数据：target 不在拓扑图 → 不分析
    """
    if asset_type == "信号":
        src = str(source or "").strip()
        tgt = str(target or "").strip()
        topology_keys = {_name_match_key(item) for item in topology_node_names}
        if src and not source_is_external and _name_match_key(src) not in topology_keys:
            return f"信号源 {src} 不在拓扑图中"
        if tgt and not target_is_external and _name_match_key(tgt) not in topology_keys:
            return f"信号目标 {tgt} 不在拓扑图中"
    elif asset_type == "部件":
        name = str(asset_name or "").strip()
        topology_keys = {_name_match_key(item) for item in topology_node_names}
        if name and _name_match_key(name) not in topology_keys:
            return f"部件 {name} 不在拓扑图中"
    elif asset_type == "数据":
        tgt = str(target or "").strip()
        topology_keys = {_name_match_key(item) for item in topology_node_names}
        if tgt and _name_match_key(tgt) not in topology_keys:
            return f"数据目标 {tgt} 不在拓扑图中"
    return ""


def build_task_units(
    asset_results: list[dict],
    *,
    enable_applicability_filter: bool = True,
    topology_node_names: set[str] | None = None,
    security_asset_facts: dict[str, Any] | None = None,
) -> list[TaskUnit]:
    tasks: list[TaskUnit] = []
    idx = 0
    seen: set[tuple[str, ...]] = set()
    duplicate_count = 0
    external_skipped = 0
    external_interface_skipped = 0
    external_component_skipped = 0
    topology_skipped = 0
    for func_data in asset_results:
        function_name = func_data.get("function", "")
        relations = [
            relation
            for relation in func_data.get("relations", [])
            if relation.get("source_id") and relation.get("target_id")
        ]
        nodes = {
            str(node.get("element_id", "")): node
            for node in func_data.get("nodes", [])
            if node.get("element_id")
        }
        # 只把 DFD Actor 视为候选外部接口。像“放电设备”这样虽然
        # out-of-scope、但建模类型为 Process 的外部实体不会成为攻击起点。
        actor_reachability: dict[str, set[str]] = defaultdict(set)
        for relation in relations:
            source_node = nodes.get(str(relation.get("source_id", "")), {})
            if source_node.get("dfd_element_type") != "tm.Actor":
                continue
            actor_name = _normalize_text(source_node.get("name"))
            if not actor_name:
                continue
            actor_reachability[str(relation.get("target_id", ""))].add(
                actor_name
            )
            for alias in source_node.get("aliases", []) or []:
                alias_name = _normalize_text(alias)
                if alias_name:
                    actor_reachability[str(relation.get("target_id", ""))].add(
                        alias_name
                    )

        for asset in func_data.get("assets", []):
            # out-of-scope/外部实体（DFD Actor 或 outOfScope 标记的节点）不作为分析资产：
            # 它们只作为攻击路径的源/目标证据，不生成安全属性任务。
            #
            # 不能只依赖 asset_is_external：部分旧版/手工 DFD 会把 Actor
            # 映射成“接口”或其它资产类别，但节点类型仍然明确是 tm.Actor。
            # 这类节点同样不能被当成车内资产创建安全属性任务，否则后续
            # 会伪造“Actor 自身攻击路径”。
            if (
                asset.get("asset_is_external")
                or asset.get("is_external_actor")
                or str(asset.get("dfd_element_type", "")).strip() == "tm.Actor"
            ):
                external_skipped += 1
                if asset.get("asset_is_external_component"):
                    external_component_skipped += 1
                elif asset.get("asset_is_external_interface") or asset.get(
                    "is_external_actor"
                ):
                    external_interface_skipped += 1
                continue
            asset_type = asset.get("asset_type", "")
            asset_name = asset.get("asset_name", "")
            target = asset.get("target", "")
            source = asset.get("source", "")
            asset_details = asset.get("assetDetails", "")
            critical_component, operating_system = _security_asset_fact(
                asset_name, security_asset_facts or {}
            )
            # Accept parsed inputs produced by older versions as well as the
            # new explicit fields. The fallback is lossless for the DFD
            # schema: signal/data assetDetails is the corresponding
            # requirement criterion and finetermval remains asset_name.
            signal_category = str(asset.get("signal_category", "") or "")
            if "signal_category" not in asset and asset_type == "信号":
                signal_category = str(asset_details or "")
            data_type = str(asset.get("data_type", "") or "")
            if "data_type" not in asset and asset_type == "数据":
                data_type = str(asset_details or "")
            element_index = asset.get("element_index", "")

            # 按拓扑图过滤：资产对应的 ECU 不在拓扑图中的不分析。
            # 信号端点若是外部接口/外部实体（outOfScope/Actor）则豁免，
            # 该端不在车内，攻击路径应终止于内部部件（见 attack_path）。
            topology_reason = ""
            if topology_node_names:
                topology_reason = _topology_filter_reason(
                    asset_type,
                    asset_name,
                    source,
                    target,
                    topology_node_names,
                    source_is_external=bool(
                        asset.get("source_is_external", False)
                    ),
                    target_is_external=bool(
                        asset.get("target_is_external", False)
                    ),
                )

            attrs = SECURITY_ATTRIBUTES_MAP.get(asset_type, ["完整性"])
            for attr in attrs:
                dedup_key = (
                    function_name, element_index, asset_name, asset_type, attr,
                    target, source, str(asset_details),
                )
                if dedup_key in seen:
                    duplicate_count += 1
                    continue
                seen.add(dedup_key)
                threat_type = ATTRIBUTE_TO_THREAT.get(attr, "未知")
                task = TaskUnit(
                    task_id=f"{idx:05d}",
                    function=function_name,
                    asset_name=asset_name,
                    asset_type=asset_type,
                    attribute_name=attr,
                    threat_type=threat_type,
                    target=target,
                    source=source,
                    asset_details=asset_details,
                    critical_component=critical_component,
                    operating_system=operating_system,
                    signal_category=signal_category,
                    data_type=data_type,
                    element_id=str(asset.get("element_id", "")),
                    element_index=str(element_index),
                    dfd_element_type=str(
                        asset.get("dfd_element_type", "")
                    ),
                    source_element_id=str(
                        asset.get("source_element_id", "")
                    ),
                    target_element_id=str(
                        asset.get("target_element_id", "")
                    ),
                    flow_protocol=str(asset.get("flow_protocol", "")),
                    source_is_external=bool(
                        asset.get("source_is_external", False)
                    ),
                    target_is_external=bool(
                        asset.get("target_is_external", False)
                    ),
                    source_is_external_interface=bool(
                        asset.get("source_is_external_interface", False)
                    ),
                    target_is_external_interface=bool(
                        asset.get("target_is_external_interface", False)
                    ),
                    source_is_external_component=bool(
                        asset.get("source_is_external_component", False)
                    ),
                    target_is_external_component=bool(
                        asset.get("target_is_external_component", False)
                    ),
                    asset_is_external=bool(
                        asset.get("asset_is_external", False)
                    ),
                    asset_is_external_interface=bool(
                        asset.get("asset_is_external_interface", False)
                    ),
                    asset_is_external_component=bool(
                        asset.get("asset_is_external_component", False)
                    ),
                    source_external_interfaces=sorted(
                        actor_reachability.get(
                            str(asset.get("source_element_id", "")), set()
                        )
                    ),
                )
                applicable, reason = _attribute_applicability(
                    asset_type, asset_name, str(asset_details), attr,
                    enable_filter=enable_applicability_filter,
                )
                # 纯外部接口之间的信号不分析：无车内资产参与，攻击路径
                # 无法依据拓扑/外部接口验证。外部部件不能在这里一并排除：
                # “外部部件 -> 外部部件”是 DFD 明确要求保留的直连关系；
                # 外部部件作为 Source、内部部件作为 Target 时，后续
                # attack_path.filter_path_frameworks 只会选择到达 Target 的
                # 同协议最短拓扑路线，不把外部部件伪造成攻击入口。内部
                # Source/Target 跨信道时，则通过同时挂接两条信道的中间部件
                # 完成转发。
                if applicable and (
                    asset_type == "信号"
                    and asset.get("source_is_external_interface")
                    and asset.get("target_is_external_interface")
                ):
                    applicable = False
                    reason = "仅连接外部接口（源与目标均不在分析范围），无拓扑/外部接口证据"
                if applicable and topology_reason:
                    applicable = False
                    reason = topology_reason
                if not applicable:
                    task.analysis_status = STATUS_NOT_APPLICABLE
                    task.status_reasons = [reason]
                    task.risk_value = None
                    task.risk_treatment = "不适用"
                    if topology_reason:
                        topology_skipped += 1
                tasks.append(task)
                idx += 1

    not_applicable = sum(t.analysis_status == STATUS_NOT_APPLICABLE for t in tasks)
    logger.info(
        "任务单元构建完成: %d（去除完全重复任务 %d 条，确定性不适用 %d 条，"
        "外部实体不分析 %d 条（接口 %d、部件 %d），拓扑外资产不分析 %d 条）",
        len(tasks), duplicate_count, not_applicable, external_skipped,
        external_interface_skipped, external_component_skipped, topology_skipped,
    )
    return tasks
