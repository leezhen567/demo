"""拓扑 JSON 与外部接口 Excel 解析及可信路径框架生成。"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import zipfile
import xml.etree.ElementTree as ET
from collections import defaultdict
from typing import Callable

try:
    import pandas as pd
except Exception:
    pd = None
from openpyxl import load_workbook

from automotive_tara.domain import (
    PathNodeVO,
    TopologyElementType,
    normalize_attack_vector,
)
from automotive_tara.topology import (
    TopologyMapUtil,
    build_topology_channel_index,
    determine_attack_vector as _determine_attack_vector,
    excel_column_index as _excel_col_to_idx,
    is_checked as _is_checked,
    name_match_key as _name_match_key,
    normalize_text as _norm_text,
)

logger = logging.getLogger(__name__)
_normalize_text = _norm_text


def _is_component_mapping_header(value: object) -> bool:
    """Return whether an Excel header identifies the mapped in-vehicle component.

    The production templates use both ``外部接口关联部件`` and
    ``外部接口关键部件``.  They have the same two-column direct-mapping
    semantics; treating only the former as valid makes the latter fall through
    to the checkbox-matrix parser and silently yields an empty interface list.
    """
    text = _normalize_text(value)
    return bool(
        text
        and (
            "关联部件" in text
            or "关键部件" in text
            or text in {"部件", "组件", "零部件"}
        )
    )


def _explicit_attack_vector(value: object) -> tuple[str, str]:
    """规范化 Excel 显式攻击向量，并保留无法识别的原文。"""
    raw = _normalize_text(value)
    if not raw:
        return "", ""
    normalized = normalize_attack_vector(raw)
    if normalized:
        return normalized, ""
    return "", f"Excel攻击向量[{raw}]不在图片规定的四类映射中"


def _parse_xlsx_rows_stdlib(excel_path: str) -> list[dict]:
    """
    无 pandas/openpyxl 时，使用标准库解析 xlsx。
    返回：[{row_num:int, cells:{col_idx: value}}...]
    """
    ns = {"x": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    rel_ns = {"r": "http://schemas.openxmlformats.org/package/2006/relationships"}

    with zipfile.ZipFile(excel_path, "r") as zf:
        shared_strings: list[str] = []
        if "xl/sharedStrings.xml" in zf.namelist():
            root = ET.fromstring(zf.read("xl/sharedStrings.xml"))
            for si in root.findall(".//x:si", ns):
                text = "".join((t.text or "") for t in si.findall(".//x:t", ns))
                shared_strings.append(text)

        # 找第一个工作表文件路径
        sheet_target = "worksheets/sheet1.xml"
        try:
            wb_root = ET.fromstring(zf.read("xl/workbook.xml"))
            sheets = wb_root.findall(".//x:sheets/x:sheet", ns)
            first_sheet = sheets[0] if sheets else None
            rid = first_sheet.attrib.get("{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id") if first_sheet is not None else None
            if rid and "xl/_rels/workbook.xml.rels" in zf.namelist():
                rel_root = ET.fromstring(zf.read("xl/_rels/workbook.xml.rels"))
                for rel in rel_root.findall(".//r:Relationship", rel_ns):
                    if rel.attrib.get("Id") == rid:
                        sheet_target = rel.attrib.get("Target", sheet_target)
                        break
        except Exception:
            pass

        sheet_path = "xl/" + sheet_target.lstrip("/")
        if sheet_path not in zf.namelist():
            # 兜底
            candidates = [n for n in zf.namelist() if n.startswith("xl/worksheets/sheet") and n.endswith(".xml")]
            if not candidates:
                return []
            sheet_path = sorted(candidates)[0]

        sheet_root = ET.fromstring(zf.read(sheet_path))
        out_rows: list[dict] = []

        for row in sheet_root.findall(".//x:sheetData/x:row", ns):
            row_num = int(row.attrib.get("r", "0") or 0)
            cells: dict[int, str] = {}
            for c in row.findall("x:c", ns):
                ref = c.attrib.get("r", "")
                col_idx = _excel_col_to_idx(ref) if ref else 0
                ctype = c.attrib.get("t", "")
                value = ""
                if ctype == "s":
                    v = c.find("x:v", ns)
                    if v is not None and v.text and v.text.isdigit():
                        ss_idx = int(v.text)
                        if 0 <= ss_idx < len(shared_strings):
                            value = shared_strings[ss_idx]
                elif ctype == "inlineStr":
                    is_node = c.find("x:is", ns)
                    if is_node is not None:
                        value = "".join((t.text or "") for t in is_node.findall(".//x:t", ns))
                else:
                    v = c.find("x:v", ns)
                    value = v.text if (v is not None and v.text is not None) else ""
                cells[col_idx] = _norm_text(value)
            out_rows.append({"row_num": row_num, "cells": cells})

        return out_rows


def _load_external_interfaces(excel_path: str) -> list[dict]:
    """读取外部接口清单：pandas -> openpyxl -> 标准库 xlsx 解析。"""
    # 1) pandas 路径
    if pd is not None:
        try:
            df = pd.read_excel(excel_path, header=1)
            df.columns = [_norm_text(c) for c in df.columns]

            direct_info_col = next((c for c in df.columns if "外部接口" in c and "信息" in c), None)
            direct_comp_col = next(
                (c for c in df.columns if _is_component_mapping_header(c)), None
            )
            direct_vector_col = next((c for c in df.columns if "攻击向量" in c), None)
            if direct_info_col and direct_comp_col:
                direct_items = []
                for _, row in df.iterrows():
                    ext = _norm_text(row.get(direct_info_col, ""))
                    comp = _norm_text(row.get(direct_comp_col, ""))
                    if ext and comp and comp.lower() != "nan":
                        vector, vector_error = _explicit_attack_vector(
                            row.get(direct_vector_col, "")
                            if direct_vector_col else ""
                        )
                        direct_items.append(
                            {
                                "external_interface": ext,
                                "related_component": comp,
                                "all_interfaces": [ext],
                                "attack_vector": vector,
                                "attack_vector_mapping_error": vector_error,
                            }
                        )
                if direct_items:
                    return direct_items

            comp_col = next((c for c in df.columns if "零部件" in c and "名称" in c), None)
            if comp_col is None and len(df.columns) >= 2:
                comp_col = df.columns[1]
            if comp_col is None:
                comp_col = df.columns[0] if len(df.columns) else None

            if comp_col is None:
                return []

            interface_columns = [c for c in df.columns if c != comp_col and _norm_text(c)]
            # 对齐原逻辑：倾向跳过前两个说明列
            if len(df.columns) > 2:
                interface_columns = [c for c in df.columns[2:] if c != comp_col and _norm_text(c)]

            external_interfaces: list[dict] = []
            for _, row in df.iterrows():
                comp = _norm_text(row.get(comp_col, ""))
                if not comp or comp.lower() == "nan":
                    continue
                active = [col for col in interface_columns if _is_checked(row.get(col, ""))]
                if active:
                    external_interfaces.append(
                        {
                            "external_interface": active[0],
                            "related_component": comp,
                            "all_interfaces": active,
                        }
                    )
            if external_interfaces:
                return external_interfaces
        except Exception as e:
            logger.warning(f"pandas读取外部接口失败，尝试其他方式: {e}")

    # 2) openpyxl 路径
    try:
        from openpyxl import load_workbook

        wb = load_workbook(excel_path, data_only=True)
        ws = wb.active

        # 先尝试"外部接口信息 + 外部接口关联部件"直接映射格式
        direct_header_row = None
        info_idx = None
        comp_idx_direct = None
        vector_idx_direct = None
        for r in range(1, min(ws.max_row, 10) + 1):
            vals = [_norm_text(c.value) for c in ws[r]]
            for i, v in enumerate(vals):
                if "外部接口" in v and "信息" in v:
                    info_idx = i
                if _is_component_mapping_header(v):
                    comp_idx_direct = i
                if "攻击向量" in v:
                    vector_idx_direct = i
            if info_idx is not None and comp_idx_direct is not None:
                direct_header_row = r
                break

        if direct_header_row is not None:
            direct_items = []
            for row in ws.iter_rows(min_row=direct_header_row + 1, values_only=True):
                vals = [_norm_text(v) for v in row]
                ext = vals[info_idx] if info_idx < len(vals) else ""
                comp = vals[comp_idx_direct] if comp_idx_direct < len(vals) else ""
                if ext and comp:
                    vector, vector_error = _explicit_attack_vector(
                        vals[vector_idx_direct]
                        if vector_idx_direct is not None and vector_idx_direct < len(vals)
                        else ""
                    )
                    direct_items.append(
                        {
                            "external_interface": ext,
                            "related_component": comp,
                            "all_interfaces": [ext],
                            "attack_vector": vector,
                            "attack_vector_mapping_error": vector_error,
                        }
                    )
            if direct_items:
                return direct_items

        # 优先寻找包含"零部件名称"的表头行
        header_row_idx = None
        comp_idx = None
        max_scan = min(ws.max_row, 20)
        for r in range(1, max_scan + 1):
            vals = [_norm_text(c.value) for c in ws[r]]
            for i, v in enumerate(vals):
                if "零部件" in v and "名称" in v:
                    header_row_idx = r
                    comp_idx = i
                    break
            if header_row_idx is not None:
                break

        if header_row_idx is None:
            header_row_idx = 2
            vals = [_norm_text(c.value) for c in ws[header_row_idx]]
            comp_idx = vals.index("零部件名称") if "零部件名称" in vals else 1

        header_vals = [_norm_text(c.value) for c in ws[header_row_idx]]
        interface_cols = [(i, h) for i, h in enumerate(header_vals) if i > comp_idx and h]

        external_interfaces: list[dict] = []
        for row in ws.iter_rows(min_row=header_row_idx + 1, values_only=True):
            row_vals = [_norm_text(v) for v in row]
            if comp_idx >= len(row_vals):
                continue
            comp = row_vals[comp_idx]
            if not comp:
                continue
            active = [h for i, h in interface_cols if i < len(row_vals) and _is_checked(row_vals[i])]
            if active:
                external_interfaces.append(
                    {
                        "external_interface": active[0],
                        "related_component": comp,
                        "all_interfaces": active,
                    }
                )
        if external_interfaces:
            return external_interfaces
    except Exception:
        pass

    # 3) 标准库兜底（无 pandas / openpyxl）
    try:
        rows = _parse_xlsx_rows_stdlib(excel_path)
    except Exception as e:
        logger.warning(f"标准库解析Excel失败: {e}")
        return []

    if not rows:
        return []

    # A) "外部接口信息 + 外部接口关联部件"直接映射格式
    direct_header = None
    info_idx = None
    comp_idx_direct = None
    vector_idx_direct = None
    for r in rows[:20]:
        for idx, v in r["cells"].items():
            if "外部接口" in v and "信息" in v:
                info_idx = idx
            if _is_component_mapping_header(v):
                comp_idx_direct = idx
            if "攻击向量" in v:
                vector_idx_direct = idx
        if info_idx is not None and comp_idx_direct is not None:
            direct_header = r["row_num"]
            break

    if direct_header is not None:
        direct_items = []
        for r in rows:
            if r["row_num"] <= direct_header:
                continue
            cells = r["cells"]
            ext = _norm_text(cells.get(info_idx, ""))
            comp = _norm_text(cells.get(comp_idx_direct, ""))
            if ext and comp:
                vector, vector_error = _explicit_attack_vector(
                    cells.get(vector_idx_direct, "")
                    if vector_idx_direct is not None else ""
                )
                direct_items.append(
                    {
                        "external_interface": ext,
                        "related_component": comp,
                        "all_interfaces": [ext],
                        "attack_vector": vector,
                        "attack_vector_mapping_error": vector_error,
                    }
                )
        if direct_items:
            return direct_items

    # B) 勾选矩阵格式
    header_row_num = None
    comp_idx = None
    for r in rows[:30]:
        for idx, v in r["cells"].items():
            if "零部件" in v and "名称" in v:
                header_row_num = r["row_num"]
                comp_idx = idx
                break
        if header_row_num is not None:
            break

    if header_row_num is None:
        # 尝试第2行兜底
        row2 = next((r for r in rows if r["row_num"] == 2), None)
        if row2:
            header_row_num = 2
            for idx, v in row2["cells"].items():
                if "零部件" in v and "名称" in v:
                    comp_idx = idx
                    break
            if comp_idx is None:
                comp_idx = 1
        else:
            return []

    header_row = next((r for r in rows if r["row_num"] == header_row_num), None)
    if not header_row:
        return []

    interface_cols = [(idx, name) for idx, name in sorted(header_row["cells"].items()) if idx > comp_idx and name]

    external_interfaces: list[dict] = []
    for r in rows:
        if r["row_num"] <= header_row_num:
            continue
        cells = r["cells"]
        comp = _norm_text(cells.get(comp_idx, ""))
        if not comp:
            continue
        active = [name for idx, name in interface_cols if _is_checked(cells.get(idx, ""))]
        if active:
            external_interfaces.append(
                {
                    "external_interface": active[0],
                    "related_component": comp,
                    "all_interfaces": active,
                }
            )

    if not external_interfaces:
        logger.warning("外部接口Excel已读取，但未识别到勾选项；请检查表头与勾选符号。")
    return external_interfaces


def topology_component_names(topology_file: str) -> set[str]:
    """返回拓扑图中的全部节点名称（部件/网关/外部实体）。

    用于严格按拓扑图过滤 DFD 资产：资产对应的 ECU 不在拓扑图中的不分析。
    """
    with open(topology_file, "r", encoding="utf-8") as f:
        topo_data = json.load(f).get("data", {})
    element_vos = TopologyMapUtil.list_element_vo(topo_data.get("cells", []))
    components = TopologyMapUtil.get_distinct_components(element_vos)
    return {
        _normalize_text(component.name)
        for component in components
        if _normalize_text(component.name)
    }


def parse_topology_and_generate_frameworks(
    topology_file: str,
    external_interface_excel: str,
    asset_results: list[dict] | None = None,
    *,
    paths_per_pair: int = 0,
    external_interface_loader: Callable[[str], list[dict]] | None = None,
) -> list[dict]:
    with open(topology_file, "r", encoding="utf-8") as f:
        topo_data = json.load(f).get("data", {})

    cells = topo_data.get("cells", [])
    protocol_legends = topo_data.get("lineData", [])
    color_name_map = {p.get("color"): p.get("name") for p in protocol_legends}

    if not os.path.exists(external_interface_excel):
        logger.warning(f"外部接口文件不存在: {external_interface_excel}")
        return []
    loader = external_interface_loader or _load_external_interfaces
    external_interfaces = loader(external_interface_excel)
    if not external_interfaces:
        logger.warning("外部接口清单为空，攻击路径框架将为空。")
        return []

    # 从DFD解析结果中提取所有 target 名称，用于后续框架预匹配
    dfd_targets: set[str] = set()
    if asset_results:
        for func_data in asset_results:
            for asset in func_data.get("assets", []):
                t = (asset.get("target") or "").strip()
                if t:
                    dfd_targets.add(_name_match_key(t))

    element_vos = TopologyMapUtil.list_element_vo(cells)
    distinct_components = TopologyMapUtil.get_distinct_components(element_vos)
    channel_index = build_topology_channel_index(
        element_vos, protocol_legends, distinct_components
    )
    channel_index.raise_for_issues()
    component_id_by_name = {
        _name_match_key(component.name): component.id
        for component in distinct_components
        if _normalize_text(component.name)
    }

    def _terminal_channel_ids(component_name: str) -> list[str]:
        component_id = component_id_by_name.get(
            _name_match_key(component_name), ""
        )
        return sorted(
            channel_index.component_to_channels.get(component_id, set())
        )

    def _terminal_channel_protocols(component_name: str) -> dict[str, str]:
        return {
            channel_id: channel_index.channel_to_protocol.get(channel_id, "")
            for channel_id in _terminal_channel_ids(component_name)
        }

    def _terminal_channel_link_ids(component_name: str) -> dict[str, list[str]]:
        component_id = component_id_by_name.get(
            _name_match_key(component_name), ""
        )
        return {
            channel_id: sorted(
                channel_index.endpoint_link_ids.get(
                    (channel_id, component_id), set()
                )
            )
            for channel_id in _terminal_channel_ids(component_name)
        }
    # 提取拓扑图中的外部实体名称（如"手机"、"云平台"等虚线矩形框节点）
    external_entity_names = {c.name for c in distinct_components if c.type == TopologyElementType.EXTERNAL_COMPONENT}
    path_node_vos = TopologyMapUtil.generate_full_path(
        external_interfaces,
        element_vos,
        protocol_legends,
        distinct_components,
        channel_index=channel_index,
    )

    # ── 按视频协议拆分路径：集2=视频协议路径，集1=其余 ──
    _VIDEO_PROTOCOLS = {"FPD-LINK", "I2C over FPD-LINK", "AHD", "A2B", "CVBS", "MOST"}

    def _has_video_protocol(path_nodes):
        for node in path_nodes:
            proto = color_name_map.get(node.color, "")
            if proto in _VIDEO_PROTOCOLS:
                return True
        return False

    path_node_vos_set2 = [p for p in path_node_vos if _has_video_protocol(p)]
    path_node_vos_set1 = [p for p in path_node_vos if not _has_video_protocol(p)]

    logger.info("BFS全路径: 框架集1=%d条, 框架集2(视频协议)=%d条",
                len(path_node_vos_set1), len(path_node_vos_set2))

    comp_to_interfaces: dict[str, list[str]] = defaultdict(list)
    component_display_by_key: dict[str, str] = {}
    # 保留外部接口 Excel 的显式攻击向量。显式列优先于名称推断；空值/非法值
    # 不能静默降级为 local，后续会作为输入映射冲突写入任务状态。
    explicit_attack_vectors: dict[tuple[str, str], str] = {}
    explicit_attack_vector_errors: dict[tuple[str, str], str] = {}
    for ext in external_interfaces:
        component = _normalize_text(ext.get("related_component"))
        interfaces = ext.get("all_interfaces") or [
            ext.get("external_interface")
        ]
        for interface_value in interfaces:
            interface = _normalize_text(interface_value)
            component_key = _name_match_key(component)
            if component_key:
                component_display_by_key.setdefault(component_key, component)
            if (
                component
                and interface
                and interface not in comp_to_interfaces[component_key]
            ):
                comp_to_interfaces[component_key].append(interface)
            key = (_name_match_key(component), _name_match_key(interface))
            if ext.get("attack_vector"):
                explicit_attack_vectors[key] = normalize_attack_vector(
                    ext.get("attack_vector")
                )
            if ext.get("attack_vector_mapping_error"):
                explicit_attack_vector_errors[key] = _normalize_text(
                    ext.get("attack_vector_mapping_error")
                )

    def _resolved_attack_vector(
        component: str, interface: str, path: list[PathNodeVO]
    ) -> tuple[str, str]:
        """返回 (规范攻击向量, 映射错误)。

        Excel 显式值（包括非法值）优先；没有显式值时才按接口/拓扑协议
        推断。未知接口永远返回空向量，由任务状态层阻断而不是默认为 local。
        """
        key = (_name_match_key(component), _name_match_key(interface))
        if key in explicit_attack_vectors:
            vector = explicit_attack_vectors[key]
            if vector:
                image_vector = normalize_attack_vector(interface)
                if image_vector and image_vector != vector:
                    return "", (
                        f"Excel攻击向量[{vector}]与图片接口[{interface}]"
                        f"规定的[{image_vector}]冲突"
                    )
                return vector, ""
        if key in explicit_attack_vector_errors:
            return "", explicit_attack_vector_errors[key]
        vector = _determine_attack_vector(interface, color_name_map, path)
        if vector:
            return vector, ""
        interface_text = _normalize_text(interface) or "未知接口"
        return "", f"外部接口[{interface_text}]未匹配图片规定的攻击向量映射"

    def _add_signal_shortcut(
        fws: list[dict],
        ext: str,
        entity_name: str,
        dfd_targets: set[str],
        attack_vector: str,
        attack_vector_error: str,
        framework_set: int,
    ) -> None:
        """为信号类型资产添加简化框架：外部接口直连外部实体。"""
        simple_desc = f"[{ext}] -> {entity_name}"
        simple_id = hashlib.sha1(simple_desc.encode("utf-8")).hexdigest()[:16]
        # 检查是否已存在相同描述的框架（去重）
        if any(fw.get("path_description") == simple_desc for fw in fws):
            return
        fws.append({
            "path_id": simple_id,
            "path_description": simple_desc,
            "path_nodes": [entity_name],
            "last_node": entity_name,
            "second_to_last_node": "",
            "start_component": entity_name,
            "external_interface": ext,
            "components": [entity_name],
            "path_protocols": [],
            "path_channel_ids": [],
            "topology_link_ids": [],
            "terminal_channel_ids": _terminal_channel_ids(entity_name),
            "terminal_channel_protocols": _terminal_channel_protocols(
                entity_name
            ),
            "terminal_channel_link_ids": _terminal_channel_link_ids(
                entity_name
            ),
            "last_protocol": "",
            "attack_vector": attack_vector,
            "attack_vector_mapping_error": attack_vector_error,
            "matched_targets": [entity_name] if _name_match_key(entity_name) in dfd_targets else [],
            "framework_set": framework_set,
            "is_signal_shortcut": True,
            "last_node_is_external": True,
        })

    def _build_frameworks(paths: list[list[PathNodeVO]], framework_set: int, external_entity_names: set[str]) -> list[dict]:
        source_target_map: dict[str, list[list[PathNodeVO]]] = defaultdict(list)
        for p in paths:
            source_id = p[0].pre_component_name_id
            target_id = p[-1].component_name_id
            source_target_map[f"{source_id}_{target_id}"].append(p)

        fws: list[dict] = []
        for _, group in source_target_map.items():
            # BFS 已经只产生每个起点—终点对的等长最短路径。默认不再
            # 截断候选；paths_per_pair>0 仅作为显式的兼容/展示上限。
            ordered_group = sorted(
                group,
                key=lambda p: (len(p), 0 if any(n.is_gateway for n in p) else 1),
            )
            filtered: list[list[PathNodeVO]] = []
            seen_signatures: set[tuple] = set()
            for p in ordered_group:
                signature = tuple(
                    (n.component_name_id, color_name_map.get(n.color, n.color))
                    for n in p
                )
                if signature in seen_signatures:
                    continue
                seen_signatures.add(signature)
                filtered.append(p)
                if paths_per_pair > 0 and len(filtered) >= paths_per_pair:
                    break

            for p in filtered:
                start_comp_name = p[0].pre_component_name
                ext_list = comp_to_interfaces.get(_name_match_key(start_comp_name), ["未知接口"])

                for ext in ext_list:
                    desc = [f"[{ext}] -> {start_comp_name}"]
                    for node in p:
                        proto = color_name_map.get(node.color, "未知协议")
                        desc.append(f" -> [{proto}] -> {node.component_name}")
                    path_desc = "".join(desc)

                    path_nodes = [start_comp_name] + [n.component_name for n in p]
                    path_protocols = [
                        color_name_map.get(node.color, "未知协议")
                        for node in p
                    ]
                    path_channel_ids = [
                        node.channel_id or node.color for node in p
                    ]
                    topology_link_ids = [
                        list(node.topology_link_ids) for node in p
                    ]
                    last_node = path_nodes[-1] if path_nodes else ""
                    second_to_last_node = path_nodes[-2] if len(path_nodes) >= 2 else ""
                    attack_vector, attack_vector_error = _resolved_attack_vector(
                        start_comp_name, ext, p
                    )

                    matched_targets = [last_node] if _name_match_key(last_node) in dfd_targets else []

                    fws.append({
                        "path_id": hashlib.sha1(path_desc.encode("utf-8")).hexdigest()[:16],
                        "path_description": path_desc,
                        "path_nodes": path_nodes,
                        "last_node": last_node,
                        "second_to_last_node": second_to_last_node,
                        "start_component": start_comp_name,
                        "external_interface": ext,
                        "components": [n.component_name for n in p],
                        "path_protocols": path_protocols,
                        # Internal provenance only. Reports keep natural-language
                        # routes, while validators can trace every hop back to
                        # one direct link or the two bus-membership links.
                        "path_channel_ids": path_channel_ids,
                        "topology_link_ids": topology_link_ids,
                        "terminal_channel_ids": _terminal_channel_ids(
                            last_node
                        ),
                        "terminal_channel_protocols": (
                            _terminal_channel_protocols(last_node)
                        ),
                        "terminal_channel_link_ids": (
                            _terminal_channel_link_ids(last_node)
                        ),
                        "last_protocol": (
                            path_protocols[-1] if path_protocols else ""
                        ),
                        "attack_vector": attack_vector,
                        "attack_vector_mapping_error": attack_vector_error,
                        "matched_targets": matched_targets,
                        "framework_set": framework_set,
                        "last_node_is_external": last_node in external_entity_names,
                    })

                    # 若 last_node 或 second_to_last_node 为外部实体，为信号类资产生成简化框架
                    if last_node in external_entity_names:
                        _add_signal_shortcut(
                            fws,
                            ext,
                            last_node,
                            dfd_targets,
                            attack_vector,
                            attack_vector_error,
                            framework_set,
                        )
                    elif second_to_last_node in external_entity_names:
                        _add_signal_shortcut(
                            fws,
                            ext,
                            second_to_last_node,
                            dfd_targets,
                            attack_vector,
                            attack_vector_error,
                            framework_set,
                        )

        # 按 path_description 去重
        unique = []
        seen = set()
        for fw in fws:
            if fw["path_description"] in seen:
                continue
            seen.add(fw["path_description"])
            unique.append(fw)
        return unique

    frameworks_set1 = _build_frameworks(path_node_vos_set1, 1, external_entity_names)
    frameworks_set2 = _build_frameworks(path_node_vos_set2, 2, external_entity_names)

    # BFS 只会生成至少跨越一条拓扑边的路径，因此会漏掉外部接口清单中
    # “接口直接接入部件”的合法入口。为每条输入映射动态建立零跳入口；
    # 信号绑定随后再由代码追加 DFD Source -> Target 关系边。
    component_names = {
        _name_match_key(component.name)
        for component in distinct_components
        if _normalize_text(component.name)
    }
    existing_descriptions = {
        framework.get("path_description", "")
        for framework in frameworks_set1 + frameworks_set2
    }
    for component_key, interfaces in comp_to_interfaces.items():
        component = component_display_by_key.get(component_key, component_key)
        if component_key not in component_names:
            continue
        for interface in interfaces:
            path_description = f"[{interface}] -> {component}"
            if path_description in existing_descriptions:
                continue
            attack_vector, attack_vector_error = _resolved_attack_vector(
                component, interface, []
            )
            frameworks_set1.append({
                "path_id": hashlib.sha1(
                    path_description.encode("utf-8")
                ).hexdigest()[:16],
                "path_description": path_description,
                "path_nodes": [component],
                "last_node": component,
                "second_to_last_node": "",
                "start_component": component,
                "external_interface": interface,
                "components": [component],
                "path_protocols": [],
                "path_channel_ids": [],
                "topology_link_ids": [],
                "terminal_channel_ids": _terminal_channel_ids(component),
                "terminal_channel_protocols": (
                    _terminal_channel_protocols(component)
                ),
                "terminal_channel_link_ids": (
                    _terminal_channel_link_ids(component)
                ),
                "last_protocol": "",
                "attack_vector": attack_vector,
                "attack_vector_mapping_error": attack_vector_error,
                "matched_targets": [
                    component
                    for target in dfd_targets
                    if target == _name_match_key(component)
                ],
                "framework_set": 1,
                "is_entry_component_path": True,
                "last_node_is_external": (
                    component in external_entity_names
                ),
            })
            existing_descriptions.add(path_description)

    merged = frameworks_set1 + frameworks_set2
    # 将 information Excel 中的接口白名单随框架携带到路径组合层。
    # 这是运行期校验数据，不会新增接口；入口模型若提及另一个已知项目接口，
    # 组合层会丢弃该模型尾句并使用绑定框架的安全模板。
    project_external_interfaces = sorted({
        _normalize_text(interface)
        for item in external_interfaces
        for interface in (
            item.get("all_interfaces")
            or [item.get("external_interface")]
        )
        if _normalize_text(interface)
    })
    for framework in merged:
        framework["project_external_interfaces"] = project_external_interfaces
    logger.info(f"拓扑攻击路径框架生成完成: 框架集1={len(frameworks_set1)}条, 框架集2={len(frameworks_set2)}条, 合计={len(merged)}条")
    return merged
