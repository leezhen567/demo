"""Semantic object vocabulary and dependency analysis for the input Agent.

Natural-language editing is deliberately split into two parts: the model may
propose a small JSON Patch-like plan, while this module reads the actual input
documents and computes what the plan touches.  It is the deterministic source
of truth for names such as ``asset_details``, ``protocol``, ``source`` and
``target``; the model is never allowed to invent a JSON pointer or silently
apply a cascade.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from pathlib import Path
from typing import Any, Iterable

try:
    from automotive_tara.topology import normalize_text as _topology_normalize
except Exception:  # pragma: no cover - keeps this module usable standalone
    _topology_normalize = None


FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "asset": ("asset", "asset_name", "资产", "资产名称", "目标资产", "对象"),
    "asset_details": ("asset_details", "assetdetails", "asset_detail", "资产细项", "资产详情", "资产描述"),
    "protocol": ("protocol", "line", "channel", "通信协议", "协议", "通信信道"),
    "source": ("source", "source_name", "源", "源节点", "起点"),
    "target": ("target", "target_name", "目标", "目标节点", "终点"),
    "flow": ("flow", "flow_id", "data_flow", "数据流", "关系", "信号"),
    "node": ("node", "node_id", "component", "节点", "部件", "外部部件"),
    "task": ("task", "task_id", "任务", "安全属性任务"),
    "attack_path": ("attack_path", "path_id", "攻击路径", "路径框架"),
    "impact": ("impact", "影响评级", "影响值", "impact_level"),
    "feasibility": ("feasibility", "攻击可行性", "可行性评级"),
    "risk": ("risk", "风险", "风险值", "风险处置"),
}


def normalize_semantic(value: Any) -> str:
    """Case/whitespace/newline-insensitive identity used for joins only."""
    text = unicodedata.normalize("NFKC", str(value or ""))
    text = text.replace("\\n", "\n").replace("\r", "\n")
    if _topology_normalize is not None:
        try:
            return _topology_normalize(text).casefold()
        except Exception:
            pass
    return re.sub(r"\s+", "", text).casefold()


def semantic_field(value: Any) -> str:
    key = normalize_semantic(value)
    for canonical, aliases in FIELD_ALIASES.items():
        if key == canonical or key in {normalize_semantic(item) for item in aliases}:
            return canonical
    return key


def _cell_text(cell: dict[str, Any]) -> str:
    attrs = cell.get("attrs") if isinstance(cell.get("attrs"), dict) else {}
    text = attrs.get("text") if isinstance(attrs.get("text"), dict) else {}
    value = text.get("text")
    if value:
        return str(value).strip()
    labels = cell.get("labels")
    if isinstance(labels, list):
        for label in labels:
            attrs = label.get("attrs") if isinstance(label, dict) else {}
            text = attrs.get("text") if isinstance(attrs, dict) else {}
            value = text.get("text") if isinstance(text, dict) else ""
            if value:
                return str(value).strip()
    return str(cell.get("name") or "").strip()


def _cell_details(cell: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key, value in cell.items():
        if not str(key).startswith("propertyList") or not isinstance(value, dict):
            continue
        detail = str(value.get("assetDetails") or "").strip()
        term = str(value.get("finetermval") or "").strip()
        if detail:
            values.append(detail)
        elif term:
            values.append(term)
    return values


def _is_dfd_flow(cell: dict[str, Any]) -> bool:
    """Recognize flow cells emitted by both DFD exporters."""
    return str(cell.get("type") or "").casefold() in {"tm.flow", "flow"} or cell.get("shape") == "edge"


def _dfd_cells(payload: Any) -> Iterable[tuple[str, int, dict[str, Any]]]:
    """Yield DFD cells from both exported DFD layouts.

    Current exports use ``detail.diagrams[*].diagramJson.cells``.  A few
    older conversion tools emit a diagram-like root ``data.cells`` instead.
    The editor only needs the cells and keeps the original file untouched, so
    accepting both here avoids a false "empty DFD" diagnosis before the real
    pipeline has a chance to apply its compatibility adapter.
    """
    detail = payload.get("detail") if isinstance(payload, dict) else None
    diagrams = detail.get("diagrams") if isinstance(detail, dict) else None
    if isinstance(diagrams, list):
        for diagram_index, diagram in enumerate(diagrams):
            diagram_json = diagram.get("diagramJson") if isinstance(diagram, dict) else None
            cells = diagram_json.get("cells") if isinstance(diagram_json, dict) else None
            if not isinstance(cells, list):
                continue
            for cell_index, cell in enumerate(cells):
                if isinstance(cell, dict):
                    yield f"/detail/diagrams/{diagram_index}/diagramJson/cells", cell_index, cell
        return
    # Keep the real document location, including the legacy container.
    data = payload.get("data") if isinstance(payload, dict) else None
    cells = data.get("cells") if isinstance(data, dict) else None
    if isinstance(cells, list):
        for cell_index, cell in enumerate(cells):
            if isinstance(cell, dict):
                yield "/data/cells", cell_index, cell


def load_project_graph(dfd_paths: list[Path], topology_path: Path, interfaces_path: Path) -> dict[str, Any]:
    """Extract a compact, format-independent graph for planning and audit."""
    graph: dict[str, Any] = {"dfd": [], "topology": {"nodes": [], "edges": [], "protocols": []}, "interfaces": []}
    for path in dfd_paths:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
        cells = list(_dfd_cells(payload))
        ids: dict[str, dict[str, Any]] = {}
        for diagram_id, index, cell in cells:
            if _is_dfd_flow(cell):
                continue
            cid = str(cell.get("id") or f"{diagram_id}:{index}")
            name = _cell_text(cell)
            values = _cell_details(cell)
            cell_path = f"{path.name}#{diagram_id}/{index}"
            detail_paths = []
            for key, value in cell.items():
                if not str(key).startswith("propertyList") or not isinstance(value, dict):
                    continue
                detail_key = "assetDetails" if "assetDetails" in value else "finetermval"
                if detail_key in value:
                    detail_paths.append(f"{cell_path}/{key}/{detail_key}")
            ids[cid] = {
                "id": cid,
                "name": name,
                "key": normalize_semantic(name),
                "details": values,
                "path": cell_path,
                "detail_paths": detail_paths,
            }
            graph["dfd"].append({"kind": "node", "file": path.name, **ids[cid]})
        for diagram_id, index, cell in cells:
            if not _is_dfd_flow(cell):
                continue
            source = cell.get("source") if isinstance(cell.get("source"), dict) else {}
            target = cell.get("target") if isinstance(cell.get("target"), dict) else {}
            sid = str(source.get("id") or source.get("cell") or "")
            tid = str(target.get("id") or target.get("cell") or "")
            flow_path = f"{path.name}#{diagram_id}/{index}"
            graph["dfd"].append({
                "kind": "flow", "file": path.name, "id": str(cell.get("id") or f"{diagram_id}:{index}"),
                "source_id": sid, "target_id": tid, "source": ids.get(sid, {}).get("name", ""),
                "target": ids.get(tid, {}).get("name", ""), "protocol": str(cell.get("protocol") or "").strip(),
                "source_key": normalize_semantic(ids.get(sid, {}).get("name", "")),
                "target_key": normalize_semantic(ids.get(tid, {}).get("name", "")),
                "protocol_key": normalize_semantic(cell.get("protocol") or ""),
                "path": flow_path,
                "source_path": f"{flow_path}/source",
                "target_path": f"{flow_path}/target",
                "protocol_path": f"{flow_path}/protocol",
            })
    try:
        topology = json.loads(topology_path.read_text(encoding="utf-8-sig"))
        data = topology.get("data", {}) if isinstance(topology, dict) else {}
        cells = data.get("cells", []) if isinstance(data, dict) else []
        color_to_protocol = {
            str(item.get("color")): str(item.get("name") or "")
            for item in data.get("lineData", []) if isinstance(item, dict)
        } if isinstance(data.get("lineData"), list) else {}
        for index, cell in enumerate(cells if isinstance(cells, list) else []):
            if not isinstance(cell, dict):
                continue
            if cell.get("shape") == "edge":
                source = cell.get("source") if isinstance(cell.get("source"), dict) else {}
                target = cell.get("target") if isinstance(cell.get("target"), dict) else {}
                attrs = cell.get("attrs") if isinstance(cell.get("attrs"), dict) else {}
                line = attrs.get("line") if isinstance(attrs.get("line"), dict) else {}
                color = str(line.get("stroke") or "")
                graph["topology"]["edges"].append({"id": str(cell.get("id") or index), "source_id": str(source.get("cell") or ""), "target_id": str(target.get("cell") or ""), "protocol": color_to_protocol.get(color, color), "path": f"#/data/cells/{index}"})
            else:
                node_id = str(cell.get("id") or index)
                name = _cell_text(cell)
                graph["topology"]["nodes"].append({"id": node_id, "name": name, "key": normalize_semantic(name), "path": f"#/data/cells/{index}"})
        graph["topology"]["protocols"] = list(color_to_protocol.values())
    except (OSError, json.JSONDecodeError):
        graph["topology"]["error"] = f"无法解析 {topology_path.name}"
    try:
        from openpyxl import load_workbook
        workbook = load_workbook(interfaces_path, read_only=True, data_only=True)
        for sheet in workbook.worksheets:
            rows = sheet.iter_rows(values_only=True)
            headers_row = next(rows, None)
            headers = [str(value or "").strip() for value in headers_row] if headers_row else []
            for row_index, row in enumerate(rows, start=2):
                values = {headers[i]: value for i, value in enumerate(row) if i < len(headers) and headers[i]}
                graph["interfaces"].append({"sheet": sheet.title, "row": row_index, "values": values})
        workbook.close()
    except Exception as exc:
        graph["interfaces_error"] = str(exc)
    return graph


def project_context(
    dfd_paths: list[Path], topology_path: Path, interfaces_path: Path,
    *, graph: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the small semantic context sent to the editor model.

    ``graph`` is injectable so a preview can parse the three input files once
    and reuse the result for both the prompt and dependency analysis.  This is
    important for large projects where repeated Excel/DFD parsing used to make
    every preview feel unnecessarily slow.
    """
    graph = graph if isinstance(graph, dict) else load_project_graph(dfd_paths, topology_path, interfaces_path)
    validation = validate_project_graph(graph)
    return {
        "project": dfd_paths[0].parent.parent.name if dfd_paths and dfd_paths[0].parent.parent else "TARA project",
        "files": {"dfd": [path.name for path in dfd_paths], "topology": topology_path.name, "interfaces": interfaces_path.name},
        "counts": {"dfd_nodes": sum(item.get("kind") == "node" for item in graph["dfd"]), "dfd_flows": sum(item.get("kind") == "flow" for item in graph["dfd"]), "topology_nodes": len(graph["topology"]["nodes"]), "topology_edges": len(graph["topology"]["edges"]), "interfaces": len(graph["interfaces"])},
        "field_mapping": {key: list(values) for key, values in FIELD_ALIASES.items()},
        "identity_rule": "名称匹配忽略大小写、空格和真实/转义换行；原始 JSON path 和 ID 仍保留用于写回。",
        "input_validation": {
            "valid": bool(validation.get("valid", False)),
            "errors": list(validation.get("errors", []))[:12],
            "warnings": list(validation.get("warnings", []))[:12],
        },
    }


def validate_project_graph(graph: dict[str, Any]) -> dict[str, Any]:
    """Validate cross-document references without modifying the inputs.

    The result is intentionally diagnostic rather than a hard gate.  Existing
    customer data can contain unnamed external actors or legacy edges; those
    are warnings.  Explicitly dangling IDs and parser failures are errors and
    are surfaced in the Agent trace so the user can correct them before a
    report run.
    """
    errors: list[str] = []
    warnings: list[str] = []
    dfd_items = graph.get("dfd", []) if isinstance(graph, dict) else []
    dfd_nodes = [item for item in dfd_items if isinstance(item, dict) and item.get("kind") == "node"]
    dfd_flows = [item for item in dfd_items if isinstance(item, dict) and item.get("kind") == "flow"]
    known_dfd_ids_by_file: dict[str, set[str]] = {}
    for node in dfd_nodes:
        if node.get("id"):
            known_dfd_ids_by_file.setdefault(str(node.get("file") or ""), set()).add(str(node.get("id")))
    for flow in dfd_flows:
        source_id = str(flow.get("source_id") or "")
        target_id = str(flow.get("target_id") or "")
        known_dfd_ids = known_dfd_ids_by_file.get(str(flow.get("file") or ""), set())
        if source_id and source_id not in known_dfd_ids:
            errors.append(f"DFD 数据流 {flow.get('id', '')} 的 source_id 不存在：{source_id}")
        elif not source_id:
            warnings.append(f"DFD 数据流 {flow.get('id', '')} 没有 source_id（可能是外部未建模端点）")
        if target_id and target_id not in known_dfd_ids:
            errors.append(f"DFD 数据流 {flow.get('id', '')} 的 target_id 不存在：{target_id}")
        elif not target_id:
            warnings.append(f"DFD 数据流 {flow.get('id', '')} 没有 target_id（可能是外部未建模端点）")
        if not str(flow.get("protocol") or "").strip():
            warnings.append(f"DFD 数据流 {flow.get('id', '')} 未声明 protocol")

    topology = graph.get("topology", {}) if isinstance(graph, dict) else {}
    topology_nodes = topology.get("nodes", []) if isinstance(topology, dict) else []
    topology_edges = topology.get("edges", []) if isinstance(topology, dict) else []
    known_topology_ids = {str(item.get("id")) for item in topology_nodes if isinstance(item, dict) and item.get("id")}
    for edge in topology_edges:
        source_id = str(edge.get("source_id") or "")
        target_id = str(edge.get("target_id") or "")
        if source_id and source_id not in known_topology_ids:
            errors.append(f"拓扑边 {edge.get('id', '')} 的 source 节点不存在：{source_id}")
        if target_id and target_id not in known_topology_ids:
            errors.append(f"拓扑边 {edge.get('id', '')} 的 target 节点不存在：{target_id}")
        if not str(edge.get("protocol") or "").strip():
            warnings.append(f"拓扑边 {edge.get('id', '')} 未解析出协议名称")

    def duplicate_names(items: Iterable[dict[str, Any]], label: str) -> None:
        grouped: dict[str, list[str]] = {}
        for item in items:
            key = normalize_semantic(item.get("name"))
            if key:
                grouped.setdefault(key, []).append(str(item.get("name") or ""))
        for key, names in grouped.items():
            if len(names) > 1:
                warnings.append(f"{label}名称不唯一（大小写/空白归一化后）：{names[0]}（{len(names)} 项）")

    duplicate_names(dfd_nodes, "DFD 节点")
    duplicate_names([item for item in topology_nodes if isinstance(item, dict)], "拓扑节点")
    for key in ("error",):
        if topology.get(key):
            errors.append(str(topology[key]))
    if graph.get("interfaces_error"):
        errors.append(f"外部接口 Excel：{graph['interfaces_error']}")
    return {
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "counts": {
            "dfd_nodes": len(dfd_nodes),
            "dfd_flows": len(dfd_flows),
            "topology_nodes": len(topology_nodes),
            "topology_edges": len(topology_edges),
            "interfaces": len(graph.get("interfaces", [])) if isinstance(graph, dict) else 0,
        },
    }


def analyze_dependency_impacts(plan: dict[str, Any], graph: dict[str, Any]) -> dict[str, Any]:
    """Return direct operations and conservative cascade effects.

    Generated report rows are never deleted here.  They are marked for
    deterministic recomputation; only an input relation explicitly removed by
    the user may be physically removed by the editor.
    """
    operations = [item for item in plan.get("operations", []) if isinstance(item, dict)]
    direct: list[dict[str, Any]] = []
    cascade: list[dict[str, Any]] = []
    invalidate: set[str] = set()
    warnings: list[str] = []
    confidence = "high"
    for operation in operations:
        target = str(operation.get("target") or "").lower()
        op = str(operation.get("op") or "set").lower()
        old = str(operation.get("old") or operation.get("name") or "").strip()
        key = normalize_semantic(old)
        file_name = str(operation.get("file") or "").strip()
        direct.append({"target": target, "op": op, "object": old or operation.get("path", ""), "file": operation.get("file", "")})
        if target == "dfd" and op in {"rename_asset", "delete_asset", "rename", "replace_text"}:
            nodes = [
                item for item in graph.get("dfd", [])
                if item.get("kind") == "node" and item.get("key") == key
                and (not file_name or str(item.get("file")) == Path(file_name).name)
            ]
            if not nodes:
                warnings.append(f"DFD 中未找到唯一目标：{old or operation.get('path', '')}")
                confidence = "low"
            elif len(nodes) > 1:
                warnings.append(f"DFD 目标名称不唯一：{old}（{len(nodes)} 项；请在计划中指定 file）")
                confidence = "medium" if confidence == "high" else confidence
            flows = [
                item for item in graph.get("dfd", [])
                if item.get("kind") == "flow"
                and (not file_name or str(item.get("file")) == Path(file_name).name)
                and (item.get("source_id") in {n.get("id") for n in nodes}
                     or item.get("target_id") in {n.get("id") for n in nodes}
                     or normalize_semantic(item.get("source")) == key
                     or normalize_semantic(item.get("target")) == key)
            ]
            for node in nodes:
                cascade.append({"kind": "DFD节点", "object": node.get("name"), "path": node.get("path"), "effect": "关系边、任务和攻击路径需要重新解析"})
            for flow in flows:
                cascade.append({"kind": "数据流/信号", "object": f"{flow.get('source')} → {flow.get('target')}", "path": flow.get("path"), "effect": "检查 source/target/protocol 绑定"})
                invalidate.add(f"flow:{flow.get('id')}")
            invalidate.update(f"task:{flow.get('id')}" for flow in flows)
            invalidate.update({"attack_paths", "impact", "feasibility"})
        elif target == "topology" and op in {"rename_node", "delete_node", "rename_protocol", "delete_protocol"}:
            topology_nodes = list(graph.get("topology", {}).get("nodes", []))
            topology_edges = list(graph.get("topology", {}).get("edges", []))
            if op in {"rename_node", "delete_node"}:
                node_id = str(operation.get("node_id") or "").strip()
                matches = [item for item in topology_nodes if (node_id and str(item.get("id")) == node_id) or (not node_id and item.get("key") == key)]
                if not matches:
                    warnings.append(f"拓扑中未找到目标节点：{old or node_id}")
                    confidence = "low"
                elif len(matches) > 1:
                    warnings.append(f"拓扑节点名称不唯一：{old}（{len(matches)} 项；请使用 node_id）")
                    confidence = "medium" if confidence == "high" else confidence
            else:
                protocol_matches = [item for item in topology_edges if normalize_semantic(item.get("protocol")) == key]
                if not protocol_matches:
                    warnings.append(f"拓扑中未找到协议/线路：{old}")
                    confidence = "low"
            cascade.extend({"kind": "可信路径框架", "object": "全部涉及该拓扑节点/协议的路径", "effect": "重新筛选最短可达路径并校验 path_id"} for _ in [0])
            invalidate.add("attack_paths")
        elif target in {"interfaces", "external_interfaces", "excel"}:
            if not graph.get("interfaces"):
                warnings.append("外部接口 Excel 没有可解析的数据行")
                confidence = "low"
            cascade.append({"kind": "攻击向量映射", "object": old or "接口清单", "effect": "重新计算攻击向量与入口候选；不允许凭空新增接口"})
            invalidate.update({"attack_vector", "attack_paths", "feasibility"})
        else:
            cascade.append({"kind": "结构校验", "object": operation.get("path", "未知路径"), "effect": "写回后重新运行输入/关系校验"})
    return {
        "direct": direct,
        "cascade": cascade,
        "invalidates": sorted(invalidate),
        "requires_confirmation": bool(operations),
        "confidence": confidence,
        "warnings": warnings,
        "policy": "输入关系只在明确删除操作中清理；报告任务、路径和风险值只标记为需重算，不静默删除。",
    }


def derive_cascade_operations(plan: dict[str, Any], graph: dict[str, Any]) -> list[dict[str, Any]]:
    """Derive narrowly-scoped cross-file renames after confirmation.

    Only an exact, unique semantic name match is synchronized.  Deletes and
    ambiguous matches are reported as invalidations instead of being guessed.
    """
    extra: list[dict[str, Any]] = []
    dfd_nodes = [item for item in graph.get("dfd", []) if item.get("kind") == "node"]
    topology_nodes = list(graph.get("topology", {}).get("nodes", []))
    for operation in plan.get("operations", []):
        if not isinstance(operation, dict):
            continue
        target = str(operation.get("target") or "").lower()
        op = str(operation.get("op") or "").lower()
        old = str(operation.get("old") or operation.get("name") or "").strip()
        new = str(operation.get("new") or "").strip()
        if op != "rename_node" or not old or not new:
            continue
        file_name = str(operation.get("file") or "").strip()
        matches = [
            item for item in dfd_nodes
            if item.get("key") == normalize_semantic(old)
            and (not file_name or str(item.get("file")) == Path(file_name).name)
        ]
        if target == "topology" and len(matches) == 1:
            extra.append({"target": "dfd", "file": matches[0].get("file"), "op": "rename_asset", "old": old, "new": new, "_derived": True})
    for operation in plan.get("operations", []):
        if not isinstance(operation, dict):
            continue
        target = str(operation.get("target") or "").lower()
        op = str(operation.get("op") or "").lower()
        old = str(operation.get("old") or operation.get("name") or "").strip()
        new = str(operation.get("new") or "").strip()
        if target != "dfd" or op != "rename_asset" or not old or not new:
            continue
        matches = [item for item in topology_nodes if item.get("key") == normalize_semantic(old)]
        if len(matches) == 1:
            extra.append({"target": "topology", "op": "rename_node", "node_id": matches[0].get("id"), "old": old, "new": new, "_derived": True})
    # A model may already include both sides of a cross-file rename.  Do not
    # append a second rename of an old name that no longer exists.  Resolve
    # semantic identity, not raw dict equality (node_id/file may be omitted).
    def identity(operation: dict[str, Any]) -> tuple:
        target = str(operation.get("target") or "").strip().lower()
        action = str(operation.get("op") or "").strip().lower()
        old = normalize_semantic(operation.get("old") or operation.get("name") or "")
        file_name = Path(str(operation.get("file") or "")).name
        node_id = str(operation.get("node_id") or "")
        if target == "topology":
            matches = [node for node in topology_nodes if
                       (node_id and str(node.get("id")) == node_id) or
                       (not node_id and node.get("key") == old)]
            if len(matches) == 1:
                node_id = str(matches[0].get("id"))
            file_name = ""
        elif target == "dfd" and not file_name:
            files = {str(node.get("file")) for node in dfd_nodes if node.get("key") == old}
            if len(files) == 1:
                file_name = next(iter(files))
        return target, action, file_name, node_id or old, str(operation.get("new") or "").strip()

    seen = {identity(op) for op in plan.get("operations", []) if isinstance(op, dict)}
    unique = []
    for operation in extra:
        key = identity(operation)
        if key not in seen:
            unique.append(operation)
            seen.add(key)
    return unique


def plan_id(plan: dict[str, Any]) -> str:
    canonical = dict(plan)
    canonical.pop("plan_id", None)
    payload = json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
