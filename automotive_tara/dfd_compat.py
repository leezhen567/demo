"""新版 DFD JSON 到旧版兼容结构的适配。

不同版本的 DFD 导出器把可视化名称放在不同位置：新版通常使用
``attrs.text.text``，旧版还要求 Flow 在 ``labels[].attrs.text.text`` 中有
显示名称，并且部分旧工具依赖每个 cell 的 ``description``。转换器只在
运行目录生成副本，不修改用户上传的原始文件；已有字段尽量保留，避免
旧版网页工具那种覆盖 ``attrs`` 导致节点身份或样式丢失的问题。新版
导出器附带的对象编号前缀会在兼容副本中规范化移除；原始 ``nodes`` /
``edges`` 始终保存在 ``sourceGraph`` 中，不会被改写。
"""

from __future__ import annotations

import copy
import json
import re
import shutil
from pathlib import Path
from typing import Any


_NUMBERED_PREFIX_RE = re.compile(
    r"^\s*(?P<prefix>[A-Za-z]{1,8}(?:[-_ ]?\d{1,6})[-_:/\.\s]*)"
    r"(?P<name>.+?)\s*$"
)
_NUMERIC_PREFIX_RE = re.compile(
    r"^\s*(?P<prefix>\d{1,6}[-_:/\.\s]+)(?P<name>.+?)\s*$"
)


def strip_numbered_name_prefix(value: Any) -> str:
    """Remove a leading exporter/object number from a DFD node name.

    Newer DFD exporters commonly store an internal object number together
    with the semantic name, for example ``P023BMS``, ``P-1-USB`` or
    ``ECU-12_VCU``.  The number is not part of the topology identity, so it
    must not prevent cross-file matching.  This routine is intentionally
    generic and conservative:

    * accepts an alphabetic object marker followed by digits, with optional
      separators (``P023``, ``P-1-``, ``ECU-12_``);
    * also accepts a clearly separated numeric prefix (``01_BMS``);
    * keeps short ambiguous names such as ``P2P`` unchanged;
    * leaves the original uploaded graph untouched; the caller stores the
      converted value only in the isolated legacy-compatible copy.

    Existing semantic names such as ``PDU`` or ``TBOX`` therefore remain
    unchanged.  The function does not contain project-specific component
    names.
    """
    text = str(value or "").strip()
    if not text:
        return ""

    match = _NUMBERED_PREFIX_RE.match(text) or _NUMERIC_PREFIX_RE.match(text)
    if not match:
        return text

    prefix = str(match.group("prefix") or "").strip()
    semantic_name = str(match.group("name") or "").strip(" -_:/.")
    # Without a delimiter, require at least two digits.  This avoids treating
    # protocol/name strings such as ``P2P Gateway`` or ``CAN2CAN`` as numbered
    # exporter labels, while still covering common compact forms like
    # ``P023BMS``.
    compact_prefix = bool(re.fullmatch(r"[A-Za-z]{1,8}\d{1,6}", prefix))
    if compact_prefix and len(re.findall(r"\d", prefix)) < 2:
        return text
    # A one-character suffix is generally an acronym/identifier rather than
    # a component name (e.g. ``P2P``), so avoid stripping it accidentally.
    if len(semantic_name) < 2 or semantic_name[0].isdigit():
        return text
    if not any(ch.isalnum() or "\u4e00" <= ch <= "\u9fff" for ch in semantic_name):
        return text
    return semantic_name


def _property_values(cell: dict[str, Any]) -> list[tuple[str, str]]:
    values: list[tuple[str, str]] = []
    for key, value in cell.items():
        if not key.startswith("propertyList") or not isinstance(value, dict):
            continue
        term = str(value.get("finetermval") or "").strip()
        if not term:
            continue
        detail = str(value.get("assetDetails") or "").strip()
        values.append((term, detail))
    return values


def _text_from_labels(cell: dict[str, Any]) -> str:
    labels = cell.get("labels")
    if not isinstance(labels, list):
        return ""
    for label in labels:
        if not isinstance(label, dict):
            continue
        attrs = label.get("attrs")
        text_attrs = attrs.get("text") if isinstance(attrs, dict) else None
        text = text_attrs.get("text") if isinstance(text_attrs, dict) else None
        if isinstance(text, str) and text.strip():
            return text.strip()
    return ""


def _text_from_attrs(cell: dict[str, Any]) -> str:
    attrs = cell.get("attrs")
    text_attrs = attrs.get("text") if isinstance(attrs, dict) else None
    text = text_attrs.get("text") if isinstance(text_attrs, dict) else None
    return text.strip() if isinstance(text, str) else ""


def _set_legacy_flow_label(cell: dict[str, Any], visible_text: str) -> None:
    """Ensure a legacy ``labels`` text exists while retaining label styling."""
    if not visible_text:
        return
    labels = cell.get("labels")
    if not isinstance(labels, list):
        labels = []
    if not labels:
        labels.append({"position": 0.5})
    first = labels[0]
    if not isinstance(first, dict):
        first = {"position": 0.5}
        labels[0] = first
    attrs = first.setdefault("attrs", {})
    if not isinstance(attrs, dict):
        attrs = {}
        first["attrs"] = attrs
    text_attrs = attrs.setdefault("text", {})
    if not isinstance(text_attrs, dict):
        text_attrs = {}
        attrs["text"] = text_attrs
    text_attrs.setdefault("text", visible_text)
    text_attrs.setdefault("font-weight", "400")
    text_attrs.setdefault("font-size", "small")
    cell["labels"] = labels


def _convert_nodes_edges_export(data: dict[str, Any]) -> dict[str, Any]:
    """Convert the canvas exporter format (``nodes``/``edges``) to cells.

    The web DFD editor exports a compact graph rather than the historical
    ``detail.diagrams[].diagramJson.cells`` envelope.  Keep this conversion
    additive so the rest of the parser can use one canonical representation.
    ``connect`` nodes are internal processes and ``interface`` nodes are
    external interfaces; ``boundary`` is only a drawing aid.
    """
    nodes = data.get("nodes")
    edges = data.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        return data

    cells: list[dict[str, Any]] = []
    node_ids = {str(item.get("id")): item for item in nodes if isinstance(item, dict)}
    for node in nodes:
        if not isinstance(node, dict):
            continue
        raw_type = str(node.get("type") or "").strip().lower()
        mapped_type = {
            "connect": "tm.Process",
            "process": "tm.Process",
            "interface": "tm.Actor",
            "actor": "tm.Actor",
            "data": "tm.Store",
            "store": "tm.Store",
            "boundary": "tm.Boundary",
        }.get(raw_type, "tm.Process")
        props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
        raw_name = str(props.get("name") or "").strip()
        name = strip_numbered_name_prefix(raw_name)
        text = node.get("text") if isinstance(node.get("text"), dict) else {}
        raw_visible = str(text.get("value") or "").strip()
        visible = strip_numbered_name_prefix(raw_visible or name)
        cell: dict[str, Any] = {
            "id": str(node.get("id") or "").strip(),
            "type": mapped_type,
            "attrs": {"text": {"text": visible}},
        }
        if mapped_type != "tm.Boundary":
            # The compact exporter stores asset terms under
            # properties.assetDetails[].property.  For a component/interface
            # the node name remains the DFD identity and is the asset term.
            detail_items = props.get("assetDetails")
            first_detail = detail_items[0] if isinstance(detail_items, list) and detail_items else {}
            if not isinstance(first_detail, dict):
                first_detail = {}
            cell["propertyList0"] = {
                "finetermval": name or visible,
                "assetDetails": str(first_detail.get("details") or "").strip(),
            }
            if raw_type == "interface":
                cell["outOfScope"] = True
                # Keep the visual DFD identity (for display and traceability),
                # while retaining the semantic interface name used by the
                # information Excel matcher (e.g. ``P-1-USB`` → ``USB``).
                alias = strip_numbered_name_prefix(
                    first_detail.get("property") or ""
                )
                if alias and alias != name:
                    cell["interfaceAliases"] = [alias]
        cells.append(cell)

    for edge in edges:
        if not isinstance(edge, dict):
            continue
        props = edge.get("properties") if isinstance(edge.get("properties"), dict) else {}
        edge_name = str(props.get("name") or edge.get("name") or "").strip()
        signal = str(props.get("signal") or props.get("protocol") or "").strip()
        cell = {
            "id": str(edge.get("id") or "").strip(),
            "type": "tm.Flow",
            "attrs": {"text": {"text": edge_name}},
            "labels": [{"position": 0.5, "attrs": {"text": {"text": edge_name}}}],
            "source": {"id": str(edge.get("sourceNodeId") or "").strip()},
            "target": {"id": str(edge.get("targetNodeId") or "").strip()},
            "protocol": signal,
        }
        details = props.get("assetDetails")
        if isinstance(details, list):
            for index, item in enumerate(details):
                if not isinstance(item, dict):
                    continue
                term = str(item.get("property") or "").strip()
                if not term:
                    continue
                cell[f"propertyList{index}"] = {
                    "finetermval": term,
                    "assetDetails": str(item.get("details") or "").strip(),
                }
        cells.append(cell)

    title = str(data.get("title") or data.get("name") or data.get("function") or "").strip()
    return {
        "summary": data.get("summary") if isinstance(data.get("summary"), dict) else {},
        "detail": {"diagrams": [{"title": title, "diagramJson": {"cells": cells}}]},
        # Preserve the original compact graph for audit/debug consumers.
        "sourceGraph": {"nodes": copy.deepcopy(nodes), "edges": copy.deepcopy(edges)},
    }


def _wrap_dfd_envelope(data: dict[str, Any]) -> dict[str, Any]:
    """Normalize supported DFD envelopes to ``detail.diagrams``.

    The browser editor has used three equivalent shapes over time: the
    historical ``detail.diagrams`` envelope, a top-level ``diagrams`` list,
    and a single ``diagramJson``/``cells`` document.  Keeping this small
    normalization step here makes the CLI, web preflight and standalone
    converter agree on what is a valid DFD.  Topology exports are deliberately
    not accepted here: they use ``data.cells`` and must be uploaded in the
    topology slot instead.
    """
    result = copy.deepcopy(data)
    if isinstance(result.get("nodes"), list) and isinstance(result.get("edges"), list):
        return _convert_nodes_edges_export(result)

    detail = result.get("detail")
    if isinstance(detail, dict) and isinstance(detail.get("diagrams"), list):
        return result

    diagrams = result.get("diagrams")
    if isinstance(diagrams, list):
        result["detail"] = {"diagrams": diagrams}
        return result

    diagram_json = result.get("diagramJson")
    if isinstance(diagram_json, dict):
        title = str(result.get("title") or result.get("name") or "").strip()
        result["detail"] = {
            "diagrams": [{"title": title, "diagramJson": diagram_json}]
        }
        return result

    cells = result.get("cells")
    if isinstance(cells, list):
        title = str(result.get("title") or result.get("name") or "").strip()
        result["detail"] = {
            "diagrams": [{"title": title, "diagramJson": {"cells": cells}}]
        }
        return result

    # A few older DFD exporters wrapped the cells in ``data``.  Topology
    # exports use the same wrapper but their cells have ``shape`` fields
    # instead of DFD ``tm.*`` types, so only accept an unmistakable DFD list.
    nested_data = result.get("data")
    nested_cells = nested_data.get("cells") if isinstance(nested_data, dict) else None
    if isinstance(nested_cells, list) and any(
        isinstance(cell, dict) and str(cell.get("type") or "").startswith("tm.")
        for cell in nested_cells
    ):
        title = str(result.get("title") or result.get("name") or "").strip()
        result["detail"] = {
            "diagrams": [{"title": title, "diagramJson": {"cells": nested_cells}}]
        }
        return result

    raise ValueError(
        "DFD JSON 结构无法识别：需要 detail.diagrams[].diagramJson.cells、"
        "diagrams、diagramJson/cells 或新版 nodes+edges；如果这是拓扑图，"
        "请上传到“拓扑图”输入框。"
    )


def normalize_dfd_json(data: dict[str, Any]) -> dict[str, Any]:
    """Return a deep-copied DFD document in the canonical legacy envelope."""
    if not isinstance(data, dict):
        raise ValueError("DFD JSON 根节点必须是对象")
    return _wrap_dfd_envelope(data)


def detect_dfd_format(data: dict[str, Any]) -> str:
    """Identify legacy-ready documents and supported exports needing conversion.

    Validate the envelope before classifying it: an unknown JSON document must
    never be treated as a new-format DFD merely because it is not legacy.
    """
    normalized = normalize_dfd_json(data)
    diagrams = normalized["detail"]["diagrams"]
    if not diagrams or any(
        not isinstance(diagram, dict)
        or not isinstance(diagram.get("diagramJson"), dict)
        or not isinstance(diagram["diagramJson"].get("cells"), list)
        for diagram in diagrams
    ):
        raise ValueError("DFD 中需要至少一张含 diagramJson.cells 数组的图")
    detail = data.get("detail")
    if not isinstance(detail, dict) or not isinstance(detail.get("diagrams"), list):
        return "new"
    for diagram in diagrams:
        for cell in diagram["diagramJson"]["cells"]:
            if (
                isinstance(cell, dict)
                and cell.get("type") == "tm.Flow"
                and not _text_from_labels(cell)
                and _text_from_attrs(cell)
            ):
                return "new"
    return "legacy"


def prepare_dfd_directory(
    source_dir: str | Path, target_dir: str | Path
) -> tuple[Path, list[dict[str, str]]]:
    """Auto-detect each file and convert only files needing compatibility fields.

    All-legacy input is used directly. Mixed input gets an isolated directory
    containing byte-identical legacy copies alongside converted new exports.
    """
    source, target = Path(source_dir), Path(target_dir)
    if not source.is_dir():
        raise ValueError(f"DFD 目录不存在：{source}")
    files = sorted(
        (path for path in source.iterdir() if path.is_file() and path.suffix.lower() == ".json"),
        key=lambda path: path.name.casefold(),
    )
    if not files:
        raise ValueError(f"DFD 目录中没有 JSON 文件：{source}")
    payloads: dict[Path, dict[str, Any]] = {}
    report: list[dict[str, str]] = []
    for path in files:
        try:
            with path.open("r", encoding="utf-8-sig") as stream:
                data = json.load(stream)
            detected = detect_dfd_format(data)
        except (OSError, UnicodeError, ValueError, TypeError) as exc:
            raise ValueError(f"{path.name}：{exc}") from exc
        payloads[path] = data
        report.append({
            "file": path.name, "format": detected,
            "action": "direct" if detected == "legacy" else "converted",
        })
    if all(item["format"] == "legacy" for item in report):
        return source, report
    target.mkdir(parents=True, exist_ok=False)
    for path, item in zip(files, report):
        destination = target / path.name
        if item["format"] == "legacy":
            shutil.copy2(path, destination)
        else:
            converted = convert_new_dfd_json(payloads[path])
            with destination.open("w", encoding="utf-8") as stream:
                json.dump(converted, stream, ensure_ascii=False, indent=2)
                stream.write("\n")
    return target, report


def convert_new_dfd_json(data: dict[str, Any]) -> dict[str, Any]:
    """Return a legacy-compatible deep copy of one DFD JSON document.

    The conversion is deliberately additive. It materializes legacy display
    fields, normalizes generic numbered prefixes in compact node names, and
    keeps original IDs, endpoint references, protocols, property lists,
    styles, existing descriptions, and the original compact graph intact.
    """
    result = normalize_dfd_json(data)
    detail = result.get("detail")
    if not isinstance(detail, dict) or not isinstance(detail.get("diagrams"), list):
        # Keep this guard defensive for callers that construct a document
        # between normalization and conversion.
        raise ValueError("DFD JSON 缺少 detail.diagrams 数组")

    summary = result.get("summary")
    if not isinstance(summary, dict):
        result["summary"] = {
            "title": "info-system",
            "owner": "Qi_Auto",
            "description": "",
        }
    else:
        summary.setdefault("title", "info-system")
        summary.setdefault("owner", "Qi_Auto")
        summary.setdefault("description", "")

    for diagram in detail["diagrams"]:
        if not isinstance(diagram, dict):
            continue
        diagram_json = diagram.get("diagramJson")
        if not isinstance(diagram_json, dict):
            continue
        cells = diagram_json.get("cells")
        if not isinstance(cells, list):
            continue
        for cell in cells:
            if not isinstance(cell, dict):
                continue
            values = _property_values(cell)
            from_labels = _text_from_labels(cell)
            from_attrs = _text_from_attrs(cell)
            visible_text = from_labels or from_attrs

            # 老版本依赖 Flow 的 labels；新版常只写 attrs.text.text。
            if cell.get("type") == "tm.Flow":
                _set_legacy_flow_label(cell, visible_text)
            else:
                # 不覆盖新版已有显示名；仅为缺少显示名的旧客户端补齐。
                attrs = cell.get("attrs")
                if not isinstance(attrs, dict):
                    attrs = {}
                    cell["attrs"] = attrs
                text_attrs = attrs.get("text")
                if not isinstance(text_attrs, dict):
                    text_attrs = {}
                    attrs["text"] = text_attrs
                if not str(text_attrs.get("text") or "").strip() and values:
                    text_attrs["text"] = ", ".join(term for term, _ in values)

            # 旧版报告/查看器使用 description 展示资产细项；已有值不覆盖。
            if values and not str(cell.get("description") or "").strip():
                cell["description"] = "\n".join(
                    f"{index}.{term}, {detail}".rstrip(", ")
                    for index, (term, detail) in enumerate(values, start=1)
                )
            elif "description" not in cell:
                cell["description"] = ""
    return result


def convert_new_dfd_file(source: str | Path, target: str | Path) -> Path:
    source_path = Path(source)
    target_path = Path(target)
    with source_path.open("r", encoding="utf-8-sig") as stream:
        data = json.load(stream)
    converted = convert_new_dfd_json(data)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    with target_path.open("w", encoding="utf-8") as stream:
        json.dump(converted, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    return target_path


def convert_new_dfd_directory(source_dir: str | Path, target_dir: str | Path) -> Path:
    source = Path(source_dir)
    target = Path(target_dir)
    if not source.is_dir():
        raise ValueError(f"DFD 目录不存在：{source}")
    target.mkdir(parents=True, exist_ok=False)
    files = sorted(
        (path for path in source.iterdir() if path.is_file() and path.suffix.lower() == ".json"),
        key=lambda path: path.name.casefold(),
    )
    if not files:
        raise ValueError(f"DFD 目录中没有 JSON 文件：{source}")
    for file_path in files:
        convert_new_dfd_file(file_path, target / file_path.name)
    return target
