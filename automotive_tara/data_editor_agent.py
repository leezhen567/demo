"""Natural-language project-input editor used by the customer demo.

The model is deliberately limited to producing a small, declarative edit plan.
Only this module applies the plan to an isolated copy of the uploaded files;
the original Gradio upload cache is never modified.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import re
import shutil
import uuid
from itertools import islice
from pathlib import Path
from typing import Any, Iterable
from urllib import request as urlrequest
from urllib.error import HTTPError
from urllib.parse import urlparse

from automotive_tara.json_utils import safe_parse_json
from automotive_tara.http_client import api_endpoint
from automotive_tara.dfd_compat import normalize_dfd_json
from automotive_tara.llm import build_chat_payload, extract_choice_contents
from automotive_tara.prompts import DATA_EDITOR_SYSTEM_PROMPT
from automotive_tara.token_budget import (
    PromptContextOverflow, clamp_output_tokens_to_context,
    estimate_prompt_tokens, fit_user_prompt_to_context,
)
from automotive_tara.data_dependency import (
    analyze_dependency_impacts,
    derive_cascade_operations,
    load_project_graph,
    normalize_semantic,
    plan_id,
    project_context,
    validate_project_graph,
)

logger = logging.getLogger(__name__)
_DEFAULT_URLOPEN = urlrequest.urlopen


def _editor_urlopen(request: urlrequest.Request, *, timeout: float):
    """Local model traffic must not go through the server's outbound proxy."""
    if ((urlparse(request.full_url).hostname or "").lower() in
            {"localhost", "127.0.0.1", "::1"}
            and urlrequest.urlopen is _DEFAULT_URLOPEN):
        return urlrequest.build_opener(urlrequest.ProxyHandler({})).open(request, timeout=timeout)
    return urlrequest.urlopen(request, timeout=timeout)


class DataEditError(ValueError):
    """A safe, user-facing error while planning or applying a data edit."""


class _EditorHTTPError(DataEditError):
    """HTTP failure retaining the provider status/body for compatibility fallback."""

    def __init__(self, status: int, detail: str):
        self.status = int(status)
        self.detail = detail.strip() or "（服务端未返回错误详情）"
        super().__init__(f"HTTP {self.status}: {self.detail[:800]}")


def _editor_context_limit() -> int:
    """Read the advertised context size without importing the whole pipeline."""
    try:
        value = int(os.getenv("TARA_VLLM_MAX_MODEL_LEN", "8192"))
    except (TypeError, ValueError):
        value = 8192
    return max(2048, value)


def _fit_editor_prompt(
    system_prompt: str,
    user_prompt: str,
    *,
    context_limit: int,
    output_tokens: int,
) -> str:
    """Keep the editor request inside the model context before sending it.

    The editor receives summaries of three uploaded files.  A large project
    can otherwise make ``prompt_tokens + max_tokens`` exceed vLLM's context
    limit and vLLM correctly returns HTTP 400.  Preserve the beginning (field
    semantics and user request) and the end (topology/interface tail) when a
    compact summary is required.
    """
    marker = "\n\n【项目摘要已按模型上下文限制截断；只能使用上面展示的 JSON path 和字段】\n\n"
    return fit_user_prompt_to_context(
        system_prompt,
        user_prompt,
        context_limit=context_limit,
        output_tokens=output_tokens,
        context_reserve=512,
        marker=marker,
    )


def _editor_chat_endpoint(api_base: str) -> str:
    """Normalize UI input to an OpenAI-compatible chat-completions URL."""
    return api_endpoint(api_base, "chat/completions")


def _editor_error_detail(exc: HTTPError) -> str:
    try:
        raw = exc.read()
    except Exception:
        raw = b""
    if not raw:
        return str(exc)
    return raw.decode("utf-8", errors="replace")[:1200]


def _json_pointer_parts(pointer: Any) -> list[str]:
    text = str(pointer or "")
    if not text.startswith("/"):
        raise DataEditError(f"JSON path 必须使用 / 开头：{text!r}")
    parts = []
    for item in text[1:].split("/"):
        item = item.replace("~1", "/").replace("~0", "~")
        if item in {".", ".."} or ".." in item:
            raise DataEditError("JSON path 不允许包含路径跳转")
        parts.append(item)
    return parts


def _index_or_key(container: Any, token: str) -> Any:
    if isinstance(container, list):
        if token == "-":
            return len(container)
        try:
            index = int(token)
        except (TypeError, ValueError) as exc:
            raise DataEditError(f"数组索引无效：{token!r}") from exc
        if index < 0 or index >= len(container):
            raise DataEditError(f"数组索引越界：{token!r}")
        return index
    if isinstance(container, dict):
        return token
    raise DataEditError("JSON path 指向了不可继续访问的值")


def _get_pointer(document: Any, pointer: str) -> Any:
    current = document
    for token in _json_pointer_parts(pointer):
        key = _index_or_key(current, token)
        if isinstance(current, dict) and key not in current:
            raise DataEditError(f"JSON path 不存在：{pointer}")
        if isinstance(current, list) and key >= len(current):
            raise DataEditError(f"JSON path 不存在：{pointer}")
        current = current[key]
    return current


def _get_parent(document: Any, pointer: str) -> tuple[Any, str]:
    parts = _json_pointer_parts(pointer)
    if not parts:
        raise DataEditError("不能直接替换 JSON 根节点")
    parent = document
    for token in parts[:-1]:
        key = _index_or_key(parent, token)
        if isinstance(parent, dict) and key not in parent:
            raise DataEditError(f"JSON path 不存在：{pointer}")
        parent = parent[key]
    return parent, parts[-1]


def _set_pointer(document: Any, pointer: str, value: Any, *, add: bool = False) -> None:
    parent, token = _get_parent(document, pointer)
    if isinstance(parent, list):
        if token == "-":
            if not add:
                raise DataEditError("只有 add 操作允许使用数组末尾 -")
            parent.append(value)
            return
        try:
            index = int(token)
        except (TypeError, ValueError) as exc:
            raise DataEditError(f"数组索引无效：{token!r}") from exc
        if add:
            if index < 0 or index > len(parent):
                raise DataEditError(f"数组插入索引越界：{token!r}")
            parent.insert(index, value)
        else:
            if index < 0 or index >= len(parent):
                raise DataEditError(f"数组索引越界：{token!r}")
            parent[index] = value
        return
    if not isinstance(parent, dict):
        raise DataEditError("JSON path 父节点不是对象或数组")
    if not add and token not in parent:
        raise DataEditError(f"JSON path 不存在：{pointer}")
    parent[token] = value


def _delete_pointer(document: Any, pointer: str) -> None:
    parent, token = _get_parent(document, pointer)
    if isinstance(parent, list):
        try:
            index = int(token)
            del parent[index]
        except (TypeError, ValueError, IndexError) as exc:
            raise DataEditError(f"数组删除索引无效：{token!r}") from exc
    elif isinstance(parent, dict) and token in parent:
        del parent[token]
    else:
        raise DataEditError(f"JSON path 不存在：{pointer}")


def _walk_values(value: Any, path: str = "") -> Iterable[tuple[str, Any]]:
    yield path or "/", value
    if isinstance(value, dict):
        for key, child in value.items():
            escaped = str(key).replace("~", "~0").replace("/", "~1")
            yield from _walk_values(child, f"{path}/{escaped}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_values(child, f"{path}/{index}")


def _compact_json_context(payload: Any, *, limit: int = 14000) -> str:
    """Return scalar JSON-pointer facts instead of dumping a huge DFD graph."""
    lines: list[str] = []
    for path, value in _walk_values(payload):
        if isinstance(value, dict):
            keys = ", ".join(str(key) for key in list(value)[:25])
            line = f"{path} = object(keys: {keys}{', …' if len(value) > 25 else ''})"
        elif isinstance(value, list):
            line = f"{path} = array(length: {len(value)})"
        else:
            text = str(value).replace("\n", " ").strip()
            if not text:
                continue
            line = f"{path} = {text[:220]}"
        if sum(len(item) + 1 for item in lines) + len(line) > limit:
            lines.append("…（上下文已截断，请仅使用已展示的 JSON path）")
            break
        lines.append(line)
    return "\n".join(lines) or "（没有可展示的标量字段）"


def _summarize_json(path: Path) -> str:
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        raise DataEditError(f"无法读取 JSON {path.name}：{exc}") from exc
    # These are the two formats used by TARA.  A compact, semantic listing is
    # much more useful to the editor than a depth-first dump that truncates
    # before later nodes in a large topology.
    if isinstance(payload, dict) and isinstance(payload.get("data"), dict):
        data = payload["data"]
        cells = data.get("cells") if isinstance(data.get("cells"), list) else []
        lines = [f"文件：{path.name}", "拓扑节点："]
        for cell_index, cell in enumerate(cells):
            if not isinstance(cell, dict) or cell.get("shape") == "edge":
                continue
            attrs = cell.get("attrs") if isinstance(cell.get("attrs"), dict) else {}
            text_attrs = attrs.get("text") if isinstance(attrs.get("text"), dict) else {}
            label = text_attrs.get("text") or attrs.get("label") or cell.get("name") or ""
            lines.append(
                f"- path=/data/cells/{cell_index} id={cell.get('id')} "
                f"shape={cell.get('shape')} name={label} "
                f"text_path=/data/cells/{cell_index}/attrs/text/text"
            )
        lines.append("拓扑边：")
        for cell_index, cell in enumerate(cells):
            if not isinstance(cell, dict) or cell.get("shape") != "edge":
                continue
            source = cell.get("source") if isinstance(cell.get("source"), dict) else {}
            target = cell.get("target") if isinstance(cell.get("target"), dict) else {}
            attrs = cell.get("attrs") if isinstance(cell.get("attrs"), dict) else {}
            line = attrs.get("line") if isinstance(attrs.get("line"), dict) else {}
            lines.append(
                f"- path=/data/cells/{cell_index} id={cell.get('id')} "
                f"source={source.get('cell')}:{source.get('port')} "
                f"target={target.get('cell')}:{target.get('port')} "
                f"line_id={line.get('id')} stroke={line.get('stroke')} "
                f"stroke_path=/data/cells/{cell_index}/attrs/line/stroke"
            )
        line_data = data.get("lineData")
        if isinstance(line_data, list):
            lines.append("线路定义：")
            lines.extend(f"- {item}" for item in line_data[:100])
        return "\n".join(lines)[:18000]
    detail = payload.get("detail") if isinstance(payload, dict) else None
    diagrams = detail.get("diagrams") if isinstance(detail, dict) else None
    if isinstance(diagrams, list):
        lines = [f"文件：{path.name}", "DFD 图及元素："]
        for diagram_index, diagram in enumerate(diagrams):
            if not isinstance(diagram, dict):
                continue
            lines.append(f"图 id={diagram.get('id')} title={diagram.get('title')}")
            diagram_json = diagram.get("diagramJson")
            cells = diagram_json.get("cells") if isinstance(diagram_json, dict) else []
            if not isinstance(cells, list):
                continue
            for cell_index, cell in enumerate(cells):
                if not isinstance(cell, dict):
                    continue
                if cell.get("type") == "tm.Flow":
                    source = cell.get("source") if isinstance(cell.get("source"), dict) else {}
                    target = cell.get("target") if isinstance(cell.get("target"), dict) else {}
                    properties = {
                        str(key): value
                        for key, value in cell.items()
                        if str(key).startswith("propertyList") and isinstance(value, dict)
                    }
                    lines.append(
                        f"- cell_path=/detail/diagrams/{diagram_index}/diagramJson/cells/{cell_index} "
                        f"type=tm.Flow id={cell.get('id')} source_id={source.get('id')} target_id={target.get('id')} "
                        f"protocol={cell.get('protocol','')} "
                        f"protocol_path=/detail/diagrams/{diagram_index}/diagramJson/cells/{cell_index}/protocol "
                        f"properties={json.dumps(properties, ensure_ascii=False)}"
                    )
                    continue
                attrs = cell.get("attrs") if isinstance(cell.get("attrs"), dict) else {}
                text_attrs = attrs.get("text") if isinstance(attrs.get("text"), dict) else {}
                properties = {
                    str(key): value
                    for key, value in cell.items()
                    if str(key).startswith("propertyList") and isinstance(value, dict)
                }
                label_text = text_attrs.get("text", "")
                if not label_text and isinstance(cell.get("labels"), list):
                    first = cell["labels"][0] if cell["labels"] else {}
                    first_attrs = first.get("attrs") if isinstance(first, dict) else {}
                    first_text = first_attrs.get("text") if isinstance(first_attrs, dict) else {}
                    label_text = first_text.get("text", "") if isinstance(first_text, dict) else ""
                property_paths = []
                for property_key, property_value in cell.items():
                    if not str(property_key).startswith("propertyList") or not isinstance(property_value, dict):
                        continue
                    base = f"/detail/diagrams/{diagram_index}/diagramJson/cells/{cell_index}/{property_key}"
                    property_paths.append(f"{base}/finetermval={property_value.get('finetermval','')}")
                    property_paths.append(f"{base}/assetDetails={property_value.get('assetDetails','')}")
                lines.append(
                    f"- cell_path=/detail/diagrams/{diagram_index}/diagramJson/cells/{cell_index} "
                    f"id={cell.get('id')} type={cell.get('type')} "
                    f"text={label_text} "
                    f"text_path=/detail/diagrams/{diagram_index}/diagramJson/cells/{cell_index}/attrs/text/text "
                    f"properties_path=/detail/diagrams/{diagram_index}/diagramJson/cells/{cell_index}/propertyList0 "
                    f"property_paths={' ; '.join(property_paths)} "
                    f"properties={json.dumps(properties, ensure_ascii=False)}"
                )
        return "\n".join(lines)[:18000]
    return f"文件：{path.name}\n结构化字段（JSON Pointer）：\n{_compact_json_context(payload)}"


def _summarize_excel(path: Path) -> str:
    try:
        from openpyxl import load_workbook
    except ImportError as exc:
        raise DataEditError("修改外部接口 Excel 需要安装 openpyxl") from exc
    try:
        workbook = load_workbook(path, read_only=True, data_only=True)
    except Exception as exc:
        raise DataEditError(f"无法读取 Excel {path.name}：{exc}") from exc
    chunks: list[str] = [f"文件：{path.name}"]
    for sheet in workbook.worksheets:
        # Do not materialize an entire external-interface workbook merely to
        # show the first 100 rows to the planning model.
        rows = islice(sheet.iter_rows(values_only=True), 101)
        chunks.append(f"工作表：{sheet.title}")
        for row_number, row in enumerate(rows, start=1):
            values = ["" if value is None else str(value) for value in row]
            chunks.append(f"第{row_number}行：{json.dumps(values, ensure_ascii=False)}")
    workbook.close()
    return "\n".join(chunks)[:14000]


def build_editor_prompt(
    dfd_paths: list[Path], topology_path: Path, interfaces_path: Path, instruction: str,
    *, context: dict[str, Any] | None = None,
    graph: dict[str, Any] | None = None,
) -> str:
    context = context if isinstance(context, dict) else project_context(dfd_paths, topology_path, interfaces_path)
    sections = [
        "你正在修改一个汽车网络安全 TARA 项目输入。请先理解项目和对象语义，再提出最小变更。",
        "字段语义（必须按此解释用户用词）：asset/资产=DFD 节点或资产名称；asset_details/资产细项=DFD propertyList 的 assetDetails；protocol/协议=DFD Flow.protocol 或拓扑 lineData；source/源节点=DFD Flow.source；target/目标节点=DFD Flow.target；node/节点=拓扑 data.cells 的非 edge 节点；task/任务、attack_path/攻击路径、impact/影响评级、feasibility/可行性评级和 risk/风险是由输入变更后需要重算的下游结果，不直接修改报告。大小写、空格和真实/转义换行只用于匹配，写回保留原始 ID 和 JSON path。",
        f"项目上下文：\n{json.dumps(context, ensure_ascii=False, indent=2)}",
        f"用户修改要求：\n{instruction.strip()}",
        "\n当前项目输入摘要：",
    ]
    if isinstance(graph, dict):
        # Large projects can contain hundreds of DFD cells.  Sending a full
        # depth-first dump makes the model context overflow and, worse, can
        # truncate the very asset named by the user.  The graph index keeps
        # exact IDs/JSON paths for relevant objects and compact file counts;
        # semantic operations still use the original files as source of truth.
        sections.append(_editor_graph_index(graph, instruction))
    else:
        for path in dfd_paths:
            sections.append(_summarize_json(path))
        sections.append(_summarize_json(topology_path))
        sections.append(_summarize_excel(interfaces_path))
    return "\n\n---\n\n".join(sections)


def _editor_graph_index(graph: dict[str, Any], instruction: str, *, limit: int = 18000) -> str:
    """Render a bounded, relevance-first index for the planning prompt."""
    instruction_key = normalize_semantic(instruction)
    dfd_items = [item for item in graph.get("dfd", []) if isinstance(item, dict)]
    topology = graph.get("topology", {}) if isinstance(graph.get("topology"), dict) else {}
    topology_nodes = [item for item in topology.get("nodes", []) if isinstance(item, dict)]
    topology_edges = [item for item in topology.get("edges", []) if isinstance(item, dict)]
    interfaces = [item for item in graph.get("interfaces", []) if isinstance(item, dict)]

    def _mentions(item: dict[str, Any]) -> bool:
        values: list[Any] = []
        for key in ("name", "details", "source", "target", "protocol", "file", "id"):
            value = item.get(key)
            values.extend(value if isinstance(value, list) else [value])
        if isinstance(item.get("values"), dict):
            values.extend(item["values"].values())
        return any(
            (key := normalize_semantic(value))
            and len(key) >= 2
            and key in instruction_key
            for value in values
        )

    def _pointer(item: dict[str, Any]) -> str:
        raw_path = str(item.get("path") or "")
        return raw_path.split("#", 1)[1] if "#" in raw_path else raw_path

    relevant_dfd = [item for item in dfd_items if _mentions(item)]
    relevant_topology = [item for item in topology_nodes if _mentions(item)]
    relevant_edges = [item for item in topology_edges if _mentions(item)]
    relevant_interfaces = [item for item in interfaces if _mentions(item)]

    lines = [
        "这是由程序读取的跨文件对象索引。优先使用‘用户相关候选’中的真实 file、id 和 path；",
        "若候选不唯一，必须在 summary 中说明需要用户指定文件，不能猜测。名称匹配忽略大小写、空格和真实/转义换行。",
        f"文件级统计：DFD对象 {len(dfd_items)}（节点/Flow分别统计见下），拓扑节点 {len(topology_nodes)}、边 {len(topology_edges)}、接口表行 {len(interfaces)}。",
    ]
    if relevant_dfd or relevant_topology or relevant_edges or relevant_interfaces:
        lines.append("用户相关候选（优先使用）：")
        for item in [*relevant_dfd, *relevant_topology, *relevant_edges, *relevant_interfaces]:
            if item in relevant_dfd:
                details = ", ".join(str(value) for value in item.get("details", []) if value)
                detail_pointers = ",".join(
                    str(value).split("#", 1)[1] if "#" in str(value) else str(value)
                    for value in item.get("detail_paths", [])
                )
                lines.append(
                    f"- DFD {item.get('kind')} file={item.get('file')} id={item.get('id')} "
                    f"name={item.get('name') or item.get('source','')}→{item.get('target','')} "
                    f"protocol={item.get('protocol','')} details={details} "
                    f"detail_pointers={detail_pointers} "
                    f"pointer={_pointer(item)}"
                )
            elif item in relevant_topology:
                lines.append(
                    f"- 拓扑节点 id={item.get('id')} name={item.get('name')} pointer={_pointer(item)}"
                )
            elif item in relevant_edges:
                lines.append(
                    f"- 拓扑边 id={item.get('id')} source_id={item.get('source_id')} "
                    f"target_id={item.get('target_id')} protocol={item.get('protocol')} pointer={_pointer(item)}"
                )
            else:
                values = json.dumps(item.get("values", {}), ensure_ascii=False)
                lines.append(
                    f"- 外部接口 sheet={item.get('sheet')} row={item.get('row')} values={values}"
                )
    else:
        lines.append("用户相关候选：未从输入文字中定位到唯一名称；请模型仅依据下方文件统计提出计划，不能编造 path。")

    lines.append("DFD文件清单：")
    file_counts: dict[str, dict[str, int]] = {}
    for item in dfd_items:
        file_name = str(item.get("file") or "")
        bucket = file_counts.setdefault(file_name, {"node": 0, "flow": 0})
        kind = "flow" if item.get("kind") == "flow" else "node"
        bucket[kind] += 1
    lines.extend(
        f"- {name}: 节点={counts['node']} Flow={counts['flow']}"
        for name, counts in file_counts.items()
    )
    lines.append("可用字段：DFD节点的 name/details、Flow 的 source/target/protocol；拓扑节点 name、拓扑边 protocol；接口表 values。")
    return "\n".join(lines)[:limit]


def _call_editor_model(
    system_prompt: str,
    user_prompt: str,
    *,
    model: str,
    api_base: str,
    api_key: str = "",
    timeout: int = 180,
) -> dict[str, Any]:
    context_limit = _editor_context_limit()
    # A plan is short even for a large batch of edits.  Reserve enough output
    # for 100 operations while keeping the input under 4096/8192-token vLLM
    # deployments.  The fit step is what prevents the common HTTP 400 caused
    # by ``prompt + max_tokens > max_model_len``.
    requested_output_tokens = min(2048, max(768, context_limit // 3))
    fitted_prompt = _fit_editor_prompt(
        system_prompt,
        user_prompt,
        context_limit=context_limit,
        output_tokens=requested_output_tokens,
    )
    requested_output_tokens = max(
        256,
        min(
            requested_output_tokens,
            context_limit - 512 - estimate_prompt_tokens(system_prompt, fitted_prompt),
        ),
    )
    endpoint = _editor_chat_endpoint(api_base)
    auth_value = api_key or os.getenv("TARA_API_KEY", "EMPTY")

    def _post(
        *,
        response_format: dict[str, Any] | None,
        include_template_kwargs: bool = True,
        max_tokens: int = requested_output_tokens,
    ) -> bytes:
        payload = build_chat_payload(
            model=model,
            system_prompt=system_prompt,
            user_prompt=fitted_prompt,
            temperature=0.0,
            max_tokens=max_tokens,
            enable_thinking=False,
            response_format=response_format,
        )
        if not include_template_kwargs:
            # Some older OpenAI-compatible gateways reject Qwen-specific
            # chat_template_kwargs with HTTP 400 even though vLLM accepts it.
            payload.pop("chat_template_kwargs", None)
        req = urlrequest.Request(
            endpoint,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                # UI-supplied credentials take precedence, while the
                # environment remains a backwards-compatible CLI path.
                "Authorization": f"Bearer {auth_value}",
            },
            method="POST",
        )
        try:
            with _editor_urlopen(req, timeout=timeout) as response:
                return response.read()
        except HTTPError as exc:
            raise _EditorHTTPError(exc.code, _editor_error_detail(exc)) from exc
        except Exception as exc:
            raise DataEditError(f"无法调用当前模型服务 {endpoint}：{exc}") from exc

    try:
        raw = _post(response_format={"type": "json_object"})
    except _EditorHTTPError as first_error:
        if first_error.status != 400:
            raise DataEditError(
                f"无法调用当前模型服务：HTTP {first_error.status}: {first_error.detail}"
            ) from first_error
        detail_lower = first_error.detail.lower()
        context_rejection = any(
            marker in detail_lower
            for marker in ("context", "max_tokens", "prompt too long", "maximum length")
        )
        retry_tokens = requested_output_tokens
        if context_rejection:
            limit_match = re.search(
                r"maximum context length is\s+(\d+)", detail_lower
            )
            input_match = re.search(
                r"at least\s+(\d+)\s+input tokens", detail_lower
            )
            if limit_match and input_match:
                exact_limit = int(limit_match.group(1))
                exact_input = int(input_match.group(1))
                estimator_gap = max(
                    0,
                    exact_input - estimate_prompt_tokens(system_prompt, fitted_prompt),
                )
                effective_limit = min(context_limit, exact_limit) - estimator_gap - 128
                if effective_limit < 768:
                    raise DataEditError(
                        "模型服务上下文窗口不足以容纳数据修改计划；请缩小项目输入或调高服务端 max_model_len"
                    ) from first_error
                fitted_prompt = _fit_editor_prompt(
                    system_prompt, user_prompt,
                    context_limit=effective_limit, output_tokens=1024,
                )
                try:
                    retry_tokens = clamp_output_tokens_to_context(
                        min(requested_output_tokens, 1024),
                        context_limit=effective_limit,
                        system_prompt=system_prompt,
                        user_prompt=fitted_prompt,
                        context_reserve=512,
                    )
                except PromptContextOverflow as exc:
                    raise DataEditError(
                        "数据修改 Agent 输入已超过服务端上下文窗口，请缩小项目输入"
                    ) from exc
            else:
                retry_tokens = min(requested_output_tokens, 1024)
            logger.warning(
                "数据修改 Agent 上下文超限，按服务端容量压缩输入并重试一次：%s",
                first_error.detail[:500],
            )
        else:
            logger.warning(
                "数据修改 Agent 请求格式被拒绝，尝试兼容 JSON 请求：%s",
                first_error.detail[:500],
            )
        try:
            raw = _post(
                response_format={"type": "json_object"} if context_rejection else None,
                include_template_kwargs=context_rejection,
                max_tokens=retry_tokens,
            )
        except _EditorHTTPError as second_error:
            raise DataEditError(
                "无法调用当前模型服务："
                f"首次 HTTP 400（{first_error.detail[:500]}）；"
                f"兼容请求仍失败 HTTP {second_error.status}（{second_error.detail[:800]}）"
            ) from second_error
    try:
        response_data = json.loads(raw.decode("utf-8"))
        contents = extract_choice_contents(response_data)
        if not contents:
            raise ValueError("模型没有返回内容")
        plan = safe_parse_json(contents[0])
    except Exception as exc:
        raise DataEditError(f"模型未返回合法修改计划：{exc}") from exc
    if not isinstance(plan, dict) or not isinstance(plan.get("operations"), list):
        raise DataEditError("修改计划必须包含 operations 数组")
    if len(plan["operations"]) > 100:
        raise DataEditError("单次最多允许 100 个修改操作")
    return plan


def _target_file(
    operation: dict[str, Any], dfd_paths: list[Path], topology_path: Path, interfaces_path: Path
) -> tuple[str, Path]:
    target = str(operation.get("target") or "").strip().lower()
    filename = str(operation.get("file") or "").strip()
    if target == "dfd":
        candidates = dfd_paths
    elif target == "topology":
        candidates = [topology_path]
    elif target in {"interfaces", "external_interfaces", "excel"}:
        candidates = [interfaces_path]
    else:
        raise DataEditError(f"不支持的 target：{target!r}")
    if filename:
        matching = [path for path in candidates if path.name == Path(filename).name]
        if not matching:
            raise DataEditError(f"找不到目标文件：{filename}")
        if len(matching) != 1:
            raise DataEditError(f"目标文件名不唯一：{filename}；请为同名 DFD 重命名后重新上传")
        return target, matching[0]
    if len(candidates) != 1:
        raise DataEditError("多个 DFD 文件时必须在操作中指定 file 文件名")
    return target, candidates[0]


def _input_fingerprint(
    dfd_paths: list[Path], topology_path: Path, interfaces_path: Path
) -> dict[str, dict[str, int | str]]:
    """Return a cheap snapshot used to bind a plan to the inspected inputs.

    Size and nanosecond mtime are sufficient for the preview/confirmation
    window and avoid hashing large Excel files on every click.  The path is
    included only as a display/debug field; confirmation compares the
    role/index keys and all metadata values so equal basenames cannot collide.
    """
    paths = [(f"dfd/{index}", path) for index, path in enumerate(dfd_paths)]
    paths.extend([("topology", topology_path), ("interfaces", interfaces_path)])
    snapshot: dict[str, dict[str, int | str]] = {}
    for key, path in paths:
        try:
            stat = path.stat()
        except OSError as exc:
            raise DataEditError(f"无法读取输入文件状态：{path.name}: {exc}") from exc
        snapshot[key] = {
            "path": str(path.resolve()),
            "size": int(stat.st_size),
            # Nanoseconds exceed JavaScript's safe integer range.  Keep the
            # exact value across JSON/UI transport and plan-id hashing.
            "mtime_ns": str(stat.st_mtime_ns),
        }
    return snapshot


def _replace_text(document: Any, old: str, new: str) -> int:
    count = 0
    if isinstance(document, dict):
        for key, value in list(document.items()):
            if isinstance(value, str) and value == old:
                document[key] = new
                count += 1
            else:
                count += _replace_text(value, old, new)
    elif isinstance(document, list):
        for index, value in enumerate(document):
            if isinstance(value, str) and value == old:
                document[index] = new
                count += 1
            else:
                count += _replace_text(value, old, new)
    return count


def _topology_node(document: Any, *, node_id: Any = None, name: Any = None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    data = document.get("data") if isinstance(document, dict) else None
    cells = data.get("cells") if isinstance(data, dict) else None
    if not isinstance(cells, list):
        raise DataEditError("拓扑 JSON 缺少 data.cells 数组")
    wanted_id = str(node_id or "").strip()
    wanted_name = str(name or "").strip()
    wanted_key = normalize_semantic(wanted_name)
    matches: list[dict[str, Any]] = []
    for cell in cells:
        if not isinstance(cell, dict) or cell.get("shape") == "edge":
            continue
        attrs = cell.get("attrs") if isinstance(cell.get("attrs"), dict) else {}
        text = attrs.get("text") if isinstance(attrs.get("text"), dict) else {}
        label = str(text.get("text") or cell.get("name") or "").strip()
        if (wanted_id and str(cell.get("id")) == wanted_id) or (wanted_key and normalize_semantic(label) == wanted_key):
            matches.append(cell)
    if len(matches) > 1 and not wanted_id:
        raise DataEditError(f"拓扑节点名称不唯一，请改用 node_id：{wanted_name}")
    if matches:
        return matches[0], cells
    raise DataEditError(f"拓扑中未找到节点：{wanted_id or wanted_name}")


def _apply_topology_semantic_operation(document: dict[str, Any], operation: dict[str, Any]) -> str:
    action = str(operation.get("op") or "").strip().lower()
    if action == "rename_node":
        cell, _ = _topology_node(document, node_id=operation.get("node_id"), name=operation.get("old") or operation.get("name"))
        new_name = str(operation.get("new") or "").strip()
        if not new_name:
            raise DataEditError("rename_node 需要非空 new")
        attrs = cell.setdefault("attrs", {})
        if not isinstance(attrs, dict):
            attrs = {}
            cell["attrs"] = attrs
        text = attrs.setdefault("text", {})
        if not isinstance(text, dict):
            text = {}
            attrs["text"] = text
        text["text"] = new_name
        return f"拓扑节点重命名为 {new_name}"
    if action == "delete_node":
        cell, cells = _topology_node(document, node_id=operation.get("node_id"), name=operation.get("name") or operation.get("old"))
        node_id = str(cell.get("id"))
        removed_edges = 0
        kept = []
        for candidate in cells:
            if not isinstance(candidate, dict):
                kept.append(candidate)
                continue
            if candidate is cell:
                continue
            if candidate.get("shape") == "edge":
                source = candidate.get("source") if isinstance(candidate.get("source"), dict) else {}
                target = candidate.get("target") if isinstance(candidate.get("target"), dict) else {}
                if str(source.get("cell")) == node_id or str(target.get("cell")) == node_id:
                    removed_edges += 1
                    continue
            kept.append(candidate)
        cells[:] = kept
        return f"删除拓扑节点 {node_id}（同时删除 {removed_edges} 条关联边）"
    data = document.setdefault("data", {})
    if action in {"add_protocol", "rename_protocol", "delete_protocol"}:
        line_data = data.setdefault("lineData", [])
        if not isinstance(line_data, list):
            raise DataEditError("拓扑 JSON 的 data.lineData 不是数组")
        if action == "add_protocol":
            name = str(operation.get("name") or operation.get("new") or "").strip()
            color = str(operation.get("color") or "").strip()
            if not name or not color:
                raise DataEditError("add_protocol 需要 name 和 color")
            if any(isinstance(item, dict) and normalize_semantic(item.get("name")) == normalize_semantic(name) for item in line_data):
                raise DataEditError(f"协议/线路已存在：{name}")
            line_data.append({"isDelete": len(line_data), "name": name, "color": color})
            return f"新增拓扑线路/协议 {name}"
        old = str(operation.get("old") or operation.get("name") or "").strip()
        matches = [item for item in line_data if isinstance(item, dict) and normalize_semantic(item.get("name")) == normalize_semantic(old)]
        if not matches:
            raise DataEditError(f"拓扑线路/协议不存在：{old}")
        if action == "rename_protocol":
            new = str(operation.get("new") or "").strip()
            if not new:
                raise DataEditError("rename_protocol 需要非空 new")
            matches[0]["name"] = new
            return f"拓扑线路/协议重命名为 {new}"
        line_data.remove(matches[0])
        return f"删除拓扑线路/协议 {old}"
    raise DataEditError(f"不支持的拓扑语义操作：{action}")


def _apply_dfd_semantic_operation(document: dict[str, Any], operation: dict[str, Any]) -> str:
    action = str(operation.get("op") or "").strip().lower()
    groups = _dfd_cell_groups(document)
    old = str(operation.get("old") or operation.get("name") or "").strip()
    new = str(operation.get("new") or "").strip()
    if action == "delete_asset":
        if not old:
            raise DataEditError("delete_asset 需要非空 name/old")
        removed_ids: set[str] = set()
        removed = 0
        all_cells = [cell for cells in groups for cell in cells if isinstance(cell, dict)]
        for cell in all_cells:
            if _is_dfd_flow(cell):
                continue
            names = [_cell_text_for_editor(cell)]
            names.extend(str(value.get("finetermval") or "").strip() for key, value in cell.items() if str(key).startswith("propertyList") and isinstance(value, dict))
            if any(normalize_semantic(value) == normalize_semantic(old) for value in names):
                removed_ids.add(str(cell.get("id") or ""))
                for cells_local in groups:
                    cells_local[:] = [candidate for candidate in cells_local if candidate is not cell]
                removed += 1
        for cells_local in groups:
            cells_local[:] = [
                candidate for candidate in cells_local
                if not (isinstance(candidate, dict) and _is_dfd_flow(candidate) and (
                    str(((candidate.get("source") or {}).get("id") or (candidate.get("source") or {}).get("cell") or "")) in removed_ids
                    or str(((candidate.get("target") or {}).get("id") or (candidate.get("target") or {}).get("cell") or "")) in removed_ids
                ))
            ]
        if not removed:
            raise DataEditError(f"DFD 中未找到待删除资产：{old}")
        return f"DFD 删除资产：{old}（{removed}个节点及关联数据流）"
    if not old or not new:
        raise DataEditError(f"{action} 需要非空 old/name 和 new")
    count = 0
    for cells in groups:
        for cell in cells:
            if not isinstance(cell, dict):
                continue
            if action == "rename_flow_protocol":
                if _is_dfd_flow(cell) and normalize_semantic(cell.get("protocol")) == normalize_semantic(old):
                    cell["protocol"] = new
                    count += 1
                continue
            if action != "rename_asset":
                raise DataEditError(f"不支持的 DFD 语义操作：{action}")
            for key, value in cell.items():
                if str(key).startswith("propertyList") and isinstance(value, dict):
                    if normalize_semantic(value.get("finetermval")) == normalize_semantic(old):
                        value["finetermval"] = new
                        count += 1
            attrs = cell.get("attrs") if isinstance(cell.get("attrs"), dict) else {}
            text = attrs.get("text") if isinstance(attrs.get("text"), dict) else {}
            if normalize_semantic(text.get("text")) == normalize_semantic(old):
                text["text"] = new
                count += 1
            labels = cell.get("labels")
            if isinstance(labels, list):
                for label in labels:
                    label_attrs = label.get("attrs") if isinstance(label, dict) else None
                    label_text = label_attrs.get("text") if isinstance(label_attrs, dict) else None
                    if isinstance(label_text, dict) and normalize_semantic(label_text.get("text")) == normalize_semantic(old):
                        label_text["text"] = new
                        count += 1
    if not count:
        raise DataEditError(f"DFD 中未找到 {action} 目标：{old}")
    return f"DFD {action}：{old} → {new}（{count}处）"


def _cell_text_for_editor(cell: dict[str, Any]) -> str:
    attrs = cell.get("attrs") if isinstance(cell.get("attrs"), dict) else {}
    text = attrs.get("text") if isinstance(attrs.get("text"), dict) else {}
    if text.get("text"):
        return str(text["text"]).strip()
    labels = cell.get("labels")
    if isinstance(labels, list):
        for label in labels:
            label_attrs = label.get("attrs") if isinstance(label, dict) else {}
            label_text = label_attrs.get("text") if isinstance(label_attrs, dict) else {}
            if isinstance(label_text, dict) and label_text.get("text"):
                return str(label_text["text"]).strip()
    return ""


def _dfd_cell_groups(document: dict[str, Any]) -> list[list[dict[str, Any]]]:
    """Return mutable DFD cell lists for current and legacy exports."""
    detail = document.get("detail") if isinstance(document, dict) else None
    diagrams = detail.get("diagrams") if isinstance(detail, dict) else None
    if isinstance(diagrams, list):
        groups: list[list[dict[str, Any]]] = []
        for diagram in diagrams:
            diagram_json = diagram.get("diagramJson") if isinstance(diagram, dict) else None
            cells = diagram_json.get("cells") if isinstance(diagram_json, dict) else None
            if isinstance(cells, list):
                groups.append(cells)
        if groups:
            return groups
    data = document.get("data") if isinstance(document, dict) else None
    cells = data.get("cells") if isinstance(data, dict) else None
    if isinstance(cells, list):
        return [cells]
    raise DataEditError("DFD JSON 缺少 detail.diagrams 或 data.cells 数组")


def _is_dfd_flow(cell: dict[str, Any]) -> bool:
    return str(cell.get("type") or "").lower() in {"tm.flow", "flow"} or cell.get("shape") == "edge"


def _apply_json_operations(path: Path, operations: list[dict[str, Any]]) -> list[str]:
    try:
        document = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        raise DataEditError(f"无法读取 JSON {path.name}：{exc}") from exc
    summaries = _execute_json_operations(document, operations, path)
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return summaries


def _execute_json_operations(document: Any, operations: list[dict[str, Any]], path: Path) -> list[str]:
    """Shared in-memory executor for preview and confirmed writes."""
    # The visual DFD editor emits nodes/edges. Normalize that copy before
    # semantic edits so the data editor can rename assets/protocols without
    # forcing the user to run a separate conversion step first.
    if (
        isinstance(document, dict)
        and isinstance(document.get("nodes"), list)
        and isinstance(document.get("edges"), list)
    ):
        normalized = normalize_dfd_json(document)
        document.clear()
        document.update(normalized)
    summaries: list[str] = []
    for operation in operations:
        action = str(operation.get("op") or "set").strip().lower()
        if action in {"rename_asset", "delete_asset", "rename_flow_protocol"}:
            summaries.append(_apply_dfd_semantic_operation(document, operation))
            continue
        if action in {"rename_node", "delete_node", "add_protocol", "rename_protocol", "delete_protocol"}:
            summaries.append(_apply_topology_semantic_operation(document, operation))
            continue
        if action in {"set", "replace", "add"}:
            pointer = str(operation.get("path") or "")
            if action == "add":
                _set_pointer(document, pointer, copy.deepcopy(operation.get("value")), add=True)
            else:
                _set_pointer(document, pointer, copy.deepcopy(operation.get("value")))
            summaries.append(f"{path.name}：{action} {pointer}")
        elif action == "delete":
            pointer = str(operation.get("path") or "")
            _delete_pointer(document, pointer)
            summaries.append(f"{path.name}：delete {pointer}")
        elif action in {"replace_text", "rename"}:
            old, new = operation.get("old"), operation.get("new")
            if not isinstance(old, str) or not isinstance(new, str) or not old:
                raise DataEditError("replace_text 需要非空 old 和字符串 new")
            count = _replace_text(document, old, new)
            if not count:
                raise DataEditError(f"{path.name} 中未找到文本：{old}")
            summaries.append(f"{path.name}：替换文本 {old!r} → {new!r}（{count}处）")
        else:
            raise DataEditError(f"JSON 不支持操作：{action!r}")
    return summaries


def _excel_rows(path: Path) -> tuple[Any, list[Any], dict[str, int]]:
    try:
        from openpyxl import load_workbook
    except ImportError as exc:
        raise DataEditError("修改外部接口 Excel 需要安装 openpyxl") from exc
    workbook = load_workbook(path)
    sheet = workbook.active
    header_row = next(sheet.iter_rows(min_row=1, max_row=1), None)
    if header_row is None:
        raise DataEditError("外部接口 Excel 没有表头")
    headers = {str(cell.value).strip(): index for index, cell in enumerate(header_row, start=1) if cell.value is not None}
    return workbook, sheet, headers


def _row_matches(sheet: Any, row_number: int, headers: dict[str, int], match: dict[str, Any]) -> bool:
    for column, expected in match.items():
        index = headers.get(str(column).strip())
        if index is None:
            return False
        actual = sheet.cell(row_number, index).value
        if isinstance(actual, str) or isinstance(expected, str):
            if normalize_semantic(actual) != normalize_semantic(expected):
                return False
        elif actual != expected:
            return False
    return True


def _apply_excel_operations(path: Path, operations: list[dict[str, Any]]) -> list[str]:
    workbook, sheet, headers = _excel_rows(path)
    try:
        summaries = _execute_excel_operations(sheet, headers, operations, path)
        workbook.save(path)
        return summaries
    finally:
        workbook.close()


def _execute_excel_operations(sheet: Any, headers: dict[str, int], operations: list[dict[str, Any]], path: Path) -> list[str]:
    summaries: list[str] = []
    for operation in operations:
        action = str(operation.get("op") or "update_row").strip().lower()
        if action in {"replace_text", "rename_interface"}:
            old = str(operation.get("old") or "").strip()
            new = str(operation.get("new") or "").strip()
            if not old or not new:
                raise DataEditError(f"{action} 需要非空 old 和 new")
            count = 0
            for row in sheet.iter_rows():
                for cell in row:
                    matches = (
                        normalize_semantic(cell.value) == normalize_semantic(old)
                        if action == "rename_interface"
                        else str(cell.value or "").strip() == old
                    )
                    if matches:
                        cell.value = new
                        count += 1
            if not count:
                raise DataEditError(f"Excel 中未找到文本：{old}")
            summaries.append(f"{path.name}：替换文本 {old!r} → {new!r}（{count}处）")
            continue
        if action == "rename_column":
            old, new = str(operation.get("old") or "").strip(), str(operation.get("new") or "").strip()
            if old not in headers or not new:
                raise DataEditError(f"Excel 列不存在：{old}")
            sheet.cell(1, headers[old]).value = new
            headers[new] = headers.pop(old)
            summaries.append(f"{path.name}：列名 {old} → {new}")
            continue
        match = operation.get("match")
        if action in {"update_row", "delete_row"} and (not isinstance(match, dict) or not match):
            raise DataEditError("Excel 行操作必须提供 match 对象")
        matching_rows = (
            [row for row in range(2, sheet.max_row + 1) if _row_matches(sheet, row, headers, match)]
            if isinstance(match, dict)
            else []
        )
        if action == "update_row":
            updates = operation.get("set")
            if not isinstance(updates, dict) or not matching_rows:
                raise DataEditError("update_row 未匹配到行或 set 无效")
            for row in matching_rows:
                for column, value in updates.items():
                    if column not in headers:
                        raise DataEditError(f"Excel 列不存在：{column}")
                    sheet.cell(row, headers[column]).value = value
            summaries.append(f"{path.name}：更新 {len(matching_rows)} 行")
        elif action == "delete_row":
            for row in reversed(matching_rows):
                sheet.delete_rows(row, 1)
            if not matching_rows:
                raise DataEditError("delete_row 未匹配到行")
            summaries.append(f"{path.name}：删除 {len(matching_rows)} 行")
        elif action == "add_row":
            values = operation.get("values", operation.get("set"))
            if not isinstance(values, dict):
                raise DataEditError("add_row 需要 values 对象")
            row_number = sheet.max_row + 1
            for column, value in values.items():
                if column not in headers:
                    raise DataEditError(f"Excel 列不存在：{column}")
                sheet.cell(row_number, headers[column]).value = value
            summaries.append(f"{path.name}：新增 1 行")
        else:
            raise DataEditError(f"Excel 不支持操作：{action!r}")
    return summaries


def apply_edit_plan(
    plan: dict[str, Any],
    *,
    dfd_paths: list[Path],
    topology_path: Path,
    interfaces_path: Path,
    work_root: Path,
) -> tuple[list[Path], Path, Path, dict[str, Any]]:
    """Copy inputs and apply a validated model plan to the copies."""
    work_root.mkdir(parents=True, exist_ok=False)
    copied_dfd: list[Path] = []
    copies: dict[tuple[str, Path], Path] = {}
    for index, source in enumerate(dfd_paths):
        target = work_root / "dfd" / str(index) / source.name
        target.parent.mkdir(parents=True)
        shutil.copy2(source, target)
        copied_dfd.append(target)
        copies[("dfd", source)] = target
    copied_topology = work_root / "topology" / topology_path.name
    copied_interfaces = work_root / "interfaces" / interfaces_path.name
    copied_topology.parent.mkdir()
    copied_interfaces.parent.mkdir()
    shutil.copy2(topology_path, copied_topology)
    shutil.copy2(interfaces_path, copied_interfaces)
    copies[("topology", topology_path)] = copied_topology
    copies[("interfaces", interfaces_path)] = copied_interfaces
    grouped: dict[Path, list[dict[str, Any]]] = {}
    for operation in plan.get("operations", []):
        if not isinstance(operation, dict):
            raise DataEditError("每个 operation 必须是对象")
        kind, original = _target_file(operation, dfd_paths, topology_path, interfaces_path)
        kind = "interfaces" if kind in {"external_interfaces", "excel"} else kind
        target = copies[(kind, original)]
        grouped.setdefault(target, []).append(operation)
    summaries: list[str] = []
    for path, operations in grouped.items():
        if path.suffix.lower() == ".json":
            summaries.extend(_apply_json_operations(path, operations))
        elif path.suffix.lower() in {".xlsx", ".xlsm"}:
            summaries.extend(_apply_excel_operations(path, operations))
        else:
            raise DataEditError(f"不支持修改的文件类型：{path.suffix}")
    # Reparse the isolated copy after all operations.  This never blocks an
    # existing input from being inspected, but records dangling IDs and
    # duplicate identities before the copy is handed back to the analysis UI.
    try:
        graph = load_project_graph(copied_dfd, copied_topology, copied_interfaces)
        consistency = validate_project_graph(graph)
    except Exception as exc:
        consistency = {
            "valid": False,
            "errors": [f"修改后输入无法重新解析：{exc}"],
            "warnings": [],
            "counts": {},
        }
    return copied_dfd, copied_topology, copied_interfaces, {
        "说明": str(plan.get("summary") or "已应用模型修改计划"),
        "操作数": len(plan.get("operations", [])),
        "修改摘要": summaries,
        "隔离副本": str(work_root),
        "修改后一致性校验": consistency,
        "可用于分析": bool(consistency.get("valid", False)),
    }


def validate_edit_plan(
    plan: dict[str, Any], *, dfd_paths: list[Path], topology_path: Path,
    interfaces_path: Path,
) -> list[str]:
    """Validate operation shape and pointers before showing a confirmation."""
    errors: list[str] = []
    if not isinstance(plan, dict) or not isinstance(plan.get("operations"), list):
        return ["修改计划必须包含 operations 数组"]
    allowed = {"set", "replace", "add", "delete", "replace_text", "rename", "rename_asset", "delete_asset", "rename_flow_protocol", "rename_node", "delete_node", "add_protocol", "rename_protocol", "delete_protocol", "rename_interface", "update_row", "add_row", "delete_row", "rename_column"}
    for index, operation in enumerate(plan["operations"]):
        if not isinstance(operation, dict):
            errors.append(f"operations[{index}] 不是对象")
            continue
        action = str(operation.get("op") or "set").lower()
        if action not in allowed:
            errors.append(f"operations[{index}] 不支持 op={action}")
            continue
        try:
            target, path = _target_file(operation, dfd_paths, topology_path, interfaces_path)
            expected_target = {
                "rename_asset": "dfd", "delete_asset": "dfd", "rename_flow_protocol": "dfd",
                "rename_node": "topology", "delete_node": "topology", "add_protocol": "topology",
                "rename_protocol": "topology", "delete_protocol": "topology",
                "rename_interface": "interfaces", "update_row": "interfaces",
                "add_row": "interfaces", "delete_row": "interfaces", "rename_column": "interfaces",
            }.get(action)
            # Only interface operations accept their historical aliases.  The
            # previous broad alias set accidentally allowed e.g. rename_node
            # to target an Excel file, which could yield a misleadingly valid
            # preview and an unapplied operation.
            valid_targets = {expected_target} if expected_target else set()
            if expected_target == "interfaces":
                valid_targets.update({"external_interfaces", "excel"})
            if expected_target and target not in valid_targets:
                errors.append(f"operations[{index}] op={action} 不能作用于 target={target}")
                continue
            if path.suffix.lower() in {".xlsx", ".xlsm"} and action in {"set", "replace", "add", "delete", "rename_asset", "delete_asset", "rename_flow_protocol", "rename_node", "delete_node", "add_protocol", "rename_protocol", "delete_protocol"}:
                errors.append(f"operations[{index}] 不支持直接用 JSON 操作修改 Excel")
                continue
            if action in {"rename_asset", "delete_asset", "rename_flow_protocol", "rename_node", "delete_node", "rename_protocol", "delete_protocol"} and not (operation.get("old") or operation.get("name") or operation.get("node_id")):
                errors.append(f"operations[{index}] 缺少目标名称/ID")
            if action in {"rename_asset", "rename_flow_protocol", "rename_node", "rename_protocol", "rename_interface", "replace_text", "rename", "rename_column"} and not operation.get("new"):
                errors.append(f"operations[{index}] 缺少 new")
        except Exception as exc:
            errors.append(f"operations[{index}]：{exc}")
    if not errors:
        # Execute the complete sequence against in-memory documents. Checking
        # shape alone accepts nonexistent semantic targets and Excel matches.
        grouped: dict[Path, list[dict[str, Any]]] = {}
        for operation in plan["operations"]:
            _, path = _target_file(operation, dfd_paths, topology_path, interfaces_path)
            grouped.setdefault(path, []).append(operation)
        for path, operations in grouped.items():
            try:
                if path.suffix.lower() == ".json":
                    document = json.loads(path.read_text(encoding="utf-8-sig"))
                    _execute_json_operations(document, operations, path)
                else:
                    workbook, sheet, headers = _excel_rows(path)
                    try:
                        _execute_excel_operations(sheet, headers, operations, path)
                    finally:
                        workbook.close()
            except Exception as exc:
                errors.append(f"{path.name}：{exc}")
    return errors


def edit_project_inputs(
    dfd_paths: list[Path],
    topology_path: Path,
    interfaces_path: Path,
    instruction: str,
    *,
    model: str,
    api_base: str,
    editor_root: Path,
    api_key: str = "",
) -> tuple[list[Path], Path, Path, dict[str, Any]]:
    """Backward-compatible one-shot API.  New callers should use
    :func:`prepare_edit_plan` followed by :func:`apply_confirmed_edit_plan`.
    """
    plan = prepare_edit_plan(
        dfd_paths, topology_path, interfaces_path, instruction,
        model=model, api_base=api_base,
        api_key=api_key,
    )
    return apply_confirmed_edit_plan(
        plan, dfd_paths=dfd_paths, topology_path=topology_path,
        interfaces_path=interfaces_path, editor_root=editor_root,
        confirmed=True,
    )


def prepare_edit_plan(
    dfd_paths: list[Path], topology_path: Path, interfaces_path: Path,
    instruction: str, *, model: str, api_base: str, api_key: str = "",
    graph: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Ask the model for a declarative plan and attach deterministic impacts."""
    if not instruction or not instruction.strip():
        raise DataEditError("请先输入自然语言修改要求")
    if not model:
        raise DataEditError("当前没有可用模型，请先启动 vLLM")
    # One graph read is shared by the prompt, dependency analysis and input
    # validation.  Previously a single preview parsed all Excel/JSON inputs up
    # to three times, which was noticeable on HT602-sized projects.
    graph = graph if isinstance(graph, dict) else load_project_graph(dfd_paths, topology_path, interfaces_path)
    context = context if isinstance(context, dict) else project_context(dfd_paths, topology_path, interfaces_path, graph=graph)
    prompt = build_editor_prompt(
        dfd_paths,
        topology_path,
        interfaces_path,
        instruction,
        context=context,
        graph=graph,
    )
    attempts = []
    for attempt in range(2):
        plan = _call_editor_model(
            DATA_EDITOR_SYSTEM_PROMPT, prompt, model=model,
            api_base=api_base, api_key=api_key,
        )
        validation_errors = validate_edit_plan(plan, dfd_paths=dfd_paths, topology_path=topology_path, interfaces_path=interfaces_path)
        attempts.append({"attempt": attempt + 1, "errors": validation_errors})
        if not validation_errors:
            break
        if attempt == 1:
            raise DataEditError("修改计划未通过可执行校验：" + "；".join(validation_errors[:8]))
        # Put feedback before the project index so context fitting cannot
        # silently discard the reason the first proposal failed.
        prompt = (
            "上一次计划在内存试执行时失败，尚未修改文件。请根据真实字段修正；"
            "无法确定目标时返回空 operations 并在 summary 中说明，不要猜测。\n"
            + json.dumps({"rejected_operations": plan.get("operations"), "errors": validation_errors}, ensure_ascii=False)
            + "\n\n" + prompt
        )
    plan["planning_attempts"] = attempts
    plan["project_context"] = context
    plan["input_fingerprint"] = _input_fingerprint(
        dfd_paths, topology_path, interfaces_path
    )
    plan["dependency_impact"] = analyze_dependency_impacts(plan, graph)
    plan["cascade_operations"] = derive_cascade_operations(plan, graph)
    if plan["cascade_operations"]:
        cascade_errors = validate_edit_plan(
            {"operations": plan["operations"] + plan["cascade_operations"]},
            dfd_paths=dfd_paths, topology_path=topology_path, interfaces_path=interfaces_path,
        )
        if cascade_errors:
            raise DataEditError("级联修改未通过可执行校验：" + "；".join(cascade_errors[:8]))
        plan["dependency_impact"]["cascade_operations"] = plan["cascade_operations"]
        plan["dependency_impact"]["invalidates"] = sorted(set(plan["dependency_impact"].get("invalidates", [])) | {"cross_file_identity"})
    plan["agent_workflow"] = {
        "state": "await_confirmation",
        "phases": ["understand", "inspect", "propose", "validate", "await_confirmation", "apply", "verify"],
        "tools": ["inspect_inputs", "build_dependency_graph", "propose_edit_plan", "validate_plan", "apply_isolated_copy", "verify_consistency"],
        "events": [
            {"phase": "understand", "tool": "", "status": "done", "detail": "已识别 TARA 字段语义"},
            {"phase": "inspect", "tool": "inspect_inputs/build_dependency_graph", "status": "done", "detail": "已读取 DFD、拓扑和外部接口"},
            {"phase": "propose", "tool": "propose_edit_plan", "status": "done", "detail": f"模型提出 {len(plan.get('operations', []))} 项声明式操作"},
            {"phase": "validate", "tool": "validate_plan", "status": "done", "detail": "JSON path、白名单和依赖影响已检查"},
            {"phase": "await_confirmation", "tool": "", "status": "waiting", "detail": "等待用户确认；确认前零写入"},
        ],
        "write_policy": "确认前零写入；确认后只写隔离副本",
    }
    plan["requires_confirmation"] = bool(plan.get("operations"))
    plan["plan_id"] = plan_id(plan)
    return plan


def apply_confirmed_edit_plan(
    plan: dict[str, Any], *, dfd_paths: list[Path], topology_path: Path,
    interfaces_path: Path, editor_root: Path, confirmed: bool = False,
    expected_plan_id: str | None = None,
) -> tuple[list[Path], Path, Path, dict[str, Any]]:
    """Apply only an explicitly confirmed plan to an isolated input copy."""
    if not isinstance(plan, dict) or not isinstance(plan.get("operations"), list):
        raise DataEditError("缺少合法修改计划")
    actual_id = plan_id(plan)
    if expected_plan_id and expected_plan_id != actual_id:
        raise DataEditError("修改计划已变化，必须重新预览并确认")
    if plan.get("requires_confirmation", bool(plan.get("operations"))) and not confirmed:
        raise DataEditError("该修改包含数据关系变更，必须先确认级联影响")
    expected_fingerprint = plan.get("input_fingerprint")
    if isinstance(expected_fingerprint, dict):
        actual_fingerprint = _input_fingerprint(
            dfd_paths, topology_path, interfaces_path
        )
        if expected_fingerprint != actual_fingerprint:
            raise DataEditError(
                "预览后的输入文件已发生变化，已拒绝套用旧计划；请重新生成修改计划"
            )
    effective_plan = dict(plan)
    cascades = [item for item in plan.get("cascade_operations", []) if isinstance(item, dict)]
    if cascades:
        effective_plan["operations"] = list(plan.get("operations", [])) + cascades
    return apply_edit_plan(
        effective_plan, dfd_paths=dfd_paths, topology_path=topology_path,
        interfaces_path=interfaces_path,
        work_root=editor_root / uuid.uuid4().hex,
    )
