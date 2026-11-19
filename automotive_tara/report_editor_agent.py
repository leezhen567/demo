"""Human-in-the-loop editor for completed TARA reports.

The model acts as a decision maker and may request a small set of read-only
tools.  It can only propose operations against stable report row IDs.  The
application validates those operations and writes a new JSON/Excel revision
after explicit user confirmation; the original run artifacts stay untouched.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import uuid
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib import request as urlrequest
from urllib.error import HTTPError
from urllib.parse import urlparse

from automotive_tara.excel_export import ExcelExportOptions, export_tara_report_to_excel
from automotive_tara.http_client import api_endpoint
from automotive_tara.json_utils import safe_parse_json
from automotive_tara.llm import build_chat_payload, extract_choice_contents
from automotive_tara.prompts import REPORT_EDITOR_SYSTEM_PROMPT
from automotive_tara.reporting import cybersecurity_fields_for_treatment
from automotive_tara.token_budget import (
    clamp_output_tokens_to_context,
    fit_user_prompt_to_context,
    estimate_prompt_tokens,
)
from automotive_tara.security_requirements import (
    load_security_requirement_matching_logic,
    load_security_requirements,
)


class ReportEditError(ValueError):
    """Safe, user-facing report-edit failure."""


class _ReportHTTPError(ReportEditError):
    """Provider HTTP error retaining status and body for bounded fallback."""

    def __init__(self, status: int, detail: str):
        self.status = int(status)
        self.detail = str(detail or "").strip()
        super().__init__(f"模型服务 HTTP {self.status}：{self.detail}")


EDITABLE_REPORT_FIELDS = {
    "damage_scenario": "损害场景",
    "threat_scenario": "威胁场景",
    "attack_path": "攻击路径",
    "risk_treatment": "风险处置",
    "cybersecurity_goal": "网络安全目标",
    "security_requirement": "安全需求",
    "national_standard_code": "国标法规编码",
    "annex5_partbc_mapping": "附录5 Part B/C映射",
    "cybersecurity_claim": "网络安全声明",
}

_ATTRIBUTE_FIELDS = {
    "damage_scenario": "damage_scenario",
    "threat_scenario": "threat_scenarios",
}
_ROW_FIELDS = {
    "attack_path": "attack_path",
    "risk_treatment": "risk_treatment",
    "cybersecurity_goal": "cybersecurity_goal",
    "security_requirement": "security_requirement",
    "national_standard_code": "national_standard_code",
    "annex5_partbc_mapping": "annex5_partbc_mapping",
    "cybersecurity_claim": "cybersecurity_claim",
}
_ALLOWED_TOOLS = {
    "search_report",
    "get_report_rows",
    "report_statistics",
    "search_security_requirements",
}
_DEFAULT_URLOPEN = urlrequest.urlopen


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value).strip()


def _load_json(path: str | os.PathLike[str]) -> Any:
    try:
        with Path(path).open("r", encoding="utf-8-sig") as stream:
            return json.load(stream)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReportEditError(f"无法读取报告 JSON：{exc}") from exc


def _report_fingerprint(path: Path) -> dict[str, Any]:
    try:
        stat = path.stat()
    except OSError as exc:
        raise ReportEditError(f"报告文件不可读取：{path}") from exc
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return {
        "path": str(path.resolve()),
        "size": int(stat.st_size),
        "mtime_ns": str(stat.st_mtime_ns),
        "sha256": digest,
    }


def _iter_report_rows(report: Any) -> Iterable[dict[str, Any]]:
    """Yield rows in the same traversal order used by the Excel exporter."""
    risk_index = 1
    for function_item in report if isinstance(report, list) else []:
        if not isinstance(function_item, dict):
            continue
        function_name = _text(function_item.get("function"))
        for asset in function_item.get("assets", []) or []:
            if not isinstance(asset, dict):
                continue
            for attribute in asset.get("security_attributes", []) or []:
                if not isinstance(attribute, dict):
                    continue
                attacks = [
                    item for item in (attribute.get("attack", []) or [])
                    if isinstance(item, dict)
                ]
                row_attacks: list[dict[str, Any] | None] = attacks or [None]
                for path_index, attack in enumerate(row_attacks, start=1):
                    target = attack if attack is not None else attribute
                    risk_id = f"R{risk_index:03d}"
                    yield {
                        "risk_id": risk_id,
                        "function": function_name,
                        "element_index": _text(asset.get("element_index")),
                        "asset": _text(asset.get("asset_name")),
                        "asset_type": _text(asset.get("asset_type")),
                        "security_attribute": _text(attribute.get("attribute_name")),
                        "damage_scenario": _text(attribute.get("damage_scenario")),
                        "threat_scenario": _text(attribute.get("threat_scenarios")),
                        "path_index": path_index if attack is not None else None,
                        "path_id": _text(
                            ((attack or {}).get("topology_trace") or {}).get("path_id")
                            or (attack or {}).get("path_id")
                        ),
                        "attack_path": _text((attack or {}).get("attack_path")),
                        "impact_level": _text(attribute.get("impact_level")),
                        "feasibility_level": _text((attack or {}).get("feasibility_level")),
                        "risk_value": _text(
                            (attack or {}).get("risk_value", attribute.get("task_risk_value"))
                        ),
                        "risk_treatment": _text(
                            target.get("risk_treatment")
                            or attribute.get("task_risk_treatment")
                        ),
                        "cybersecurity_goal": _text(target.get("cybersecurity_goal")),
                        "security_requirement": _text(target.get("security_requirement")),
                        "national_standard_code": _text(target.get("national_standard_code")),
                        "annex5_partbc_mapping": _text(target.get("annex5_partbc_mapping")),
                        "cybersecurity_claim": _text(target.get("cybersecurity_claim")),
                        "_attribute": attribute,
                        "_attack": attack,
                    }
                    risk_index += 1


def report_row_catalog(report: Any) -> list[dict[str, Any]]:
    """Return serialisable report rows with stable risk IDs."""
    return [
        {key: value for key, value in row.items() if not key.startswith("_")}
        for row in _iter_report_rows(report)
    ]


def _compact_row(row: dict[str, Any]) -> dict[str, Any]:
    compact = dict(row)
    truncated = []
    for key, value in list(compact.items()):
        if isinstance(value, str) and len(value) > 420:
            compact[key] = value[:417] + "..."
            truncated.append(key)
    if truncated:
        compact["truncated_fields"] = truncated
    return compact


def _search_report(catalog: list[dict[str, Any]], query: str, limit: int) -> list[dict[str, Any]]:
    terms = [item.casefold() for item in re.split(r"\s+", _text(query)) if item]
    matches = []
    for row in catalog:
        searchable = " ".join(_text(value) for value in row.values()).casefold()
        if terms and not all(term in searchable for term in terms):
            continue
        matches.append(_compact_row(row))
        if len(matches) >= limit:
            break
    return matches


def _search_requirements(query: str, limit: int) -> dict[str, Any]:
    terms = [item.casefold() for item in re.split(r"\s+", _text(query)) if item]
    fields = (
        "安全需求编码", "名称", "一级分类", "安全需求", "要求", "国标法规编码",
        "适用类别", "信号类别", "协议", "数据种类", "安全属性", "适用的外部接口",
        "适用的操作系统", "概念映射", "附录5PartBC映射",
    )
    matches: list[dict[str, str]] = []
    for row in load_security_requirements():
        searchable = " ".join(_text(row.get(field)) for field in fields).casefold()
        if terms and not all(term in searchable for term in terms):
            continue
        matches.append({field: _text(row.get(field)) for field in fields})
        if len(matches) >= limit:
            break
    return {
        "matches": matches,
        "matching_logic_excerpt": load_security_requirement_matching_logic()[:2400],
    }


def _execute_tools(
    calls: list[dict[str, Any]],
    catalog: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    by_id = {row["risk_id"]: row for row in catalog}
    for call in calls[:6]:
        if not isinstance(call, dict):
            continue
        name = _text(call.get("name"))
        arguments = call.get("arguments")
        arguments = arguments if isinstance(arguments, dict) else {}
        if name not in _ALLOWED_TOOLS:
            results.append({"tool": name, "error": "工具不在白名单"})
            continue
        try:
            limit = max(1, min(10, int(arguments.get("limit", 5) or 5)))
        except (TypeError, ValueError):
            limit = 5
        if name == "search_report":
            result: Any = _search_report(catalog, _text(arguments.get("query")), limit)
        elif name == "get_report_rows":
            wanted = arguments.get("risk_ids")
            wanted = wanted if isinstance(wanted, list) else []
            result = [by_id[_text(item).upper()] for item in wanted[:limit]
                      if _text(item).upper() in by_id]
        elif name == "report_statistics":
            result = {
                "rows": len(catalog),
                "functions": len({row["function"] for row in catalog}),
                "assets": len({(row["function"], row["element_index"], row["asset"]) for row in catalog}),
                "risk_treatment": dict(Counter(row["risk_treatment"] or "未设置" for row in catalog)),
                "risk_value": dict(Counter(row["risk_value"] or "未评级" for row in catalog)),
            }
        else:
            result = _search_requirements(_text(arguments.get("query")), limit)
        results.append({"tool": name, "arguments": arguments, "result": result})
    return results


def _chat_endpoint(api_base: str) -> str:
    try:
        return api_endpoint(_text(api_base), "chat/completions")
    except ValueError as exc:
        raise ReportEditError(f"LLM API Base 无效：{exc}") from exc


def _urlopen(req: urlrequest.Request, timeout: float):
    host = (urlparse(req.full_url).hostname or "").casefold()
    if host in {"localhost", "127.0.0.1", "::1"} and urlrequest.urlopen is _DEFAULT_URLOPEN:
        return urlrequest.build_opener(urlrequest.ProxyHandler({})).open(req, timeout=timeout)
    return urlrequest.urlopen(req, timeout=timeout)


def _fit_report_prompt(prompt: str, context_limit: int, output_tokens: int, reserve: int = 512) -> str:
    """Reduce complete evidence rows, keeping the request and valid JSON intact."""
    try:
        data = json.loads(prompt)
    except (ValueError, TypeError):
        return fit_user_prompt_to_context(
            REPORT_EDITOR_SYSTEM_PROMPT, prompt, context_limit=context_limit,
            output_tokens=output_tokens, context_reserve=reserve,
        )
    if not isinstance(data, dict):
        raise ReportEditError("报告 Agent 上下文必须为对象")
    while True:
        rendered = json.dumps(data, ensure_ascii=False)
        if estimate_prompt_tokens(REPORT_EDITOR_SYSTEM_PROMPT, rendered) + output_tokens + reserve <= context_limit:
            return rendered
        collections = []
        overview = data.get("report", {})
        if isinstance(overview, dict) and overview.get("sample_rows"):
            collections.append(overview["sample_rows"])
        for evidence in data.get("tool_results", []):
            result = evidence.get("result")
            rows = result.get("matches") if isinstance(result, dict) else result
            if isinstance(rows, list) and rows:
                collections.append(rows)
        if not collections:
            if len(data.get("tool_results", [])) > 1:
                data["tool_results"].pop(0)
                continue
            raise ReportEditError("当前任务文字或单条证据超过模型上下文容量，请缩小本轮修改范围")
        max(collections, key=lambda items: len(json.dumps(items, ensure_ascii=False))).pop()
        data["context_notice"] = "部分证据行因上下文容量被省略；只能修改当前可见的行，缺少证据请继续按风险ID检索。"


def _call_model(
    *, model: str, api_base: str, api_key: str, user_prompt: str,
) -> dict[str, Any]:
    if not _text(model):
        raise ReportEditError("未发现可用模型")
    endpoint = _chat_endpoint(api_base)
    try:
        context_limit = max(2048, int(os.getenv("TARA_VLLM_MAX_MODEL_LEN", "8192")))
    except (TypeError, ValueError):
        context_limit = 8192
    requested_tokens = min(1792, max(768, context_limit // 4))
    fitted_prompt = _fit_report_prompt(user_prompt, context_limit, requested_tokens)
    effective_tokens = clamp_output_tokens_to_context(
        requested_tokens,
        context_limit=context_limit,
        system_prompt=REPORT_EDITOR_SYSTEM_PROMPT,
        user_prompt=fitted_prompt,
        context_reserve=512,
    )

    def post(
        response_format: dict[str, Any] | None,
        *,
        max_tokens: int = effective_tokens,
        include_template_kwargs: bool = False,
    ) -> bytes:
        payload = build_chat_payload(
            model=model,
            system_prompt=REPORT_EDITOR_SYSTEM_PROMPT,
            user_prompt=fitted_prompt,
            temperature=0.0,
            max_tokens=max_tokens,
            enable_thinking=False,
            response_format=response_format,
        )
        if not include_template_kwargs:
            payload.pop("chat_template_kwargs", None)
        req = urlrequest.Request(
            endpoint,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {_text(api_key) or os.getenv('TARA_API_KEY', 'EMPTY')}",
            },
            method="POST",
        )
        try:
            with _urlopen(req, 180) as response:
                return response.read()
        except HTTPError as exc:
            try:
                detail = exc.read().decode("utf-8", errors="replace")[:1000]
            except Exception:
                detail = str(exc)
            secret = _text(api_key) or os.getenv("TARA_API_KEY", "")
            if secret:
                detail = detail.replace(secret, "[已隐藏]")
            raise _ReportHTTPError(exc.code, detail) from exc
        except Exception as exc:
            raise ReportEditError(f"无法调用模型服务：{exc}") from exc

    response_format: dict[str, Any] | None = {"type": "json_object"}
    local_template = (urlparse(endpoint).hostname or "").casefold() in {"localhost", "127.0.0.1", "::1"}
    parse_retries = 0
    for attempt in range(4):
        try:
            raw = post(response_format, max_tokens=effective_tokens, include_template_kwargs=local_template)
        except _ReportHTTPError as first_error:
            if first_error.status in {429, 502, 503, 504} and attempt == 0:
                continue
            if first_error.status not in {400, 422} or attempt >= 3:
                raise
            detail_lower = first_error.detail.casefold()
            context_rejection = any(
                marker in detail_lower
                for marker in ("maximum context", "context length", "input_tokens", "prompt too long")
            )
            if context_rejection:
                limit_match = re.search(r"maximum context length is\s+(\d+)", detail_lower)
                input_match = re.search(r"at least\s+(\d+)\s+input tokens", detail_lower)
                exact_limit = int(limit_match.group(1)) if limit_match else context_limit
                exact_input = int(input_match.group(1)) if input_match else 0
                exact_budget = exact_limit - exact_input - 384 if exact_input else effective_tokens // 2
                if exact_budget < 128:
                    gap = max(0, exact_input - estimate_prompt_tokens(REPORT_EDITOR_SYSTEM_PROMPT, fitted_prompt))
                    context_limit = min(context_limit, exact_limit) - gap - 128
                    fitted_prompt = _fit_report_prompt(user_prompt, context_limit, min(1024, requested_tokens))
                    effective_tokens = clamp_output_tokens_to_context(
                        min(1024, requested_tokens), context_limit=context_limit,
                        system_prompt=REPORT_EDITOR_SYSTEM_PROMPT, user_prompt=fitted_prompt, context_reserve=512,
                    )
                else:
                    effective_tokens = max(128, min(effective_tokens, exact_budget))
            else:
                if response_format is None and not local_template:
                    raise
                response_format = None
                local_template = False
            continue
        try:
            payload = json.loads(raw.decode("utf-8"))
            contents = extract_choice_contents(payload)
            if not contents:
                raise ValueError("模型没有返回内容")
            result = safe_parse_json(contents[0])
            if not isinstance(result, dict):
                raise ValueError("Agent 决策必须是 JSON 对象")
            return result
        except (ValueError, TypeError, KeyError, IndexError) as exc:
            if parse_retries or attempt >= 3:
                raise ReportEditError("模型决策 JSON 不完整，已重试一次；请减少本轮修改行数后重试") from exc
            parse_retries += 1
            effective_tokens = min(3072, max(1792, context_limit // 3))
            fitted_prompt = _fit_report_prompt(user_prompt, context_limit, effective_tokens)
    raise ReportEditError("模型服务多次拒绝请求，请检查服务状态后重试")


def _normalise_decision(value: dict[str, Any]) -> dict[str, Any]:
    decision = _text(value.get("decision")).casefold()
    calls = value.get("tool_calls")
    operations = value.get("operations")
    if decision not in {"tool", "final"} and not calls and not operations and not value.get("answer"):
        raise ReportEditError("模型没有返回回答、工具调用或修改建议，请重试")
    return {
        "decision": decision if decision in {"tool", "final"} else "final",
        "answer": _text(value.get("answer")),
        "tool_calls": calls if isinstance(calls, list) else [],
        "operations": operations if isinstance(operations, list) else [],
    }


def _validate_operations(
    operations: list[Any], catalog: list[dict[str, Any]],
) -> list[dict[str, str]]:
    valid_ids = {row["risk_id"] for row in catalog}
    validated: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    if len(operations) > 50:
        raise ReportEditError("单次最多确认 50 项修改，请分批处理")
    for raw in operations:
        if not isinstance(raw, dict):
            raise ReportEditError("修改操作必须是对象")
        risk_id = _text(raw.get("risk_id")).upper()
        field = _text(raw.get("field"))
        value = _text(raw.get("value"))
        reason = _text(raw.get("reason"))
        if risk_id not in valid_ids:
            raise ReportEditError(f"修改计划引用了不存在的风险行：{risk_id}")
        if field not in EDITABLE_REPORT_FIELDS:
            raise ReportEditError(f"字段不允许直接修改：{field}")
        if field == "risk_treatment" and value.casefold() not in {
            "风险缓解", "risk mitigation", "mitigation",
            "风险接受", "risk acceptance", "acceptance",
        }:
            raise ReportEditError("风险处置只能设置为风险缓解或风险接受")
        if len(value) > 12000:
            raise ReportEditError(f"{risk_id} 的 {field} 内容过长")
        key = (risk_id, field)
        if key in seen:
            raise ReportEditError(f"修改计划重复设置 {risk_id}.{field}")
        seen.add(key)
        validated.append({
            "risk_id": risk_id,
            "field": field,
            "value": value,
            "reason": reason or "用户要求",
        })
    requirement_fields = {
        "security_requirement": "安全需求",
        "national_standard_code": "国标法规编码",
        "annex5_partbc_mapping": "附录5PartBC映射",
    }
    by_risk: dict[str, dict[str, str]] = {}
    for item in validated:
        if item["field"] in requirement_fields and item["value"]:
            by_risk.setdefault(item["risk_id"], {})[item["field"]] = item["value"]
    template_rows = load_security_requirements() if by_risk else ()
    for risk_id, requested in by_risk.items():
        matches = [row for row in template_rows if
            all(
                _text(row.get(requirement_fields[field])) == value
                for field, value in requested.items()
            )
        ]
        if not matches:
            raise ReportEditError(
                f"{risk_id} 的安全需求/法规/附录映射不是模板中的同一权威记录"
            )
        triples = {tuple(_text(row.get(label)) for label in requirement_fields.values()) for row in matches}
        if len(triples) != 1:
            raise ReportEditError(f"{risk_id} 匹配到多条安全需求，请指定需求编码并同时更新需求、法规与附录映射")
        for field, value in zip(requirement_fields, next(iter(triples))):
            if (risk_id, field) not in seen:
                validated.append({"risk_id": risk_id, "field": field, "value": value, "reason": "与所选权威安全需求同步"})
                seen.add((risk_id, field))
    return validated


def prepare_report_edit_plan(
    report_path: str | os.PathLike[str],
    instruction: str,
    *,
    model: str,
    api_base: str,
    api_key: str = "",
    progress: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Use a bounded tool loop, then return a confirmation-bound plan."""
    source = Path(report_path).resolve()
    report = _load_json(source)
    catalog = report_row_catalog(report)
    if not catalog:
        raise ReportEditError("报告没有可修改的风险行")
    request_text = _text(instruction)
    if not request_text:
        raise ReportEditError("请输入报告修改要求")
    fingerprint = _report_fingerprint(source)
    context = {
        "instruction": request_text,
        "report": {"rows": len(catalog), "sample_rows": [_compact_row(row) for row in catalog[:3]]},
        "tool_results": [],
    }
    tool_results: list[dict[str, Any]] = []
    agent_trace: list[dict[str, Any]] = []
    for turn in range(4):
        context["remaining_tool_rounds"] = 3 - turn
        if progress:
            progress(f"Agent 第 {turn + 1}/4 轮：正在理解任务与检索证据")
        final = _normalise_decision(_call_model(
            model=model, api_base=api_base, api_key=api_key,
            user_prompt=json.dumps(context, ensure_ascii=False),
        ))
        agent_trace.append({"phase": "llm_decision", "round": turn + 1, "status": "done", "decision": final["decision"]})
        if final["decision"] != "tool" and not final["tool_calls"]:
            break
        if turn == 3:
            raise ReportEditError("本轮检索尚未完成，请指定风险ID或缩小修改范围后重试")
        if not final["tool_calls"]:
            raise ReportEditError("模型要求检索但没有给出工具参数，请重试")
        results = _execute_tools(final["tool_calls"], catalog)
        tool_results.extend(results)
        agent_trace.extend({"phase": "tool", "round": turn + 1, "status": "done", "tool": item.get("tool"), "arguments": item.get("arguments", {})} for item in results)
        # Retain recent evidence without repeatedly sending the whole report.
        context["tool_results"] = tool_results[-8:]
    operations = _validate_operations(final["operations"], catalog)
    plan_payload = {
        "instruction": request_text,
        "source_report": str(source),
        "source_fingerprint": fingerprint,
        "answer": final["answer"] or ("已生成修改计划" if operations else "未提出修改"),
        "operations": operations,
        "tool_results": tool_results,
        "agent_trace": [
            *agent_trace,
            {"phase": "validate", "status": "done", "operations": len(operations)},
            {"phase": "confirmation", "status": "waiting" if operations else "not_required"},
        ],
        "model": model,
        "created_at": datetime.now().isoformat(timespec="seconds"),
    }
    plan_payload["agent_trace"] = [item for item in plan_payload["agent_trace"] if item]
    plan_payload["plan_id"] = hashlib.sha256(
        json.dumps(plan_payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()[:16]
    return plan_payload


def _manifest_options(source: Path) -> tuple[str, str, ExcelExportOptions]:
    manifest_path = next(
        (
            parent / "run_manifest.json"
            for parent in (source.parent, *source.parents)
            if (parent / "run_manifest.json").is_file()
        ),
        source.parent / "run_manifest.json",
    )
    manifest = _load_json(manifest_path) if manifest_path.is_file() else {}
    configuration = manifest.get("configuration", {}) if isinstance(manifest, dict) else {}
    effective = configuration.get("effective", {}) if isinstance(configuration, dict) else {}
    invocation = configuration.get("invocation", {}) if isinstance(configuration, dict) else {}

    def flag(name: str, default: bool) -> bool:
        value = effective.get(name, default)
        if isinstance(value, bool):
            return value
        return _text(value).casefold() in {"1", "true", "yes", "on"}

    feasibility = _text(invocation.get("feasibility_method") or effective.get("TARA_FEASIBILITY_METHOD")) or "attack_potential"
    impact = _text(invocation.get("impact_method") or effective.get("TARA_IMPACT_METHOD")) or "21434"
    if not manifest:
        first_row = next(iter(_iter_report_rows(_load_json(source))), None)
        if first_row:
            attribute = first_row["_attribute"]
            feasibility = _text(attribute.get("feasibility_method")) or feasibility
            impact = _text(attribute.get("impact_method")) or impact
    options = ExcelExportOptions(
        impact_method=impact,
        enable_reason=flag("TARA_ENABLE_REASON", True),
        enable_consistency=flag("TARA_ENABLE_CONSISTENCY", False),
        enable_r155=flag("TARA_ENABLE_R155", False),
        enable_rag=False,
        enable_asset_details=flag("TARA_ENABLE_ASSET_DETAILS", True),
    )
    return feasibility, impact, options


def apply_report_edit_plan(plan: dict[str, Any]) -> dict[str, Any]:
    """Apply a validated plan to a new report revision and regenerate Excel."""
    if not isinstance(plan, dict) or not plan.get("plan_id"):
        raise ReportEditError("没有待确认的报告修改计划")
    source = Path(_text(plan.get("source_report"))).resolve()
    expected = plan.get("source_fingerprint")
    if not isinstance(expected, dict) or _report_fingerprint(source) != expected:
        raise ReportEditError("原报告在计划生成后已变化，请重新生成修改计划")
    report = copy.deepcopy(_load_json(source))
    rows = {row["risk_id"]: row for row in _iter_report_rows(report)}
    operations = _validate_operations(plan.get("operations", []), report_row_catalog(report))
    if not operations:
        raise ReportEditError("修改计划没有可应用的操作")

    applied: list[dict[str, str]] = []
    ordered_operations = sorted(
        enumerate(operations),
        key=lambda item: (item[1]["field"] != "risk_treatment", item[0]),
    )
    for _, operation in ordered_operations:
        row = rows[operation["risk_id"]]
        field = operation["field"]
        if field in _ATTRIBUTE_FIELDS:
            row["_attribute"][_ATTRIBUTE_FIELDS[field]] = operation["value"]
        else:
            target = row["_attack"] if row["_attack"] is not None else row["_attribute"]
            if field == "attack_path" and row["_attack"] is None:
                raise ReportEditError(f"{operation['risk_id']} 没有攻击路径，不能设置 attack_path")
            target[_ROW_FIELDS[field]] = operation["value"]
            if field == "risk_treatment" and row["_attack"] is None:
                target["task_risk_treatment"] = operation["value"]
            if field == "risk_treatment":
                target.update(cybersecurity_fields_for_treatment(
                    risk_treatment=operation["value"],
                    asset_name=row["asset"],
                    attribute_name=row["security_attribute"],
                    threat_type=_text(row["_attribute"].get("threat_type")),
                    function_name=row["function"],
                ))
                if operation["value"].casefold() not in {
                    "风险缓解", "risk mitigation", "mitigation"
                }:
                    for key in (
                        "security_requirement", "national_standard_code", "annex5_partbc_mapping"
                    ):
                        target[key] = ""
                    target["security_requirements"] = []
        applied.append(dict(operation))

    revision_id = datetime.now().strftime("%Y%m%d-%H%M%S-%f") + "-" + uuid.uuid4().hex[:6]
    revision_root = source.parent / "report_revisions" / revision_id
    revision_root.mkdir(parents=True, exist_ok=False)
    json_path = revision_root / f"{source.stem}-revised.json"
    temp_json = revision_root / f".{json_path.name}.tmp"
    with temp_json.open("w", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    os.replace(temp_json, json_path)

    feasibility, impact, options = _manifest_options(source)
    excel_path = revision_root / f"{source.stem}-revised.xlsx"
    export_tara_report_to_excel(
        str(json_path),
        str(excel_path),
        options=options,
    )
    revision_manifest = {
        "schema_version": "tara-report-revision-v1",
        "revision_id": revision_id,
        "source_report": str(source),
        "source_fingerprint": plan["source_fingerprint"],
        "plan_id": plan["plan_id"],
        "instruction": plan.get("instruction", ""),
        "model": plan.get("model", ""),
        "feasibility_method": feasibility,
        "impact_method": impact,
        "operations": applied,
        "outputs": {"json": str(json_path), "xlsx": str(excel_path)},
        "created_at": datetime.now().isoformat(timespec="seconds"),
    }
    manifest_out = revision_root / "revision_manifest.json"
    with manifest_out.open("w", encoding="utf-8") as stream:
        json.dump(revision_manifest, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    return {
        "report": report,
        "json_path": str(json_path),
        "excel_path": str(excel_path),
        "manifest_path": str(manifest_out),
        "revision_manifest": revision_manifest,
    }
