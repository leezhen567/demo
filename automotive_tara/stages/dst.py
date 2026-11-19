"""Generated stage implementation; all mutable runtime dependencies enter via ctx."""

from __future__ import annotations

import hashlib
import logging
import re
import time
from collections import Counter
from concurrent.futures import as_completed
from functools import partial
from typing import Any, Callable

import orjson

from automotive_tara.domain import (
    AP_ALLOWED_VALUES, ATTACK_VECTOR_SCORE, CVSS_C, CVSS_P, CVSS_U,
    HEAVENS_AP_ALLOWED_VALUES, OPPORTUNITY_WINDOW_MAP,
    HEAVENS_TL_TO_FEASIBILITY as _HEAVENS_TL_TO_FEASIBILITY,
    HEAVENS_WINDOW_BY_VECTOR as _HEAVENS_WINDOW_BY_VECTOR,
    STATUS_MODEL_FAILED, STATUS_NOT_APPLICABLE, STATUS_VALID, TaskUnit,
    calculate_attack_potential_level, calculate_attack_potential_score,
    calculate_attack_vector_level, calculate_cvss_level, calculate_cvss_score,
    calculate_heavens_ap_level, calculate_heavens_ap_score,
    calculate_heavens_risk_value, calculate_risk_value, get_risk_treatment,
    normalize_attack_vector, safe_int as _safe_int,
)
from automotive_tara.json_utils import canonical_task_id as _canonical_task_id, safe_parse_json
from automotive_tara.llm import strict_array_response_format
from automotive_tara.prompts import (
    AP_BATCH_SYSTEM_PROMPT, ATTACK_ENTRY_SYSTEM_PROMPT,
    ATTACK_TARGET_SYSTEM_PROMPT, CVSS_BATCH_SYSTEM_PROMPT,
    DST_BATCH_SYSTEM_PROMPT, HEAVENS_AP_BATCH_SYSTEM_PROMPT,
    IMPACT_BATCH_SYSTEM_PROMPT, IMPACT_REASON_SYSTEM_PROMPT,
    IMPACT_SYSTEM_PROMPT,
)
from automotive_tara.reason_policy import (
    AP_REASON_KEYS, CVSS_REASON_KEYS, HEAVENS_REASON_KEYS, IMPACT_REASON_KEYS,
    RATING_REASON_MAX_CHARS, reason_fields_valid,
)
from automotive_tara.runtime import RuntimeContext
from automotive_tara.cache_dependencies import knowledge_entries, record_result, scenario_output, stage_key
from automotive_tara.model_gateway import ModelRequestRejected
from automotive_tara.token_budget import PromptContextOverflow
from automotive_tara.topology import (
    determine_attack_vector as _determine_attack_vector,
    external_interface_key as _external_interface_key,
    limit_shortest_frameworks, normalize_text as _normalize_text,
    same_external_interface as _same_external_interface,
    same_protocol as _same_protocol,
)

logger = logging.getLogger(__name__)

_DST_CAPABILITY_GUARD_ERROR = "DST能力断言与资产证据冲突"
_DST_NO_CAPABILITY_MARKERS = {
    "不可抵赖性": (
        ("无日志记录能力", "不产生可感知的损害"),
        ("无审计能力", "不产生可感知的损害"),
    ),
    "权限属性": (
        ("无操作系统级权限机制", "不产生可感知的损害"),
        ("不存在操作系统级权限机制", "不产生可感知的损害"),
    ),
}

def _validate_dst_capability_assertion(ctx: RuntimeContext, task: TaskUnit) -> bool:
    """拦截模型凭资产名称臆断日志/权限能力缺失的结果。

    确定性规则已识别出的纯传感/执行部件会转为 NOT_APPLICABLE；
    其余资产出现“无能力、无损害”模板时视为模型错误，清空结果以触发重试。
    """
    task.errors = [error for error in task.errors if error not in {'damage_scenario为空', 'threat_scenarios为空'} and (not error.startswith(_DST_CAPABILITY_GUARD_ERROR))]
    markers = _DST_NO_CAPABILITY_MARKERS.get(task.attribute_name, ())
    if not any((absence_marker in task.damage_scenario and no_damage_marker in task.damage_scenario for (absence_marker, no_damage_marker) in markers)):
        return True
    (applicable, reason) = ctx.service('_attribute_applicability')(task.asset_type, task.asset_name, task.asset_details, task.attribute_name)
    if not applicable:
        task.analysis_status = STATUS_NOT_APPLICABLE
        task.status_reasons = [reason]
        task.influence_parameters = {}
        task.attack_paths = []
        task.selected_path_frameworks = []
        task.attack_details = []
        task.risk_value = None
        task.risk_treatment = '不适用'
        return True
    task.damage_scenario = ''
    task.threat_scenarios = ''
    task.r155_references = []
    task.errors.append(f'{_DST_CAPABILITY_GUARD_ERROR}: {task.asset_name} 未提供能力缺失证据，已拒绝模板化无损害结果')
    return False

def _dst_response_format(ctx: RuntimeContext, ids: list[str]) -> dict:
    return strict_array_response_format(schema_name='tara_damage_threat_batch', array_name='items', count=len(ids), item_properties={'id': {'type': 'string', 'enum': ids}, 'd': {'type': 'string'}, 't': {'type': 'string'}}, required=['id', 'd', 't'])

def _parse_dst_short_result(ctx: RuntimeContext, raw: str, batch: list[TaskUnit]) -> list[dict]:
    """解析局部 D1..Dn，并安全恢复为调用方任务顺序。"""
    empty = [{'damage_scenario': '', 'threat_scenarios': ''} for _ in batch]
    try:
        parsed = safe_parse_json(raw)
    except Exception:
        return empty
    items = parsed.get('items', []) if isinstance(parsed, dict) else parsed
    if not isinstance(items, list):
        return empty
    expected = [f'D{index}' for index in range(1, len(batch) + 1)]
    by_id: dict[str, dict] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        item_id = str(item.get('id', '')).strip()
        if item_id in expected and item_id not in by_id:
            by_id[item_id] = {'damage_scenario': str(item.get('d', item.get('damage_scenario', ''))).strip(), 'threat_scenarios': str(item.get('t', item.get('threat_scenarios', ''))).strip()}
    if by_id:
        return [by_id.get(item_id, empty[index]) for (index, item_id) in enumerate(expected)]
    return _parse_dst_result(ctx, raw, batch)

def _dst_item_cache_key(ctx: RuntimeContext, task: TaskUnit, rag_ds: str, rag_ts: str) -> dict:
    system_prompt = ctx.setting('DST_BATCH_SYSTEM_PROMPT', DST_BATCH_SYSTEM_PROMPT)
    return stage_key(ctx, task, 'scenarios', system_prompt, knowledge={
        'damage': knowledge_entries(rag_ds), 'threat': knowledge_entries(rag_ts),
    })

def _dst_prompt(
    ctx: RuntimeContext,
    batch: list[TaskUnit],
    rag_ds: str,
    rag_ts: str,
    *,
    retry: bool,
    retry_reasons: dict[str, str] | None = None,
    detail_chars: int | None = None,
) -> str:
    """构造 DST 请求；重试时把可执行的失败原因随局部任务发送给模型。"""
    items = []
    enable_asset_details = ctx.setting('ENABLE_ASSET_DETAILS', True)
    retry_reasons = retry_reasons or {}
    for (index, task) in enumerate(batch, start=1):
        item = {'id': f'D{index}', 'function': task.function, 'asset_type': task.asset_type, 'asset_name': task.asset_name, 'attribute_name': task.attribute_name, 'threat_type': task.threat_type}
        if enable_asset_details:
            details = str(task.asset_details or '（无）')
            item['asset_details'] = (
                details[:detail_chars] if detail_chars is not None else details
            )
        item['source'] = task.source or '（无）'
        item['target'] = task.target or '（无）'
        if retry:
            item['retry_reason'] = retry_reasons.get(
                task.task_id,
                '上次结果缺少必需字段或未通过语义约束，请完整重新生成。',
            )
        items.append(item)
    instruction = (
        '前一次只有这些任务缺失或不合格；只重新生成本次输入。'
        '请阅读每项 retry_reason，修复指出的问题，不要复述该字段；'
        if retry
        else ''
    )
    return f"{instruction}请为以下 {len(items)} 个资产分别生成损害场景和威胁场景。\n损害场景参考知识（RAG）:\n{rag_ds}\n\n威胁场景参考知识（RAG）:\n{rag_ts}\n\n任务：{orjson.dumps(items).decode('utf-8')}\n仅返回JSON对象；items中每项使用输入的局部id，d和t必须为非空字符串。"


def _dst_retry_reason(task: TaskUnit) -> str:
    """将内部校验结果压缩成模型可执行的纠错指令。"""
    reasons: list[str] = []
    if not str(task.damage_scenario or '').strip():
        reasons.append('damage_scenario 为空')
    if not str(task.threat_scenarios or '').strip():
        reasons.append('threat_scenarios 为空')
    for error in task.errors:
        if str(error).startswith(_DST_CAPABILITY_GUARD_ERROR):
            reasons.append(
                '模型臆断资产无日志/审计能力，但输入没有能力缺失证据；'
                '默认按具备相应能力生成不可抵赖性场景'
            )
    return '；'.join(dict.fromkeys(reasons))[:420] or (
        '上次结果未通过 DST 字段或语义约束，请重新生成非空且与安全属性匹配的结果'
    )

def _call_dst_subset(
    ctx: RuntimeContext,
    batch: list[TaskUnit],
    rag_ds: str,
    rag_ts: str,
    *,
    retry: bool = False,
    retry_reasons: dict[str, str] | None = None,
) -> list[dict]:
    if not batch:
        return []
    ids = [f'D{index}' for index in range(1, len(batch) + 1)]
    user_prompt = _dst_prompt(
        ctx,
        batch,
        rag_ds,
        rag_ts,
        retry=retry,
        retry_reasons=retry_reasons,
    )
    system_prompt = ctx.setting('DST_BATCH_SYSTEM_PROMPT', DST_BATCH_SYSTEM_PROMPT)
    try:
        dst_tokens = ctx.service('_dynamic_token_budget')('dst', len(batch), include_reasons=False, system_prompt=system_prompt, user_prompt=user_prompt, record=True)
    except PromptContextOverflow:
        ctx.service('_increment_pipeline_metric')('dst_context_overflows')
        if len(batch) > 1:
            midpoint = len(batch) // 2
            ctx.service('_increment_pipeline_metric')('dst_context_split_calls', 2)
            return (
                _call_dst_subset(ctx, batch[:midpoint], rag_ds, rag_ts,
                                 retry=retry, retry_reasons=retry_reasons)
                + _call_dst_subset(ctx, batch[midpoint:], rag_ds, rag_ts,
                                   retry=retry, retry_reasons=retry_reasons)
            )
        for limit in (280, 120, 40):
            user_prompt = _dst_prompt(
                ctx, batch, rag_ds[:limit], rag_ts[:limit],
                retry=retry, retry_reasons=retry_reasons,
                detail_chars=limit,
            )
            try:
                dst_tokens = ctx.service('_dynamic_token_budget')(
                    'dst', 1, include_reasons=False,
                    system_prompt=system_prompt, user_prompt=user_prompt, record=True,
                )
                ctx.service('_increment_pipeline_metric')('dst_context_compressions')
                break
            except PromptContextOverflow:
                continue
        else:
            batch[0].errors.append('dst_context_overflow')
            return [{}]
    ctx.service('_increment_pipeline_metric')('dst_model_calls')
    if retry:
        ctx.service('_increment_pipeline_metric')('dst_subset_retry_calls')
    try:
        raw = ctx.service('llm_call_with_semaphore')(
            system_prompt, user_prompt, max_tokens=dst_tokens,
            response_format=_dst_response_format(ctx, ids),
            raise_on_rejection=True,
        )
    except ModelRequestRejected as exc:
        ctx.service('_increment_pipeline_metric')('dst_service_rejections')
        for task in batch:
            task.errors.append(f'dst_service_rejected:{exc}')
        return [{} for _ in batch]
    if not isinstance(raw, str) or not raw.strip() or raw.strip() == '{}':
        ctx.service('_increment_pipeline_metric')('dst_empty_responses')
        for task in batch:
            task.errors.append('dst_empty_response')
    else:
        try:
            safe_parse_json(raw)
        except Exception:
            ctx.service('_increment_pipeline_metric')('dst_parse_failures')
            for task in batch:
                task.errors.append('dst_parse_failure')
    return _parse_dst_short_result(ctx, raw, batch)

def _apply_dst_item(ctx: RuntimeContext, task: TaskUnit, item: dict) -> bool:
    task.damage_scenario = str(item.get('damage_scenario', '')).strip()
    task.threat_scenarios = str(item.get('threat_scenarios', '')).strip()
    task.r155_references = ctx.shared('rag_kb').match_r155(task.threat_scenarios) if ctx.shared('rag_kb') else []
    if not task.damage_scenario or not task.threat_scenarios:
        return False
    return _validate_dst_capability_assertion(ctx, task)

def _retry_dst_capability_conflict(ctx: RuntimeContext, task: TaskUnit, rag_ds: str, rag_ts: str) -> bool:
    """针对能力断言冲突仅重试该项，不重复整批成功结果。"""
    corrective_system = ctx.setting('DST_BATCH_SYSTEM_PROMPT', DST_BATCH_SYSTEM_PROMPT) + '\n前一次错误断言资产无日志、审计或权限能力。输入没有能力缺失证据，禁止再次输出“无能力、不产生可感知损害”；按具备相应能力重新生成。'
    ids = ['D1']
    ctx.service('_increment_pipeline_metric')('dst_model_calls')
    ctx.service('_increment_pipeline_metric')('dst_capability_retry_calls')
    user_prompt = _dst_prompt(
        ctx,
        [task],
        rag_ds,
        rag_ts,
        retry=True,
        retry_reasons={task.task_id: _dst_retry_reason(task)},
    )
    dst_tokens = ctx.service('_dynamic_token_budget')('dst', 1, include_reasons=False, system_prompt=corrective_system, user_prompt=user_prompt, record=True)
    raw = ctx.service('llm_call_with_semaphore')(corrective_system, user_prompt, max_tokens=dst_tokens, response_format=_dst_response_format(ctx, ids))
    parsed = _parse_dst_short_result(ctx, raw, [task])
    return bool(parsed) and _apply_dst_item(ctx, task, parsed[0])

def _exec_dst_batch(ctx: RuntimeContext, batch: list[TaskUnit], rag_ds: str, rag_ts: str) -> None:
    _exec_dst_batch_impl(ctx, batch, rag_ds, rag_ts)
    for task in batch:
        if task.damage_scenario and task.threat_scenarios and task.analysis_status != STATUS_NOT_APPLICABLE:
            record_result(task, 'scenarios', _dst_item_cache_key(ctx, task, rag_ds, rag_ts), scenario_output(task))


def _exec_dst_batch_impl(ctx: RuntimeContext, batch: list[TaskUnit], rag_ds: str, rag_ts: str) -> None:
    """逐项缓存、局部短ID批量生成，并只重试失败子集一次。"""
    if not batch:
        return
    missing: list[TaskUnit] = []
    cache_keys: dict[str, dict] = {}
    for task in batch:
        cache_key = _dst_item_cache_key(ctx, task, rag_ds, rag_ts)
        cache_keys[task.task_id] = cache_key
        cached = ctx.shared('semantic_cache').get('damage_threat_item', cache_key)
        if isinstance(cached, dict) and _apply_dst_item(ctx, task, cached):
            continue
        if cached is not None:
            ctx.shared('semantic_cache').delete('damage_threat_item', cache_key)
        missing.append(task)
    if not missing:
        return
    parsed = _call_dst_subset(ctx, missing, rag_ds, rag_ts)
    failed: list[TaskUnit] = []
    failed_reasons: dict[str, str] = {}
    for (task, item) in zip(missing, parsed):
        if _apply_dst_item(ctx, task, item):
            ctx.shared('semantic_cache').set('damage_threat_item', cache_keys[task.task_id], item)
        elif task.analysis_status != STATUS_NOT_APPLICABLE:
            failed.append(task)
            failed_reasons[task.task_id] = _dst_retry_reason(task)
    if failed:
        logger.warning('DST batch %d 个中 %d 个缺失或不合格，仅重试失败子集一次 （group=%s|%s）', len(missing), len(failed), batch[0].asset_type, batch[0].attribute_name)
        retry_results = _call_dst_subset(
            ctx,
            failed,
            rag_ds,
            rag_ts,
            retry=True,
            retry_reasons=failed_reasons,
        )
        for (task, item) in zip(failed, retry_results):
            valid = _apply_dst_item(ctx, task, item)
            if not valid and any((error.startswith(_DST_CAPABILITY_GUARD_ERROR) for error in task.errors)):
                valid = _retry_dst_capability_conflict(ctx, task, rag_ds, rag_ts)
            if valid:
                ctx.shared('semantic_cache').set('damage_threat_item', cache_keys[task.task_id], {'damage_scenario': task.damage_scenario, 'threat_scenarios': task.threat_scenarios})
    for task in batch:
        task.errors = [error for error in task.errors if error not in {'damage_scenario为空', 'threat_scenarios为空'}]
        if task.analysis_status == STATUS_NOT_APPLICABLE:
            continue
        if not task.damage_scenario:
            task.errors.append('damage_scenario为空')
        if not task.threat_scenarios:
            task.errors.append('threat_scenarios为空')

def _parse_dst_result(ctx: RuntimeContext, raw: str, batch: list) -> list[dict]:
    """解析 DST LLM 返回值，统一输出 list[dict] 格式。

    优先按 task_id 对齐；旧格式只有在返回数量与 batch 完全相等时才允许
    按位置兼容。单条结果绝不复制给整个 batch。
    """
    try:
        parsed = safe_parse_json(raw)
        if isinstance(parsed, dict):
            parsed = [parsed]
    except Exception:
        parsed = None
    empty = [{'task_id': t.task_id, 'damage_scenario': '', 'threat_scenarios': ''} for t in batch]
    if not isinstance(parsed, list):
        return empty
    dict_items = [item for item in parsed if isinstance(item, dict)]
    expected = {t.task_id for t in batch}
    has_ids = any((str(item.get('task_id', '')).strip() for item in dict_items))
    if has_ids:
        id_items: dict[str, dict] = {}
        duplicate_ids: set[str] = set()
        for item in dict_items:
            task_id = _canonical_task_id(item.get('task_id'), expected)
            if not task_id:
                continue
            if task_id in id_items:
                duplicate_ids.add(task_id)
                continue
            id_items[task_id] = item
        for task_id in duplicate_ids:
            id_items.pop(task_id, None)
        return [dict(id_items.get(t.task_id, empty[i]), task_id=t.task_id) for (i, t) in enumerate(batch)]
    if len(dict_items) == len(batch):
        return [dict(item, task_id=t.task_id) for (item, t) in zip(dict_items, batch)]
    return empty
