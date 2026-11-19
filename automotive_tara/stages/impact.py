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
from automotive_tara.impact_format import build_impact_batch_user_prompt, build_impact_single_user_prompt
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
    reason_fields_valid, sanitize_reason_fields,
)
from automotive_tara.runtime import RuntimeContext
from automotive_tara.cache_dependencies import scenario_reference, stage_key, record_result
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
_DST_NO_CAPABILITY_MARKERS = (
    "无日志记录能力", "无日志能力", "不具备日志", "没有日志",
    "无操作系统级权限机制", "无权限机制", "不具备权限", "没有权限",
)


def _clear_recovered_impact_failures(task: TaskUnit) -> None:
    """评级重试成功后移除只描述旧失败状态的诊断信息。"""
    task.errors = [
        error for error in task.errors
        if not str(error).startswith('影响评级')
    ]
    task.status_reasons = [
        reason for reason in task.status_reasons
        if not str(reason).startswith('影响评级')
    ]

def generate_influence_parameters(
    ctx: RuntimeContext,
    task: TaskUnit,
    *,
    repair: bool = False,
) -> dict:
    def build_prompt(damage: str, details: str) -> str:
        prompt = build_impact_single_user_prompt(
            task, damage_scenario=damage, asset_details=details
        )
        if repair:
            prompt += (
                '\n这是单项补救请求。上一次批量结果未被接受；请重新独立评估，'
                '严格返回四个分值及对应的非空简短理由，不要复用其它任务的 task_id 或内容。'
            )
        return prompt

    user_prompt = build_prompt(
        str(task.damage_scenario), str(task.asset_details)
    )
    cache_key = {
        'function': task.function, 'asset_name': task.asset_name,
        'asset_type': task.asset_type, 'attribute_name': task.attribute_name,
        'threat_type': task.threat_type, 'asset_details': task.asset_details,
        'damage_scenario': task.damage_scenario, 'source': task.source,
        'target': task.target, 'flow_protocol': task.flow_protocol,
    }
    cache_key['request_mode'] = 'repair' if repair else 'single'

    def _extract_params(value: Any) -> dict:
        """兼容单项旧结构和批量 Schema 的 ``items`` 外层。"""
        if not isinstance(value, dict):
            return {}
        params = value.get('influence_parameters')
        if isinstance(params, dict):
            return params
        items = value.get('items')
        if isinstance(items, list) and len(items) == 1 and isinstance(items[0], dict):
            params = items[0].get('influence_parameters')
            if isinstance(params, dict):
                return params
        return {}

    def _valid_impact_response(value: Any) -> bool:
        if not isinstance(value, dict):
            return False
        params = _extract_params(value)
        return isinstance(params, dict) and all((1 <= _safe_int(params.get(key), default=-1) <= 4 for key in ('Safety', 'Finance', 'Operation', 'Privacy'))) and sanitize_reason_fields(params, IMPACT_REASON_KEYS, enabled=ctx.setting('ENABLE_REASON')) is not None
    system_prompt = ctx.setting('IMPACT_SYSTEM_PROMPT', IMPACT_SYSTEM_PROMPT)
    try:
        impact_tokens = ctx.service('_dynamic_token_budget')(
            'impact_single', 1, system_prompt=system_prompt,
            user_prompt=user_prompt, record=True,
        )
    except PromptContextOverflow:
        for limit in (480, 240, 120):
            user_prompt = build_prompt(
                str(task.damage_scenario)[:limit],
                str(task.asset_details)[:limit],
            )
            try:
                impact_tokens = ctx.service('_dynamic_token_budget')(
                    'impact_single', 1, system_prompt=system_prompt,
                    user_prompt=user_prompt, record=True,
                )
                ctx.service('_increment_pipeline_metric')(
                    'impact_context_compressions'
                )
                break
            except PromptContextOverflow:
                continue
        else:
            task.errors.append('impact_context_overflow')
            raise
    _t_start = time.perf_counter()
    # 单项补救必须复用批量阶段的结构化 schema。此前这里未传
    # response_format，模型在批量失败后的补救请求中可能返回自然语言，
    # 导致唯一失败项再次进入 MODEL_FAILED。
    response_format = _impact_batch_response_format(
        ctx,
        [task],
        include_reasons=ctx.setting('ENABLE_REASON'),
        schema_name='tara_impact_single',
    )
    (parsed, _) = ctx.service('cached_llm_json')(
        bucket='influence_parameters',
        cache_key=cache_key,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        default={'influence_parameters': {'Safety': 0, 'Finance': 0, 'Operation': 0, 'Privacy': 0}},
        max_tokens=impact_tokens,
        validator=_valid_impact_response,
        response_format=response_format,
    )
    ctx.service('_add_phase_time')('impact', time.perf_counter() - _t_start)
    params = _extract_params(parsed)
    sanitized = sanitize_reason_fields(
        params, IMPACT_REASON_KEYS, enabled=ctx.setting('ENABLE_REASON')
    )
    if sanitized is None:
        return {}
    result: dict = {'Safety': int(sanitized.get('Safety', 0)), 'Finance': int(sanitized.get('Finance', 0)), 'Operation': int(sanitized.get('Operation', 0)), 'Privacy': int(sanitized.get('Privacy', 0))}
    if ctx.setting('ENABLE_REASON'):
        for reason_key in IMPACT_REASON_KEYS:
            result[reason_key] = sanitized[reason_key].strip()
    return result

def _find_best_match_sample(ctx: RuntimeContext, samples: list[dict], target: dict, numeric_keys: list[str]) -> dict | None:
    """从采样列表中找出与目标（多数票）数值匹配维度最多的样本。"""
    if not samples:
        return None
    best = samples[0]
    best_score = -1
    for s in samples:
        score = sum((1 for k in numeric_keys if _safe_int(s.get(k)) == target.get(k)))
        if score > best_score:
            best_score = score
            best = s
    return best

def _sc_aggregate_numeric(ctx: RuntimeContext, samples_per_position: list[list[dict]], param_keys: list[str]) -> tuple[dict, dict]:
    """对多个采样结果做多数投票聚合。

    Args:
        samples_per_position: 每个采样在该位置返回的参数字典列表
                              e.g. [[{Safety:3,Finance:2}, {Safety:4,Finance:1}], ...]
        param_keys: 需要聚合的数值型参数键名列表

    Returns:
        (aggregated_params, confidence):
          aggregated_params: 多数投票后的参数字典
          confidence: 每个参数的置信度 (agreement/total)
    """
    if not samples_per_position:
        return ({}, {})
    aggregated = {}
    confidence = {}
    for key in param_keys:
        values = []
        for params in samples_per_position:
            v = _safe_int(params.get(key))
            if v > 0:
                values.append(v)
        if values:
            counter = Counter(values)
            (most_common, count) = counter.most_common(1)[0]
            aggregated[key] = most_common
            confidence[key] = count / len(values)
        else:
            aggregated[key] = 1
            confidence[key] = 0.0
    return (aggregated, confidence)

def _sc_exec_impact_with_sc(ctx: RuntimeContext, batch: list[TaskUnit], n_samples: int=5) -> None:
    """带 Self-Consistency 的影响评级：采样 N 次 → 多数投票 → 置信度。

    SC choices 只输出四维数值，避免开启理由时 N 份长文本挤爆输出 token。
    聚合完成后再按固定分值批量生成一份最终理由。vLLM 的 ``n`` 会在
    服务端展开为 N 条序列，因此还通过专用信号量限制隐性并发放大。
    """

    def _build_user_prompt() -> str:
        lines = []
        for (j, t) in enumerate(batch):
            lines.append(f'## 损害场景 {j}')
            lines.append(f'- task_id: {t.task_id}')
            lines.append(f'- function: {t.function}')
            lines.append(f'- asset_name: {t.asset_name}')
            lines.append(f'- asset_type: {t.asset_type}')
            lines.append(f'- attribute_name: {t.attribute_name}')
            lines.append(f"- asset_details: {t.asset_details or '（无）'}")
            lines.append(f"- source: {t.source or '（无）'}")
            lines.append(f"- target: {t.target or '（无）'}")
            lines.append(f'- damage_scenario: {t.damage_scenario}')
        return f'请为以下 {len(batch)} 个损害场景分别进行影响评级。\n\n' + '\n'.join(lines) + '\n\n每个结果必须原样返回对应task_id。'
    user_prompt = _build_user_prompt()
    numeric_tokens = ctx.service('_dynamic_token_budget')('impact_numeric', len(batch), include_reasons=False, system_prompt=ctx.setting("IMPACT_SC_NUMERIC_SYSTEM_PROMPT"), user_prompt=user_prompt, record=True)
    parsed_samples: list[list[dict]] = []
    empty_choices = 0
    parse_failures = 0
    alignment_failures = 0
    returned_choices = 0
    if ctx.setting('SC_SINGLE_CALL'):
        try:
            ctx.service('_increment_pipeline_metric')('impact_sc_model_calls')
            with ctx.shared('sc_multi_choice_semaphore'):
                raw_choices = ctx.service('llm_call_with_semaphore')(ctx.setting("IMPACT_SC_NUMERIC_SYSTEM_PROMPT"), user_prompt, retries=0, max_tokens=numeric_tokens, response_format=_impact_batch_response_format(ctx, batch, include_reasons=False, schema_name='tara_impact_sc_numeric'), n=n_samples, return_all_choices=True)
            if not isinstance(raw_choices, list):
                raw_choices = []
            returned_choices = len(raw_choices)
            for raw in raw_choices:
                if not raw or raw.strip() in ('', '{}'):
                    empty_choices += 1
                    continue
                try:
                    parsed = safe_parse_json(raw)
                except Exception:
                    parse_failures += 1
                    continue
                aligned = _align_task_results(ctx, parsed, batch)
                if all((item is not None for item in aligned)):
                    parsed_samples.append([item for item in aligned if item is not None])
                else:
                    alignment_failures += 1
        except Exception as e:
            logger.debug('SC-Impact vLLM多choice解析失败: %s', e)
    if not parsed_samples:
        logger.warning('SC-Impact: %d×%d 数值采样无有效choice，仅回退1次短数值调用（returned=%d empty=%d parse=%d align=%d）', n_samples, len(batch), returned_choices, empty_choices, parse_failures, alignment_failures)
        try:
            ctx.service('_increment_pipeline_metric')('impact_sc_fallback_calls')
            raw = ctx.service('llm_call_with_semaphore')(ctx.setting("IMPACT_SC_NUMERIC_SYSTEM_PROMPT"), user_prompt, retries=0, max_tokens=numeric_tokens, response_format=_impact_batch_response_format(ctx, batch, include_reasons=False, schema_name='tara_impact_sc_numeric_fallback'))
            if isinstance(raw, str) and raw.strip() not in ('', '{}'):
                parsed = safe_parse_json(raw)
                aligned = _align_task_results(ctx, parsed, batch)
                if all((item is not None for item in aligned)):
                    parsed_samples.append([item for item in aligned if item is not None])
        except Exception as e:
            logger.debug('SC-Impact 单次回退解析失败: %s', e)
    if not parsed_samples:
        for t in batch:
            t.influence_parameters = {}
            t.influence_confidence = {'Safety': 0.0, 'Finance': 0.0, 'Operation': 0.0, 'Privacy': 0.0}
            t.impact_confidence = 0.0
            t.low_confidence_flags.append('impact: no valid samples from SC')
            t.analysis_status = STATUS_MODEL_FAILED
            t.status_reasons.append('影响评级未获得有效采样')
        return
    for (j, t) in enumerate(batch):
        samples_for_task = []
        for sample in parsed_samples:
            if j < len(sample):
                item = sample[j]
                if 'influence_parameters' in item:
                    params = item['influence_parameters']
                else:
                    params = {'Safety': item.get('S'), 'Finance': item.get('F'), 'Operation': item.get('O'), 'Privacy': item.get('P')}
                numeric = {key: _safe_int(params.get(key)) for key in ('Safety', 'Finance', 'Operation', 'Privacy')}
                if all((1 <= numeric[key] <= 4 for key in numeric)):
                    samples_for_task.append({**params, **numeric})
        if not samples_for_task:
            t.influence_parameters = {}
            t.influence_confidence = {'Safety': 0.0, 'Finance': 0.0, 'Operation': 0.0, 'Privacy': 0.0}
            t.impact_confidence = 0.0
            t.analysis_status = STATUS_MODEL_FAILED
            if '影响评级未获得字段齐全的合法采样' not in t.status_reasons:
                t.status_reasons.append('影响评级未获得字段齐全的合法采样')
            continue
        param_keys = ['Safety', 'Finance', 'Operation', 'Privacy']
        (agg_params, confidence) = _sc_aggregate_numeric(ctx, samples_for_task, param_keys)
        t.influence_parameters = agg_params
        (t.impact_value, t.impact_level) = ctx.service('compute_impact')(agg_params)
        t.influence_confidence = confidence
        t.impact_confidence = sum(confidence.values()) / len(confidence) if confidence else 0.0
        if t.impact_confidence < ctx.setting('SC_CONFIDENCE_THRESHOLD'):
            t.low_confidence_flags.append(f"impact: confidence={t.impact_confidence:.2f} < {ctx.setting('SC_CONFIDENCE_THRESHOLD')}")
    reason_batch = [task for task in batch if all((1 <= _safe_int(task.influence_parameters.get(key)) <= 4 for key in ('Safety', 'Finance', 'Operation', 'Privacy')))]
    _populate_sc_impact_reasons(ctx, reason_batch)
    logger.debug('SC-Impact: batch_size=%d n_samples=%d valid_samples=%d', len(batch), n_samples, len(parsed_samples))

def _reason_fields_valid(ctx: RuntimeContext, params: Any, expected_keys: tuple[str, ...]) -> bool:
    """兼容旧内部名称；校验规则由 reason_policy 集中维护。"""
    return reason_fields_valid(params, expected_keys, enabled=ctx.setting('ENABLE_REASON'))

def _validated_numeric_params(ctx: RuntimeContext, params: Any, allowed_values: dict[str, list[int]], reason_keys: tuple[str, ...]=()) -> dict:
    """仅接受字段齐全且数值合法的评级；缺项不能被默认为最危险/最安全。"""
    if not isinstance(params, dict):
        return {}
    fixed: dict[str, Any] = {}
    for (key, allowed) in allowed_values.items():
        if key not in params:
            return {}
        value = _safe_int(params.get(key), default=-999999)
        if value not in allowed:
            return {}
        fixed[key] = value
    if reason_keys and ctx.setting('ENABLE_REASON'):
        # 超长 reason 截断保留（评级参数不受影响）；缺失/占位符/换行仍丢弃。
        sanitized = sanitize_reason_fields(params, reason_keys)
        if sanitized is None:
            return {}
        params = sanitized
    elif reason_keys and (not _reason_fields_valid(ctx, params, reason_keys)):
        return {}
    if ctx.setting('ENABLE_REASON') and reason_keys:
        for key in reason_keys:
            fixed[key] = params[key].strip()
    return fixed

def _align_task_results(ctx: RuntimeContext, parsed: Any, batch: list[TaskUnit]) -> list[dict | None]:
    """按task_id对齐批量结果；仅对严格等长的旧格式允许位置兼容。"""
    if isinstance(parsed, dict):
        for key in ('results', 'items', 'data'):
            if isinstance(parsed.get(key), list):
                parsed = parsed[key]
                break
        else:
            parsed = [parsed]
    if not isinstance(parsed, list):
        return [None] * len(batch)
    items = [item for item in parsed if isinstance(item, dict)]
    with_ids = [item for item in items if str(item.get('task_id', '')).strip()]
    if with_ids:
        by_id: dict[str, dict] = {}
        expected = {t.task_id for t in batch}
        for item in with_ids:
            task_id = _canonical_task_id(item.get('task_id'), expected)
            if not task_id or task_id in by_id:
                continue
            by_id[task_id] = item
        aligned = [by_id.get(t.task_id) for t in batch]
        if any((item is not None for item in aligned)):
            # vLLM 的严格 schema 通常会保证 task_id 正确，但个别模型仍可能
            # 在一个位置输出空/非法 ID。只在“恰好一个缺口 + 返回数量严格相等
            # + 其余项同时按原顺序匹配”时按位置修复，避免把乱序内容错绑到
            # 其他任务；无法满足这些条件时继续走失败子集重试。
            missing_positions = [
                index for index, item in enumerate(aligned) if item is None
            ]
            if len(items) == len(batch) and len(missing_positions) == 1:
                missing_index = missing_positions[0]
                expected_ids = {task.task_id for task in batch}
                positionally_consistent = True
                for index, (item, task) in enumerate(zip(items, batch)):
                    if index == missing_index:
                        continue
                    task_id = _canonical_task_id(
                        item.get('task_id'), expected_ids
                    )
                    if task_id != task.task_id:
                        positionally_consistent = False
                        break
                candidate = items[missing_index]
                candidate_id = _canonical_task_id(
                    candidate.get('task_id'), expected_ids
                )
                if positionally_consistent and not candidate_id:
                    aligned[missing_index] = candidate
                    ctx.service('_increment_pipeline_metric')(
                        'task_id_single_hole_position_repairs'
                    )
                    return aligned
            return aligned
        if len(items) == len(batch):
            raw_ids = [str(item.get('task_id', '')).strip() for item in items]
            if all((task_id.isdigit() for task_id in raw_ids)):
                numeric_ids = [int(task_id) for task_id in raw_ids]
                if numeric_ids in (list(range(len(batch))), list(range(1, len(batch) + 1))):
                    ctx.service('_increment_pipeline_metric')('task_id_position_rebind_batches')
                    return items
        return aligned
    if len(items) == len(batch):
        return items
    return [None] * len(batch)

def _apply_impact_result(ctx: RuntimeContext, task: TaskUnit, item: dict) -> bool:
    params = item.get('influence_parameters', item)
    if not isinstance(params, dict):
        return False
    values = {'Safety': _safe_int(params.get('Safety')), 'Finance': _safe_int(params.get('Finance')), 'Operation': _safe_int(params.get('Operation')), 'Privacy': _safe_int(params.get('Privacy'))}
    if not all((1 <= values[k] <= 4 for k in values)):
        return False
    if ctx.setting('ENABLE_REASON'):
        sanitized = sanitize_reason_fields(params, IMPACT_REASON_KEYS)
        if sanitized is None:
            return False
        params = sanitized
    task.influence_parameters = values
    if ctx.setting('ENABLE_REASON'):
        for reason_key in IMPACT_REASON_KEYS:
            task.influence_parameters[reason_key] = params[reason_key].strip()
    (task.impact_value, task.impact_level) = ctx.service('compute_impact')(task.influence_parameters)
    _clear_recovered_impact_failures(task)
    return True

def _impact_batch_response_format(ctx: RuntimeContext, batch: list[TaskUnit], *, include_reasons: bool | None=None, schema_name: str='tara_impact_batch') -> dict:
    if include_reasons is None:
        include_reasons = ctx.setting('ENABLE_REASON')
    parameter_properties: dict[str, dict] = {key: {'type': 'integer', 'enum': [1, 2, 3, 4]} for key in ('Safety', 'Finance', 'Operation', 'Privacy')}
    required = ['Safety', 'Finance', 'Operation', 'Privacy']
    if include_reasons:
        for reason_key in IMPACT_REASON_KEYS:
            # 不使用 maxLength：vLLM 在字符上限处硬截断字符串后，模型会继续输出
            # 制表符填充直至 max_tokens，导致 JSON 尾部不完整、整批作废。
            # 超长理由由 reason_fields_valid(≤RATING_REASON_MAX_CHARS) 丢弃后走拆半修复。
            parameter_properties[reason_key] = {'type': 'string', 'minLength': 2}
        required.extend(IMPACT_REASON_KEYS)
    return {'type': 'json_schema', 'json_schema': {'name': schema_name, 'strict': True, 'schema': {'type': 'object', 'properties': {'items': {'type': 'array', 'minItems': len(batch), 'maxItems': len(batch), 'items': {'type': 'object', 'properties': {'task_id': {'type': 'string', 'enum': [task.task_id for task in batch]}, 'influence_parameters': {'type': 'object', 'properties': parameter_properties, 'required': required, 'additionalProperties': False}}, 'required': ['task_id', 'influence_parameters'], 'additionalProperties': False}}}, 'required': ['items'], 'additionalProperties': False}}}

def _impact_reason_response_format(ctx: RuntimeContext, batch: list[TaskUnit]) -> dict:
    # 不使用 maxLength（原因同 _impact_batch_response_format）：超长理由由校验层丢弃后重试。
    reason_properties = {key: {'type': 'string', 'minLength': 2} for key in IMPACT_REASON_KEYS}
    return {'type': 'json_schema', 'json_schema': {'name': 'tara_impact_reasons', 'strict': True, 'schema': {'type': 'object', 'properties': {'items': {'type': 'array', 'minItems': len(batch), 'maxItems': len(batch), 'items': {'type': 'object', 'properties': {'task_id': {'type': 'string', 'enum': [task.task_id for task in batch]}, 'reasons': {'type': 'object', 'properties': reason_properties, 'required': list(IMPACT_REASON_KEYS), 'additionalProperties': False}}, 'required': ['task_id', 'reasons'], 'additionalProperties': False}}}, 'required': ['items'], 'additionalProperties': False}}}

def _request_sc_impact_reasons(ctx: RuntimeContext, batch: list[TaskUnit]) -> list[TaskUnit]:
    """为已聚合的固定分值生成理由，返回本次仍未获得完整理由的任务。"""
    if not ctx.setting('ENABLE_REASON') or not batch:
        return []
    lines = []
    for (j, task) in enumerate(batch):
        scores = {key: _safe_int(task.influence_parameters.get(key)) for key in ('Safety', 'Finance', 'Operation', 'Privacy')}
        lines.extend((f'## 结果 {j}', f'- task_id: {task.task_id}', f'- asset_name: {task.asset_name}', f'- asset_type: {task.asset_type}', f'- attribute_name: {task.attribute_name}', f'- damage_scenario: {task.damage_scenario}', '- fixed_scores: ' + orjson.dumps(scores).decode('utf-8')))
    user_prompt = f'请为以下 {len(batch)} 项固定影响分值生成评级理由。\n\n' + '\n'.join(lines)
    system_prompt = ctx.setting('IMPACT_REASON_SYSTEM_PROMPT', IMPACT_REASON_SYSTEM_PROMPT)
    reason_max_tokens = ctx.service('_dynamic_token_budget')('impact_reason', len(batch), include_reasons=True, system_prompt=system_prompt, user_prompt=user_prompt, record=True)
    ctx.service('_increment_pipeline_metric')('impact_reason_model_calls')
    raw = ctx.service('llm_call_with_semaphore')(system_prompt, user_prompt, retries=0, max_tokens=reason_max_tokens, response_format=_impact_reason_response_format(ctx, batch))
    if not isinstance(raw, str) or raw.strip() in ('', '{}'):
        return list(batch)
    try:
        aligned = _align_task_results(ctx, safe_parse_json(raw), batch)
    except Exception:
        return list(batch)
    missing: list[TaskUnit] = []
    for (task, item) in zip(batch, aligned):
        reasons = item.get('reasons') if isinstance(item, dict) else None
        if not _reason_fields_valid(ctx, reasons, IMPACT_REASON_KEYS):
            missing.append(task)
            continue
        for reason_key in IMPACT_REASON_KEYS:
            task.influence_parameters[reason_key] = reasons[reason_key].strip()
    return missing

def _populate_sc_impact_reasons(ctx: RuntimeContext, batch: list[TaskUnit]) -> None:
    """批量生成理由；仅对缺失项做一次紧凑重试，避免重算四维分值。"""
    if not ctx.setting('ENABLE_REASON'):
        return
    missing = _request_sc_impact_reasons(ctx, batch)
    if missing:
        logger.warning('SC-Impact 理由生成首轮缺失 %d/%d 项，仅对缺失项重试 1 次', len(missing), len(batch))
        missing = _request_sc_impact_reasons(ctx, missing)
    for task in missing:
        task.analysis_status = STATUS_MODEL_FAILED
        if '影响评级理由缺失' not in task.status_reasons:
            task.status_reasons.append('影响评级理由缺失')

def _impact_item_cache_key(ctx: RuntimeContext, task: TaskUnit) -> dict:
    """Use asset evidence, not a run's ordinal task_id or batch boundary."""
    system_prompt = ctx.setting('IMPACT_BATCH_SYSTEM_PROMPT', IMPACT_BATCH_SYSTEM_PROMPT)
    return stage_key(ctx, task, 'impact', system_prompt,
                     parents={'scenarios': scenario_reference(task)},
                     settings={'impact_method': ctx.setting('IMPACT_METHOD', '21434'),
                               'sc_prompt_sha256': hashlib.sha256(str(ctx.setting('IMPACT_SC_NUMERIC_SYSTEM_PROMPT')).encode()).hexdigest() if ctx.setting('SC_ENABLED') else None,
                               'reason_prompt_sha256': hashlib.sha256(str(ctx.setting('IMPACT_REASON_SYSTEM_PROMPT')).encode()).hexdigest() if ctx.setting('ENABLE_REASON') else None})


def _store_valid_impact_items(ctx: RuntimeContext, tasks: list[TaskUnit], keys: dict) -> bool:
    complete = True
    for task in tasks:
        value = {'influence_parameters': task.influence_parameters,
                 'influence_confidence': task.influence_confidence,
                 'impact_confidence': task.impact_confidence,
                 'low_confidence_flags': [flag for flag in task.low_confidence_flags if flag.startswith('impact')]}
        if _apply_impact_result(ctx, task, value):
            ctx.shared('semantic_cache').set('impact_item', keys[task.task_id], value)
        else:
            complete = False
    return complete


def _exec_impact_batch(
    ctx: RuntimeContext,
    batch: list[TaskUnit],
    *,
    _repair_depth: int = 0,
) -> None:
    _exec_impact_batch_impl(ctx, batch, _repair_depth=_repair_depth)
    for task in batch:
        if task.analysis_status != STATUS_NOT_APPLICABLE and all(
            1 <= _safe_int(task.influence_parameters.get(name)) <= 4
            for name in ('Safety', 'Finance', 'Operation', 'Privacy')
        ):
            record_result(task, 'impact', _impact_item_cache_key(ctx, task), task.influence_parameters)


def _exec_impact_batch_impl(
    ctx: RuntimeContext,
    batch: list[TaskUnit],
    *,
    _repair_depth: int = 0,
) -> None:
    system_prompt = ctx.setting('IMPACT_BATCH_SYSTEM_PROMPT', IMPACT_BATCH_SYSTEM_PROMPT)
    # A batch cache only hits when the scheduler creates the same grouping.
    # Materialize validated per-task entries as well, so checkpoint resumes,
    # changed batch sizes and reordered inputs reuse prior ratings safely.
    item_bucket = 'impact_item'
    pending: list[TaskUnit] = []
    item_keys: dict[str, dict] = {}
    for task in batch:
        item_version = _impact_item_cache_key(ctx, task)
        item_keys[task.task_id] = item_version
        cached_item = ctx.shared('semantic_cache').get(item_bucket, item_version)
        if isinstance(cached_item, dict) and _apply_impact_result(ctx, task, cached_item):
            task.influence_confidence = dict(cached_item.get('influence_confidence') or {})
            task.impact_confidence = float(cached_item.get('impact_confidence') or 0.0)
            task.low_confidence_flags = [flag for flag in task.low_confidence_flags if not flag.startswith('impact')]
            task.low_confidence_flags.extend(cached_item.get('low_confidence_flags') or [])
            continue
        pending.append(task)
    if not pending:
        ctx.service('_increment_pipeline_metric')('impact_item_cache_hits', len(batch))
        return
    if len(pending) != len(batch):
        ctx.service('_increment_pipeline_metric')('impact_item_cache_hits', len(batch) - len(pending))
    batch = pending
    if ctx.setting('SC_ENABLED') and ctx.setting('ENABLE_CONSISTENCY'):
        _sc_exec_impact_with_sc(ctx, batch, n_samples=ctx.setting('SC_SAMPLES'))
        _store_valid_impact_items(ctx, batch, item_keys)
        return
    user_prompt = build_impact_batch_user_prompt(batch)
    cache_key = {
        'batch_size': len(batch),
        'tasks': [
            (
                t.task_id, t.function, t.asset_name, t.asset_type,
                t.attribute_name, t.threat_type, t.damage_scenario,
                t.source, t.target, t.flow_protocol,
            )
            for t in batch
        ],
    }
    try:
        batch_max_tokens = ctx.service('_impact_batch_max_tokens')(
            len(batch), system_prompt=system_prompt,
            user_prompt=user_prompt, record=True,
        )
    except PromptContextOverflow:
        ctx.service('_increment_pipeline_metric')('impact_context_overflows')
        for task in batch:
            task.errors.append('impact_batch_context_overflow')
        fallback = ctx.service('_fallback_impact_batch')
        if _repair_depth:
            fallback(batch, _repair_depth=_repair_depth)
        else:
            fallback(batch)
        _store_valid_impact_items(ctx, batch, item_keys)
        return
    versioned_cache_key = ctx.service('_build_llm_cache_key')(cache_key, system_prompt, user_prompt, batch_max_tokens)
    cached = ctx.shared('semantic_cache').get('impact_batch', versioned_cache_key)
    if cached is not None:
        aligned = _align_task_results(ctx, cached, batch)
        if all((item is not None and _apply_impact_result(ctx, t, item) for (t, item) in zip(batch, aligned))):
            _store_valid_impact_items(ctx, batch, item_keys)
            return
        logger.warning('影响评级缓存与当前batch无法安全对齐，忽略缓存')
    ctx.service('_increment_pipeline_metric')('impact_model_calls')
    raw = ctx.service('llm_call_with_semaphore')(system_prompt, user_prompt, max_tokens=batch_max_tokens, response_format=_impact_batch_response_format(ctx, batch))
    if not raw or raw.strip() in ('', '{}'):
        fallback = ctx.service('_fallback_impact_batch')
        if _repair_depth:
            fallback(batch, _repair_depth=_repair_depth)
        else:
            fallback(batch)
        _store_valid_impact_items(ctx, batch, item_keys)
        return
    try:
        parsed = safe_parse_json(raw)
    except Exception as exc:
        ctx.service('_increment_pipeline_metric')('impact_truncated_or_invalid_json_batches')
        logger.warning('影响评级批量JSON不完整或非法，按失败子集有限拆半修复，不展开为 %d 次逐项调用: %s', len(batch), str(exc)[:160])
        fallback = ctx.service('_fallback_impact_batch')
        if _repair_depth:
            fallback(batch, _repair_depth=_repair_depth)
        else:
            fallback(batch)
        _store_valid_impact_items(ctx, batch, item_keys)
        return
    aligned = _align_task_results(ctx, parsed, batch)
    alignment_missing: list[TaskUnit] = []
    validation_failed: list[TaskUnit] = []
    for (t, item) in zip(batch, aligned):
        try:
            if item is None:
                alignment_missing.append(t)
            elif not _apply_impact_result(ctx, t, item):
                validation_failed.append(t)
        except Exception as e:
            t.errors.append(f'影响评级异常: {e}')
            validation_failed.append(t)
    failed = alignment_missing + validation_failed
    if failed:
        if alignment_missing:
            raw_items = parsed
            if isinstance(raw_items, dict):
                for key in ('results', 'items', 'data'):
                    if isinstance(raw_items.get(key), list):
                        raw_items = raw_items[key]
                        break
            returned_ids = [
                str(item.get('task_id', '')).strip()
                for item in (raw_items if isinstance(raw_items, list) else [])
                if isinstance(item, dict)
            ]
            logger.warning(
                '影响评级: task_id无法对齐=%d，评级值或理由不合格=%d，'
                '仅对 %d/%d 个失败项分批重试；返回task_id=%s，期望task_id=%s',
                len(alignment_missing), len(validation_failed), len(failed),
                len(batch), returned_ids, [task.task_id for task in batch],
            )
        else:
            logger.warning(
                '影响评级: task_id无法对齐=%d，评级值或理由不合格=%d，'
                '仅对 %d/%d 个失败项分批重试',
                len(alignment_missing), len(validation_failed), len(failed),
                len(batch),
            )
        if len(failed) > 1:
            fallback = ctx.service('_fallback_impact_batch')
            if _repair_depth:
                fallback(failed, _repair_depth=_repair_depth)
            else:
                fallback(failed)
        else:
            task = failed[0]
            try:
                params = generate_influence_parameters(ctx, task, repair=True)
                if not _apply_impact_result(ctx, task, {'influence_parameters': params}):
                    task.errors.append('影响评级: 单项重试仍缺失、非法或理由不完整')
                    task.analysis_status = STATUS_MODEL_FAILED
                    task.status_reasons.append('影响评级模型失败')
            except Exception as exc:
                task.errors.append(f'影响评级: 单项重试异常: {exc}')
                task.analysis_status = STATUS_MODEL_FAILED
                task.status_reasons.append('影响评级模型失败')
    if _store_valid_impact_items(ctx, batch, item_keys):
        batch_values = [{'task_id': t.task_id, 'influence_parameters': t.influence_parameters} for t in batch]
        ctx.shared('semantic_cache').set('impact_batch', versioned_cache_key, batch_values)

def _fallback_impact_batch(
    ctx: RuntimeContext,
    batch: list[TaskUnit],
    *,
    _repair_depth: int = 0,
) -> None:
    """影响评级有限降级：只拆半指定层数，避免指数级调用。"""
    if len(batch) <= 1:
        for t in batch:
            try:
                params = generate_influence_parameters(ctx, t, repair=True)
                if not _apply_impact_result(ctx, t, {'influence_parameters': params}):
                    t.errors.append('影响评级: 单项重试仍无有效结果')
                    t.analysis_status = STATUS_MODEL_FAILED
                    t.status_reasons.append('影响评级模型失败')
            except Exception as e:
                t.errors.append(f'影响评级: 单项重试异常: {e}')
                t.analysis_status = STATUS_MODEL_FAILED
                t.status_reasons.append('影响评级模型失败')
        return
    if _repair_depth >= int(ctx.setting('IMPACT_REPAIR_MAX_DEPTH', 1)):
        ctx.service('_increment_pipeline_metric')(
            'impact_repair_depth_limited_tasks', len(batch)
        )
        for task in batch:
            task.influence_parameters = {}
            task.analysis_status = STATUS_MODEL_FAILED
            if '影响评级批量修复达到上限' not in task.status_reasons:
                task.status_reasons.append('影响评级批量修复达到上限')
            task.errors.append(
                '影响评级: 批量结果仍不合格，已停止递归拆分'
            )
        return
    ctx.service('_increment_pipeline_metric')('impact_repair_split_calls', 2)
    mid = len(batch) // 2
    _exec_impact_batch(
        ctx, batch[:mid], _repair_depth=_repair_depth + 1
    )
    _exec_impact_batch(
        ctx, batch[mid:], _repair_depth=_repair_depth + 1
    )
