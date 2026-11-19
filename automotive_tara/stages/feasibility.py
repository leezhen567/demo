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
    reason_fields_valid, sanitize_reason_fields,
)
from automotive_tara.runtime import RuntimeContext
from automotive_tara.cache_dependencies import path_reference, stage_key, record_result
from automotive_tara.analysis_cache import digest_json
from automotive_tara.token_budget import (
    TOKEN_PROFILES, PromptContextOverflow, estimate_prompt_tokens,
)
from automotive_tara.topology import (
    determine_attack_vector as _determine_attack_vector,
    external_interface_key as _external_interface_key,
    limit_shortest_frameworks, normalize_text as _normalize_text,
    same_external_interface as _same_external_interface,
    same_protocol as _same_protocol,
)
from automotive_tara.stages.impact import (
    _validated_numeric_params as _impact_validated_numeric_params,
)

logger = logging.getLogger(__name__)

_DST_CAPABILITY_GUARD_ERROR = "DST能力断言与资产证据冲突"
_DST_NO_CAPABILITY_MARKERS = (
    "无日志记录能力", "无日志能力", "不具备日志", "没有日志",
    "无操作系统级权限机制", "无权限机制", "不具备权限", "没有权限",
)


def _max_paths_per_call(ctx: RuntimeContext) -> int:
    """返回理由策略下真正生效的可行性路径合批数。"""
    configured = max(1, int(ctx.setting('FEASIBILITY_PATHS_PER_CALL')))
    if not ctx.setting('ENABLE_REASON'):
        return configured
    return max(
        1,
        min(
            configured,
            int(ctx.setting('FEASIBILITY_REASON_PATHS_PER_CALL', 8)),
        ),
    )


def _sc_numeric_only_prompt(system_prompt: str, reason_keys: tuple[str, ...]) -> str:
    """将一致性采样请求裁剪为只生成数值，理由在聚合后单独生成。

    原始可行性 Prompt 在开启理由时会要求每个 choice 都生成理由，
    这会浪费 token，并使同一条路径的理由随采样一起波动。这里保留
    完整评级量规，只移除理由协议和 JSON 示例中的 reason 字段。
    """
    prompt = system_prompt or ""
    marker = "\n\n## 评级理由输出协议"
    if marker in prompt:
        prompt = prompt.split(marker, 1)[0]
    prompt = "\n".join(
        line
        for line in prompt.splitlines()
        if "必须附带评级理由" not in line
        and "评分理由必须" not in line
    )
    for key in reason_keys:
        escaped = re.escape(key)
        prompt = re.sub(
            rf',\s*"{escaped}"\s*:\s*"[^"]*"',
            "",
            prompt,
        )
        prompt = re.sub(
            rf'"{escaped}"\s*:\s*"[^"]*"\s*,?',
            "",
            prompt,
        )
    return (
        prompt
        + "\n\n## Self-Consistency 数值采样协议（最高优先级）\n"
        + "当前 choice 只输出 path_id 以及要求的数值评级字段；禁止输出"
          "任何 reason、理由、解释或其他字段。"
    )


def _sc_reason_response_format(path_ids: list[str], reason_keys: tuple[str, ...]) -> dict:
    """构造 SC 聚合后的一次性理由响应 Schema。"""
    properties: dict[str, dict] = {
        "path_id": {"type": "string", "enum": path_ids},
    }
    properties.update({key: {"type": "string", "minLength": 2} for key in reason_keys})
    required = ["path_id", *reason_keys]
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "tara_feasibility_sc_reasons",
            "strict": True,
            "schema": {
                "type": "object",
                "properties": {
                    "attack_parameters_list": {
                        "type": "array",
                        "minItems": len(path_ids),
                        "maxItems": len(path_ids),
                        "items": {
                            "type": "object",
                            "properties": properties,
                            "required": required,
                            "additionalProperties": False,
                        },
                    }
                },
                "required": ["attack_parameters_list"],
                "additionalProperties": False,
            },
        },
    }


def _populate_sc_feasibility_reasons(
    ctx: RuntimeContext,
    task: TaskUnit,
    attack_paths: list[tuple[str, str]],
    params: list[dict],
    *,
    method: str,
) -> set[int]:
    """为已聚合的固定可行性分值生成一次理由，返回仍缺理由的位置。

    数值已在 SC 阶段确定，理由请求严禁修改数值；失败时只保留失败位置，
    由调用方按“理由缺失即不合格”处理，不重新抽取评级参数。
    """
    if not ctx.setting("ENABLE_REASON") or not attack_paths:
        return set()
    if method == "heavens":
        reason_keys = ("Expertise_reason", "Knowledge_about_TOE_reason", "Equipment_reason")
        stage_name = "feasibility_heavens"
    else:
        reason_keys = (
            "Exposure_time_reason",
            "Professional_experience_reason",
            "Required_information_reason",
            "Required_equipment_reason",
        )
        stage_name = "feasibility_ap"
    path_ids = [f"{task.task_id}:path:{i}" for i in range(len(attack_paths))]

    def _build_prompt(indices: list[int]) -> str:
        rows: list[str] = []
        for index in indices:
            path, vector = attack_paths[index]
            fixed = {
                key: params[index].get(key)
                for key in params[index]
                if not key.endswith("_reason")
            }
            rows.extend(
                (
                    f"## 路径 {path_ids[index]}",
                    f"- path_id: {path_ids[index]}",
                    f"- attack_path: {path}",
                    f"- attack_vector: {vector}",
                    "- fixed_parameters: " + orjson.dumps(fixed).decode("utf-8"),
                )
            )
        return (
            f"请为以下 {len(indices)} 条已固定评级数值的攻击路径生成理由。\n"
            "数值已经确定，禁止修改、重新评级或输出其他数值；每条路径只返回"
            "一个简短重点理由字段，理由必须结合路径和固定数值。\n"
            + "\n".join(rows)
        )

    def _request(indices: list[int]) -> set[int]:
        if not indices:
            return set()
        user_prompt = _build_prompt(indices)
        system_prompt = (
            "你是汽车网络安全可行性评级复核专家。只生成已固定评级数值的"
            "简短理由，禁止修改数值。仅输出 JSON。"
        )
        tokens = ctx.service("_dynamic_token_budget")(
            stage_name,
            len(indices),
            include_reasons=True,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            record=True,
        )
        raw = ctx.service("llm_call_with_semaphore")(
            system_prompt,
            user_prompt,
            retries=0,
            max_tokens=tokens,
            response_format=_sc_reason_response_format(
                [path_ids[index] for index in indices], reason_keys
            ),
        )
        try:
            parsed = safe_parse_json(raw) if isinstance(raw, str) else {}
        except Exception:
            return set(indices)
        if not isinstance(parsed, dict):
            return set(indices)
        aligned = _align_path_parameter_list(
            ctx,
            parsed.get("attack_parameters_list", []),
            [path_ids[index] for index in indices],
        )
        missing: set[int] = set()
        for local_index, global_index in enumerate(indices):
            item = aligned[local_index] if local_index < len(aligned) else {}
            if not reason_fields_valid(item, reason_keys, enabled=True):
                missing.add(global_index)
                continue
            for key in reason_keys:
                params[global_index][key] = item[key].strip()
        return missing

    valid_indices = [index for index, item in enumerate(params) if item]
    missing = _request(valid_indices)
    if missing:
        logger.warning(
            "%s SC 理由首轮缺失 %d/%d 项，仅对缺失项重试 1 次",
            method.upper(),
            len(missing),
            len(valid_indices),
        )
        missing = _request(sorted(missing))
    return missing


def _align_path_parameter_list(ctx: RuntimeContext, params_list: Any, path_ids: list[str]) -> list[dict]:
    """按 path_id 对齐批量可行性结果；旧格式只在严格等长时按位置兼容。"""
    if not isinstance(params_list, list):
        return [{} for _ in path_ids]
    items = [item for item in params_list if isinstance(item, dict)]
    with_ids = [item for item in items if str(item.get('path_id', '')).strip()]
    if with_ids:
        by_id: dict[str, dict] = {}
        expected = set(path_ids)
        for item in with_ids:
            path_id = str(item.get('path_id', '')).strip()
            if path_id not in expected or path_id in by_id:
                # 单个重复/越界 path_id 只影响该项，不摧毁整批；
                # 其余合法项仍按 path_id 对齐，缺失项保持为空交由修复链重试。
                continue
            by_id[path_id] = item
        return [by_id.get(path_id, {}) for path_id in path_ids]
    if len(items) == len(path_ids):
        return items
    return [{} for _ in path_ids]

def _sc_ap_chunk(ctx: RuntimeContext, system_prompt: str, user_prompt: str, chunk_size: int, n_samples: int=5, allowed_values: dict=None, reason_keys: tuple=None, path_ids: list[str] | None=None, item_normalizer: Callable[[dict, int], dict] | None=None) -> tuple[list[dict], list[dict]]:
    """对攻击可行性评估的一个 chunk 做 Self-Consistency 采样。

    采样 N 次，逐位置多数投票聚合参数并吸附到合法值。

    Args:
        allowed_values: 合法值字典，默认 AP_ALLOWED_VALUES（ISO 五维）；
                        传 HEAVENS_AP_ALLOWED_VALUES 用于 HEAVENS 四维。
        reason_keys: 评级理由键名元组。

    Returns:
        (aggregated_params_list, confidence_list)
    """
    if allowed_values is None:
        allowed_values = AP_ALLOWED_VALUES
    if reason_keys is None:
        reason_keys = ('Exposure_time_reason', 'Professional_experience_reason', 'Required_information_reason', 'Opportunity_window_reason', 'Required_equipment_reason')
    path_ids = path_ids or [str(i) for i in range(chunk_size)]
    all_samples: list[list[dict]] = []
    token_stage = 'feasibility_heavens' if allowed_values == HEAVENS_AP_ALLOWED_VALUES else 'feasibility_ap'
    numeric_system_prompt = _sc_numeric_only_prompt(system_prompt, reason_keys)
    feasibility_tokens = ctx.service('_dynamic_token_budget')(token_stage, chunk_size, include_reasons=False, system_prompt=numeric_system_prompt, user_prompt=user_prompt, record=True)

    def _one_sample():
        raw = ctx.service('llm_call_with_semaphore')(numeric_system_prompt, user_prompt, retries=0, max_tokens=feasibility_tokens)
        if not raw or raw.strip() in ('', '{}'):
            return None
        try:
            parsed = safe_parse_json(raw)
            if isinstance(parsed, list):
                parsed = {'attack_parameters_list': parsed}
            params_list = parsed.get('attack_parameters_list', [])
            aligned = _align_path_parameter_list(ctx, params_list, path_ids)
            if any(aligned):
                return aligned
        except Exception:
            pass
        return None
    executor = ctx.service('get_sc_executor')()
    futures = {executor.submit(_one_sample): i for i in range(n_samples)}
    for f in as_completed(futures):
        try:
            result = f.result()
            if result:
                all_samples.append(result)
        except Exception:
            pass
    if not all_samples:
        return ([], [])
    aggregated: list[dict] = []
    confidences: list[dict] = []
    for pos in range(chunk_size):
        pos_samples: list[dict] = []
        for sample in all_samples:
            if pos < len(sample):
                candidate = sample[pos]
                if item_normalizer is not None:
                    candidate = item_normalizer(candidate, pos)
                validated = _impact_validated_numeric_params(ctx, candidate, allowed_values, ())
                if validated:
                    pos_samples.append(validated)
        if not pos_samples:
            aggregated.append({})
            confidences.append({'_overall': 0.0})
            continue
        agg_params: dict = {}
        agg_conf: dict = {}
        for key in allowed_values.keys():
            values = [_safe_int(s.get(key, 0)) for s in pos_samples]
            if values:
                counter = Counter(values)
                (most_common, count) = counter.most_common(1)[0]
                agg_params[key] = most_common
                agg_conf[key] = count / len(values)
            else:
                agg_params[key] = 0
                agg_conf[key] = 0.0
        fixed: dict = {}
        for (k, allowed) in allowed_values.items():
            v = agg_params.get(k, 0)
            fixed[k] = min(allowed, key=lambda x: abs(x - v))
        aggregated.append(fixed)
        agg_conf['_overall'] = sum(agg_conf.values()) / len(agg_conf) if agg_conf else 0.0
        confidences.append(agg_conf)
    return (aggregated, confidences)

def _normalize_cvss_model_params(ctx: RuntimeContext, item: Any) -> dict:
    """展开 CVSS 紧凑输出字段，同时兼容旧完整字段名。"""
    if not isinstance(item, dict):
        return {}
    normalized = dict(item)
    for (full_name, short_name) in {'complexity': 'C', 'privileges': 'P', 'user_interaction': 'U'}.items():
        if full_name not in normalized and short_name in normalized:
            normalized[full_name] = normalized[short_name]
    return normalized

_IMPLEMENTED_RATING_MARKER = "【安全需求实施后评级输入】"


def _implemented_rating_system_prompt(
    system_prompt: str, attack_paths: list[str],
) -> str:
    if not any(_IMPLEMENTED_RATING_MARKER in path for path in attack_paths):
        return system_prompt
    return system_prompt + (
        "\n\n【已实施安全需求的目标约束复评】"
        "只有带【安全需求实施后评级输入】标记的路径采用此规则。"
        "逐条读取其【本路径数值硬约束】，这是当前评级任务的数值边界。"
        "机会窗口由攻击向量固定，不要输出；只对其余维度选择合法值。"
        "若给出 candidate_dimension_combinations，必须完整选择其中一组有依据的维度值，"
        "不能把不同组合拼接，也不能改写固定维度。"
        "复算后的等级和风险值须满足本路径目标。"
        "CVSS 按给定系数做乘法，不按分值求和。"
        "以已实施安全需求对攻击步骤的影响解释每个所选分值；"
        "评分理由只能依据给定的实施后路径、控制分析和安全需求，"
        "不得新增未提供证据的私钥泄露、未知漏洞或特殊设备来凑分。"
        "不要直接沿用实施前的维度分值。"
    )


def generate_attack_parameters_cvss_batch(ctx: RuntimeContext, task: TaskUnit, attack_paths: list[tuple[str, str]], *, _allow_reason_retry: bool=True) -> list[dict]:
    """批量评估多条攻击路径的CVSS参数，一次LLM调用。

    Args:
        task: TaskUnit
        attack_paths: [(attack_path_text, attack_vector), ...]

    Returns:
        [{"attack_vector": ..., "complexity": ..., "privileges": ..., "user_interaction": ...}, ...]
    """
    system_prompt = _implemented_rating_system_prompt(
        ctx.setting('CVSS_BATCH_SYSTEM_PROMPT', CVSS_BATCH_SYSTEM_PROMPT),
        [text for text, _ in attack_paths],
    )
    path_ids = [f'{task.task_id}:path:{i}' for i in range(len(attack_paths))]
    paths_block = '\n\n'.join((f'[路径 {path_ids[i]}]\npath_id: {path_ids[i]}\n攻击路径: {ap}\n攻击向量: {vec}' for (i, (ap, vec)) in enumerate(attack_paths)))
    user_prompt = f'输入：\n- function: {task.function}\n- asset_name: {task.asset_name}\n- threat_scenarios: {task.threat_scenarios}\n\n多条攻击路径如下（攻击向量已由外部接口映射确定）：\n{paths_block}\n\n请为每条攻击路径分别分析并用 C、P、U 输出CVSS可利用性参数，\n每项必须原样返回 path_id，禁止省略、合并或改变顺序。'
    cache_key = {'asset_name': task.asset_name, 'attack_paths': [ap for (ap, _) in attack_paths]}

    def _valid_cvss_response(value: Any) -> bool:
        if isinstance(value, list):
            value = {'attack_parameters_list': value}
        if not isinstance(value, dict):
            return False
        aligned = _align_path_parameter_list(ctx, value.get('attack_parameters_list', []), path_ids)
        return bool(aligned) and all((
            str(normalized.get('complexity', '')).strip().lower() in CVSS_C
            and str(normalized.get('privileges', '')).strip().lower() in CVSS_P
            and str(normalized.get('user_interaction', '')).strip().lower() in CVSS_U
            and sanitize_reason_fields(
                normalized,
                CVSS_REASON_KEYS,
                enabled=ctx.setting('ENABLE_REASON'),
            ) is not None
            for normalized in (_normalize_cvss_model_params(ctx, item) for item in aligned)
        ))
    feasibility_tokens = ctx.service('_dynamic_token_budget')('feasibility_cvss', len(attack_paths), system_prompt=system_prompt, user_prompt=user_prompt, record=True)
    _t_start = time.perf_counter()
    (parsed, _) = ctx.service('cached_llm_json')(bucket='attack_parameters_cvss_batch', cache_key=cache_key, system_prompt=system_prompt, user_prompt=user_prompt, default={'attack_parameters_list': []}, max_tokens=feasibility_tokens, validator=_valid_cvss_response)
    ctx.service('_add_phase_time')('feasibility', time.perf_counter() - _t_start)
    params_list = _align_path_parameter_list(ctx, parsed.get('attack_parameters_list', []), path_ids)
    results = []
    for (i, (ap, vec)) in enumerate(attack_paths):
        p = _normalize_cvss_model_params(ctx, params_list[i] if i < len(params_list) else {})
        entry = {'attack_vector': vec, 'complexity': str(p.get('complexity', '')).strip().lower(), 'privileges': str(p.get('privileges', '')).strip().lower(), 'user_interaction': str(p.get('user_interaction', '')).strip().lower()}
        if entry['complexity'] in CVSS_C and entry['privileges'] in CVSS_P and (entry['user_interaction'] in CVSS_U):
            if ctx.setting('ENABLE_REASON'):
                sanitized = sanitize_reason_fields(p, CVSS_REASON_KEYS)
                if sanitized is None:
                    results.append({})
                    continue
                for reason_key in CVSS_REASON_KEYS:
                    entry[reason_key] = sanitized[reason_key].strip()
            results.append(entry)
        else:
            results.append({})
            task.errors.append(f'CVSS 可行性评估: 路径 {i} 参数缺失或非法')
    if ctx.setting('ENABLE_REASON') and _allow_reason_retry:
        for (index, result) in enumerate(results):
            if result:
                continue
            retry = generate_attack_parameters_cvss_batch(ctx, task, [attack_paths[index]], _allow_reason_retry=False)
            if retry and retry[0]:
                results[index] = retry[0]
            else:
                task.errors.append(f'CVSS 可行性评估: 路径 {index} 理由补位重试失败')
        if all(results):
            task.errors = [error for error in task.errors if not error.startswith('CVSS 可行性评估: 路径')]
    return results

def _derived_window_reason(norm_vector: str) -> str:
    """机会窗口由代码按攻击向量直接映射派生，理由统一确定，不依赖 LLM。"""
    return f'攻击向量为"{norm_vector}"'


def _normalize_ap_model_params(ctx: RuntimeContext, item: Any, attack_vector: str) -> dict:
    """展开紧凑 AP 字段，并用可信拓扑派生机会窗口。"""
    if not isinstance(item, dict):
        return {}
    normalized = dict(item)
    aliases = {'Exposure_time': 'T', 'Professional_experience': 'X', 'Required_information': 'I', 'Required_equipment': 'Q'}
    for (full_name, short_name) in aliases.items():
        if full_name not in normalized and short_name in normalized:
            normalized[full_name] = normalized[short_name]
    normalized_vector = normalize_attack_vector(attack_vector)
    window = OPPORTUNITY_WINDOW_MAP.get(normalized_vector)
    if window is not None:
        normalized['Opportunity_window'] = window
        if ctx.setting('ENABLE_REASON'):
            normalized['Opportunity_window_reason'] = _derived_window_reason(normalized_vector)
    return normalized

def generate_attack_parameters_ap_batch(ctx: RuntimeContext, task: TaskUnit, attack_paths: list[tuple[str, str]], *, _allow_reason_retry: bool=True) -> list[dict]:
    """批量评估多条攻击路径的 Attack Potential 参数。
    默认每次评估最多 20 条路径；输出理由时使用单独的安全合批上限。
    当 SC_ENABLED 时，每 chunk 做多次采样取多数投票并记录置信度。

    Args:
        task: TaskUnit
        attack_paths: [(attack_path_text, attack_vector), ...]
    """
    max_paths_per_call = _max_paths_per_call(ctx)
    system_prompt = _implemented_rating_system_prompt(
        ctx.setting('AP_BATCH_SYSTEM_PROMPT', AP_BATCH_SYSTEM_PROMPT),
        [text for text, _ in attack_paths],
    )
    all_params: list[dict] = []
    all_confidences: list[dict] = []
    sc_used = False
    for chunk_start in range(0, len(attack_paths), max_paths_per_call):
        chunk = attack_paths[chunk_start:chunk_start + max_paths_per_call]
        chunk_path_ids = [f'{task.task_id}:path:{chunk_start + i}' for i in range(len(chunk))]
        paths_block = '\n\n'.join((f'[路径 {chunk_path_ids[i]}]\npath_id: {chunk_path_ids[i]}\n攻击路径: {ap}\n攻击向量: {vec}' for (i, (ap, vec)) in enumerate(chunk)))
        user_prompt = f'输入：\n- function: {task.function}\n- asset_name: {task.asset_name}\n- attribute_name: {task.attribute_name}\n- threat_scenarios: {task.threat_scenarios}\n\n多条攻击路径如下（攻击向量已由外部拓扑分析确定）：\n{paths_block}\n\n请为每条攻击路径分别分析并输出 T、X、I、Q 四个攻击潜力参数。\n每项必须原样返回 path_id，禁止省略、合并或改变顺序。\n不要输出 Opportunity_window；程序会根据攻击向量确定该值。'
        feasibility_tokens = ctx.service('_dynamic_token_budget')('feasibility_ap', len(chunk), system_prompt=system_prompt, user_prompt=user_prompt, record=True)
        if ctx.setting('SC_ENABLED') and ctx.setting('ENABLE_CONSISTENCY') and _allow_reason_retry:
            sc_used = True
            (chunk_params, chunk_conf) = _sc_ap_chunk(ctx, system_prompt, user_prompt, chunk_size=len(chunk), n_samples=ctx.setting('SC_SAMPLES'), path_ids=chunk_path_ids, item_normalizer=lambda item, position: _normalize_ap_model_params(ctx, item, chunk[position][1]))
            ctx.service('_add_phase_time')('feasibility', 0)
            if not chunk_params:
                task.errors.append(f'可行性评估 SC: 无有效采样（chunk {chunk_start}）')
                chunk_params = [{} for _ in chunk]
                chunk_conf = [{} for _ in chunk]
            missing_reasons = _populate_sc_feasibility_reasons(
                ctx, task, chunk, chunk_params, method='ap'
            )
            for position in missing_reasons:
                if 0 <= position < len(chunk_params):
                    # 按理由策略：理由缺失的路径不得进入最终风险计算；
                    # 不重新抽取其已经确定的数值，避免理由重试造成分值漂移。
                    chunk_params[position] = {}
                    task.errors.append(
                        f'可行性评估: 路径 {chunk_start + position} 理由补位重试失败'
                    )
            all_params.extend(chunk_params)
            all_confidences.extend(chunk_conf)
            continue
        cache_key = {'asset_name': task.asset_name, 'attack_paths': [(t, v) for (t, v) in chunk]}

        def _valid_ap_response(value: Any) -> bool:
            if isinstance(value, list):
                value = {'attack_parameters_list': value}
            if not isinstance(value, dict):
                return False
            aligned = _align_path_parameter_list(ctx, value.get('attack_parameters_list', []), chunk_path_ids)
            return bool(aligned) and all((bool(_impact_validated_numeric_params(ctx, _normalize_ap_model_params(ctx, item, chunk[position][1]), AP_ALLOWED_VALUES, AP_REASON_KEYS)) for (position, item) in enumerate(aligned)))
        _t_start = time.perf_counter()
        (parsed, _) = ctx.service('cached_llm_json')(bucket='attack_parameters_ap_batch', cache_key=cache_key, system_prompt=system_prompt, user_prompt=user_prompt, default={'attack_parameters_list': []}, max_tokens=feasibility_tokens, validator=_valid_ap_response)
        ctx.service('_add_phase_time')('feasibility', time.perf_counter() - _t_start)
        if isinstance(parsed, list):
            parsed = {'attack_parameters_list': parsed}
        params_list = _align_path_parameter_list(ctx, parsed.get('attack_parameters_list', []), chunk_path_ids)
        if not params_list:
            task.errors.append(f'可行性评估: LLM 返回空结果（chunk {chunk_start}）')
            all_params.extend([{} for _ in chunk])
            continue
        if len(params_list) < len(chunk):
            task.errors.append(f'可行性评估: 期望 {len(chunk)} 条，返回 {len(params_list)} 条')
        for i in range(len(chunk)):
            p = params_list[i] if i < len(params_list) else {}
            fixed = _impact_validated_numeric_params(ctx, _normalize_ap_model_params(ctx, p, chunk[i][1]), AP_ALLOWED_VALUES, AP_REASON_KEYS)
            if not fixed:
                task.errors.append(f'可行性评估: 路径 {chunk_start + i} 参数缺失或非法')
            all_params.append(fixed)
    if ctx.setting('ENABLE_REASON') and _allow_reason_retry and not sc_used:
        for (index, params) in enumerate(all_params):
            if _impact_validated_numeric_params(ctx, params, AP_ALLOWED_VALUES, AP_REASON_KEYS):
                continue
            retry = generate_attack_parameters_ap_batch(ctx, task, [attack_paths[index]], _allow_reason_retry=False)
            if retry and retry[0]:
                all_params[index] = retry[0]
            else:
                task.errors.append(f'可行性评估: 路径 {index} 理由补位重试失败')
        if all((_impact_validated_numeric_params(ctx, params, AP_ALLOWED_VALUES, AP_REASON_KEYS) for params in all_params)):
            task.errors = [error for error in task.errors if not error.startswith('可行性评估: LLM 返回空结果') and (not error.startswith('可行性评估: 路径'))]
    if ctx.setting('ENABLE_CONSISTENCY'):
        if all_confidences:
            task.feasibility_confidence = all_confidences
            for (ci, conf) in enumerate(all_confidences):
                overall = conf.get('_overall', 0.0)
                if overall < ctx.setting('SC_CONFIDENCE_THRESHOLD'):
                    task.low_confidence_flags.append(f"feasibility[AP][{ci}]: confidence={overall:.2f} < {ctx.setting('SC_CONFIDENCE_THRESHOLD')}")
    corrections = 0
    for (i, (_, vec)) in enumerate(attack_paths):
        if i >= len(all_params):
            break
        norm_vec = normalize_attack_vector(vec)
        if norm_vec in OPPORTUNITY_WINDOW_MAP:
            mapped = OPPORTUNITY_WINDOW_MAP[norm_vec]
            if all_params[i] and _safe_int(all_params[i].get('Opportunity_window', -1)) != mapped:
                all_params[i]['Opportunity_window'] = mapped
                if ctx.setting('ENABLE_REASON'):
                    all_params[i]['Opportunity_window_reason'] = _derived_window_reason(norm_vec)
                corrections += 1
    if corrections:
        logger.debug('AP 后处理: 修正 %d 个 Opportunity_window（对齐攻击向量）', corrections)
    return all_params

def _normalize_heavens_model_params(ctx: RuntimeContext, item: Any, attack_vector: str) -> dict:
    """展开紧凑模型字段，并用可信拓扑派生攻击窗口。"""
    if not isinstance(item, dict):
        return {}
    normalized = dict(item)
    aliases = {'Expertise': 'E', 'Knowledge_about_TOE': 'K', 'Equipment': 'Q'}
    for (full_name, short_name) in aliases.items():
        if full_name not in normalized and short_name in normalized:
            normalized[full_name] = normalized[short_name]
    window = _HEAVENS_WINDOW_BY_VECTOR.get(normalize_attack_vector(attack_vector))
    if window is not None:
        normalized['Window_of_Opportunity'] = window
        if ctx.setting('ENABLE_REASON'):
            normalized['Window_of_Opportunity_reason'] = _derived_window_reason(normalize_attack_vector(attack_vector))
    return normalized

def generate_attack_parameters_heavens_batch(ctx: RuntimeContext, task: TaskUnit, attack_paths: list[tuple[str, str]], *, _allow_reason_retry: bool=True) -> list[dict]:
    """批量评估多条攻击路径的 HEAVENS 四维可行性参数。
    与 generate_attack_parameters_ap_batch 结构相同，但使用 HEAVENS 维度定义和提示词。
    """
    max_paths_per_call = _max_paths_per_call(ctx)
    system_prompt = _implemented_rating_system_prompt(
        ctx.setting('HEAVENS_AP_BATCH_SYSTEM_PROMPT', HEAVENS_AP_BATCH_SYSTEM_PROMPT),
        [text for text, _ in attack_paths],
    )
    all_params: list[dict] = []
    all_confidences: list[dict] = []
    sc_used = False
    for chunk_start in range(0, len(attack_paths), max_paths_per_call):
        chunk = attack_paths[chunk_start:chunk_start + max_paths_per_call]
        chunk_path_ids = [f'{task.task_id}:path:{chunk_start + i}' for i in range(len(chunk))]
        paths_block = '\n\n'.join((f'[路径 {chunk_path_ids[i]}]\npath_id: {chunk_path_ids[i]}\n攻击路径: {ap}\n攻击向量: {vec}' for (i, (ap, vec)) in enumerate(chunk)))
        user_prompt = f'输入：\n- function: {task.function}\n- asset_name: {task.asset_name}\n- attribute_name: {task.attribute_name}\n- threat_scenarios: {task.threat_scenarios}\n\n多条攻击路径如下（攻击向量已由外部拓扑分析确定）：\n{paths_block}\n\n请为每条攻击路径分别分析并输出 HEAVENS 的 E、K、Q 三个参数（0-3）。\n每项必须原样返回 path_id，禁止省略、合并或改变顺序。\n不要输出 Window_of_Opportunity；程序会根据攻击向量确定该值。'
        feasibility_tokens = ctx.service('_dynamic_token_budget')('feasibility_heavens', len(chunk), system_prompt=system_prompt, user_prompt=user_prompt, record=True)
        if ctx.setting('SC_ENABLED') and ctx.setting('ENABLE_CONSISTENCY') and _allow_reason_retry:
            sc_used = True
            heavens_reason_keys = ('Expertise_reason', 'Knowledge_about_TOE_reason', 'Window_of_Opportunity_reason', 'Equipment_reason')
            numeric_system_prompt = _sc_numeric_only_prompt(system_prompt, heavens_reason_keys)
            (chunk_params, chunk_conf) = _sc_ap_chunk(ctx, system_prompt, user_prompt, chunk_size=len(chunk), n_samples=ctx.setting('SC_SAMPLES'), allowed_values=HEAVENS_AP_ALLOWED_VALUES, reason_keys=heavens_reason_keys, path_ids=chunk_path_ids, item_normalizer=lambda item, position: _normalize_heavens_model_params(ctx, item, chunk[position][1]))
            ctx.service('_add_phase_time')('feasibility', 0)
            if not chunk_params:
                task.errors.append(f'HEAVENS 可行性评估 SC: 无有效采样（chunk {chunk_start}）')
                try:
                    retry_raw = ctx.service('llm_call_with_semaphore')(numeric_system_prompt, user_prompt, retries=2, max_tokens=feasibility_tokens)
                    if retry_raw and retry_raw.strip() not in ('', '{}'):
                        rp = safe_parse_json(retry_raw)
                        if isinstance(rp, list):
                            rp = {'attack_parameters_list': rp}
                        rpl = _align_path_parameter_list(ctx, rp.get('attack_parameters_list', []), chunk_path_ids)
                        chunk_params = []
                        chunk_conf = []
                        for pi in range(len(chunk)):
                            if pi < len(rpl) and rpl[pi]:
                                fixed = _impact_validated_numeric_params(ctx, _normalize_heavens_model_params(ctx, rpl[pi], chunk[pi][1]), HEAVENS_AP_ALLOWED_VALUES, ())
                                chunk_params.append(fixed)
                                chunk_conf.append({k: 0.0 for k in HEAVENS_AP_ALLOWED_VALUES})
                                chunk_conf[-1]['_overall'] = 0.0
                            else:
                                chunk_params.append({})
                                chunk_conf.append({'_overall': 0.0})
                        logger.info('HEAVENS AP SC: 回退单次调用成功（chunk %d）', chunk_start)
                except Exception:
                    pass
                if not chunk_params or all((not cp for cp in chunk_params)):
                    chunk_params = [{} for _ in chunk]
                    chunk_conf = [{} for _ in chunk]
            retried = 0
            allowed_vals = HEAVENS_AP_ALLOWED_VALUES
            for pi in range(len(chunk_params)):
                if not _impact_validated_numeric_params(ctx, chunk_params[pi], allowed_vals, ()):
                    try:
                        single_raw = ctx.service('llm_call_with_semaphore')(numeric_system_prompt, user_prompt, retries=2, max_tokens=feasibility_tokens)
                        if single_raw and single_raw.strip() not in ('', '{}'):
                            sp = safe_parse_json(single_raw)
                            if isinstance(sp, list):
                                sp = {'attack_parameters_list': sp}
                            spl = _align_path_parameter_list(ctx, sp.get('attack_parameters_list', []), chunk_path_ids)
                            if pi < len(spl) and spl[pi]:
                                fixed = _impact_validated_numeric_params(ctx, _normalize_heavens_model_params(ctx, spl[pi], chunk[pi][1]), allowed_vals, ())
                                if not fixed:
                                    continue
                                chunk_params[pi] = fixed
                                chunk_conf[pi] = {k: 0.0 for k in allowed_vals}
                                chunk_conf[pi]['_overall'] = 0.0
                                retried += 1
                    except Exception:
                        pass
            if retried:
                logger.info('HEAVENS AP SC: 补位重试 %d 个位置（chunk %d）', retried, chunk_start)
            missing_reasons = _populate_sc_feasibility_reasons(
                ctx, task, chunk, chunk_params, method='heavens'
            )
            for position in missing_reasons:
                if 0 <= position < len(chunk_params):
                    chunk_params[position] = {}
                    task.errors.append(
                        f'HEAVENS 可行性评估: 路径 {chunk_start + position} 理由补位重试失败'
                    )
            all_params.extend(chunk_params)
            all_confidences.extend(chunk_conf)
            continue
        cache_key = {'asset_name': task.asset_name, 'attack_paths': [(t, v) for (t, v) in chunk]}

        def _valid_heavens_response(value: Any) -> bool:
            if isinstance(value, list):
                value = {'attack_parameters_list': value}
            if not isinstance(value, dict):
                return False
            aligned = _align_path_parameter_list(ctx, value.get('attack_parameters_list', []), chunk_path_ids)
            return bool(aligned) and all((bool(_impact_validated_numeric_params(ctx, _normalize_heavens_model_params(ctx, item, chunk[position][1]), HEAVENS_AP_ALLOWED_VALUES, HEAVENS_REASON_KEYS)) for (position, item) in enumerate(aligned)))
        _t_start = time.perf_counter()
        (parsed, _) = ctx.service('cached_llm_json')(bucket='attack_parameters_heavens_batch', cache_key=cache_key, system_prompt=system_prompt, user_prompt=user_prompt, default={'attack_parameters_list': []}, max_tokens=feasibility_tokens, validator=_valid_heavens_response)
        ctx.service('_add_phase_time')('feasibility', time.perf_counter() - _t_start)
        if isinstance(parsed, list):
            parsed = {'attack_parameters_list': parsed}
        params_list = _align_path_parameter_list(ctx, parsed.get('attack_parameters_list', []), chunk_path_ids)
        if not params_list:
            task.errors.append(f'HEAVENS 可行性评估: LLM 返回空结果（chunk {chunk_start}）')
            all_params.extend([{} for _ in chunk])
            continue
        if len(params_list) < len(chunk):
            task.errors.append(f'HEAVENS 可行性评估: 期望 {len(chunk)} 条，返回 {len(params_list)} 条')
        for i in range(len(chunk)):
            p = params_list[i] if i < len(params_list) else {}
            fixed = _impact_validated_numeric_params(ctx, _normalize_heavens_model_params(ctx, p, chunk[i][1]), HEAVENS_AP_ALLOWED_VALUES, HEAVENS_REASON_KEYS)
            if not fixed:
                task.errors.append(f'HEAVENS 可行性评估: 路径 {chunk_start + i} 参数缺失或非法')
            all_params.append(fixed)
    if ctx.setting('ENABLE_REASON') and _allow_reason_retry and not sc_used:
        for (index, params) in enumerate(all_params):
            if _impact_validated_numeric_params(ctx, params, HEAVENS_AP_ALLOWED_VALUES, HEAVENS_REASON_KEYS):
                continue
            retry = generate_attack_parameters_heavens_batch(ctx, task, [attack_paths[index]], _allow_reason_retry=False)
            if retry and retry[0]:
                all_params[index] = retry[0]
            else:
                task.errors.append(f'HEAVENS 可行性评估: 路径 {index} 理由补位重试失败')
        if all((_impact_validated_numeric_params(ctx, params, HEAVENS_AP_ALLOWED_VALUES, HEAVENS_REASON_KEYS) for params in all_params)):
            task.errors = [error for error in task.errors if not error.startswith('HEAVENS 可行性评估: LLM 返回空结果') and (not error.startswith('HEAVENS 可行性评估: 路径'))]
    if ctx.setting('ENABLE_CONSISTENCY'):
        if all_confidences:
            task.feasibility_confidence = all_confidences
            for (ci, conf) in enumerate(all_confidences):
                overall = conf.get('_overall', 0.0)
                if overall < ctx.setting('SC_CONFIDENCE_THRESHOLD'):
                    task.low_confidence_flags.append(f"feasibility[HEAVENS][{ci}]: confidence={overall:.2f} < {ctx.setting('SC_CONFIDENCE_THRESHOLD')}")
    corrections = 0
    for (i, (_, vec)) in enumerate(attack_paths):
        if i >= len(all_params):
            break
        norm_vec = normalize_attack_vector(vec)
        mapped = _HEAVENS_WINDOW_BY_VECTOR.get(norm_vec)
        if mapped is not None and all_params[i]:
            cur = _safe_int(all_params[i].get('Window_of_Opportunity', -1))
            if cur != mapped:
                all_params[i]['Window_of_Opportunity'] = mapped
                if ctx.setting('ENABLE_REASON'):
                    all_params[i]['Window_of_Opportunity_reason'] = _derived_window_reason(norm_vec)
                corrections += 1
    if corrections:
        logger.debug('HEAVENS 后处理: 修正 %d 个 Window_of_Opportunity（对齐攻击向量）', corrections)
    return all_params

def _topology_trace(task: TaskUnit, path_index: int) -> dict:
    """Return internal route provenance without exposing it in prose fields."""

    if path_index >= len(task.selected_path_frameworks):
        return {"channel_ids": [], "raw_link_ids_by_hop": []}
    framework = task.selected_path_frameworks[path_index]
    return {
        # These fields make the path-to-requirement binding auditable.  The
        # framework is selected by trusted topology code; report matching must
        # not reconstruct an interface from the task-wide interface union.
        "path_id": str(framework.get("path_id") or ""),
        "external_interface": str(framework.get("external_interface") or ""),
        "start_component": str(framework.get("start_component") or ""),
        "attack_vector": normalize_attack_vector(
            framework.get("attack_vector", "")
        ),
        "channel_ids": list(framework.get("path_channel_ids") or []),
        "raw_link_ids_by_hop": [
            list(link_ids or [])
            for link_ids in (framework.get("topology_link_ids") or [])
        ],
    }


def _path_provenance_fields(task: TaskUnit, index: int) -> dict:
    provenance = (
        task.attack_path_provenance[index]
        if index < len(task.attack_path_provenance or [])
        else {}
    )
    provenance = provenance if isinstance(provenance, dict) else {}
    source = str(provenance.get("generation_source") or "")
    model_generated = source in {"llm_complete", "cache_llm_complete"}
    fallback = source == "template_fallback"
    review_required = not model_generated
    reason = str(provenance.get("fallback_reason") or "")
    if review_required and not reason:
        reason = "missing_generation_record"
    return {
        "attack_path_source": (
            "模板兜底" if fallback else
            "模型生成" if model_generated else "来源待核验"
        ),
        "attack_path_generation_source": source or "unknown",
        "attack_path_fallback_reason": reason if review_required else "",
        "review_required": review_required,
        "review_reasons": [f"攻击路径来源待复核：{reason}"] if review_required else [],
    }


def _build_feasibility_details(ctx: RuntimeContext, task: TaskUnit, paths: list[dict], all_params: list[dict], method: str) -> list[dict]:
    """把已校验的可行性参数转换为攻击详情；空参数保持为空，不伪造低风险。"""
    details = []
    for (ai, path) in enumerate(paths):
        params = dict(all_params[ai]) if ai < len(all_params) and all_params[ai] else {}
        if not params:
            continue
        # 机会窗口/Window_of_Opportunity 由代码按攻击向量直接映射派生，值+理由统一确定，不依赖 LLM 输出
        if method != 'cvss':
            norm_vector = normalize_attack_vector(path['vector'])
            if method == 'heavens':
                derived_window = _HEAVENS_WINDOW_BY_VECTOR.get(norm_vector)
                window_key, reason_key = 'Window_of_Opportunity', 'Window_of_Opportunity_reason'
            else:
                derived_window = OPPORTUNITY_WINDOW_MAP.get(norm_vector)
                window_key, reason_key = 'Opportunity_window', 'Opportunity_window_reason'
            if derived_window is not None:
                params[window_key] = derived_window
                if ctx.setting('ENABLE_REASON'):
                    params[reason_key] = _derived_window_reason(norm_vector)
        if method == 'cvss':
            score = calculate_cvss_score(params)
            level = calculate_cvss_level(score)
            params['complexity'] = CVSS_C.get(params.get('complexity', 'high'), 0.44)
            params['privileges'] = CVSS_P.get(params.get('privileges', 'none'), 0.85)
            params['user_interaction'] = CVSS_U.get(params.get('user_interaction', 'none'), 0.85)
            risk_value_num = calculate_risk_value(ctx.service('impact_risk_index')(task.impact_value, task.impact_level), level)
            risk_value = risk_value_num
        elif method == 'heavens':
            params['attack_vector'] = path['vector']
            score = calculate_heavens_ap_score(params)
            level = calculate_heavens_ap_level(score)
            if ctx.setting('IMPACT_METHOD') == 'heavens':
                (risk_value, risk_value_num) = calculate_heavens_risk_value(task.impact_level, level)
            else:
                risk_level = _HEAVENS_TL_TO_FEASIBILITY.get(level, 'Very Low')
                risk_value_num = calculate_risk_value(ctx.service('impact_risk_index')(task.impact_value, task.impact_level), risk_level)
                risk_value = risk_value_num
        else:
            params['attack_vector'] = path['vector']
            score = calculate_attack_potential_score(params)
            level = calculate_attack_potential_level(score)
            risk_value_num = calculate_risk_value(ctx.service('impact_risk_index')(task.impact_value, task.impact_level), level)
            risk_value = risk_value_num
        details.append({'attack_path': path['text'], 'attack_parameters': params, 'attack_vector': normalize_attack_vector(path.get('vector', '')), 'feasibility_score': score, 'feasibility_level': level, 'risk_value': risk_value, 'risk_value_num': risk_value_num, 'risk_treatment': get_risk_treatment(risk_value_num), 'feasibility_confidence': task.feasibility_confidence[ai] if ai < len(task.feasibility_confidence) else {}, 'topology_trace': _topology_trace(task, ai), **_path_provenance_fields(task, ai)})
    return details

def _apply_feasibility_result(ctx: RuntimeContext, task: TaskUnit, paths: list[dict], all_params: list[dict], method: str) -> None:
    """原子写回一个任务；任一路径缺失时不保留可能误导的风险值。"""
    details = _build_feasibility_details(ctx, task, paths, all_params, method)
    task.attack_details = details
    if details and len(details) == len(paths):
        task.analysis_status = STATUS_VALID
        task.risk_value = max((detail['risk_value_num'] for detail in details))
        task.risk_treatment = get_risk_treatment(task.risk_value)
        # 任务可能来自一个旧的 Stage C checkpoint：本次重试已经完整写回
        # 结果时，清除只描述上一次不完整评级的诊断，避免最终 VALID 任务
        # 继续出现在异常报告中。
        failure_prefix = f'{method} 可行性评级未完整覆盖路径：'
        task.errors = [
            error for error in task.errors
            if not str(error).startswith(failure_prefix)
        ]
        task.status_reasons = [
            reason for reason in task.status_reasons
            if reason not in {
                '攻击可行性评估结果缺失、非法或未完整覆盖路径',
                '攻击可行性评估执行失败',
            }
        ]
        return
    valid_count = len(details)
    logger.warning(
        '可行性评级写回失败 task=%s method=%s: expected_paths=%d valid_results=%d returned_slots=%d',
        task.task_id, method, len(paths), valid_count, len(all_params),
    )
    detail_error = (
        f'{method} 可行性评级未完整覆盖路径：期望 {len(paths)} 条，'
        f'有效 {valid_count} 条，返回槽位 {len(all_params)} 条'
    )
    if detail_error not in task.errors:
        task.errors.append(detail_error)
    for detail in details:
        detail.pop('risk_value', None)
        detail.pop('risk_value_num', None)
        detail.pop('risk_treatment', None)
        detail['assessment_status'] = STATUS_MODEL_FAILED
    task.analysis_status = STATUS_MODEL_FAILED
    reason = '攻击可行性评估结果缺失、非法或未完整覆盖路径'
    if reason not in task.status_reasons:
        task.status_reasons.append(reason)
    task.risk_value = None
    task.risk_treatment = '需复核'

def _cross_task_feasibility_prompt(ctx: RuntimeContext, method: str, items: list[dict]) -> str:
    """构造紧凑分组 JSON：任务上下文只写一次，避免 20 路径批次越过 4096。"""
    task_groups: list[dict] = []
    current_group: dict | None = None
    for item in items:
        task = item['task']
        if current_group is None or current_group['_task_index'] != item['task_index']:
            # Stage C 的评级主要依据资产、资产类型、属性和已经展开的攻击路径。
            # function/threat 在攻击路径阶段已经被吸收，重复放入每个跨任务
            # 批次会明显挤占 4096 上下文，导致批次被迫缩小和截断。
            current_group = {
                '_task_index': item['task_index'],
                'task_id': task.task_id,
                'asset': task.asset_name,
                'asset_type': task.asset_type,
                'attribute': task.attribute_name,
                'paths': [],
            }
            task_groups.append(current_group)
        current_group['paths'].append({'path_id': item['path_id'], 'attack_path': item['text'], 'attack_vector': item['vector']})
    for group in task_groups:
        group.pop('_task_index', None)
    if method == 'cvss':
        instruction = '分别用 C、P、U 输出 CVSS 可利用性参数。'
    elif method == 'heavens':
        instruction = '分别输出 HEAVENS 的 E、K、Q 参数；不要输出 Window_of_Opportunity，程序会按攻击向量确定。'
    else:
        instruction = '分别输出 T、X、I、Q 攻击潜力参数；不要输出 Opportunity_window，程序会按攻击向量确定。'
    return (
        f'请独立评估以下 {len(items)} 条攻击路径。不同任务的上下文不得混用，'
        '即使文本相似也必须独立评级。\n'
        + orjson.dumps(task_groups).decode('utf-8')
        + f'\n{instruction}\n'
        '每项必须原样返回 path_id；禁止省略、合并、复制其他路径结论或改变顺序。\n'
        '理由只写对应分值的核心依据，使用 12-32 个汉字（英文不超过 48 个字符），'
        '禁止复述攻击路径或输出额外解释。'
    )


def _partition_cross_task_items(
    ctx: RuntimeContext,
    method: str,
    items: list[dict],
) -> list[list[dict]]:
    """按真实 Prompt 长度自适应装箱，避免超上下文后再靠重试拆分。"""
    if not items:
        return []
    limit = _max_paths_per_call(ctx)
    stage = {
        'cvss': 'feasibility_cvss',
        'heavens': 'feasibility_heavens',
    }.get(method, 'feasibility_ap')
    system_prompt = _cross_task_system_prompt(ctx, method, items)
    profile = TOKEN_PROFILES[stage]
    per_item = (
        profile.per_item_with_reasons
        if ctx.setting('ENABLE_REASON')
        else profile.per_item
    )
    context_limit = int(ctx.setting('MODEL_CONTEXT_TOKENS', 4096))
    batches: list[list[dict]] = []
    current: list[dict] = []

    def fits(candidate: list[dict]) -> bool:
        prompt = _cross_task_feasibility_prompt(ctx, method, candidate)
        desired_output = profile.base + per_item * len(candidate)
        return (
            estimate_prompt_tokens(system_prompt, prompt)
            + desired_output + 384 <= context_limit
        )

    for item in items:
        if not fits([item]):
            original = str(item['text'])
            for limit_chars in (1600, 800, 400, 200):
                if len(original) <= limit_chars:
                    continue
                half = limit_chars // 2
                compressed = {
                    **item,
                    'text': (
                        original[:half]
                        + '\n[中间步骤已压缩，仅用于可行性评分]\n'
                        + original[-half:]
                    ),
                }
                if fits([compressed]):
                    item = compressed
                    ctx.service('_increment_pipeline_metric')(
                        'feasibility_path_context_compressions'
                    )
                    break
            if not fits([item]):
                # Keep the ID in the batch so the existing partial-result
                # handler marks only this path MODEL_FAILED. The budget guard
                # rejects it before HTTP, while other paths still complete.
                item['task'].errors.append(
                    f"feasibility_context_overflow: {item['path_id']} "
                    f"超过 {context_limit} tokens"
                )
                ctx.service('_increment_pipeline_metric')(
                    'feasibility_path_context_overflows'
                )
        candidate = [*current, item]
        if current and (len(candidate) > limit or not fits(candidate)):
            batches.append(current)
            current = [item]
        else:
            current = candidate
    if current:
        batches.append(current)
    return batches


def _validate_cross_task_feasibility_item(ctx: RuntimeContext, method: str, item: dict, raw_params: Any) -> dict:
    """规范化并严格校验跨任务批量返回的一项。"""
    vector = item['vector']
    if method == 'cvss':
        normalized = _normalize_cvss_model_params(ctx, raw_params)
        result = {'attack_vector': vector, 'complexity': str(normalized.get('complexity', '')).strip().lower(), 'privileges': str(normalized.get('privileges', '')).strip().lower(), 'user_interaction': str(normalized.get('user_interaction', '')).strip().lower()}
        if result['complexity'] not in CVSS_C or result['privileges'] not in CVSS_P or result['user_interaction'] not in CVSS_U:
            return {}
        if ctx.setting('ENABLE_REASON'):
            sanitized = sanitize_reason_fields(normalized, CVSS_REASON_KEYS)
            if sanitized is None:
                return {}
            for key in CVSS_REASON_KEYS:
                result[key] = sanitized[key].strip()
        return result
    if method == 'heavens':
        return _impact_validated_numeric_params(ctx, _normalize_heavens_model_params(ctx, raw_params, vector), HEAVENS_AP_ALLOWED_VALUES, HEAVENS_REASON_KEYS)
    return _impact_validated_numeric_params(ctx, _normalize_ap_model_params(ctx, raw_params, vector), AP_ALLOWED_VALUES, AP_REASON_KEYS)


def _validate_cross_task_feasibility_item_minimal(
    ctx: RuntimeContext, method: str, item: dict, raw_params: Any, *, reason_keys: tuple
) -> dict:
    """跨任务批量场景：校验时排除由代码派生的 Opportunity_window_reason 等字段。"""
    vector = item['vector']
    if method == 'cvss':
        normalized = _normalize_cvss_model_params(ctx, raw_params)
        result = {'attack_vector': vector, 'complexity': str(normalized.get('complexity', '')).strip().lower(), 'privileges': str(normalized.get('privileges', '')).strip().lower(), 'user_interaction': str(normalized.get('user_interaction', '')).strip().lower()}
        if result['complexity'] not in CVSS_C or result['privileges'] not in CVSS_P or result['user_interaction'] not in CVSS_U:
            return {}
        if ctx.setting('ENABLE_REASON'):
            sanitized = sanitize_reason_fields(normalized, reason_keys)
            if sanitized is None:
                return {}
            for key in reason_keys:
                if key in sanitized:
                    result[key] = str(sanitized[key]).strip()
        return result
    if method == 'heavens':
        return _impact_validated_numeric_params(ctx, _normalize_heavens_model_params(ctx, raw_params, vector), HEAVENS_AP_ALLOWED_VALUES, reason_keys)
    return _impact_validated_numeric_params(ctx, _normalize_ap_model_params(ctx, raw_params, vector), AP_ALLOWED_VALUES, reason_keys)


def _cross_task_system_prompt(
    ctx: RuntimeContext, method: str, items: list[dict] | None = None,
) -> str:
    """返回当前运行的 Stage C Prompt，并对实施后复评附加专用约束。"""
    base = {
        'cvss': ctx.setting('CVSS_BATCH_SYSTEM_PROMPT', CVSS_BATCH_SYSTEM_PROMPT),
        'heavens': ctx.setting(
            'HEAVENS_AP_BATCH_SYSTEM_PROMPT', HEAVENS_AP_BATCH_SYSTEM_PROMPT
        ),
    }.get(method, ctx.setting('AP_BATCH_SYSTEM_PROMPT', AP_BATCH_SYSTEM_PROMPT))
    return _implemented_rating_system_prompt(
        base, [str(item.get('text') or '') for item in (items or [])]
    )


def _cross_task_reason_keys(method: str) -> tuple[str, ...]:
    """跨任务结果的理由字段；Window_of_Opportunity 由代码派生。"""
    return {
        'cvss': CVSS_REASON_KEYS,
        'heavens': (
            'Expertise_reason',
            'Knowledge_about_TOE_reason',
            'Window_of_Opportunity_reason',
            'Equipment_reason',
        ),
    }.get(method, (
        'Exposure_time_reason',
        'Professional_experience_reason',
        'Required_information_reason',
        'Required_equipment_reason',
    ))


def _cross_task_item_cache_spec(
    ctx: RuntimeContext, method: str, item: dict
) -> tuple[str, dict, str, str, int]:
    """构造单路径语义缓存键。

    批次缓存只能复用完全相同的装箱结果；一条路径在批次拆分、失败修复或
    checkpoint 恢复后很容易落入不同批次。单路径缓存允许复用已经验证的
    结果，同时不改变首次运行的请求数量。
    """
    # Lookups need only dependency references. Build prompts and estimate
    # context tokens later, for the paths that actually need a model call.
    system_prompt = _cross_task_system_prompt(ctx, method, [item])
    task = item['task']
    key = stage_key(ctx, task, 'feasibility', system_prompt,
                    parents={'attack_path': path_reference(task, item['path_index'], item['text'])},
                    frameworks=task.selected_path_frameworks[item['path_index']:item['path_index'] + 1],
                    settings={'method': method, 'attack_vector': item['vector']})
    return (
        f'attack_parameters_{method}_item',
        key,
        system_prompt,
        '',
        0,
    )

def _retry_single_feasibility_item(ctx: RuntimeContext, method: str, item: dict) -> dict:
    """只重试批量中未通过校验的路径，防止整批成功结果被重复生成。"""
    task = item['task']
    path = [(item['text'], item['vector'])]
    with ctx.shared('stage_c_llm_semaphore'):
        if method == 'cvss':
            result = ctx.service("generate_attack_parameters_cvss_batch")(
                task, path, _allow_reason_retry=False
            )
        elif method == 'heavens':
            result = ctx.service("generate_attack_parameters_heavens_batch")(
                task, path, _allow_reason_retry=False
            )
        else:
            result = ctx.service("generate_attack_parameters_ap_batch")(
                task, path, _allow_reason_retry=False
            )
    return result[0] if result and result[0] else {}


def _record_feasibility_dependency(ctx, method, item, params):
    _, key, _, _, _ = _cross_task_item_cache_spec(ctx, method, item)
    name = 'feasibility:' + method + ':' + digest_json(key['dependencies']['parents'])
    record_result(item['task'], name, key, params)

def _cross_task_feasibility_response_format(ctx: RuntimeContext, method: str, path_ids: list[str]) -> dict:
    if method == 'cvss':
        properties: dict[str, dict] = {'path_id': {'type': 'string', 'enum': path_ids}, 'C': {'type': 'string', 'enum': ['Low', 'High', 'low', 'high']}, 'P': {'type': 'string', 'enum': ['None', 'Low', 'High', 'none', 'low', 'high']}, 'U': {'type': 'string', 'enum': ['None', 'Required', 'none', 'required']}}
        required = ['path_id', 'C', 'P', 'U']
        reason_keys = CVSS_REASON_KEYS
    elif method == 'heavens':
        properties = {'path_id': {'type': 'string', 'enum': path_ids}, 'E': {'type': 'integer', 'enum': [0, 1, 2, 3]}, 'K': {'type': 'integer', 'enum': [0, 1, 2, 3]}, 'Q': {'type': 'integer', 'enum': [0, 1, 2, 3]}}
        required = ['path_id', 'E', 'K', 'Q']
        reason_keys = ('Expertise_reason', 'Knowledge_about_TOE_reason', 'Equipment_reason')
    else:
        properties = {'path_id': {'type': 'string', 'enum': path_ids}, 'T': {'type': 'integer', 'enum': AP_ALLOWED_VALUES['Exposure_time']}, 'X': {'type': 'integer', 'enum': AP_ALLOWED_VALUES['Professional_experience']}, 'I': {'type': 'integer', 'enum': AP_ALLOWED_VALUES['Required_information']}, 'Q': {'type': 'integer', 'enum': AP_ALLOWED_VALUES['Required_equipment']}}
        required = ['path_id', 'T', 'X', 'I', 'Q']
        reason_keys = ('Exposure_time_reason', 'Professional_experience_reason', 'Required_information_reason', 'Required_equipment_reason')
    if ctx.setting('ENABLE_REASON'):
        for reason_key in reason_keys:
            # 不能用 maxLength：vLLM 在字符上限处硬截断字符串后，模型会继续输出
            # 制表符等填充直至 max_tokens，导致 JSON 尾部不完整、整批作废。
            # 超长理由由校验层 reason_fields_valid(≤RATING_REASON_MAX_CHARS) 丢弃后
            # 走已有的 partial retry / 逐路径修复。
            properties[reason_key] = {'type': 'string', 'minLength': 2}
        required.extend(reason_keys)
    return {'type': 'json_schema', 'json_schema': {'name': f'tara_{method}_cross_task_batch', 'strict': True, 'schema': {'type': 'object', 'properties': {'attack_parameters_list': {'type': 'array', 'minItems': len(path_ids), 'maxItems': len(path_ids), 'items': {'type': 'object', 'properties': properties, 'required': required, 'additionalProperties': False}}}, 'required': ['attack_parameters_list'], 'additionalProperties': False}}}

def _generate_cross_task_feasibility_batch(
    ctx: RuntimeContext,
    method: str,
    items: list[dict],
    *,
    _allow_partial_retry: bool = True,
) -> list[dict]:
    """一次调用评估多个任务的路径，并按全局 path_id 安全对齐。"""
    system_prompt = _cross_task_system_prompt(ctx, method, items)
    bucket = f'attack_parameters_{method}_cross_task_batch'
    user_prompt = _cross_task_feasibility_prompt(ctx, method, items)
    path_ids = [item['path_id'] for item in items]
    cache_key = {'method': method, 'paths': [(item['path_id'], item['task'].function, item['task'].asset_name, item['task'].attribute_name, item['task'].threat_scenarios, item['text'], item['vector']) for item in items]}
    token_stage = {'cvss': 'feasibility_cvss', 'heavens': 'feasibility_heavens'}.get(method, 'feasibility_ap')
    feasibility_tokens = ctx.service('_dynamic_token_budget')(token_stage, len(items), system_prompt=system_prompt, user_prompt=user_prompt, record=True)
    versioned_key = ctx.service('_build_llm_cache_key')(cache_key, system_prompt, user_prompt, feasibility_tokens)
    parsed = ctx.shared('semantic_cache').get(bucket, versioned_key)
    cache_hit = parsed is not None

    def _request_batch() -> Any:
        """请求当前批次一次；缓存失效时也必须走同一条受控调用链。"""
        started = time.perf_counter()
        with ctx.shared('stage_c_llm_semaphore'):
            ctx.service('_increment_pipeline_metric')('stage_c_model_calls')
            raw = ctx.service('llm_call_with_semaphore')(system_prompt, user_prompt, max_tokens=feasibility_tokens, response_format=_cross_task_feasibility_response_format(ctx, method, path_ids))
        ctx.service('_add_phase_time')('feasibility', time.perf_counter() - started)
        try:
            return safe_parse_json(raw) if raw and raw.strip() not in ('', '{}') else {}
        except Exception as exc:
            logger.warning(
                '跨任务可行性 JSON 解析失败 method=%s paths=%d raw_chars=%d: %s',
                method,
                len(items),
                len(raw or ''),
                exc,
            )
            return {}

    if not cache_hit:
        parsed = _request_batch()
    if isinstance(parsed, list):
        parsed = {'attack_parameters_list': parsed}
    raw_list = parsed.get('attack_parameters_list', []) if isinstance(parsed, dict) else []
    params_list = _align_path_parameter_list(ctx, raw_list, path_ids)
    # 跨任务调用：Opportunity_window 由代码派生，无需校验其 reason
    method_reason_keys = _cross_task_reason_keys(method)
    results = [_validate_cross_task_feasibility_item_minimal(ctx, method, item, params_list[index] if index < len(params_list) else {}, reason_keys=method_reason_keys) for (index, item) in enumerate(items)]
    if all(results):
        if not cache_hit:
            ctx.shared('semantic_cache').set(bucket, versioned_key, {'attack_parameters_list': [{'path_id': item['path_id'], **result} for (item, result) in zip(items, results)]})
        return results
    if cache_hit:
        ctx.shared('semantic_cache').delete(bucket, versioned_key)
        logger.warning('跨任务可行性缓存校验失败并已删除: bucket=%s', bucket)
        # 旧缓存可能来自不同的提示词/理由策略或被中断写入。删除后必须
        # 立即重新请求当前批次，否则会把“缓存失效”误报成模型整批失败。
        cache_hit = False
        parsed = _request_batch()
        if isinstance(parsed, list):
            parsed = {'attack_parameters_list': parsed}
        raw_list = parsed.get('attack_parameters_list', []) if isinstance(parsed, dict) else []
        params_list = _align_path_parameter_list(ctx, raw_list, path_ids)
        results = [
            _validate_cross_task_feasibility_item_minimal(
                ctx,
                method,
                item,
                params_list[index] if index < len(params_list) else {},
                reason_keys=method_reason_keys,
            )
            for (index, item) in enumerate(items)
        ]
        if all(results):
            ctx.shared('semantic_cache').set(
                bucket,
                versioned_key,
                {'attack_parameters_list': [
                    {'path_id': item['path_id'], **result}
                    for (item, result) in zip(items, results)
                ]},
            )
            return results
    missing = [index for (index, result) in enumerate(results) if not result]
    if len(missing) == len(items):
        if _allow_partial_retry and len(items) > 1:
            # 整批 JSON 截断、结构化解码异常或全部字段非法时，同样的完整
            # prompt 在 temperature=0 下原样重试通常仍会失败。只做一层二分
            # 批量修复，改变输出规模并避免放大成 N 次逐路径请求。
            midpoint = (len(items) + 1) // 2
            split_batches = (items[:midpoint], items[midpoint:])
            logger.warning(
                '跨任务可行性 batch 整批无有效结果（%d 条），按 %d+%d 进行一次受限批量修复',
                len(items),
                len(split_batches[0]),
                len(split_batches[1]),
            )
            ctx.service('_increment_pipeline_metric')(
                'stage_c_repair_batches', len(split_batches)
            )
            ctx.service('_increment_pipeline_metric')(
                'stage_c_repair_paths', len(items)
            )
            repaired: list[dict] = []
            for split_items in split_batches:
                if not split_items:
                    continue
                repaired.extend(
                    _generate_cross_task_feasibility_batch(
                        ctx,
                        method,
                        split_items,
                        _allow_partial_retry=False,
                    )
                )
            recovered = sum(bool(item) for item in repaired)
            if recovered != len(items):
                logger.warning(
                    '跨任务可行性受限批量修复后仍缺失: recovered=%d expected=%d',
                    recovered,
                    len(items),
                )
            return repaired
        logger.warning(
            '跨任务可行性 batch 整批无有效结果（%d 条），受限批量修复已用尽，拒绝展开为逐路径请求',
            len(items),
        )
        return results
    if not _allow_partial_retry:
        return results
    logger.warning(
        '跨任务可行性 batch %d/%d 项缺失或非法，仅修复失败路径',
        len(missing),
        len(items),
    )
    if len(missing) > 1:
        repair_items = [items[index] for index in missing]
        ctx.service('_increment_pipeline_metric')('stage_c_repair_batches')
        ctx.service('_increment_pipeline_metric')(
            'stage_c_repair_paths', len(repair_items)
        )
        repaired = _generate_cross_task_feasibility_batch(
            ctx,
            method,
            repair_items,
            _allow_partial_retry=False,
        )
        for index, repaired_item in zip(missing, repaired):
            if repaired_item:
                results[index] = repaired_item
        # 修复批次自身仍部分失败时，未成功项降级为单项重试，避免任务永久失败。
        for index in missing:
            if results[index]:
                continue
            try:
                results[index] = ctx.service('_retry_single_feasibility_item')(method, items[index])
            except Exception as exc:
                logger.warning('可行性路径 %s 单项重试异常: %s', items[index]['path_id'], exc)
        return results
    for index in missing:
        try:
            results[index] = ctx.service('_retry_single_feasibility_item')(method, items[index])
        except Exception as exc:
            logger.warning('可行性路径 %s 单项重试异常: %s', items[index]['path_id'], exc)
    return results

def _stage_c_attack_cross_task(ctx: RuntimeContext, tasks: list[TaskUnit], jobs: list[dict], method: str, progress_callback: Callable[[int, int], None] | None) -> None:
    """跨任务合并 Stage C 路径，减少多路线任务造成的小请求。"""
    items = []
    for job in jobs:
        task = tasks[job['task_index']]
        for (path_index, path) in enumerate(job['paths']):
            items.append({'task': task, 'task_index': job['task_index'], 'path_index': path_index, 'path_id': f'{task.task_id}:path:{path_index}', **path})
    original_items_by_slot = {
        (item['task_index'], item['path_index']): item for item in items
    }

    # 批次缓存只在装箱完全一致时命中。Stage C 的路径通常在 checkpoint
    # 恢复或局部修复后重新装箱，因此再加一层已校验的单路径缓存，避免把
    # 同一条路径因为批次边界变化再次送入模型。
    params_by_task = {
        job['task_index']: [{} for _ in job['paths']] for job in jobs
    }
    remaining = {
        job['task_index']: len(job['paths']) for job in jobs
    }
    method_reason_keys = _cross_task_reason_keys(method)
    pending_items: list[dict] = []
    item_cache_hits = 0
    for item in items:
        bucket, cache_key, _, _, _ = _cross_task_item_cache_spec(
            ctx, method, item
        )
        cached = ctx.shared('semantic_cache').get(bucket, cache_key)
        if cached is not None:
            validated = _validate_cross_task_feasibility_item_minimal(
                ctx,
                method,
                item,
                cached,
                reason_keys=method_reason_keys,
            )
            if validated:
                params_by_task[item['task_index']][item['path_index']] = validated
                remaining[item['task_index']] -= 1
                item_cache_hits += 1
                continue
            # 旧版本或理由策略不同的单路径缓存不得污染本次结果。
            ctx.shared('semantic_cache').delete(bucket, cache_key)
        pending_items.append(item)
    if item_cache_hits:
        ctx.service('_increment_pipeline_metric')(
            'stage_c_item_cache_hits', item_cache_hits
        )
    if pending_items:
        ctx.service('_increment_pipeline_metric')(
            'stage_c_item_cache_misses', len(pending_items)
        )
    batches = _partition_cross_task_items(ctx, method, pending_items)
    ctx.service('_set_pipeline_metric')('stage_c_tasks', len(jobs))
    ctx.service('_set_pipeline_metric')('stage_c_paths', len(items))
    ctx.service('_set_pipeline_metric')('stage_c_batches_planned', len(batches))
    if batches:
        ctx.service('_set_pipeline_metric')(
            'stage_c_batch_size_max', max(map(len, batches))
        )
        ctx.service('_set_pipeline_metric')(
            'stage_c_batch_size_min', min(map(len, batches))
        )
    else:
        ctx.service('_set_pipeline_metric')('stage_c_batch_size_max', 0)
        ctx.service('_set_pipeline_metric')('stage_c_batch_size_min', 0)
    jobs_by_task = {job['task_index']: job for job in jobs}
    completed_tasks = 0
    total_tasks = len(jobs)
    last_flush_done = 0
    last_flush_at = time.monotonic()
    executor = ctx.service('get_executor')()
    submission_window = min(ctx.setting('MAX_PENDING_FUTURES'), max(1, ctx.setting('MAX_WORKERS') * 2))

    def _apply_if_complete(task_index: int) -> int:
        if remaining[task_index] != 0:
            return 0
        job = jobs_by_task[task_index]
        _apply_feasibility_result(
            ctx,
            tasks[task_index],
            job['paths'],
            params_by_task[task_index],
            method,
        )
        return 1

    # 全部路径都来自单路径缓存时，不应等待一个空的 Future 窗口。
    for task_index in jobs_by_task:
        completed_tasks += _apply_if_complete(task_index)

    for start in range(0, len(batches), submission_window):
        window = batches[start:start + submission_window]
        future_map = {ctx.service('_submit_pipeline')(executor, partial(_generate_cross_task_feasibility_batch, ctx), method, batch): batch for batch in window}
        for future in as_completed(future_map):
            batch = future_map[future]
            try:
                results = future.result()
            except Exception as exc:
                logger.warning('Stage C 跨任务 batch 执行异常: %s', exc)
                results = [{} for _ in batch]
            if not isinstance(results, list):
                results = []
            if len(results) < len(batch):
                results = results + [{} for _ in range(len(batch) - len(results))]
            for (item, result) in zip(batch, results):
                task_index = item['task_index']
                params_by_task[task_index][item['path_index']] = result
                remaining[task_index] -= 1
                if result:
                    bucket, cache_key, _, _, _ = _cross_task_item_cache_spec(
                        ctx, method,
                        original_items_by_slot[
                            (item['task_index'], item['path_index'])
                        ],
                    )
                    ctx.shared('semantic_cache').set(bucket, cache_key, result)
                completed_tasks += _apply_if_complete(task_index)
            now = time.monotonic()
            if progress_callback is not None and (completed_tasks - last_flush_done >= ctx.setting('STAGE_C_CACHE_FLUSH_TASKS') or now - last_flush_at >= ctx.setting('STAGE_C_CACHE_FLUSH_SECONDS')):
                try:
                    progress_callback(completed_tasks, total_tasks)
                except Exception as exc:
                    logger.warning('Stage C 增量缓存回调失败: %s', exc)
                else:
                    last_flush_done = completed_tasks
                    last_flush_at = now
    # 批量与二分修复仍可能同时失败（例如 JSON 截断）。只对最终未获得
    # 有效模型评分的路径再做有上限的单路径请求；成功路径不重复调用。
    unresolved = [
        item for item in items
        if not params_by_task[item['task_index']][item['path_index']]
    ]
    retry_items_by_slot = {
        (item['task_index'], item['path_index']): item
        for batch in batches for item in batch
    }
    final_retry_limit = max(
        0, int(ctx.setting('STAGE_C_FINAL_RETRY_MAX_PATHS', 32))
    )
    if len(unresolved) > final_retry_limit:
        ctx.service('_increment_pipeline_metric')(
            'stage_c_final_retry_skipped',
            len(unresolved) - final_retry_limit,
        )
    recovered_tasks: set[int] = set()
    for item in unresolved[:final_retry_limit]:
        try:
            repaired = ctx.service('_retry_single_feasibility_item')(
                method,
                retry_items_by_slot.get(
                    (item['task_index'], item['path_index']), item
                ),
            )
        except Exception as exc:
            logger.warning(
                'Stage C 最终单路径补救失败 path_id=%s: %s',
                item['path_id'], exc,
            )
            continue
        validated = _validate_cross_task_feasibility_item_minimal(
            ctx, method, item, repaired,
            reason_keys=method_reason_keys,
        ) if repaired else {}
        if not validated:
            continue
        task_index = item['task_index']
        path_index = item['path_index']
        params_by_task[task_index][path_index] = validated
        recovered_tasks.add(task_index)
        bucket, cache_key, _, _, _ = _cross_task_item_cache_spec(
            ctx, method, item
        )
        ctx.shared('semantic_cache').set(bucket, cache_key, validated)
        ctx.service('_increment_pipeline_metric')(
            'stage_c_final_retry_recovered'
        )
    for task_index in recovered_tasks:
        if all(params_by_task[task_index]):
            job = jobs_by_task[task_index]
            _apply_feasibility_result(
                ctx, tasks[task_index], job['paths'],
                params_by_task[task_index], method,
            )
    if unresolved:
        ctx.service('_increment_pipeline_metric')(
            'stage_c_final_retry_paths',
            min(len(unresolved), final_retry_limit),
        )
    if progress_callback is not None and completed_tasks > last_flush_done:
        try:
            progress_callback(completed_tasks, total_tasks)
        except Exception as exc:
            logger.warning('Stage C 最终增量缓存回调失败: %s', exc)
    for item in items:
        params = params_by_task[item['task_index']][item['path_index']]
        if params:
            _record_feasibility_dependency(ctx, method, item, params)
    logger.info(
        'Stage C 跨任务合批完成: %d 个任务 / %d 条路径 / %d 次批量调用 / %d 条单路径缓存命中',
        total_tasks,
        len(items),
        len(batches),
        item_cache_hits,
    )

def stage_c_attack_batch(ctx: RuntimeContext, tasks: list[TaskUnit], method: str, progress_callback: Callable[[int, int], None] | None=None) -> None:
    """阶段C：批量评估攻击可行性 + 风险矩阵。

    attack_vector 无需 LLM 调用，直接映射；
    其余方法按 FEASIBILITY_PATHS_PER_CALL 跨任务合并多条路径。
    """
    if method == 'attack_vector':
        ctx.service('_set_pipeline_metric')('stage_c_tasks', len(tasks))
        ctx.service('_set_pipeline_metric')('stage_c_paths', sum((len(task.attack_paths or []) for task in tasks)))
        ctx.service('_set_pipeline_metric')('stage_c_batches_planned', 0)
        for task in tasks:
            if ctx.service('finalize_task_status')(task) != STATUS_VALID:
                task.attack_details = []
                continue
            details = []
            for (ai, ap_text) in enumerate(task.attack_paths or []):
                vector = ctx.service('_attack_vector_for_path')(task, ai, ap_text)
                norm = normalize_attack_vector(vector)
                params = {'attack_vector': norm}
                if ctx.setting('ENABLE_REASON'):
                    if (
                        ai < len(task.selected_path_frameworks)
                        and task.selected_path_frameworks[ai].get(
                            'is_external_component_direct'
                        )
                    ):
                        params['attack_vector_reason'] = (
                            f'根据 DFD 外部部件直接接入边界，确定攻击向量为 {norm}'
                        )
                    else:
                        params['attack_vector_reason'] = (
                            f'根据可信拓扑路径对应的外部接口，确定攻击向量为 {norm}'
                        )
                score = ATTACK_VECTOR_SCORE.get(norm, 0.55)
                level = calculate_attack_vector_level(vector)
                risk_value = calculate_risk_value(ctx.service('impact_risk_index')(task.impact_value, task.impact_level), level)
                details.append({'attack_path': ap_text, 'attack_parameters': params, 'attack_vector': norm, 'feasibility_score': score, 'feasibility_level': level, 'risk_value': risk_value, 'risk_treatment': get_risk_treatment(risk_value), 'feasibility_confidence': {'attack_vector': 1.0, '_overall': 1.0}, 'topology_trace': _topology_trace(task, ai), **_path_provenance_fields(task, ai)})
            task.attack_details = details
            task.feasibility_confidence = [{'attack_vector': 1.0, '_overall': 1.0} for _ in details]
            if details:
                task.risk_value = max((d['risk_value'] for d in details))
                task.risk_treatment = get_risk_treatment(task.risk_value)
        if progress_callback is not None:
            progress_callback(len(tasks), len(tasks))
        return
    jobs: list[dict] = []
    for (ti, task) in enumerate(tasks):
        if ctx.service('finalize_task_status')(task) != STATUS_VALID:
            task.attack_details = []
            continue
        paths_with_meta = []
        for (ai, ap_text) in enumerate(task.attack_paths):
            vector = ctx.service('_attack_vector_for_path')(task, ai, ap_text)
            paths_with_meta.append({'text': ap_text, 'vector': vector})
        jobs.append({'task_index': ti, 'paths': paths_with_meta})
    if not jobs:
        return
    if len(jobs) > 1 and (not (ctx.setting('SC_ENABLED') and ctx.setting('ENABLE_CONSISTENCY'))):
        _stage_c_attack_cross_task(ctx, tasks, jobs, method, progress_callback)
        return

    def worker(index: int, job: dict):
        task = tasks[job['task_index']]
        paths = job['paths']
        items = [{'task': task, 'task_index': job['task_index'], 'path_index': pi,
                  'path_id': f'{task.task_id}:path:{pi}', **path} for pi, path in enumerate(paths)]
        all_params = [{} for _ in paths]
        confidences = [{} for _ in paths]
        pending = []
        for pi, item in enumerate(items):
            bucket, key, _, _, _ = _cross_task_item_cache_spec(ctx, method, item)
            cached = ctx.shared('semantic_cache').get(bucket, key)
            validated = _validate_cross_task_feasibility_item_minimal(
                ctx, method, item, cached, reason_keys=_cross_task_reason_keys(method)
            ) if isinstance(cached, dict) else {}
            if validated:
                all_params[pi] = validated
                confidences[pi] = dict(cached.get('_cache_confidence') or {})
            else:
                pending.append(pi)
        ctx.service('_increment_pipeline_metric')('stage_c_item_cache_hits', len(paths) - len(pending))
        ctx.service('_increment_pipeline_metric')('stage_c_item_cache_misses', len(pending))
        pending_paths = [paths[pi] for pi in pending]
        path_tuples = [(p['text'], p['vector']) for p in pending_paths]
        generated = []
        if pending and method == 'cvss':
            generated = ctx.service("generate_attack_parameters_cvss_batch")(
                task, path_tuples
            )
        elif pending and method == 'heavens':
            generated = ctx.service("generate_attack_parameters_heavens_batch")(
                task, path_tuples
            )
        elif pending:
            generated = ctx.service("generate_attack_parameters_ap_batch")(
                task, path_tuples
            )
        for position, pi in enumerate(pending):
            if position >= len(generated):
                continue
            params = _validate_cross_task_feasibility_item_minimal(
                ctx, method, items[pi], generated[position], reason_keys=_cross_task_reason_keys(method)
            ) if generated[position] else {}
            all_params[pi] = params
            if position < len(task.feasibility_confidence):
                confidences[pi] = task.feasibility_confidence[position]
            if params:
                bucket, key, _, _, _ = _cross_task_item_cache_spec(ctx, method, items[pi])
                ctx.shared('semantic_cache').set(bucket, key, {**params, '_cache_confidence': confidences[pi]})
        task.feasibility_confidence = confidences if any(confidences) else []
        for item, params in zip(items, all_params):
            if params:
                _record_feasibility_dependency(ctx, method, item, params)
        return {'task_index': job['task_index'], 'all_params': all_params}
    total_jobs = len(jobs)
    done = 0
    _stage_c_start = time.perf_counter()
    log_interval = max(total_jobs // 50, 10)
    last_flush_done = 0
    last_flush_at = time.monotonic()

    def apply_result(result: dict) -> None:
        """任务完成即写回，避免等全部 Future 结束后才保留结果。"""
        task = tasks[result['task_index']]
        paths = next((candidate['paths'] for candidate in jobs if candidate['task_index'] == result['task_index']))
        _apply_feasibility_result(ctx, task, paths, result.get('all_params', []), method)
    executor = ctx.service('get_executor')()
    submission_window = min(ctx.setting('MAX_PENDING_FUTURES'), max(ctx.setting('BATCH_SIZE_ATTACK'), ctx.setting('MAX_WORKERS') * 2))
    for start in range(0, total_jobs, submission_window):
        chunk = jobs[start:start + submission_window]
        future_map = {ctx.service('_submit_pipeline')(executor, worker, start + offset, job): start + offset for (offset, job) in enumerate(chunk)}
        for future in as_completed(future_map):
            try:
                result = future.result()
                if isinstance(result, dict):
                    apply_result(result)
            except Exception as e:
                logger.warning('Stage C 任务执行异常: %s', e)
            done += 1
            now = time.monotonic()
            if progress_callback is not None and (done - last_flush_done >= ctx.setting('STAGE_C_CACHE_FLUSH_TASKS') or now - last_flush_at >= ctx.setting('STAGE_C_CACHE_FLUSH_SECONDS')):
                try:
                    progress_callback(done, total_jobs)
                except Exception as e:
                    logger.warning('Stage C 增量缓存回调失败: %s', e)
                last_flush_done = done
                last_flush_at = now
            if done % log_interval == 0 or done == total_jobs:
                elapsed = time.perf_counter() - _stage_c_start
                logger.info('Stage C 可行性进度: %d/%d (%d%%) | 耗时 %.0fs | 速率 %.1f任务/s', done, total_jobs, done * 100 // total_jobs, elapsed, done / elapsed if elapsed > 0 else 0)
    if progress_callback is not None and done > last_flush_done:
        try:
            progress_callback(done, total_jobs)
        except Exception as e:
            logger.warning('Stage C 最终增量缓存回调失败: %s', e)
    for job in jobs:
        task = tasks[job['task_index']]
        if task.analysis_status == STATUS_VALID and (not task.attack_details):
            task.analysis_status = STATUS_MODEL_FAILED
            if '攻击可行性评估执行失败' not in task.status_reasons:
                task.status_reasons.append('攻击可行性评估执行失败')
            task.risk_value = None
            task.risk_treatment = '需复核'
