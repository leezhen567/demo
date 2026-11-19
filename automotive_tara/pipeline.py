
"""Automotive TARA 完整分析流水线。

该模块是生产实现。
"""

import copy
from contextlib import ExitStack, contextmanager
from contextvars import ContextVar
import glob
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from functools import lru_cache, partial
from pathlib import Path

import orjson
from collections import Counter, defaultdict
from concurrent.futures import (
    FIRST_COMPLETED,
    Future,
    ThreadPoolExecutor,
    as_completed,
    wait,
)
from threading import Lock, Semaphore
from typing import Any, Callable, Optional

try:
    import pandas as pd
except Exception:
    pd = None
from urllib import request as urlrequest

from automotive_tara.domain import (
    AP_ALLOWED_VALUES,
    ATTRIBUTE_TO_THREAT,
    ATTACK_VECTOR_SCORE,
    ATTACK_VECTOR_TO_LEVEL,
    CVSS_C,
    CVSS_P,
    CVSS_U,
    CVSS_V,
    HEAVENS_AP_ALLOWED_VALUES,
    HEAVENS_DIM_WEIGHTS as _HEAVENS_DIM_WEIGHTS,
    HEAVENS_RISK_MATRIX as _HEAVENS_RISK_MATRIX,
    HEAVENS_RISK_NUM as _HEAVENS_RISK_NUM,
    HEAVENS_TL_TO_FEASIBILITY as _HEAVENS_TL_TO_FEASIBILITY,
    HEAVENS_WINDOW_BY_VECTOR as _HEAVENS_WINDOW_BY_VECTOR,
    OPPORTUNITY_WINDOW_MAP,
    PathNodeVO,
    RISK_MATRIX,
    SECURITY_ATTRIBUTES_MAP,
    STATUS_INPUT_MAPPING_CONFLICT,
    STATUS_INSUFFICIENT_EVIDENCE,
    STATUS_MODEL_FAILED,
    STATUS_NEEDS_REVIEW,
    STATUS_NOT_APPLICABLE,
    STATUS_TOPOLOGY_UNCOVERED,
    STATUS_VALID,
    TaskUnit,
    TopologyElementType,
    TopologyElementVO,
    calculate_attack_potential_level,
    calculate_attack_potential_score,
    calculate_attack_vector_level,
    calculate_cvss_level,
    calculate_cvss_score,
    calculate_heavens_4l_impact_value,
    calculate_heavens_ap_level,
    calculate_heavens_ap_score,
    calculate_heavens_dimension_values,
    calculate_heavens_impact_level,
    calculate_heavens_impact_value,
    calculate_heavens_risk_value,
    calculate_impact_level,
    calculate_impact_value,
    calculate_risk_value,
    compute_impact_for_method,
    get_risk_treatment,
    impact_risk_index_for_method,
    normalize_attack_vector,
    safe_int as _safe_int,
    task_from_dict as _domain_task_from_dict,
    task_analysis_reference,
    task_to_dict as _task_to_dict,
)
from automotive_tara import checkpoint as checkpoint_store
from automotive_tara.residual_reassessment import (
    build_post_control_path_prompt,
    build_post_control_rating_input,
    build_target_rating_constraints,
    post_control_path_response_format,
    synthesize_target_rating,
    validate_post_control_path,
    validate_target_rating,
)
from automotive_tara.config import *
from automotive_tara.config import _ENABLE_FUNC_DESC, _PROJECT_ROOT, _env_bool
from automotive_tara import analysis_cache
from automotive_tara.dfd import (
    _attribute_applicability as _dfd_attribute_applicability,
    _match_func_description,
    _truncate_desc,
    build_task_units as _build_task_units,
    load_security_asset_facts as _load_security_asset_facts,
    load_function_inventory,
    parse_dfd_json as _parse_dfd_json,
)
from automotive_tara.execution import ExecutorRegistry, MetricsRegistry, StageTimer
from automotive_tara.excel_export import (
    ExcelExportOptions,
    _build_columns_excel as _excel_build_columns,
    _build_excel_rows as _excel_build_rows,
    _get_attack_field_values as _excel_attack_fields,
    _style_excel as _excel_style,
    export_tara_report_to_excel as _export_excel,
)
from automotive_tara.http_client import (
    HTTPConnectionPool,
    parse_api_url as _parse_api_url,
)
from automotive_tara.api_service import check_api_service
from automotive_tara.input_paths import (
    default_dfd_path,
    default_interfaces_path,
    default_topology_path,
)
from automotive_tara.json_utils import (
    canonical_task_id as _canonical_task_id,
    safe_parse_json,
)
from automotive_tara import model_gateway
from automotive_tara.llm import (
    build_chat_payload,
    extract_choice_contents,
    is_connection_refused,
    is_stale_connection_error,
    strict_array_response_format,
)
from automotive_tara.rag import (
    BGEM3RAGKnowledgeBase,
    LazyRAGKnowledgeBase,
    RAGConfig,
)
from automotive_tara.reason_policy import (
    AP_REASON_KEYS, AP_MODEL_REASON_KEYS,
    CVSS_REASON_KEYS,
    HEAVENS_REASON_KEYS,
    IMPACT_REASON_KEYS,
    RATING_REASON_MAX_CHARS,
    append_reason_policy,
    reason_fields_valid,
)
from automotive_tara.prompts import (
    AP_BATCH_SYSTEM_PROMPT,
    ATTACK_ENTRY_SYSTEM_PROMPT,
    ATTACK_PATH_SYSTEM_PROMPT,
    ATTACK_TARGET_SYSTEM_PROMPT,
    CVSS_BATCH_SYSTEM_PROMPT,
    DST_BATCH_SYSTEM_PROMPT,
    HEAVENS_AP_BATCH_SYSTEM_PROMPT,
    IMPACT_BATCH_SYSTEM_PROMPT,
    IMPACT_REASON_SYSTEM_PROMPT,
    IMPACT_SYSTEM_PROMPT,
    build_impact_sc_numeric_prompt as _build_impact_sc_numeric_prompt,
    strip_disabled_reason_examples,
)
from automotive_tara import run_metadata as metadata_store
from automotive_tara.training_data import TrainingCapture, disabled_capture
from automotive_tara.run_paths import (
    default_run_dir,
    default_shared_cache_dir,
    infer_project_name,
    safe_project_name,
)
from automotive_tara.reporting import (
    build_error_report as _build_error_report,
    build_tara_report as _build_tara_report,
    excel_cell_value as _excel_cell_value,
    format_confidence as _fmt_conf,
    format_risk_value as _fmt_risk_value,
    generate_cybersecurity_claim as _gen_cybersecurity_claim,
    generate_cybersecurity_goal as _gen_cybersecurity_goal,
    normalize_excel_text as _normalize_text,
    sanitize_excel_text as _sanitize_excel_text,
)
from automotive_tara.security_requirements import (
    apply_security_requirement_llm_selection,
    build_security_requirement_llm_prompt,
    match_security_requirements,
    security_requirement_context,
    security_requirement_llm_response_format,
    validate_security_requirement_llm_response,
)
from automotive_tara.runtime import RuntimeContext
from automotive_tara import cache_dependencies as dependency_cache
from automotive_tara.stages import attack_path as attack_path_stage
from automotive_tara.stages import dst as dst_stage
from automotive_tara.stages import feasibility as feasibility_stage
from automotive_tara.stages import impact as impact_stage
from automotive_tara.storage import (
    SemanticCache,
    atomic_write_bytes as _atomic_write_bytes,
    save_json,
)
from automotive_tara.status import finalize_task_status as _finalize_task_status
from automotive_tara.topology_parser import (
    _load_external_interfaces,
    _parse_xlsx_rows_stdlib,
    parse_topology_and_generate_frameworks as _parse_topology_frameworks,
    topology_component_names as _topology_component_names,
)
from automotive_tara.token_budget import (
    clamp_output_tokens_to_context,
    dynamic_output_tokens,
)
from automotive_tara.topology import (
    TopologyMapUtil,
    determine_attack_vector as _determine_attack_vector,
    excel_column_index as _excel_col_to_idx,
    external_interface_key as _external_interface_key,
    is_checked as _is_checked,
    limit_shortest_frameworks,
    normalize_text as _norm_text,
    same_external_interface as _same_external_interface,
    same_protocol as _same_protocol,
)


# HTTP 连接池实例（延迟初始化）
_http_pool: HTTPConnectionPool | None = None
_http_pool_lock = Lock()


def _set_http_pool(pool: HTTPConnectionPool) -> None:
    global _http_pool
    _http_pool = pool


def _get_http_pool() -> HTTPConnectionPool:
    return model_gateway.get_http_pool(
        lambda: _http_pool,
        lock=_http_pool_lock,
        api_base=API_BASE,
        max_size=MAX_CONCURRENT_LLM,
        timeout=REQUEST_TIMEOUT,
        idle_ttl=HTTP_KEEPALIVE_IDLE_TTL,
        set_pool=_set_http_pool,
    )


def _http_post_json(path: str, body: bytes) -> dict:
    return model_gateway.http_post_json(
        path, body, get_pool=_get_http_pool,
        api_base=API_BASE, api_key=API_KEY,
    )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 1) 全局配置
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("TARA")

# ── 项目根路径 ───────────────────────────────────


_STAGE_TOKEN_CAPS = {
    "default": MAX_TOKENS,
    "dst": DST_MAX_TOKENS,
    "attack_entry": ATTACK_COMPONENT_MAX_TOKENS,
    "attack_target": ATTACK_COMPONENT_MAX_TOKENS,
    "attack_path_direct": DIRECT_ATTACK_PATH_MAX_TOKENS,
    "impact_single": IMPACT_MAX_TOKENS,
    "impact_batch": IMPACT_MAX_TOKENS,
    "impact_numeric": IMPACT_MAX_TOKENS,
    "impact_reason": IMPACT_MAX_TOKENS,
    "feasibility_ap": FEASIBILITY_MAX_TOKENS,
    "feasibility_heavens": FEASIBILITY_MAX_TOKENS,
    "feasibility_cvss": FEASIBILITY_MAX_TOKENS,
}


def _dynamic_token_budget(
    stage: str,
    item_count: int,
    *,
    include_reasons: bool | None = None,
    system_prompt: str = "",
    user_prompt: str = "",
    record: bool = False,
) -> int:
    """计算并可选记录一次阶段级动态输出预算。"""
    if include_reasons is None:
        include_reasons = ENABLE_REASON
    # 完整攻击路径是唯一需要独立于通用 TARA_MAX_TOKENS 的长文本阶段。
    # 其它阶段继续服从全局上限，避免误把评分/短动作请求放大。
    global_cap = MAX_TOKENS
    minimum_output = 64
    if stage == "attack_path_direct":
        global_cap = max(MAX_TOKENS, DIRECT_ATTACK_PATH_MAX_TOKENS)
        minimum_output = DIRECT_ATTACK_PATH_MIN_TOKENS
    budget = dynamic_output_tokens(
        stage,
        item_count,
        include_reasons=include_reasons,
        global_cap=global_cap,
        stage_cap=_STAGE_TOKEN_CAPS.get(stage, MAX_TOKENS),
        minimum_output_tokens=minimum_output,
        context_limit=MODEL_CONTEXT_TOKENS,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
    )
    if record and "_pipeline_metrics_lock" in globals():
        metric_stage = re.sub(r"[^a-z0-9]+", "_", stage.lower()).strip("_")
        with _pipeline_metrics_lock:
            calls_key = f"token_budget_{metric_stage}_decisions"
            total_key = f"token_budget_{metric_stage}_total"
            max_key = f"token_budget_{metric_stage}_max"
            _pipeline_metrics[calls_key] += 1
            _pipeline_metrics[total_key] += budget
            _pipeline_metrics[max_key] = max(
                _pipeline_metrics.get(max_key, 0),
                budget,
            )
    return budget


def _impact_batch_max_tokens(
    batch_size: int,
    *,
    include_reasons: bool | None = None,
    system_prompt: str = "",
    user_prompt: str = "",
    record: bool = False,
) -> int:
    """兼容旧内部名称，实际委托统一动态预算器。"""
    return _dynamic_token_budget(
        "impact_batch",
        batch_size,
        include_reasons=include_reasons,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        record=record,
    )


def _dynamic_token_budget_snapshot() -> dict[str, int]:
    feasibility_items = min(
        FEASIBILITY_PATHS_PER_CALL,
        (
            FEASIBILITY_REASON_PATHS_PER_CALL
            if ENABLE_REASON
            else FEASIBILITY_PATHS_PER_CALL
        ),
    )
    return {
        "dst_batch": _dynamic_token_budget("dst", BATCH_SIZE_DST),
        "attack_entry_batch": _dynamic_token_budget(
            "attack_entry", ATTACK_PATH_TASKS_PER_CALL
        ),
        "attack_target_batch": _dynamic_token_budget(
            "attack_target", ATTACK_PATH_TASKS_PER_CALL
        ),
        "attack_path_direct_batch": _dynamic_token_budget(
            "attack_path_direct", DIRECT_ATTACK_PATHS_PER_CALL,
            include_reasons=False,
        ),
        "impact_batch": _impact_batch_max_tokens(BATCH_SIZE_IMPACT),
        "impact_numeric_batch": _dynamic_token_budget(
            "impact_numeric",
            BATCH_SIZE_IMPACT,
            include_reasons=False,
        ),
        "impact_reason_batch": (
            _dynamic_token_budget(
                "impact_reason",
                BATCH_SIZE_IMPACT,
                include_reasons=True,
            )
            if ENABLE_REASON
            else 0
        ),
        "feasibility_ap_batch": _dynamic_token_budget(
            "feasibility_ap", feasibility_items
        ),
        "feasibility_heavens_batch": _dynamic_token_budget(
            "feasibility_heavens", feasibility_items
        ),
        "feasibility_cvss_batch": _dynamic_token_budget(
            "feasibility_cvss", feasibility_items
        ),
    }


# 运行时初始化延迟到 run_tara()，导入模块不会创建目录或写文件。
_runtime_initialized = False
_runtime_init_lock = Lock()
_run_lock = Lock()
_run_meta: dict[str, Any] = {}
_model_deployment_revisions: dict[str, str] = {}
_cache_model_revisions: dict[str, str] = {}
_training_capture = disabled_capture()
_live_usage_lock = Lock()
_live_usage_last_write = 0.0


_SENSITIVE_CONFIG_MARKERS = (
    "API_KEY",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
)


def _redact_config_value(name: str, value: Any) -> Any:
    return metadata_store._redact_config_value(name, value)


def _tara_environment_overrides() -> dict[str, Any]:
    return metadata_store._tara_environment_overrides()


def _effective_run_configuration(**overrides) -> dict[str, Any]:
    configuration = metadata_store._effective_run_configuration(
        runtime=globals(), token_budget_snapshot=_dynamic_token_budget_snapshot,
        **overrides,
    )
    # Persist the project scenario even when rating reasons are disabled.
    # A changed attacker/development premise must be visible in the run audit.
    marker = "## 项目评估前提："
    if (
        configuration["effective"]["TARA_FEASIBILITY_METHOD"] == "attack_potential"
        and marker in AP_BATCH_SYSTEM_PROMPT
    ):
        configuration["derived"]["feasibility_assumptions"] = {
            "type": "project_scenario",
            "description": AP_BATCH_SYSTEM_PROMPT.split(marker, 1)[1].split("\n## ", 1)[0].strip(),
        }
    return configuration


def _write_run_metadata(configuration: dict[str, Any]) -> None:
    metadata_store._write_run_metadata(_run_meta, OUTPUT_DIR, configuration)


def _current_run_configuration() -> dict[str, Any]:
    return metadata_store._current_run_configuration(_run_meta)


def _report_timestamp() -> str:
    """Return a filesystem-safe timestamp tied to the current run start."""

    raw = str(_run_meta.get("start_time") or "").strip()
    try:
        return datetime.fromisoformat(raw).strftime("%Y%m%d-%H%M%S")
    except (TypeError, ValueError):
        return datetime.now().strftime("%Y%m%d-%H%M%S")


def _apply_report_filename(
    output_path: str,
    *,
    data_flow_dir: str,
    topology_file: str,
    external_interface_excel: str,
) -> tuple[str, str]:
    """Name default report artifacts as ``date-time-project``.

    Explicit ``--output-name`` values remain respected for integrations that
    intentionally choose a custom filename.  The normal CLI and web entry
    points both use ``tara_report.json`` and therefore receive the stable,
    human-readable project name automatically.
    """

    path = Path(output_path)
    if not path.name.casefold().startswith("tara_report"):
        project = infer_project_name(
            (data_flow_dir, topology_file, external_interface_excel),
            default="TARA",
        )
        return str(path), project
    project = infer_project_name(
        (data_flow_dir, topology_file, external_interface_excel),
        default="TARA",
    )
    suffix = path.suffix or ".json"
    generated = f"{_report_timestamp()}_{safe_project_name(project)}{suffix}"
    return str(path.with_name(generated)), project


def _initialize_runtime() -> None:
    global _runtime_initialized, _run_meta
    if _runtime_initialized:
        return
    with _runtime_init_lock:
        if _runtime_initialized:
            return
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        log_file = os.path.join(OUTPUT_DIR, "tara_run.log")
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        )
        logger.addHandler(file_handler)
        _run_meta = {
            "schema_version": "tara-run-metadata-v2",
            "start_time": datetime.now().isoformat(),
            "output_dir": OUTPUT_DIR,
            "model": MODEL_NAME,
            "impact_model": IMPACT_MODEL_NAME,
            "api_base": API_BASE,
            "llm_retries": LLM_RETRIES,
            "seed": SAMPLING_SEED,
            "top_p": TOP_P,
            "top_k": TOP_K,
            "frequency_penalty": FREQUENCY_PENALTY,
            "presence_penalty": PRESENCE_PENALTY,
            "runtime_profile": RUNTIME_PROFILE,
            "feasibility_method": FEASIBILITY_METHOD,
            "impact_method": IMPACT_METHOD,
            "enable_rag": ENABLE_RAG,
            "rag_top_k": RAG_TOP_K,
            "max_concurrent_llm": MAX_CONCURRENT_LLM,
            "attack_path_workers": ATTACK_PATH_WORKERS,
            "stage_c_max_concurrent_llm": STAGE_C_MAX_CONCURRENT_LLM,
            "max_workers": MAX_WORKERS,
            "batch_dst": BATCH_SIZE_DST,
            "batch_impact": BATCH_SIZE_IMPACT,
            "impact_repair_max_depth": IMPACT_REPAIR_MAX_DEPTH,
            "dynamic_token_budgets": _dynamic_token_budget_snapshot(),
            "attack_paths_per_call": ATTACK_PATH_TASKS_PER_CALL,
            "feasibility_paths_per_call": FEASIBILITY_PATHS_PER_CALL,
            "feasibility_reason_paths_per_call": FEASIBILITY_REASON_PATHS_PER_CALL,
            "http_keepalive_idle_ttl": HTTP_KEEPALIVE_IDLE_TTL,
            "stage_c_cache_flush_tasks": STAGE_C_CACHE_FLUSH_TASKS,
            "stage_c_cache_flush_seconds": STAGE_C_CACHE_FLUSH_SECONDS,
            "pipeline_recovery_rounds": PIPELINE_RECOVERY_ROUNDS,
            "test_max_assets": TEST_MAX_ASSETS,
            "security_requirements_path": SECURITY_REQUIREMENTS_PATH,
            "security_requirements_logic_path": SECURITY_REQUIREMENTS_LOGIC_PATH,
            "security_requirements_llm": SECURITY_REQUIREMENTS_LLM,
            "security_requirements_scope": SECURITY_REQUIREMENTS_SCOPE,
            "security_requirements_implemented_reassessment": (
                SECURITY_REQUIREMENTS_IMPLEMENTED_REASSESSMENT
            ),
            "security_requirements_two_stage_reassessment": SECURITY_REQUIREMENTS_TWO_STAGE_REASSESSMENT,
            "security_requirements_reassessment_engine": (
                "deterministic_target"
                if SECURITY_REQUIREMENTS_IMPLEMENTED_REASSESSMENT else "off"
            ),
        }
        _write_run_metadata(_effective_run_configuration())
        _runtime_initialized = True
        logger.info("日志文件: %s", log_file)
        if ADAPTIVE_SCHEDULING:
            logger.info("自适应调度配置: %s", RUNTIME_PROFILE)


def _validate_method_combination(
    feasibility_method: str, impact_method: str
) -> None:
    """拒绝影响评级与可行性评级之间不兼容的风险矩阵组合。"""
    feasibility = (feasibility_method or "").strip().lower()
    impact = (impact_method or "").strip().lower()
    supported_feasibility = {
        "attack_potential",
        "attack_vector",
        "cvss",
        "heavens",
    }
    if feasibility not in supported_feasibility:
        raise ValueError(
            "可行性评级方法仅支持 attack_potential、attack_vector、cvss 或 "
            f"heavens，当前为 {feasibility!r}"
        )

    # HEAVENS 原生风险矩阵是 IL(5级) × TL(5级)，两侧必须同时选择 HEAVENS。
    if feasibility == "heavens" and impact != "heavens":
        raise ValueError(
            "HEAVENS 可行性评级只能与 heavens 五级影响评级组成风险矩阵"
        )
    if impact == "heavens" and feasibility != "heavens":
        raise ValueError(
            "heavens 五级影响评级只能与 HEAVENS 可行性评级组成风险矩阵；"
            "与 attack_potential、attack_vector 或 cvss 组合时请使用 "
            "heavens_4level"
        )


def _validate_runtime_config() -> None:
    positive_ints = {
        "TARA_MAX_WORKERS": MAX_WORKERS,
        "TARA_MAX_CONCURRENT_LLM": MAX_CONCURRENT_LLM,
        "TARA_ATTACK_PATH_WORKERS": ATTACK_PATH_WORKERS,
        "TARA_STAGE_C_MAX_CONCURRENT_LLM": STAGE_C_MAX_CONCURRENT_LLM,
        "TARA_VLLM_MAX_NUM_SEQS": VLLM_MAX_NUM_SEQS,
        "TARA_TASK_CONTEXT_TOKENS": MODEL_CONTEXT_TOKENS,
        "TARA_BATCH_DST": BATCH_SIZE_DST,
        "TARA_BATCH_IMPACT": BATCH_SIZE_IMPACT,
        "TARA_IMPACT_REPAIR_MAX_DEPTH": IMPACT_REPAIR_MAX_DEPTH,
        "TARA_BATCH_SIZE_ATTACK": BATCH_SIZE_ATTACK,
        "TARA_ATTACK_PATHS_PER_CALL": ATTACK_PATH_TASKS_PER_CALL,
        "TARA_MAX_PENDING_FUTURES": MAX_PENDING_FUTURES,
        "TARA_DST_MAX_TOKENS": DST_MAX_TOKENS,
        "TARA_ATTACK_COMPONENT_MAX_TOKENS": ATTACK_COMPONENT_MAX_TOKENS,
        "TARA_DIRECT_ATTACK_PATH_MIN_TOKENS": DIRECT_ATTACK_PATH_MIN_TOKENS,
        "TARA_DIRECT_ATTACK_PATH_MAX_TOKENS": DIRECT_ATTACK_PATH_MAX_TOKENS,
        "TARA_IMPACT_MAX_TOKENS": IMPACT_MAX_TOKENS,
        "TARA_FEASIBILITY_MAX_TOKENS": FEASIBILITY_MAX_TOKENS,
        "TARA_SEMANTIC_CACHE_BUCKET_SIZE": SEMANTIC_CACHE_BUCKET_SIZE,
        "TARA_FEASIBILITY_PATHS_PER_CALL": FEASIBILITY_PATHS_PER_CALL,
        "TARA_FEASIBILITY_REASON_PATHS_PER_CALL": FEASIBILITY_REASON_PATHS_PER_CALL,
        "TARA_STAGE_C_CACHE_FLUSH_TASKS": STAGE_C_CACHE_FLUSH_TASKS,
    }
    invalid = [f"{name}={value}" for name, value in positive_ints.items() if value <= 0]
    if invalid:
        raise ValueError("以下配置必须为正整数: " + ", ".join(invalid))
    if TOPOLOGY_PATHS_PER_PAIR < 0:
        raise ValueError(
            "TARA_TOPOLOGY_PATHS_PER_PAIR 必须为0（不截断）或正整数，"
            f"当前为 {TOPOLOGY_PATHS_PER_PAIR}"
        )
    if DIRECT_ATTACK_PATH_MIN_TOKENS > DIRECT_ATTACK_PATH_MAX_TOKENS:
        raise ValueError(
            "TARA_DIRECT_ATTACK_PATH_MIN_TOKENS 不能大于 "
            "TARA_DIRECT_ATTACK_PATH_MAX_TOKENS"
        )
    if REQUEST_TIMEOUT <= 0:
        raise ValueError(f"TARA_REQUEST_TIMEOUT 必须大于0，当前为 {REQUEST_TIMEOUT}")
    if LLM_RETRIES < 0:
        raise ValueError(f"TARA_LLM_RETRIES 必须大于等于0，当前为 {LLM_RETRIES}")
    if PIPELINE_RECOVERY_ROUNDS < 0:
        raise ValueError(
            "TARA_PIPELINE_RECOVERY_ROUNDS 必须大于等于0，"
            f"当前为 {PIPELINE_RECOVERY_ROUNDS}"
        )
    if HTTP_KEEPALIVE_IDLE_TTL <= 0:
        raise ValueError(
            "TARA_HTTP_KEEPALIVE_IDLE_TTL 必须大于0，"
            f"当前为 {HTTP_KEEPALIVE_IDLE_TTL}"
        )
    if STAGE_C_CACHE_FLUSH_SECONDS <= 0:
        raise ValueError(
            "TARA_STAGE_C_CACHE_FLUSH_SECONDS 必须大于0，"
            f"当前为 {STAGE_C_CACHE_FLUSH_SECONDS}"
        )
    if not 0 <= TEMPERATURE <= 2:
        raise ValueError(f"TARA_TEMPERATURE 必须位于0~2，当前为 {TEMPERATURE}")
    if SAMPLING_SEED < 0:
        raise ValueError(f"TARA_SEED 必须大于等于0，当前为 {SAMPLING_SEED}")
    if not 0 < TOP_P <= 1:
        raise ValueError(f"TARA_TOP_P 必须位于(0,1]，当前为 {TOP_P}")
    if TOP_K < 1:
        raise ValueError(f"TARA_TOP_K 必须大于等于1，当前为 {TOP_K}")
    for name, value in (("TARA_FREQUENCY_PENALTY", FREQUENCY_PENALTY), ("TARA_PRESENCE_PENALTY", PRESENCE_PENALTY)):
        if not -2 <= value <= 2:
            raise ValueError(f"{name} 必须位于[-2,2]，当前为 {value}")
    if not 0 <= SC_CONFIDENCE_THRESHOLD <= 1:
        raise ValueError(
            f"TARA_SC_CONFIDENCE_THRESHOLD 必须位于0~1，当前为 {SC_CONFIDENCE_THRESHOLD}"
        )
    if SC_SAMPLES <= 0:
        raise ValueError(f"TARA_SC_SAMPLES 必须大于0，当前为 {SC_SAMPLES}")
    if IMPACT_METHOD not in {"21434", "heavens", "heavens_4level"}:
        raise ValueError(
            "TARA_IMPACT_METHOD 仅支持 21434、heavens 或 heavens_4level，"
            f"当前为 {IMPACT_METHOD!r}"
        )
    _validate_method_combination(FEASIBILITY_METHOD, IMPACT_METHOD)
    if RAG_METHOD not in {"none", "bge-m3"}:
        raise ValueError(
            "TARA_RAG_METHOD 当前仅支持 none 或 bge-m3；"
            f"{RAG_METHOD!r} 尚未实现，不能静默按其他算法运行"
        )
    _parse_api_url(API_BASE)


_validate_runtime_config()
_FUNCTION_DESC_MAP: dict[str, str] = {}  # 当前 DFD 功能名 -> 简短说明

llm_semaphore = Semaphore(MAX_CONCURRENT_LLM)
stage_c_llm_semaphore = Semaphore(
    min(MAX_CONCURRENT_LLM, STAGE_C_MAX_CONCURRENT_LLM)
)
# 一个 n-choice 请求占 n 条序列，同时也占一个普通 LLM 信号量槽位。
# c*n + (MAX_CONCURRENT_LLM-c) <= VLLM_MAX_NUM_SEQS，据此计算安全上限。
if SC_SAMPLES <= 1:
    SC_MULTI_CHOICE_CONCURRENCY = min(
        MAX_CONCURRENT_LLM, VLLM_MAX_NUM_SEQS
    )
elif ENABLE_REASON:
    SC_MULTI_CHOICE_CONCURRENCY = max(
        1,
        min(
            MAX_CONCURRENT_LLM,
            (VLLM_MAX_NUM_SEQS - MAX_CONCURRENT_LLM)
            // (SC_SAMPLES - 1),
        ),
    )
else:
    SC_MULTI_CHOICE_CONCURRENCY = max(
        1,
        min(MAX_CONCURRENT_LLM, VLLM_MAX_NUM_SEQS // SC_SAMPLES),
    )
sc_multi_choice_semaphore = Semaphore(SC_MULTI_CHOICE_CONCURRENCY)
_llm_rate_lock = Lock()
_metrics_registry = MetricsRegistry()
_llm_metrics = _metrics_registry.llm
_llm_metrics_lock = _metrics_registry.llm_lock
_pipeline_metrics = _metrics_registry.pipeline
_pipeline_metrics_lock = _metrics_registry.pipeline_lock
_stage_times = _metrics_registry.stage_times
_phase_times = _metrics_registry.phase_times
_phase_lock = _metrics_registry.phase_lock
_executor_registry = ExecutorRegistry(MAX_PENDING_FUTURES)
_llm_usage_stage_override: ContextVar[str | None] = ContextVar(
    "tara_llm_usage_stage_override", default=None
)
_checkpoint_futures = _executor_registry.checkpoint_futures
_checkpoint_futures_lock = _executor_registry.checkpoint_futures_lock


_last_llm_call_at = 0.0


def _llm_metrics_snapshot() -> dict[str, Any]:
    return _metrics_registry.llm_snapshot()


def _set_pipeline_metric(name: str, value: int) -> None:
    _metrics_registry.set_pipeline(name, value)


def _increment_pipeline_metric(name: str, value: int = 1) -> None:
    _metrics_registry.increment_pipeline(name, value)


def _pipeline_metrics_snapshot() -> dict[str, int]:
    return _metrics_registry.pipeline_snapshot()


def _reset_run_metrics() -> None:
    _metrics_registry.reset()


def _respect_call_interval() -> None:
    global _last_llm_call_at
    if CALL_INTERVAL <= 0:
        return
    with _llm_rate_lock:
        now = time.monotonic()
        wait = CALL_INTERVAL - (now - _last_llm_call_at)
        if wait > 0:
            time.sleep(wait)
        _last_llm_call_at = time.monotonic()


def _compute_file_sha256(path: str) -> str:
    """计算文件的 SHA256 哈希。"""
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _verify_model_hashes(manifest_path: str, model_dir: str) -> bool:
    """校验模型文件 SHA256 清单。清单格式：每行 '<sha256>  <相对路径>'。

    清单缺失时返回 False，调用方应根据 VERIFY_MODEL_HASHES 决定是否阻断。
    """
    if not os.path.exists(manifest_path):
        logger.warning("模型哈希清单缺失: %s（跳过完整性校验）", manifest_path)
        return False
    with open(manifest_path, "r", encoding="utf-8") as f:
        lines = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    ok = True
    for ln in lines:
        parts = ln.split(None, 1)
        if len(parts) != 2:
            continue
        expected_hash, rel_path = parts
        abs_path = os.path.join(model_dir, rel_path)
        if not os.path.exists(abs_path):
            logger.error("模型文件缺失: %s", abs_path)
            ok = False
            continue
        actual = _compute_file_sha256(abs_path)
        if actual != expected_hash:
            logger.error("模型哈希不匹配: %s (期望 %s, 实际 %s)", rel_path, expected_hash[:16], actual[:16])
            ok = False
    if ok:
        logger.info("模型哈希校验通过: %s (%d 个文件)", model_dir, len(lines))
    return ok

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 1.6) 计时工具
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# 阶段计时：Timer 自动记录到 _stage_times


# 阶段累计计时器（线程安全）


class Timer(StageTimer):
    def __init__(self, stage_name: str):
        super().__init__(stage_name, _metrics_registry)


def _add_phase_time(phase: str, elapsed: float) -> None:
    _metrics_registry.add_phase_time(phase, elapsed)


@contextmanager
def _use_llm_usage_stage(stage: str):
    token = _llm_usage_stage_override.set(stage)
    try:
        yield
    finally:
        _llm_usage_stage_override.reset(token)


_STAGE_TELEMETRY_PHASES = (
    ("Step 1: DFD 资产解析", "Step 1: DFD 资产解析", ()),
    ("Step 2: 拓扑攻击路径框架", "Step 2: 拓扑攻击路径框架", ()),
    ("Step 3: 扩展属性 + RAG", "Step 3: 扩展属性 + RAG", ()),
    ("Step 4: 损害威胁场景", "Step 4: 损害威胁场景", ("dst",)),
    (
        "Step 5: 影响评级",
        "Step 5: 影响评级",
        ("impact", "impact_numeric_sc", "impact_reason"),
    ),
    (
        "Step 6: 攻击路径生成",
        "Step 6: 攻击路径生成",
        ("attack_path_direct", "attack_entry", "attack_target"),
    ),
    (
        "Step 7: 批量可行性评估",
        "Step 7: 批量可行性评估",
        (
            "feasibility_cvss", "feasibility_heavens",
            "feasibility_attack_potential",
        ),
    ),
    (
        "Step 8: 报告与安全需求匹配",
        "Step 8: 报告生成",
        ("security_requirement_selection",),
    ),
    (
        "Step 9: 安全需求实施后复评",
        "Step 9: 安全需求实施后复评",
        ("post_control_path", "post_control_feasibility"),
    ),
    (
        "阶段失败子集恢复",
        "阶段失败子集恢复",
        ("retry_dst", "retry_impact", "retry_attack_path"),
    ),
)


def _stage_telemetry_snapshot() -> dict[str, dict[str, Any]]:
    """Combine measured phase wall time with server-reported token usage."""
    by_stage = _llm_metrics_snapshot().get("by_stage", {})
    if not isinstance(by_stage, dict):
        by_stage = {}
    result: dict[str, dict[str, Any]] = {}
    for phase_name, wall_clock_key, llm_stages in _STAGE_TELEMETRY_PHASES:
        counters = [
            by_stage.get(name, {})
            for name in llm_stages
            if isinstance(by_stage.get(name, {}), dict)
        ]
        http_requests = sum(int(item.get("http_requests", 0) or 0) for item in counters)
        prompt_usage_requests = sum(
            int(item.get("prompt_tokens_usage_requests", 0) or 0)
            for item in counters
        )
        completion_usage_requests = sum(
            int(item.get("completion_tokens_usage_requests", 0) or 0)
            for item in counters
        )
        prompt_tokens_reported = sum(
            int(item.get("prompt_tokens", 0) or 0) for item in counters
        )
        completion_tokens_reported = sum(
            int(item.get("completion_tokens", 0) or 0) for item in counters
        )
        if http_requests == 0:
            token_status = "no_chat_completion_calls"
            prompt_tokens: int | None = 0
            completion_tokens: int | None = 0
        else:
            prompt_tokens = (
                prompt_tokens_reported
                if prompt_usage_requests == http_requests else None
            )
            completion_tokens = (
                completion_tokens_reported
                if completion_usage_requests == http_requests else None
            )
            token_status = (
                "complete"
                if prompt_tokens is not None and completion_tokens is not None
                else "partial"
                if prompt_usage_requests or completion_usage_requests
                else "unavailable"
            )
        elapsed = _stage_times.get(wall_clock_key)
        result[phase_name] = {
            "token_source": "chat_completions_usage",
            "wall_clock_seconds": round(float(elapsed), 3)
            if elapsed is not None else 0.0,
            "wall_clock_status": (
                "not_run_or_checkpoint"
                if elapsed == 0
                else "measured"
                if elapsed is not None
                else "not_run"
            ),
            "http_requests": http_requests,
            "successful_requests": sum(
                int(item.get("successful_requests", 0) or 0)
                for item in counters
            ),
            "failed_requests": sum(
                int(item.get("failed_requests", 0) or 0)
                for item in counters
            ),
            "retry_requests": sum(
                int(item.get("retry_requests", 0) or 0)
                for item in counters
            ),
            "http_seconds_sum": round(
                sum(float(item.get("http_seconds", 0.0) or 0.0) for item in counters),
                3,
            ),
            "input_tokens": prompt_tokens,
            "output_tokens": completion_tokens,
            "input_tokens_reported": prompt_tokens_reported,
            "output_tokens_reported": completion_tokens_reported,
            "input_usage_requests": prompt_usage_requests,
            "output_usage_requests": completion_usage_requests,
            "token_usage_status": token_status,
        }

    # Unknown prompt types remain visible rather than disappearing from totals.
    unknown = by_stage.get("unknown", {})
    if isinstance(unknown, dict) and int(unknown.get("http_requests", 0) or 0):
        unknown_requests = int(unknown.get("http_requests", 0) or 0)
        unknown_input_coverage = int(
            unknown.get("prompt_tokens_usage_requests", 0) or 0
        )
        unknown_output_coverage = int(
            unknown.get("completion_tokens_usage_requests", 0) or 0
        )
        unknown_input = int(unknown.get("prompt_tokens", 0) or 0)
        unknown_output = int(unknown.get("completion_tokens", 0) or 0)
        result["未归类模型调用"] = {
            "token_source": "chat_completions_usage",
            "wall_clock_seconds": None,
            "wall_clock_status": "not_attributed",
            "http_requests": unknown_requests,
            "successful_requests": int(unknown.get("successful_requests", 0) or 0),
            "failed_requests": int(unknown.get("failed_requests", 0) or 0),
            "retry_requests": int(unknown.get("retry_requests", 0) or 0),
            "http_seconds_sum": round(float(unknown.get("http_seconds", 0.0) or 0.0), 3),
            "input_tokens": (
                unknown_input if unknown_input_coverage == unknown_requests else None
            ),
            "output_tokens": (
                unknown_output if unknown_output_coverage == unknown_requests else None
            ),
            "input_tokens_reported": unknown_input,
            "output_tokens_reported": unknown_output,
            "input_usage_requests": unknown_input_coverage,
            "output_usage_requests": unknown_output_coverage,
            "token_usage_status": (
                "complete"
                if unknown_input_coverage == unknown_requests
                and unknown_output_coverage == unknown_requests
                else "partial"
                if unknown_input_coverage or unknown_output_coverage
                else "unavailable"
            ),
        }
    return result


def _log_stage_telemetry() -> dict[str, dict[str, Any]]:
    telemetry = _stage_telemetry_snapshot()
    logger.info(
        "阶段资源统计：Token取Chat Completions服务usage原值；本地BGE向量/重排模型不计入聊天Token；"
        "wall_clock为阶段端到端墙钟时间，http_seconds_sum为并发请求耗时之和"
    )
    for stage, item in telemetry.items():
        wall_clock = item["wall_clock_seconds"]
        wall_text = (
            "未归属" if wall_clock is None
            else f"{wall_clock:.3f}s ({item['wall_clock_status']})"
        )
        if item["token_usage_status"] == "no_chat_completion_calls":
            token_text = "input_tokens=0 output_tokens=0 (no chat-completion calls)"
        elif item["token_usage_status"] == "complete":
            token_text = (
                f"input_tokens={item['input_tokens']} "
                f"output_tokens={item['output_tokens']}"
            )
        else:
            token_text = (
                f"input_tokens_reported={item['input_tokens_reported']}"
                f"({item['input_usage_requests']}/{item['http_requests']} usage) "
                f"output_tokens_reported={item['output_tokens_reported']}"
                f"({item['output_usage_requests']}/{item['http_requests']} usage)"
            )
        logger.info(
            "[阶段资源] %s | wall_clock=%s | chat_requests=%d(success=%d failed=%d retry=%d) "
            "| %s | token_usage=%s | http_seconds_sum=%.3fs",
            stage,
            wall_text,
            item["http_requests"],
            item["successful_requests"],
            item["failed_requests"],
            item["retry_requests"],
            token_text,
            item["token_usage_status"],
            item["http_seconds_sum"],
        )
    return telemetry


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 2) 业务常量
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# 领域常量与评级规则由 automotive_tara.domain 提供，并由此处组合生产流水线。


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 3) 语义缓存
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

semantic_cache = SemanticCache(max_bucket_size=SEMANTIC_CACHE_BUCKET_SIZE)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 3.5) BGE-M3 混合检索 RAG（Dense + Sparse + RRF + Cross-Encoder）
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# 按 tara_phase 的片段截断长度（字符数）


def _new_rag_knowledge_base() -> BGEM3RAGKnowledgeBase:
    return BGEM3RAGKnowledgeBase(
        RAG_DIRS,
        config=RAGConfig(
            enable_rag=ENABLE_RAG,
            enable_r155=ENABLE_R155,
            r155_annex5_path=R155_ANNEX5_PATH,
            vector_store_dir=VECTOR_STORE_DIR,
            verify_model_hashes=VERIFY_MODEL_HASHES,
            reranker_enabled=RERANKER_ENABLED,
            reranker_model_path=RERANKER_MODEL_PATH,
            reranker_candidates=RERANKER_CANDIDATES,
            reranker_batch_size=RERANKER_BATCH_SIZE,
            rrf_k=RRF_K,
            bge_m3_path=BGE_M3_PATH,
        ),
        model_hash_verifier=_verify_model_hashes,
    )


rag_kb = (
    LazyRAGKnowledgeBase(_new_rag_knowledge_base)
    if (ENABLE_RAG or ENABLE_R155)
    else None
)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 4) 数据结构
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _task_from_dict(d: dict) -> TaskUnit:
    """兼容旧内部名称；实际反序列化由领域模块维护。"""
    return _domain_task_from_dict(d)


def _tasks_to_dict(tasks: list[TaskUnit]) -> list[dict]:
    return [_task_to_dict(t) for t in tasks]


def _tasks_from_dict(data: list[dict]) -> list[TaskUnit]:
    return [_domain_task_from_dict(d) for d in data]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 5) 通用工具
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def llm_call_with_semaphore(
    system_prompt: str,
    user_prompt: str,
    retries: int | None = None,
    max_tokens: int | None = None,
    response_format: dict | None = None,
    *,
    n: int = 1,
    return_all_choices: bool = False,
    raise_on_rejection: bool = False,
    model_override: str | None = None,
) -> str | list[str]:
    global _live_usage_last_write
    effective_retries = LLM_RETRIES if retries is None else max(0, int(retries))
    selected_model = model_override or MODEL_NAME
    def capture_event(record):
        if _training_capture.enabled:
            _capture_llm_call(system_prompt, record)
        if LIVE_MODEL_OUTPUT:
            from automotive_tara.live_model_output import append_model_event
            append_model_event(OUTPUT_DIR, record, stage=_usage_stage_for_prompt(system_prompt, user_prompt))

    result = model_gateway.call_model(
        system_prompt,
        user_prompt,
        model=selected_model,
        temperature=TEMPERATURE,
        context_tokens=MODEL_CONTEXT_TOKENS,
        skip_chat_template=SKIP_CHAT_TEMPLATE or REMOTE_API,
        descriptions=_FUNCTION_DESC_MAP,
        token_budget=_dynamic_token_budget,
        post_json=_http_post_json,
        semaphore=llm_semaphore,
        respect_call_interval=_respect_call_interval,
        metrics=_llm_metrics,
        metrics_lock=_llm_metrics_lock,
        stage_metrics=_metrics_registry.llm_stage_metrics(
            _llm_usage_stage_override.get()
            or _usage_stage_for_prompt(system_prompt, user_prompt)
        ),
        retries=effective_retries,
        max_tokens=max_tokens,
        response_format=response_format,
        n=n,
        return_all_choices=return_all_choices,
        raise_on_rejection=raise_on_rejection,
        seed=SAMPLING_SEED,
        top_p=TOP_P,
        top_k=None if REMOTE_API else TOP_K,
        frequency_penalty=FREQUENCY_PENALTY,
        presence_penalty=PRESENCE_PENALTY,
        capture_call=capture_event if (_training_capture.enabled or LIVE_MODEL_OUTPUT) else None,
        sleep=time.sleep,
    )
    # Keep a tiny, prompt-free usage snapshot for the web UI.  Training/audit
    # capture is optional and may be disabled for privacy, but users should
    # still see that API calls are happening while a run is in progress.  The
    # write is throttled so high-concurrency runs do not pay an fsync per
    # request; the final run_manifest remains authoritative.
    if _runtime_initialized:
        now = time.monotonic()
        with _live_usage_lock:
            if now - _live_usage_last_write >= 0.5:
                _live_usage_last_write = now
                try:
                    save_json(
                        {
                            "schema_version": "tara-live-llm-v1",
                            "updated_at": datetime.now().isoformat(),
                            "live": True,
                            "llm": _llm_metrics_snapshot(),
                        },
                        os.path.join(OUTPUT_DIR, "llm_usage_live.json"),
                    )
                except Exception:
                    logger.debug("实时 LLM 用量快照写入失败", exc_info=True)
    return result


def _training_stage_for_prompt(system_prompt: str) -> str:
    """把精确生产 Prompt 归入稳定训练阶段标签。"""
    prompt = system_prompt or ""
    if "安全需求匹配审查器" in prompt:
        return "security_requirement_selection"
    if "损害场景建模和威胁场景建模任务" in prompt:
        return "dst"
    if (
        "直接生成完整" in prompt
        and (
            "拓扑框架是只读事实" in prompt
            or "topology_route 是唯一可信的拓扑事实" in prompt
            or "topology_route 是唯一可信路线" in prompt
        )
    ):
        return "attack_path_direct"
    if "初始访问技术动作" in prompt:
        return "attack_entry"
    if "具体的最终攻击动作" in prompt:
        return "attack_target"
    if "这些分值是固定结论，禁止修改或重新评级" in prompt:
        return "impact_reason"
    if "Self-Consistency 数值采样协议" in prompt:
        return "impact_numeric_sc"
    if "Safety、Finance、Operation、Privacy 四个维度进行影响评级" in prompt:
        return "impact"
    if "CVSS可利用性评估专家" in prompt:
        return "feasibility_cvss"
    if "HEAVENS攻击可行性评估专家" in prompt:
        return "feasibility_heavens"
    if "ISO/SAE 21434攻击潜力评估专家" in prompt:
        return "feasibility_attack_potential"
    return "unknown"


def _usage_stage_for_prompt(system_prompt: str, user_prompt: str) -> str:
    """Classify model calls for normal-run usage logs without storing prompts."""
    system = system_prompt or ""
    user = user_prompt or ""
    if "已实施安全需求的目标约束复评" in system:
        return "post_control_feasibility"
    if (
        "已经实现且有效运行的安全需求" in system
        and "原攻击路径" in system
    ):
        return "post_control_path"
    if "【安全需求实施后评级输入】" in user:
        return "post_control_feasibility"
    return _training_stage_for_prompt(system)


def _capture_llm_call(
    system_prompt: str, record: dict[str, Any]
) -> None:
    enriched = dict(record)
    enriched["stage"] = (
        _llm_usage_stage_override.get()
        or _usage_stage_for_prompt(system_prompt, "")
    )
    enriched["prompt_signature"] = _prompt_signature()
    _training_capture.record_llm_call(enriched)


def _build_llm_cache_key(
    cache_key: Any,
    system_prompt: str,
    user_prompt: str,
    max_tokens: int | None = None,
    *,
    model_override: str | None = None,
) -> dict:
    selected_model = model_override or MODEL_NAME
    result = model_gateway.build_cache_key(
        cache_key,
        system_prompt,
        user_prompt,
        model=selected_model,
        temperature=TEMPERATURE,
        descriptions=_FUNCTION_DESC_MAP,
        token_budget=_dynamic_token_budget,
        max_tokens=max_tokens,
        seed=SAMPLING_SEED,
        top_p=TOP_P,
        top_k=None if REMOTE_API else TOP_K,
        frequency_penalty=FREQUENCY_PENALTY,
        presence_penalty=PRESENCE_PENALTY,
    )
    revision = _model_deployment_revisions.get(selected_model)
    if revision:
        result["deployment_revision"] = revision
    return result


def cached_llm_json(*, model_override: str | None = None, **kwargs) -> tuple[Any, bool]:
    # Cache identity and HTTP request must use the same served model.
    build_key = _build_llm_cache_key
    call_llm = llm_call_with_semaphore
    if model_override:
        build_key = partial(_build_llm_cache_key, model_override=model_override)
        call_llm = partial(llm_call_with_semaphore, model_override=model_override)
    return model_gateway.cached_json(
        semantic_cache=semantic_cache,
        build_key=build_key,
        call_llm=call_llm,
        token_budget=_dynamic_token_budget,
        **kwargs,
    )


_security_requirement_selection_cache: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
_security_requirement_selection_lock = Lock()


def _security_requirement_fallback(
    candidates: list[dict[str, Any]],
    *,
    reason: str,
) -> list[dict[str, Any]]:
    """Keep rule-filtered requirements available when the optional selector fails."""
    result: list[dict[str, Any]] = []
    for candidate in candidates:
        item = dict(candidate)
        basis = dict(item.get("match_basis") or {})
        basis.update(
            {
                "matching_engine": "rule_filter_fallback",
                "matching_logic_source": str(SECURITY_REQUIREMENTS_LOGIC_PATH),
                "template_source": str(SECURITY_REQUIREMENTS_PATH),
                "llm_fallback_reason": reason,
            }
        )
        item["match_basis"] = basis
        result.append(item)
    return result


def _rebind_security_requirement_evidence(
    selected: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
    context: dict[str, Any],
) -> list[dict[str, Any]]:
    """Reuse an LLM decision while refreshing path-specific audit facts."""
    current_by_id = {
        str(item.get("requirement_id") or ""): item for item in candidates
    }
    result: list[dict[str, Any]] = []
    for cached_item in selected:
        requirement_id = str(cached_item.get("requirement_id") or "")
        current_item = current_by_id.get(requirement_id)
        if current_item is None:
            continue
        item = dict(current_item)
        basis = dict(cached_item.get("match_basis") or {})
        current_basis = dict(item.get("match_basis") or {})
        for key in (
            "asset_type",
            "signal_category",
            "data_type",
            "security_attribute",
            "protocol",
            "critical_component",
            "operating_system",
            "external_interfaces",
            "attack_vector",
            "path_id",
            "risk_treatment",
        ):
            if key in current_basis:
                basis[key] = current_basis[key]
            elif key in context:
                basis[key] = context[key]
        item["match_basis"] = basis
        result.append(item)
    return result


def _llm_security_requirement_matcher(
    task: TaskUnit,
    *,
    attack_detail: dict[str, Any] | None = None,
    path_index: int | None = None,
) -> list[dict[str, Any]]:
    """Select workbook rows with LLM semantics after deterministic rule gating."""
    candidates = match_security_requirements(
        task,
        path=SECURITY_REQUIREMENTS_PATH,
        attack_detail=attack_detail,
        path_index=path_index,
    )
    if not SECURITY_REQUIREMENTS_LLM or not candidates:
        return candidates

    logic_path = str(Path(SECURITY_REQUIREMENTS_LOGIC_PATH).resolve())
    context = security_requirement_context(
        task, attack_detail=attack_detail, path_index=path_index
    )
    candidate_ids = tuple(
        str(item.get("requirement_id") or "") for item in candidates
    )
    system_prompt, user_prompt = build_security_requirement_llm_prompt(
        task,
        candidates,
        logic_text="",
        template_path=SECURITY_REQUIREMENTS_PATH,
        attack_detail=attack_detail,
        path_index=path_index,
    )
    candidate_id_set = set(candidate_ids)
    validator = lambda value: validate_security_requirement_llm_response(
        value, candidate_id_set
    )
    # The durable decision is bound to its upstream path node and the exact
    # candidate rows, rather than generated wording or a runtime path number.
    prompt_data = json.JSONDecoder().raw_decode(user_prompt)[0]
    selection_context = dict(prompt_data.get('当前攻击路径') or {})
    selection_context.pop('路径ID', None)
    selection_context.pop('攻击路径', None)
    selection_key = dependency_cache.stage_key(
        _stage_runtime_context(), task, 'security_requirements', system_prompt,
        parents={'attack_path': dependency_cache.path_reference(
            task, path_index if path_index is not None else -1, context['attack_path']
        )},
        knowledge={'candidate_rows': sorted(
            analysis_cache.digest_json(row) for row in prompt_data.get('规则匹配候选Excel整行', [])
        )},
        settings={'context': selection_context,
                  'logic': analysis_cache.file_digest(SECURITY_REQUIREMENTS_LOGIC_PATH)},
    )
    selection_stage = 'requirements:' + analysis_cache.digest_json(selection_key['dependencies']['parents'])
    cache_key = ('security-requirement-dependencies-v1', analysis_cache.digest_json(selection_key))
    with _security_requirement_selection_lock:
        cached_result = _security_requirement_selection_cache.get(cache_key)
    if cached_result is not None:
        dependency_cache.record_result(task, selection_stage, selection_key,
                                       {'requirement_ids': [item['requirement_id'] for item in cached_result]})
        return _rebind_security_requirement_evidence(cached_result, candidates, context)
    cached_selection = semantic_cache.get('security_requirement_dependency', selection_key)
    if cached_selection is not None and validator(cached_selection):
        dependency_cache.record_result(task, selection_stage, selection_key, cached_selection)
        return apply_security_requirement_llm_selection(
            candidates, cached_selection, logic_path=logic_path,
            template_path=str(Path(SECURITY_REQUIREMENTS_PATH).resolve()), cache_hit=True,
        )
    try:
        response, cache_hit = cached_llm_json(
            bucket="security_requirement_selection",
            cache_key=cache_key,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            # ``None`` and an empty list are invalid sentinels here: a
            # risk-mitigation path with rule candidates must retain at least
            # one security requirement.  Transport/parse failures therefore
            # trigger the same safe rule fallback.
            default={"requirement_ids": None},
            max_tokens=max(96, min(512, 24 + 12 * len(candidates))),
            response_format=security_requirement_llm_response_format(candidate_ids),
            validator=validator,
        )
        if not validator(response):
            selected = _security_requirement_fallback(
                candidates,
                reason="LLM 未返回至少一个合法编码，保留全部规则候选",
            )
        else:
            semantic_cache.set('security_requirement_dependency', selection_key, response)
            dependency_cache.record_result(task, selection_stage, selection_key, response)
            selected = apply_security_requirement_llm_selection(
                candidates,
                response,
                logic_path=logic_path,
                template_path=str(Path(SECURITY_REQUIREMENTS_PATH).resolve()),
                cache_hit=cache_hit,
            )
    except Exception as exc:
        logger.warning("安全需求 LLM 匹配失败，回退规则筛选: %s", exc)
        selected = _security_requirement_fallback(
            candidates, reason=f"LLM 调用异常: {exc}"
        )

    if all((item.get('match_basis') or {}).get('matching_engine') != 'rule_filter_fallback' for item in selected):
        with _security_requirement_selection_lock:
            _security_requirement_selection_cache[cache_key] = [dict(item) for item in selected]
    return selected


def _match_attack_vector_from_text(attack_text: str, frameworks: list[dict]) -> str | None:
    """从攻击路径文本中匹配框架，返回对应的 attack_vector。

    通过查找文本中出现的 external_interface 关键词确定对应框架，
    避免因 LLM 输出顺序与框架顺序不一致导致向量错配。

    Returns:
        attack_vector 字符串（network/adjacent/local/physical），或 None（无匹配）。
    """
    text_lower = attack_text.lower()

    # 1) 优先匹配框架的 external_interface（含中英文同义词）
    def _iface_in_text(ext_iface: str) -> bool:
        iface = ext_iface.lower().strip()
        if iface and iface in text_lower:
            return True
        # exact 匹配不中时检查常见中英文别名
        if ("bluetooth" in iface or "蓝牙" in iface) and ("蓝牙" in text_lower or "bluetooth" in text_lower):
            return True
        if iface in ("wifi", "wlan") and ("wifi" in text_lower or "wlan" in text_lower or "无线" in text_lower):
            return True
        if iface == "卫星定位" and "卫星" in text_lower:
            return True
        return False

    for fw in frameworks:
        ext = fw.get("external_interface") or ""
        if ext and _iface_in_text(ext):
            return normalize_attack_vector(fw.get("attack_vector", "")) or None

    # 2) Fallback: 关键词检测（与 _determine_attack_vector 一致）
    # 注意: 先检测具体接口关键词（蓝牙/usb/obd），再检测通用描述词（远程）
    # 避免 "通过蓝牙远程登录" 被误判为 network
    if any(k in text_lower for k in ["蓝牙", "bluetooth", "星闪", "v2x"]):
        return "adjacent"
    if any(k in text_lower for k in ["obd", "usb", "nfc", "tf卡", "sd卡", "ic卡", "充电口", "内部通讯"]):
        return "local"
    if any(k in text_lower for k in ["蜂窝", "4g", "5g", "lte", "ota", "cloud", "远程", "ethernet"]):
        return "network"
    if any(k in text_lower for k in ["wifi", "wlan", "ble", "射频", "rs232", "uwb", "卫星", "gnss", "gps", "北斗", "v2x"]):
        return "adjacent"
    if any(k in text_lower for k in ["jtag", "debug", "uart", "spi", "i2c"]):
        return "physical"
    return None


def _attack_vector_for_path(
    task: "TaskUnit",
    path_index: int,
    attack_text: str,
) -> str:
    """优先使用同序拓扑元数据；旧数据缺少对齐关系时再匹配文本。"""
    if path_index < len(task.selected_path_frameworks):
        vector = task.selected_path_frameworks[path_index].get("attack_vector")
        if vector:
            return str(vector)
    return _match_attack_vector_from_text(
        attack_text, task.selected_path_frameworks
    ) or ""


def compute_impact(influence_parameters: dict) -> tuple[int, str]:
    """按当前运行配置选择领域层的影响计算方法。"""
    return compute_impact_for_method(influence_parameters, IMPACT_METHOD)


def impact_risk_index(impact_value: int, impact_level: str) -> int:
    """返回传统 4×4 风险矩阵所需的 1~4 影响索引。

    HEAVENS 五级影响不得进入本函数，它只能与 HEAVENS 五级可行性通过
    calculate_heavens_risk_value() 使用原生 5×5 风险矩阵。
    """
    return impact_risk_index_for_method(impact_value, IMPACT_METHOD)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 5.4) 分离线程池（避免流水线任务等待同池内的 SC 子任务而死锁）
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def get_executor(max_workers: int | None = None) -> ThreadPoolExecutor:
    return _executor_registry.pipeline(max_workers or MAX_WORKERS)


def get_attack_path_executor() -> ThreadPoolExecutor:
    return _executor_registry.attack_path(ATTACK_PATH_WORKERS)


def get_attack_path_retry_executor() -> ThreadPoolExecutor:
    # Repair calls are rare and should not create a retry storm. Keep a small,
    # process-wide pool; the shared LLM semaphore still enforces the global cap.
    return _executor_registry.attack_path_retry(min(8, ATTACK_PATH_WORKERS))


def get_sc_executor() -> ThreadPoolExecutor:
    return _executor_registry.sc(max(MAX_CONCURRENT_LLM, SC_SAMPLES))


def get_checkpoint_executor() -> ThreadPoolExecutor:
    return _executor_registry.checkpoint()


def save_semantic_cache_async(path: str) -> None:
    _executor_registry.save_semantic_cache_async(semantic_cache, path)


def _submit_pipeline(executor, function, *args, **kwargs) -> Future:
    return _executor_registry.submit(executor, function, *args, **kwargs)


def _parallel_map(function, items) -> None:
    if items:
        _executor_registry.parallel_map(
            function, items, executor=get_executor(),
            window=MAX_PENDING_FUTURES,
        )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 5.5) Checkpoint（中间结果检查点）
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CHECKPOINT_VERSION = "v11.10"
_RUN_INPUT_SIGNATURE = ""


def _checkpoint_path(stage: str) -> str:
    return checkpoint_store.checkpoint_path(CHECKPOINT_DIR, stage)


@lru_cache(maxsize=1)
def _prompt_signature() -> str:
    """汇总关键业务提示词；提示词变化自动使旧检查点失效。"""
    prompt_names = (
        "DST_BATCH_SYSTEM_PROMPT",
        "ATTACK_ENTRY_SYSTEM_PROMPT",
        "ATTACK_PATH_SYSTEM_PROMPT",
        "ATTACK_TARGET_SYSTEM_PROMPT",
        "IMPACT_SYSTEM_PROMPT",
        "IMPACT_BATCH_SYSTEM_PROMPT",
        "AP_BATCH_SYSTEM_PROMPT",
        "CVSS_BATCH_SYSTEM_PROMPT",
        "HEAVENS_AP_BATCH_SYSTEM_PROMPT",
        "IMPACT_SC_NUMERIC_SYSTEM_PROMPT",
        "IMPACT_REASON_SYSTEM_PROMPT",
    )
    joined = "\n".join(str(globals().get(name, "")) for name in prompt_names)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


@lru_cache(maxsize=1)
def _pipeline_source_signature() -> str:
    """记录入口及拆分模块源码，防止代码已变更却恢复旧检查点。"""
    digest = hashlib.sha256()
    source_paths = sorted({
        os.path.abspath(__file__),
        os.path.join(_PROJECT_ROOT, "tara.py"),
        *(
            glob.glob(
                os.path.join(_PROJECT_ROOT, "automotive_tara", "**", "*.py"),
                recursive=True,
            )
        ),
    })
    for path in source_paths:
        if not os.path.isfile(path):
            continue
        digest.update(os.path.relpath(path, _PROJECT_ROOT).encode("utf-8"))
        with open(path, "rb") as source_file:
            for chunk in iter(lambda: source_file.read(1 << 20), b""):
                digest.update(chunk)
    return digest.hexdigest()


def _checkpoint_meta(method: str, total_tasks: int) -> dict:
    """生成当前运行的元信息快照，包含所有影响结果的参数。"""
    return {
        "method": method,
        "impact_method": IMPACT_METHOD,
        "total_tasks": total_tasks,
        "enable_rag": ENABLE_RAG,
        "enable_r155": ENABLE_R155,
        "rag_top_k": RAG_TOP_K,
        "enable_reason": ENABLE_REASON,
        "enable_consistency": ENABLE_CONSISTENCY,
        "enable_applicability_filter": ENABLE_APPLICABILITY_FILTER,
        "sc_enabled": SC_ENABLED,
        "sc_samples": SC_SAMPLES,
        "sc_multi_choice_concurrency": SC_MULTI_CHOICE_CONCURRENCY,
        "rating_reason_max_chars": RATING_REASON_MAX_CHARS,
        "batch_dst": BATCH_SIZE_DST,
        "batch_impact": BATCH_SIZE_IMPACT,
        "impact_repair_max_depth": IMPACT_REPAIR_MAX_DEPTH,
        "attack_paths_per_call": ATTACK_PATH_TASKS_PER_CALL,
        "attack_path_workers": ATTACK_PATH_WORKERS,
        "stage_c_max_concurrent_llm": STAGE_C_MAX_CONCURRENT_LLM,
        "vllm_max_num_seqs": VLLM_MAX_NUM_SEQS,
        "model": MODEL_NAME,
        "impact_model": IMPACT_MODEL_NAME,
        "lora_deployment_revisions": dict(_model_deployment_revisions),
        "temperature": TEMPERATURE,
        "seed": SAMPLING_SEED,
        "top_p": TOP_P,
        "top_k": TOP_K,
        "frequency_penalty": FREQUENCY_PENALTY,
        "presence_penalty": PRESENCE_PENALTY,
        "adaptive_scheduling": ADAPTIVE_SCHEDULING,
        "runtime_profile": RUNTIME_PROFILE,
        "max_tokens": MAX_TOKENS,
        "llm_retries": LLM_RETRIES,
        "model_context_tokens": MODEL_CONTEXT_TOKENS,
        "service_context_tokens": SERVICE_CONTEXT_TOKENS,
        "dynamic_token_budgets": _dynamic_token_budget_snapshot(),
        "dst_max_tokens": DST_MAX_TOKENS,
        "attack_component_max_tokens": ATTACK_COMPONENT_MAX_TOKENS,
        "impact_max_tokens": IMPACT_MAX_TOKENS,
        "feasibility_max_tokens": FEASIBILITY_MAX_TOKENS,
        "feasibility_paths_per_call": FEASIBILITY_PATHS_PER_CALL,
        "feasibility_reason_paths_per_call": FEASIBILITY_REASON_PATHS_PER_CALL,
        "pipeline_recovery_rounds": PIPELINE_RECOVERY_ROUNDS,
        "test_asset_selection": TEST_ASSET_SELECTION,
        "topology_paths_per_pair": TOPOLOGY_PATHS_PER_PAIR,
        "security_requirements_path": SECURITY_REQUIREMENTS_PATH,
        "security_requirements_logic_path": SECURITY_REQUIREMENTS_LOGIC_PATH,
        "security_requirements_llm": SECURITY_REQUIREMENTS_LLM,
        "security_requirements_scope": SECURITY_REQUIREMENTS_SCOPE,
        "security_requirements_implemented_reassessment": (
            SECURITY_REQUIREMENTS_IMPLEMENTED_REASSESSMENT
        ),
        "security_requirements_two_stage_reassessment": SECURITY_REQUIREMENTS_TWO_STAGE_REASSESSMENT,
        "security_requirements_reassessment_engine": (
            "deterministic_target"
            if SECURITY_REQUIREMENTS_IMPLEMENTED_REASSESSMENT else "off"
        ),
        "input_signature": _RUN_INPUT_SIGNATURE,
        "prompt_signature": _prompt_signature(),
        "source_signature": _pipeline_source_signature(),
        "dfd_file": DFD_FILE,
        "topology_file": TOPOLOGY_FILE,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "checkpoint_version": CHECKPOINT_VERSION,
    }


def save_checkpoint(tasks: list[TaskUnit], stage: str, method: str) -> str:
    return checkpoint_store.save_checkpoint(
        CHECKPOINT_DIR, tasks, stage, _checkpoint_meta(method, len(tasks))
    )


def save_checkpoint_async(tasks: list[TaskUnit], stage: str, method: str) -> None:
    checkpoint_store.save_checkpoint_async(
        CHECKPOINT_DIR, tasks, stage, _checkpoint_meta(method, len(tasks)),
        executor=get_checkpoint_executor(), futures=_checkpoint_futures,
        futures_lock=_checkpoint_futures_lock,
    )


def wait_for_checkpoint_writes() -> None:
    checkpoint_store.wait_for_writes(
        _checkpoint_futures, _checkpoint_futures_lock
    )


def checkpoint_is_compatible(
    stage: str, method: str, total_tasks: int
) -> bool:
    return checkpoint_store.is_compatible(
        CHECKPOINT_DIR, stage, _checkpoint_meta(method, total_tasks)
    )


def load_checkpoint(stage: str) -> list[TaskUnit] | None:
    return checkpoint_store.load_checkpoint(CHECKPOINT_DIR, stage)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 6) 输入解析（DFD.py 逻辑）
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 7) 功能清单加载
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def parse_dfd_json(input_dir: str) -> list[dict]:
    return _parse_dfd_json(input_dir, strict_inputs=STRICT_INPUTS)


def _attribute_applicability(
    asset_type: str, asset_name: str, asset_details: str, attribute_name: str,
) -> tuple[bool, str]:
    return _dfd_attribute_applicability(
        asset_type, asset_name, asset_details, attribute_name,
        enable_filter=ENABLE_APPLICABILITY_FILTER,
    )


def build_task_units(
    asset_results: list[dict],
    *,
    topology_node_names: set[str] | None = None,
    security_asset_facts: dict[str, Any] | None = None,
) -> list[TaskUnit]:
    return _build_task_units(
        asset_results,
        enable_applicability_filter=ENABLE_APPLICABILITY_FILTER,
        topology_node_names=topology_node_names,
        security_asset_facts=security_asset_facts,
    )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 8) 拓扑解析
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def parse_topology_and_generate_frameworks(
    topology_file: str,
    external_interface_excel: str,
    asset_results: list[dict] | None = None,
) -> list[dict]:
    return _parse_topology_frameworks(
        topology_file,
        external_interface_excel,
        asset_results,
        paths_per_pair=TOPOLOGY_PATHS_PER_PAIR,
        external_interface_loader=_load_external_interfaces,
    )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 8) Prompt（生成+内嵌自评）
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


# ── 批量生成系统提示词 ─────────────────────────


# ── 根据开关状态裁剪 prompt 示例中的 _reason 字段 ──
if not ENABLE_REASON:
    stripped_prompts = strip_disabled_reason_examples({
        "impact": IMPACT_BATCH_SYSTEM_PROMPT,
        "ap": AP_BATCH_SYSTEM_PROMPT,
        "heavens": HEAVENS_AP_BATCH_SYSTEM_PROMPT,
        "cvss": CVSS_BATCH_SYSTEM_PROMPT,
    })
    IMPACT_BATCH_SYSTEM_PROMPT = stripped_prompts["impact"]
    AP_BATCH_SYSTEM_PROMPT = stripped_prompts["ap"]
    HEAVENS_AP_BATCH_SYSTEM_PROMPT = stripped_prompts["heavens"]
    CVSS_BATCH_SYSTEM_PROMPT = stripped_prompts["cvss"]
    IMPACT_SYSTEM_PROMPT = strip_disabled_reason_examples(
        {"impact": IMPACT_SYSTEM_PROMPT}
    )["impact"]


IMPACT_SC_NUMERIC_SYSTEM_PROMPT = _build_impact_sc_numeric_prompt(
    IMPACT_BATCH_SYSTEM_PROMPT
)

def _append_reason_policy(prompt: str, fields: tuple[str, ...]) -> str:
    """兼容旧内部名称；开关值仍由当前运行配置动态决定。"""
    return append_reason_policy(prompt, fields, enabled=ENABLE_REASON)


IMPACT_SYSTEM_PROMPT = _append_reason_policy(
    IMPACT_SYSTEM_PROMPT, IMPACT_REASON_KEYS
)
IMPACT_BATCH_SYSTEM_PROMPT = _append_reason_policy(
    IMPACT_BATCH_SYSTEM_PROMPT, IMPACT_REASON_KEYS
)
AP_BATCH_SYSTEM_PROMPT = _append_reason_policy(
    AP_BATCH_SYSTEM_PROMPT, AP_MODEL_REASON_KEYS
)
HEAVENS_AP_BATCH_SYSTEM_PROMPT = _append_reason_policy(
    HEAVENS_AP_BATCH_SYSTEM_PROMPT, HEAVENS_REASON_KEYS
)
CVSS_BATCH_SYSTEM_PROMPT = _append_reason_policy(
    CVSS_BATCH_SYSTEM_PROMPT, CVSS_REASON_KEYS
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 9) 生成与评估核心函数
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


# ── 批量生成函数 ──────────────────────────────


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


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Self-Consistency 校准模块
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


# ── 智能体 RAG 查询生成 ────────────────────────────


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 10) 任务构建 + 路径筛选
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_PURE_DEVICE_RE = re.compile(
    r"传感器|执行器|电机|马达|泵|阀|灯|雨刮|加热丝|风扇|喇叭|扬声器|蜂鸣器|开关"
)
_ACCESS_CONTROL_CAPABILITY_RE = re.compile(
    r"控制器|ECU|域控|网关|系统|模块|主机|终端|账号|账户|用户|权限|认证|授权|"
    r"诊断|日志|审计|存储|升级|更新|安全|密钥|证书",
    re.IGNORECASE,
)


_filter_framework_cache: dict[
    tuple[Any, ...], tuple[list[dict], list[str]]
] = {}
_filter_framework_cache_lock = Lock()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 11) 并发流水线
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def finalize_task_status(task: TaskUnit) -> str:
    return _finalize_task_status(task, enable_reason=ENABLE_REASON)


_STAGE_CONFIG_NAMES = [
    'ATTACK_PATH_TASKS_PER_CALL', 'DIRECT_ATTACK_PATHS_PER_CALL',
    'DIRECT_ATTACK_PATH_RETRY_MAX_CALLS',
    'BATCH_SIZE_ATTACK', 'ENABLE_ASSET_DETAILS', 'ENABLE_CONSISTENCY',
    'ENABLE_RAG', 'ENABLE_REASON', 'FEASIBILITY_PATHS_PER_CALL',
    'FEASIBILITY_REASON_PATHS_PER_CALL', 'IMPACT_METHOD',
    'IMPACT_REPAIR_MAX_DEPTH', 'MAX_PENDING_FUTURES', 'MAX_WORKERS',
    'MODEL_CONTEXT_TOKENS', 'MODEL_NAME', 'SC_CONFIDENCE_THRESHOLD',
    'SC_ENABLED', 'SC_SAMPLES', 'SC_SINGLE_CALL',
    'STAGE_C_CACHE_FLUSH_SECONDS', 'STAGE_C_CACHE_FLUSH_TASKS',
    'STAGE_C_FINAL_RETRY_MAX_PATHS',
    'TEMPERATURE', 'SAMPLING_SEED', 'TOP_P', 'TOP_K',
    'FREQUENCY_PENALTY', 'PRESENCE_PENALTY', 'ADAPTIVE_SCHEDULING',
    'LLM_RETRIES',
    # Prompt 属于运行配置。理由开关生成的最终 Prompt 必须经 Context
    # 传入阶段模块，不能使用阶段模块导入时保存的旧副本。
    'DST_BATCH_SYSTEM_PROMPT', 'IMPACT_SYSTEM_PROMPT',
    'IMPACT_BATCH_SYSTEM_PROMPT', 'IMPACT_REASON_SYSTEM_PROMPT',
    'IMPACT_SC_NUMERIC_SYSTEM_PROMPT', 'ATTACK_ENTRY_SYSTEM_PROMPT',
    'ATTACK_PATH_SYSTEM_PROMPT', 'ATTACK_TARGET_SYSTEM_PROMPT',
    'AP_BATCH_SYSTEM_PROMPT', 'CVSS_BATCH_SYSTEM_PROMPT',
    'HEAVENS_AP_BATCH_SYSTEM_PROMPT',
]
_STAGE_STATE_NAMES = ['_filter_framework_cache', '_filter_framework_cache_lock', 'rag_kb', 'sc_multi_choice_semaphore', 'semantic_cache', 'stage_c_llm_semaphore', '_FUNCTION_DESC_MAP', '_model_deployment_revisions', '_cache_model_revisions']
_STAGE_SERVICE_NAMES = [
    "_add_phase_time", "_attack_vector_for_path", "_attribute_applicability",
    "_build_llm_cache_key", "_call_attack_entry_chunk",
    "_generate_direct_attack_paths",
    "_dynamic_token_budget", "_fallback_impact_batch",
    "_generate_attack_target_actions",
    "_impact_batch_max_tokens", "_increment_pipeline_metric",
    "_retry_single_feasibility_item", "_set_pipeline_metric",
    "_submit_pipeline", "cached_llm_json", "compute_impact",
    "finalize_task_status", "generate_attack_parameters_ap_batch",
    "generate_attack_parameters_cvss_batch",
    "generate_attack_parameters_heavens_batch", "get_attack_path_executor",
    "get_attack_path_retry_executor", "get_executor",
    "get_sc_executor", "impact_risk_index", "llm_call_with_semaphore",
]


def _stage_runtime_context(stage: str | None = None) -> RuntimeContext:
    namespace = globals()
    services = {name: namespace[name] for name in _STAGE_SERVICE_NAMES}
    if stage == "impact" and IMPACT_MODEL_NAME != MODEL_NAME:
        # Request-scoped routing is safe during concurrent pipeline stages.
        services["llm_call_with_semaphore"] = partial(llm_call_with_semaphore, model_override=IMPACT_MODEL_NAME)
        services["_build_llm_cache_key"] = partial(_build_llm_cache_key, model_override=IMPACT_MODEL_NAME)
        services["cached_llm_json"] = partial(cached_llm_json, model_override=IMPACT_MODEL_NAME)
    return RuntimeContext(
        config={**{name: namespace[name] for name in _STAGE_CONFIG_NAMES},
                'IMPACT_MODEL_NAME': IMPACT_MODEL_NAME},
        services=services,
        state={name: namespace.get(name) for name in _STAGE_STATE_NAMES},
        record_metric=_increment_pipeline_metric,
    )


_STAGE_DELEGATES = {
    "_apply_dst_item": (dst_stage, "_apply_dst_item"),
    "_call_dst_subset": (dst_stage, "_call_dst_subset"),
    "_dst_item_cache_key": (dst_stage, "_dst_item_cache_key"),
    "_dst_prompt": (dst_stage, "_dst_prompt"),
    "_dst_response_format": (dst_stage, "_dst_response_format"),
    "_exec_dst_batch": (dst_stage, "_exec_dst_batch"),
    "_parse_dst_result": (dst_stage, "_parse_dst_result"),
    "_parse_dst_short_result": (dst_stage, "_parse_dst_short_result"),
    "_retry_dst_capability_conflict": (dst_stage, "_retry_dst_capability_conflict"),
    "_validate_dst_capability_assertion": (dst_stage, "_validate_dst_capability_assertion"),
    "_align_task_results": (impact_stage, "_align_task_results"),
    "_apply_impact_result": (impact_stage, "_apply_impact_result"),
    "_exec_impact_batch": (impact_stage, "_exec_impact_batch"),
    "_fallback_impact_batch": (impact_stage, "_fallback_impact_batch"),
    "_find_best_match_sample": (impact_stage, "_find_best_match_sample"),
    "_impact_batch_response_format": (impact_stage, "_impact_batch_response_format"),
    "_impact_reason_response_format": (impact_stage, "_impact_reason_response_format"),
    "_populate_sc_impact_reasons": (impact_stage, "_populate_sc_impact_reasons"),
    "_reason_fields_valid": (impact_stage, "_reason_fields_valid"),
    "_request_sc_impact_reasons": (impact_stage, "_request_sc_impact_reasons"),
    "_sc_aggregate_numeric": (impact_stage, "_sc_aggregate_numeric"),
    "_sc_exec_impact_with_sc": (impact_stage, "_sc_exec_impact_with_sc"),
    "_validated_numeric_params": (impact_stage, "_validated_numeric_params"),
    "generate_influence_parameters": (impact_stage, "generate_influence_parameters"),
    "_attack_entry_cache_key": (attack_path_stage, "_attack_entry_cache_key"),
    "_attack_entry_signature": (attack_path_stage, "_attack_entry_signature"),
    "_call_attack_entry_chunk": (attack_path_stage, "_call_attack_entry_chunk"),
    "_generate_direct_attack_paths": (attack_path_stage, "_generate_direct_attack_paths"),
    "_normalize_direct_attack_path_format": (attack_path_stage, "_normalize_direct_attack_path_format"),
    "_compose_hybrid_attack_path": (attack_path_stage, "_compose_hybrid_attack_path"),
    "_entry_action_mentions_interface": (attack_path_stage, "_entry_action_mentions_interface"),
    "_exec_attack_path_batch": (attack_path_stage, "_exec_attack_path_batch"),
    "_fallback_entry_action": (attack_path_stage, "_fallback_entry_action"),
    "_fallback_target_action": (attack_path_stage, "_fallback_target_action"),
    "_framework_route_sentence": (attack_path_stage, "_framework_route_sentence"),
    "_framework_route_tokens": (attack_path_stage, "_framework_route_tokens"),
    "_generate_attack_target_actions": (attack_path_stage, "_generate_attack_target_actions"),
    "_hybrid_paths_valid": (attack_path_stage, "_hybrid_paths_valid"),
    "_normalize_target_action": (attack_path_stage, "_normalize_target_action"),
    "_plain_attack_path_text": (attack_path_stage, "_plain_attack_path_text"),
    "_plain_attack_text": (attack_path_stage, "_plain_attack_text"),
    "_prepare_attack_entry_catalog": (attack_path_stage, "_prepare_attack_entry_catalog"),
    "_target_action_cache_key": (attack_path_stage, "_target_action_cache_key"),
    "filter_path_frameworks": (attack_path_stage, "filter_path_frameworks"),
    "_align_path_parameter_list": (feasibility_stage, "_align_path_parameter_list"),
    "_apply_feasibility_result": (feasibility_stage, "_apply_feasibility_result"),
    "_build_feasibility_details": (feasibility_stage, "_build_feasibility_details"),
    "_cross_task_feasibility_prompt": (feasibility_stage, "_cross_task_feasibility_prompt"),
    "_cross_task_feasibility_response_format": (feasibility_stage, "_cross_task_feasibility_response_format"),
    "_generate_cross_task_feasibility_batch": (feasibility_stage, "_generate_cross_task_feasibility_batch"),
    "_normalize_ap_model_params": (feasibility_stage, "_normalize_ap_model_params"),
    "_normalize_cvss_model_params": (feasibility_stage, "_normalize_cvss_model_params"),
    "_normalize_heavens_model_params": (feasibility_stage, "_normalize_heavens_model_params"),
    "_retry_single_feasibility_item": (feasibility_stage, "_retry_single_feasibility_item"),
    "_sc_ap_chunk": (feasibility_stage, "_sc_ap_chunk"),
    "_stage_c_attack_cross_task": (feasibility_stage, "_stage_c_attack_cross_task"),
    "_validate_cross_task_feasibility_item": (feasibility_stage, "_validate_cross_task_feasibility_item"),
    "generate_attack_parameters_ap_batch": (feasibility_stage, "generate_attack_parameters_ap_batch"),
    "generate_attack_parameters_cvss_batch": (feasibility_stage, "generate_attack_parameters_cvss_batch"),
    "generate_attack_parameters_heavens_batch": (feasibility_stage, "generate_attack_parameters_heavens_batch"),
    "stage_c_attack_batch": (feasibility_stage, "stage_c_attack_batch"),
}


def _make_stage_delegate(module, function_name: str):
    implementation = getattr(module, function_name)

    def delegate(*args, **kwargs):
        return implementation(
            _stage_runtime_context("impact" if module is impact_stage else None),
            *args, **kwargs,
        )

    delegate.__name__ = function_name
    delegate.__qualname__ = function_name
    return delegate


for _delegate_name, (_delegate_module, _implementation_name) in _STAGE_DELEGATES.items():
    globals()[_delegate_name] = _make_stage_delegate(
        _delegate_module, _implementation_name
    )
del _delegate_name, _delegate_module, _implementation_name


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 12) 报告构建
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_MITIGATION_TREATMENTS = {"风险缓解", "risk mitigation", "mitigation"}


def _needs_implemented_control(detail: dict[str, Any], task: TaskUnit) -> bool:
    """Target paths selected by this run's mitigation threshold."""
    risk = detail.get("risk_value_num")
    if risk is None:
        risk = detail.get("risk_value")
    if isinstance(risk, (int, float)) and not isinstance(risk, bool):
        return risk >= (3 if SECURITY_REQUIREMENTS_SCOPE == "345" else 4)
    treatment = str(
        detail.get("risk_treatment", task.risk_treatment) or ""
    ).strip().casefold()
    return treatment in _MITIGATION_TREATMENTS


def _requirement_scope_treatment(risk_value: int) -> str:
    if SECURITY_REQUIREMENTS_SCOPE == "345" and risk_value == 3:
        return "风险缓解"
    return get_risk_treatment(risk_value)


def _refresh_risk_treatments(tasks: list[TaskUnit]) -> None:
    """Apply the current risk threshold to new and resumed feasibility results."""
    for task in tasks:
        for detail in task.attack_details or []:
            if not isinstance(detail, dict):
                continue
            value = detail.get("risk_value_num")
            if value is None:
                value = detail.get("risk_value")
            if (
                isinstance(value, (int, float))
                and not isinstance(value, bool)
                and value in (1, 2, 3, 4, 5)
            ):
                detail["risk_treatment"] = _requirement_scope_treatment(int(value))
        value = task.risk_value
        if (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and value in (1, 2, 3, 4, 5)
        ):
            task.risk_treatment = _requirement_scope_treatment(int(value))


def _freeze_path_security_requirements(tasks: list[TaskUnit]) -> int:
    """Select and attach the exact workbook rows used by every mitigation path.

    Security-requirement selection historically happened only while rendering
    the report.  Residual-risk assessment needs the same result earlier, so we
    freeze it once on the path and let both reports reuse it.
    """
    matcher = (
        _llm_security_requirement_matcher
        if SECURITY_REQUIREMENTS_LLM
        else match_security_requirements
    )
    selected_paths = 0
    for task in tasks:
        for path_index, detail in enumerate(task.attack_details or []):
            if not _needs_implemented_control(detail, task):
                continue
            requirements = matcher(
                task,
                attack_detail=detail,
                path_index=path_index,
            )
            detail["security_requirements"] = list(requirements or [])
            detail["security_requirement_match_status"] = (
                "matched" if requirements else "no_template_match"
            )
            if requirements:
                selected_paths += 1
            else:
                logger.warning(
                    "需缓解路径没有可用安全需求，无法执行实施后复评: task=%s path=%d",
                    task.task_id,
                    path_index,
                )
    return selected_paths


def _reassessment_dimension_keys(method: str) -> tuple[str, ...]:
    if method == "cvss":
        return ("complexity", "privileges", "user_interaction")
    if method == "heavens":
        return tuple(HEAVENS_AP_ALLOWED_VALUES)
    return tuple(AP_ALLOWED_VALUES)


def _baseline_reassessment_context(detail: dict[str, Any], method: str) -> dict[str, Any]:
    parameters = detail.get("attack_parameters") or {}
    return {
        "评级方法": method,
        "基线维度": {
            key: parameters[key]
            for key in _reassessment_dimension_keys(method)
            if key in parameters
        },
        "基线可行性分值": detail.get("feasibility_score"),
        "基线可行性等级": detail.get("feasibility_level"),
        "基线风险值": detail.get("risk_value_num", detail.get("risk_value")),
    }


def _reassessment_difficulty_conflicts(
    baseline: dict[str, Any], generated: dict[str, Any], method: str
) -> list[dict[str, Any]]:
    """Identify a control implementation that appears to make one path easier."""
    old = baseline.get("attack_parameters") or {}
    new = generated.get("attack_parameters") or {}
    conflicts = []
    for key in _reassessment_dimension_keys(method):
        old_value, new_value = old.get(key), new.get(key)
        if any(
            isinstance(value, bool) or not isinstance(value, (int, float))
            for value in (old_value, new_value)
        ):
            continue
        easier = new_value > old_value if method == "cvss" else new_value < old_value
        if easier:
            conflicts.append({"dimension": key, "baseline": old_value, "reassessed": new_value})
    return conflicts


def _implemented_control_prompt(
    attack_path: str, requirements: list[dict[str, Any]],
    baseline_detail: dict[str, Any], method: str,
) -> str:
    """Add a compact, explicit implemented-control premise to one path."""
    controls = [
        {
            "安全需求编码": str(item.get("requirement_id") or ""),
            "安全需求": str(
                item.get("requirement")
                or item.get("security_requirement")
                or item.get("name")
                or ""
            ),
        }
        for item in requirements
    ]
    direction = (
        "CVSS可利用性系数变大意味着攻击更容易。"
        if method == "cvss" else "攻击潜力维度分值变小意味着攻击更容易。"
    )
    return (
        f"{attack_path}\n\n"
        "【安全需求实施后复评前提】以下安全需求已经全部实现且有效运行。"
        "保持资产、威胁场景、原攻击路径、攻击入口和攻击向量等其他输入不变，"
        "请逐维对照下列基线评级，评估控制实施后的剩余攻击可行性。"
        "仅在安全需求确实影响某维度时调整该维度；不得为达成风险接受目标而编造分值。"
        "如判断某维度反而更容易，仍输出真实判断，程序将标记评级冲突供人工复核。"
        + direction + "\n【实施前基线评级】"
        + orjson.dumps(_baseline_reassessment_context(baseline_detail, method)).decode("utf-8")
        + "\n【已实施安全需求】"
        + orjson.dumps(controls).decode("utf-8")
    )


def _reassess_after_security_requirements(
    tasks: list[TaskUnit], method: str
) -> list[TaskUnit]:
    """Return a copy whose mitigation paths contain residual-risk ratings."""
    residual_tasks = copy.deepcopy(tasks)
    if method == "attack_vector":
        logger.warning(
            "攻击向量法没有可由安全需求改变的 AI 评级维度；实施后报告沿用原评级"
        )
        return residual_tasks

    work_tasks: list[TaskUnit] = []
    mappings: list[tuple[int, list[int]]] = []
    for task_index, task in enumerate(tasks):
        selected_indices = [
            index
            for index, detail in enumerate(task.attack_details or [])
            if detail.get("security_requirements")
            and str(
                detail.get("risk_treatment", task.risk_treatment) or ""
            ).strip().casefold() in _MITIGATION_TREATMENTS
        ]
        if not selected_indices:
            continue
        work = copy.deepcopy(task)
        work.attack_paths = [
            _implemented_control_prompt(
                str(task.attack_details[index].get("attack_path") or ""),
                list(task.attack_details[index]["security_requirements"]),
                task.attack_details[index],
                method,
            )
            for index in selected_indices
        ]
        work.selected_path_frameworks = [
            copy.deepcopy(task.selected_path_frameworks[index])
            for index in selected_indices
            if index < len(task.selected_path_frameworks)
        ]
        work.attack_path_provenance = [
            copy.deepcopy(task.attack_path_provenance[index])
            for index in selected_indices
            if index < len(task.attack_path_provenance)
        ]
        work.attack_details = []
        work.feasibility_confidence = []
        work_tasks.append(work)
        mappings.append((task_index, selected_indices))

    if not work_tasks:
        return residual_tasks

    logger.info(
        "Step 9：安全需求实施后复评，共 %d 个任务 / %d 条风险缓解路径",
        len(work_tasks),
        sum(len(indices) for _, indices in mappings),
    )
    stage_c_attack_batch(work_tasks, method)

    for work, (task_index, selected_indices) in zip(work_tasks, mappings):
        target = residual_tasks[task_index]
        for local_index, original_index in enumerate(selected_indices):
            baseline = target.attack_details[original_index]
            requirements = list(baseline.get("security_requirements") or [])
            if local_index >= len(work.attack_details):
                baseline["security_requirement_reassessment_status"] = "failed"
                continue
            generated = work.attack_details[local_index]
            # Preserve the original record byte-for-byte outside the fields
            # that are consequences of feasibility rerating.  In particular,
            # impact, path text/vector, topology trace, scenarios and selected
            # requirements are not regenerated or replaced.
            reassessed = dict(baseline)
            for field in (
                "attack_parameters",
                "feasibility_score",
                "feasibility_level",
                "risk_value",
                "risk_value_num",
                "risk_treatment",
                "feasibility_confidence",
            ):
                if field in generated:
                    reassessed[field] = copy.deepcopy(generated[field])
            reassessed["security_requirements"] = requirements
            reassessed["security_requirements_implemented"] = True
            reassessed["security_requirement_reassessment_baseline"] = (
                _baseline_reassessment_context(baseline, method)
            )
            conflicts = _reassessment_difficulty_conflicts(baseline, generated, method)
            if conflicts:
                reason = "安全需求实施后评级冲突：" + "；".join(
                    f"{item['dimension']} {item['baseline']}→{item['reassessed']}"
                    for item in conflicts
                ) + "；攻击难度反而下降，需人工复核"
                reassessed["security_requirement_rating_conflicts"] = conflicts
                reassessed["security_requirement_reassessment_status"] = "rating_conflict"
                reassessed["security_requirement_reassessment_model_treatment"] = (
                    generated.get("risk_treatment")
                )
                reassessed["risk_treatment"] = "需复核"
                reassessed["review_required"] = True
                reassessed["review_reasons"] = [
                    *list(baseline.get("review_reasons") or []), reason
                ]
                logger.warning(
                    "安全需求实施后评级冲突 task=%s path=%d: %s",
                    target.task_id, original_index, reason,
                )
            else:
                reassessed["security_requirement_reassessment_status"] = "completed"
            target.attack_details[original_index] = reassessed

        valid_risks = [
            detail.get("risk_value_num", detail.get("risk_value"))
            for detail in target.attack_details
            if isinstance(
                detail.get("risk_value_num", detail.get("risk_value")),
                (int, float),
            )
        ]
        if valid_risks:
            target.risk_value = max(valid_risks)
            target.risk_treatment = get_risk_treatment(target.risk_value)
        if any(d.get("security_requirement_reassessment_status") == "rating_conflict" for d in target.attack_details):
            target.risk_treatment = "需复核"
        target.feasibility_confidence = [
            dict(detail.get("feasibility_confidence") or {})
            for detail in target.attack_details
        ]
    return residual_tasks

def _post_control_path_decision(
    task: TaskUnit, detail: dict[str, Any]
) -> dict[str, Any]:
    """One bounded model decision; invalid/failed calls remain unscored."""
    requirements = list(detail.get("security_requirements") or [])
    original_path = str(detail.get("attack_path") or "")
    system_prompt, user_prompt = build_post_control_path_prompt(
        task, detail, requirements
    )
    validator = lambda value: validate_post_control_path(
        value, requirements, original_path
    )
    try:
        response, _ = cached_llm_json(
            bucket="post_control_attack_path_v1",
            cache_key=(task.task_id, original_path, requirements),
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            default=None,
            max_tokens=min(1536, 384 + 128 * len(requirements)),
            response_format=post_control_path_response_format(),
            validator=validator,
        )
        if validator(response):
            return response
        reason = "模型未给出完整、可核验的新攻击路径判断"
    except Exception as exc:
        reason = f"新攻击路径判断失败：{type(exc).__name__}: {exc}"
        logger.warning("安全需求实施后路径判定失败 task=%s: %s", task.task_id, reason)
    return {
        "status": "uncertain", "post_control_path": "",
        "basis": reason, "control_analysis": [],
    }


def _mark_post_control_review(
    detail: dict[str, Any], status: str, reason: str
) -> None:
    # A failed post-control rating has no residual score. Keeping the copied
    # baseline dimensions would make the implemented report look assessed.
    for field in (
        "attack_parameters", "feasibility_score", "feasibility_level",
        "risk_value", "risk_value_num", "feasibility_confidence",
    ):
        detail[field] = None
    detail["security_requirements_implemented"] = True
    detail["security_requirement_rating_within_range"] = False
    detail["security_requirement_reassessment_status"] = status
    detail["risk_treatment"] = "需复核"
    detail["review_required"] = True
    detail["review_reasons"] = [*list(detail.get("review_reasons") or []), reason]


def _finalize_target_reassessment_tasks(tasks: list[TaskUnit]) -> None:
    for task in tasks:
        unresolved = any(
            str(detail.get("security_requirement_reassessment_status") or "").endswith("needs_review")
            for detail in task.attack_details
        )
        risks = [
            detail.get("risk_value_num") for detail in task.attack_details
            if isinstance(detail.get("risk_value_num"), (int, float))
        ]
        task.risk_value = None if unresolved else max(risks, default=None)
        task.risk_treatment = "需复核" if unresolved else (
            get_risk_treatment(task.risk_value) if task.risk_value is not None else "需复核"
        )
        task.feasibility_confidence = [
            dict(detail.get("feasibility_confidence") or {}) for detail in task.attack_details
        ]


def _residual_risk_target_failures(
    baseline_tasks: list[TaskUnit], residual_tasks: list[TaskUnit]
) -> list[dict[str, Any]]:
    """Reject scoped mitigation paths without implemented risk <= 2."""
    failures: list[dict[str, Any]] = []
    for task_index, baseline_task in enumerate(baseline_tasks):
        residual_task = residual_tasks[task_index] if task_index < len(residual_tasks) else None
        details = (residual_task.attack_details or []) if residual_task is not None else []
        for path_index, baseline in enumerate(baseline_task.attack_details or []):
            if not _needs_implemented_control(baseline, baseline_task):
                continue
            detail = details[path_index] if path_index < len(details) else {}
            risk = detail.get("risk_value_num")
            if risk is None:
                risk = detail.get("risk_value")
            status = detail.get("security_requirement_reassessment_status")
            reasons = []
            if not detail.get("security_requirements"):
                reasons.append("缺少已选择的安全需求")
            if not detail.get("security_requirements_implemented"):
                reasons.append("安全需求实施前提未确认")
            if status not in {"completed", "target_constrained_model", "target_constructed"}:
                reasons.append(f"复评状态未完成：{status or '缺失'}")
            if isinstance(risk, bool) or not isinstance(risk, (int, float)) or risk not in (1, 2):
                reasons.append(f"实施后风险值未达到≤2：{risk!r}")
            if str(detail.get("risk_treatment") or "").strip() != "风险接受":
                reasons.append("风险处置不是风险接受")
            if reasons:
                failures.append({
                    "task_id": baseline_task.task_id,
                    "path_index": path_index,
                    "reasons": reasons,
                })
    return failures


def _enforce_residual_risk_target(
    baseline_tasks: list[TaskUnit], residual_tasks: list[TaskUnit],
    baseline_report: list[dict], baseline_output_path: str, failure_path: str,
) -> None:
    """Do not publish an implemented-control report with any risk above two."""
    failures = _residual_risk_target_failures(baseline_tasks, residual_tasks)
    if not failures:
        return
    save_json(baseline_report, baseline_output_path)
    save_json({
        "target_risk_max": 2,
        "failed_paths": len(failures),
        "failures": failures,
    }, failure_path)
    logger.error(
        "实施后风险≤2强制验收失败：%d 条需缓解路径未达标；明细：%s",
        len(failures), failure_path,
    )
    raise RuntimeError(
        f"实施后报告未生成：{len(failures)} 条需缓解路径"
        f"未达到风险值≤2；请查看 {failure_path}"
    )


def _reassess_after_security_requirements_deterministic(
    tasks: list[TaskUnit], method: str
) -> list[TaskUnit]:
    """Construct legal target-scenario dimensions without a post-control LLM call."""
    residual = copy.deepcopy(tasks)
    success_count = 0
    unresolved_count = 0
    for task_index, task in enumerate(tasks):
        impact_index = (
            1 if IMPACT_METHOD == "heavens" else
            impact_risk_index_for_method(task.impact_value, IMPACT_METHOD)
        )
        for path_index, source in enumerate(task.attack_details or []):
            if not _needs_implemented_control(source, task):
                continue
            target = residual[task_index].attack_details[path_index]
            target["security_requirement_reassessment_mode"] = "deterministic_target"
            target["security_requirement_reassessment_baseline"] = (
                _baseline_reassessment_context(source, method)
            )
            target["security_requirement_reassessment_path_status"] = "original_path_retained"
            target["security_requirement_reassessment_path_basis"] = (
                "不重新生成攻击路径；按控制已实施的目标情景选择合法评分组合"
            )
            target["security_requirement_reassessment_model_rating"] = None
            if not source.get("security_requirements"):
                _mark_post_control_review(
                    target, "missing_requirements_needs_review",
                    "需缓解路径没有可用安全需求，不能构造实施后目标情景",
                )
                unresolved_count += 1
                continue
            constraints = build_target_rating_constraints(
                source, method, impact_index, task.impact_level, IMPACT_METHOD,
            )
            target["security_requirement_reassessment_constraints"] = constraints
            if constraints is None:
                _mark_post_control_review(
                    target, "target_range_unavailable_needs_review",
                    "固定影响等级、攻击向量和合法维度下不存在风险≤2的评分组合",
                )
                unresolved_count += 1
                continue
            rating = synthesize_target_rating(
                source, constraints, method, impact_index,
                task.impact_level, IMPACT_METHOD,
            )
            if rating is None:
                _mark_post_control_review(
                    target, "target_combination_invalid_needs_review",
                    "程序未能构造通过逐维、总分及风险矩阵校验的组合",
                )
                unresolved_count += 1
                continue
            for field, value in rating.items():
                target[field] = copy.deepcopy(value)
            target["security_requirements_implemented"] = True
            target["security_requirement_rating_within_range"] = True
            target["security_requirement_reassessment_status"] = "target_constructed"
            target["security_requirement_reassessment_score_origin"] = "deterministic_target_scenario"
            target["review_required"] = True
            target["review_reasons"] = [
                *list(target.get("review_reasons") or []),
                "目标情景分值由程序在合法范围内构造；需核验控制实际效果与逐维评分依据。",
            ]
            success_count += 1
    _finalize_target_reassessment_tasks(residual)
    logger.info(
        "Step 9 确定性目标评分完成：%d 条风险≤2，%d 条无合法组合或缺少需求",
        success_count, unresolved_count,
    )
    return residual


def _reassess_after_security_requirements_two_stage(
    tasks: list[TaskUnit], method: str
) -> list[TaskUnit]:
    """Compute feasible rating ranges first, then accept only an in-range model rating."""
    residual = copy.deepcopy(tasks)
    mitigation = [
        (ti, pi) for ti, task in enumerate(tasks)
        for pi, detail in enumerate(task.attack_details or [])
        if str(
            detail.get("risk_treatment", task.risk_treatment) or ""
        ).strip().casefold() in _MITIGATION_TREATMENTS
    ]
    selected = [
        (ti, pi) for ti, pi in mitigation
        if tasks[ti].attack_details[pi].get("security_requirements")
    ]
    selected_set = set(selected)
    for ti, pi in mitigation:
        target = residual[ti].attack_details[pi]
        target["security_requirement_reassessment_mode"] = "bounded_llm"
        target["security_requirement_reassessment_baseline"] = _baseline_reassessment_context(
            tasks[ti].attack_details[pi], method
        )
        if (ti, pi) not in selected_set:
            _mark_post_control_review(
                target, "missing_requirements_needs_review",
                "风险缓解路径没有可用安全需求，无法生成实施后评级",
            )
            target["security_requirements_implemented"] = False
    if not selected:
        if mitigation:
            _finalize_target_reassessment_tasks(residual)
        return residual
    if method == "attack_vector":
        for ti, pi in selected:
            _mark_post_control_review(
                residual[ti].attack_details[pi], "unsupported_needs_review",
                "攻击向量法没有可行性分值维度范围，无法执行目标范围复评",
            )
        _finalize_target_reassessment_tasks(residual)
        return residual

    def risk_index(task: TaskUnit) -> int:
        return (
            1 if IMPACT_METHOD == "heavens" else
            impact_risk_index_for_method(task.impact_value, IMPACT_METHOD)
        )

    logger.info("Step 9 新版第一步：判断 %d 条实施后攻击路径", len(selected))
    decisions: dict[tuple[int, int], dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=min(6, len(selected))) as pool:
        futures = {
            pool.submit(_post_control_path_decision, tasks[ti], tasks[ti].attack_details[pi]): (ti, pi)
            for ti, pi in selected
        }
        for future in as_completed(futures):
            slot = futures[future]
            try:
                decisions[slot] = future.result()
            except Exception as exc:
                logger.warning("实施后路径判定失败 task=%s path=%d: %s", tasks[slot[0]].task_id, slot[1], exc)
                decisions[slot] = {
                    "status": "uncertain", "post_control_path": "",
                    "basis": "模型调用异常，路径状态待复核",
                    "control_analysis": [],
                }

    constraints_by_slot: dict[tuple[int, int], dict[str, Any]] = {}
    eligible: list[tuple[int, int]] = []
    for ti, pi in selected:
        task = tasks[ti]
        constraints = build_target_rating_constraints(
            task.attack_details[pi], method, risk_index(task),
            task.impact_level, IMPACT_METHOD,
        )
        if constraints is None:
            target = residual[ti].attack_details[pi]
            _mark_post_control_review(
                target, "target_range_unavailable_needs_review",
                "基线维度无法生成风险≤2的合法评级范围；实施后风险未评级",
            )
            target["security_requirement_reassessment_mode"] = "bounded_llm"
            continue
        constraints_by_slot[(ti, pi)] = constraints
        eligible.append((ti, pi))

    work_tasks: list[TaskUnit] = []
    mappings: list[tuple[int, list[int]]] = []
    for ti, task in enumerate(tasks):
        indices = [pi for task_index, pi in eligible if task_index == ti]
        if not indices:
            continue
        work = copy.deepcopy(task)
        work.attack_paths = [
            build_post_control_rating_input(
                decisions[(ti, pi)], task.attack_details[pi], method,
                list(task.attack_details[pi].get("security_requirements") or []),
                constraints_by_slot[(ti, pi)],
            )
            for pi in indices
        ]
        work.selected_path_frameworks = [
            copy.deepcopy(task.selected_path_frameworks[pi])
            if pi < len(task.selected_path_frameworks) else {}
            for pi in indices
        ]
        work.attack_path_provenance = [
            copy.deepcopy(task.attack_path_provenance[pi])
            if pi < len(task.attack_path_provenance) else {}
            for pi in indices
        ]
        work.attack_details = []
        work.feasibility_confidence = []
        work_tasks.append(work)
        mappings.append((ti, indices))

    accepted: dict[tuple[int, int], dict[str, Any]] = {}
    latest_attempt: dict[tuple[int, int], dict[str, Any] | None] = {}
    logger.info("Step 9 新版第二步：先算评分范围，再让模型对 %d 条路径限范围评分", len(eligible))
    if work_tasks:
        try:
            stage_c_attack_batch(work_tasks, method)
        except Exception as exc:
            logger.warning("范围内复评模型调用失败: %s", exc)
            for work in work_tasks:
                work.attack_details = []

    for work, (ti, indices) in zip(work_tasks, mappings):
        for local_index, pi in enumerate(indices):
            slot = (ti, pi)
            raw = (
                work.attack_details[local_index]
                if local_index < len(work.attack_details)
                and isinstance(work.attack_details[local_index], dict)
                and work.attack_details[local_index].get("attack_path") == work.attack_paths[local_index]
                else None
            )
            latest_attempt[slot] = raw
            if raw and validate_target_rating(
                raw, tasks[ti].attack_details[pi], constraints_by_slot[slot],
                method, risk_index(tasks[ti]), tasks[ti].impact_level, IMPACT_METHOD,
            ):
                accepted[slot] = raw


    for ti, pi in selected:
        target = residual[ti].attack_details[pi]
        source = tasks[ti].attack_details[pi]
        slot = (ti, pi)
        target["security_requirement_reassessment_mode"] = "bounded_llm"
        target["security_requirement_reassessment_path_status"] = decisions[slot]["status"]
        target["security_requirement_reassessment_path"] = decisions[slot].get("post_control_path") or ""
        target["security_requirement_reassessment_path_basis"] = decisions[slot]["basis"]
        target["security_requirement_control_analysis"] = decisions[slot]["control_analysis"]
        target["security_requirement_reassessment_baseline"] = _baseline_reassessment_context(source, method)
        target["security_requirement_reassessment_constraints"] = constraints_by_slot.get(slot)
        latest = latest_attempt.get(slot)
        target["security_requirement_reassessment_model_rating"] = (
            {
                key: copy.deepcopy(latest.get(key))
                for key in ("attack_parameters", "feasibility_score", "feasibility_level",
                            "risk_value", "risk_value_num", "risk_treatment")
            } if latest else None
        )
        generated = accepted.get(slot)
        if generated is None:
            if slot not in constraints_by_slot:
                continue
            _mark_post_control_review(
                target, "target_rating_out_of_range_needs_review",
                "模型输出未通过固定维度、其余维度合计范围及风险矩阵校验；实施后风险未评级",
            )
            continue
        for field in (
            "attack_parameters", "feasibility_score", "feasibility_level",
            "risk_value", "risk_value_num", "risk_treatment", "feasibility_confidence",
        ):
            if field in generated:
                target[field] = copy.deepcopy(generated[field])
        target["security_requirements_implemented"] = True
        target["security_requirement_rating_within_range"] = True
        target["security_requirement_reassessment_status"] = "target_constrained_model"
        target["review_required"] = True
        target["review_reasons"] = [
            *list(target.get("review_reasons") or []),
            "模型评分通过预计算范围及风险矩阵校验；仍需核验安全需求是否按假设实施。",
        ]

    _finalize_target_reassessment_tasks(residual)
    logger.info(
        "Step 9 新版完成：%d 条模型范围内评级通过，%d 条实施后风险未评级待复核",
        len(accepted), len(mitigation) - len(accepted),
    )
    return residual


def build_tara_report(tasks: list[TaskUnit], feasibility_method: str, impact_method: str = "") -> list[dict]:
    return _build_tara_report(
        tasks,
        feasibility_method,
        impact_method,
        enable_reason=ENABLE_REASON,
        enable_asset_details=ENABLE_ASSET_DETAILS,
        attack_path_cleaner=_plain_attack_path_text,
        security_requirement_matcher=(
            _llm_security_requirement_matcher
            if SECURITY_REQUIREMENTS_LLM
            else None
        ),
    )


def build_error_report(tasks: list[TaskUnit]) -> list[dict]:
    return _build_error_report(tasks)


# ═══════════════════════════════════════════════════════════
# Excel 报告导出 (TARA Report → .xlsx)
# ═══════════════════════════════════════════════════════════


def _excel_options() -> ExcelExportOptions:
    return ExcelExportOptions(
        impact_method=IMPACT_METHOD,
        enable_reason=ENABLE_REASON,
        enable_consistency=ENABLE_CONSISTENCY,
        enable_r155=ENABLE_R155,
        enable_rag=ENABLE_RAG,
        enable_asset_details=ENABLE_ASSET_DETAILS,
    )


def _build_columns_excel(method: str = "attack_potential", impact_method: str = ""):
    return _excel_build_columns(method, impact_method, options=_excel_options())


def _get_attack_field_values(attack_params: dict, method: str) -> dict:
    return _excel_attack_fields(attack_params, method, options=_excel_options())


def _build_excel_rows(data, method="attack_potential", impact_method=""):
    return _excel_build_rows(
        data, method, impact_method, options=_excel_options()
    )


def _style_excel(ws, columns=None, method="attack_potential"):
    return _excel_style(ws, columns, method, options=_excel_options())


def export_tara_report_to_excel(
    json_path: str, xlsx_path: str, rag_cache: dict | None = None,
    rag_queries: dict | None = None,
) -> int:
    return _export_excel(
        json_path, xlsx_path, rag_cache, rag_queries, options=_excel_options()
    )


def _compute_rag_hash() -> str:
    """计算 RAG 数据目录 + 配置参数的哈希值，用于缓存失效判断。

    覆盖所有影响 RAG 输出的参数：文件内容、RAG 方法、top_k、
    max_chars、reranker 配置等。
    """
    import hashlib
    h = hashlib.sha256()
    # Include relative path and bytes: same-named documents in different
    # folders must not share a knowledge-base version.
    for category, d in RAG_DIRS.items():
        if not os.path.isdir(d):
            continue
        for root, dirs, files in os.walk(d):
            dirs.sort()
            for fn in sorted(files):
                fp = os.path.join(root, fn)
                try:
                    h.update(f"{category}:{os.path.relpath(fp, d)}".encode("utf-8"))
                    with open(fp, "rb") as source:
                        for block in iter(lambda: source.read(1024 * 1024), b""):
                            h.update(block)
                except OSError:
                    pass
    # 配置参数哈希（影响 RAG 输出的所有参数）
    config_str = (
        f"method:{RAG_METHOD}"
        f"|top_k:{RAG_TOP_K}"
        f"|max_chars:{RAG_MAX_CONTEXT_CHARS}"
        f"|rerank:{RERANKER_ENABLED}"
        f"|rerank_candidates:{RERANKER_CANDIDATES}"
        f"|bm25_k1:{BM25_K1}"
        f"|bm25_b:{BM25_B}"
    )
    h.update(config_str.encode("utf-8"))
    return h.hexdigest()


def _rag_request(
    task: TaskUnit, phase: str, corpus_version: str, project_name: str = ""
) -> tuple[str, str, Any]:
    """Stable retrieval identity: exact query, project asset and KB version."""
    query = f"{task.function} {task.asset_name} {task.asset_type} {task.attribute_name}"
    if phase == "threat":
        query += f" {task.threat_type}"
    phase_filter: Any = {
        "damage": "damage_scenario",
        "threat": "threat_scenario",
        "attack_path": ["threat_scenario", "attack_path", "attack_feasibility"],
    }[phase]
    identity = {
        "project": project_name,
        "function": task.function,
        "element_id": task.element_id,
        "element_index": task.element_index,
        "asset_name": task.asset_name,
        "asset_type": task.asset_type,
        "source": task.source,
        "target": task.target,
        "attribute": task.attribute_name,
    }
    digest = hashlib.sha256(orjson.dumps({
        "version": corpus_version, "phase": phase, "query": query,
        "asset": identity, "filter": phase_filter,
    }, option=orjson.OPT_SORT_KEYS)).hexdigest()
    return digest, query, phase_filter


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 13) 并发流水线
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def _run_pipeline(
    tasks: list[TaskUnit],
    rag_cache: dict,
    path_frameworks: list[dict],
    method: str = "attack_potential",
) -> None:
    """DST 优先屏障 →（影响评级批次 || 完整攻击路径批次）。

    DST 未完成时不提交下游 LLM 请求，避免下游请求淹没共享信号量。
    主链路由模型生成完整攻击路径文本，代码只提供可信拓扑框架；
    缺失路径进入有界模型恢复，不使用模板拼接路径。
    """
    active_tasks = [
        task for task in tasks if task.analysis_status != STATUS_NOT_APPLICABLE
    ]
    total = len(active_tasks)
    if total == 0:
        return

    groups: dict[tuple, list[TaskUnit]] = defaultdict(list)
    for t in active_tasks:
        groups[(
            t.asset_type, t.attribute_name,
            rag_cache.get("damage", {}).get(t.task_id, ""),
            rag_cache.get("threat", {}).get(t.task_id, ""),
        )].append(t)

    executor = get_executor()

    # ── 检查是否所有 DST 已就绪（stage_dst checkpoint 恢复）──
    _all_dst_ready = all(
        t.damage_scenario and t.threat_scenarios for t in active_tasks
    )

    if not _all_dst_ready:
        logger.info("═══ [计时] Step 4: 损害威胁场景 开始 ═══")
        _dst_start = time.perf_counter()
        # 有界流式提交，但在全部 DST 完成前不允许下游占用 LLM 槽位。
        dst_batches: list[tuple[list[TaskUnit], str, str]] = []
        for group_key, group_tasks in groups.items():
            rag_ds, rag_ts = group_key[2], group_key[3]
            for start in range(0, len(group_tasks), BATCH_SIZE_DST):
                batch = group_tasks[start:start + BATCH_SIZE_DST]
                dst_batches.append((batch, rag_ds, rag_ts))

        dst_total = len(dst_batches)
        _set_pipeline_metric("dst_tasks", total)
        _set_pipeline_metric("dst_batches_planned", dst_total)
        dst_window = min(
            MAX_PENDING_FUTURES,
            max(1, MAX_CONCURRENT_LLM),
        )
        logger.info(
            "DST 流式调度: %d 个 batch（%d 安全属性），窗口=%d",
            dst_total,
            total,
            dst_window,
        )

        dst_futures: dict[Future, list[TaskUnit]] = {}
        next_dst = 0

        def _fill_dst_window() -> None:
            nonlocal next_dst
            while next_dst < dst_total and len(dst_futures) < dst_window:
                batch, rag_ds, rag_ts = dst_batches[next_dst]
                future = _submit_pipeline(
                    executor, _exec_dst_batch, batch, rag_ds, rag_ts
                )
                dst_futures[future] = batch
                next_dst += 1

        _fill_dst_window()
        dst_done = 0
        log_interval = max(dst_total // 20, 5)
        while dst_futures:
            completed, _ = wait(
                tuple(dst_futures), return_when=FIRST_COMPLETED
            )
            for dst_future in completed:
                batch = dst_futures.pop(dst_future)
                dst_done += 1
                try:
                    dst_future.result()
                except Exception as e:
                    logger.error("DST batch 异常: %s", e)
                    for task in batch:
                        task.errors.append(f"DST batch异常: {e}")
                if dst_done % log_interval == 0 or dst_done == dst_total:
                    elapsed = time.perf_counter() - _dst_start
                    logger.info(
                        "DST batch 进度: %d/%d | 耗时 %.0fs",
                        dst_done,
                        dst_total,
                        elapsed,
                    )
            _fill_dst_window()

        _dst_elapsed = time.perf_counter() - _dst_start
        _stage_times["Step 4: 损害威胁场景"] = _dst_elapsed
        logger.info("═══ [计时] Step 4: 损害威胁场景 完成，耗时 %.2f 秒 (%.2f 分钟) ═══",
                    _dst_elapsed, _dst_elapsed / 60)

        # DST 完成后立即 checkpoint，崩溃后无需重跑 DST。
        try:
            save_checkpoint_async(tasks, "stage_dst", method)
        except Exception as e:
            logger.warning("[Checkpoint] stage_dst 快照创建失败: %s", e)
    else:
        logger.info("所有 %d 个任务的 DST 结果已就绪，跳过 DST 阶段", total)
        _stage_times["Step 4: 损害威胁场景"] = 0

    logger.info("═══ [计时] Step 5: 攻击路径+影响评级 开始 ═══")
    _post_start = time.perf_counter()

    ready_tasks = [
        task
        for task in active_tasks
        if task.analysis_status != STATUS_NOT_APPLICABLE
        and task.damage_scenario
        and task.threat_scenarios
    ]
    for task in ready_tasks:
        task.selected_path_frameworks = filter_path_frameworks(
            task, path_frameworks
        )

    post_futures: dict[Future, str] = {}
    # Impact 先提交，在主线程准备入口目录时即可并行执行。
    impact_batches = [
        ready_tasks[start : start + BATCH_SIZE_IMPACT]
        for start in range(0, len(ready_tasks), BATCH_SIZE_IMPACT)
    ]
    _set_pipeline_metric("impact_tasks", len(ready_tasks))
    _set_pipeline_metric("impact_batches_planned", len(impact_batches))
    impact_phase_start = time.perf_counter()
    for impact_batch in impact_batches:
        future = _submit_pipeline(executor, _exec_impact_batch, impact_batch)
        post_futures[future] = f"Impact:{len(impact_batch)}"

    topology_tasks = [
        task for task in ready_tasks if task.selected_path_frameworks
    ]
    # 完整攻击路径由一次批量调用直接生成，不再单独生成入口技术目录。
    entry_catalog = {}
    attack_batches = [
        topology_tasks[start : start + ATTACK_PATH_TASKS_PER_CALL]
        for start in range(0, len(topology_tasks), ATTACK_PATH_TASKS_PER_CALL)
    ]
    _set_pipeline_metric("attack_path_tasks", len(topology_tasks))
    _set_pipeline_metric("attack_path_batches_planned", len(attack_batches))
    _set_pipeline_metric(
        "attack_paths_expanded",
        sum(
            len(task.selected_path_frameworks)
            for task in topology_tasks
        ),
    )
    attack_executor = get_attack_path_executor()
    attack_path_phase_start = time.perf_counter()
    for attack_batch in attack_batches:
        future = _submit_pipeline(
            attack_executor,
            _exec_attack_path_batch,
            attack_batch,
            path_frameworks,
            rag_cache,
            entry_catalog,
        )
        post_futures[future] = f"AttackPath:{len(attack_batch)}"

    logger.info(
        "DST屏障后已提交: 影响评级 %d 批，直接攻击路径 %d 批（%d 个任务）",
        len(impact_batches),
        len(attack_batches),
        len(topology_tasks),
    )

    if not post_futures:
        _stage_times["Step 5: 攻击路径+影响评级"] = 0
        _stage_times["Step 5: 影响评级"] = 0
        _stage_times["Step 6: 攻击路径生成"] = 0
        return

    done = 0
    total_post = len(post_futures)
    log_post = max(total_post // 50, 10)
    next_log = log_post
    impact_done = 0
    attack_path_done = 0
    last_progress_done = 0
    last_progress_at = _post_start

    for f_post in as_completed(post_futures):
        label = post_futures[f_post]
        try:
            f_post.result()
        except Exception as e:
            logger.error("%s 异常: %s", label, e)
        done += 1
        if label.startswith("Impact:"):
            impact_done += 1
            if impact_done == len(impact_batches):
                _stage_times["Step 5: 影响评级"] = (
                    time.perf_counter() - impact_phase_start
                )
        elif label.startswith("AttackPath:"):
            attack_path_done += 1
            if attack_path_done == len(attack_batches):
                _stage_times["Step 6: 攻击路径生成"] = (
                    time.perf_counter() - attack_path_phase_start
                )
        if done >= next_log or done == total_post:
            now = time.perf_counter()
            elapsed = now - _post_start
            interval_elapsed = max(now - last_progress_at, 1e-6)
            interval_rate = (done - last_progress_done) / interval_elapsed
            average_rate = done / elapsed if elapsed > 0 else 0
            logger.info(
                "Post-DST 进度: %d/%d | 影响评级 %d/%d | 攻击路径 %d/%d "
                "| 耗时 %.0fs | 区间速率 %.2f批/s | 平均 %.2f批/s",
                done,
                total_post,
                impact_done,
                len(impact_batches),
                attack_path_done,
                len(attack_batches),
                elapsed,
                interval_rate,
                average_rate,
            )
            last_progress_done = done
            last_progress_at = now
            next_log = min(done + log_post, total_post)

    _post_elapsed = time.perf_counter() - _post_start
    _stage_times["Step 5: 攻击路径+影响评级"] = _post_elapsed
    _stage_times.setdefault("Step 5: 影响评级", 0.0)
    _stage_times.setdefault("Step 6: 攻击路径生成", 0.0)
    logger.info("═══ [计时] Step 5: 攻击路径+影响评级 完成，耗时 %.2f 秒 (%.2f 分钟) ═══",
                _post_elapsed, _post_elapsed / 60)


def _retry_failed_tasks(
    tasks: list[TaskUnit],
    path_frameworks: list[dict],
    rag_cache: dict,
    max_retries: int | None = None,
    *,
    retry_attack_paths: bool = False,
) -> int:
    """重试各阶段关键字段为空的 task，最多重试 max_retries 次。

    覆盖 DST → Impact →（可选）Attack Path 三个阶段，每轮仅处理仍失败的
    task。攻击路径恢复只请求缺失 path_id，成功项从模型结果缓存复用。
    返回经 max_retries 轮后仍失败的数量。
    """

    if max_retries is None:
        max_retries = PIPELINE_RECOVERY_ROUNDS

    # ── DST 重试（并行） ────────────────────────────
    for attempt in range(1, max_retries + 1):
        failed = [
            t for t in tasks
            if t.analysis_status != STATUS_NOT_APPLICABLE
            and (not t.damage_scenario or not t.threat_scenarios)
        ]
        if not failed:
            break
        logger.warning("重试 DST（第 %d/%d 次）: %d 个", attempt, max_retries, len(failed))

        def _retry_one_dst(t):
            rag_ds = rag_cache.get("damage", {}).get(t.task_id, "")
            rag_ts = rag_cache.get("threat", {}).get(t.task_id, "")
            try:
                with _use_llm_usage_stage("retry_dst"):
                    _exec_dst_batch([t], rag_ds, rag_ts)
            except Exception as e:
                t.errors.append(f"DST 重试异常: {e}")

        _parallel_map(_retry_one_dst, failed)

    # DST 重试可能在 Step 5 的初始屏障之后才补齐损害/威胁场景。此前这类
    # task 虽然已经有文本，却从未重新绑定拓扑框架，最后会被错误地落成
    # TOPOLOGY_UNCOVERED。重试成功后只重新执行确定性的框架筛选，不新增
    # LLM 调用；真正无适用框架的任务仍保持未覆盖状态。
    rebound = 0
    for task in tasks:
        if (
            task.analysis_status != STATUS_NOT_APPLICABLE
            and task.damage_scenario
            and task.threat_scenarios
            and not task.selected_path_frameworks
        ):
            task.selected_path_frameworks = filter_path_frameworks(
                task, path_frameworks
            )
            if task.selected_path_frameworks:
                rebound += 1
    if rebound:
        logger.info("DST 重试后补齐攻击路径框架: %d 个任务", rebound)

    # ── 影响评级重试（并行） ──────────────────────
    # 判断条件：damage_scenario 存在 + influence_parameters 为空 dict 或完全没设置
    # 注意：damage_scenario 说"不产生可感知的损害"时，impact 全 0 是正确结果，不应重试
    def _impact_needs_retry(t):
        if not t.damage_scenario:
            return False
        ip = t.influence_parameters
        if not ip or not isinstance(ip, dict):
            return True
        # 已有至少一个 key（含 reason key），说明已被处理过，不再重试
        return len(ip) == 0

    for attempt in range(1, max_retries + 1):
        failed = [
            t for t in tasks
            if t.analysis_status != STATUS_NOT_APPLICABLE and _impact_needs_retry(t)
        ]
        if not failed:
            break
        logger.warning("重试影响评级（第 %d/%d 次）: %d 个", attempt, max_retries, len(failed))

        def _retry_impact_batch(batch):
            try:
                with _use_llm_usage_stage("retry_impact"):
                    _exec_impact_batch(batch)
            except Exception as e:
                for task in batch:
                    task.errors.append(f"影响评级重试异常: {e}")

        retry_batches = [
            failed[start : start + BATCH_SIZE_IMPACT]
            for start in range(0, len(failed), BATCH_SIZE_IMPACT)
        ]
        _parallel_map(_retry_impact_batch, retry_batches)

    # ── 攻击路径最终恢复：只补仍缺失的模型路径 ──────
    if retry_attack_paths:
        for attempt in range(1, max_retries + 1):
            failed = [
                t for t in tasks
                if t.analysis_status != STATUS_NOT_APPLICABLE
                and t.damage_scenario
                and t.threat_scenarios
                and t.selected_path_frameworks
                and not t.attack_paths
            ]
            if not failed:
                break
            logger.warning(
                "模型补救缺失攻击路径（第 %d/%d 次）: %d 个",
                attempt,
                max_retries,
                len(failed),
            )

            entry_catalog = {}
            retry_batches = [
                failed[start : start + ATTACK_PATH_TASKS_PER_CALL]
                for start in range(0, len(failed), ATTACK_PATH_TASKS_PER_CALL)
            ]

            def _retry_ap_batch(batch):
                try:
                    with _use_llm_usage_stage("retry_attack_path"):
                        _exec_attack_path_batch(
                            batch, path_frameworks, rag_cache, entry_catalog
                        )
                except Exception as e:
                    for task in batch:
                        task.errors.append(f"攻击路径重试异常: {e}")

            _parallel_map(_retry_ap_batch, retry_batches)

    # ── 统计仍失败的任务 ──────────────────────────
    # impact 全 0 不再视为失败（damage_scenario 说"不产生可感知的损害"时全 0 是正确结果）
    still_failed = sum(
        1 for t in tasks
        if t.analysis_status != STATUS_NOT_APPLICABLE
        and (not t.damage_scenario or not t.threat_scenarios)
    )
    if still_failed:
        logger.warning("重试后仍有 %d 个任务关键字段为空，输出中将包含不完整项", still_failed)
    return still_failed


def _timed_retry_failed_tasks(
    tasks: list[TaskUnit],
    path_frameworks: list[dict],
    rag_cache: dict,
    *,
    retry_attack_paths: bool,
) -> int:
    started = time.perf_counter()
    remaining = _retry_failed_tasks(
        tasks,
        path_frameworks,
        rag_cache,
        retry_attack_paths=retry_attack_paths,
    )
    elapsed = time.perf_counter() - started
    _stage_times["阶段失败子集恢复"] = (
        _stage_times.get("阶段失败子集恢复", 0.0) + elapsed
    )
    logger.info(
        "═══ [计时] 阶段失败子集恢复完成，耗时 %.2f 秒 (%.2f 分钟) ═══",
        elapsed,
        elapsed / 60,
    )
    return remaining


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 14) 主流程
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _hash_input_path(path: str) -> str:
    """对输入文件或目录中的 JSON 文件做稳定内容哈希。"""
    h = hashlib.sha256()
    if os.path.isfile(path):
        files = [path]
        root = os.path.dirname(os.path.abspath(path))
    elif os.path.isdir(path):
        root = os.path.abspath(path)
        files = sorted(glob.glob(os.path.join(root, "*.json")))
    else:
        return ""
    for file_path in files:
        rel = os.path.relpath(file_path, root)
        h.update(rel.encode("utf-8"))
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    return h.hexdigest()


def _validate_run_inputs(
    data_flow_dir: str,
    topology_file: str,
    external_interface_excel: str,
) -> None:
    problems: list[str] = []
    if not os.path.exists(data_flow_dir):
        problems.append(f"DFD 输入不存在: {data_flow_dir}")
    elif os.path.isdir(data_flow_dir) and not glob.glob(os.path.join(data_flow_dir, "*.json")):
        problems.append(f"DFD 目录中没有 JSON 文件: {data_flow_dir}")
    elif os.path.isfile(data_flow_dir) and os.path.getsize(data_flow_dir) == 0:
        problems.append(f"DFD 文件为空: {data_flow_dir}")
    if not os.path.isfile(topology_file):
        problems.append(f"拓扑 JSON 不存在: {topology_file}")
    elif os.path.getsize(topology_file) == 0:
        problems.append(f"拓扑 JSON 为空: {topology_file}")
    if not os.path.isfile(external_interface_excel):
        problems.append(f"对外接口清单不存在: {external_interface_excel}")
    elif os.path.getsize(external_interface_excel) == 0:
        problems.append(f"对外接口清单为空: {external_interface_excel}")
    if problems:
        message = "；".join(problems)
        if STRICT_INPUTS:
            raise FileNotFoundError(message)
        logger.warning(message)


def _check_llm_service() -> None:
    """启动前验证 OpenAI 兼容服务及 served model，避免跑到中途才发现配置错误。"""
    _model_deployment_revisions.clear()
    _run_meta["lora_deployment_revisions"] = {}
    if not LLM_PREFLIGHT:
        logger.info("LLM 服务预检已通过 TARA_LLM_PREFLIGHT=0 跳过")
        return
    result = check_api_service(
        API_BASE, API_KEY, [MODEL_NAME, IMPACT_MODEL_NAME],
        timeout=min(REQUEST_TIMEOUT, 15), open_url=urlrequest.urlopen,
    )
    if not REMOTE_API and _parse_api_url(API_BASE)[0] in {"localhost", "127.0.0.1", "::1"}:
        from automotive_tara.lora_export import adapter_revision
        for model in {MODEL_NAME, IMPACT_MODEL_NAME}:
            revision = adapter_revision(result.get("model_roots", {}).get(model, ""))
            if revision:
                _model_deployment_revisions[model] = revision
    _run_meta["lora_deployment_revisions"] = dict(_model_deployment_revisions)
    logger.info("API 预检使用 %s（%s）", result["api_base"], result["checked_by"])
    logger.info("LLM 服务预检通过: 基础=%s | 影响评级=%s", MODEL_NAME, IMPACT_MODEL_NAME)


def _check_wall_clock(start: float, stage: str) -> None:
    if WALL_CLOCK_TIMEOUT <= 0:
        return
    elapsed = time.perf_counter() - start
    if elapsed > WALL_CLOCK_TIMEOUT:
        raise TimeoutError(
            f"TARA 总运行已超过 {WALL_CLOCK_TIMEOUT}s（完成阶段: {stage}，"
            f"实际 {elapsed:.1f}s）"
        )


def _git_commit() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=_PROJECT_ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
    except Exception:
        return ""


def _git_worktree_dirty() -> bool | None:
    """返回工作树是否有未提交变更；无法读取 Git 状态时返回 None。"""
    try:
        return bool(
            subprocess.run(
                ["git", "status", "--porcelain", "--untracked-files=normal"],
                cwd=_PROJECT_ROOT,
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
            ).stdout.strip()
        )
    except Exception:
        return None


def _scoring_signature() -> str:
    payload = repr(
        (
            sorted(RISK_MATRIX.items()),
            sorted(_HEAVENS_RISK_MATRIX.items()),
            sorted((key, sorted(value.items())) for key, value in _HEAVENS_DIM_WEIGHTS.items()),
            sorted(AP_ALLOWED_VALUES.items()),
            sorted(HEAVENS_AP_ALLOWED_VALUES.items()),
        )
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


_DEMO_ASSET_TYPE_ORDER = ("部件", "信号", "数据")


def _demo_asset_type_key(asset_type: Any) -> str:
    """Normalize the three asset classes used by the standard demo scope."""
    value = re.sub(r"\s+", "", str(asset_type or "")).casefold()
    aliases = {
        "部件": "部件",
        "component": "部件",
        "components": "部件",
        "ecu": "部件",
        "信号": "信号",
        "signal": "信号",
        "signals": "信号",
        "数据": "数据",
        "data": "数据",
        "dataset": "数据",
    }
    if value in aliases:
        return aliases[value]
    # Accept descriptive labels such as ``信号类资产`` while keeping the
    # selection limited to the requested component/signal/data categories.
    for marker, normalized in aliases.items():
        if marker in value and marker not in {"ecu", "data"}:
            return normalized
    return ""


def _select_standard_demo_assets(asset_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Select at most one component, signal and data asset per parsed DFD.

    The first occurrence in each DFD is retained to keep the demo stable and
    deterministic.  Other asset classes (for example external interfaces) are
    intentionally excluded from this scope; full analysis remains unchanged.
    """
    selected_results: list[dict[str, Any]] = []
    selected_count = 0
    for func_data in asset_results:
        selected_by_type: dict[str, dict[str, Any]] = {}
        for asset in func_data.get("assets", []) or []:
            asset_type = _demo_asset_type_key(asset.get("asset_type"))
            if asset_type in _DEMO_ASSET_TYPE_ORDER and asset_type not in selected_by_type:
                selected_by_type[asset_type] = asset
        selected_assets = [
            selected_by_type[asset_type]
            for asset_type in _DEMO_ASSET_TYPE_ORDER
            if asset_type in selected_by_type
        ]
        if not selected_assets:
            continue
        selected_func = dict(func_data)
        selected_func["assets"] = selected_assets
        selected_results.append(selected_func)
        selected_count += len(selected_assets)
    logger.info(
        "标准演示模式：每个 DFD 各取一个部件/信号/数据资产，实际纳入 %d 个资产（%d 个 DFD）",
        selected_count,
        len(selected_results),
    )
    return selected_results


def _replay_completed_analysis(
    snapshot: dict, destinations: dict, key: str, method: str,
    data_flow_dir: str, topology_file: str, interfaces_file: str, started: float,
) -> tuple[list[dict], list[dict]]:
    """Reuse verified report bytes while recording only this run's real work."""
    manifest = copy.deepcopy(snapshot["manifest"])
    original_outputs = manifest.get("outputs", {})
    reuse = {
        "enabled": True, "hit": True, "key": key,
        "source_report": original_outputs.get("json"),
        "source_finish_time": manifest.get("finish_time"),
        "snapshot_created_at": snapshot.get("created_at"),
        "verified_artifacts": {role: record["sha256"] for role, record in snapshot["artifacts"].items()},
    }
    outputs = {
        role: os.path.abspath(destination) if destination and role in snapshot["artifacts"] else None
        for role, destination in destinations.items()
    }
    outputs["report_variant"] = original_outputs.get("report_variant", "baseline")
    outputs["llm_usage_live"] = os.path.abspath(os.path.join(OUTPUT_DIR, "llm_usage_live.json"))
    for role in ("training_calls_jsonl", "training_samples_jsonl", "training_review_xlsx", "training_manifest_json"):
        outputs[role] = None
    elapsed = time.perf_counter() - started
    manifest.update({
        "start_time": _run_meta.get("start_time"), "finish_time": datetime.now().isoformat(),
        "elapsed_seconds": round(elapsed, 3), "git_commit": _git_commit(), "git_dirty": _git_worktree_dirty(),
        "inputs": {"dfd": os.path.abspath(data_flow_dir), "topology": os.path.abspath(topology_file),
                   "external_interfaces": os.path.abspath(interfaces_file), "signature": _RUN_INPUT_SIGNATURE},
        "configuration": _current_run_configuration(), "outputs": outputs,
        "checkpoint": _checkpoint_meta(method, manifest.get("counts", {}).get("tasks", 0)),
        "semantic_cache": semantic_cache.stats(), "completed_result_cache": reuse,
        "llm": _llm_metrics_snapshot(), "pipeline": {"completed_result_cache_hits": 1},
        "stage_telemetry": {}, "stage_seconds": {}, "training_capture": _training_capture.snapshot(),
    })
    manifest.setdefault("versions", {})["source_signature"] = _pipeline_source_signature()
    _run_meta["completed_result_cache"] = reuse
    _write_run_metadata(_current_run_configuration())
    save_json({"schema_version": "tara-llm-usage-v1", "updated_at": datetime.now().isoformat(),
               "live": False, "llm": manifest["llm"]}, outputs["llm_usage_live"])
    save_json(manifest, os.path.join(OUTPUT_DIR, "run_manifest.json"))
    logger.info("完整结果缓存命中: %s；报告内容保持原样，未发起 LLM 请求", key[:16])
    logger.info("TARA 完成: 完整结果复用，耗时 %.2fs | 主报告: %s", elapsed, outputs["json"])
    with open(outputs["json"], encoding="utf-8") as source:
        report = json.load(source)
    with open(outputs["errors_json"], encoding="utf-8") as source:
        errors = json.load(source)
    return report, errors


def _run_tara_impl(
    data_flow_dir: str,
    topology_file: str,
    external_interface_excel: str,
    output_path: str,
    feasibility_method: str = FEASIBILITY_METHOD,
    max_assets_for_test: Optional[int] = None,
    skip_checkpoint_resume: bool = False,
    analysis_refs: Optional[list[str]] = None,
    _cache_stack: ExitStack | None = None,
) -> tuple[list[dict], list[dict]]:
    global _RUN_INPUT_SIGNATURE, _training_capture, _live_usage_last_write
    method = (feasibility_method or "attack_potential").strip().lower()
    _initialize_runtime()
    output_path, project_name = _apply_report_filename(
        output_path,
        data_flow_dir=data_flow_dir,
        topology_file=topology_file,
        external_interface_excel=external_interface_excel,
    )
    _run_meta["project_name"] = project_name
    _training_capture.close()
    _training_capture = TrainingCapture(
        OUTPUT_DIR,
        enabled=CAPTURE_TRAINING,
        include_rejected=CAPTURE_REJECTED,
    )
    if CAPTURE_TRAINING:
        logger.info(
            "训练数据旁路采集已开启: %s (保留失败调用=%s)",
            _training_capture.training_dir,
            CAPTURE_REJECTED,
        )
    _reset_run_metrics()
    with _live_usage_lock:
        _live_usage_last_write = 0.0
    # Cache entries are shared across runs, while telemetry in a manifest is
    # run-scoped.  Preserve the entries but reset only hit/miss counters so the
    # reported cache rate is actionable for this invocation.
    # The production cache exposes reset_metrics(), but keep the pipeline
    # compatible with lightweight/custom cache implementations used by
    # integrations and tests.  Metrics are best-effort; cache entries remain
    # shared across runs.
    reset_cache_metrics = getattr(semantic_cache, "reset_metrics", None)
    if callable(reset_cache_metrics):
        reset_cache_metrics()
    requested_analysis_refs = list(dict.fromkeys(analysis_refs or []))
    requested_asset_selection = {}
    if ASSET_SELECTION_PATH:
        from automotive_tara.asset_selection import validate_selection
        with open(ASSET_SELECTION_PATH, encoding='utf-8') as source:
            requested_asset_selection = validate_selection(json.load(source))
    selection_signature = (
        hashlib.sha256(
            "|".join(requested_analysis_refs).encode("utf-8")
        ).hexdigest()
        if requested_analysis_refs
        else None
    )
    if requested_asset_selection:
        selection_signature = analysis_cache.digest_json([requested_analysis_refs, requested_asset_selection])
    _write_run_metadata(
        _effective_run_configuration(
            data_flow_dir=data_flow_dir,
            topology_file=topology_file,
            external_interface_excel=external_interface_excel,
            output_path=output_path,
            feasibility_method=method,
            max_assets_for_test=max_assets_for_test,
            skip_checkpoint_resume=skip_checkpoint_resume,
            experiment_selection_count=len(requested_analysis_refs),
            experiment_selection_signature=selection_signature,
        )
    )
    _validate_method_combination(method, IMPACT_METHOD)

    _pipeline_start = time.perf_counter()
    _validate_run_inputs(data_flow_dir, topology_file, external_interface_excel)
    _RUN_INPUT_SIGNATURE = hashlib.sha256(
        "|".join(
            (
                _hash_input_path(data_flow_dir),
                _hash_input_path(topology_file),
                _hash_input_path(external_interface_excel),
                selection_signature or "",
            )
        ).encode("utf-8")
    ).hexdigest()

    # ── 持久化缓存路径（跨版本共享） ────────────
    os.makedirs(SHARED_CACHE_DIR, exist_ok=True)
    _sem_cache_path = os.path.join(SHARED_CACHE_DIR, "semantic_cache.json")
    _rag_cache_path = os.path.join(SHARED_CACHE_DIR, "rag_cache.json")

    # 恢复持久化语义缓存
    model_cache_identities = analysis_cache.model_identities(
        API_BASE, [MODEL_NAME, IMPACT_MODEL_NAME], Path(_PROJECT_ROOT)
    )
    _cache_model_revisions.clear()
    _cache_model_revisions.update({
        name: analysis_cache.digest_json(identity)
        for name, identity in model_cache_identities.items()
    })
    bind_cache = getattr(semantic_cache, "bind", None)
    if callable(bind_cache):
        try:
            bind_cache(_sem_cache_path, model_namespaces={
                name: analysis_cache.digest_json(identity)
                for name, identity in model_cache_identities.items()
            })
        except Exception as exc:
            logger.warning("持久化缓存连接失败，回退到本地快照: %s", exc)
            semantic_cache.load(_sem_cache_path)
    else:
        semantic_cache.load(_sem_cache_path)

    logger.info("=" * 72)
    logger.info("TARA 开始")
    logger.info(f"模型: {MODEL_NAME} | 影响评级模型: {IMPACT_MODEL_NAME} | API: {API_BASE}")
    logger.info(f"可行性评估方法: {method} | 影响评级方法: {IMPACT_METHOD}")
    logger.info("=" * 72)

    # RAG 方法后缀：三方法对比时输出不相互覆盖。
    # 无 RAG 是默认/基线模式，报告文件名保持 ``日期-时间-项目名``，
    # 不再追加 ``_no_rag``；这样最终交付物名称不会暴露内部运行开关。
    if ENABLE_RAG and RAG_METHOD not in ("", "bge-m3"):
        base, ext = os.path.splitext(output_path)
        output_path = f"{base}_{RAG_METHOD}{ext}"
    if os.path.splitext(output_path)[1].lower() != ".json":
        output_path += ".json"
    output_stem = os.path.splitext(output_path)[0]
    errors_path = f"{output_stem}_errors.json"
    baseline_output_path = f"{output_stem}_baseline.json"
    baseline_xlsx_path = f"{output_stem}_baseline.xlsx"
    if SECURITY_REQUIREMENTS_IMPLEMENTED_REASSESSMENT:
        output_path = f"{output_stem}_security_requirements_implemented.json"
        xlsx_path = f"{output_stem}_security_requirements_implemented.xlsx"
    else:
        xlsx_path = f"{output_stem}.xlsx"
    # 记录经过 RAG 后缀和扩展名规范化后的最终输出路径。
    _write_run_metadata(
        _effective_run_configuration(
            data_flow_dir=data_flow_dir,
            topology_file=topology_file,
            external_interface_excel=external_interface_excel,
            output_path=output_path,
            feasibility_method=method,
            max_assets_for_test=max_assets_for_test,
            skip_checkpoint_resume=skip_checkpoint_resume,
            experiment_selection_count=len(requested_analysis_refs),
            experiment_selection_signature=selection_signature,
        )
    )

    completed_cache = None
    completed_key = ""
    completed_identity = None
    if REUSE_COMPLETED_RESULTS and not CAPTURE_TRAINING and _cache_stack is not None:
        facts = _load_security_asset_facts(data_flow_dir)
        completed_identity = analysis_cache.result_identity(
            inputs=analysis_cache.input_fingerprints(data_flow_dir, topology_file, external_interface_excel),
            effective=_current_run_configuration()["effective"],
            scope={"method": method, "max_assets": max_assets_for_test, "analysis_refs": requested_analysis_refs,
                   "asset_selection": requested_asset_selection},
            models=model_cache_identities,
            dependencies={
                "requirements": analysis_cache.file_digest(SECURITY_REQUIREMENTS_PATH),
                "matching_logic": analysis_cache.file_digest(SECURITY_REQUIREMENTS_LOGIC_PATH),
                "security_requirements_llm": SECURITY_REQUIREMENTS_LLM,
                "two_stage_reassessment": SECURITY_REQUIREMENTS_TWO_STAGE_REASSESSMENT,
                "asset_facts": {key: value for key, value in facts.items() if key != "source"},
                "rag": _compute_rag_hash() if ENABLE_RAG else None,
                "r155": analysis_cache.file_digest(R155_ANNEX5_PATH) if ENABLE_R155 else None,
                "functions": analysis_cache.file_digest(FUNC_INVENTORY_PATH) if _ENABLE_FUNC_DESC and FUNC_INVENTORY_PATH else None,
                "access_partition": hashlib.sha256(str(API_KEY).encode("utf-8")).hexdigest(),
            },
            source_signature=analysis_cache.analysis_source_signature(Path(_PROJECT_ROOT)),
            project_name=project_name,
        )
        completed_key = analysis_cache.digest_json(completed_identity)
        completed_cache = analysis_cache.CompletedAnalysisCache(SHARED_CACHE_DIR)
        destinations = {
            "json": output_path, "errors_json": errors_path, "xlsx": xlsx_path,
            "baseline_json": baseline_output_path if SECURITY_REQUIREMENTS_IMPLEMENTED_REASSESSMENT else None,
            "baseline_xlsx": baseline_xlsx_path if SECURITY_REQUIREMENTS_IMPLEMENTED_REASSESSMENT else None,
            "dfd_relationships_json": os.path.join(OUTPUT_DIR, "dfd_relationships.json"),
        }
        try:
            _cache_stack.enter_context(completed_cache.lock(completed_key))
            snapshot = completed_cache.restore(completed_key, destinations)
        except (OSError, ValueError, TypeError) as exc:
            logger.warning("完整结果缓存无法读取，继续正常分析: %s", exc)
            completed_cache = None
            snapshot = None
        if snapshot is not None:
            return _replay_completed_analysis(
                snapshot, destinations, completed_key, method,
                data_flow_dir, topology_file, external_interface_excel, _pipeline_start,
            )
        logger.info("完整结果缓存未命中: %s；继续按条目缓存执行", completed_key[:16])

    _check_llm_service()

    # ─── Step 1: DFD资产识别 ─────────────────────────
    with Timer("Step 1: DFD 资产解析"):
        asset_results = parse_dfd_json(data_flow_dir)
    if not asset_results:
        raise ValueError(f"DFD 未解析出任何有效功能/资产: {data_flow_dir}")
    dfd_relationships_path = os.path.join(
        OUTPUT_DIR, "dfd_relationships.json"
    )
    relationship_snapshot = [
        {
            "function": item.get("function", ""),
            "nodes": item.get("nodes", []),
            "relations": item.get("relations", []),
        }
        for item in asset_results
    ]
    save_json(relationship_snapshot, dfd_relationships_path)
    _set_pipeline_metric(
        "dfd_relationships",
        sum(len(item["relations"]) for item in relationship_snapshot),
    )
    _check_wall_clock(_pipeline_start, "DFD 资产解析")

    # 标准演示模式：每个 DFD 各取一个部件、信号和数据资产（存在则取）。
    # 该选择优先于通用的 ``--max-assets`` 截断，避免按文件顺序偏向某一类。
    if TEST_ASSET_SELECTION == "per_dfd_type":
        asset_results = _select_standard_demo_assets(asset_results)

    # 测试模式：仅取前N个DFD资产
    elif max_assets_for_test is not None and max_assets_for_test > 0:
        all_assets = [
            asset
            for func_data in asset_results
            for asset in func_data.get("assets", [])
        ]
        excluded_assets = all_assets[max_assets_for_test:]
        limited_results = []
        count = 0
        for func_data in asset_results:
            assets = func_data.get("assets", [])
            if count >= max_assets_for_test:
                break
            remain = max_assets_for_test - count
            if len(assets) > remain:
                copy_func = dict(func_data)
                copy_func["assets"] = assets[:remain]
                limited_results.append(copy_func)
                count += remain
                break
            else:
                limited_results.append(func_data)
                count += len(assets)
        asset_results = limited_results
        logger.info(f"测试模式启用：仅使用前 {max_assets_for_test} 个DFD资产，实际纳入 {count} 个")
        if excluded_assets:
            excluded_preview = "；".join(
                (
                    f"{asset.get('element_index') or asset.get('element_id')}"
                    f"({asset.get('source') or '-'}→"
                    f"{asset.get('target') or asset.get('name') or '-'})"
                )
                for asset in excluded_assets[:5]
            )
            logger.warning(
                "测试模式截断了 %d 个DFD资产，未进入后续分析；"
                "首批被排除项: %s",
                len(excluded_assets),
                excluded_preview,
            )

    # ─── 功能清单加载（仅按当前请求的 function 注入） ──────
    global _FUNCTION_DESC_MAP
    if _ENABLE_FUNC_DESC and FUNC_INVENTORY_PATH:
        if os.path.exists(FUNC_INVENTORY_PATH):
            with Timer("功能清单加载"):
                inventory = load_function_inventory(FUNC_INVENTORY_PATH)
                _FUNCTION_DESC_MAP = {}
                for func_data in asset_results:
                    func_name = func_data.get("function", "")
                    desc = _match_func_description(func_name, inventory)
                    if desc:
                        _FUNCTION_DESC_MAP[func_name] = _truncate_desc(desc, max_chars=120)
                logger.info("功能说明已加载并按请求作用域注入: %d 个功能", len(_FUNCTION_DESC_MAP))
        else:
            logger.warning(f"功能清单文件不存在: {FUNC_INVENTORY_PATH}")
    elif not _ENABLE_FUNC_DESC:
        logger.info("功能清单已通过 TARA_ENABLE_FUNC_DESC=0 关闭")

    # Keep the selected input record count for diagnostics.  The user-facing
    # analysed count is computed from task identities below, after external
    # actors and other non-analysed DFD records have been filtered.
    input_asset_count = sum(
        len(func_data.get("assets", []) or [])
        for func_data in asset_results
        if isinstance(func_data, dict)
    )

    # ─── Step 2: 拓扑攻击路径框架 ────────────────────
    path_frameworks = []
    topology_nodes: set[str] = set()
    with Timer("Step 2: 拓扑攻击路径框架"):
        if os.path.exists(topology_file) and os.path.exists(external_interface_excel):
            path_frameworks = parse_topology_and_generate_frameworks(topology_file, external_interface_excel, asset_results)
            # 严格按拓扑图过滤 DFD 资产：节点集合用于后续任务构建
            topology_nodes = _topology_component_names(topology_file)
        else:
            logger.warning("拓扑文件或接口清单不存在，攻击路径框架为空")
    if not path_frameworks and STRICT_INPUTS:
        raise ValueError("拓扑与接口清单未生成任何攻击路径框架，请检查节点名称和接口映射")
    logger.info("拓扑节点集合: %d 个（部件/网关/外部实体），用于资产过滤", len(topology_nodes))
    _check_wall_clock(_pipeline_start, "拓扑攻击路径框架")

    # ─── Step 3: 扩展属性 + RAG ──────────────────────
    _step3_start = time.perf_counter()
    security_asset_facts = _load_security_asset_facts(data_flow_dir)
    if security_asset_facts.get("source"):
        logger.info(
            "安全需求资产适用性事实已加载: %s",
            security_asset_facts["source"],
        )
    else:
        logger.info("未加载项目级关键零部件/操作系统事实，受限字段按未知处理")
    tasks = build_task_units(
        asset_results,
        topology_node_names=topology_nodes,
        security_asset_facts=security_asset_facts,
    )
    if requested_asset_selection:
        from automotive_tara.asset_selection import filter_tasks
        tasks = filter_tasks(tasks, requested_asset_selection)
        logger.info('交互式资产范围已应用：%d 个分析单元；scope=%s', len(tasks), requested_asset_selection)
    # Do not derive the UI/report count from ``set(asset_name)``: two DFD
    # elements may legitimately share a display name (or differ only by
    # case), while each task-backed input element is independently analysed.
    # The report builder later merges security attributes under an asset key;
    # this identity-level count preserves the original analysed scope.
    analysed_asset_count = len({
        (
            task.function,
            task.element_id,
            task.element_index,
            task.asset_name,
            task.asset_type,
            task.source,
            task.target,
        )
        for task in tasks
    })
    if requested_analysis_refs:
        tasks_by_reference = {
            task_analysis_reference(task): task for task in tasks
        }
        missing_references = [
            reference
            for reference in requested_analysis_refs
            if reference not in tasks_by_reference
        ]
        if missing_references:
            raise ValueError(
                "冻结实验清单与当前工程输入不兼容，缺少分析单元: "
                f"{missing_references[:8]}"
            )
        tasks = [
            tasks_by_reference[reference]
            for reference in requested_analysis_refs
        ]
        # A frozen experiment may intentionally select only a subset of
        # attributes/assets.  Count the actual selected asset identities in
        # that case, still preserving duplicate display names from distinct
        # DFD elements.
        analysed_asset_count = len({
            (
                task.function,
                task.element_id,
                task.element_index,
                task.asset_name,
                task.asset_type,
                task.source,
                task.target,
            )
            for task in tasks
        })
        logger.info(
            "冻结实验清单已应用: %d 个分析单元 | signature=%s",
            len(tasks),
            selection_signature,
        )

    for task in tasks:
        task.cache_dependencies['project'] = project_name

    # Runtime maps task IDs to contexts; persisted entries use exact request
    # digests, so two projects with a display-name collision stay isolated.
    rag_cache: dict[str, dict[str, str]] = {"damage": {}, "threat": {}, "attack_path": {}}
    rag_queries: dict[str, dict[str, str]] = {"damage": {}, "threat": {}, "attack_path": {}}
    if ENABLE_RAG:
        rag_hash = _compute_rag_hash()
        stored_cache: dict[str, dict[str, str]] = {
            "damage": {}, "threat": {}, "attack_path": {},
        }
        if os.path.isfile(_rag_cache_path):
            try:
                with open(_rag_cache_path, "r", encoding="utf-8") as f:
                    cached = json.load(f)
                if cached.get("_hash") == rag_hash and cached.get("_schema") == 2:
                    for phase in stored_cache:
                        values = cached.get(phase, {})
                        if isinstance(values, dict):
                            stored_cache[phase] = {
                                key: value for key, value in values.items()
                                if isinstance(key, str) and isinstance(value, str)
                            }
                else:
                    logger.info("RAG 知识库版本或缓存结构已变更，重新构建缓存")
            except Exception as e:
                logger.warning("RAG 缓存加载失败: %s", e)

        pending: dict[tuple[str, str], tuple[str, Any]] = {}
        bindings: dict[tuple[str, str], list[str]] = defaultdict(list)
        for task in tasks:
            if task.analysis_status == STATUS_NOT_APPLICABLE:
                continue
            for phase in ("damage", "threat", "attack_path"):
                digest, query, phase_filter = _rag_request(
                    task, phase, rag_hash, project_name
                )
                bindings[(phase, digest)].append(task.task_id)
                rag_queries[phase][task.task_id] = query
                if digest not in stored_cache[phase]:
                    pending[(phase, digest)] = (query, phase_filter)

        def _rag_retrieve(job):
            (phase, digest), (query, phase_filter) = job
            return phase, digest, rag_kb.retrieve(
                query, top_k=RAG_TOP_K, max_chars=RAG_MAX_CONTEXT_CHARS,
                tara_phase_filter=phase_filter,
            )

        if pending:
            with Timer("Step 3: RAG 缺失查询补检"):
                futures = [
                    _submit_pipeline(get_executor(), _rag_retrieve, job)
                    for job in pending.items()
                ]
                for future in as_completed(futures):
                    phase, digest, result = future.result()
                    stored_cache[phase][digest] = result
            try:
                save_json({"_schema": 2, "_hash": rag_hash, **stored_cache}, _rag_cache_path)
            except Exception as exc:
                logger.warning("RAG 缓存持久化失败: %s", exc)
        for (phase, digest), task_ids in bindings.items():
            context = stored_cache[phase].get(digest, "")
            for task_id in task_ids:
                rag_cache[phase][task_id] = context
        logger.info("RAG 缓存命中/补检: %d/%d", len(bindings) - len(pending), len(pending))

    _step3_elapsed = time.perf_counter() - _step3_start
    _metrics_registry.set_stage_time(
        "Step 3: 扩展属性 + RAG", _step3_elapsed
    )
    logger.info(
        "═══ [计时] Step 3: 扩展属性 + RAG 完成，耗时 %.2f 秒 (%.2f 分钟) ═══",
        _step3_elapsed,
        _step3_elapsed / 60,
    )

    # ─── Checkpoint 恢复 ──────────────────────────────
    # 三个 checkpoint 点（从最新到最旧）：
    #   stage_C_attack = 全部完成
    #   stage_AB = 并发流水线完成（DST + 攻击路径 + 影响评级），需继续 Stage C
    #   stage_dst = DST 完成（攻击路径 + 影响评级待续），需继续 AP+Impact + Stage C
    current_task_data: list[TaskUnit] | None = None
    need_pipeline = True
    need_stage_c = True
    # Keep the freshly built task facts available while loading older
    # checkpoints.  Checkpoints created before the applicability fields were
    # added do not contain critical-component/OS values.
    fresh_tasks_by_reference = {
        task_analysis_reference(task): task for task in tasks
    }

    if not skip_checkpoint_resume:
        # 从最新到最旧查找
        for stage in ("stage_C_attack", "stage_AB", "stage_dst"):
            if not checkpoint_is_compatible(stage, method, len(tasks)):
                continue
            ckpt = load_checkpoint(stage)
            if ckpt is not None:
                if stage in {"stage_C_attack", "stage_AB"} and any(
                    task.selected_path_frameworks
                    and task.analysis_status != STATUS_NOT_APPLICABLE
                    and (
                        len(task.attack_paths) != len(task.selected_path_frameworks)
                        or len(task.attack_path_provenance) != len(task.attack_paths)
                        or any(
                            not isinstance(item, dict)
                            or item.get("generation_source") not in {
                                "llm_complete", "cache_llm_complete"
                            }
                            for item in task.attack_path_provenance
                        )
                    )
                    for task in ckpt
                ):
                    logger.warning(
                        "[Checkpoint] %s 含缺失或非模型攻击路径，跳过并重新生成",
                        stage,
                    )
                    continue
                current_task_data = ckpt
                if stage == "stage_C_attack":
                    need_pipeline = False
                    need_stage_c = False
                    logger.info("[Checkpoint] 从 %s 恢复，全部已完成", stage)
                elif stage == "stage_dst":
                    tasks = ckpt  # DST results ready, _run_pipeline skips Phase 1
                    need_pipeline = True
                    need_stage_c = True
                    logger.info("[Checkpoint] 从 %s 恢复，跳过 DST，继续 AP+Impact+Stage C", stage)
                else:  # stage_AB
                    need_pipeline = False
                    need_stage_c = True
                    logger.info("[Checkpoint] 从 %s 恢复，跳过流水线，继续 Stage C", stage)
                break
        if current_task_data is not None:
            restored_fact_count = 0
            for resumed_task in current_task_data:
                fresh_task = fresh_tasks_by_reference.get(
                    task_analysis_reference(resumed_task)
                )
                if fresh_task is None:
                    continue
                changed = False
                if (
                    resumed_task.critical_component is None
                    and fresh_task.critical_component is not None
                ):
                    resumed_task.critical_component = fresh_task.critical_component
                    changed = True
                if not resumed_task.operating_system and fresh_task.operating_system:
                    resumed_task.operating_system = fresh_task.operating_system
                    changed = True
                if changed:
                    restored_fact_count += 1
            if restored_fact_count:
                logger.info(
                    "已从当前输入补齐旧 checkpoint 的安全需求适用性事实: %d 个任务",
                    restored_fact_count,
                )
    else:
        logger.info("Checkpoint恢复已跳过（skip_checkpoint_resume=True）")

    # ─── Step 4-6: DST 阶段屏障 →（Impact || 完整攻击路径）──
    if need_pipeline:
        logger.info(
            "分阶段流水线: Step 4 损害威胁场景完成后，"
            "并行执行 Step 5 完整攻击路径与 Step 6 影响评级"
        )
        _run_pipeline(tasks, rag_cache, path_frameworks, method)
        # 重试各阶段仍有空值/错误的 task
        _timed_retry_failed_tasks(
            tasks, path_frameworks, rag_cache, retry_attack_paths=True
        )
        save_checkpoint_async(tasks, "stage_AB", method)
        # Stage C 是最长阶段；先落盘 DST/Impact 缓存，避免后续中断后重跑。
        save_semantic_cache_async(_sem_cache_path)
        current_task_data = tasks
        logger.info("并发流水线完成，已保存 stage_AB checkpoint 与语义缓存")
        _check_wall_clock(_pipeline_start, "DST/攻击路径/影响评级")
    else:
        # 从 checkpoint 恢复后也做一次重试清理
        if current_task_data is not None:
            _timed_retry_failed_tasks(
                current_task_data,
                path_frameworks,
                rag_cache,
                retry_attack_paths=True,
            )

    # ── Step 7: 攻击可行性批量评估 ─────────────────
    assert current_task_data is not None, "当前任务数据为空，无法继续"
    if need_stage_c:
        def _persist_stage_c_cache(done: int, total: int) -> None:
            save_semantic_cache_async(_sem_cache_path)
            logger.info("Stage C 增量缓存已调度保存: %d/%d", done, total)

        with Timer("Step 7: 批量可行性评估"):
            total_aps = sum(len(t.attack_paths or []) for t in current_task_data)
            logger.info(f"Step 7：批量评估攻击可行性，总攻击路径数={total_aps}")
            stage_c_attack_batch(
                current_task_data,
                method,
                progress_callback=_persist_stage_c_cache,
            )

        save_checkpoint_async(current_task_data, "stage_C_attack", method)
        _check_wall_clock(_pipeline_start, "攻击可行性评估")

    assert current_task_data is not None, "当前任务数据为空，无法继续"
    _refresh_risk_treatments(current_task_data)

    # ─── Step 8: 安全需求选择与基线报告 ─────────────
    with Timer("Step 8: 报告生成"):
        if SECURITY_REQUIREMENTS_IMPLEMENTED_REASSESSMENT:
            selected_requirement_paths = _freeze_path_security_requirements(
                current_task_data
            )
            logger.info(
                "已冻结 %d 条路径的安全需求选择，准备实施后复评",
                selected_requirement_paths,
            )
        baseline_report = build_tara_report(
            current_task_data, method, IMPACT_METHOD
        )
        err_report = build_error_report(current_task_data)

    report = baseline_report
    residual_task_data: list[TaskUnit] | None = None
    if SECURITY_REQUIREMENTS_IMPLEMENTED_REASSESSMENT:
        with Timer("Step 9: 安全需求实施后复评"):
            residual_task_data = _reassess_after_security_requirements_deterministic(
                current_task_data, method
            )
            _enforce_residual_risk_target(
                current_task_data, residual_task_data, baseline_report,
                baseline_output_path,
                os.path.join(OUTPUT_DIR, "residual_target_failures.json"),
            )
            report = build_tara_report(
                residual_task_data, method, IMPACT_METHOD
            )
        save_json(baseline_report, baseline_output_path)

    # When reassessment is enabled the primary artifact is intentionally the
    # implemented-control (residual-risk) report requested by the demo.  The
    # untouched baseline remains alongside it for audit and comparison.
    save_json(report, output_path)
    save_json(err_report, errors_path)

    # ── Excel 报告导出 ──────────────────────────
    try:
        n_rows = export_tara_report_to_excel(output_path, xlsx_path, rag_cache=rag_cache, rag_queries=rag_queries)
        logger.info(f"Excel 报告已生成: {xlsx_path} ({n_rows} 行)")
        if SECURITY_REQUIREMENTS_IMPLEMENTED_REASSESSMENT:
            baseline_rows = export_tara_report_to_excel(
                baseline_output_path,
                baseline_xlsx_path,
                rag_cache=rag_cache,
                rag_queries=rag_queries,
            )
            logger.info(
                "基线 Excel 报告已生成: %s (%d 行)",
                baseline_xlsx_path,
                baseline_rows,
            )
    except Exception as e:
        logger.warning(f"Excel 报告生成失败: {e}")

    training_samples: list[dict[str, Any]] = []
    if CAPTURE_TRAINING:
        try:
            training_samples = _training_capture.export_adopted(
                current_task_data,
                model=MODEL_NAME,
                feasibility_method=method,
                impact_method=IMPACT_METHOD,
                enable_reason=ENABLE_REASON,
                prompt_signature=_prompt_signature(),
                system_prompts={
                    "dst": DST_BATCH_SYSTEM_PROMPT,
                    "impact": IMPACT_BATCH_SYSTEM_PROMPT,
                    "attack_entry": ATTACK_ENTRY_SYSTEM_PROMPT,
                    "attack_path": ATTACK_PATH_SYSTEM_PROMPT,
                    "attack_target": ATTACK_TARGET_SYSTEM_PROMPT,
                    "attack_potential": AP_BATCH_SYSTEM_PROMPT,
                    "cvss": CVSS_BATCH_SYSTEM_PROMPT,
                    "heavens": HEAVENS_AP_BATCH_SYSTEM_PROMPT,
                },
            )
            logger.info(
                "训练数据已生成: %d 条采用样本 | 审阅表: %s",
                len(training_samples),
                _training_capture.review_path,
            )
        except Exception as exc:
            logger.exception("训练采用样本导出失败: %s", exc)
        finally:
            # 此后没有模型调用；先排空后台写队列，让 manifest 记录最终统计。
            _training_capture.close()

    # ── 持久化语义缓存 ──────────────────────────
    save_semantic_cache_async(_sem_cache_path)
    wait_for_checkpoint_writes()

    total_elapsed = time.perf_counter() - _pipeline_start
    logger.info("=" * 72)
    unique_functions = len(set(t.function for t in current_task_data))
    unique_assets = len(set(t.asset_name for t in current_task_data))
    total_aps = sum(len(t.attack_paths or []) for t in current_task_data)
    logger.info(f"TARA 完成: 总功能数={unique_functions}, 分析资产数={analysed_asset_count}, 去重资产名数={unique_assets}, 安全属性总数={len(current_task_data)}, 攻击路径总数={total_aps}, 异常安全属性={len(err_report)}")
    logger.info("  各阶段实际耗时 (wall-clock):")
    for stage in ["Step 1: DFD 资产解析", "Step 2: 拓扑攻击路径框架",
                  "Step 3: 扩展属性 + RAG", "Step 4: 损害威胁场景",
                  "Step 5: 影响评级", "Step 6: 攻击路径生成",
                  "Step 5: 攻击路径+影响评级", "Step 7: 批量可行性评估",
                  "Step 8: 报告生成", "Step 9: 安全需求实施后复评",
                  "阶段失败子集恢复"]:
        secs = _stage_times.get(stage)
        if secs is not None:
            logger.info(f"    {stage}: {secs:.1f}s ({secs/60:.1f}min)")
    stage_telemetry = _log_stage_telemetry()
    logger.info(f"  项目总运行时间: {total_elapsed:.2f} 秒 ({total_elapsed / 60:.2f} 分钟)")
    logger.info("  流水线调用统计: %s", _pipeline_metrics_snapshot())
    logger.info("  LLM HTTP统计: %s", _llm_metrics_snapshot())
    logger.info(f"  主报告: {output_path}")
    if SECURITY_REQUIREMENTS_IMPLEMENTED_REASSESSMENT:
        logger.info("  安全需求实施前基线报告: %s", baseline_output_path)
    if err_report:
        logger.info(f"  异常报告: {errors_path}")
    logger.info("=" * 72)

    status_counts = Counter(t.analysis_status for t in current_task_data)
    manifest = {
        "schema_version": "tara-run-v11",
        "project_name": project_name,
        "start_time": _run_meta.get("start_time"),
        "finish_time": datetime.now().isoformat(),
        "elapsed_seconds": round(total_elapsed, 3),
        "git_commit": _git_commit(),
        "git_dirty": _git_worktree_dirty(),
        "inputs": {
            "dfd": os.path.abspath(data_flow_dir),
            "topology": os.path.abspath(topology_file),
            "external_interfaces": os.path.abspath(external_interface_excel),
            "signature": _RUN_INPUT_SIGNATURE,
        },
        # 与 run_metadata.json 共享同一份完整有效配置，禁止分别维护。
        "configuration": _current_run_configuration(),
        "checkpoint": _checkpoint_meta(method, len(current_task_data)),
        "versions": {
            "checkpoint_schema": CHECKPOINT_VERSION,
            "prompt_signature": _prompt_signature(),
            "source_signature": _pipeline_source_signature(),
            "scoring_signature": _scoring_signature(),
            "rag_signature": _compute_rag_hash() if ENABLE_RAG else None,
        },
        "outputs": {
            "json": os.path.abspath(output_path),
            "errors_json": os.path.abspath(errors_path),
            "xlsx": os.path.abspath(xlsx_path),
            "report_variant": (
                "security_requirements_implemented"
                if SECURITY_REQUIREMENTS_IMPLEMENTED_REASSESSMENT
                else "baseline"
            ),
            "baseline_json": (
                os.path.abspath(baseline_output_path)
                if SECURITY_REQUIREMENTS_IMPLEMENTED_REASSESSMENT
                else None
            ),
            "baseline_xlsx": (
                os.path.abspath(baseline_xlsx_path)
                if SECURITY_REQUIREMENTS_IMPLEMENTED_REASSESSMENT
                else None
            ),
            "llm_usage_live": os.path.abspath(
                os.path.join(OUTPUT_DIR, "llm_usage_live.json")
            ),
            "dfd_relationships_json": os.path.abspath(
                dfd_relationships_path
            ),
            "training_calls_jsonl": (
                str(_training_capture.calls_path)
                if CAPTURE_TRAINING else None
            ),
            "training_samples_jsonl": (
                str(_training_capture.samples_path)
                if CAPTURE_TRAINING else None
            ),
            "training_review_xlsx": (
                str(_training_capture.review_path)
                if CAPTURE_TRAINING else None
            ),
            "training_manifest_json": (
                str(_training_capture.manifest_path)
                if CAPTURE_TRAINING else None
            ),
        },
        "counts": {
            "functions": unique_functions,
            # ``assets`` is the number of task-backed asset instances actually
            # analysed (external actors/non-analysed records excluded).
            # ``input_asset_records`` retains the selected raw-input count,
            # while ``unique_asset_names`` retains the old diagnostic metric.
            "assets": analysed_asset_count,
            "assets_analyzed": analysed_asset_count,
            "input_asset_records": input_asset_count,
            "unique_asset_names": unique_assets,
            "tasks": len(current_task_data),
            "attack_paths": total_aps,
            "statuses": dict(status_counts),
        },
        "semantic_cache": semantic_cache.stats(),
        "completed_result_cache": {
            "enabled": completed_cache is not None,
            "hit": False,
            "key": completed_key,
        },
        "pipeline": _pipeline_metrics_snapshot(),
        "llm": _llm_metrics_snapshot(),
        "stage_telemetry": stage_telemetry,
        "training_capture": _training_capture.snapshot(),
        "stage_seconds": dict(_stage_times),
    }
    save_json(manifest, os.path.join(OUTPUT_DIR, "run_manifest.json"))
    if completed_cache is not None:
        try:
            stored = completed_cache.publish(completed_key, completed_identity, manifest)
            logger.info("完整分析结果缓存%s: %s", "已保存" if stored else "未保存（已有快照或本次结果不完整）", completed_key[:16])
        except Exception as exc:
            logger.warning("完整分析结果缓存保存失败: %s", exc)
    return report, err_report


def run_tara(
    data_flow_dir: str,
    topology_file: str,
    external_interface_excel: str,
    output_path: str,
    feasibility_method: str = FEASIBILITY_METHOD,
    max_assets_for_test: Optional[int] = None,
    skip_checkpoint_resume: bool = False,
    analysis_refs: Optional[list[str]] = None,
) -> tuple[list[dict], list[dict]]:
    """运行完整流水线，并保证异常路径也释放连接、等待检查点及保存缓存。"""
    global _http_pool
    # 模块包含运行级全局缓存、计时器和输出目录；同进程并发执行会互相污染。
    # UI 已使用独立子进程，多线程调用方则在这里安全串行化。
    with _run_lock:
        try:
            with ExitStack() as cache_stack:
                return _run_tara_impl(
                    data_flow_dir=data_flow_dir,
                    topology_file=topology_file,
                    external_interface_excel=external_interface_excel,
                    output_path=output_path,
                    feasibility_method=feasibility_method,
                    max_assets_for_test=max_assets_for_test,
                    skip_checkpoint_resume=skip_checkpoint_resume,
                    analysis_refs=analysis_refs,
                    _cache_stack=cache_stack,
                )
        finally:
            _training_capture.close()
            wait_for_checkpoint_writes()
            if _runtime_initialized:
                semantic_cache.save(
                    os.path.join(SHARED_CACHE_DIR, "semantic_cache.json")
                )
            if _http_pool is not None:
                _http_pool.close()
                _http_pool = None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 14) 入口
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

if __name__ == "__main__":
    if not TOPOLOGY_FILE:
        logger.error("未设置 TARA_TOPOLOGY_FILE 环境变量，请指定拓扑图 JSON 文件路径")
        sys.exit(1)
    if not DFD_FILE:
        logger.error("未设置 TARA_DFD_FILE 环境变量，请指定 DFD JSON 文件路径")
        sys.exit(1)

    # FEASIBILITY_METHOD / TEST_MAX_ASSETS / SKIP_CHECKPOINT 均为模块级变量

    run_tara(
        data_flow_dir=DFD_FILE,
        topology_file=TOPOLOGY_FILE,
        external_interface_excel=EXTERNAL_INTERFACE_EXCEL,
        output_path=os.path.join(OUTPUT_DIR, "tara_report.json"),
        feasibility_method=FEASIBILITY_METHOD,
        max_assets_for_test=TEST_MAX_ASSETS,
        skip_checkpoint_resume=SKIP_CHECKPOINT,
    )
