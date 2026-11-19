"""完整运行配置快照与元数据持久化。"""

from __future__ import annotations

import copy
import os
from typing import Any, Optional

import orjson

from automotive_tara.storage import atomic_write_bytes


SENSITIVE_CONFIG_MARKERS = (
    "API_KEY",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
)

# 普通环境参数只需在这里声明一次。路径、调用参数覆盖和密钥在下方单独处理。
_DIRECT_CONFIG_MAP = {
    "TARA_MODEL": "MODEL_NAME",
    "TARA_IMPACT_MODEL": "IMPACT_MODEL_NAME",
    "TARA_API_BASE": "API_BASE",
    "TARA_TEMPERATURE": "TEMPERATURE",
    "TARA_FREQUENCY_PENALTY": "FREQUENCY_PENALTY",
    "TARA_PRESENCE_PENALTY": "PRESENCE_PENALTY",
    "TARA_SEED": "SAMPLING_SEED",
    "TARA_TOP_P": "TOP_P",
    "TARA_TOP_K": "TOP_K",
    "TARA_MAX_TOKENS": "MAX_TOKENS",
    "TARA_REQUEST_TIMEOUT": "REQUEST_TIMEOUT",
    "TARA_LLM_RETRIES": "LLM_RETRIES",
    "TARA_HTTP_KEEPALIVE_IDLE_TTL": "HTTP_KEEPALIVE_IDLE_TTL",
    "TARA_TASK_CONTEXT_TOKENS": "MODEL_CONTEXT_TOKENS",
    "TARA_SERVICE_CONTEXT_TOKENS": "SERVICE_CONTEXT_TOKENS",
    "TARA_WALL_CLOCK_TIMEOUT": "WALL_CLOCK_TIMEOUT",
    "TARA_DST_MAX_TOKENS": "DST_MAX_TOKENS",
    "TARA_ATTACK_COMPONENT_MAX_TOKENS": "ATTACK_COMPONENT_MAX_TOKENS",
    "TARA_DIRECT_ATTACK_PATHS_PER_CALL": "DIRECT_ATTACK_PATHS_PER_CALL",
    "TARA_DIRECT_ATTACK_PATH_RETRY_MAX_CALLS": "DIRECT_ATTACK_PATH_RETRY_MAX_CALLS",
    "TARA_DIRECT_ATTACK_PATH_MIN_TOKENS": "DIRECT_ATTACK_PATH_MIN_TOKENS",
    "TARA_DIRECT_ATTACK_PATH_MAX_TOKENS": "DIRECT_ATTACK_PATH_MAX_TOKENS",
    "TARA_IMPACT_MAX_TOKENS": "IMPACT_MAX_TOKENS",
    "TARA_FEASIBILITY_MAX_TOKENS": "FEASIBILITY_MAX_TOKENS",
    "TARA_MAX_WORKERS": "MAX_WORKERS",
    "TARA_MAX_CONCURRENT_LLM": "MAX_CONCURRENT_LLM",
    "TARA_ATTACK_PATH_WORKERS": "ATTACK_PATH_WORKERS",
    "TARA_STAGE_C_MAX_CONCURRENT_LLM": "STAGE_C_MAX_CONCURRENT_LLM",
    "TARA_VLLM_MAX_NUM_SEQS": "VLLM_MAX_NUM_SEQS",
    "TARA_CALL_INTERVAL": "CALL_INTERVAL",
    "TARA_BATCH_DST": "BATCH_SIZE_DST",
    "TARA_BATCH_IMPACT": "BATCH_SIZE_IMPACT",
    "TARA_IMPACT_REPAIR_MAX_DEPTH": "IMPACT_REPAIR_MAX_DEPTH",
    "TARA_BATCH_SIZE_ATTACK": "BATCH_SIZE_ATTACK",
    "TARA_ATTACK_PATHS_PER_CALL": "ATTACK_PATH_TASKS_PER_CALL",
    "TARA_MAX_PENDING_FUTURES": "MAX_PENDING_FUTURES",
    "TARA_TOPOLOGY_PATHS_PER_PAIR": "TOPOLOGY_PATHS_PER_PAIR",
    "TARA_SEMANTIC_CACHE_BUCKET_SIZE": "SEMANTIC_CACHE_BUCKET_SIZE",
    "TARA_REUSE_COMPLETED_RESULTS": "REUSE_COMPLETED_RESULTS",
    'TARA_LIVE_MODEL_OUTPUT': 'LIVE_MODEL_OUTPUT',
    'TARA_ASSET_SELECTION_PATH': 'ASSET_SELECTION_PATH',
    "TARA_FEASIBILITY_PATHS_PER_CALL": "FEASIBILITY_PATHS_PER_CALL",
    "TARA_STAGE_C_FINAL_RETRY_MAX_PATHS": "STAGE_C_FINAL_RETRY_MAX_PATHS",
    "TARA_FEASIBILITY_REASON_PATHS_PER_CALL": (
        "FEASIBILITY_REASON_PATHS_PER_CALL"
    ),
    "TARA_STAGE_C_CACHE_FLUSH_TASKS": "STAGE_C_CACHE_FLUSH_TASKS",
    "TARA_STAGE_C_CACHE_FLUSH_SECONDS": "STAGE_C_CACHE_FLUSH_SECONDS",
    "TARA_PIPELINE_RECOVERY_ROUNDS": "PIPELINE_RECOVERY_ROUNDS",
    "TARA_IMPACT_METHOD": "IMPACT_METHOD",
    "TARA_SC_ENABLED": "SC_ENABLED",
    "TARA_SC_SAMPLES": "SC_SAMPLES",
    "TARA_SC_CONFIDENCE_THRESHOLD": "SC_CONFIDENCE_THRESHOLD",
    "TARA_SC_SINGLE_CALL": "SC_SINGLE_CALL",
    "TARA_ENABLE_REASON": "ENABLE_REASON",
    "TARA_ENABLE_CONSISTENCY": "ENABLE_CONSISTENCY",
    "TARA_ENABLE_RAG": "ENABLE_RAG",
    "TARA_ENABLE_R155": "ENABLE_R155",
    "TARA_RAG_METHOD": "RAG_METHOD",
    "TARA_RAG_TOP_K": "RAG_TOP_K",
    "TARA_RAG_MAX_CHARS": "RAG_MAX_CONTEXT_CHARS",
    "TARA_BM25_K1": "BM25_K1",
    "TARA_BM25_B": "BM25_B",
    "TARA_RRF_K": "RRF_K",
    "TARA_RAG_RERANK": "RERANKER_ENABLED",
    "TARA_RERANK_CANDIDATES": "RERANKER_CANDIDATES",
    "TARA_RERANKER_BATCH_SIZE": "RERANKER_BATCH_SIZE",
    "TARA_ENABLE_FUNC_DESC": "_ENABLE_FUNC_DESC",
    "TARA_SKIP_CHAT_TEMPLATE": "SKIP_CHAT_TEMPLATE",
    "TARA_VERIFY_MODEL_HASHES": "VERIFY_MODEL_HASHES",
    "TARA_STRICT_INPUTS": "STRICT_INPUTS",
    "TARA_LLM_PREFLIGHT": "LLM_PREFLIGHT",
    "TARA_ENABLE_APPLICABILITY_FILTER": "ENABLE_APPLICABILITY_FILTER",
    "TARA_ENABLE_ASSET_DETAILS": "ENABLE_ASSET_DETAILS",
    "TARA_SECURITY_REQUIREMENTS_IMPLEMENTED_REASSESSMENT": (
        "SECURITY_REQUIREMENTS_IMPLEMENTED_REASSESSMENT"
    ),
    "TARA_SECURITY_REQUIREMENTS_SCOPE": "SECURITY_REQUIREMENTS_SCOPE",
    "TARA_DFD_FORMAT": "DFD_INPUT_FORMAT",
    "TARA_CAPTURE_TRAINING": "CAPTURE_TRAINING",
    "TARA_CAPTURE_REJECTED": "CAPTURE_REJECTED",
    "TARA_ADAPTIVE_SCHEDULING": "ADAPTIVE_SCHEDULING",
    "TARA_TEST_ASSET_SELECTION": "TEST_ASSET_SELECTION",
    "TARA_GPU_MEMORY_GB": "GPU_MEMORY_GB",
    "TARA_MODEL_SIZE_B": "MODEL_SIZE_B",
    "TARA_MODEL_QUANTIZATION": "MODEL_QUANTIZATION",
    "TARA_REMOTE_API": "REMOTE_API",
}

_ABSOLUTE_PATH_CONFIG_MAP = {
    "TARA_OUTPUT_DIR": "OUTPUT_DIR",
    "TARA_CHECKPOINT_DIR": "CHECKPOINT_DIR",
    "TARA_SHARED_CACHE_DIR": "SHARED_CACHE_DIR",
    "TARA_R155_ANNEX5_PATH": "R155_ANNEX5_PATH",
    "TARA_RAG_BASE_DIR": "RAG_BASE_DIR",
    "TARA_RERANKER_PATH": "RERANKER_MODEL_PATH",
    "TARA_BGE_M3_PATH": "BGE_M3_PATH",
    "TARA_VECTOR_STORE_DIR": "VECTOR_STORE_DIR",
    "TARA_SECURITY_REQUIREMENTS_PATH": "SECURITY_REQUIREMENTS_PATH",
}


def _redact_config_value(name: str, value: Any) -> Any:
    """配置文件中不落盘密钥；非敏感配置保留原始类型和值。"""
    upper_name = name.upper()
    if any(marker in upper_name for marker in SENSITIVE_CONFIG_MARKERS):
        return "<redacted>" if value not in (None, "") else ""
    return value


def _tara_environment_overrides() -> dict[str, Any]:
    """记录进程收到的全部 TARA_* 覆盖项，包括未来新增参数。"""
    return {
        name: _redact_config_value(name, value)
        for name, value in sorted(os.environ.items())
        if name.startswith("TARA_")
    }


def _effective_run_configuration(
    *,
    runtime,
    token_budget_snapshot,
    data_flow_dir: Optional[str] = None,
    topology_file: Optional[str] = None,
    external_interface_excel: Optional[str] = None,
    output_path: Optional[str] = None,
    feasibility_method: Optional[str] = None,
    max_assets_for_test: Optional[int] = None,
    skip_checkpoint_resume: Optional[bool] = None,
    experiment_selection_count: int = 0,
    experiment_selection_signature: Optional[str] = None,
) -> dict[str, Any]:
    """返回单一、完整且可安全落盘的运行参数快照。"""
    effective_method = (
        feasibility_method
        if feasibility_method is not None
        else runtime["FEASIBILITY_METHOD"]
    ).strip().lower()
    effective_max_assets = (
        max_assets_for_test
        if max_assets_for_test is not None
        else runtime["TEST_MAX_ASSETS"]
    )
    effective_skip_checkpoint = (
        bool(skip_checkpoint_resume)
        if skip_checkpoint_resume is not None
        else runtime["SKIP_CHECKPOINT"]
    )
    effective_dfd = (
        data_flow_dir if data_flow_dir is not None else runtime["DFD_FILE"]
    )
    effective_topology = (
        topology_file
        if topology_file is not None
        else runtime["TOPOLOGY_FILE"]
    )
    effective_interfaces = (
        external_interface_excel
        if external_interface_excel is not None
        else runtime["EXTERNAL_INTERFACE_EXCEL"]
    )

    effective = {
        environment_name: runtime[runtime_name]
        for environment_name, runtime_name in _DIRECT_CONFIG_MAP.items()
    }
    effective.update(
        {
            environment_name: os.path.abspath(runtime[runtime_name])
            for environment_name, runtime_name
            in _ABSOLUTE_PATH_CONFIG_MAP.items()
        }
    )
    function_inventory = runtime["FUNC_INVENTORY_PATH"]
    effective.update(
        {
            "TARA_DFD_FILE": os.path.abspath(effective_dfd),
            "TARA_TOPOLOGY_FILE": os.path.abspath(effective_topology),
            "TARA_EXTERNAL_INTERFACE_EXCEL": os.path.abspath(
                effective_interfaces
            ),
            "TARA_API_KEY": _redact_config_value(
                "TARA_API_KEY", runtime["API_KEY"]
            ),
            "TARA_API_KEY_CONFIGURED": bool(
                runtime["API_KEY"] and runtime["API_KEY"] != "EMPTY"
            ),
            "TARA_FEASIBILITY_METHOD": effective_method,
            "TARA_FUNC_INVENTORY": (
                os.path.abspath(function_inventory)
                if function_inventory
                else ""
            ),
            "TARA_SKIP_CHECKPOINT": effective_skip_checkpoint,
            "TARA_TEST_MAX_ASSETS": effective_max_assets,
        }
    )

    invocation = {
        "data_flow_dir": os.path.abspath(effective_dfd),
        "topology_file": os.path.abspath(effective_topology),
        "external_interface_excel": os.path.abspath(effective_interfaces),
        "output_path": os.path.abspath(output_path) if output_path else None,
        "feasibility_method": effective_method,
        "impact_method": runtime["IMPACT_METHOD"],
        "max_assets_for_test": effective_max_assets,
        "skip_checkpoint_resume": effective_skip_checkpoint,
        "experiment_selection_count": experiment_selection_count,
        "experiment_selection_signature": experiment_selection_signature,
    }
    output_dir = os.path.abspath(runtime["OUTPUT_DIR"])
    derived = {
        "project_root": os.path.abspath(runtime["_PROJECT_ROOT"]),
        "rag_directories": {
            name: os.path.abspath(path)
            for name, path in runtime["RAG_DIRS"].items()
        },
        "full_run": effective_max_assets is None,
        "reason_policy": (
            "required" if runtime["ENABLE_REASON"] else "forbidden"
        ),
        "attack_path_architecture": "direct_llm_trusted_topology_v1",
        "output_layout": "daily_versioned_v1",
        "output_day": os.path.basename(os.path.dirname(output_dir)),
        "output_version": os.path.basename(output_dir),
        "sc_multi_choice_concurrency": runtime[
            "SC_MULTI_CHOICE_CONCURRENCY"
        ],
        "sc_inflight_sequence_budget": (
            runtime["SC_MULTI_CHOICE_CONCURRENCY"] * runtime["SC_SAMPLES"]
        ),
        "rating_reason_max_chars": runtime["RATING_REASON_MAX_CHARS"],
        "dynamic_token_budgets": token_budget_snapshot(),
        "runtime_profile": copy.deepcopy(runtime.get("RUNTIME_PROFILE", {})),
        "model_runtime_profile": runtime.get("MODEL_RUNTIME_PROFILE", "generic"),
        "experiment_selection_applied": experiment_selection_count > 0,
    }
    return {
        "schema_version": "tara-configuration-v1",
        "effective": effective,
        "invocation": invocation,
        "derived": derived,
        "environment_overrides": _tara_environment_overrides(),
    }


def _write_run_metadata(
    run_meta,
    output_dir,
    configuration: dict[str, Any],
) -> None:
    """更新元数据并原子写入，manifest 复用同一配置快照。"""
    run_meta["configuration"] = copy.deepcopy(configuration)
    effective = configuration["effective"]
    summary_fields = {
        "output_dir": "TARA_OUTPUT_DIR",
        "model": "TARA_MODEL",
        "api_base": "TARA_API_BASE",
        "llm_retries": "TARA_LLM_RETRIES",
        "temperature": "TARA_TEMPERATURE",
        "seed": "TARA_SEED",
        "top_p": "TARA_TOP_P",
        "top_k": "TARA_TOP_K",
        "frequency_penalty": "TARA_FREQUENCY_PENALTY",
        "presence_penalty": "TARA_PRESENCE_PENALTY",
        "feasibility_method": "TARA_FEASIBILITY_METHOD",
        "impact_method": "TARA_IMPACT_METHOD",
        "dfd_format": "TARA_DFD_FORMAT",
        "enable_rag": "TARA_ENABLE_RAG",
        "rag_top_k": "TARA_RAG_TOP_K",
        "max_concurrent_llm": "TARA_MAX_CONCURRENT_LLM",
        "attack_path_workers": "TARA_ATTACK_PATH_WORKERS",
        "stage_c_max_concurrent_llm": "TARA_STAGE_C_MAX_CONCURRENT_LLM",
        "max_workers": "TARA_MAX_WORKERS",
        "batch_dst": "TARA_BATCH_DST",
        "batch_impact": "TARA_BATCH_IMPACT",
        "attack_paths_per_call": "TARA_ATTACK_PATHS_PER_CALL",
        "direct_attack_paths_per_call": "TARA_DIRECT_ATTACK_PATHS_PER_CALL",
        "direct_attack_path_retry_max_calls": "TARA_DIRECT_ATTACK_PATH_RETRY_MAX_CALLS",
        "feasibility_paths_per_call": "TARA_FEASIBILITY_PATHS_PER_CALL",
        "stage_c_final_retry_max_paths": "TARA_STAGE_C_FINAL_RETRY_MAX_PATHS",
        "feasibility_reason_paths_per_call": (
            "TARA_FEASIBILITY_REASON_PATHS_PER_CALL"
        ),
        "http_keepalive_idle_ttl": "TARA_HTTP_KEEPALIVE_IDLE_TTL",
        "stage_c_cache_flush_tasks": "TARA_STAGE_C_CACHE_FLUSH_TASKS",
        "stage_c_cache_flush_seconds": "TARA_STAGE_C_CACHE_FLUSH_SECONDS",
        "test_max_assets": "TARA_TEST_MAX_ASSETS",
    }
    run_meta.update(
        {
            summary_name: effective[environment_name]
            for summary_name, environment_name in summary_fields.items()
        }
    )
    atomic_write_bytes(
        os.path.join(output_dir, "run_metadata.json"),
        orjson.dumps(run_meta, option=orjson.OPT_INDENT_2),
    )


def _current_run_configuration(run_meta) -> dict[str, Any]:
    """为最终 manifest 提供元数据中配置的防御性副本。"""
    configuration = run_meta.get("configuration")
    if not isinstance(configuration, dict):
        raise RuntimeError("运行配置快照尚未初始化")
    return copy.deepcopy(configuration)
