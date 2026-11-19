"""Environment-backed TARA settings.

Importing this module only parses values; it does not create directories,
open network connections, or load models.
"""

from __future__ import annotations

import os
from pathlib import Path

from automotive_tara.input_paths import (
    default_dfd_path, default_interfaces_path, default_topology_path,
)
from automotive_tara.run_paths import default_run_dir, default_shared_cache_dir


_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _env_bool(name: str, default: bool = False) -> bool:
    """严格解析布尔环境变量，避免 off/FALSE/空值被误判为开启。"""
    raw = os.getenv(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off", ""}:
        return False
    raise ValueError(
        f"{name} 必须为 1/0、true/false、yes/no 或 on/off，当前为 {raw!r}"
    )


# ──── 路径 ─────────────────────────────────────────────────────────────
def _default_output_dir():
    """自动生成 ``outputs/YYYY-MM-DD/V{N}_HHMMSS_PID`` 目录。"""
    return str(default_run_dir(_PROJECT_ROOT))

OUTPUT_DIR       = os.getenv("TARA_OUTPUT_DIR",       _default_output_dir())
CHECKPOINT_DIR   = os.getenv("TARA_CHECKPOINT_DIR",   os.path.join(OUTPUT_DIR, ".checkpoints"))
SHARED_CACHE_DIR = os.getenv("TARA_SHARED_CACHE_DIR",
                       str(default_shared_cache_dir(_PROJECT_ROOT)))
R155_ANNEX5_PATH = os.getenv("TARA_R155_ANNEX5_PATH",
                       os.path.join(_PROJECT_ROOT, "data", "r155_annex5.json"))
DFD_FILE               = os.getenv(
    "TARA_DFD_FILE", str(default_dfd_path(Path(_PROJECT_ROOT)))
)
DFD_INPUT_FORMAT = (
    os.getenv("TARA_DFD_FORMAT", "legacy").strip().lower() or "legacy"
)
TOPOLOGY_FILE          = os.getenv(
    "TARA_TOPOLOGY_FILE",
    str(default_topology_path(Path(_PROJECT_ROOT))),
)
EXTERNAL_INTERFACE_EXCEL = os.getenv("TARA_EXTERNAL_INTERFACE_EXCEL",
                              str(default_interfaces_path(Path(_PROJECT_ROOT))))
SECURITY_REQUIREMENTS_PATH = os.getenv(
    "TARA_SECURITY_REQUIREMENTS_PATH",
    os.path.join(_PROJECT_ROOT, "data", "rag", "安全需求导入模板-20260720.xlsx"),
)
SECURITY_REQUIREMENTS_LOGIC_PATH = os.getenv(
    "TARA_SECURITY_REQUIREMENTS_LOGIC_PATH",
    os.path.join(_PROJECT_ROOT, "data", "rag", "安全需求匹配逻辑2.0.docx"),
)
# The normal CLI keeps the deterministic matcher as a lightweight, offline
# default.  The web demo explicitly enables the grounded LLM selector so
# customer reports use semantic selection while remaining bounded by the
# workbook and the matching-logic document.
SECURITY_REQUIREMENTS_LLM = _env_bool("TARA_SECURITY_REQUIREMENTS_LLM", False)
SECURITY_REQUIREMENTS_SCOPE = os.getenv(
    "TARA_SECURITY_REQUIREMENTS_SCOPE", "45"
).strip()
if SECURITY_REQUIREMENTS_SCOPE not in {"345", "45"}:
    SECURITY_REQUIREMENTS_SCOPE = "45"
# Reassess residual attack feasibility after the selected security
# requirements are treated as implemented controls.  Disabled for the normal
# CLI by default; the AI-selection demo exposes an explicit switch.
SECURITY_REQUIREMENTS_IMPLEMENTED_REASSESSMENT = _env_bool(
    "TARA_SECURITY_REQUIREMENTS_IMPLEMENTED_REASSESSMENT", False
)
# Optional two-step residual analysis: first establish a credible post-control
# attack path, then score that path.  The existing reassessment remains default.
SECURITY_REQUIREMENTS_TWO_STAGE_REASSESSMENT = _env_bool(
    "TARA_SECURITY_REQUIREMENTS_TWO_STAGE_REASSESSMENT", False
)

# ──── 模型 / API ───────────────────────────────────────────────────────
# 默认使用当前 A100 生产验证过的 AWQ 模型；通过 TARA_MODEL 或 --model
# 仍可临时切换到服务端暴露的其他模型名。
MODEL_NAME       = os.getenv("TARA_MODEL", "Qwen3.8-27B-AWQ-INT4")
IMPACT_MODEL_NAME = os.getenv("TARA_IMPACT_MODEL", "").strip() or MODEL_NAME


def _runtime_defaults_for_model(model_name: str) -> tuple[str, dict[str, int]]:
    """Return the validated client profile for the selected served model.

    The three production models have different KV-cache/latency envelopes;
    keeping one global batch profile causes either the 35B-A3B model to be
    under-utilised or the BF16 27B model to be over-subscribed. Explicit
    ``TARA_*`` values still override every value returned here.
    """
    folded = str(model_name or "").strip().casefold()
    if "35b-a3b" in folded and any(
        token in folded for token in ("awq", "int4", "4bit", "gptq")
    ):
        return "qwen3.6-35b-a3b-awq", {
            "max_concurrent_llm": 48,
            "stage_c_max_concurrent_llm": 32,
            "batch_dst": 12,
            "batch_impact": 12,
            "batch_size_attack": 16,
            "direct_attack_paths_per_call": 8,
            "feasibility_paths_per_call": 24,
        }
    if "qwen3.8" in folded and "27b" in folded and any(
        token in folded for token in ("awq", "int4", "4bit", "gptq")
    ):
        return "qwen3.8-27b-awq-int4", {
            "max_concurrent_llm": 48,
            "stage_c_max_concurrent_llm": 48,
            "batch_dst": 8,
            "batch_impact": 8,
            "batch_size_attack": 16,
            "direct_attack_paths_per_call": 8,
            "feasibility_paths_per_call": 24,
        }
    if "qwen3.8" in folded and "27b" in folded:
        return "qwen3.8-27b-bf16", {
            "max_concurrent_llm": 16,
            "stage_c_max_concurrent_llm": 16,
            "batch_dst": 8,
            "batch_impact": 8,
            "batch_size_attack": 16,
            "direct_attack_paths_per_call": 8,
            "feasibility_paths_per_call": 20,
        }
    return "generic", {
        "max_concurrent_llm": 16,
        "stage_c_max_concurrent_llm": 16,
        "batch_dst": 8,
        "batch_impact": 8,
        "batch_size_attack": 16,
        "direct_attack_paths_per_call": 8,
        "feasibility_paths_per_call": 20,
    }


MODEL_RUNTIME_PROFILE, _MODEL_RUNTIME_DEFAULTS = _runtime_defaults_for_model(MODEL_NAME)


def _model_default(name: str, fallback: int) -> str:
    return str(_MODEL_RUNTIME_DEFAULTS.get(name, fallback))


API_BASE         = os.getenv("TARA_API_BASE",           "http://127.0.0.1:8000/v1")
API_KEY          = os.getenv("TARA_API_KEY",            "EMPTY")
# 稳定生产默认值：评级和结构化输出使用贪心解码，避免同一输入因
# temperature 采样产生不同的离散评级。需要探索性生成时可通过环境变量覆盖。
TEMPERATURE      = float(os.getenv("TARA_TEMPERATURE",  "0"))
# 请求级采样参数。稳定生产默认使用固定随机种子、全概率范围和贪心候选，
# 同一请求在不同批次中更容易得到相同的离散评级。文本生成如需更丰富，
# 可通过环境变量覆盖；这些参数会随运行配置和缓存键记录。
SAMPLING_SEED    = int(os.getenv("TARA_SEED", "42"))
TOP_P            = float(os.getenv("TARA_TOP_P", "1.0"))
TOP_K            = int(os.getenv("TARA_TOP_K", "1"))
# OpenAI-compatible repetition controls.  Keeping the default at zero preserves
# the deterministic production profile while allowing text-heavy stages to be
# tuned without changing the vLLM process.
FREQUENCY_PENALTY = float(os.getenv("TARA_FREQUENCY_PENALTY", "0"))
PRESENCE_PENALTY  = float(os.getenv("TARA_PRESENCE_PENALTY", "0"))
MAX_TOKENS       = int(os.getenv("TARA_MAX_TOKENS",     "2048"))         # 普通阶段动态预算的全局硬上限
REQUEST_TIMEOUT  = int(os.getenv("TARA_REQUEST_TIMEOUT", "240"))         # 单次请求超时(秒)
# Transport-level retry budget.  Stage-specific validation retries are
# separate and targeted; keeping this at one avoids repeating a large batch
# after a transient parse/HTTP failure.  Set to 0 for cache-only/offline runs.
LLM_RETRIES      = max(0, int(os.getenv("TARA_LLM_RETRIES", "1")))
# Request policy is independent of the vLLM engine's maximum sequence length.
MODEL_CONTEXT_TOKENS = int(os.getenv("TARA_TASK_CONTEXT_TOKENS", "16384"))
SERVICE_CONTEXT_TOKENS = int(os.getenv('TARA_SERVICE_CONTEXT_TOKENS', '0'))
HTTP_KEEPALIVE_IDLE_TTL = float(
    os.getenv("TARA_HTTP_KEEPALIVE_IDLE_TTL", "3")
)  # 超过该空闲时间不再复用连接，避免服务端半关闭
WALL_CLOCK_TIMEOUT = int(os.getenv("TARA_WALL_CLOCK_TIMEOUT", "0"))      # 总运行超时(秒), 0=不限
DST_MAX_TOKENS         = int(os.getenv("TARA_DST_MAX_TOKENS",         "2048"))
ATTACK_COMPONENT_MAX_TOKENS = int(
    os.getenv("TARA_ATTACK_COMPONENT_MAX_TOKENS", "1536")
)  # 早期兼容分支使用的入口/目标短动作输出长度
DIRECT_ATTACK_PATHS_PER_CALL = int(
    os.getenv(
        "TARA_DIRECT_ATTACK_PATHS_PER_CALL",
        _model_default("direct_attack_paths_per_call", 8),
    )
)  # 控制 JSON 响应长度；显式环境变量仍可覆盖
DIRECT_ATTACK_PATH_RETRY_MAX_CALLS = int(
    os.getenv("TARA_DIRECT_ATTACK_PATH_RETRY_MAX_CALLS", "16")
)
# 完整攻击路径需要同时输出 path_id 和多步正文，输出长度明显高于入口/目标
# 短动作。独立设置其动态预算上下限，避免 ``TARA_MAX_TOKENS=2048`` 把大批次
# JSON 截断；实际值仍会按模型上下文剩余空间进一步收紧。
DIRECT_ATTACK_PATH_MIN_TOKENS = int(
    os.getenv("TARA_DIRECT_ATTACK_PATH_MIN_TOKENS", "4096")
)
DIRECT_ATTACK_PATH_MAX_TOKENS = int(
    os.getenv("TARA_DIRECT_ATTACK_PATH_MAX_TOKENS", "8192")
)
# 缺失路径只允许模型拆批补全；重试次数有界，最终缺失仍须标记失败。
IMPACT_MAX_TOKENS      = int(os.getenv("TARA_IMPACT_MAX_TOKENS",      "2048"))
FEASIBILITY_MAX_TOKENS = int(os.getenv("TARA_FEASIBILITY_MAX_TOKENS", "3072"))

# ──── 并行度 / 线程池 ─────────────────────────────────────────────────
MAX_WORKERS        = int(os.getenv("TARA_MAX_WORKERS",         "96"))    # 流水线线程池大小
MAX_CONCURRENT_LLM = int(
    os.getenv("TARA_MAX_CONCURRENT_LLM", _model_default("max_concurrent_llm", 16))
)  # 按选定模型的生产并发上限(信号量)
ATTACK_PATH_WORKERS = int(
    os.getenv("TARA_ATTACK_PATH_WORKERS", str(MAX_CONCURRENT_LLM))
)  # 独立执行通道，避免被影响评级的 FIFO 队列阻塞
STAGE_C_MAX_CONCURRENT_LLM = int(
    os.getenv(
        "TARA_STAGE_C_MAX_CONCURRENT_LLM",
        _model_default("stage_c_max_concurrent_llm", 16),
    )
)  # Stage C 长批次单独限流，按选定模型兼顾吞吐与尾延迟
VLLM_MAX_NUM_SEQS = int(
    os.getenv("TARA_VLLM_MAX_NUM_SEQS", "32")
)  # 必须与 start_vllm.sh 的 --max-num-seqs 一致，用于 n-choice 容量规划
CALL_INTERVAL      = float(os.getenv("TARA_CALL_INTERVAL",     "0"))    # 调用间隔(秒), 0=不限

# Runtime scheduling is deliberately conservative.  When enabled, a profile
# is derived from the advertised model size and available GPU memory; an
# explicit TARA_* value always wins over a derived value.  This only changes
# client-side batching/concurrency and never attempts to reconfigure vLLM.
# 固定生产档默认关闭自适应覆盖，确保不同机器/容器的 nvidia-smi 探测
# 不会悄悄把已验证的并发和批量降回保守值。需要按显存自动降档时显式
# 设置 TARA_ADAPTIVE_SCHEDULING=1。
ADAPTIVE_SCHEDULING = _env_bool("TARA_ADAPTIVE_SCHEDULING", False)
GPU_MEMORY_GB = float(os.getenv("TARA_GPU_MEMORY_GB", "0"))
MODEL_SIZE_B = float(os.getenv("TARA_MODEL_SIZE_B", "0"))
MODEL_QUANTIZATION = os.getenv("TARA_MODEL_QUANTIZATION", "").strip().lower()
REMOTE_API = _env_bool("TARA_REMOTE_API", False)

# ──── 批处理大小 ───────────────────────────────────────────────────────
BATCH_SIZE_DST      = int(
    os.getenv("TARA_BATCH_DST", _model_default("batch_dst", 8))
)  # Damage+Threat 批量 N
BATCH_SIZE_IMPACT   = int(
    os.getenv("TARA_BATCH_IMPACT", _model_default("batch_impact", 8))
)  # Impact 评级批量 N
IMPACT_REPAIR_MAX_DEPTH = int(
    os.getenv("TARA_IMPACT_REPAIR_MAX_DEPTH", "1")
)  # 非法批次最多拆半修复一层，防止 1→2→4→8 指数放大
BATCH_SIZE_ATTACK   = int(
    os.getenv("TARA_BATCH_SIZE_ATTACK", _model_default("batch_size_attack", 16))
)  # Attack 可行性批量 N
ATTACK_PATH_TASKS_PER_CALL = int(
    os.getenv("TARA_ATTACK_PATHS_PER_CALL", "12")
)  # 攻击路径批次的任务上限
MAX_PENDING_FUTURES = int(os.getenv("TARA_MAX_PENDING_FUTURES", "192"))
# 0 表示不截断候选。拓扑解析本身只保留每个起点—终点的等长最短
# 路径；显式设置正整数仅用于兼容旧实验的候选采样，不影响最终规则。
TOPOLOGY_PATHS_PER_PAIR = int(os.getenv("TARA_TOPOLOGY_PATHS_PER_PAIR", "0"))
SEMANTIC_CACHE_BUCKET_SIZE = int(os.getenv("TARA_SEMANTIC_CACHE_BUCKET_SIZE", "10000"))
REUSE_COMPLETED_RESULTS = _env_bool("TARA_REUSE_COMPLETED_RESULTS", True)
LIVE_MODEL_OUTPUT = _env_bool('TARA_LIVE_MODEL_OUTPUT', False)
ASSET_SELECTION_PATH = os.getenv('TARA_ASSET_SELECTION_PATH', '')
FEASIBILITY_PATHS_PER_CALL = int(
    os.getenv(
        "TARA_FEASIBILITY_PATHS_PER_CALL",
        _model_default("feasibility_paths_per_call", 20),
    )
)
FEASIBILITY_REASON_PATHS_PER_CALL = int(
    os.getenv("TARA_FEASIBILITY_REASON_PATHS_PER_CALL", "12")
)  # 简短理由模式的合批上限；仍按真实 Prompt 长度自动缩小
STAGE_C_CACHE_FLUSH_TASKS = int(
    os.getenv("TARA_STAGE_C_CACHE_FLUSH_TASKS", "250")
)
STAGE_C_CACHE_FLUSH_SECONDS = float(
    os.getenv("TARA_STAGE_C_CACHE_FLUSH_SECONDS", "120")
)
PIPELINE_RECOVERY_ROUNDS = int(
    os.getenv("TARA_PIPELINE_RECOVERY_ROUNDS", "1")
)  # 各阶段内部已局部重试，末尾仅保留一轮恢复
STAGE_C_FINAL_RETRY_MAX_PATHS = int(
    os.getenv("TARA_STAGE_C_FINAL_RETRY_MAX_PATHS", "32")
)  # 整批修复后仍缺失的路径，最多再做这么多次单路径模型补救

# Derive client-side limits once, after all user-facing knobs have been read.
# An explicit environment value always takes precedence, so production runs
# remain reproducible while a fresh deployment adapts to its available GPU.
from automotive_tara.adaptive_runtime import (  # noqa: E402
    apply_unset_defaults,
    derive_runtime_profile,
)

RUNTIME_PROFILE = derive_runtime_profile(
    MODEL_NAME,
    gpu_memory_gb=GPU_MEMORY_GB if GPU_MEMORY_GB > 0 else None,
    quantization=MODEL_QUANTIZATION,
    probe_gpu=not REMOTE_API,
)
if ADAPTIVE_SCHEDULING:
    _adaptive_values = apply_unset_defaults(RUNTIME_PROFILE)
    MAX_CONCURRENT_LLM = int(_adaptive_values.get("MAX_CONCURRENT_LLM", MAX_CONCURRENT_LLM))
    STAGE_C_MAX_CONCURRENT_LLM = int(_adaptive_values.get("STAGE_C_MAX_CONCURRENT_LLM", STAGE_C_MAX_CONCURRENT_LLM))
    BATCH_SIZE_DST = int(_adaptive_values.get("BATCH_SIZE_DST", BATCH_SIZE_DST))
    BATCH_SIZE_IMPACT = int(_adaptive_values.get("BATCH_SIZE_IMPACT", BATCH_SIZE_IMPACT))
    FEASIBILITY_PATHS_PER_CALL = int(_adaptive_values.get("FEASIBILITY_PATHS_PER_CALL", FEASIBILITY_PATHS_PER_CALL))
    # ATTACK_PATH_WORKERS is declared before the profile is derived because
    # its historical default references MAX_CONCURRENT_LLM.  Rebind it after
    # adaptation unless the operator explicitly supplied a worker limit;
    # otherwise a low-memory profile could still create a 16-worker path pool.
    if "TARA_ATTACK_PATH_WORKERS" not in os.environ:
        ATTACK_PATH_WORKERS = MAX_CONCURRENT_LLM
RUNTIME_PROFILE["applied_defaults"] = {
    key: value for key, value in (_adaptive_values.items() if ADAPTIVE_SCHEDULING else [])
}

# The bundled shared service admits up to eight report calls across processes.
# Keep displayed/per-stage limits consistent with that application quota.
from urllib.parse import urlsplit as _urlsplit
if (_urlsplit(API_BASE).hostname or '').lower() in {'127.0.0.1','localhost','::1'}:
    MAX_CONCURRENT_LLM = min(8, MAX_CONCURRENT_LLM)
    STAGE_C_MAX_CONCURRENT_LLM = min(8, STAGE_C_MAX_CONCURRENT_LLM)
    if 'TARA_ATTACK_PATH_WORKERS' not in os.environ:
        ATTACK_PATH_WORKERS = MAX_CONCURRENT_LLM

# ──── 评级方法 ─────────────────────────────────────────────────────────
# 可行性: "attack_potential" | "attack_vector" | "cvss" | "heavens"
FEASIBILITY_METHOD  = os.getenv("TARA_FEASIBILITY_METHOD", "attack_potential").strip().lower()
# 影响:   "21434" (取最大,4级) | "heavens" (加权求和,5级) | "heavens_4level" (加权求和,4级)
IMPACT_METHOD       = os.getenv("TARA_IMPACT_METHOD",      "21434").strip().lower()
# ──── Self-Consistency (SC) 一致性校准 ─────────────────────────────────
SC_ENABLED              = os.getenv("TARA_SC_ENABLED",              "0").strip() not in {"0", "false", "False"}
SC_SAMPLES              = int(os.getenv("TARA_SC_SAMPLES",           "10"))    # 每个任务采样次数
SC_CONFIDENCE_THRESHOLD = float(os.getenv("TARA_SC_CONFIDENCE_THRESHOLD", "0.8"))
SC_SINGLE_CALL          = os.getenv("TARA_SC_SINGLE_CALL",          "0").strip() not in {"0", "false", "False"}

# ──── 评级输出开关 ─────────────────────────────────────────────────────
ENABLE_REASON      = _env_bool("TARA_ENABLE_REASON", True)  # 严格控制影响/可行性评级理由
ENABLE_CONSISTENCY = os.getenv("TARA_ENABLE_CONSISTENCY",  "0").strip() not in {"0", "false", "False"}  # 一致性校验逻辑

# ──── RAG 开关与参数 ──────────────────────────────────────────────────
ENABLE_RAG         = os.getenv("TARA_ENABLE_RAG",  "0").strip() not in {"0", "false", "False"}
ENABLE_R155        = os.getenv("TARA_ENABLE_R155", "0").strip() not in {"0", "false", "False"}
RAG_METHOD         = os.getenv("TARA_RAG_METHOD",  "none").strip().lower()   # "bge-m3" | "none"
RAG_BASE_DIR       = os.getenv("TARA_RAG_BASE_DIR", os.path.join(_PROJECT_ROOT, "data", "rag"))
RAG_DIRS = {
    "tara_reports":     os.path.join(RAG_BASE_DIR, "tara_reports"),
    "attack_databases": os.path.join(RAG_BASE_DIR, "attack_databases"),
}
RAG_TOP_K            = int(os.getenv("TARA_RAG_TOP_K",         "5"))
RAG_MAX_CONTEXT_CHARS = int(os.getenv("TARA_RAG_MAX_CHARS",   "1800"))
BM25_K1              = float(os.getenv("TARA_BM25_K1",         "1.5"))
BM25_B               = float(os.getenv("TARA_BM25_B",          "0.75"))
RRF_K                = int(os.getenv("TARA_RRF_K",             "60"))

# ──── Cross-encoder 重排 ───────────────────────────────────────────────
RERANKER_ENABLED     = os.getenv("TARA_RAG_RERANK", "1").strip() not in {"0", "false", "False"}
RERANKER_MODEL_PATH  = os.getenv("TARA_RERANKER_PATH",
                         os.path.join(_PROJECT_ROOT, "models", "bge-reranker-v2-m3"))
BGE_M3_PATH          = os.getenv("TARA_BGE_M3_PATH",
                         os.path.join(_PROJECT_ROOT, "models", "bge-m3"))
RERANKER_CANDIDATES  = int(os.getenv("TARA_RERANK_CANDIDATES",   "50"))   # BM25 初筛候选数
RERANKER_BATCH_SIZE  = int(os.getenv("TARA_RERANKER_BATCH_SIZE", "16"))

# ──── 向量存储 ─────────────────────────────────────────────────────────
VECTOR_STORE_DIR = os.getenv("TARA_VECTOR_STORE_DIR",
                     os.path.join(RAG_BASE_DIR, "vector_store"))

# ──── 功能清单 (DFD 函数描述) ──────────────────────────────────────────
FUNC_INVENTORY_PATH  = os.getenv("TARA_FUNC_INVENTORY", "")
_ENABLE_FUNC_DESC    = os.getenv("TARA_ENABLE_FUNC_DESC", "1").strip() not in {"0", "false", "False"}

# ──── 运行控制 ─────────────────────────────────────────────────────────
SKIP_CHAT_TEMPLATE   = os.getenv("TARA_SKIP_CHAT_TEMPLATE",   "0").strip() not in {"0", "false", "False"}
SKIP_CHECKPOINT      = os.getenv("TARA_SKIP_CHECKPOINT",      "0").strip() in  {"1", "true", "True"}
TEST_MAX_ASSETS      = int(os.getenv("TARA_TEST_MAX_ASSETS",   "0"))   # 0=全量, >0=测试模式
TEST_ASSET_SELECTION = os.getenv("TARA_TEST_ASSET_SELECTION", "").strip().lower()
VERIFY_MODEL_HASHES  = os.getenv("TARA_VERIFY_MODEL_HASHES",  "1").strip() not in {"0", "false", "False"}
STRICT_INPUTS        = os.getenv("TARA_STRICT_INPUTS",         "1").strip() not in {"0", "false", "False"}
LLM_PREFLIGHT        = os.getenv("TARA_LLM_PREFLIGHT",         "1").strip() not in {"0", "false", "False"}
ENABLE_APPLICABILITY_FILTER = os.getenv(
    "TARA_ENABLE_APPLICABILITY_FILTER", "1"
).strip() not in {"0", "false", "False"}

# ──── 资产细项开关 ────────────────────────────────────────────────────────
# 开：最终报告生成"资产细项"列，且生成损害/威胁场景时把资产细项作为 LLM 输入参考。
# 关：报告中无该列，损害场景生成也不输入资产细项。
ENABLE_ASSET_DETAILS = os.getenv("TARA_ENABLE_ASSET_DETAILS", "1").strip() not in {
    "0", "false", "False"
}

# ──── 训练数据旁路采集 ─────────────────────────────────────────────────
# 默认关闭；开启后仅记录已有调用和最终采用结果，不增加任何 LLM 请求。
CAPTURE_TRAINING = _env_bool("TARA_CAPTURE_TRAINING", False)
CAPTURE_REJECTED = _env_bool("TARA_CAPTURE_REJECTED", False)
if CAPTURE_REJECTED:
    CAPTURE_TRAINING = True

if RAG_METHOD == "none":
    ENABLE_RAG = False
if TEST_MAX_ASSETS <= 0:
    TEST_MAX_ASSETS = None
if TEST_ASSET_SELECTION not in {"", "per_dfd_type"}:
    raise ValueError(
        "TARA_TEST_ASSET_SELECTION 仅支持 per_dfd_type 或空值，"
        f"当前为 {TEST_ASSET_SELECTION!r}"
    )
