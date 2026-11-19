"""Small, dependency-free runtime profile for heterogeneous LLM servers.

The pipeline must remain usable on a CPU-only development machine and on a
single A100 without importing torch or probing a model at import time.  This
module therefore uses explicit environment overrides first, then a bounded
``nvidia-smi`` probe, and finally conservative defaults.  It never changes
server-side vLLM settings; it only supplies client scheduling defaults.
"""

from __future__ import annotations

import os
import re
import subprocess
from typing import Any


def _float_env(name: str) -> float:
    try:
        return max(0.0, float(os.getenv(name, "0") or 0))
    except (TypeError, ValueError):
        return 0.0


def detect_gpu_memory_gb() -> float:
    """Return total GPU memory when available, otherwise ``0``.

    A one-second subprocess timeout keeps configuration import cheap and the
    probe is intentionally best-effort.  ``TARA_GPU_MEMORY_GB`` is useful in
    containers where nvidia-smi is not mounted.
    """
    explicit = _float_env("TARA_GPU_MEMORY_GB")
    if explicit > 0:
        return explicit
    try:
        output = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=memory.total", "--format=csv,noheader,nounits"],
            stderr=subprocess.DEVNULL,
            timeout=1.0,
            text=True,
        )
        values = [float(item.strip()) / 1024.0 for item in output.splitlines() if item.strip()]
        return max(values, default=0.0)
    except (OSError, subprocess.SubprocessError, ValueError):
        return 0.0


def infer_model_size_b(model_name: str) -> float:
    explicit = _float_env("TARA_MODEL_SIZE_B")
    if explicit > 0:
        return explicit
    match = re.search(r"(?<!\d)(\d+(?:\.\d+)?)\s*b(?:illion)?(?!\w)", model_name or "", re.I)
    if match:
        try:
            return float(match.group(1))
        except ValueError:
            pass
    return 0.0


def derive_runtime_profile(
    model_name: str,
    *,
    gpu_memory_gb: float | None = None,
    quantization: str = "",
    probe_gpu: bool = True,
) -> dict[str, Any]:
    """Derive safe client limits from coarse model/GPU classes.

    Explicit ``TARA_MAX_CONCURRENT_LLM``, ``TARA_BATCH_*`` and
    ``TARA_FEASIBILITY_PATHS_PER_CALL`` values are never overridden by callers.
    The 80GB + AWQ tiers are validated production profiles: Qwen3.8-27B-AWQ
    uses 48/48 with batch 8, while Qwen3.6-35B-A3B-AWQ uses 48/32 with batch
    12 and 24 paths. Smaller or unknown environments remain conservative. Set
    ``probe_gpu=False`` for a remote API so local ``nvidia-smi`` is not used.
    """
    # A remote OpenAI-compatible endpoint cannot expose its GPU memory through
    # the local ``nvidia-smi`` probe.  Callers set ``probe_gpu=False`` for such
    # endpoints so that an A100 in the client machine is not mistaken for the
    # server's capacity.  Explicit ``gpu_memory_gb`` always wins.
    memory = float(
        gpu_memory_gb
        if gpu_memory_gb is not None
        else (detect_gpu_memory_gb() if probe_gpu else 0.0)
    )
    size = infer_model_size_b(model_name)
    quantized = any(
        token in f"{model_name or ''} {quantization or ''}".lower()
        for token in ("awq", "gptq", "4bit", "int4")
    )
    if memory <= 0:
        limits = {"max_concurrent_llm": 16, "stage_c_max_concurrent_llm": 16, "batch_dst": 8, "batch_impact": 8, "feasibility_paths_per_call": 20, "context_tokens": 4096}
        tier = "unknown"
    elif memory < 24:
        limits = {"max_concurrent_llm": 4, "stage_c_max_concurrent_llm": 4, "batch_dst": 4, "batch_impact": 4, "feasibility_paths_per_call": 8, "context_tokens": 3072}
        tier = "<24GB"
    elif memory < 48:
        limits = {"max_concurrent_llm": 8, "stage_c_max_concurrent_llm": 8, "batch_dst": 6, "batch_impact": 6, "feasibility_paths_per_call": 12, "context_tokens": 4096}
        tier = "24-48GB"
    elif memory >= 80 and quantized and size >= 30:
        # Current production target: Qwen3.6-35B-A3B-AWQ on one A100 80GB.
        # Stage C stays below the global semaphore because its prompts are
        # substantially longer than DST/Impact prompts.
        limits = {"max_concurrent_llm": 48, "stage_c_max_concurrent_llm": 32, "batch_dst": 12, "batch_impact": 12, "feasibility_paths_per_call": 24, "context_tokens": 8192}
        tier = ">=80GB-35B-quantized"
    elif memory >= 80 and quantized:
        # Qwen3.8-27B-AWQ has shorter requests and the validated Stage C
        # ceiling is the same as the global client semaphore.
        limits = {"max_concurrent_llm": 48, "stage_c_max_concurrent_llm": 48, "batch_dst": 8, "batch_impact": 8, "feasibility_paths_per_call": 24, "context_tokens": 8192}
        tier = ">=80GB-27B-quantized"
    elif memory >= 64 and quantized:
        limits = {"max_concurrent_llm": 32, "stage_c_max_concurrent_llm": 24, "batch_dst": 10, "batch_impact": 10, "feasibility_paths_per_call": 20, "context_tokens": 8192}
        tier = "64-80GB-quantized"
    else:
        limits = {"max_concurrent_llm": 16, "stage_c_max_concurrent_llm": 16, "batch_dst": 8, "batch_impact": 8, "feasibility_paths_per_call": 20, "context_tokens": 8192}
        tier = ">=48GB"
    # Large unquantized models need a little more headroom per request.  AWQ
    # models can keep the normal batch because their KV footprint is smaller.
    if size >= 30 and not quantized and memory < 80:
        limits["feasibility_paths_per_call"] = min(limits["feasibility_paths_per_call"], 12)
    return {
        "enabled": True,
        "tier": tier,
        "gpu_memory_gb": round(memory, 2),
        "model_size_b": size,
        "quantized": quantized,
        "limits": limits,
        "source": (
            "env"
            if _float_env("TARA_GPU_MEMORY_GB") > 0
            else ("nvidia-smi/bounded-default" if probe_gpu else "remote-api-unknown")
        ),
    }


def apply_unset_defaults(profile: dict[str, Any]) -> dict[str, Any]:
    """Apply only unset environment defaults and return the applied values."""
    limits = profile.get("limits", {}) if isinstance(profile, dict) else {}
    mapping = {
        "TARA_MAX_CONCURRENT_LLM": ("max_concurrent_llm", "MAX_CONCURRENT_LLM"),
        "TARA_STAGE_C_MAX_CONCURRENT_LLM": ("stage_c_max_concurrent_llm", "STAGE_C_MAX_CONCURRENT_LLM"),
        "TARA_BATCH_DST": ("batch_dst", "BATCH_SIZE_DST"),
        "TARA_BATCH_IMPACT": ("batch_impact", "BATCH_SIZE_IMPACT"),
        "TARA_FEASIBILITY_PATHS_PER_CALL": ("feasibility_paths_per_call", "FEASIBILITY_PATHS_PER_CALL"),
        "TARA_TASK_CONTEXT_TOKENS": ("context_tokens", "MODEL_CONTEXT_TOKENS"),
    }
    applied: dict[str, Any] = {}
    for env_name, (profile_name, setting_name) in mapping.items():
        if env_name in os.environ or profile_name not in limits:
            continue
        applied[setting_name] = limits[profile_name]
    return applied
