"""Export text-trained Qwen3.5 adapters for a multimodal vLLM wrapper.

PEFT CausalLM training uses model.layers.*, while the full multimodal runtime
expects model.language_model.layers.* in its HF-to-vLLM mapping. Export copies
only rename tensor keys; original training checkpoints and values stay intact.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path

TEXT_PREFIX = "base_model.model.model.layers."
MULTIMODAL_PREFIX = "base_model.model.model.language_model.layers."
SUPPORTED_MODELS = {"qwen3_5", "qwen3_5_moe"}
EXPORT_VERSION = "qwen35-text-to-multimodal-lora-v1"


def file_sha256(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024*1024), b""):
            result.update(block)
    return result.hexdigest()


def runtime_key(name: str) -> str:
    if name.startswith(TEXT_PREFIX):
        return MULTIMODAL_PREFIX + name[len(TEXT_PREFIX):]
    return name


def adapter_revision(root: str) -> str | None:
    """Fingerprint a locally advertised LoRA without hashing base-model shards."""
    if not root:
        return None
    folder = Path(root)
    if not folder.is_absolute():
        return None
    weights, config = folder / "adapter_model.safetensors", folder / "adapter_config.json"
    if not weights.is_file() or not config.is_file():
        return None
    return hashlib.sha256((file_sha256(config)+file_sha256(weights)).encode()).hexdigest()


def prepare_vllm_adapter(adapter: Path, runtime_model: Path, output_root: Path | None = None) -> Path:
    """Return a content-addressed deployment copy when namespace conversion is needed."""
    from safetensors import safe_open
    from safetensors.torch import load_file, save_file

    adapter, runtime_model = adapter.resolve(), runtime_model.resolve()
    config_path, weights_path = adapter / "adapter_config.json", adapter / "adapter_model.safetensors"
    runtime_config_path = runtime_model / "config.json"
    runtime_config = json.loads(runtime_config_path.read_text())
    if runtime_config.get("model_type") not in SUPPORTED_MODELS or not any(
        str(a).endswith("ForConditionalGeneration") for a in runtime_config.get("architectures", [])
    ):
        return adapter
    with safe_open(weights_path, framework="pt", device="cpu") as weights:
        names, metadata = list(weights.keys()), weights.metadata()
    flat_names = [name for name in names if name.startswith(TEXT_PREFIX)]
    if not flat_names:
        return adapter
    if any(name.startswith(MULTIMODAL_PREFIX) for name in names):
        raise ValueError("Mixed text/multimodal adapter namespaces; refuse ambiguous export")
    # This conversion covers language decoder adapters only. Do not guess how
    # to migrate visual towers or arbitrary embedding/head modifications.
    if len(flat_names) != len(names):
        raise ValueError("Text adapter contains tensors outside decoder layers; explicit export mapping is required")
    adapter_config = json.loads(config_path.read_text())
    source_model = Path(adapter_config["base_model_name_or_path"])
    source_config = json.loads((source_model / "config.json").read_text())
    source_text, runtime_text = source_config.get("text_config", source_config), runtime_config.get("text_config", runtime_config)
    for key in ("hidden_size", "num_hidden_layers", "num_attention_heads", "num_key_value_heads", "num_experts"):
        if source_text.get(key) != runtime_text.get(key):
            raise ValueError(f"Incompatible adapter/runtime architecture: {key}")
    contract = {
        "version": EXPORT_VERSION,
        "source_adapter": str(adapter),
        "source_config_sha256": file_sha256(config_path),
        "source_weights_sha256": file_sha256(weights_path),
        "runtime_config_sha256": file_sha256(runtime_config_path),
        "renamed_tensors": len(flat_names),
        "source_prefix": TEXT_PREFIX,
        "export_prefix": MULTIMODAL_PREFIX,
    }
    signature = hashlib.sha256(json.dumps(contract, sort_keys=True).encode()).hexdigest()
    root = (output_root or Path(__file__).resolve().parents[1] / "outputs/vllm/lora_exports").resolve()
    root.mkdir(parents=True, exist_ok=True)
    target = root / f"{adapter.parent.name}-{signature[:16]}"
    with (root / "export.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        manifest_path = target / "export_manifest.json"
        if manifest_path.is_file():
            saved = json.loads(manifest_path.read_text())
            if saved["contract"] != contract or file_sha256(target / "adapter_model.safetensors") != saved["export_weights_sha256"]:
                raise ValueError(f"Existing deployment export failed integrity checks: {target}")
            return target
        if target.exists():
            raise FileExistsError(f"Incomplete export directory; preserve and inspect it: {target}")
        temporary = Path(tempfile.mkdtemp(prefix=".lora-export-", dir=root))
        try:
            tensors = load_file(weights_path, device="cpu")
            exported = {runtime_key(name): value for name, value in tensors.items()}
            if len(exported) != len(tensors):
                raise ValueError("Tensor key collision during namespace export")
            save_file(exported, temporary / "adapter_model.safetensors", metadata=metadata)
            shutil.copy2(config_path, temporary / "adapter_config.json")
            manifest = {"contract": contract, "export_weights_sha256": file_sha256(temporary / "adapter_model.safetensors"), "numerical_changes": False, "usage": "vLLM deployment only; resume training from the original adapter/checkpoint"}
            (temporary / "export_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2)+"\n")
            os.rename(temporary, target)
        finally:
            if temporary.exists(): shutil.rmtree(temporary)
    return target
