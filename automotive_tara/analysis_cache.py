"""Stable analysis identities and verified snapshots of completed reports."""

from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import logging
import os
import shutil
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlsplit, urlunsplit

from automotive_tara.storage import atomic_write_bytes

logger = logging.getLogger(__name__)


def digest_json(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def file_digest(path: str | Path) -> str:
    source = Path(path)
    if not source.is_file():
        return ""
    if source.suffix.casefold() == ".json":
        try:
            return digest_json(json.loads(source.read_text(encoding="utf-8-sig")))
        except (ValueError, UnicodeError):
            pass
    digest = hashlib.sha256()
    with source.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def input_fingerprints(dfd: str, topology: str, interfaces: str) -> dict[str, Any]:
    source = Path(dfd)
    # DFD stems can supply function names, so retain those logical names.
    files = sorted(source.glob("*.json")) if source.is_dir() else [source]
    return {
        "dfd": [(file.name, file_digest(file)) for file in files],
        "topology": file_digest(topology),
        "interfaces": file_digest(interfaces),
    }


def model_identities(api_base: str, models: list[str], project_root: Path) -> dict[str, dict]:
    parsed = urlsplit(api_base.rstrip("/"))
    # Keep provider identity without persisting URL credentials or query secrets.
    host = parsed.hostname or ""
    netloc = host + (f":{parsed.port}" if parsed.port else "")
    local = host.casefold() in {"localhost", "127.0.0.1", "::1"}
    provider = (
        f"local://{parsed.port or 80}{parsed.path.rstrip('/')}"
        if local else urlunsplit((parsed.scheme, netloc, parsed.path.rstrip("/"), "", ""))
    )
    state: dict = {}
    if local:
        try:
            state = json.loads((project_root / "outputs/vllm/current.json").read_text(encoding="utf-8"))
            if not isinstance(state, dict):
                state = {}
        except (OSError, ValueError):
            pass
    result = {}
    for model in dict.fromkeys(models):
        identity: dict[str, Any] = {"provider": provider, "model": model}
        if not local:
            identity["access_partition"] = hashlib.sha256(os.getenv("TARA_API_KEY", "EMPTY").encode("utf-8")).hexdigest()
        directory = None
        if local:
            if model == state.get("lora_name"):
                directory = state.get("lora_path")
            elif model == state.get("served_name"):
                directory = state.get("model_path")
            candidate = Path(directory) if directory else Path(os.getenv("TARA_MODEL_ROOT", "models")) / model
            if candidate.is_dir():
                files = []
                for path in sorted(candidate.rglob("*")):
                    if path.is_file() and path.suffix in {".json", ".safetensors", ".bin", ".model", ".jinja"}:
                        stat = path.stat()
                        # Weight size/mtime detect deployed revisions without rereading tens of GB.
                        files.append((path.relative_to(candidate).as_posix(), stat.st_size,
                                      stat.st_mtime_ns, file_digest(path) if path.suffix in {".json", ".jinja"} else ""))
                identity["files"] = files
        identity["deployment_revision"] = os.getenv("TARA_MODEL_CACHE_REVISION", "")
        result[model] = identity
    return result


def analysis_source_signature(project_root: Path) -> str:
    """UI-only changes should not invalidate completed analytical results."""
    ignored = {"report_editor_agent.py", "data_editor_agent.py", "analysis_assistant.py", "assistant_runtime.py",
               "assistant_actions.py", "assistant_repository.py", "assistant_report.py", "assistant_context.py", "assistant_entry.py", "assistant_history.py", "request_admission.py",
               "live_model_output.py", "api_service.py", "cli.py"}
    paths = [project_root / "tara.py", *sorted((project_root / "automotive_tara").rglob("*.py"))]
    return digest_json([
        (path.relative_to(project_root).as_posix(), file_digest(path))
        for path in paths if path.is_file() and not path.name.startswith("demo") and path.name not in ignored
    ])


_OPERATIONAL_SETTINGS = {
    "TARA_OUTPUT_DIR", "TARA_CHECKPOINT_DIR", "TARA_SHARED_CACHE_DIR",
    "TARA_DFD_FILE", "TARA_TOPOLOGY_FILE", "TARA_EXTERNAL_INTERFACE_EXCEL",
    "TARA_API_BASE", "TARA_API_KEY", "TARA_API_KEY_CONFIGURED", "TARA_SKIP_CHECKPOINT",
    "TARA_REQUEST_TIMEOUT", "TARA_HTTP_KEEPALIVE_IDLE_TTL", "TARA_WALL_CLOCK_TIMEOUT",
    "TARA_MAX_WORKERS", "TARA_MAX_CONCURRENT_LLM", "TARA_ATTACK_PATH_WORKERS",
    "TARA_STAGE_C_MAX_CONCURRENT_LLM", "TARA_VLLM_MAX_NUM_SEQS", "TARA_CALL_INTERVAL",
    "TARA_MAX_PENDING_FUTURES", "TARA_SEMANTIC_CACHE_BUCKET_SIZE",
    "TARA_STAGE_C_CACHE_FLUSH_TASKS", "TARA_STAGE_C_CACHE_FLUSH_SECONDS",
    "TARA_ADAPTIVE_SCHEDULING", "TARA_GPU_MEMORY_GB", "TARA_MODEL_SIZE_B",
    "TARA_MODEL_QUANTIZATION", "TARA_VERIFY_MODEL_HASHES", "TARA_LLM_PREFLIGHT",
    "TARA_CAPTURE_TRAINING", "TARA_CAPTURE_REJECTED", "TARA_REUSE_COMPLETED_RESULTS",
    'TARA_LIVE_MODEL_OUTPUT', 'TARA_ASSET_SELECTION_PATH',
    'TARA_SERVICE_CONTEXT_TOKENS',
    # Scheduling boundaries are intentionally independent of analytical identity.
    "TARA_BATCH_DST", "TARA_BATCH_IMPACT", "TARA_BATCH_SIZE_ATTACK",
    "TARA_ATTACK_PATHS_PER_CALL", "TARA_DIRECT_ATTACK_PATHS_PER_CALL",
    "TARA_FEASIBILITY_PATHS_PER_CALL", "TARA_FEASIBILITY_REASON_PATHS_PER_CALL",
    # Dependency content is fingerprinted separately, instead of its directory.
    "TARA_R155_ANNEX5_PATH", "TARA_RAG_BASE_DIR", "TARA_RERANKER_PATH",
    "TARA_BGE_M3_PATH", "TARA_VECTOR_STORE_DIR", "TARA_SECURITY_REQUIREMENTS_PATH",
    "TARA_FUNC_INVENTORY",
}


def result_identity(*, inputs: dict, effective: dict, scope: dict, models: dict,
                    dependencies: dict, source_signature: str, project_name: str) -> dict:
    return {
        "schema": "tara-completed-analysis-v1",
        "project": project_name,
        "inputs": inputs,
        "settings": {key: value for key, value in effective.items() if key not in _OPERATIONAL_SETTINGS},
        "scope": scope,
        "models": models,
        "dependencies": dependencies,
        "analysis_source_sha256": source_signature,
    }


class CompletedAnalysisCache:
    ARTIFACTS = ("json", "errors_json", "xlsx", "baseline_json", "baseline_xlsx", "dfd_relationships_json")

    def __init__(self, shared_root: str | Path):
        self.root = Path(shared_root) / "completed_analyses"

    @contextmanager
    def lock(self, key: str) -> Iterator[None]:
        directory = self.root / ".locks"
        directory.mkdir(parents=True, exist_ok=True)
        with (directory / f"{key}.lock").open("a+b") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def read(self, key: str) -> dict | None:
        directory = self.root / key
        try:
            snapshot = json.loads((directory / "snapshot.json").read_text(encoding="utf-8"))
            if snapshot.get("key") != key or snapshot.get("schema") != 1:
                return None
            if not isinstance(snapshot.get("manifest"), dict) or not isinstance(snapshot.get("artifacts"), dict):
                return None
            artifacts = snapshot["artifacts"]
            if not all(role in artifacts for role in ("json", "errors_json", "xlsx")):
                return None
            for role, record in artifacts.items():
                if role not in self.ARTIFACTS or Path(record["file"]).name != record["file"]:
                    return None
                path = directory / record["file"]
                # Verify raw bytes, preserving identical JSON and Excel artifacts on replay.
                if hashlib.sha256(path.read_bytes()).hexdigest() != record["sha256"]:
                    return None
            return snapshot
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def restore(self, key: str, destinations: dict[str, str | None]) -> dict | None:
        snapshot = self.read(key)
        if snapshot is None:
            return None
        artifacts = snapshot["artifacts"]
        if any(destinations.get(role) and role not in artifacts for role in ("json", "xlsx", "baseline_json", "baseline_xlsx")):
            return None
        for role, record in artifacts.items():
            destination = destinations.get(role)
            if destination:
                atomic_write_bytes(destination, (self.root / key / record["file"]).read_bytes())
        return copy.deepcopy(snapshot)

    def publish(self, key: str, identity: dict, manifest: dict) -> bool:
        statuses = manifest.get("counts", {}).get("statuses", {})
        if not statuses or any(count and status not in {"VALID", "NOT_APPLICABLE"} for status, count in statuses.items()):
            return False
        outputs = manifest.get("outputs", {})
        if any(not outputs.get(role) or not Path(outputs[role]).is_file() for role in ("json", "errors_json", "xlsx")):
            return False
        if json.loads(Path(outputs["errors_json"]).read_text(encoding="utf-8")):
            return False
        if self.read(key) is not None:
            return False
        self.root.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=f".{key}.", dir=self.root))
        try:
            artifacts = {}
            for role in self.ARTIFACTS:
                raw = outputs.get(role)
                if not raw:
                    continue
                source = Path(raw)
                if not source.is_file():
                    return False
                filename = role + source.suffix
                data = source.read_bytes()
                atomic_write_bytes(str(staging / filename), data)
                artifacts[role] = {"file": filename, "sha256": hashlib.sha256(data).hexdigest()}
            snapshot = {"schema": 1, "key": key, "identity": identity, "manifest": manifest,
                        "created_at": datetime.now(timezone.utc).isoformat(), "artifacts": artifacts}
            atomic_write_bytes(str(staging / "snapshot.json"), json.dumps(snapshot, ensure_ascii=False, default=str).encode("utf-8"))
            destination = self.root / key
            if destination.exists():
                shutil.rmtree(destination)
            os.replace(staging, destination)
            return True
        finally:
            if staging.exists():
                shutil.rmtree(staging)
