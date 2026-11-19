"""Configuration and bundled history for the standalone Demo distribution."""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from automotive_tara.http_client import normalize_api_base

API_REQUIRED = "请在服务端设置 TARA_API_BASE、TARA_MODEL 和 TARA_API_KEY，然后重启工作台。"
CASE_ID = "archive-full-assets"


def configured_api() -> tuple[str, str, str] | None:
    base, key, model = (os.getenv(name, "").strip() for name in ("TARA_API_BASE", "TARA_API_KEY", "TARA_MODEL"))
    if not base or not key or not model:
        return None
    return normalize_api_base(base), key, model


def require_api() -> tuple[str, str, str]:
    config = configured_api()
    if config is None:
        raise ValueError(API_REQUIRED)
    return config


def install_history(source: Path, jobs: Path, queue: Path) -> None:
    from automotive_tara import demo_jobs

    meta = json.loads((source / "summary.json").read_text(encoding="utf-8"))
    job = (jobs / CASE_ID).resolve()
    run = job / "result" / "run"
    run.mkdir(parents=True, exist_ok=True)
    report_paths = {}
    for name in ("baseline", "residual"):
        report = run / f"{name}.json"
        workbook = report.with_suffix(".xlsx")
        for artifact in (report, workbook):
            shutil.copyfile(source / artifact.name, artifact)
        report_paths[name] = (str(report), str(workbook))
    timing = "\n".join(f"[计时] {name}: {seconds:.3f}s" for name, seconds in meta["stages"].items())
    log = "历史运行脱敏摘要\n" + timing + "\n"
    (run / "tara_run.log").write_text(log, encoding="utf-8")
    (job / "demo_console.log").write_text(log, encoding="utf-8")
    manifest = {
        "project_name": meta["title"], "finish_time": meta["completed_at"],
        "elapsed_seconds": meta["elapsed_seconds"], "stage_seconds": meta["stages"],
        "counts": {**meta["counts"], "assets_analyzed": meta["counts"]["assets"]},
        "configuration": {"effective": {"TARA_IMPACT_METHOD": "21434", "TARA_FEASIBILITY_METHOD": "attack_potential"}},
        "outputs": {
            "baseline_json": report_paths["baseline"][0], "baseline_xlsx": report_paths["baseline"][1],
            "json": report_paths["residual"][0], "xlsx": report_paths["residual"][1],
            "report_variant": "security_requirements_implemented",
        },
    }
    (run / "run_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
    archive = queue.resolve() / CASE_ID
    archive.mkdir(parents=True, exist_ok=True)
    spec = archive / "job_spec.json"
    spec.write_text(json.dumps({
        "project_name": meta["title"], "model": "历史记录", "impact_method": "21434",
        "feasibility_method": "attack_potential", "enable_reason": False, "api_base": "历史记录",
    }, ensure_ascii=False), encoding="utf-8")
    demo_jobs.register_archive(queue, CASE_ID, spec, meta["completed_at"])
