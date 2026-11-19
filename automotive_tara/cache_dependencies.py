"""Content-addressed dependencies for incremental analysis, independent of prose.

Generated results carry their producing node's identity. Downstream nodes use
that identity, while an output checksum detects external/manual edits. Legacy
results without provenance conservatively retain exact-content invalidation.
"""

from __future__ import annotations

import re
import hashlib
from functools import lru_cache
from pathlib import Path
from typing import Any

from .analysis_cache import digest_json
from .domain import TaskUnit


def _shared(ctx, name: str, default=None):
    return getattr(ctx, "shared", lambda _name, fallback=None: fallback)(name, default)


def asset_evidence(ctx, task: TaskUnit) -> dict:
    names = (
        "function", "asset_name", "asset_type", "attribute_name", "threat_type",
        "source", "target", "source_element_id", "target_element_id", "flow_protocol",
        "source_is_external", "target_is_external", "source_is_external_interface",
        "target_is_external_interface", "source_is_external_component",
        "target_is_external_component", "asset_is_external", "asset_is_external_interface",
        "asset_is_external_component", "critical_component", "operating_system",
        "signal_category", "data_type", "dfd_element_type",
    )
    evidence = {name: getattr(task, name) for name in names}
    evidence["element"] = task.element_id or task.element_index
    evidence["project"] = task.cache_dependencies.get("project", "")
    if ctx.setting("ENABLE_ASSET_DETAILS", True):
        evidence["asset_details"] = task.asset_details
    evidence["function_description"] = (_shared(ctx, "_FUNCTION_DESC_MAP", {}) or {}).get(task.function, "")
    return evidence


def knowledge_entries(context: str) -> list[dict]:
    """Treat each retrieved source snippet as a versioned knowledge entry.

    Retrieval order, line wrapping and duplicate snippets are presentation;
    source and actual snippet content are evidence. No fuzzy text matching.
    """
    entries = {}
    for block in re.split(r"\n\s*---\s*\n", str(context or "")):
        block = block.strip()
        if not block or block in {"[RAG已关闭]", "[RAG为空]", "[RAG未命中]"}:
            continue
        source = re.match(r"\[来源:([^\]]*)\]\s*", block)
        name = source.group(1) if source else ""
        body = block[source.end():] if source else block
        version = digest_json(re.sub(r"\s+", " ", body).strip())
        entry = {"source": name, "content_sha256": version}
        entries[digest_json(entry)] = entry
    return [entries[key] for key in sorted(entries)]


def framework_evidence(framework: dict) -> dict:
    # IDs used only to correlate a model response must not identify a route.
    return {key: value for key, value in framework.items()
            if key not in {"path_id", "task_id", "framework_id", "framework_set"}}


def route_reference(framework: dict) -> str:
    return digest_json(framework_evidence(framework))


@lru_cache(maxsize=12)
def implementation_signature(stage: str) -> str:
    root = Path(__file__).parent
    stage_module = {'scenarios': 'dst', 'attack_paths': 'attack_path', 'target_action': 'attack_path'}.get(stage, stage)
    paths = [Path(__file__), root / 'domain.py', root / 'stages' / f'{stage_module}.py']
    if stage == 'impact':
        paths.append(root / 'impact_format.py')
    if stage in {'attack_path', 'attack_paths', 'target_action'}:
        paths.append(root / 'topology.py')
    if stage == 'security_requirements':
        paths.append(root / 'security_requirements.py')
    return digest_json([(path.name, hashlib.sha256(path.read_bytes()).hexdigest())
                        for path in paths if path.is_file()])


def stage_key(ctx, task: TaskUnit, stage: str, prompt: str, *, parents=None,
              frameworks=(), knowledge=None, settings=None) -> dict:
    model = ctx.setting("IMPACT_MODEL_NAME") if stage == "impact" else None
    model = model or ctx.setting("MODEL_NAME")
    policy = {name: ctx.setting(name) for name in (
        "TEMPERATURE", "SAMPLING_SEED", "TOP_P", "TOP_K", "FREQUENCY_PENALTY",
        "PRESENCE_PENALTY", "ENABLE_REASON", "ENABLE_CONSISTENCY", "SC_ENABLED", "SC_SAMPLES",
    )}
    policy.update(settings or {})
    return {
        "schema": "tara-dependency-node-v1", "stage": stage, "model": model,
        "model_revision": (_shared(ctx, "_cache_model_revisions", {}) or {}).get(model, ""),
        "deployment_revision": (_shared(ctx, "_model_deployment_revisions", {}) or {}).get(model, ""),
        "implementation": implementation_signature(stage),
        "prompt_sha256": digest_json(prompt), "policy": policy,
        "dependencies": {
            "asset": digest_json(asset_evidence(ctx, task)),
            "parents": parents or {},
            "topology": sorted({route_reference(framework) for framework in frameworks}),
            "knowledge": knowledge or {},
        },
    }


def record_result(task: TaskUnit, stage: str, key: dict, output: Any) -> None:
    task.cache_dependencies[stage] = {
        "fingerprint": digest_json(key), "key": key,
        "output_sha256": digest_json(output),
    }


def result_reference(task: TaskUnit, stage: str, output: Any) -> str:
    record = task.cache_dependencies.get(stage, {})
    if (isinstance(record, dict) and record.get("fingerprint")
            and isinstance(record.get('key'), dict)
            and record.get("output_sha256") == digest_json(output)
            and record.get("fingerprint") == digest_json(record.get("key"))):
        parents = record['key'].get('dependencies', {}).get('parents', {})
        if stage != 'scenarios' and 'scenarios' in parents and parents['scenarios'] != scenario_reference(task):
            return digest_json({'changed_upstream': scenario_reference(task),
                                'previous_result': record['fingerprint'], 'output': digest_json(output)})
        return record["fingerprint"]
    # Untracked checkpoint, manual edit, or missing generation provenance:
    # never infer that a different attack is merely a wording change.
    return digest_json({"untracked_or_edited_output": output})


def scenario_output(task: TaskUnit) -> dict:
    return {"damage_scenario": task.damage_scenario, "threat_scenarios": task.threat_scenarios}


def scenario_reference(task: TaskUnit) -> str:
    return result_reference(task, "scenarios", scenario_output(task))


def path_stage(framework: dict) -> str:
    return "attack_path:" + route_reference(framework)


def path_reference(task: TaskUnit, index: int, text: str) -> str:
    if 0 <= index < len(task.selected_path_frameworks):
        return result_reference(task, path_stage(task.selected_path_frameworks[index]), text)
    return digest_json({"untracked_or_edited_output": text})
