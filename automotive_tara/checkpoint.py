"""Checkpoint 快照、持久化和兼容性比较。"""

from __future__ import annotations

import copy
import json
import logging
import os
from concurrent.futures import Future, ThreadPoolExecutor
from threading import Lock
from typing import Callable

import orjson

from automotive_tara.domain import TaskUnit, task_from_dict, task_to_dict
from automotive_tara.storage import save_json

logger = logging.getLogger(__name__)

CHECKPOINT_FILES = {
    "stage_A_gen": "tasks_after_stageA.json",
    "stage_B_impact": "tasks_after_stageB.json",
    "stage_AB": "tasks_after_stageAB.json",
    "stage_C_attack": "tasks_after_stageC.json",
    "stage_dst": "tasks_after_stageDST.json",
}

REQUIRED_META_KEYS = (
    "checkpoint_version", "method", "impact_method", "total_tasks",
    "enable_rag", "enable_r155", "rag_top_k", "enable_reason",
    "enable_consistency", "enable_applicability_filter",
    "sc_enabled", "sc_samples", "model",
    "batch_dst", "batch_impact", "attack_paths_per_call",
    "impact_repair_max_depth", "pipeline_recovery_rounds",
    "stage_c_max_concurrent_llm", "temperature", "max_tokens",
    "model_context_tokens", "dynamic_token_budgets", "dst_max_tokens",
    "attack_component_max_tokens", "impact_max_tokens",
    "feasibility_max_tokens", "feasibility_paths_per_call",
    "feasibility_reason_paths_per_call",
    "topology_paths_per_pair", "input_signature", "prompt_signature",
    "source_signature",
)


def checkpoint_path(directory: str, stage: str) -> str:
    return os.path.join(directory, CHECKPOINT_FILES[stage])


def snapshot_tasks(tasks: list[TaskUnit], stage: str) -> list[dict]:
    """DST 屏障只复制已稳定字段，避免与后续并行写回发生竞态。"""
    if stage != "stage_dst":
        return copy.deepcopy([task_to_dict(task) for task in tasks])
    snapshots: list[dict] = []
    for task in tasks:
        stable = TaskUnit(
            task_id=task.task_id,
            function=task.function,
            asset_name=task.asset_name,
            asset_type=task.asset_type,
            attribute_name=task.attribute_name,
            threat_type=task.threat_type,
            target=task.target,
            source=task.source,
            asset_details=task.asset_details,
            critical_component=task.critical_component,
            operating_system=task.operating_system,
            signal_category=task.signal_category,
            data_type=task.data_type,
            element_id=task.element_id,
            element_index=task.element_index,
            dfd_element_type=task.dfd_element_type,
            source_element_id=task.source_element_id,
            target_element_id=task.target_element_id,
            flow_protocol=task.flow_protocol,
            source_is_external=task.source_is_external,
            target_is_external=task.target_is_external,
            source_is_external_interface=task.source_is_external_interface,
            target_is_external_interface=task.target_is_external_interface,
            source_is_external_component=task.source_is_external_component,
            target_is_external_component=task.target_is_external_component,
            asset_is_external=task.asset_is_external,
            asset_is_external_interface=task.asset_is_external_interface,
            asset_is_external_component=task.asset_is_external_component,
            source_external_interfaces=list(task.source_external_interfaces),
            input_mapping_conflicts=list(task.input_mapping_conflicts),
            damage_scenario=task.damage_scenario,
            threat_scenarios=task.threat_scenarios,
            r155_references=list(task.r155_references),
            analysis_status=task.analysis_status,
            status_reasons=list(task.status_reasons),
            risk_value=task.risk_value,
            risk_treatment=task.risk_treatment,
            errors=list(task.errors),
            cache_dependencies=copy.deepcopy({
                key: value for key, value in task.cache_dependencies.items()
                if key in {"project", "scenarios"}
            }),
        )
        snapshots.append(task_to_dict(stable))
    return snapshots


def write_checkpoint(
    directory: str,
    stage: str,
    metadata: dict,
    tasks_snapshot: list[dict],
) -> str:
    path = checkpoint_path(directory, stage)
    save_json({"meta": metadata, "tasks": tasks_snapshot}, path)
    logger.info(
        "[Checkpoint] %s 已保存 -> %s (%d 个任务)",
        stage, path, len(tasks_snapshot),
    )
    return path


def save_checkpoint(
    directory: str,
    tasks: list[TaskUnit],
    stage: str,
    metadata: dict,
) -> str:
    os.makedirs(directory, exist_ok=True)
    return write_checkpoint(
        directory, stage, metadata, snapshot_tasks(tasks, stage)
    )


def save_checkpoint_async(
    directory: str,
    tasks: list[TaskUnit],
    stage: str,
    metadata: dict,
    *,
    executor: ThreadPoolExecutor,
    futures: list[Future],
    futures_lock: Lock,
) -> None:
    os.makedirs(directory, exist_ok=True)
    tasks_snapshot = snapshot_tasks(tasks, stage)

    def save() -> None:
        try:
            write_checkpoint(directory, stage, metadata, tasks_snapshot)
        except Exception as exc:
            logger.warning("[Checkpoint] 异步保存失败 %s: %s", stage, exc)

    future = executor.submit(save)
    with futures_lock:
        futures.append(future)


def wait_for_writes(futures: list[Future], futures_lock: Lock) -> None:
    with futures_lock:
        pending = list(futures)
        futures.clear()
    for future in pending:
        try:
            future.result()
        except Exception as exc:
            logger.warning("[Checkpoint] 等待保存任务失败: %s", exc)


def is_compatible(
    directory: str,
    stage: str,
    expected: dict,
) -> bool:
    path = checkpoint_path(directory, stage)
    if not os.path.isfile(path):
        return False
    try:
        with open(path, "rb") as source:
            metadata = orjson.loads(source.read()).get("meta", {})
    except Exception as exc:
        logger.warning("[Checkpoint] %s 元信息读取失败: %s", stage, exc)
        return False
    mismatches = [
        key for key in REQUIRED_META_KEYS
        if key not in metadata or metadata.get(key) != expected.get(key)
    ]
    if mismatches:
        logger.warning(
            "[Checkpoint] %s 与当前运行不兼容，忽略（字段: %s）",
            stage, ", ".join(mismatches),
        )
        return False
    return True


def load_checkpoint(directory: str, stage: str) -> list[TaskUnit] | None:
    path = checkpoint_path(directory, stage)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as source:
            tasks_data = json.load(source).get("tasks", [])
        if not tasks_data:
            logger.warning("[Checkpoint] %s 文件为空", stage)
            return None
        tasks = [task_from_dict(item) for item in tasks_data]
        logger.info(
            "[Checkpoint] %s 已加载 <- %s (%d 个任务)",
            stage, path, len(tasks),
        )
        return tasks
    except Exception as exc:
        logger.warning(
            "[Checkpoint] %s 加载失败: %s，将重新运行该阶段",
            stage, exc,
        )
        return None
