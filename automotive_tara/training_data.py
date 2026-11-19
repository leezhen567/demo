"""TARA 训练数据旁路采集、专家审阅表和回流数据导出。

采集器不参与模型缓存、任务校验或报告计算。关闭时所有入口都是常数时间空操作；
开启时模型调用记录通过后台线程写盘，避免并发阶段等待文件 I/O。
"""

from __future__ import annotations

import hashlib
import logging
import os
import queue
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

import orjson
from openpyxl import Workbook, load_workbook
from openpyxl.worksheet.datavalidation import DataValidation
from openpyxl.styles import Alignment, Font, PatternFill

from automotive_tara.domain import (
    AP_ALLOWED_VALUES,
    CVSS_C,
    CVSS_P,
    CVSS_U,
    HEAVENS_AP_ALLOWED_VALUES,
    TaskUnit,
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
)
from automotive_tara.reason_policy import (
    AP_REASON_KEYS,
    CVSS_REASON_KEYS,
    HEAVENS_REASON_KEYS,
    IMPACT_REASON_KEYS,
    sanitize_reason_fields,
)
from automotive_tara.storage import atomic_write_bytes


logger = logging.getLogger(__name__)

_STOP = object()
_REVIEW_HEADERS = (
    "sample_id",
    "run_id",
    "stage",
    "task_id",
    "path_id",
    "model",
    "trainable",
    "input_json",
    "model_output_json",
    "expert_decision",
    "expert_output_json",
    "expert_comment",
    "prompt_id",
)
_ACCEPT_DECISIONS = {"accept", "accepted", "通过", "采纳", "正确"}
_CORRECT_DECISIONS = {"correct", "corrected", "修改", "已修正", "修正"}
_REJECT_DECISIONS = {"reject", "rejected", "拒绝", "错误", "不采纳"}

# 专家可见列。机器字段仍保留在每个 Sheet 的末尾并隐藏，供导入器无损回读。
_FRIENDLY_COMMON_HEADERS = (
    "sample_id",
    "task_id",
    "path_id",
    "stage",
    "function",
    "asset_name",
    "asset_type",
    "attribute_name",
    "ai_summary",
    "expert_decision",
    "expert_comment",
)
_FRIENDLY_STAGE_HEADERS = {
    "dst": (
        "AI_damage_scenario",
        "AI_threat_scenarios",
        "expert_damage_scenario",
        "expert_threat_scenarios",
    ),
    "impact": tuple(
        [f"AI_{key}" for key in ("Safety", "Finance", "Operation", "Privacy")]
        + [f"AI_{key}_reason" for key in IMPACT_REASON_KEYS]
        + [
            f"expert_{key}"
            for key in ("Safety", "Finance", "Operation", "Privacy")
        ]
        + [f"expert_{key}" for key in IMPACT_REASON_KEYS]
    ),
    "attack_entry": ("AI_entry_action", "expert_entry_action"),
    "attack_target": ("AI_target_action", "expert_target_action"),
    "attack_path_review": ("AI_attack_path", "expert_attack_path"),
    "feasibility": (
        "AI_Exposure_time", "AI_Professional_experience",
        "AI_Required_information", "AI_Required_equipment",
        "AI_Exposure_time_reason", "AI_Professional_experience_reason",
        "AI_Required_information_reason", "AI_Required_equipment_reason",
        "AI_complexity", "AI_privileges", "AI_user_interaction",
        "AI_complexity_reason", "AI_privileges_reason",
        "AI_user_interaction_reason",
        "AI_Expertise", "AI_Knowledge_about_TOE", "AI_Equipment",
        "AI_Expertise_reason", "AI_Knowledge_about_TOE_reason",
        "AI_Equipment_reason",
        "expert_Exposure_time", "expert_Professional_experience",
        "expert_Required_information", "expert_Required_equipment",
        "expert_Exposure_time_reason", "expert_Professional_experience_reason",
        "expert_Required_information_reason", "expert_Required_equipment_reason",
        "expert_complexity", "expert_privileges", "expert_user_interaction",
        "expert_complexity_reason", "expert_privileges_reason",
        "expert_user_interaction_reason",
        "expert_Expertise", "expert_Knowledge_about_TOE", "expert_Equipment",
        "expert_Expertise_reason", "expert_Knowledge_about_TOE_reason",
        "expert_Equipment_reason",
    ),
}
_MACHINE_REVIEW_HEADERS = (
    "run_id",
    "model",
    "trace_id",
    "prompt_version",
    "trainable",
    "input_json",
    "model_output_json",
    "expert_output_json",
    "prompt_id",
)


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat()


def _json_text(value: Any) -> str:
    return orjson.dumps(value).decode("utf-8")


def _stable_id(*parts: Any) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(orjson.dumps(part, option=orjson.OPT_SORT_KEYS))
        digest.update(b"\0")
    return digest.hexdigest()[:24]


def _parse_json(value: Any, *, field: str) -> Any:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} 为空")
    try:
        return orjson.loads(value)
    except orjson.JSONDecodeError as exc:
        raise ValueError(f"{field} 不是合法 JSON: {exc}") from exc


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "是"}


class TrainingCapture:
    """单次运行的低开销 JSONL 采集器。"""

    def __init__(
        self,
        output_dir: str | os.PathLike[str],
        *,
        enabled: bool,
        include_rejected: bool = False,
    ) -> None:
        self.enabled = bool(enabled)
        self.include_rejected = bool(include_rejected)
        self.output_dir = Path(output_dir).resolve()
        self.training_dir = self.output_dir / "training"
        self.calls_path = self.training_dir / "llm_calls.jsonl"
        self.samples_path = self.training_dir / "adopted_samples.jsonl"
        self.review_path = self.training_dir / "expert_review.xlsx"
        self.manifest_path = self.training_dir / "dataset_manifest.json"
        self.run_id = self.output_dir.name
        self._queue: queue.Queue[dict[str, Any] | object] = queue.Queue()
        self._thread: threading.Thread | None = None
        self._closed = False
        self._lock = threading.Lock()
        self._stats = {
            "llm_calls_enqueued": 0,
            "llm_calls_written": 0,
            "llm_calls_dropped": 0,
            "adopted_samples": 0,
        }
        if self.enabled:
            self.training_dir.mkdir(parents=True, exist_ok=True)
            self._thread = threading.Thread(
                target=self._writer,
                name="tara-training-capture",
                daemon=True,
            )
            self._thread.start()

    def record_llm_call(self, record: Mapping[str, Any]) -> None:
        """非阻塞记录一次 HTTP 尝试；失败记录由开关决定是否保留。"""
        if not self.enabled or self._closed:
            return
        status = str(record.get("status", ""))
        if status != "success" and not self.include_rejected:
            with self._lock:
                self._stats["llm_calls_dropped"] += 1
            return
        payload = {
            "schema_version": "tara-llm-call-v1",
            "record_type": "llm_call",
            "run_id": self.run_id,
            "captured_at": _now_iso(),
            **dict(record),
        }
        payload.setdefault(
            "call_id",
            _stable_id(
                self.run_id,
                payload.get("stage"),
                payload.get("request"),
                payload.get("attempt"),
                payload.get("captured_at"),
            ),
        )
        self._queue.put(payload)
        with self._lock:
            self._stats["llm_calls_enqueued"] += 1

    def export_adopted(
        self,
        tasks: Sequence[TaskUnit],
        *,
        model: str,
        feasibility_method: str,
        impact_method: str,
        enable_reason: bool,
        prompt_signature: str,
        system_prompts: Mapping[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """导出流水线最终采用的阶段级样本，并生成可回流专家审阅表。"""
        if not self.enabled:
            return []
        samples = build_adopted_samples(
            tasks,
            run_id=self.run_id,
            model=model,
            feasibility_method=feasibility_method,
            impact_method=impact_method,
            enable_reason=enable_reason,
            prompt_signature=prompt_signature,
            system_prompts=system_prompts,
        )
        content = b"".join(
            orjson.dumps(item, option=orjson.OPT_APPEND_NEWLINE)
            for item in samples
        )
        atomic_write_bytes(str(self.samples_path), content)
        export_expert_review(samples, self.review_path)
        stage_counts: dict[str, int] = {}
        trainable_count = 0
        for item in samples:
            stage = str(item.get("stage", "unknown"))
            stage_counts[stage] = stage_counts.get(stage, 0) + 1
            trainable_count += int(bool(item.get("trainable")))
        atomic_write_bytes(
            str(self.manifest_path),
            orjson.dumps(
                {
                    "schema_version": "tara-training-dataset-v1",
                    "created_at": _now_iso(),
                    "run_id": self.run_id,
                    "model": model,
                    "feasibility_method": feasibility_method,
                    "impact_method": impact_method,
                    "reason_policy": "required" if enable_reason else "forbidden",
                    "prompt_signature": prompt_signature,
                    "source_run_metadata": str(
                        (self.output_dir / "run_metadata.json").resolve()
                    ),
                    "files": {
                        "llm_calls": self.calls_path.name,
                        "adopted_samples": self.samples_path.name,
                        "expert_review": self.review_path.name,
                    },
                    "counts": {
                        "total": len(samples),
                        "trainable": trainable_count,
                        "review_only": len(samples) - trainable_count,
                        "by_stage": stage_counts,
                    },
                },
                option=orjson.OPT_INDENT_2,
            ),
        )
        with self._lock:
            self._stats["adopted_samples"] = len(samples)
        return samples

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            stats = dict(self._stats)
        return {
            "enabled": self.enabled,
            "include_rejected": self.include_rejected,
            "directory": str(self.training_dir) if self.enabled else None,
            "manifest": str(self.manifest_path) if self.enabled else None,
            **stats,
        }

    def close(self) -> None:
        if not self.enabled or self._closed:
            return
        self._closed = True
        self._queue.put(_STOP)
        if self._thread is not None:
            self._thread.join(timeout=30)
            if self._thread.is_alive():
                logger.warning("训练数据后台写线程未在 30 秒内退出")

    def _writer(self) -> None:
        pending = 0
        try:
            with self.calls_path.open("ab") as file_obj:
                while True:
                    try:
                        item = self._queue.get(timeout=1.0)
                    except queue.Empty:
                        if pending:
                            file_obj.flush()
                            pending = 0
                        continue
                    if item is _STOP:
                        break
                    file_obj.write(
                        orjson.dumps(item, option=orjson.OPT_APPEND_NEWLINE)
                    )
                    pending += 1
                    with self._lock:
                        self._stats["llm_calls_written"] += 1
                    if pending >= 32:
                        file_obj.flush()
                        pending = 0
                file_obj.flush()
        except Exception:
            logger.exception("训练调用轨迹写入失败: %s", self.calls_path)


def disabled_capture(output_dir: str | os.PathLike[str] = ".") -> TrainingCapture:
    return TrainingCapture(output_dir, enabled=False)


def _task_input(task: TaskUnit) -> dict[str, Any]:
    return {
        "task_id": task.task_id,
        "function": task.function,
        "element_index": task.element_index,
        "asset_name": task.asset_name,
        "asset_type": task.asset_type,
        "asset_details": task.asset_details,
        "signal_category": task.signal_category,
        "data_type": task.data_type,
        "attribute_name": task.attribute_name,
        "threat_type": task.threat_type,
        "source": task.source,
        "target": task.target,
        "flow_protocol": task.flow_protocol,
    }


def _sample(
    *,
    run_id: str,
    stage: str,
    task: TaskUnit,
    model: str,
    system_prompt: str,
    input_data: Mapping[str, Any],
    target: Mapping[str, Any],
    prompt_signature: str,
    path_id: str = "",
    trainable: bool = True,
    source: str = "pipeline_adopted",
) -> dict[str, Any]:
    user_content = _json_text(input_data)
    assistant_content = _json_text(target)
    sample_id = _stable_id(stage, task.task_id, path_id, input_data, target)
    trace_id = _stable_id("trace", run_id, stage, task.task_id, path_id)
    return {
        "schema_version": "tara-training-sample-v1",
        "sample_id": sample_id,
        "trace_id": trace_id,
        "run_id": run_id,
        "stage": stage,
        "task_id": task.task_id,
        "path_id": path_id,
        "model": model,
        "source": source,
        "status": "accepted",
        "trainable": trainable,
        "prompt_signature": prompt_signature,
        "input": dict(input_data),
        "target": dict(target),
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": assistant_content},
        ],
    }


def build_adopted_samples(
    tasks: Sequence[TaskUnit],
    *,
    run_id: str,
    model: str,
    feasibility_method: str,
    impact_method: str,
    enable_reason: bool,
    prompt_signature: str,
    system_prompts: Mapping[str, str] | None = None,
) -> list[dict[str, Any]]:
    """从最终 TaskUnit 构造经代码校验的阶段级数据，不收录缺失字段。"""
    samples: list[dict[str, Any]] = []
    active_prompts = dict(system_prompts or {})
    dst_prompt = active_prompts.get("dst", DST_BATCH_SYSTEM_PROMPT)
    impact_prompt = active_prompts.get("impact", IMPACT_BATCH_SYSTEM_PROMPT)
    attack_entry_prompt = active_prompts.get(
        "attack_entry", ATTACK_ENTRY_SYSTEM_PROMPT
    )
    attack_path_prompt = active_prompts.get(
        "attack_path", ATTACK_PATH_SYSTEM_PROMPT
    )
    attack_target_prompt = active_prompts.get(
        "attack_target", ATTACK_TARGET_SYSTEM_PROMPT
    )
    feasibility_prompt = active_prompts.get(feasibility_method) or {
        "attack_potential": AP_BATCH_SYSTEM_PROMPT,
        "cvss": CVSS_BATCH_SYSTEM_PROMPT,
        "heavens": HEAVENS_AP_BATCH_SYSTEM_PROMPT,
    }.get(feasibility_method, "")
    feasibility_reasons = {
        "attack_potential": AP_REASON_KEYS,
        "cvss": CVSS_REASON_KEYS,
        "heavens": HEAVENS_REASON_KEYS,
    }.get(feasibility_method, ())
    seen_entry_samples: set[str] = set()

    for task in tasks:
        common = _task_input(task)
        has_valid_paths = bool(task.attack_paths)
        if task.damage_scenario.strip() and task.threat_scenarios.strip():
            samples.append(
                _sample(
                    run_id=run_id,
                    stage="dst",
                    task=task,
                    model=model,
                    system_prompt=dst_prompt,
                    input_data=common,
                    target={
                        "damage_scenario": task.damage_scenario.strip(),
                        "threat_scenarios": task.threat_scenarios.strip(),
                    },
                    prompt_signature=prompt_signature,
                )
            )

        if (
            has_valid_paths
            and task.attack_target_action.strip()
            and task.attack_target_action_source in {"model", "cache"}
        ):
            samples.append(
                _sample(
                    run_id=run_id,
                    stage="attack_target",
                    task=task,
                    model=model,
                    system_prompt=attack_target_prompt,
                    input_data={
                        **common,
                        "damage_scenario": task.damage_scenario,
                        "threat_scenario": task.threat_scenarios,
                    },
                    target={"target_action": task.attack_target_action.strip()},
                    prompt_signature=prompt_signature,
                    source=f"pipeline_adopted_{task.attack_target_action_source}",
                )
            )

        for path_index, entry_action in enumerate(
            task.attack_entry_actions if has_valid_paths else []
        ):
            source_name = (
                task.attack_entry_action_sources[path_index]
                if path_index < len(task.attack_entry_action_sources)
                else ""
            )
            if not str(entry_action).strip():
                continue
            framework = (
                task.selected_path_frameworks[path_index]
                if path_index < len(task.selected_path_frameworks)
                else {}
            )
            if source_name == "direct_model":
                path_value = (
                    task.attack_paths[path_index]
                    if path_index < len(task.attack_paths)
                    else ""
                )
                if path_value.strip():
                    samples.append(
                        _sample(
                            run_id=run_id,
                            stage="attack_path_review",
                            task=task,
                            model=model,
                            system_prompt=attack_path_prompt,
                            input_data={
                                **common,
                                "damage_scenario": task.damage_scenario,
                                "threat_scenario": task.threat_scenarios,
                                "topology_framework": framework,
                            },
                            target={"attack_path": path_value.strip()},
                            prompt_signature=prompt_signature,
                            path_id=f"{task.task_id}:path:{path_index}",
                            source="pipeline_adopted_direct_model",
                        )
                    )
                continue
            if source_name not in {"model", "cache"}:
                continue
            entry_key = _stable_id(
                framework.get("external_interface", ""),
                framework.get("start_component", ""),
                framework.get("attack_vector", ""),
                str(entry_action).strip(),
            )
            if entry_key in seen_entry_samples:
                continue
            seen_entry_samples.add(entry_key)
            samples.append(
                _sample(
                    run_id=run_id,
                    stage="attack_entry",
                    task=task,
                    model=model,
                    system_prompt=attack_entry_prompt,
                    input_data={
                        "external_interface": framework.get(
                            "external_interface", ""
                        ),
                        "start_component": framework.get(
                            "start_component", ""
                        ),
                        "attack_vector": framework.get("attack_vector", ""),
                    },
                    target={"entry_action": str(entry_action).strip()},
                    prompt_signature=prompt_signature,
                    path_id=f"{task.task_id}:path:{path_index}",
                    source=f"pipeline_adopted_{source_name}",
                )
            )

        impact = sanitize_reason_fields(
            task.influence_parameters,
            IMPACT_REASON_KEYS,
            enabled=enable_reason,
        )
        if impact is not None and all(
            isinstance(impact.get(key), int) and 1 <= impact[key] <= 4
            for key in ("Safety", "Finance", "Operation", "Privacy")
        ):
            impact_target = {
                key: impact[key]
                for key in ("Safety", "Finance", "Operation", "Privacy")
            }
            if enable_reason:
                impact_target.update(
                    {key: impact[key] for key in IMPACT_REASON_KEYS}
                )
            samples.append(
                _sample(
                    run_id=run_id,
                    stage="impact",
                    task=task,
                    model=model,
                    system_prompt=impact_prompt,
                    input_data={
                        **common,
                        "damage_scenario": task.damage_scenario,
                        "impact_method": impact_method,
                    },
                    target={"influence_parameters": impact_target},
                    prompt_signature=prompt_signature,
                )
            )

        # 最终路径包含代码展开的可信拓扑，保留给专家审阅和评测，但禁止直接
        # 混入“让模型生成拓扑”的 SFT 数据。
        for path_index, attack_path in enumerate(task.attack_paths or []):
            if not str(attack_path).strip():
                continue
            path_id = f"{task.task_id}:path:{path_index}"
            framework = (
                task.selected_path_frameworks[path_index]
                if path_index < len(task.selected_path_frameworks)
                else {}
            )
            samples.append(
                _sample(
                    run_id=run_id,
                    stage="attack_path_review",
                    task=task,
                    model=model,
                    system_prompt=(
                        "该样本用于专家审阅混合架构生成的最终攻击路径；"
                        "拓扑框架由代码提供，不作为模型自由生成目标。"
                    ),
                    input_data={
                        **common,
                        "damage_scenario": task.damage_scenario,
                        "threat_scenarios": task.threat_scenarios,
                        "trusted_framework": framework,
                    },
                    target={"attack_path": str(attack_path).strip()},
                    prompt_signature=prompt_signature,
                    path_id=path_id,
                    trainable=False,
                )
            )

        if feasibility_method == "attack_vector" or not feasibility_prompt:
            continue
        for path_index, detail in enumerate(task.attack_details or []):
            if not isinstance(detail, dict):
                continue
            params = detail.get("attack_parameters")
            if not isinstance(params, dict) or not params:
                continue
            model_params = _model_feasibility_parameters(
                params, feasibility_method, enable_reason=enable_reason
            )
            if not model_params:
                continue
            path_id = f"{task.task_id}:path:{path_index}"
            samples.append(
                _sample(
                    run_id=run_id,
                    stage="feasibility",
                    task=task,
                    model=model,
                    system_prompt=feasibility_prompt,
                    input_data={
                        **common,
                        "attack_path": detail.get("attack_path", ""),
                        "feasibility_method": feasibility_method,
                    },
                    target={"attack_parameters": model_params},
                    prompt_signature=prompt_signature,
                    path_id=path_id,
                )
            )
    return samples


def _reverse_score(value: Any, mapping: Mapping[str, float]) -> str:
    if isinstance(value, str) and value.strip().lower() in mapping:
        return value.strip().lower()
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return ""
    for label, score in mapping.items():
        if abs(numeric - score) < 1e-9:
            return label
    return ""


def _model_feasibility_parameters(
    params: Mapping[str, Any], method: str, *, enable_reason: bool
) -> dict[str, Any]:
    """还原模型负责的字段，排除代码派生的向量和机会窗口。"""
    if method == "attack_potential":
        numeric_keys = (
            "Exposure_time",
            "Professional_experience",
            "Required_information",
            "Required_equipment",
        )
        reason_keys = tuple(
            key for key in AP_REASON_KEYS if key != "Opportunity_window_reason"
        )
        allowed = AP_ALLOWED_VALUES
    elif method == "heavens":
        numeric_keys = ("Expertise", "Knowledge_about_TOE", "Equipment")
        reason_keys = tuple(
            key
            for key in HEAVENS_REASON_KEYS
            if key != "Window_of_Opportunity_reason"
        )
        allowed = HEAVENS_AP_ALLOWED_VALUES
    elif method == "cvss":
        result = {
            "complexity": _reverse_score(params.get("complexity"), CVSS_C),
            "privileges": _reverse_score(params.get("privileges"), CVSS_P),
            "user_interaction": _reverse_score(
                params.get("user_interaction"), CVSS_U
            ),
        }
        if not all(result.values()):
            return {}
        if enable_reason:
            sanitized = sanitize_reason_fields(params, CVSS_REASON_KEYS)
            if sanitized is None:
                return {}
            result.update({key: sanitized[key] for key in CVSS_REASON_KEYS})
        return result
    else:
        return {}

    result: dict[str, Any] = {}
    for key in numeric_keys:
        try:
            value = int(params.get(key))
        except (TypeError, ValueError):
            return {}
        if value not in allowed[key]:
            return {}
        result[key] = value
    if enable_reason:
        sanitized = sanitize_reason_fields(params, reason_keys)
        if sanitized is None:
            return {}
        result.update({key: sanitized[key] for key in reason_keys})
    return result


def _validate_expert_output(
    stage: str,
    corrected: Any,
    original: Any,
    input_data: Mapping[str, Any],
) -> str:
    """返回空串表示修正目标可训练，否则返回明确错误。"""
    if not isinstance(corrected, dict):
        return "expert_output_json 顶层必须是 JSON 对象"
    if stage == "dst":
        if not all(
            isinstance(corrected.get(key), str) and corrected[key].strip()
            for key in ("damage_scenario", "threat_scenarios")
        ):
            return "DST 修正必须包含非空 damage_scenario 和 threat_scenarios"
        return ""
    if stage == "impact":
        params = corrected.get("influence_parameters")
        if not isinstance(params, dict) or not all(
            isinstance(params.get(key), int) and 1 <= params[key] <= 4
            for key in ("Safety", "Finance", "Operation", "Privacy")
        ):
            return "影响评级修正必须包含四个 1~4 整数维度"
        original_params = (
            original.get("influence_parameters", {})
            if isinstance(original, dict)
            else {}
        )
        require_reasons = any(key in original_params for key in IMPACT_REASON_KEYS)
        if sanitize_reason_fields(
            params, IMPACT_REASON_KEYS, enabled=require_reasons
        ) is None:
            return "影响评级修正的理由字段缺失或不合法"
        return ""
    text_key_by_stage = {
        "attack_entry": "entry_action",
        "attack_target": "target_action",
        "attack_path_review": "attack_path",
    }
    if stage in text_key_by_stage:
        key = text_key_by_stage[stage]
        if not isinstance(corrected.get(key), str) or not corrected[key].strip():
            return f"{stage} 修正必须包含非空 {key}"
        return ""
    if stage == "feasibility":
        params = corrected.get("attack_parameters")
        if not isinstance(params, dict):
            return "可行性修正必须包含 attack_parameters 对象"
        original_params = (
            original.get("attack_parameters", {})
            if isinstance(original, dict)
            else {}
        )
        require_reasons = any(
            str(key).endswith("_reason") for key in original_params
        )
        method = str(input_data.get("feasibility_method", ""))
        if not _model_feasibility_parameters(
            params, method, enable_reason=require_reasons
        ):
            return "可行性修正字段缺失、取值越界或理由不合法"
        return ""
    return f"不支持的训练阶段: {stage}"


def _display_value(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return _json_text(value)
    return value


def _friendly_stage_values(item: Mapping[str, Any], stage: str) -> dict[str, Any]:
    """将结构化目标展平为专家容易阅读的列。"""
    target = item.get("target", {})
    target = target if isinstance(target, dict) else {}
    values: dict[str, Any] = {}
    if stage == "dst":
        values.update(
            {
                "AI_damage_scenario": target.get("damage_scenario", ""),
                "AI_threat_scenarios": target.get("threat_scenarios", ""),
            }
        )
    elif stage == "impact":
        params = target.get("influence_parameters", {})
        params = params if isinstance(params, dict) else {}
        for key in ("Safety", "Finance", "Operation", "Privacy"):
            values[f"AI_{key}"] = params.get(key, "")
        for key in IMPACT_REASON_KEYS:
            values[f"AI_{key}_reason"] = params.get(key, "")
    elif stage == "attack_entry":
        values["AI_entry_action"] = target.get("entry_action", "")
    elif stage == "attack_target":
        values["AI_target_action"] = target.get("target_action", "")
    elif stage == "attack_path_review":
        values["AI_attack_path"] = target.get("attack_path", "")
    elif stage == "feasibility":
        params = target.get("attack_parameters", {})
        params = params if isinstance(params, dict) else {}
        for key in _FRIENDLY_STAGE_HEADERS["feasibility"]:
            if key.startswith("AI_"):
                values[key] = params.get(key[3:], "")
    return values


def _friendly_input_values(item: Mapping[str, Any]) -> dict[str, Any]:
    data = item.get("input", {})
    data = data if isinstance(data, dict) else {}
    target = item.get("target", {})
    target = target if isinstance(target, dict) else {}
    stage = str(item.get("stage", ""))
    summary = ""
    if stage == "dst":
        summary = str(data.get("asset_details") or data.get("threat_type") or "")
    elif stage == "impact":
        summary = str(data.get("damage_scenario") or "")
    elif stage == "feasibility":
        summary = str(data.get("attack_path") or "")
    else:
        summary = str(data.get("damage_scenario") or data.get("threat_scenario") or "")
    return {
        "sample_id": item.get("sample_id", ""),
        "task_id": item.get("task_id", ""),
        "path_id": item.get("path_id", ""),
        "stage": stage,
        "function": data.get("function", ""),
        "asset_name": data.get("asset_name", ""),
        "asset_type": data.get("asset_type", ""),
        "attribute_name": data.get("attribute_name", ""),
        "ai_summary": summary,
    }


def _friendly_correction(
    stage: str,
    row: Mapping[str, Any],
    original: Mapping[str, Any],
    input_data: Mapping[str, Any],
) -> dict[str, Any] | None:
    """读取专家可见修正列；全部为空时返回 None。"""
    def get(name: str) -> Any:
        return row.get(name)

    if stage == "dst":
        result = {
            "damage_scenario": str(get("expert_damage_scenario") or "").strip(),
            "threat_scenarios": str(get("expert_threat_scenarios") or "").strip(),
        }
        return result if any(result.values()) else None
    if stage == "attack_entry":
        value = str(get("expert_entry_action") or "").strip()
        return {"entry_action": value} if value else None
    if stage == "attack_target":
        value = str(get("expert_target_action") or "").strip()
        return {"target_action": value} if value else None
    if stage == "attack_path_review":
        value = str(get("expert_attack_path") or "").strip()
        return {"attack_path": value} if value else None
    if stage == "impact":
        keys = ("Safety", "Finance", "Operation", "Privacy")
        result: dict[str, Any] = {}
        for key in keys:
            value = get(f"expert_{key}")
            if value not in (None, ""):
                try:
                    result[key] = int(float(value))
                except (TypeError, ValueError):
                    result[key] = value
        for key in IMPACT_REASON_KEYS:
            value = str(get(f"expert_{key}") or "").strip()
            if value:
                result[key] = value
        return {"influence_parameters": result} if result else None
    if stage == "feasibility":
        method = str(input_data.get("feasibility_method", ""))
        if method == "attack_potential":
            keys = (
                "Exposure_time", "Professional_experience",
                "Required_information", "Required_equipment",
            )
            reason_keys = AP_REASON_KEYS
        elif method == "cvss":
            keys = ("complexity", "privileges", "user_interaction")
            reason_keys = CVSS_REASON_KEYS
        elif method == "heavens":
            keys = ("Expertise", "Knowledge_about_TOE", "Equipment")
            reason_keys = HEAVENS_REASON_KEYS
        else:
            return None
        result = {}
        for key in keys:
            value = get(f"expert_{key}")
            if value not in (None, ""):
                if method != "cvss":
                    try:
                        result[key] = int(float(value))
                    except (TypeError, ValueError):
                        result[key] = value
                else:
                    result[key] = str(value).strip()
        for key in reason_keys:
            value = str(get(f"expert_{key}") or "").strip()
            if value:
                result[key] = value
        return {"attack_parameters": result} if result else None
    return None


def export_expert_review(
    samples: Sequence[Mapping[str, Any]],
    path: str | os.PathLike[str],
) -> None:
    """生成专家友好的分阶段审阅工作簿。

    专家可见区域只包含自然语言、评级数字和决策列；原始 JSON/Prompt ID
    放在隐藏机器列中，导入时仍能还原完整训练消息。
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    workbook = Workbook()
    workbook.remove(workbook.active)
    stage_names = tuple(dict.fromkeys(str(item["stage"]) for item in samples))
    if not stage_names:
        stage_names = ("Empty",)
    prompt_catalog: dict[str, str] = {}
    trace_rows: list[tuple[Any, ...]] = []
    instruction = workbook.create_sheet("使用说明", 0)
    instruction.append(("TARA 专家审阅说明",))
    instruction.append(("请只填写 expert_decision、专家修正列和 expert_comment。",))
    instruction.append(("expert_decision 可填：accepted（正确）、corrected（修正）、rejected（错误无可信修正）。",))
    instruction.append(("corrected 时只填写对应的 expert_* 列；不需要编辑 JSON 或隐藏列。",))
    instruction.append(("灰色/隐藏列为机器回读字段，请不要修改、排序或删除 sample_id/task_id/path_id。",))
    instruction.column_dimensions["A"].width = 110
    for row in instruction.iter_rows():
        for cell in row:
            cell.alignment = Alignment(vertical="top", wrap_text=True)
    instruction["A1"].font = Font(bold=True, size=14)
    for stage in stage_names:
        sheet = workbook.create_sheet(stage[:31])
        visible_headers = _FRIENDLY_COMMON_HEADERS + _FRIENDLY_STAGE_HEADERS.get(
            stage, ()
        )
        all_headers = visible_headers + _MACHINE_REVIEW_HEADERS
        sheet.append(all_headers)
        for item in samples:
            if item.get("stage") != stage:
                continue
            messages = item.get("messages", [])
            system_prompt = (
                str(messages[0].get("content", ""))
                if messages and isinstance(messages[0], dict)
                else ""
            )
            prompt_id = _stable_id("system_prompt", system_prompt)
            prompt_catalog[prompt_id] = system_prompt
            friendly = _friendly_input_values(item)
            friendly.update(_friendly_stage_values(item, stage))
            friendly.update(
                {
                    "expert_decision": "",
                    "expert_comment": "",
                    "run_id": item.get("run_id", ""),
                    "model": item.get("model", ""),
                    "trace_id": item.get("trace_id", ""),
                    "prompt_version": item.get("prompt_signature", ""),
                    "trainable": bool(item.get("trainable", False)),
                    "input_json": _json_text(item.get("input", {})),
                    "model_output_json": _json_text(item.get("target", {})),
                    "expert_output_json": "",
                    "prompt_id": prompt_id,
                }
            )
            sheet.append(
                tuple(friendly.get(header, "") for header in all_headers)
            )
            trace_rows.append(
                (
                    sheet.max_row,
                    sheet.title,
                    friendly.get("sample_id", ""),
                    friendly.get("task_id", ""),
                    friendly.get("path_id", ""),
                    friendly.get("trace_id", ""),
                    friendly.get("stage", ""),
                    friendly.get("prompt_version", ""),
                    friendly.get("model", ""),
                    friendly.get("trainable", False),
                    friendly.get("run_id", ""),
                )
            )
        sheet.freeze_panes = "A2"
        sheet.auto_filter.ref = sheet.dimensions
        for cell in sheet[1]:
            cell.font = Font(bold=True)
            cell.fill = PatternFill("solid", fgColor="D9EAF7")
        for index, header in enumerate(all_headers, start=1):
            letter = sheet.cell(row=1, column=index).column_letter
            if header in _MACHINE_REVIEW_HEADERS:
                sheet.column_dimensions[letter].hidden = True
            elif header in {"expert_decision", "expert_comment"}:
                sheet.column_dimensions[letter].width = (
                    22 if header == "expert_decision" else 45
                )
            elif (
                "scenario" in header
                or "action" in header
                or "path" in header
                or "reason" in header
                or header in {"ai_summary", "function"}
            ):
                sheet.column_dimensions[letter].width = 48
            else:
                sheet.column_dimensions[letter].width = 18
        decision_index = all_headers.index("expert_decision") + 1
        decision_letter = sheet.cell(row=1, column=decision_index).column_letter
        decision_validation = DataValidation(
            type="list",
            formula1='"accepted,corrected,rejected"',
            allow_blank=True,
        )
        decision_validation.error = "请选择 accepted、corrected 或 rejected"
        decision_validation.errorTitle = "无效专家标记"
        sheet.add_data_validation(decision_validation)
        if sheet.max_row >= 2:
            decision_validation.add(
                f"{decision_letter}2:{decision_letter}{sheet.max_row}"
            )
        for row in sheet.iter_rows(min_row=2):
            for cell in row:
                cell.alignment = Alignment(vertical="top", wrap_text=True)
    catalog_sheet = workbook.create_sheet("_prompt_catalog")
    catalog_sheet.append(("prompt_id", "system_prompt"))
    for prompt_id, system_prompt in prompt_catalog.items():
        catalog_sheet.append((prompt_id, system_prompt))
    catalog_sheet.sheet_state = "hidden"
    trace_sheet = workbook.create_sheet("_trace_map")
    trace_sheet.append(
        (
            "excel_row",
            "sheet",
            "sample_id",
            "task_id",
            "path_id",
            "trace_id",
            "stage",
            "prompt_version",
            "model_name",
            "trainable",
            "run_id",
        )
    )
    for row in trace_rows:
        trace_sheet.append(row)
    trace_sheet.sheet_state = "hidden"
    temp_path = target.with_name(
        f".{target.name}.{os.getpid()}.{threading.get_ident()}.tmp.xlsx"
    )
    try:
        workbook.save(temp_path)
        os.replace(temp_path, target)
    finally:
        if temp_path.exists():
            temp_path.unlink()


def import_expert_review(
    workbook_path: str | os.PathLike[str],
    output_dir: str | os.PathLike[str],
) -> dict[str, int]:
    """将专家审阅表导出为 SFT、纠错偏好和拒绝样本 JSONL。"""
    workbook = load_workbook(workbook_path, data_only=False, read_only=True)
    sft: list[dict[str, Any]] = []
    preferences: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    reviewed_only: list[dict[str, Any]] = []
    errors: list[str] = []
    seen_ids: set[str] = set()
    prompt_catalog: dict[str, str] = {}
    if "_prompt_catalog" in workbook.sheetnames:
        catalog_rows = workbook["_prompt_catalog"].iter_rows(values_only=True)
        next(catalog_rows, None)
        prompt_catalog = {
            str(row[0]): str(row[1] or "")
            for row in catalog_rows
            if row and row[0]
        }
    for sheet in workbook.worksheets:
        if sheet.title in {"_prompt_catalog", "_trace_map", "使用说明"}:
            continue
        rows = sheet.iter_rows(values_only=True)
        try:
            header_row = next(rows)
        except StopIteration:
            continue
        indices = {str(value): index for index, value in enumerate(header_row)}
        missing = [name for name in _REVIEW_HEADERS if name not in indices]
        if missing:
            errors.append(f"{sheet.title}: 缺少列 {', '.join(missing)}")
            continue
        for row_number, row in enumerate(rows, start=2):
            def value(name: str) -> Any:
                index = indices[name]
                return row[index] if index < len(row) else None

            row_values = {
                str(header): (row[index] if index < len(row) else None)
                for header, index in indices.items()
            }

            decision = str(value("expert_decision") or "").strip().lower()
            if not decision:
                continue
            sample_id = str(value("sample_id") or "").strip()
            if not sample_id:
                errors.append(f"{sheet.title}!{row_number}: sample_id 为空")
                continue
            if sample_id in seen_ids:
                errors.append(f"{sheet.title}!{row_number}: sample_id 重复 {sample_id}")
                continue
            seen_ids.add(sample_id)
            try:
                input_data = _parse_json(value("input_json"), field="input_json")
                model_output = _parse_json(
                    value("model_output_json"), field="model_output_json"
                )
            except ValueError as exc:
                errors.append(f"{sheet.title}!{row_number}: {exc}")
                continue
            prompt_id = str(value("prompt_id") or "").strip()
            if prompt_id not in prompt_catalog:
                errors.append(
                    f"{sheet.title}!{row_number}: prompt_id 无法在目录中找到"
                )
                continue
            messages = [
                {"role": "system", "content": prompt_catalog[prompt_id]},
                {"role": "user", "content": _json_text(input_data)},
                {"role": "assistant", "content": _json_text(model_output)},
            ]
            base = {
                "excel_row": row_number,
                "sample_id": sample_id,
                "run_id": str(value("run_id") or ""),
                "stage": str(value("stage") or ""),
                "task_id": str(value("task_id") or ""),
                "path_id": str(value("path_id") or ""),
                "trace_id": str(row_values.get("trace_id") or ""),
                "prompt_version": str(row_values.get("prompt_version") or ""),
                "model": str(value("model") or ""),
                "expert_comment": str(value("expert_comment") or ""),
            }
            if decision not in (
                _ACCEPT_DECISIONS | _CORRECT_DECISIONS | _REJECT_DECISIONS
            ):
                errors.append(
                    f"{sheet.title}!{row_number}: 未知 expert_decision={decision!r}"
                )
                continue
            trainable = _as_bool(value("trainable"))
            if not trainable:
                reviewed_record = {
                    **base,
                    "decision": decision,
                    "model_output": model_output,
                }
                corrected_text = value("expert_output_json")
                friendly_corrected = _friendly_correction(
                    base["stage"], row_values, model_output, input_data
                )
                if not corrected_text and friendly_corrected is not None:
                    corrected = friendly_corrected
                elif corrected_text:
                    try:
                        corrected = _parse_json(
                            corrected_text, field="expert_output_json"
                        )
                    except ValueError as exc:
                        errors.append(f"{sheet.title}!{row_number}: {exc}")
                        continue
                else:
                    corrected = None
                if decision in _CORRECT_DECISIONS and corrected is None:
                    errors.append(
                        f"{sheet.title}!{row_number}: corrected 必须填写专家修正列"
                    )
                    continue
                if corrected is not None:
                    validation_error = _validate_expert_output(
                        base["stage"], corrected, model_output, input_data
                    )
                    if validation_error:
                        errors.append(
                            f"{sheet.title}!{row_number}: {validation_error}"
                        )
                        continue
                    reviewed_record["expert_output"] = corrected
                reviewed_only.append(reviewed_record)
                continue
            if decision in _ACCEPT_DECISIONS:
                validation_error = _validate_expert_output(
                    base["stage"], model_output, model_output, input_data
                )
                if validation_error:
                    errors.append(
                        f"{sheet.title}!{row_number}: {validation_error}"
                    )
                    continue
                sft.append({**base, "messages": messages, "label_source": "expert_accept"})
            elif decision in _CORRECT_DECISIONS:
                corrected_text = value("expert_output_json")
                if corrected_text:
                    try:
                        corrected = _parse_json(
                            corrected_text, field="expert_output_json"
                        )
                    except ValueError as exc:
                        errors.append(f"{sheet.title}!{row_number}: {exc}")
                        continue
                else:
                    corrected = _friendly_correction(
                        base["stage"], row_values, model_output, input_data
                    )
                if corrected is None:
                    errors.append(
                        f"{sheet.title}!{row_number}: corrected 必须填写专家修正列"
                    )
                    continue
                validation_error = _validate_expert_output(
                    base["stage"], corrected, model_output, input_data
                )
                if validation_error:
                    errors.append(
                        f"{sheet.title}!{row_number}: {validation_error}"
                    )
                    continue
                corrected_messages = list(messages)
                if not corrected_messages or corrected_messages[-1].get("role") != "assistant":
                    errors.append(
                        f"{sheet.title}!{row_number}: messages 缺少末尾 assistant"
                    )
                    continue
                corrected_messages[-1] = {
                    "role": "assistant",
                    "content": _json_text(corrected),
                }
                sft.append(
                    {
                        **base,
                        "messages": corrected_messages,
                        "label_source": "expert_corrected",
                    }
                )
                preferences.append(
                    {
                        **base,
                        "prompt_messages": corrected_messages[:-1],
                        "chosen": corrected,
                        "rejected": model_output,
                    }
                )
            elif decision in _REJECT_DECISIONS:
                rejected.append({**base, "messages": messages, "model_output": model_output})

    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    for name, records in (
        ("sft.jsonl", sft),
        ("preferences.jsonl", preferences),
        ("rejected.jsonl", rejected),
        ("reviewed_only.jsonl", reviewed_only),
    ):
        atomic_write_bytes(
            str(destination / name),
            b"".join(
                orjson.dumps(record, option=orjson.OPT_APPEND_NEWLINE)
                for record in records
            ),
        )
    atomic_write_bytes(
        str(destination / "import_errors.json"),
        orjson.dumps(errors, option=orjson.OPT_INDENT_2),
    )
    summary = {
        "sft": len(sft),
        "preferences": len(preferences),
        "rejected": len(rejected),
        "reviewed_only": len(reviewed_only),
        "errors": len(errors),
    }
    atomic_write_bytes(
        str(destination / "import_summary.json"),
        orjson.dumps(summary, option=orjson.OPT_INDENT_2),
    )
    return summary
