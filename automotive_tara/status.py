"""任务完成状态的确定性判定。"""

from __future__ import annotations

from automotive_tara.domain import (
    STATUS_INPUT_MAPPING_CONFLICT,
    STATUS_INSUFFICIENT_EVIDENCE,
    STATUS_MODEL_FAILED,
    STATUS_NEEDS_REVIEW,
    STATUS_NOT_APPLICABLE,
    STATUS_TOPOLOGY_UNCOVERED,
    STATUS_VALID,
    TaskUnit,
    safe_int,
)
from automotive_tara.reason_policy import IMPACT_REASON_KEYS, reason_fields_valid


def finalize_task_status(task: TaskUnit, *, enable_reason: bool) -> str:
    """根据当前证据确定任务状态；失败状态不得进入风险矩阵。"""
    if task.analysis_status == STATUS_NOT_APPLICABLE:
        task.risk_value = None
        task.risk_treatment = "不适用"
        return task.analysis_status

    reasons: list[str] = []
    if (
        task.analysis_status == STATUS_MODEL_FAILED
        and task.status_reasons
        and (
            not task.damage_scenario
            or not task.threat_scenarios
            or not task.influence_parameters
            or not task.attack_paths
        )
    ):
        status = STATUS_MODEL_FAILED
        reasons.extend(task.status_reasons)
    elif not task.damage_scenario or not task.threat_scenarios:
        status = STATUS_MODEL_FAILED
        reasons.append("损害场景或威胁场景缺失")
    elif not task.influence_parameters or not all(
        1 <= safe_int(task.influence_parameters.get(key)) <= 4
        for key in ("Safety", "Finance", "Operation", "Privacy")
    ):
        status = STATUS_MODEL_FAILED
        reasons.append("影响评级缺失或超出1~4范围")
    elif not reason_fields_valid(
        task.influence_parameters,
        IMPACT_REASON_KEYS,
        enabled=enable_reason,
    ):
        status = STATUS_MODEL_FAILED
        reasons.append("影响评级理由缺失或为空")
    elif task.input_mapping_conflicts and (
        not task.selected_path_frameworks
        or any(
            str(reason).startswith("攻击向量映射失败")
            for reason in task.input_mapping_conflicts
        )
    ):
        # 攻击向量未知/非法时即使存在其它候选框架也必须阻断，防止
        # 可行性评级把未知值当作 local。一般协议回退仍可保留为警告。
        status = STATUS_INPUT_MAPPING_CONFLICT
        reasons.extend(task.input_mapping_conflicts)
    elif not task.selected_path_frameworks:
        status = STATUS_TOPOLOGY_UNCOVERED
        reasons.append("拓扑未找到适用攻击路径框架")
    elif not task.attack_paths:
        status = STATUS_INSUFFICIENT_EVIDENCE
        reasons.append("未获得可验证的攻击路径")
    elif len(task.attack_paths) != len(task.selected_path_frameworks):
        status = STATUS_NEEDS_REVIEW
        reasons.append("攻击路径数量与拓扑框架数量不一致")
    else:
        status = STATUS_VALID

    # 即使同时存在模型输出缺失，也不能吞掉攻击向量输入映射错误；报告的
    # 状态说明必须给出可定位的接口和冲突原因。
    for mapping_reason in task.input_mapping_conflicts:
        if str(mapping_reason).startswith("攻击向量映射失败") and mapping_reason not in reasons:
            reasons.append(mapping_reason)

    task.analysis_status = status
    if reasons:
        for reason in reasons:
            if reason not in task.status_reasons:
                task.status_reasons.append(reason)
        task.risk_value = None
        task.risk_treatment = "需复核"
    else:
        task.status_reasons = []
    return status
