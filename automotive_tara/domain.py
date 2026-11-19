"""与 I/O、LLM 和流水线调度无关的 TARA 领域模型与评级计算。"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any


STATUS_VALID = "VALID"
STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"
STATUS_INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
STATUS_MODEL_FAILED = "MODEL_FAILED"
STATUS_TOPOLOGY_UNCOVERED = "TOPOLOGY_UNCOVERED"
STATUS_INPUT_MAPPING_CONFLICT = "INPUT_MAPPING_CONFLICT"
STATUS_NEEDS_REVIEW = "NEEDS_REVIEW"


SECURITY_ATTRIBUTES_MAP: dict[str, list[str]] = {
    "数据": ["完整性", "机密性", "可用性"],
    "信号": ["完整性", "机密性", "真实性", "可用性"],
    "部件": [
        "完整性",
        "机密性",
        "真实性",
        "不可抵赖性",
        "权限属性",
        "可用性",
    ],
    "接口": ["完整性", "机密性", "真实性", "可用性"],
}

ATTRIBUTE_TO_THREAT: dict[str, str] = {
    "完整性": "篡改",
    "机密性": "信息泄露",
    "可用性": "拒绝服务",
    "真实性": "欺骗",
    "不可抵赖性": "抵赖",
    "权限属性": "越权",
}

AP_ALLOWED_VALUES = {
    "Exposure_time": [0, 1, 4, 17, 19],
    "Professional_experience": [0, 3, 6, 9],
    "Required_information": [0, 3, 7, 11],
    "Opportunity_window": [0, 1, 4, 10],
    "Required_equipment": [0, 4, 7, 9],
}

HEAVENS_AP_ALLOWED_VALUES = {
    "Expertise": [0, 1, 2, 3],
    "Knowledge_about_TOE": [0, 1, 2, 3],
    "Window_of_Opportunity": [0, 1, 2, 3],
    "Equipment": [0, 1, 2, 3],
}

HEAVENS_WINDOW_BY_VECTOR = {
    "network": 0,
    "adjacent": 1,
    "local": 2,
    "physical": 3,
}

HEAVENS_TL_TO_FEASIBILITY = {
    "Severe": "High",
    "High": "High",
    "Medium": "Medium",
    "Low": "Low",
    "None": "Very Low",
}

CVSS_V = {
    "network": 0.85,
    "adjacent": 0.62,
    "local": 0.55,
    "physical": 0.20,
}
CVSS_C = {"low": 0.77, "high": 0.44}
CVSS_P = {"none": 0.85, "low": 0.62, "high": 0.27}
CVSS_U = {"none": 0.85, "required": 0.62}

ATTACK_VECTOR_TO_LEVEL = {
    "network": "High",
    "adjacent": "Medium",
    "local": "Low",
    "physical": "Very Low",
}

ATTACK_VECTOR_SCORE = {
    "network": 0.85,
    "adjacent": 0.62,
    "local": 0.55,
    "physical": 0.20,
}

OPPORTUNITY_WINDOW_MAP = {
    "network": 0,
    "adjacent": 1,
    "local": 4,
    "physical": 10,
}

RISK_MATRIX = {
    (4, "High"): 5,
    (4, "Medium"): 4,
    (4, "Low"): 3,
    (4, "Very Low"): 2,
    (3, "High"): 4,
    (3, "Medium"): 3,
    (3, "Low"): 2,
    (3, "Very Low"): 1,
    (2, "High"): 3,
    (2, "Medium"): 2,
    (2, "Low"): 2,
    (2, "Very Low"): 1,
    (1, "High"): 1,
    (1, "Medium"): 1,
    (1, "Low"): 1,
    (1, "Very Low"): 1,
}

HEAVENS_IL_INDEX = {
    "None": 0,
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Severe": 4,
}
HEAVENS_TL_INDEX = dict(HEAVENS_IL_INDEX)
HEAVENS_RISK_MATRIX = {
    (0, 0): "QM",
    (0, 1): "QM",
    (0, 2): "QM",
    (0, 3): "QM",
    (0, 4): "低",
    (1, 0): "QM",
    (1, 1): "低",
    (1, 2): "低",
    (1, 3): "低",
    (1, 4): "中",
    (2, 0): "QM",
    (2, 1): "低",
    (2, 2): "中",
    (2, 3): "中",
    (2, 4): "高",
    (3, 0): "QM",
    (3, 1): "低",
    (3, 2): "中",
    (3, 3): "高",
    (3, 4): "高",
    (4, 0): "低",
    (4, 1): "中",
    (4, 2): "高",
    (4, 3): "高",
    (4, 4): "严重",
}
HEAVENS_RISK_NUM = {"QM": 1, "低": 2, "中": 3, "高": 4, "严重": 5}

HEAVENS_DIM_WEIGHTS = {
    "Safety": {1: 0, 2: 10, 3: 100, 4: 1000},
    "Finance": {1: 0, 2: 10, 3: 100, 4: 1000},
    "Operation": {1: 0, 2: 1, 3: 10, 4: 100},
    "Privacy": {1: 0, 2: 1, 3: 10, 4: 100},
}

# 外部接口→攻击向量的唯一规范映射。顺序和含义以用户提供的接口表为准：
# 远程(network)、近场(adjacent)、本地(local)、物理接触(physical)。
# 未命中时必须返回空字符串，由上层标记 INPUT_MAPPING_CONFLICT，禁止默认为 local。
_ATTACK_VECTOR_ALIASES: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "network",
        (
            "network", "remote", "远程", "蜂窝", "cellular", "4g", "5g",
            "lte", "ota", "cloud", "ethernet", "以太网",
        ),
    ),
    (
        "adjacent",
        (
            "adjacent", "near", "近场", "rs232", "uwb", "卫星", "gnss",
            "gps", "北斗", "satellite", "v2x", "星闪", "wifi", "wlan",
            "bluetooth", "蓝牙", "ble", "rf", "射频",
        ),
    ),
    (
        "local",
        (
            "local", "本地", "ic卡", "tf卡", "sd卡",
            "内部通讯", "充电口", "充电接口", "obd", "usb", "nfc",
        ),
    ),
    (
        "physical",
        (
            "physical", "物理接触", "物理", "内部调试", "debug", "uart",
            "jtag", "spi", "i2c",
        ),
    ),
)


def _attack_vector_text_key(value: Any) -> str:
    """统一接口名称/Excel 向量文本的大小写、空格和标点。"""
    return re.sub(r"[\s_\-/\\\[\]（）()：:]+", "", str(value or "").strip().lower())


@dataclass
class TaskUnit:
    task_id: str
    function: str
    asset_name: str
    asset_type: str
    attribute_name: str
    threat_type: str
    target: str = ""
    source: str = ""
    asset_details: str = ""
    # Project-provided applicability facts used only by security-requirement
    # matching.  ``None`` means the project did not establish whether a
    # component is critical; it must not be treated as either yes or no.
    critical_component: bool | None = None
    operating_system: str = ""
    # Normalised DFD fields used by security-requirement matching. For a
    # signal flow, ``signal_category`` is its raw ``assetDetails``; for a
    # data-store asset, ``data_type`` is its raw ``assetDetails``. The
    # ``asset_name`` remains the DFD ``finetermval`` (the concrete signal or
    # data name). These fields stay separate so matching does not infer
    # semantics from arbitrary display text, and remain empty for unrelated
    # asset types unless an input adapter supplies an explicit value.
    signal_category: str = ""
    data_type: str = ""
    element_id: str = ""
    element_index: str = ""
    dfd_element_type: str = ""
    source_element_id: str = ""
    target_element_id: str = ""
    flow_protocol: str = ""
    source_is_external: bool = False
    target_is_external: bool = False
    # DFD 边界端点分类：外部接口用于绑定 information/拓扑入口，
    # 外部部件不参与接口白名单匹配，只作为路径端点。
    source_is_external_interface: bool = False
    target_is_external_interface: bool = False
    source_is_external_component: bool = False
    target_is_external_component: bool = False
    asset_is_external: bool = False
    asset_is_external_interface: bool = False
    asset_is_external_component: bool = False
    source_external_interfaces: list[str] = field(default_factory=list)
    input_mapping_conflicts: list[str] = field(default_factory=list)
    damage_scenario: str = ""
    threat_scenarios: str = ""
    r155_references: list[str] = field(default_factory=list)
    attack_paths: list[str] = field(default_factory=list)
    # 成功任务与 attack_paths 同序；失败任务记录每个期望 path_id 的模型
    # 生成状态和原因，但不将缺失路径写入 attack_paths 或正式报告。
    attack_path_provenance: list[dict] = field(default_factory=list)
    attack_entry_actions: list[str] = field(default_factory=list)
    attack_entry_action_sources: list[str] = field(default_factory=list)
    attack_target_action: str = ""
    attack_target_action_source: str = ""
    selected_path_frameworks: list[dict] = field(default_factory=list)
    influence_parameters: dict = field(default_factory=dict)
    impact_value: int = 1
    impact_level: str = "Negligible"
    attack_details: list[dict] = field(default_factory=list)
    risk_value: int | None = None
    risk_treatment: str = "需复核"
    analysis_status: str = STATUS_VALID
    status_reasons: list[str] = field(default_factory=list)
    influence_confidence: dict = field(default_factory=dict)
    impact_confidence: float = 0.0
    feasibility_confidence: list[dict] = field(default_factory=list)
    low_confidence_flags: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    # Dependency DAG for incremental caching; no generated prose in node keys.
    cache_dependencies: dict = field(default_factory=dict)


def task_analysis_reference(task: TaskUnit) -> str:
    """Return a stable, non-sequential reference for paired experiments.

    The reference depends only on the frozen engineering identity of an
    analysis unit.  It is deliberately independent of runtime task numbers,
    generated text, model output and report ordering.
    """

    material = "|".join(
        (
            task.function,
            task.element_index,
            task.asset_name,
            task.asset_type,
            task.attribute_name,
            task.source,
            task.target,
            task.flow_protocol,
        )
    )
    return "A" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]


@dataclass
class TopologyElementVO:
    id: str
    name: str = ""
    type: int | None = None
    color: str = ""
    source_id: str = ""
    target_id: str = ""
    is_gateway: bool = False
    ids: list[str] = field(default_factory=list)


@dataclass
class PathNodeVO:
    component_name_id: str
    component_name: str
    pre_component_name_id: str
    pre_component_name: str
    line_id: str
    color: str
    is_gateway: bool
    # ``line_id`` historically stores the channel colour for compatibility.
    # These explicit fields retain the engineering meaning without changing
    # existing report text or route selection behaviour.
    channel_id: str = ""
    topology_link_ids: tuple[str, ...] = field(default_factory=tuple)


class TopologyElementType:
    COMPONENT = 1
    GATEWAY = 2
    EXTERNAL_COMPONENT = 3
    LINE = 4


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def task_to_dict(task: TaskUnit) -> dict:
    return {
        field_name: getattr(task, field_name)
        for field_name in task.__dataclass_fields__
    }


def task_from_dict(data: dict) -> TaskUnit:
    asset_type = str(data.get("asset_type", ""))
    asset_name = str(data.get("asset_name", ""))
    asset_details = str(data.get("asset_details", ""))
    # Checkpoints created before the explicit semantic fields were added are
    # still valid.  Recover the lossless DFD mapping from the legacy fields
    # when loading those snapshots.
    signal_category = str(data.get("signal_category", ""))
    if "signal_category" not in data and asset_type == "信号":
        signal_category = asset_details
    data_type = str(data.get("data_type", ""))
    if "data_type" not in data and asset_type == "数据":
        data_type = asset_details
    return TaskUnit(
        task_id=str(data.get("task_id", "")),
        function=str(data.get("function", "")),
        asset_name=asset_name,
        asset_type=asset_type,
        attribute_name=str(data.get("attribute_name", "")),
        threat_type=str(data.get("threat_type", "")),
        target=str(data.get("target", "")),
        source=str(data.get("source", "")),
        asset_details=asset_details,
        critical_component=(
            data.get("critical_component")
            if "critical_component" in data
            else None
        ),
        operating_system=str(data.get("operating_system", "") or ""),
        signal_category=signal_category,
        data_type=data_type,
        element_id=str(data.get("element_id", "")),
        element_index=str(data.get("element_index", "")),
        dfd_element_type=str(data.get("dfd_element_type", "")),
        source_element_id=str(data.get("source_element_id", "")),
        target_element_id=str(data.get("target_element_id", "")),
        flow_protocol=str(data.get("flow_protocol", "")),
        source_is_external=bool(data.get("source_is_external", False)),
        target_is_external=bool(data.get("target_is_external", False)),
        source_is_external_interface=bool(
            data.get("source_is_external_interface", False)
        ),
        target_is_external_interface=bool(
            data.get("target_is_external_interface", False)
        ),
        source_is_external_component=bool(
            data.get("source_is_external_component", False)
        ),
        target_is_external_component=bool(
            data.get("target_is_external_component", False)
        ),
        asset_is_external=bool(data.get("asset_is_external", False)),
        asset_is_external_interface=bool(
            data.get("asset_is_external_interface", False)
        ),
        asset_is_external_component=bool(
            data.get("asset_is_external_component", False)
        ),
        source_external_interfaces=list(
            data.get("source_external_interfaces", [])
        ),
        input_mapping_conflicts=list(data.get("input_mapping_conflicts", [])),
        damage_scenario=str(data.get("damage_scenario", "")),
        threat_scenarios=str(data.get("threat_scenarios", "")),
        r155_references=list(data.get("r155_references", [])),
        attack_paths=list(data.get("attack_paths", [])),
        attack_path_provenance=list(data.get("attack_path_provenance", [])),
        attack_entry_actions=list(data.get("attack_entry_actions", [])),
        attack_entry_action_sources=list(
            data.get("attack_entry_action_sources", [])
        ),
        attack_target_action=str(data.get("attack_target_action", "")),
        attack_target_action_source=str(
            data.get("attack_target_action_source", "")
        ),
        selected_path_frameworks=list(
            data.get("selected_path_frameworks", [])
        ),
        influence_parameters=dict(data.get("influence_parameters", {})),
        impact_value=safe_int(data.get("impact_value"), 1),
        impact_level=str(data.get("impact_level", "Negligible")),
        attack_details=list(data.get("attack_details", [])),
        risk_value=(
            safe_int(data.get("risk_value"))
            if data.get("risk_value") is not None
            else None
        ),
        risk_treatment=str(data.get("risk_treatment", "需复核")),
        analysis_status=str(data.get("analysis_status", STATUS_VALID)),
        status_reasons=list(data.get("status_reasons", [])),
        influence_confidence=dict(data.get("influence_confidence", {})),
        impact_confidence=float(data.get("impact_confidence", 0.0)),
        feasibility_confidence=list(
            data.get("feasibility_confidence", [])
        ),
        low_confidence_flags=list(data.get("low_confidence_flags", [])),
        errors=list(data.get("errors", [])),
        cache_dependencies=dict(data.get("cache_dependencies", {})),
    )


def normalize_attack_vector(value: str) -> str:
    normalized = _attack_vector_text_key(value)
    if not normalized:
        return ""
    if normalized in {"network", "adjacent", "local", "physical"}:
        return normalized
    # 先接受规范英文值，再按图片中的接口/中文标签匹配别名。
    for vector, aliases in _ATTACK_VECTOR_ALIASES:
        # 长别名优先，避免短接口缩写误命中其它单词。
        for alias in sorted(aliases, key=len, reverse=True):
            if len(alias) <= 2:
                # RF/IC/TF/SD 等短接口缩写只能作为独立值或名称首尾，
                # 不能因为普通英文单词中偶然出现相同字母而误判为 local。
                if normalized != alias and not (
                    normalized.startswith(alias) or normalized.endswith(alias)
                ):
                    continue
            elif alias not in normalized:
                continue
            return vector
    return ""


def calculate_impact_value(influence_parameters: dict) -> int:
    if not influence_parameters:
        return 1
    value = max(
        safe_int(influence_parameters.get("Safety")),
        safe_int(influence_parameters.get("Finance")),
        safe_int(influence_parameters.get("Operation")),
        safe_int(influence_parameters.get("Privacy")),
    )
    return max(1, min(4, value))


def calculate_impact_level(impact_value: int) -> str:
    return {
        1: "Negligible",
        2: "Moderate",
        3: "Major",
        4: "Severe",
    }.get(impact_value, "Negligible")


def calculate_heavens_impact_value(influence_parameters: dict) -> int:
    if not influence_parameters:
        return 0
    return sum(
        weights.get(
            max(1, min(4, safe_int(influence_parameters.get(dimension), 1))),
            0,
        )
        for dimension, weights in HEAVENS_DIM_WEIGHTS.items()
    )


def calculate_heavens_dimension_values(influence_parameters: dict) -> dict:
    if not influence_parameters:
        return {}
    weighted = dict(influence_parameters)
    for dimension, weights in HEAVENS_DIM_WEIGHTS.items():
        level = safe_int(influence_parameters.get(dimension), 1)
        weighted[dimension] = weights.get(max(1, min(4, level)), 0)
    return weighted


def calculate_heavens_impact_level(heavens_value: int) -> str:
    if heavens_value == 0:
        return "None"
    if heavens_value <= 19:
        return "Low"
    if heavens_value <= 99:
        return "Medium"
    if heavens_value <= 999:
        return "High"
    return "Severe"


def calculate_heavens_4l_impact_value(influence_parameters: dict) -> int:
    if not influence_parameters:
        return 1
    total = calculate_heavens_impact_value(influence_parameters)
    if total <= 19:
        return 1
    if total <= 99:
        return 2
    if total <= 999:
        return 3
    return 4


def compute_impact_for_method(
    influence_parameters: dict,
    impact_method: str,
) -> tuple[int, str]:
    if impact_method == "heavens":
        value = calculate_heavens_impact_value(influence_parameters)
        return value, calculate_heavens_impact_level(value)
    if impact_method == "heavens_4level":
        value = calculate_heavens_4l_impact_value(influence_parameters)
        return value, calculate_impact_level(value)
    value = calculate_impact_value(influence_parameters)
    return value, calculate_impact_level(value)


def calculate_attack_potential_score(params: dict) -> int:
    return sum(safe_int(params.get(key)) for key in AP_ALLOWED_VALUES)


def calculate_attack_potential_level(total_score: int) -> str:
    if total_score <= 13:
        return "High"
    if total_score <= 19:
        return "Medium"
    if total_score <= 24:
        return "Low"
    return "Very Low"


def calculate_heavens_ap_score(params: dict) -> int:
    return sum(safe_int(params.get(key)) for key in HEAVENS_AP_ALLOWED_VALUES)


def calculate_heavens_ap_level(total_score: int) -> str:
    if total_score <= 1:
        return "Severe"
    if total_score <= 3:
        return "High"
    if total_score <= 6:
        return "Medium"
    if total_score <= 9:
        return "Low"
    return "None"


def calculate_cvss_score(params: dict) -> float:
    vector = CVSS_V.get(
        normalize_attack_vector(params.get("attack_vector", "")),
        0.55,
    )
    complexity = CVSS_C.get(
        (params.get("complexity", "high") or "high").strip().lower(),
        0.44,
    )
    privileges = CVSS_P.get(
        (params.get("privileges", "none") or "none").strip().lower(),
        0.85,
    )
    interaction = CVSS_U.get(
        (params.get("user_interaction", "none") or "none").strip().lower(),
        0.85,
    )
    return round(
        8.22 * vector * complexity * privileges * interaction,
        2,
    )


def calculate_cvss_level(score: float) -> str:
    if 2.96 <= score <= 3.89:
        return "High"
    if 2.00 <= score <= 2.95:
        return "Medium"
    if 1.06 <= score <= 1.99:
        return "Low"
    if 0.12 <= score <= 1.05:
        return "Very Low"
    return "Very Low" if score < 2.96 else "High"


def calculate_attack_vector_level(vector: str) -> str:
    return ATTACK_VECTOR_TO_LEVEL.get(normalize_attack_vector(vector), "Low")


def calculate_risk_value(impact_value: int, feasibility_level: str) -> int:
    return RISK_MATRIX.get((impact_value, feasibility_level), 1)


def impact_risk_index_for_method(
    impact_value: int,
    impact_method: str,
) -> int:
    if impact_method == "heavens":
        raise ValueError("HEAVENS 五级影响不能进入传统 4×4 风险矩阵")
    return max(1, min(4, safe_int(impact_value, 1)))


def calculate_heavens_risk_value(
    impact_level: str,
    feasibility_level: str,
) -> tuple[str, int]:
    impact_index = HEAVENS_IL_INDEX.get(impact_level, 0)
    threat_index = HEAVENS_TL_INDEX.get(feasibility_level, 0)
    label = HEAVENS_RISK_MATRIX.get((impact_index, threat_index), "QM")
    return label, HEAVENS_RISK_NUM.get(label, 1)


def get_risk_treatment(risk_value: int) -> str:
    return "风险缓解" if risk_value >= 4 else "风险接受"
