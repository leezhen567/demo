"""Generated stage implementation; all mutable runtime dependencies enter via ctx."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from collections import defaultdict, deque
from concurrent.futures import as_completed
from functools import partial
from typing import Any, Callable

import orjson

from automotive_tara.model_gateway import ModelRequestRejected
from automotive_tara.token_budget import PromptContextOverflow

from automotive_tara.domain import (
    AP_ALLOWED_VALUES, ATTACK_VECTOR_SCORE, CVSS_C, CVSS_P, CVSS_U,
    HEAVENS_AP_ALLOWED_VALUES, OPPORTUNITY_WINDOW_MAP,
    HEAVENS_TL_TO_FEASIBILITY as _HEAVENS_TL_TO_FEASIBILITY,
    HEAVENS_WINDOW_BY_VECTOR as _HEAVENS_WINDOW_BY_VECTOR,
    STATUS_MODEL_FAILED, STATUS_NOT_APPLICABLE, STATUS_VALID, TaskUnit,
    calculate_attack_potential_level, calculate_attack_potential_score,
    calculate_attack_vector_level, calculate_cvss_level, calculate_cvss_score,
    calculate_heavens_ap_level, calculate_heavens_ap_score,
    calculate_heavens_risk_value, calculate_risk_value, get_risk_treatment,
    normalize_attack_vector, safe_int as _safe_int,
)
from automotive_tara.json_utils import canonical_task_id as _canonical_task_id, safe_parse_json
from automotive_tara.prompts import (
    AP_BATCH_SYSTEM_PROMPT, ATTACK_ENTRY_SYSTEM_PROMPT,
    ATTACK_PATH_SYSTEM_PROMPT, ATTACK_TARGET_SYSTEM_PROMPT,
    CVSS_BATCH_SYSTEM_PROMPT,
    DST_BATCH_SYSTEM_PROMPT, HEAVENS_AP_BATCH_SYSTEM_PROMPT,
    IMPACT_BATCH_SYSTEM_PROMPT, IMPACT_REASON_SYSTEM_PROMPT,
    IMPACT_SYSTEM_PROMPT,
)
from automotive_tara.reason_policy import (
    AP_REASON_KEYS, CVSS_REASON_KEYS, HEAVENS_REASON_KEYS, IMPACT_REASON_KEYS,
    RATING_REASON_MAX_CHARS, reason_fields_valid,
)
from automotive_tara.runtime import RuntimeContext
from automotive_tara.cache_dependencies import (
    knowledge_entries, path_stage, record_result, scenario_reference, stage_key,
)
from automotive_tara.topology import (
    determine_attack_vector as _determine_attack_vector,
    external_interface_key as _external_interface_key,
    limit_shortest_frameworks, normalize_text as _normalize_text,
    name_match_key as _name_match_key,
    protocol_key as _protocol_key,
    same_protocol as _same_protocol,
)

logger = logging.getLogger(__name__)


_DST_CAPABILITY_GUARD_ERROR = "DST能力断言与资产证据冲突"
_DST_NO_CAPABILITY_MARKERS = (
    "无日志记录能力", "无日志能力", "不具备日志", "没有日志",
    "无操作系统级权限机制", "无权限机制", "不具备权限", "没有权限",
)

# DFD 信号协议与拓扑外部接口写法可能不同（“蜂窝通讯” vs “蜂窝信道”、
# “蓝牙” vs “Bluetooth”、“USB” vs “USB接口”）。同义词表把协议文本映射到
# 拓扑侧的外部接口名，使外部信号能选中正确的边界框架；子串关系另作兜底。
_DFD_PROTOCOL_INTERFACE_SYNONYMS = {
    "蜂窝通讯": "蜂窝信道",
    "蜂窝": "蜂窝信道",
    "cellular": "蜂窝信道",
    "蓝牙": "Bluetooth",
    "bluetooth": "Bluetooth",
    "bt": "Bluetooth",
    "ble": "Bluetooth",
    "rf": "射频信道",
    "rfid": "射频信道",
    "射频": "射频信道",
    "wifi": "WIFI信道",
    "wlan": "WIFI信道",
    "usb": "USB接口",
    "obd": "OBD接口",
}

# 路径文本中的协议允许使用不改变事实的常见写法。这里的等价关系只用于
# 校验模型是否覆盖可信框架，不会把同义词写回拓扑数据，也不会放宽节点
# 的身份匹配。CAN/CANFD 在物理信道绑定层属于同一兼容族，但路线文本
# 仍保留两组写法，避免把一个 CANFD 跳误当成缺失的 CAN 跳。
_ROUTE_PROTOCOL_ALIAS_GROUPS: tuple[tuple[str, ...], ...] = (
    (
        "蜂窝信道", "蜂窝网络", "蜂窝通信", "蜂窝通讯", "蜂窝",
        "蜂窝信道接口", "蜂窝网络接口", "cellular", "4g", "5g", "lte",
    ),
    (
        "CAN", "CAN总线", "CAN接口", "CAN总线接口", "CAN bus", "CAN-BUS",
    ),
    (
        "CANFD", "CAN-FD", "CAN FD", "CANFD总线", "CAN-FD总线",
        "CAN FD总线", "CANFD接口",
    ),
    (
        "以太网", "以太网接口", "Ethernet", "Ethernet接口",
    ),
    (
        "WIFI", "WiFi", "Wi-Fi", "WIFI信道", "WIFI网络", "WIFI接口",
        "无线局域网",
    ),
    (
        "蓝牙", "Bluetooth", "Bluetooth接口", "蓝牙信道", "BLE",
    ),
    (
        "USB", "USB接口", "USB信道",
    ),
    (
        "OBD", "OBD接口", "OBD-II", "OBD诊断接口",
    ),
    (
        "射频", "射频信道", "射频接口", "RF", "RF接口",
    ),
    (
        "充电口", "充电接口", "充电端口",
    ),
    (
        "RS232", "RS-232", "RS232接口",
    ),
    (
        "UWB", "UWB接口",
    ),
    (
        "V2X", "V2X接口",
    ),
    (
        "NFC", "NFC接口",
    ),
    (
        "UART", "UART接口",
    ),
    (
        "JTAG", "JTAG接口",
    ),
    (
        "卫星定位", "GNSS", "GPS", "卫星定位接口",
    ),
)


def _route_token_variants(token: Any) -> tuple[str, ...]:
    """返回可信路线 token 在自然语言中的受控等价写法。

    只对协议/外部信道别名展开；拓扑部件名称仍要求原名称（大小写、
    拓扑标签换行等基础归一化由 ``normalize_text`` 处理）。
    """
    normalized = _normalize_text(token)
    if not normalized:
        return ()
    key = _protocol_key(normalized)
    variants: set[str] = {normalized}
    if key:
        for group in _ROUTE_PROTOCOL_ALIAS_GROUPS:
            group_keys = {_protocol_key(item) for item in group}
            if key in group_keys:
                variants.update(group)
                break
    # 对“CAN总线/蜂窝信道”这类后缀写法，补充其明确的短名和接口形式。
    # 仅当 token 本身带有协议后缀时启用，避免把任意 ECU 名称扩展成别名。
    suffixes = ("接口", "信道", "网络", "总线", "通信", "通讯")
    for suffix in suffixes:
        if normalized.endswith(suffix) and len(normalized) > len(suffix):
            base = normalized[: -len(suffix)].strip()
            if base:
                variants.update({base, *(f"{base}{item}" for item in suffixes)})
            break
    return tuple(sorted(variants, key=lambda value: (-len(value), value)))


def _find_route_token(text: Any, token: Any, start: int = 0) -> int:
    """在路径文本中查找 token 或其受控协议别名的最早位置。"""
    haystack = _normalize_text(text).casefold()
    if not haystack:
        return -1
    positions: list[int] = []
    for variant in _route_token_variants(token):
        needle = _normalize_text(variant).casefold()
        if not needle:
            continue
        cursor = max(0, start)
        while True:
            position = haystack.find(needle, cursor)
            if position < 0:
                break
            end = position + len(needle)
            if _route_protocol_prefix_is_shadowed(haystack, position, token):
                cursor = position + 1
                continue
            # 拉丁协议名使用词边界，避免可信 token ``CAN`` 误命中模型
            # 中另一个 CANFD 跳；中文后缀（如“总线”）仍可自然连接。
            if (
                (not needle[0].isascii() or not needle[0].isalnum()
                 or position == 0
                 or not haystack[position - 1].isascii()
                 or not haystack[position - 1].isalnum())
                and (
                    not needle[-1].isascii() or not needle[-1].isalnum()
                    or end == len(haystack)
                    or not haystack[end].isascii()
                    or not haystack[end].isalnum()
                )
            ):
                positions.append(position)
                break
            cursor = position + 1
    positions = [position for position in positions if position >= 0]
    return min(positions) if positions else -1


def _route_token_in_text(text: Any, token: Any) -> bool:
    return _find_route_token(text, token) >= 0


def _find_exact_route_token(text: Any, token: Any, start: int = 0) -> int:
    """查找节点原名（仅做大小写、空白归一化，不做协议别名展开）。"""
    haystack = _normalize_text(text).casefold()
    needle = _normalize_text(token).casefold()
    if not haystack or not needle:
        return -1
    cursor = max(0, start)
    while True:
        position = haystack.find(needle, cursor)
        if position < 0:
            return -1
        end = position + len(needle)
        if (
            (not needle[0].isascii() or not needle[0].isalnum()
             or position == 0
             or not haystack[position - 1].isascii()
             or not haystack[position - 1].isalnum())
            and (
                not needle[-1].isascii() or not needle[-1].isalnum()
                or end == len(haystack)
                or not haystack[end].isascii()
                or not haystack[end].isalnum()
            )
        ):
            return position
        cursor = position + 1


def _route_protocol_prefix_is_shadowed(
    haystack: str, position: int, token: Any
) -> bool:
    """避免短协议名命中另一个更长的协议名。

    路线正文仍需区分 ``CAN`` 与 ``CANFD/CAN-FD`` 的具体跳次，避免在
    缺少一个 CAN 跳时仅凭子串命中 CANFD。该文本级保护不影响物理信道
    绑定层对 CAN/CANFD 的兼容判断。
    """
    key = _protocol_key(token)
    if key != "can":
        return False
    suffix = haystack[position:]
    return bool(re.match(r"can(?:[-\s]?fd)(?![a-z0-9])", suffix))


def _route_token_match_end(text: Any, token: Any, position: int) -> int:
    """返回指定位置处实际命中的最长受控写法的结束位置。"""
    haystack = _normalize_text(text).casefold()
    if position < 0 or position >= len(haystack):
        return position
    ends = []
    for variant in _route_token_variants(token):
        needle = _normalize_text(variant).casefold()
        if not needle or not haystack.startswith(needle, position):
            continue
        end = position + len(needle)
        if _route_protocol_prefix_is_shadowed(haystack, position, token):
            continue
        if needle[0].isascii() and needle[0].isalnum() and position > 0:
            previous = haystack[position - 1]
            if previous.isascii() and previous.isalnum():
                continue
        if needle[-1].isascii() and needle[-1].isalnum() and end < len(haystack):
            following = haystack[end]
            if following.isascii() and following.isalnum():
                continue
        ends.append(end)
    return max(ends, default=position)


def _route_token_allows_protocol_alias(framework: dict, token: Any, index: int) -> bool:
    """判断路线 token 是否允许协议同义表达。

    ``path_nodes`` 是拓扑部件白名单；即使某个部件恰好叫 CAN/WIFI，也
    不能把它当成通信协议替换。没有完整 ``path_protocols`` 元数据的旧
    测试/导出则按受控协议别名组识别，仍不放宽已列出的节点。
    """
    key = _protocol_key(token)
    if not key:
        return False
    node_keys = {
        _protocol_key(node)
        for node in (framework.get("path_nodes") or [])
        if _protocol_key(node)
    }
    if key in node_keys:
        return False
    protocol_keys = {
        _protocol_key(protocol)
        for protocol in (framework.get("path_protocols") or [])
        if _protocol_key(protocol)
    }
    if key in protocol_keys:
        return True
    # 普通拓扑路线的第一个 token 是 external_interface；外部部件直连的
    # 第一个 token 则是 source 节点，不能展开成接口别名。
    if index == 0 and not framework.get("is_external_component_direct"):
        return True
    return any(key in {_protocol_key(item) for item in group} for group in _ROUTE_PROTOCOL_ALIAS_GROUPS)


def _is_unspecified_protocol(value: Any) -> bool:
    """判断拓扑导出中的未命名线路是否只是缺少协议元数据。

    部分拓扑导出会把未配置图例名称的颜色线路写成 ``lineN``。它不是
    一个真实协议，不能因为它与 DFD 中的 CAN/以太网等名称不同，就把
    已经在同一条物理线路上的 Source/Target 判定为输入冲突。
    """
    text = _normalize_text(value).casefold()
    if not text:
        return True
    return bool(
        re.fullmatch(r"line\s*\d+", text)
        or text in {"未知协议", "unknown", "n/a", "na", "未命名协议"}
    )


def _protocol_interface_keys(protocol: str) -> set[str]:
    """返回 DFD 协议可等价命中的拓扑接口 key 集合。

    先按归一化 key 精确比较，再按同义词表映射（如“蜂窝通讯”→“蜂窝信道”），
    最后用子串关系兜底（如“usb”⊂“usb接口”、“wifi”⊂“wifi信道”）。
    """
    text = _normalize_text(protocol)
    if not text:
        return set()
    base = _protocol_key(text)
    keys = {base} if base else set()
    if not base:
        return set()
    for source, interface in _DFD_PROTOCOL_INTERFACE_SYNONYMS.items():
        source_key = _protocol_key(source)
        if source_key and (source_key == base or source_key in base or base in source_key):
            interface_key = _protocol_key(interface)
            if interface_key:
                keys.add(interface_key)
    return keys


def _framework_protocol_matches(framework: dict, protocol: str) -> bool:
    """拓扑框架是否与 DFD 外部信号协议在边界段等价。

    外部信号的 DFD 协议描述边界段（外部实体到内部部件），对应拓扑框架的
    external_interface；内部信号则对应末跳 last_protocol。两者都参与比对，
    容忍 DFD 与拓扑图写法差异。
    """
    keys = _protocol_interface_keys(protocol)
    if not keys:
        return True
    candidates = [
        _normalize_text(framework.get('external_interface', '')),
        _normalize_text(framework.get('last_protocol', '')),
    ]
    # Some legacy exports omit ``last_protocol`` even though the per-hop list
    # is present.  The final hop is equivalent evidence and avoids rejecting a
    # valid cross-channel route merely because the summary field is absent.
    path_protocols = list(framework.get('path_protocols') or [])
    if path_protocols:
        candidates.append(_normalize_text(path_protocols[-1]))
    declared = [value for value in candidates if value and not _is_unspecified_protocol(value)]
    if any(_protocol_key(value) in keys for value in declared):
        return True
    # If a concrete interface/protocol is declared and none of it matches,
    # this is a real mapping conflict.  Only entirely missing/placeholder
    # metadata is treated as unknown rather than incompatible.
    return not declared


def _signal_binding_channels(
    source_framework: dict,
    target_frameworks: list[dict],
    protocol: str,
) -> list[tuple[str, str]]:
    """Return valid endpoint attachments for an internal DFD signal hop.

    A DFD protocol describes the communication medium of the relationship;
    it does *not* require the two endpoint framework records to reuse the same
    exported channel/color ID.  A topology exporter can assign different
    attachment IDs to the Source and Target while both attachments still
    represent ``CAN`` (or another protocol).  The valid rule is therefore:

    * Source has at least one attachment whose protocol matches the DFD flow;
    * Target has at least one attachment whose protocol matches the DFD flow.

    When a common channel ID is available we retain it as the strongest
    provenance.  Otherwise the Source-side matching ID is retained for the
    generated framework; the endpoint protocol evidence remains in the
    terminal metadata copied from Target.  Older hand-built frameworks without
    terminal metadata still return an empty list so the caller can apply its
    compatibility fallback explicitly.
    """

    def _attachments(frameworks: list[dict]) -> dict[str, set[str]]:
        result: dict[str, set[str]] = {}
        for framework in frameworks:
            protocol_map = framework.get("terminal_channel_protocols", {}) or {}
            for raw_channel_id in framework.get("terminal_channel_ids", []) or []:
                channel_id = _normalize_text(raw_channel_id)
                if not channel_id:
                    continue
                result.setdefault(channel_id, set()).add(
                    _normalize_text(protocol_map.get(raw_channel_id, ""))
                    or _normalize_text(protocol_map.get(channel_id, ""))
                )
        return result

    source_by_channel = _attachments([source_framework])
    target_by_channel = _attachments(target_frameworks)

    def _matches(channel_protocol: str) -> bool:
        # lineN/unknown is an unlabeled topology placeholder.  It is usable
        # only when the same physical ID is shared by both endpoints; it is
        # not enough to prove an independent protocol match.
        return bool(protocol) and bool(channel_protocol) and not _is_unspecified_protocol(channel_protocol) and _same_protocol(channel_protocol, protocol)

    source_matching = {
        channel_id
        for channel_id, protocols in source_by_channel.items()
        if any(_matches(channel_protocol) for channel_protocol in protocols)
    }
    target_matching = {
        channel_id
        for channel_id, protocols in target_by_channel.items()
        if any(_matches(channel_protocol) for channel_protocol in protocols)
    }

    candidates: list[tuple[str, str]] = []
    # Prefer a physically shared channel when one exists.  Validate each
    # endpoint's declaration independently; do not let a duplicate channel ID
    # with conflicting metadata overwrite the other endpoint's value.
    for channel_id in sorted(source_by_channel.keys() & target_by_channel.keys()):
        source_protocols = source_by_channel[channel_id]
        target_protocols = target_by_channel[channel_id]
        if protocol:
            source_ok = any(_matches(value) for value in source_protocols)
            target_ok = any(_matches(value) for value in target_protocols)
            placeholder_ok = any(
                _is_unspecified_protocol(value)
                for value in (*source_protocols, *target_protocols)
            )
            if not ((source_ok and target_ok) or (placeholder_ok and not source_ok and not target_ok)):
                continue
            display_protocol = next(
                (value for value in (*source_protocols, *target_protocols) if _matches(value)),
                protocol,
            )
        else:
            # No DFD protocol: only a genuinely shared attachment is usable.
            display_protocol = next(
                (value for value in (*source_protocols, *target_protocols) if value and not _is_unspecified_protocol(value)),
                protocol,
            ) or protocol
        candidates.append((channel_id, display_protocol or protocol))

    if candidates:
        return candidates

    # Main production rule: matching protocol on both endpoints is sufficient,
    # even when the exporter used distinct channel IDs for those attachments.
    # Keep one candidate per Source attachment so multiple valid Source buses
    # remain traceable without creating a cross-product of every Target bus.
    if protocol and source_matching and target_matching:
        return sorted((channel_id, protocol) for channel_id in source_matching)
    return []


def _signal_hop_link_ids(
    source_framework: dict,
    target_frameworks: list[dict],
    channel_id: str,
    protocol: str = "",
) -> list[str]:
    """Collect membership-link evidence for a signal protocol hop.

    If the endpoint exporters use different channel IDs, collect the Target
    links from its protocol-matching attachment as well.  This keeps the
    provenance complete while preserving the Source-side ID used for the
    stable framework key.
    """

    evidence: set[str] = set()
    for framework in [source_framework, *target_frameworks]:
        evidence.update(
            _normalize_text(link_id)
            for link_id in (
                (framework.get("terminal_channel_link_ids", {}) or {}).get(
                    channel_id, []
                )
            )
            if _normalize_text(link_id)
        )
        if protocol:
            protocol_map = framework.get("terminal_channel_protocols", {}) or {}
            link_map = framework.get("terminal_channel_link_ids", {}) or {}
            for candidate_id, candidate_protocol in protocol_map.items():
                if not _same_protocol(candidate_protocol, protocol):
                    continue
                evidence.update(
                    _normalize_text(link_id)
                    for link_id in link_map.get(candidate_id, []) or []
                    if _normalize_text(link_id)
                )
        channel_ids = list(framework.get("path_channel_ids") or [])
        link_groups = list(framework.get("topology_link_ids") or [])
        for position, candidate in enumerate(channel_ids):
            if _normalize_text(candidate) != channel_id:
                continue
            if position < len(link_groups):
                evidence.update(
                    _normalize_text(link_id)
                    for link_id in (link_groups[position] or [])
                    if _normalize_text(link_id)
                )
    return sorted(evidence)


def _terminal_channel_summary(framework: dict) -> str:
    """将端点挂接的协议整理成可诊断文本。

    信道颜色/内部 ID 是路线计算证据，不应暴露在用户可见的分析状态
    中；诊断信息只展示协议名称。内部的 ``terminal_channel_ids`` 仍然
    保留用于路径溯源，但信号绑定按两端各自的协议匹配判断，不要求
    Source 与 Target 复用同一个导出信道 ID。
    """
    ids = [
        _normalize_text(value)
        for value in framework.get("terminal_channel_ids", [])
        if _normalize_text(value)
    ]
    protocols = framework.get("terminal_channel_protocols", {}) or {}
    if not ids:
        return "（无）"
    protocol_names = {
        _normalize_text(protocols.get(channel_id, "未声明协议")) or "未声明协议"
        for channel_id in set(ids)
    }
    return "、".join(sorted(protocol_names, key=lambda value: (value == "未声明协议", value)))


def _aggregate_terminal_channel_metadata(
    frameworks: list[dict],
) -> dict:
    """Collapse repeated target frameworks to one O(channels) lookup view."""

    channel_ids: set[str] = set()
    protocols: dict[str, str] = {}
    link_ids: dict[str, set[str]] = {}
    for framework in frameworks:
        channel_ids.update(
            _normalize_text(channel_id)
            for channel_id in framework.get("terminal_channel_ids", [])
            if _normalize_text(channel_id)
        )
        protocols.update(
            {
                _normalize_text(channel_id): _normalize_text(protocol)
                for channel_id, protocol in (
                    framework.get("terminal_channel_protocols", {}) or {}
                ).items()
                if _normalize_text(channel_id)
            }
        )
        for channel_id, values in (
            framework.get("terminal_channel_link_ids", {}) or {}
        ).items():
            normalized_channel = _normalize_text(channel_id)
            if not normalized_channel:
                continue
            link_ids.setdefault(normalized_channel, set()).update(
                _normalize_text(link_id)
                for link_id in (values or [])
                if _normalize_text(link_id)
            )
    return {
        "terminal_channel_ids": sorted(channel_ids),
        "terminal_channel_protocols": protocols,
        "terminal_channel_link_ids": {
            channel_id: sorted(values)
            for channel_id, values in link_ids.items()
        },
    }


def _framework_matches_dfd_entry(framework: dict, dfd_entry: str) -> bool:
    """判断 DFD 外部入口名是否绑定到同一条表格/拓扑框架。

    information Excel 是接口白名单，DFD 中的 Actor 名称只能作为“绑定证据”，
    不能替换框架中的真实外部接口。工程中常见简称与带说明后缀的接口名称、
    或 Actor 名称直接等于拓扑入口部件的写法，因此同时比较框架的
    external_interface 和 start_component。比较采用规范化后的安全包含关系，
    不维护任何项目接口硬编码表，也不会据此创建新接口。
    """
    entry_keys = {_external_interface_key(dfd_entry)}
    # 协议/Actor 的中英文简称只用于匹配已经存在的表格项；这里绝不
    # 生成一个新的 external_interface。
    entry_keys.update(
        _external_interface_key(key)
        for key in _protocol_interface_keys(dfd_entry)
        if _external_interface_key(key)
    )
    entry_keys.discard('')
    if not entry_keys:
        return False
    candidates = (
        framework.get("external_interface", ""),
        framework.get("start_component", ""),
    )
    for candidate in candidates:
        candidate_key = _external_interface_key(candidate)
        if not candidate_key:
            continue
        for entry_key in entry_keys:
            if entry_key == candidate_key:
                return True
            # 只允许带说明后缀的同一名称相互匹配，过短的 key 不做包含匹配，
            # 避免“CAN”等短词误命中其它接口。
            if min(len(entry_key), len(candidate_key)) >= 3 and (
                entry_key in candidate_key or candidate_key in entry_key
            ):
                return True
    return False


def _route_node_key(value: Any) -> str:
    """Normalize a topology component name for graph joins."""
    return _name_match_key(_normalize_text(value))


def _link_ids_for_hop(value: Any) -> tuple[str, ...]:
    """Normalize the per-hop raw-link evidence stored in a framework."""
    if isinstance(value, (list, tuple, set)):
        values = value
    elif value:
        values = (value,)
    else:
        values = ()
    return tuple(sorted({
        _normalize_text(item)
        for item in values
        if _normalize_text(item)
    }))


def _build_framework_route_graph(
    frameworks: list[dict],
) -> tuple[
    dict[str, dict[str, list[dict[str, Any]]]],
    dict[str, set[str]],
    dict[str, str],
]:
    """Build a bidirectional component graph from frozen route evidence.

    The parser stores one channel/protocol/link-evidence record per adjacent
    pair in ``path_nodes``.  Reusing these records gives signal binding access
    to the full topology without requiring a second topology parser in the
    attack-path stage.  Every edge is inserted in both directions because the
    project topology semantics are bidirectional; direction is supplied only
    by the DFD relation when choosing a route.
    """
    graph: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    component_channels: dict[str, set[str]] = defaultdict(set)
    display_names: dict[str, str] = {}

    for framework in frameworks:
        nodes = [
            _normalize_text(node)
            for node in (framework.get("path_nodes") or [])
            if _normalize_text(node)
        ]
        channels = list(framework.get("path_channel_ids") or [])
        protocols = list(framework.get("path_protocols") or [])
        link_groups = list(framework.get("topology_link_ids") or [])
        for node in nodes:
            key = _route_node_key(node)
            if key:
                display_names.setdefault(key, node)
        for position, (left, right) in enumerate(zip(nodes, nodes[1:])):
            left_key = _route_node_key(left)
            right_key = _route_node_key(right)
            if not left_key or not right_key or left_key == right_key:
                continue
            channel_id = (
                _normalize_text(channels[position])
                if position < len(channels)
                else ""
            )
            if not channel_id:
                # Legacy hand-built frameworks without channel provenance are
                # retained for the direct-binding compatibility path, but they
                # cannot prove an intermediate topology hop.
                continue
            protocol = (
                _normalize_text(protocols[position])
                if position < len(protocols)
                else ""
            )
            link_ids = _link_ids_for_hop(
                link_groups[position] if position < len(link_groups) else ()
            )
            edge = {
                "channel_id": channel_id,
                "protocol": protocol,
                "topology_link_ids": link_ids,
            }
            component_channels[left_key].add(channel_id)
            component_channels[right_key].add(channel_id)
            for source_key, target_key in (
                (left_key, right_key),
                (right_key, left_key),
            ):
                existing = graph[source_key][target_key]
                edge_signature = (
                    edge["channel_id"],
                    edge["protocol"],
                    edge["topology_link_ids"],
                )
                if not any(
                    (
                        item["channel_id"],
                        item["protocol"],
                        item["topology_link_ids"],
                    )
                    == edge_signature
                    for item in existing
                ):
                    existing.append(dict(edge))

    for neighbours in graph.values():
        for edges in neighbours.values():
            edges.sort(
                key=lambda item: (
                    item["channel_id"],
                    item["protocol"],
                    item["topology_link_ids"],
                )
            )
    return graph, component_channels, display_names


def _signal_edge_protocol_allowed(edge_protocol: str, dfd_protocol: str) -> bool:
    """Return whether a topology hop can carry the DFD signal."""
    if not dfd_protocol or _normalize_text(dfd_protocol) == "DFD数据流":
        return True
    # Missing/placeholder legend metadata is not evidence of a conflict.  The
    # channel and raw-link records still constrain the route.
    if _is_unspecified_protocol(edge_protocol):
        return True
    return _same_protocol(edge_protocol, dfd_protocol)


def _shortest_signal_routes(
    graph: dict[str, dict[str, list[dict[str, Any]]]],
    component_channels: dict[str, set[str]],
    display_names: dict[str, str],
    source: str,
    target: str,
    protocol: str,
) -> list[dict[str, Any]]:
    """Find all shortest, protocol-compatible, loop-free source→target routes."""
    source_key = _route_node_key(source)
    target_key = _route_node_key(target)
    if not source_key or not target_key:
        return []
    if source_key == target_key:
        return [{"nodes": [display_names.get(source_key, source)], "edges": []}]
    if source_key not in graph or target_key not in graph:
        return []

    queue = deque(
        [
            (
                source_key,
                frozenset({source_key}),
                [display_names.get(source_key, source)],
                [],
            )
        ]
    )
    shortest_distance: dict[str, int] = {source_key: 0}
    target_distance: int | None = None
    routes: list[dict[str, Any]] = []
    seen_routes: set[tuple] = set()

    while queue:
        current_key, visited, node_tail, edge_tail = queue.popleft()
        distance = len(edge_tail)
        if target_distance is not None and distance >= target_distance:
            continue
        known_current = shortest_distance.get(current_key)
        if known_current is not None and distance > known_current:
            continue
        for next_key in sorted(graph.get(current_key, {})):
            if next_key in visited:
                continue
            for edge in graph[current_key][next_key]:
                if not _signal_edge_protocol_allowed(
                    edge.get("protocol", ""), protocol
                ):
                    continue
                next_distance = distance + 1
                if target_distance is not None and next_distance > target_distance:
                    continue
                # A channel transition is valid only at a component attached
                # to both channels.  This is the same gateway/controller rule
                # used by the topology validator, now applied to the inferred
                # intermediate route as well.
                if edge_tail:
                    previous_channel = edge_tail[-1].get("channel_id", "")
                    current_channel = edge.get("channel_id", "")
                    if previous_channel != current_channel and not {
                        previous_channel,
                        current_channel,
                    }.issubset(component_channels.get(current_key, set())):
                        continue
                known_next = shortest_distance.get(next_key)
                if known_next is not None and next_distance > known_next:
                    continue

                next_nodes = [*node_tail, display_names.get(next_key, next_key)]
                next_edges = [*edge_tail, edge]
                visited_next = frozenset((*visited, next_key))
                if known_next is None or next_distance < known_next:
                    shortest_distance[next_key] = next_distance
                if next_key == target_key:
                    target_distance = next_distance if target_distance is None else target_distance
                    route_signature = (
                        tuple(next_nodes),
                        tuple(
                            (
                                item.get("channel_id", ""),
                                item.get("protocol", ""),
                                item.get("topology_link_ids", ()),
                            )
                            for item in next_edges
                        ),
                    )
                    if route_signature not in seen_routes:
                        seen_routes.add(route_signature)
                        routes.append({"nodes": next_nodes, "edges": next_edges})
                else:
                    queue.append((next_key, visited_next, next_nodes, next_edges))
    if not routes:
        return []
    shortest = min(len(route["edges"]) for route in routes)
    return [route for route in routes if len(route["edges"]) == shortest]


def _cached_framework_route_graph(
    ctx: RuntimeContext,
    frameworks: list[dict],
) -> tuple[
    dict[str, dict[str, list[dict[str, Any]]]],
    dict[str, set[str]],
    dict[str, str],
]:
    """Build the signal graph once per framework collection per run."""
    cache = ctx.shared("_filter_framework_cache")
    lock = ctx.shared("_filter_framework_cache_lock")
    cache_key = ("__signal_route_graph__", id(frameworks))
    if isinstance(cache, dict):
        if lock is not None:
            with lock:
                cached = cache.get(cache_key)
        else:
            cached = cache.get(cache_key)
        if cached is not None:
            return cached
    graph = _build_framework_route_graph(frameworks)
    if isinstance(cache, dict):
        if lock is not None:
            with lock:
                cache.setdefault(cache_key, graph)
                cached = cache.get(cache_key)
        else:
            cache.setdefault(cache_key, graph)
            cached = cache.get(cache_key)
        return cached or graph
    return graph


def _external_component_direct_framework(task: TaskUnit) -> dict:
    """为外部部件端点创建不经过接口白名单的直接绑定框架。"""
    source = _normalize_text(task.source)
    target = _normalize_text(task.target)
    protocol = _normalize_text(task.flow_protocol)
    route = [source]
    if target and target != source:
        if protocol:
            route.append(f"[{protocol}]")
        route.append(target)
    description = " -> ".join(route)
    path_id = hashlib.sha1(
        f"external-component-direct|{task.function}|{task.element_index}|"
        f"{source}|{protocol}|{target}".encode("utf-8")
    ).hexdigest()[:16]
    return {
        "path_id": path_id,
        "path_description": description,
        "path_nodes": (
            [source]
            if source and source == target
            else [node for node in (source, target) if node]
        ),
        "last_node": target,
        "second_to_last_node": source if target and target != source else "",
        "start_component": source,
        # 外部部件不是 interface。保留空值，禁止借用其它项目接口。
        "external_interface": "",
        "components": (
            [source]
            if source and source == target
            else [node for node in (source, target) if node]
        ),
        "path_protocols": [protocol] if protocol and target and target != source else [],
        "last_protocol": protocol,
        # 外部部件本身不是接口，无法从 information 表取得 network/adjacent/local
        # 映射；直接接入车辆的边界按物理接触处理，避免把未知接口错误默认为 local。
        "attack_vector": normalize_attack_vector(protocol) or "physical",
        "attack_vector_source": (
            "dfd_protocol"
            if normalize_attack_vector(protocol)
            else "external_component_physical_boundary"
        ),
        "matched_targets": [target] if target else [],
        "framework_set": 1,
        "is_external_component_direct": True,
        "external_component_source": source,
        "external_component_target": target,
        "dfd_element_index": task.element_index,
        "dfd_source": source,
        "dfd_target": target,
        "dfd_protocol": protocol,
    }


def _framework_has_route_cycle(framework: dict) -> bool:
    """Return whether a topology framework revisits a component.

    ``path_nodes`` intentionally contains components only (the external
    interface is kept in a separate field), so a repeated normalized name is
    an unambiguous cycle.  A one-node external-component shortcut is not a
    cycle and remains valid.
    """
    nodes = [
        _normalize_text(node).casefold()
        for node in (framework.get("path_nodes") or [])
        if _normalize_text(node)
    ]
    return len(nodes) != len(set(nodes))

def filter_path_frameworks(ctx: RuntimeContext, task: TaskUnit, all_frameworks: list[dict]) -> list[dict]:
    target = (task.target or '').strip()
    source = (task.source or '').strip()
    cache_key = (id(all_frameworks), target, source, task.asset_type, task.asset_name, task.element_index, task.flow_protocol, task.source_is_external, task.target_is_external, task.source_is_external_interface, task.target_is_external_interface, task.source_is_external_component, task.target_is_external_component, task.asset_is_external, tuple(task.source_external_interfaces))
    with ctx.shared('_filter_framework_cache_lock'):
        cached = ctx.shared('_filter_framework_cache').get(cache_key)
    if cached is not None:
        (cached_frameworks, cached_conflicts) = cached
        task.input_mapping_conflicts = list(cached_conflicts)
        return list(cached_frameworks)
    task.input_mapping_conflicts = []

    def _finish(selected_frameworks: list[dict]) -> list[dict]:
        """统一校验攻击向量并缓存筛选结果。

        拓扑框架若带有非法/未知攻击向量，整项任务阻断，避免后续可行性
        评级把未知值悄悄当作 local 或其它默认分值。外部 Actor 自身路径和
        确实不在拓扑中的部件自路径没有外部接口证据，保留其空向量并由状态
        层按相应原因展示。
        """
        selected = list(selected_frameworks or [])
        valid: list[dict] = []
        vector_errors: list[str] = []
        for framework in selected:
            if _framework_has_route_cycle(framework):
                # A stale checkpoint or a hand-built caller may still contain
                # a route such as CEM→VCU→BCU→CEM.  Never expose it to the
                # model/report; drop it before any semantic generation.
                logger.warning(
                    "丢弃含回环的拓扑候选路径 path_id=%s nodes=%s",
                    framework.get("path_id", ""),
                    framework.get("path_nodes", []),
                )
                continue
            raw_vector = framework.get("attack_vector", "")
            vector = normalize_attack_vector(raw_vector)
            is_synthetic = bool(
                framework.get("is_external_actor_self")
                or framework.get("is_uncovered_part")
                or framework.get("is_external_component_direct")
            )
            # 旧的/测试用框架若完全没有 external_interface 元数据，无法判断
            # 其是否属于外部接口映射，保留原框架兼容性；解析器生成的框架
            # 始终带 external_interface 或 mapping_error，因此未知接口会被阻断。
            if (
                not vector
                and not is_synthetic
                and (
                    framework.get("attack_vector_mapping_error")
                    or framework.get("external_interface")
                )
            ):
                interface = _normalize_text(
                    framework.get("external_interface")
                ) or "未知接口"
                detail = _normalize_text(
                    framework.get("attack_vector_mapping_error")
                ) or f"外部接口[{interface}]未匹配图片规定的攻击向量映射"
                reason = f"攻击向量映射失败：{detail}"
                if reason not in vector_errors:
                    vector_errors.append(reason)
                continue
            if vector and vector != raw_vector:
                framework = {**framework, "attack_vector": vector}
            valid.append(framework)

        if vector_errors:
            for reason in vector_errors:
                if reason not in task.input_mapping_conflicts:
                    task.input_mapping_conflicts.append(reason)
            # 只要一个候选框架无法解释，不能用其它框架掩盖输入映射错误。
            valid = []
        with ctx.shared('_filter_framework_cache_lock'):
            ctx.shared('_filter_framework_cache')[cache_key] = (
                valid,
                list(task.input_mapping_conflicts),
            )
        return list(valid)

    if task.asset_is_external or task.dfd_element_type == 'tm.Actor' or task.asset_type == '接口':
        actor_name = task.asset_name.strip() or task.element_index
        self_description = f'[{actor_name}]'
        selected = [{'path_id': hashlib.sha1(f'dfd-actor-self|{task.function}|{task.element_index}|{actor_name}'.encode('utf-8')).hexdigest()[:16], 'path_description': self_description, 'path_nodes': [actor_name], 'last_node': actor_name, 'second_to_last_node': '', 'start_component': actor_name, 'external_interface': actor_name, 'components': [actor_name], 'attack_vector': _determine_attack_vector(actor_name, {}, []), 'matched_targets': [actor_name], 'framework_set': 1, 'is_external_actor_self': True}]
        return _finish(selected)
    is_signal = task.asset_type == '信号'
    if not is_signal:
        all_frameworks = [fw for fw in all_frameworks if fw.get('framework_set', 1) == 1]
    selected: list[dict] = []
    fallback_by_target: list[dict] = []
    fallback_by_name: list[dict] = []
    if is_signal:
        source_key = _route_node_key(source)
        target_key = _route_node_key(target)

        def _framework_reaches(framework: dict, endpoint_key: str) -> bool:
            if not endpoint_key:
                return False
            last_key = _route_node_key(framework.get("last_node", ""))
            if last_key == endpoint_key:
                return True
            return any(
                _route_node_key(item) == endpoint_key
                for item in (framework.get("matched_targets") or [])
            )

        source_frameworks = [
            framework for framework in all_frameworks
            if _framework_reaches(framework, source_key)
        ]
        target_frameworks = [
            framework for framework in all_frameworks
            if _framework_reaches(framework, target_key)
        ]
        if task.source_is_external_component:
            if not source or not target:
                task.input_mapping_conflicts.append(
                    "DFD外部部件Source缺少Source或Target端点，禁止生成伪造攻击路径"
                )
                with ctx.shared('_filter_framework_cache_lock'):
                    ctx.shared('_filter_framework_cache')[cache_key] = (
                        [], list(task.input_mapping_conflicts)
                    )
                return _finish([])

            # DFD 中的 out-of-scope Process/Store（例如外部设备）不是车辆
            # 网络入口。对于“外部部件 → 车内部件”的信号关系，只用 Target
            # 作为路径终点，并从拓扑中选取能承载该 DFD 协议的最短入口路径；
            # 不把外部部件名称伪造成 external_interface，也不把它写成
            # 攻击路径的起始 ECU。这样与 tm.Actor 的外部 Source 规则一致。
            if not task.target_is_external:
                if not target_frameworks:
                    task.input_mapping_conflicts.append(
                        f"DFD外部部件Source[{source}]的Target[{target}]"
                        "未找到可验证拓扑框架"
                    )
                    with ctx.shared('_filter_framework_cache_lock'):
                        ctx.shared('_filter_framework_cache')[cache_key] = (
                            [], list(task.input_mapping_conflicts)
                        )
                    return _finish([])
                target_protocol = task.flow_protocol.strip()
                protocol_frameworks = [
                    framework
                    for framework in target_frameworks
                    if _framework_protocol_matches(framework, target_protocol)
                ] if target_protocol else list(target_frameworks)
                if target_protocol and not protocol_frameworks:
                    task.input_mapping_conflicts.append(
                        f"DFD外部部件Source[{source}]的协议[{target_protocol}]"
                        f"无法在Target[{target}]的拓扑入口中匹配"
                    )
                    with ctx.shared('_filter_framework_cache_lock'):
                        ctx.shared('_filter_framework_cache')[cache_key] = (
                            [], list(task.input_mapping_conflicts)
                        )
                    return _finish([])
                selected = [
                    {
                        **framework,
                        "is_dfd_signal_binding": True,
                        "signal_source_binding_relaxed": True,
                        "external_component_source": source,
                        "dfd_element_index": task.element_index,
                        "dfd_source": source,
                        "dfd_target": target,
                        "dfd_protocol": target_protocol,
                    }
                    for framework in limit_shortest_frameworks(
                        protocol_frameworks
                    )
                    if not _framework_has_route_cycle(framework)
                ]
                with ctx.shared('_filter_framework_cache_lock'):
                    ctx.shared('_filter_framework_cache')[cache_key] = (
                        selected, list(task.input_mapping_conflicts)
                    )
                return _finish(selected)

            # 只有外部部件→外部部件这类没有车内拓扑终点的关系，才保留
            # 一条不经过接口白名单的逻辑直连框架。它不是普通入口路线，
            # evaluator 会依据 is_external_component_direct 专门校验。
            direct = _external_component_direct_framework(task)
            return _finish([direct])
        if task.source_is_external and (not task.target_is_external):
            if not target or not target_frameworks:
                with ctx.shared('_filter_framework_cache_lock'):
                    ctx.shared('_filter_framework_cache')[cache_key] = ([], [])
                return _finish([])
            protocol = task.flow_protocol.strip()
            # DFD 外部 Actor 只能绑定到 information Excel 已列出的入口
            # interface/start_component；若 Actor 既不等于接口，也不等于
            # 关联入口部件，不能把其它接口线“借给”它。
            # 生产解析器生成的框架总带 external_interface 元数据；旧测试/兼容
            # 调用若完全没有该字段，保留按协议筛选的兼容行为，不把缺失元数据
            # 误报成项目输入冲突。
            has_table_metadata = any(
                _normalize_text(framework.get('external_interface'))
                for framework in target_frameworks
            )
            if has_table_metadata:
                # 外部设备/介质名称可能不等于接口名，此时允许关系边中的
                # protocol 作为绑定证据；最终仍只写入表格中的真实接口。
                source_entries = [source] + list(task.source_external_interfaces or [])
                if protocol:
                    source_entries.append(protocol)
                bound_target_frameworks = [
                    framework
                    for framework in target_frameworks
                    if any(
                        _framework_matches_dfd_entry(framework, entry)
                        for entry in source_entries
                        if _normalize_text(entry)
                    )
                ]
                if not bound_target_frameworks:
                    task.input_mapping_conflicts.append(
                        f'DFD外部接口/入口[{source}]未在information接口清单中绑定到Target[{target}]'
                    )
                    with ctx.shared('_filter_framework_cache_lock'):
                        ctx.shared('_filter_framework_cache')[cache_key] = (
                            [], list(task.input_mapping_conflicts)
                        )
                    return _finish([])
                target_frameworks = bound_target_frameworks
            if protocol:
                # 外部信号的 DFD 协议描述边界段：优先匹配框架外部接口（容忍
                # 写法差异，如“蜂窝通讯”↔“蜂窝信道”），其次匹配末跳协议。
                # source 是 DFD 外部 Actor 时，协议线是唯一的拓扑筛选证据；
                # 没有同协议框架就明确报告映射问题，不能回退到其它接口线。
                protocol_frameworks = [framework for framework in target_frameworks if _framework_protocol_matches(framework, protocol)]
                if not protocol_frameworks:
                    task.input_mapping_conflicts.append(f'DFD信号协议[{protocol}]与拓扑Target[{target}]的外部接口/末跳协议不一致')
                    with ctx.shared('_filter_framework_cache_lock'):
                        ctx.shared('_filter_framework_cache')[cache_key] = (
                            [], list(task.input_mapping_conflicts)
                        )
                    return _finish([])
                target_frameworks = protocol_frameworks
            selected = limit_shortest_frameworks(target_frameworks)
            with ctx.shared('_filter_framework_cache_lock'):
                ctx.shared('_filter_framework_cache')[cache_key] = (selected, [])
            return _finish(selected)
        if task.target_is_external and (not task.source_is_external):
            if not source or not source_frameworks:
                with ctx.shared('_filter_framework_cache_lock'):
                    ctx.shared('_filter_framework_cache')[cache_key] = ([], [])
                return _finish([])
            protocol = task.flow_protocol.strip()
            if protocol:
                # 目标为外部实体：优先选中与 DFD 协议边界段一致的外部接口框架，
                # 无匹配时回退全部（路径仍以内部部件为终点，协议由组合层标注）。
                protocol_frameworks = [framework for framework in source_frameworks if _framework_protocol_matches(framework, protocol)]
                if protocol_frameworks:
                    source_frameworks = protocol_frameworks
            selected = limit_shortest_frameworks(source_frameworks)
            with ctx.shared('_filter_framework_cache_lock'):
                ctx.shared('_filter_framework_cache')[cache_key] = (selected, [])
            return _finish(selected)
        if task.source_is_external and task.target_is_external:
            # 两端都是外部实体（如 APP↔云平台）：仅当 DFD 为端点绑定了外部接口
            # 且该接口存在于拓扑接口集合时才生成直连路径；纯外部间逻辑数据流
            # （如 TSP平台↔手机APP 无接口证据）不应伪造物理攻击路径。
            bound_interfaces = [
                _normalize_text(interface)
                for interface in (task.source_external_interfaces or [])
                if _normalize_text(interface)
            ]
            reachable_interface = any(
                _framework_matches_dfd_entry(framework, interface)
                for interface in bound_interfaces
                for framework in all_frameworks
            )
            if source and target and reachable_interface:
                protocol = task.flow_protocol.strip() or 'DFD数据流'
                bound_frameworks = [
                    framework for framework in all_frameworks
                    if any(
                        _framework_matches_dfd_entry(framework, interface)
                        for interface in bound_interfaces
                    )
                ]
                source_framework = bound_frameworks[0] if bound_frameworks else {}
                attack_vector = normalize_attack_vector(
                    source_framework.get('attack_vector', '')
                ) or normalize_attack_vector(protocol)
                attack_vector_error = _normalize_text(
                    source_framework.get('attack_vector_mapping_error', '')
                )
                if not attack_vector and not attack_vector_error:
                    attack_vector_error = (
                        f"DFD协议[{protocol}]未匹配图片规定的攻击向量映射"
                    )
                direct_fw = {
                    'path_id': hashlib.sha1(f"ext-to-ext|{task.function}|{task.element_index}|{source}|{protocol}|{target}".encode('utf-8')).hexdigest()[:16],
                    'path_description': f"{source} -> [{protocol}] -> {target}",
                    'path_nodes': [source, target],
                    'last_node': target,
                    'second_to_last_node': source,
                    'start_component': source_framework.get('start_component') or source,
                    'external_interface': source_framework.get('external_interface') or source,
                    'components': [source, target],
                    'path_protocols': [protocol],
                    'last_protocol': protocol,
                    'attack_vector': attack_vector,
                    'attack_vector_mapping_error': attack_vector_error,
                    'matched_targets': [target],
                    'framework_set': 1,
                    'is_external_to_external': True,
                    'dfd_element_index': task.element_index,
                    'dfd_source': source,
                    'dfd_target': target,
                    'dfd_protocol': protocol,
                }
                selected = [direct_fw]
                with ctx.shared('_filter_framework_cache_lock'):
                    ctx.shared('_filter_framework_cache')[cache_key] = (selected, list(task.input_mapping_conflicts))
                return _finish(selected)
            if source and target and not reachable_interface:
                task.input_mapping_conflicts.append(
                    f'DFD外部[Source={source}]与外部[Target={target}]未绑定可到达拓扑的外部接口'
                )
            with ctx.shared('_filter_framework_cache_lock'):
                ctx.shared('_filter_framework_cache')[cache_key] = ([], list(task.input_mapping_conflicts))
            return _finish([])
        if not source or not target or (not source_frameworks) or (not target_frameworks):
            # 信号任一端没有经过拓扑/接口清单验证时，禁止用 DFD 节点名
            # 伪造 external_interface 和入口部件。只能明确记录映射冲突，
            # 由状态层输出 TOPOLOGY_UNCOVERED/INPUT_MAPPING_CONFLICT。
            if source and target:
                missing = []
                if not source_frameworks:
                    missing.append(f"Source[{source}]")
                if not target_frameworks:
                    missing.append(f"Target[{target}]")
                task.input_mapping_conflicts.append(
                    "信号未找到可验证拓扑框架：" + "、".join(missing)
                )
            with ctx.shared('_filter_framework_cache_lock'):
                ctx.shared('_filter_framework_cache')[cache_key] = (
                    [], list(task.input_mapping_conflicts)
                )
            return _finish([])
        dfd_interfaces = [interface for interface in task.source_external_interfaces if _normalize_text(interface)]
        if dfd_interfaces:
            direct_source_frameworks = [framework for framework in source_frameworks if framework.get('is_entry_component_path') and (framework.get('last_node') or '').strip() == source]
            if direct_source_frameworks:
                source_frameworks = direct_source_frameworks
                dfd_interfaces = []
        if dfd_interfaces:
            topology_interfaces = {
                key
                for framework in all_frameworks
                for key in (
                    _external_interface_key(framework.get('external_interface', '')),
                    _external_interface_key(framework.get('start_component', '')),
                )
                if key
            }
            matched_source_frameworks = [
                framework
                for framework in source_frameworks
                if any(
                    _framework_matches_dfd_entry(framework, interface)
                    for interface in dfd_interfaces
                )
            ]
            for interface in dfd_interfaces:
                interface_key = _external_interface_key(interface)
                has_topology_binding = any(
                    _framework_matches_dfd_entry(framework, interface)
                    for framework in all_frameworks
                )
                if interface_key not in topology_interfaces and not has_topology_binding:
                    task.input_mapping_conflicts.append(f'DFD外部接口[{interface}]未在拓扑/外部接口Excel中映射')
                elif not any(
                    _framework_matches_dfd_entry(framework, interface)
                    for framework in source_frameworks
                ):
                    task.input_mapping_conflicts.append(f'DFD外部接口[{interface}]在拓扑中无法到达信号Source[{source}]')
            if matched_source_frameworks:
                source_frameworks = matched_source_frameworks
            elif task.input_mapping_conflicts:
                with ctx.shared('_filter_framework_cache_lock'):
                    ctx.shared('_filter_framework_cache')[cache_key] = ([], list(task.input_mapping_conflicts))
                return _finish([])
        protocol = task.flow_protocol.strip() or 'DFD数据流'
        topology_channel_metadata = any(
            "terminal_channel_ids" in framework
            for framework in source_frameworks + target_frameworks
        )
        target_terminal_metadata = _aggregate_terminal_channel_metadata(
            target_frameworks
        )
        binding_target_frameworks = [target_terminal_metadata]
        # Build the route graph once from the same frozen framework evidence.
        # This is what permits a signal to cross two CAN segments through a
        # component attached to both, instead of forcing a synthetic direct
        # Source→Target hop.
        route_graph, route_component_channels, route_display_names = (
            _cached_framework_route_graph(ctx, all_frameworks)
        )
        graph_has_edges = any(
            neighbours for neighbours in route_graph.values()
        )
        shortest_signal_routes = _shortest_signal_routes(
            route_graph,
            route_component_channels,
            route_display_names,
            source,
            target,
            protocol,
        ) if graph_has_edges else []

        if shortest_signal_routes:
            for source_framework in source_frameworks:
                source_nodes = [
                    _normalize_text(node)
                    for node in (source_framework.get("path_nodes") or [])
                    if _normalize_text(node)
                ]
                if not source_nodes or _route_node_key(source_nodes[-1]) != _route_node_key(source):
                    continue
                prefix_keys = {
                    _route_node_key(node) for node in source_nodes[:-1]
                }
                prefix_channels = list(
                    source_framework.get("path_channel_ids") or []
                )
                prefix_protocols = list(
                    source_framework.get("path_protocols") or []
                )
                prefix_links = list(
                    source_framework.get("topology_link_ids") or []
                )
                for route in shortest_signal_routes:
                    route_nodes = list(route.get("nodes") or [])
                    route_edges = list(route.get("edges") or [])
                    if not route_nodes:
                        continue
                    appended_nodes = route_nodes[1:]
                    # A source prefix may already contain the intermediate
                    # node/target.  Combining it would create a loop; try the
                    # next external entry or fall back to a target-bound
                    # shortest framework below.
                    if any(
                        _route_node_key(node) in prefix_keys
                        for node in appended_nodes
                    ):
                        continue
                    full_nodes = source_nodes + appended_nodes
                    if len({
                        _route_node_key(node) for node in full_nodes
                    }) != len(full_nodes):
                        continue
                    continuation_channels = [
                        _normalize_text(edge.get("channel_id"))
                        for edge in route_edges
                    ]
                    continuation_protocols = [
                        _normalize_text(edge.get("protocol")) or protocol
                        for edge in route_edges
                    ]
                    continuation_links = [
                        list(edge.get("topology_link_ids") or [])
                        for edge in route_edges
                    ]
                    full_channels = prefix_channels + continuation_channels
                    full_protocols = prefix_protocols + continuation_protocols
                    full_links = prefix_links + continuation_links
                    path_description = _normalize_text(
                        source_framework.get("path_description")
                    )
                    if not path_description:
                        path_description = source_nodes[0]
                    for node, hop_protocol in zip(
                        appended_nodes, continuation_protocols
                    ):
                        path_description += (
                            f" -> [{hop_protocol or protocol}] -> {node}"
                        )
                    path_id = hashlib.sha1(
                        (
                            f"{source_framework.get('path_id', '')}|"
                            f"{task.element_index}|{source}|{target}|"
                            f"{tuple(full_nodes)}|{tuple(full_channels)}"
                        ).encode("utf-8")
                    ).hexdigest()[:16]
                    selected.append({
                        **source_framework,
                        "path_id": path_id,
                        "path_description": path_description,
                        "path_nodes": full_nodes,
                        "last_node": target,
                        "second_to_last_node": (
                            full_nodes[-2] if len(full_nodes) >= 2 else ""
                        ),
                        "components": full_nodes[1:],
                        "path_protocols": full_protocols,
                        "path_channel_ids": full_channels,
                        "topology_link_ids": full_links,
                        **target_terminal_metadata,
                        "last_protocol": (
                            full_protocols[-1] if full_protocols else ""
                        ),
                        "matched_targets": [target],
                        "is_dfd_signal_binding": True,
                        "signal_source_binding_relaxed": (
                            len(full_nodes) < 2
                            or full_nodes[-2] != source
                        ),
                        "dfd_element_index": task.element_index,
                        "dfd_source": source,
                        "dfd_target": target,
                        "dfd_protocol": protocol,
                    })

        if not selected and not graph_has_edges:
            # Compatibility for historical tests and callers whose manually
            # constructed frameworks predate per-hop channel metadata.
            for source_framework in source_frameworks:
                source_nodes = list(source_framework.get("path_nodes") or [])
                if not source_nodes or source_nodes[-1] != source:
                    continue
                channel_candidates = _signal_binding_channels(
                    source_framework, binding_target_frameworks, protocol
                )
                if not channel_candidates and not topology_channel_metadata:
                    channel_candidates = [("", protocol)]
                for channel_id, channel_protocol in channel_candidates:
                    hop_protocol = channel_protocol or protocol
                    hop_link_ids = _signal_hop_link_ids(
                        source_framework, binding_target_frameworks, channel_id,
                        hop_protocol,
                    ) if channel_id else []
                    path_nodes = source_nodes + [target]
                    if _framework_has_route_cycle({"path_nodes": path_nodes}):
                        continue
                    path_description = (
                        f"{source_framework.get('path_description', '')}"
                        f" -> [{hop_protocol}] -> {target}"
                    )
                    selected.append({
                        **source_framework,
                        "path_id": hashlib.sha1(
                            f"{source_framework.get('path_id', '')}|"
                            f"{task.element_index}|{source}|{channel_id}|{target}"
                            .encode("utf-8")
                        ).hexdigest()[:16],
                        "path_description": path_description,
                        "path_nodes": path_nodes,
                        "last_node": target,
                        "second_to_last_node": source,
                        "components": list(
                            source_framework.get("components") or source_nodes
                        ) + [target],
                        "path_protocols": list(
                            source_framework.get("path_protocols") or []
                        ) + [hop_protocol],
                        "path_channel_ids": list(
                            source_framework.get("path_channel_ids") or []
                        ) + ([channel_id] if channel_id else []),
                        "topology_link_ids": list(
                            source_framework.get("topology_link_ids") or []
                        ) + ([hop_link_ids] if channel_id else []),
                        **target_terminal_metadata,
                        "last_protocol": hop_protocol,
                        "matched_targets": [target],
                        "is_dfd_signal_binding": True,
                        "dfd_element_index": task.element_index,
                        "dfd_source": source,
                        "dfd_target": target,
                        "dfd_protocol": protocol,
                    })

        if not selected:
            # If every Source→Target combination would revisit a component
            # (e.g. an entry path reaches CEM before a BCU→CEM flow), the
            # signal rule is intentionally relaxed: retain the shortest
            # trusted routes that reach the DFD Target.  The target is the
            # security-relevant endpoint; Source is no longer required to be
            # the penultimate node or even to appear in the final route.
            target_candidates = [
                framework
                for framework in target_frameworks
                if not _framework_has_route_cycle(framework)
                and (
                    not protocol
                    or _is_unspecified_protocol(framework.get("last_protocol"))
                    or _same_protocol(framework.get("last_protocol"), protocol)
                )
            ]
            if target_candidates:
                selected = [
                    {
                        **framework,
                        "is_dfd_signal_binding": True,
                        "signal_source_binding_relaxed": True,
                        "dfd_element_index": task.element_index,
                        "dfd_source": source,
                        "dfd_target": target,
                        "dfd_protocol": protocol,
                    }
                    for framework in limit_shortest_frameworks(target_candidates)
                ]
        if topology_channel_metadata and not selected:
            source_summary = _terminal_channel_summary(source_frameworks[0]) if source_frameworks else "（无）"
            target_summary = _terminal_channel_summary(target_terminal_metadata)
            task.input_mapping_conflicts.append(
                f'DFD信号协议无法匹配两端挂接：Source[{source}]挂接[{source_summary}]，'
                f'Target[{target}]挂接[{target_summary}]，DFD协议[{protocol}]；'
                f'Source与Target两端均未找到与该协议一致的挂接'
            )
        selected = limit_shortest_frameworks(selected)
        with ctx.shared('_filter_framework_cache_lock'):
            ctx.shared('_filter_framework_cache')[cache_key] = (selected, list(task.input_mapping_conflicts))
        return _finish(selected)
    for fw in all_frameworks:
        matched = fw.get('matched_targets', [])
        target_ok = bool(matched) and target in matched
        if not target_ok:
            last_node = (fw.get('last_node') or '').strip()
            target_ok = bool(target) and last_node == target
        if target_ok:
            selected.append(fw)
        elif not is_signal:
            if target and target in fw.get('path_description', ''):
                fallback_by_target.append(fw)
            elif task.asset_name and task.asset_name in fw.get('path_description', ''):
                fallback_by_name.append(fw)
    if not selected:
        if fallback_by_target:
            selected = fallback_by_target
        elif fallback_by_name:
            selected = fallback_by_name
    if not selected and target and (not is_signal):
        parent = target.split('-')[0].split('_')[0] if '-' in target or '_' in target else ''
        if parent:
            for fw in all_frameworks:
                last_node = (fw.get('last_node') or '').strip()
                if last_node == parent:
                    selected.append(fw)
        if not selected and task.asset_type == "部件":
            # 部件资产在拓扑中找不到任何匹配框架，按外部组件处理：生成自我攻击路径。
            # 数据资产不能伪造“部件自身”路径；其 target 必须先由 DFD
            # 连接边解析为真实部件，并且该部件确实存在可达拓扑框架。
            synthetic_name = target or task.asset_name.strip() or task.element_index
            self_path = {
                'path_id': hashlib.sha1(f'part-uncovered|{task.function}|{task.element_index}|{synthetic_name}'.encode('utf-8')).hexdigest()[:16],
                'path_description': f'[{synthetic_name}]',
                'path_nodes': [synthetic_name],
                'last_node': synthetic_name,
                'second_to_last_node': '',
                'start_component': synthetic_name,
                'external_interface': synthetic_name,
                'components': [synthetic_name],
                'attack_vector': 'physical',
                'matched_targets': [synthetic_name],
                'framework_set': 1,
                'is_uncovered_part': True,
            }
            selected = [self_path]
    selected = limit_shortest_frameworks(selected)
    with ctx.shared('_filter_framework_cache_lock'):
        ctx.shared('_filter_framework_cache')[cache_key] = (selected, list(task.input_mapping_conflicts))
    return _finish(selected)

def _attack_entry_signature(ctx: RuntimeContext, framework: dict) -> str:
    """入口技术仅按真实入口、起始部件和攻击向量复用，不混用目标语义。"""
    path_nodes = framework.get('path_nodes') or []
    start_component = framework.get('start_component') or (path_nodes[0] if path_nodes else '')
    payload = {'external_interface': _normalize_text(framework.get('external_interface')).lower(), 'start_component': _normalize_text(start_component).lower(), 'attack_vector': normalize_attack_vector(framework.get('attack_vector', ''))}
    return hashlib.sha256(orjson.dumps(payload, option=orjson.OPT_SORT_KEYS)).hexdigest()[:24]

def _entry_action_mentions_interface(ctx: RuntimeContext, external_interface: str, entry_action: str) -> bool:
    """识别具体接口及常见等价叫法，避免拼接后重复入口前缀。"""
    interface = _normalize_text(external_interface).lower()
    action = _normalize_text(entry_action).lower()
    if not interface or not action:
        return False
    if _route_token_in_text(action, interface):
        return True
    aliases = {'蜂窝': ('蜂窝网络', '蜂窝信道', '4g', '5g', 'lte'), '蓝牙': ('蓝牙', 'bluetooth', 'ble'), 'wifi': ('wifi', 'wi-fi', 'wlan', '无线局域网'), '射频': ('射频', 'rf', '遥控钥匙'), 'obd': ('obd', '诊断接口', '诊断口'), 'usb': ('usb', '移动介质'), '充电': ('充电口', '充电接口'), '卫星': ('卫星定位', 'gnss', 'gps')}
    for (marker, equivalents) in aliases.items():
        if marker in interface and any((alias in action for alias in equivalents)):
            return True
    return False


def _entry_action_mentions_component(start_component: str, entry_action: str) -> bool:
    """入口动作是否明确包含拓扑框架规定的起始部件。"""
    component = _normalize_text(start_component).lower()
    action = _normalize_text(entry_action).lower()
    return bool(component and action and component in action)


def _entry_action_suffix(entry_action: str) -> str:
    """仅保留模型入口动作中接口/部件绑定之后的技术描述。

    首行的真实入口前缀由代码写入，模型只能提供逗号后的技术语义；
    没有明确分隔的整句不直接使用，避免把模型臆造的接口名带入报告。
    """
    parts = re.split(r"[，,；;：:]", _normalize_text(entry_action), maxsplit=1)
    if len(parts) != 2:
        return ""
    suffix = _plain_attack_text(None, parts[1])
    return suffix.strip(" ，,；;：:")


def _entry_action_mentions_foreign_table_interface(
    framework: dict, expected_interface: str, entry_action: str
) -> bool:
    """模型入口动作是否额外提及了本项目白名单中的其它接口。"""
    action = _normalize_text(entry_action).lower()
    expected = _normalize_text(expected_interface).lower()
    expected_key = _external_interface_key(expected)
    if not action:
        return False
    for candidate in framework.get("project_external_interfaces") or []:
        candidate_text = _normalize_text(candidate).lower()
        candidate_key = _external_interface_key(candidate_text)
        if (
            candidate_text
            and candidate_text != expected
            and candidate_key
            and candidate_key != expected_key
            and candidate_text in action
        ):
            return True
    return False

def _normalize_target_action(ctx: RuntimeContext, value: Any) -> str:
    """移除模型误带的入口/路由前缀，只保留针对目标资产的最终动作。"""
    action = _normalize_text(value)
    action = re.sub('^\\s*\\d+\\s*[.、)]\\s*', '', action)
    action = re.sub('^\\s*攻击者\\s*', '', action)
    prefix_patterns = ('^(?:通过|利用|经由|借助|从)\\s*[^，,；;。]{0,32}?(?:接口|信道|网络)\\s*', '^(?:通过|利用|经由|借助|从)\\s*\\[[^\\]]+\\]\\s*')
    for pattern in prefix_patterns:
        stripped = re.sub(pattern, '', action, count=1)
        if stripped != action:
            action = stripped.lstrip('，,；;：: ')
            break
    return action.strip()

def _plain_attack_text(ctx: RuntimeContext, value: Any) -> str:
    """清除内部框架标记，报告只保留自然语言名称。"""
    text = _normalize_text(value)
    text = re.sub('[\\[\\]【】]', '', text)
    text = re.sub('\\s*(?:->|→|➡|➜)\\s*', '至', text)
    return re.sub('\\s+', ' ', text).strip()

def _plain_attack_path_text(ctx: RuntimeContext, value: Any) -> str:
    """清理攻击路径展示标记，同时保留步骤换行。"""
    return '\n'.join((cleaned for line in str(value or '').splitlines() if (cleaned := _plain_attack_text(ctx, line))))

def _framework_route_tokens(ctx: RuntimeContext, framework: dict) -> list[str]:
    """从可信框架提取按序的接口、部件和协议名称。"""
    description = _normalize_text(framework.get('path_description'))
    tokens = [_plain_attack_text(ctx, token) for token in re.split('\\s*(?:->|→|➡|➜)\\s*', description) if _plain_attack_text(ctx, token)]
    if tokens:
        return tokens
    interface = _plain_attack_text(ctx, framework.get('external_interface'))
    nodes = [_plain_attack_text(ctx, node) for node in framework.get('path_nodes') or [] if _plain_attack_text(ctx, node)]
    return ([interface] if interface else []) + nodes

def _framework_route_sentence(ctx: RuntimeContext, framework: dict) -> str:
    """将内部箭头框架渲染为不含标记的可信链路摘要。

    此函数只用于旧兼容组合链；正式生产链由模型根据 ``topology_route``
    直接撰写完整步骤，不能把这里的摘要当作攻击技术文本。
    """
    tokens = _framework_route_tokens(ctx, framework)
    if not tokens:
        return '攻击者在已取得访问权限的可信通信链路上实施后续操作'
    if len(tokens) == 1:
        return f'攻击者利用{tokens[0]}实施攻击'
    sentence = f'攻击者通过{tokens[0]}取得{tokens[1]}的访问权限'
    index = 2
    while index < len(tokens):
        if index + 1 < len(tokens):
            sentence += f'，再经{tokens[index]}与{tokens[index + 1]}通信'
            index += 2
        else:
            sentence += f'，并利用{tokens[index]}通信链路'
            index += 1
    return sentence


def _framework_route_steps(ctx: RuntimeContext, framework: dict) -> list[str]:
    """为模型不可用时生成最小化、逐跳且非模板化的可信路线步骤。

    该兜底不试图替代模型的攻击语义，只确保报告仍能表达真实拓扑关系，
    并避免旧版“传递恶意载荷 / 到达节点”的空泛句式。
    """
    tokens = _framework_route_tokens(ctx, framework)
    if len(tokens) <= 2:
        return []
    current_component = tokens[1]
    steps: list[str] = []
    index = 2
    while index + 1 < len(tokens):
        protocol = tokens[index]
        next_component = tokens[index + 1]
        steps.append(
            f'攻击者滥用{current_component}已建立的访问权限，经{protocol}'
            f'构造并发送伪造通信请求，使{next_component}处理该请求'
        )
        current_component = next_component
        index += 2
    if index < len(tokens):
        steps.append(
            f'攻击者在{current_component}上利用{tokens[index]}通信链路维持受控会话'
        )
    return steps

def _fallback_entry_action(ctx: RuntimeContext, item: dict) -> str:
    interface = item.get('external_interface') or '外部接口'
    start = item.get('start_component') or '入口部件'
    vector = normalize_attack_vector(item.get('attack_vector', ''))
    technique = {
        'network': '利用暴露的服务或协议缺陷建立远程受控会话',
        'adjacent': '绕过邻近无线认证并建立受控会话',
        'local': '滥用本地诊断会话或介质处理链取得受控访问',
        'physical': '通过物理接触调试或硬件接口取得受控访问',
    }.get(vector, '利用接口协议缺陷建立受控访问')
    return f'通过{_plain_attack_text(ctx, interface)}接入{_plain_attack_text(ctx, start)}，{technique}'

def _fallback_target_action(ctx: RuntimeContext, task: TaskUnit) -> str:
    # 兜底动作必须只覆盖当前安全属性，避免模型失败时把机密性扩展成
    # 后续完整性/可用性攻击或未经输入支持的严重事故。
    templates = {
        '机密性': f'读取并导出资产{task.asset_name}处理或存储的敏感数据，导致{task.asset_name}的机密性被破坏',
        '完整性': f'篡改资产{task.asset_name}的数据、参数或控制逻辑，导致{task.asset_name}的完整性被破坏',
        '可用性': f'阻断资产{task.asset_name}的通信或耗尽其处理资源，导致{task.asset_name}的可用性被破坏',
        '真实性': f'伪造资产{task.asset_name}的身份、数据来源或控制报文，导致{task.asset_name}的真实性被破坏',
        '不可抵赖性': f'删除或篡改资产{task.asset_name}的审计与操作记录，导致{task.asset_name}的不可抵赖性被破坏',
        '权限属性': f'绕过资产{task.asset_name}的授权检查并执行未授权操作，导致{task.asset_name}的权限属性被破坏',
    }
    return templates.get(
        task.attribute_name,
        f'针对资产{task.asset_name}实施{task.threat_type}攻击，导致{task.asset_name}的{task.attribute_name}被破坏',
    )


def _target_action_matches_attribute(task: TaskUnit, action: str) -> bool:
    """拒绝把目标动作写成跨安全属性的复合攻击或泛化后果。"""
    text = _normalize_text(action).lower()
    if not text:
        return False
    rules = {
        '机密性': (
            ('读取', '复制', '窃取', '导出', '泄露', '获取', '访问', '监听', '截获', '提取'),
            ('篡改', '修改', '注入', '阻断', '干扰', '热失控', '动力中断', '人身伤害', '制定针对性'),
        ),
        '完整性': (('篡改', '修改', '注入', '覆盖', '伪造', '替换', '重写', '植入'), ('窃取', '泄露', '阻断')),
        '可用性': (('阻断', '删除', '耗尽', '拒绝服务', '不可用', '中断', '丢弃', '无法处理', '无法响应', '异常终止', '崩溃'), ('窃取', '泄露', '伪造身份')),
        '真实性': (('伪造', '冒充', '欺骗', '冒用', '伪装', '重放'), ('窃取', '泄露', '阻断')),
        '不可抵赖性': (('日志', '审计', '操作记录', '追溯', '删除', '篡改', '伪造'), ('热失控', '人身伤害')),
        '权限属性': (('绕过', '提升权限', '越权', '授权检查', '未授权', '未经授权', '未获授权', '提权', '非法访问'), ('窃取', '泄露', '热失控')),
    }
    required, forbidden = rules.get(task.attribute_name, ((), ()))
    if any(marker in text for marker in forbidden):
        return False
    return not required or any(marker in text for marker in required)

def _call_attack_entry_chunk(ctx: RuntimeContext, items: list[dict]) -> dict[str, str]:
    """一次 LLM 调用生成一批去重入口技术，并按短ID严格对齐。"""
    prompt_items = [{'id': f'E{index}', 'external_interface': item['external_interface'], 'start_component': item['start_component'], 'attack_vector': item['attack_vector']} for (index, item) in enumerate(items, start=1)]
    user_prompt = f'请为以下 {len(prompt_items)} 个真实攻击入口分别生成初始访问技术：\n' + orjson.dumps(prompt_items).decode('utf-8') + '\n必须返回完全相同的id，且entries数量与输入一致。'
    expected_ids = [item['id'] for item in prompt_items]
    response_format = {'type': 'json_schema', 'json_schema': {'name': 'tara_attack_entry_batch', 'strict': True, 'schema': {'type': 'object', 'properties': {'entries': {'type': 'array', 'minItems': len(items), 'maxItems': len(items), 'items': {'type': 'object', 'properties': {'id': {'type': 'string', 'enum': expected_ids}, 'entry_action': {'type': 'string', 'minLength': 8, 'maxLength': 160}}, 'required': ['id', 'entry_action'], 'additionalProperties': False}}}, 'required': ['entries'], 'additionalProperties': False}}}
    system_prompt = ctx.setting('ATTACK_ENTRY_SYSTEM_PROMPT', ATTACK_ENTRY_SYSTEM_PROMPT)
    ctx.service('_increment_pipeline_metric')('attack_entry_model_calls')
    attack_entry_tokens = ctx.service('_dynamic_token_budget')('attack_entry', len(items), include_reasons=False, system_prompt=system_prompt, user_prompt=user_prompt, record=True)
    raw = ctx.service('llm_call_with_semaphore')(system_prompt, user_prompt, max_tokens=attack_entry_tokens, response_format=response_format)
    try:
        parsed = safe_parse_json(raw)
    except Exception:
        return {}
    entries = parsed.get('entries', []) if isinstance(parsed, dict) else []
    if not isinstance(entries, list):
        return {}
    by_id: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        entry_id = str(entry.get('id', '')).strip()
        action = _normalize_text(entry.get('entry_action'))
        if entry_id in expected_ids and entry_id not in by_id and action:
            by_id[entry_id] = action
    if not by_id and len(entries) == len(items):
        ordered = [_normalize_text(entry.get('entry_action')) if isinstance(entry, dict) else '' for entry in entries]
    else:
        ordered = [by_id.get(entry_id, '') for entry_id in expected_ids]
    return {item['signature']: action for (item, action) in zip(items, ordered) if action}

def _attack_entry_cache_key(ctx: RuntimeContext, item: dict) -> dict:
    system_prompt = ctx.setting('ATTACK_ENTRY_SYSTEM_PROMPT', ATTACK_ENTRY_SYSTEM_PROMPT)
    return {'schema': 'hybrid-attack-entry-v1', 'model': ctx.setting('MODEL_NAME'), 'temperature': ctx.setting('TEMPERATURE'), 'seed': ctx.setting('SAMPLING_SEED'), 'top_p': ctx.setting('TOP_P'), 'top_k': ctx.setting('TOP_K'), 'frequency_penalty': ctx.setting('FREQUENCY_PENALTY'), 'presence_penalty': ctx.setting('PRESENCE_PENALTY'), 'system_prompt_sha256': hashlib.sha256(system_prompt.encode('utf-8')).hexdigest(), 'signature': item['signature']}

def _prepare_attack_entry_catalog(ctx: RuntimeContext, tasks: list[TaskUnit]) -> dict[str, str]:
    """全运行去重入口技术；每个精确入口签名只生成和缓存一次。"""
    unique: dict[str, dict] = {}
    for task in tasks:
        for framework in task.selected_path_frameworks:
            if framework.get("is_external_component_direct"):
                continue
            signature = _attack_entry_signature(ctx, framework)
            path_nodes = framework.get('path_nodes') or []
            unique.setdefault(signature, {'signature': signature, 'external_interface': _normalize_text(framework.get('external_interface')) or '外部接口', 'start_component': _normalize_text(framework.get('start_component') or (path_nodes[0] if path_nodes else '')) or '入口部件', 'attack_vector': normalize_attack_vector(framework.get('attack_vector', ''))})
    catalog: dict[str, str] = {}
    sources: dict[str, str] = {}
    missing: list[dict] = []
    for item in unique.values():
        cached = ctx.shared('semantic_cache').get('attack_entry_technique', _attack_entry_cache_key(ctx, item))
        if isinstance(cached, str) and cached.strip():
            catalog[item['signature']] = cached.strip()
            sources[item['signature']] = 'cache'
        else:
            missing.append(item)
    chunks = [missing[start:start + ctx.setting('ATTACK_PATH_TASKS_PER_CALL')] for start in range(0, len(missing), ctx.setting('ATTACK_PATH_TASKS_PER_CALL'))]
    ctx.service('_set_pipeline_metric')('attack_entry_unique_signatures', len(unique))
    ctx.service('_set_pipeline_metric')('attack_entry_cache_hits', len(unique) - len(missing))
    ctx.service('_set_pipeline_metric')('attack_entry_batches_planned', len(chunks))
    if chunks:
        executor = ctx.service('get_attack_path_executor')()
        futures = {
            ctx.service('_submit_pipeline')(
                executor, ctx.service('_call_attack_entry_chunk'), chunk
            ): chunk
            for chunk in chunks
        }
        for future in as_completed(futures):
            chunk = futures[future]
            try:
                generated = future.result()
            except Exception as exc:
                logger.warning('攻击入口技术批次异常: %s', exc)
                generated = {}
            for item in chunk:
                action = _normalize_text(generated.get(item['signature']))
                if not action:
                    action = _fallback_entry_action(ctx, item)
                    sources[item['signature']] = 'fallback'
                else:
                    sources[item['signature']] = 'model'
                catalog[item['signature']] = action
                if item['signature'] in generated:
                    ctx.shared('semantic_cache').set('attack_entry_technique', _attack_entry_cache_key(ctx, item), action)
    ctx.set_shared('attack_entry_action_sources', sources)
    logger.info('混合攻击路径入口目录: %d 个唯一入口，%d 个缓存命中，%d 次批量调用', len(unique), len(unique) - len(missing), len(chunks))
    return catalog

def _target_action_cache_key(ctx: RuntimeContext, task: TaskUnit, rag_context: str) -> dict:
    system_prompt = ctx.setting('ATTACK_TARGET_SYSTEM_PROMPT', ATTACK_TARGET_SYSTEM_PROMPT)
    return stage_key(ctx, task, 'target_action', system_prompt,
                     parents={'scenarios': scenario_reference(task)},
                     knowledge={'attack_path': knowledge_entries(rag_context)})


def _direct_attack_path_item_cache_key(ctx, task, framework, rag_context):
    return stage_key(ctx, task, 'attack_path',
                     ctx.setting('ATTACK_PATH_SYSTEM_PROMPT', ATTACK_PATH_SYSTEM_PROMPT),
                     parents={'scenarios': scenario_reference(task)}, frameworks=[framework],
                     knowledge={'attack_path': knowledge_entries(rag_context)})


def _direct_attack_path_cache_key(
    ctx: RuntimeContext,
    task: TaskUnit,
    frameworks: list[dict],
    rag_context: str,
) -> dict:
    """Whole-task compatibility cache; individual routes are checked first."""
    key = stage_key(ctx, task, 'attack_paths',
                    ctx.setting('ATTACK_PATH_SYSTEM_PROMPT', ATTACK_PATH_SYSTEM_PROMPT),
                    parents={'scenarios': scenario_reference(task)}, frameworks=frameworks,
                    knowledge={'attack_path': knowledge_entries(rag_context)})
    # Group values are bound by path_id. The separate route-item cache remaps
    # these transient IDs safely when topology enumeration changes.
    key['bindings'] = [str(framework.get('path_id', '')) for framework in frameworks]
    return key


def _attack_path_provenance(
    ctx: RuntimeContext,
    framework: dict,
    source: str,
    reason: str = "",
) -> dict[str, str]:
    """Build stable per-path provenance for reports and paper experiments."""
    evidence = {
        "path_id": _normalize_text(framework.get("path_id")),
        "route": _framework_route_tokens(ctx, framework),
        "channel_ids": list(framework.get("path_channel_ids", []) or []),
        "topology_link_ids": list(framework.get("topology_link_ids", []) or []),
        "external_interface": _normalize_text(framework.get("external_interface")),
        "start_component": _normalize_text(framework.get("start_component")),
        "attack_vector": normalize_attack_vector(framework.get("attack_vector", "")),
    }
    digest = hashlib.sha256(
        orjson.dumps(evidence, option=orjson.OPT_SORT_KEYS)
    ).hexdigest()
    return {
        "path_id": evidence["path_id"],
        "generation_source": source,
        "fallback_reason": reason,
        "framework_sha256": digest,
    }


def _direct_attack_path_response_format(_task_count: int) -> dict:
    """为完整路径提供宽松的可解析 JSON 外壳。

    这里不再把任务数、路径数、文本长度当作模型质量门禁。vLLM 只需
    返回可解析的 ``items/task_id/paths/path_id/attack_path`` 字段；遗漏
    的任务或路径会在调用方限量拆批重试；仍缺失则标记 MODEL_FAILED，
    不会用可信拓扑拼装一条伪称由模型生成的路径。
    """
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "tara_direct_attack_path_batch",
            "strict": True,
            "schema": {
                "type": "object",
                "properties": {
                    "items": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "task_id": {"type": "string"},
                                "paths": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "path_id": {"type": "string"},
                                            "attack_path": {
                                                "type": "string",
                                            },
                                        },
                                        "required": ["path_id", "attack_path"],
                                        "additionalProperties": False,
                                    },
                                },
                            },
                            "required": ["task_id", "paths"],
                            "additionalProperties": False,
                        },
                    }
                },
                "required": ["items"],
                "additionalProperties": False,
            },
        },
    }


_DIRECT_PATH_FORMAT_MISSING = object()


def _normalize_direct_attack_path_format(
    ctx_or_value: RuntimeContext | Any,
    value: Any = _DIRECT_PATH_FORMAT_MISSING,
) -> str:
    """恢复模型偶发省略的步骤换行，不改写攻击语义或拓扑名称。

    vLLM 的 JSON Schema 只能保证 ``attack_path`` 是字符串，不能约束
    字符串内部的换行。部分模型会返回 ``1. ...2. ...3. ...``；这里仅在
    后续编号前补换行，并把字面量 ``\\n`` 转成真正换行，改善报告可读性，
    不以格式差异拒绝模型正文。
    """
    # 该函数也通过 pipeline 的兼容委托导出；委托会自动注入 ctx，内部
    # 调用则只传 value，因此同时兼容两种签名。
    if value is _DIRECT_PATH_FORMAT_MISSING:
        value = ctx_or_value
    text = str(value or "").replace("\\r\\n", "\n").replace("\\n", "\n")
    # 展示层统一使用自然语言，去掉模型偶尔带出的内部框架标记；这只是
    # 文本清理，不会验证、拒绝或重试路径。
    text = re.sub(r"[\[\]【】]", "", text)
    text = re.sub(r"\s*(?:->|→|➡|➜)\s*", "至", text)
    # 编号可能紧跟上一句，也可能由空格分隔；只识别 2～99 的步骤号，
    # 且编号后不能直接跟数字，避免误拆版本号、百分比或协议参数中的
    # 小数。部分模型会省略编号后的空格，因此这里允许无空格形式。
    text = re.sub(
        r"(?<!\n)(?=(?:[2-9]|[1-9][0-9])\.(?!\s*\d))",
        "\n",
        text,
    )
    # 模型偶尔会重复编号（例如 1、2、2、4）。编号属于展示格式，不应
    # 因此影响路径写回；逐行去掉模型编号后重新连续编号，攻击语义和
    # 拓扑名称保持不变。
    lines: list[str] = []
    for line in text.splitlines():
        line = re.sub(r"^\s*\d+\s*[.、)]\s*", "", line).strip()
        if line:
            lines.append(f"{len(lines) + 1}. {line}")
    return "\n".join(lines)


_PATH_HOP_ATTACK_MARKERS = (
    "利用", "构造", "注入", "伪造", "重放", "篡改", "修改", "劫持",
    "绕过", "写入", "滥用", "触发", "诊断", "入侵", "替换",
    "阻断", "干扰", "中间人", "漏洞", "攻击报文", "攻击请求",
)
_PATH_RESULT_MARKERS = (
    "导致", "造成", "致使", "从而", "使得", "被破坏", "受损", "失去",
    "泄露", "无法", "不可用", "失真", "错误", "不一致",
)
_PATH_AUTHORIZATION_OUTCOMES = (
    "越权", "提权", "提升权限", "权限提升", "绕过授权",
    "未授权访问", "未经授权访问", "非法访问",
)


def _direct_path_quality_issue(
    ctx: RuntimeContext,
    task: TaskUnit,
    framework: dict,
    path: str,
) -> str:
    """只依据可信路线和任务属性验收模型正文，不生成或改写攻击内容。"""
    route = _framework_route_tokens(ctx, framework)
    lines = [
        re.sub(r"^\s*\d+\s*[.、)]\s*", "", line).strip()
        for line in str(path or "").splitlines()
        if line.strip()
    ]
    external_self = bool(framework.get("is_external_actor_self"))
    external_to_external = bool(framework.get("is_external_to_external"))
    if external_self:
        if len(route) != 1 or len(lines) != 2:
            return "external_actor_path_structure_mismatch"
        if _find_exact_route_token(lines[0], route[0]) < 0:
            return "external_actor_entry_missing"
    elif external_to_external:
        if len(route) != 3 or len(lines) != 2:
            return "external_flow_path_structure_mismatch"
        source_pos = _find_exact_route_token(lines[0], route[0])
        protocol_pos = _find_route_token(lines[0], route[1])
        target_pos = _find_exact_route_token(
            lines[0], route[2],
            source_pos + len(route[0]) if source_pos >= 0 else 0,
        )
        if min(source_pos, protocol_pos, target_pos) < 0:
            return "external_flow_node_or_protocol_missing"
    else:
        if len(route) < 2 or len(route) % 2:
            return "topology_route_has_no_ecu_chain"
        hop_count = (len(route) - 2) // 2
        if len(lines) != hop_count + 2:
            return "one_segment_per_ecu_hop_required"
        interface_pos = _find_route_token(lines[0], route[0])
        start_pos = _find_exact_route_token(
            lines[0], route[1],
            _route_token_match_end(lines[0], route[0], interface_pos)
            if interface_pos >= 0 else 0,
        )
        if interface_pos < 0 or start_pos < 0:
            return "external_interface_to_entry_ecu_missing"
        for hop in range(hop_count):
            line = lines[hop + 1]
            source, protocol, target = route[1 + 2 * hop:4 + 2 * hop]
            source_pos = _find_exact_route_token(line, source)
            protocol_pos = _find_route_token(line, protocol)
            target_pos = _find_exact_route_token(
                line, target,
                source_pos + len(source) if source_pos >= 0 else 0,
            )
            if min(source_pos, protocol_pos, target_pos) < 0:
                return f"ecu_hop_{hop + 1}_node_or_protocol_missing"
            if not any(marker in line for marker in _PATH_HOP_ATTACK_MARKERS):
                return f"ecu_hop_{hop + 1}_attack_technique_missing"
    if not any(marker in lines[0] for marker in _PATH_HOP_ATTACK_MARKERS):
        return "initial_access_technique_missing"
    terminal = _normalize_text(framework.get("last_node")) or route[-1]
    if _name_match_key(terminal) != _name_match_key(route[-1]):
        return "topology_terminal_mismatch"
    if task.asset_type == "数据" and task.target and (
        _name_match_key(terminal) != _name_match_key(task.target)
    ):
        return "data_storage_ecu_mismatch"
    if task.asset_type == "信号" and task.target and not task.target_is_external and (
        _name_match_key(terminal) != _name_match_key(task.target)
    ):
        return "signal_receiver_ecu_mismatch"

    outcome = lines[-1]
    if _find_exact_route_token(outcome, terminal) < 0:
        return "outcome_terminal_ecu_missing"
    asset = _normalize_text(task.asset_name)
    if asset and asset.casefold() not in _normalize_text(outcome).casefold():
        return "outcome_asset_missing"
    if task.attribute_name != "权限属性" and any(
        marker in outcome for marker in _PATH_AUTHORIZATION_OUTCOMES
    ):
        return "wrong_attribute_authorization_outcome"
    if not _target_action_matches_attribute(task, outcome):
        return "outcome_attribute_mismatch"
    if not any(marker in outcome for marker in _PATH_RESULT_MARKERS):
        return "outcome_consequence_missing"
    return ""


def _canonical_path_id(value: Any, expected_ids: set[str] | None = None) -> str:
    """按路径 ID 做保守规范化，兼容模型偶发的大写/空白差异。

    ``path_id`` 是代码根据拓扑框架计算出的十六进制标识，不应该使用
    模糊的子串匹配。只有在大小写折叠后唯一对应时才接受，避免把一条
    路径错误绑定到另一条路径。
    """
    raw = _normalize_text(value)
    if not raw:
        return ""
    if not expected_ids:
        return raw
    if raw in expected_ids:
        return raw
    folded = raw.casefold()
    matches = [item for item in expected_ids if item.casefold() == folded]
    return matches[0] if len(matches) == 1 else ""


def _salvage_single_task_path_items(
    raw: str,
    task_id: str,
    expected_path_ids: set[str],
) -> dict[str, str]:
    """Recover complete, individually valid path objects from a broken array.

    A malformed final item should not discard already-complete path objects.
    This is deliberately limited to one expected task: the task identity is
    then unambiguous, while each recovered path still must carry an exact
    expected ``path_id``.
    """
    match = re.search(r'"(?:paths|attack_paths)"\s*:\s*\[', raw or "")
    if match is None or not expected_path_ids:
        return {}

    decoder = json.JSONDecoder()
    position = match.end()
    recovered: dict[str, str] = {}
    while position < len(raw):
        while position < len(raw) and raw[position].isspace():
            position += 1
        if position >= len(raw) or raw[position] == "]":
            break
        if raw[position] == ",":
            position += 1
            continue
        try:
            item, next_position = decoder.raw_decode(raw, position)
        except (json.JSONDecodeError, TypeError, ValueError):
            break
        if not isinstance(item, dict):
            break
        position = next_position
        path_id = _canonical_path_id(item.get("path_id"), expected_path_ids)
        path_text = item.get("attack_path")
        if path_text is None:
            path_text = item.get("path", item.get("description", item.get("text")))
        if (
            path_id
            and path_id not in recovered
            and isinstance(path_text, str)
            and path_text.strip()
        ):
            recovered[path_id] = path_text.strip()
    return recovered


def _run_bounded_path_retry_jobs(
    ctx: RuntimeContext,
    jobs: list[Any],
    worker: Callable[[Any], Any],
) -> list[Any]:
    """Run repair calls concurrently on the dedicated, globally bounded pool."""
    if not jobs:
        return []
    try:
        executor = ctx.service("get_attack_path_retry_executor")()
    except RuntimeError:
        # Lightweight stage tests and older custom RuntimeContexts can retain
        # deterministic serial behavior without constructing infrastructure.
        executor = None
    if executor is None or len(jobs) == 1:
        return [worker(job) for job in jobs]

    results: list[Any] = []
    # Bound queued work per producer; the process-wide executor and the common
    # LLM semaphore provide the outer concurrency limits.
    for start in range(0, len(jobs), 8):
        futures = [executor.submit(worker, job) for job in jobs[start : start + 8]]
        for future in as_completed(futures):
            results.append(future.result())
    return results


def _direct_paths_from_response(
    raw: str,
    expected_task_ids: set[str],
    *,
    expected_path_ids_by_task: dict[str, set[str]] | None = None,
    diagnostics: dict[str, int | str] | None = None,
) -> dict[str, dict[str, str]]:
    """解析完整攻击路径回复并按 ``task_id/path_id`` 保守关联。

    生产模型通常遵循 ``{"items": [{"task_id", "paths"}]}``，但不同
    OpenAI 兼容服务或微调模型可能返回 ``results``/``data`` 外壳、顶层
    数组、``attack_paths`` 字段，或把路径 ID 写成大写。这里仅兼容这些
    等价结构；节点、协议和路径正文仍不做猜测，无法唯一关联的内容只
    能重试模型，最终失败时不得写入攻击路径。
    """
    stats = diagnostics if diagnostics is not None else {}
    stats.setdefault("raw_chars", len(raw or ""))
    if not isinstance(raw, str) or not raw.strip() or raw.strip() in {"{}", "[]"}:
        stats["empty_body"] = 1
        return {}
    try:
        parsed = safe_parse_json(raw)
    except Exception:
        # 单路径请求的纯文本可唯一归属到该任务/路径；批量请求仍必须
        # 保留结构化 ID，不能把一段正文猜测分配给别的资产。
        only_task = next(iter(expected_task_ids)) if len(expected_task_ids) == 1 else ""
        only_paths = (expected_path_ids_by_task or {}).get(only_task, set())
        if len(only_paths) == 1 and not raw.lstrip().startswith(("{", "[")):
            stats["plain_text_single_path"] = 1
            return {only_task: {next(iter(only_paths)): raw.strip()}}
        stats["parse_failures"] = 1
        if len(expected_task_ids) == 1:
            recovered = _salvage_single_task_path_items(
                raw, only_task, only_paths
            )
            if recovered:
                stats["partial_json_recovered_paths"] = len(recovered)
                stats["recognized_tasks"] = 1
                stats["recognized_paths"] = len(recovered)
                return {only_task: recovered}
        return {}

    returned: Any = None
    if isinstance(parsed, dict):
        for key in ("items", "results", "tasks", "data"):
            value = parsed.get(key)
            if isinstance(value, (list, dict)):
                returned = value
                break
        # 单任务模型有时直接返回 {task_id, paths}。
        if returned is None and parsed.get("task_id") is not None:
            returned = [parsed]
        # 兼容单任务直接返回 {paths: [...]} 的情况；只有一个预期任务时
        # 才允许补上 task_id，避免把批量回复错绑到任意任务。
        if returned is None and isinstance(parsed.get("paths"), (list, dict)):
            if len(expected_task_ids) == 1:
                returned = [{"task_id": next(iter(expected_task_ids)), **parsed}]
    elif isinstance(parsed, list):
        returned = parsed

    if isinstance(returned, dict):
        returned = list(returned.values())
    if not isinstance(returned, list):
        stats["invalid_outer_shape"] = 1
        return {}
    stats["returned_items"] = len(returned)

    # 顶层单任务数组可以直接是 path 对象数组；仅在只有一个预期任务
    # 且每项看起来确实是路径时包装，避免丢失合法正文。
    if (
        len(expected_task_ids) == 1
        and returned
        and all(
            isinstance(item, dict)
            and item.get("task_id") is None
            and (
                item.get("path_id") is not None
                or item.get("attack_path") is not None
                or item.get("path") is not None
            )
            for item in returned
        )
    ):
        returned = [{"task_id": next(iter(expected_task_ids)), "paths": returned}]

    result: dict[str, dict[str, str]] = {}
    expected_path_ids_by_task = expected_path_ids_by_task or {}
    for item in returned:
        if not isinstance(item, dict) or item.get("task_id") is None:
            stats["task_items_without_id"] = int(stats.get("task_items_without_id", 0)) + 1
            continue
        task_id = _canonical_task_id(item.get("task_id"), expected_task_ids)
        if not task_id:
            stats["unmatched_task_ids"] = int(stats.get("unmatched_task_ids", 0)) + 1
            continue
        if task_id in result:
            # 重复任务项不能安全合并：合并会掩盖模型把路径分配错任务的
            # 问题。保留第一项，并把重复计入诊断。
            stats["duplicate_task_items"] = int(stats.get("duplicate_task_items", 0)) + 1
            continue

        paths: Any = item.get("paths")
        if paths is None:
            paths = item.get("attack_paths")
        if paths is None and item.get("path_id") is not None:
            paths = [item]
        if isinstance(paths, dict):
            # 兼容 {"path_id": "正文"} 形式，但不接受嵌套未知对象。
            paths = [
                {"path_id": path_id, "attack_path": path_text}
                for path_id, path_text in paths.items()
            ]
        if not isinstance(paths, list):
            stats["task_items_without_paths"] = int(stats.get("task_items_without_paths", 0)) + 1
            result[task_id] = {}
            continue

        expected_ids = expected_path_ids_by_task.get(task_id)
        by_id: dict[str, str] = {}
        for path_item in paths:
            if not isinstance(path_item, dict):
                continue
            path_id = _canonical_path_id(
                path_item.get("path_id"), expected_ids
            )
            if not path_id:
                # 没有 expected 映射时保留非空 ID，供兼容调用方使用；
                # 正式生产调用始终传入 expected_path_ids_by_task。
                if expected_ids is not None:
                    stats["unmatched_path_ids"] = int(stats.get("unmatched_path_ids", 0)) + 1
                continue
            attack_path = path_item.get("attack_path")
            if attack_path is None:
                attack_path = path_item.get("path")
            if attack_path is None:
                attack_path = path_item.get("description")
            if attack_path is None:
                attack_path = path_item.get("text")
            if path_id in by_id or not isinstance(attack_path, str):
                continue
            if attack_path.strip():
                by_id[path_id] = attack_path.strip()
            else:
                stats["empty_path_bodies"] = int(stats.get("empty_path_bodies", 0)) + 1
        result[task_id] = by_id
    stats["recognized_tasks"] = len(result)
    stats["recognized_paths"] = sum(len(paths) for paths in result.values())
    return result


def _generate_direct_attack_paths(
    ctx: RuntimeContext,
    tasks: list[TaskUnit],
    rag_cache: dict[str, dict[str, str]] | None = None,
) -> dict[str, dict[str, str]]:
    results = _generate_direct_attack_paths_impl(ctx, tasks, rag_cache)
    for task in tasks:
        context = (rag_cache or {}).get('attack_path', {}).get(task.task_id, '') if ctx.setting('ENABLE_RAG') else ''
        for framework in task.selected_path_frameworks:
            text = results.get(task.task_id, {}).get(str(framework.get('path_id', '')), '')
            if isinstance(text, str) and text.strip():
                key = _direct_attack_path_item_cache_key(ctx, task, framework, context)
                ctx.shared('semantic_cache').set('direct_attack_path_item', key, text.strip())
                record_result(task, path_stage(framework), key, text.strip())
    return results


def _generate_direct_attack_paths_impl(
    ctx: RuntimeContext,
    tasks: list[TaskUnit],
    rag_cache: dict[str, dict[str, str]] | None = None,
) -> dict[str, dict[str, str]]:
    """一次批量生成完整路径，拓扑框架只作为不可变输入。"""
    rag_cache = rag_cache or {}
    system_prompt = ctx.setting('ATTACK_PATH_SYSTEM_PROMPT', ATTACK_PATH_SYSTEM_PROMPT)
    results: dict[str, dict[str, str]] = {}
    misses: list[tuple[TaskUnit, list[dict], str, dict]] = []
    partial_by_task: dict[str, dict[str, str]] = {}
    for task in tasks:
        task.attack_path_provenance = []
        frameworks, _ = _dedupe_framework_path_pairs(
            ctx,
            list(task.selected_path_frameworks),
            [""] * len(task.selected_path_frameworks),
        )
        rag_context = (
            rag_cache.get("attack_path", {}).get(task.task_id, "")
            if ctx.setting("ENABLE_RAG")
            else ""
        )
        cache_key = _direct_attack_path_cache_key(ctx, task, frameworks, rag_context)
        item_paths = {}
        for framework in frameworks:
            item_key = _direct_attack_path_item_cache_key(ctx, task, framework, rag_context)
            text = ctx.shared('semantic_cache').get('direct_attack_path_item', item_key)
            if isinstance(text, str) and text.strip():
                item_paths[_normalize_text(framework.get('path_id'))] = text.strip()
        ctx.service('_increment_pipeline_metric')('attack_path_item_cache_hits', len(item_paths))
        if frameworks and len(item_paths) == len(frameworks):
            results[task.task_id] = item_paths
            task.attack_path_provenance = [
                _attack_path_provenance(ctx, framework, 'cache_llm_complete', '')
                for framework in frameworks
            ]
            continue
        cached = ctx.shared("semantic_cache").get("direct_attack_path", cache_key)
        if isinstance(cached, dict):
            # 只按模型返回的 path_id 和非空正文复用，不审查路径措辞。
            cached_paths: dict[str, str] = {}
            by_id = {str(key): value for key, value in cached.items()}
            for framework in frameworks:
                path_id = _normalize_text(framework.get("path_id"))
                candidate = by_id.get(path_id, "")
                if isinstance(candidate, str) and candidate.strip():
                    cached_paths[path_id] = candidate.strip()
            if len(cached_paths) == len(frameworks):
                results[task.task_id] = cached_paths
                task.attack_path_provenance = [
                    _attack_path_provenance(
                        ctx, framework, "cache_llm_complete", ""
                    )
                    for framework in frameworks
                ]
                continue
            if cached_paths:
                ctx.shared("semantic_cache").set(
                    "direct_attack_path_partial", cache_key, cached_paths
                )
            ctx.shared("semantic_cache").delete("direct_attack_path", cache_key)
        partial = ctx.shared("semantic_cache").get(
            "direct_attack_path_partial", cache_key
        )
        partial_paths: dict[str, str] = dict(item_paths)
        if isinstance(partial, dict):
            for framework in frameworks:
                path_id = _normalize_text(framework.get("path_id"))
                candidate = partial.get(path_id, "")
                if isinstance(candidate, str) and candidate.strip():
                    partial_paths[path_id] = candidate.strip()
        partial_by_task[str(task.task_id).strip()] = partial_paths
        if (
            frameworks
            and len(partial_by_task[str(task.task_id).strip()]) == len(frameworks)
        ):
            results[task.task_id] = partial_by_task[str(task.task_id).strip()]
            task.attack_path_provenance = [
                _attack_path_provenance(
                    ctx, framework, "cache_llm_complete", ""
                )
                for framework in frameworks
            ]
            ctx.shared("semantic_cache").set(
                "direct_attack_path", cache_key, results[task.task_id]
            )
            ctx.shared("semantic_cache").delete(
                "direct_attack_path_partial", cache_key
            )
            continue
        misses.append((task, frameworks, rag_context, cache_key))

    ctx.service("_increment_pipeline_metric")("attack_path_direct_tasks", len(tasks))
    ctx.service("_increment_pipeline_metric")(
        "attack_path_direct_cache_hits", len(tasks) - len(misses)
    )
    # 一条多跳路线需要逐个 ECU 写段，输出长度随跳数增长；按实际
    # 路线段数计入批次预算，避免长路线沿用单跳路线的批量上限。
    max_paths_per_call = max(
        1, int(ctx.setting("DIRECT_ATTACK_PATHS_PER_CALL", 16))
    )
    chunks: list[list[tuple[TaskUnit, list[dict], str, dict]]] = []
    current: list[tuple[TaskUnit, list[dict], str, dict]] = []
    current_path_count = 0
    for miss in misses:
        path_count = max(
            1,
            sum(
                max(1, len(_framework_route_tokens(ctx, framework)) // 2)
                for framework in miss[1]
            ),
        )
        if current and current_path_count + path_count > max_paths_per_call:
            chunks.append(current)
            current = []
            current_path_count = 0
        current.append(miss)
        current_path_count += path_count
    if current:
        chunks.append(current)
    ctx.service("_set_pipeline_metric")(
        "attack_path_direct_batches_planned", len(chunks)
    )
    for chunk in chunks:
        prompt_items = []
        expected: dict[str, list[str]] = {}
        for task, frameworks, rag_context, _ in chunk:
            path_items = []
            ids: list[str] = []
            for framework in frameworks:
                path_id = _normalize_text(framework.get("path_id"))
                if not path_id or path_id in partial_by_task.get(
                    str(task.task_id).strip(), {}
                ):
                    continue
                route = _framework_route_tokens(ctx, framework)
                ids.append(path_id)
                path_items.append(
                    {
                        "path_id": path_id,
                        "topology_route": route,
                        "target_node": _normalize_text(framework.get("last_node"))
                        or (route[-1] if route else ""),
                        "is_external_actor_self": bool(
                            framework.get("is_external_actor_self")
                        ),
                        "is_external_to_external": bool(
                            framework.get("is_external_to_external")
                        ),
                        "external_interface": _plain_attack_text(
                            ctx, framework.get("external_interface")
                        ),
                        "start_component": _plain_attack_text(
                            ctx,
                            framework.get("start_component")
                            or (framework.get("path_nodes") or [""])[0],
                        ),
                        "attack_entry": {
                            "interface": _plain_attack_text(
                                ctx, framework.get("external_interface")
                            ),
                            "start_component": _plain_attack_text(
                                ctx,
                                framework.get("start_component")
                                or (framework.get("path_nodes") or [""])[0],
                            ),
                        },
                        "attack_target": {
                            "asset": task.asset_name,
                            "attribute": task.attribute_name,
                        },
                    }
                )
            task_id = str(task.task_id).strip()
            expected[task_id] = ids
            prompt_item = {
                "task_id": task_id,
                "asset_name": task.asset_name,
                "asset_type": task.asset_type,
                "target_role": (
                    "存储数据的ECU" if task.asset_type == "数据"
                    else (
                        "可信框架末端节点（外部目标特例）"
                        if task.target_is_external else "接收信号的ECU"
                    ) if task.asset_type == "信号"
                    else "被攻击的ECU"
                ),
                "attribute_name": task.attribute_name,
                "threat_type": task.threat_type,
                "damage_scenario": task.damage_scenario,
                "threat_scenario": task.threat_scenarios,
                "source": task.source or "（无）",
                "target": task.target or "（无）",
                "frameworks": path_items,
                "reference": rag_context[:400],
            }
            prompt_items.append(prompt_item)
        user_prompt = (
            f"请为以下 {len(prompt_items)} 个任务生成完整攻击路径。生成时按每条 path 的 attack_entry、"
            "topology_route、attack_target 依次组织；车内路径按接口到入口ECU一行、"
            "每个ECU间协议跳各一行；明确标记的纯外部路径按实际节点写。"
            "最后一行写目标节点上资产的直接损害结果；不要描述攻击向量分类：\n"
            + orjson.dumps(prompt_items).decode("utf-8")
            + "\n每个任务必须返回输入中的全部 path_id，不能新增或遗漏；多行路径的步骤编号必须各占一行。"
        )
        response_format = _direct_attack_path_response_format(len(chunk))
        request_error = ""
        try:
            tokens = ctx.service("_dynamic_token_budget")(
                "attack_path_direct",
                sum(len(ids) for ids in expected.values()),
                include_reasons=False,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                record=True,
            )
            ctx.service("_increment_pipeline_metric")("attack_path_direct_model_calls")
            raw = ctx.service("llm_call_with_semaphore")(
                system_prompt,
                user_prompt,
                max_tokens=tokens,
                response_format=response_format,
                raise_on_rejection=True,
            )
        except PromptContextOverflow:
            raw, request_error = "{}", "context_overflow"
            ctx.service("_increment_pipeline_metric")("attack_path_direct_context_overflows")
        except ModelRequestRejected as exc:
            raw, request_error = "{}", str(exc)
            ctx.service("_increment_pipeline_metric")("attack_path_direct_service_rejections")
        expected_task_ids = {str(task.task_id).strip() for task, *_ in chunk}
        response_diagnostics: dict[str, int | str] = {}
        returned_by_task = _direct_paths_from_response(
            raw,
            expected_task_ids,
            expected_path_ids_by_task={
                task_id: set(path_ids)
                for task_id, path_ids in expected.items()
            },
            diagnostics=response_diagnostics,
        )
        expected_path_count = sum(len(path_ids) for path_ids in expected.values())
        returned_path_count = sum(
            len(paths) for paths in returned_by_task.values()
        )
        missing_task_count = len(expected_task_ids - set(returned_by_task))
        missing_path_count = max(0, expected_path_count - returned_path_count)
        if response_diagnostics.get("parse_failures"):
            ctx.service("_increment_pipeline_metric")(
                "attack_path_direct_response_parse_failures"
            )
        if response_diagnostics.get("partial_json_recovered_paths"):
            ctx.service("_increment_pipeline_metric")(
                "attack_path_direct_partial_json_recovered_paths",
                int(response_diagnostics["partial_json_recovered_paths"]),
            )
        if response_diagnostics.get("empty_body"):
            ctx.service("_increment_pipeline_metric")(
                "attack_path_direct_empty_responses"
            )
        if response_diagnostics.get("unmatched_task_ids"):
            ctx.service("_increment_pipeline_metric")(
                "attack_path_direct_unmatched_task_ids",
                int(response_diagnostics["unmatched_task_ids"]),
            )
        if response_diagnostics.get("unmatched_path_ids"):
            ctx.service("_increment_pipeline_metric")(
                "attack_path_direct_unmatched_path_ids",
                int(response_diagnostics["unmatched_path_ids"]),
            )
        if missing_task_count or missing_path_count:
            # 以前这里直接在最后打印“未收到模型正文”，无法区分空响应、
            # JSON 解析失败和 ID 关联失败。保留正文不落日志，只输出计数，
            # 便于定位问题且不会泄露 DFD/RAG 内容。
            logger.warning(
                "完整攻击路径响应不完整: expected_tasks=%d returned_tasks=%d "
                "expected_paths=%d returned_paths=%d diagnostics=%s",
                len(expected_task_ids),
                len(returned_by_task),
                expected_path_count,
                returned_path_count,
                response_diagnostics,
            )
        accepted_by_task: dict[str, dict[str, str]] = {}
        source_by_task: dict[str, dict[str, tuple[str, str]]] = {}
        for task, frameworks, _, cache_key in chunk:
            task_id = str(task.task_id).strip()
            returned_by_id = returned_by_task.get(task_id, {})
            accepted: dict[str, str] = dict(partial_by_task.get(task_id, {}))
            sources: dict[str, tuple[str, str]] = {
                path_id: ("cache_llm_complete", "partial_cache")
                for path_id in accepted
            }
            for framework in frameworks:
                path_id = _normalize_text(framework.get("path_id"))
                candidate = returned_by_id.get(path_id, "")
                if isinstance(candidate, str) and candidate.strip():
                    accepted[path_id] = candidate.strip()
                    sources[path_id] = ("llm_complete", "primary")
            accepted_by_task[task_id] = accepted
            source_by_task[task_id] = sources

        # Retry only missing path IDs. Preserve every accepted first-pass path;
        # cap extra calls, not the first 16 path IDs, so large failed batches
        # do not deterministically abandon their tail.
        missing_reasons: dict[tuple[str, str], str] = {}
        retry_units: list[tuple[dict, dict]] = []
        for item in prompt_items:
            task_id = item["task_id"]
            for framework_item in item["frameworks"]:
                path_id = framework_item["path_id"]
                if path_id not in accepted_by_task[task_id]:
                    missing_reasons[(task_id, path_id)] = (
                        request_error
                        or ("parse_failure" if response_diagnostics.get("parse_failures") else "")
                        or ("empty_response" if response_diagnostics.get("empty_body") else "")
                        or ("id_mismatch" if response_diagnostics.get("unmatched_task_ids") or response_diagnostics.get("unmatched_path_ids") else "")
                        or "missing_model_path"
                    )
                    retry_units.append((item, framework_item))
        retry_max_calls = max(
            1, int(ctx.setting("DIRECT_ATTACK_PATH_RETRY_MAX_CALLS", 16))
        )
        retry_limit = retry_max_calls * 4
        if len(retry_units) > retry_limit:
            ctx.service("_increment_pipeline_metric")(
                "attack_path_direct_retry_limit_skipped",
                len(retry_units) - retry_limit,
            )
        retry_jobs: list[dict[str, Any]] = []
        for start in range(0, min(len(retry_units), retry_limit), 4):
            subset = retry_units[start:start + 4]
            retry_by_task: dict[str, dict] = {}
            for item, framework_item in subset:
                task_id = item["task_id"]
                if task_id not in retry_by_task:
                    retry_by_task[task_id] = {
                        "task_id": task_id,
                        "asset_name": item["asset_name"],
                        "asset_type": item["asset_type"],
                        "target_role": item["target_role"],
                        "target": item["target"],
                        "attribute_name": item["attribute_name"],
                        "damage_scenario": str(item["damage_scenario"])[:240],
                        "threat_scenario": str(item["threat_scenario"])[:240],
                        "frameworks": [],
                        "reference": str(item["reference"])[:120],
                    }
                retry_by_task[task_id]["frameworks"].append({
                    **framework_item,
                    "revision_reason": missing_reasons[(task_id, framework_item["path_id"])],
                })
            retry_items = list(retry_by_task.values())
            retry_prompt = (
                "仅补全以下缺失的 task_id/path_id 攻击路径，按原样返回 ID，不改动其他路径：\n"
                + orjson.dumps(retry_items).decode("utf-8")
            )
            retry_expected: dict[str, set[str]] = {}
            for item, framework_item in subset:
                retry_expected.setdefault(item["task_id"], set()).add(framework_item["path_id"])
            retry_jobs.append({
                "subset": subset,
                "prompt": retry_prompt,
                "expected": retry_expected,
            })

        def _run_group_retry(job: dict[str, Any]):
            subset = job["subset"]
            retry_prompt = job["prompt"]
            retry_expected = job["expected"]
            try:
                retry_tokens = ctx.service("_dynamic_token_budget")(
                    "attack_path_direct", len(subset), include_reasons=False,
                    system_prompt=system_prompt, user_prompt=retry_prompt, record=True,
                )
                ctx.service("_increment_pipeline_metric")("attack_path_direct_retry_calls")
                retry_raw = ctx.service("llm_call_with_semaphore")(
                    system_prompt, retry_prompt, max_tokens=retry_tokens,
                    response_format=_direct_attack_path_response_format(len(retry_expected)),
                    raise_on_rejection=True,
                )
                retry_stats: dict[str, int | str] = {}
                recovered = _direct_paths_from_response(
                    retry_raw, set(retry_expected),
                    expected_path_ids_by_task=retry_expected,
                    diagnostics=retry_stats,
                )
                if retry_stats.get("parse_failures"):
                    ctx.service("_increment_pipeline_metric")(
                        "attack_path_direct_retry_parse_failures"
                    )
                if retry_stats.get("partial_json_recovered_paths"):
                    ctx.service("_increment_pipeline_metric")(
                        "attack_path_direct_partial_json_recovered_paths",
                        int(retry_stats["partial_json_recovered_paths"]),
                    )
                retry_reason = (
                    "parse_failure" if retry_stats.get("parse_failures")
                    else "empty_response" if retry_stats.get("empty_body")
                    else "id_mismatch" if retry_stats.get("unmatched_task_ids") or retry_stats.get("unmatched_path_ids")
                    else "missing_model_path"
                )
            except PromptContextOverflow:
                recovered, retry_reason = {}, "context_overflow"
                ctx.service("_increment_pipeline_metric")("attack_path_direct_context_overflows")
            except ModelRequestRejected as exc:
                recovered, retry_reason = {}, str(exc)
                ctx.service("_increment_pipeline_metric")("attack_path_direct_service_rejections")
            except Exception as exc:
                recovered, retry_reason = {}, f"retry_exception:{type(exc).__name__}"
                logger.warning("攻击路径分组补生成异常: %s", exc)
            return subset, recovered, retry_reason

        for subset, recovered, retry_reason in _run_bounded_path_retry_jobs(
            ctx, retry_jobs, _run_group_retry
        ):
            for item, framework_item in subset:
                task_id, path_id = item["task_id"], framework_item["path_id"]
                value = recovered.get(task_id, {}).get(path_id, "")
                if isinstance(value, str) and value.strip():
                    accepted_by_task[task_id][path_id] = value.strip()
                    source_by_task[task_id][path_id] = ("llm_complete", "retry")
                    ctx.service("_increment_pipeline_metric")("attack_path_direct_retry_recovered")
                else:
                    missing_reasons[(task_id, path_id)] = retry_reason

        # 分组重试仍缺失时，有限量拆成单路径请求，覆盖上下文、解析、ID和服务异常。
        # topology_route 作为可信输入不裁剪；单路径重试后仍无正文才记为生成失败。
        unresolved_units = [
            (item, framework_item)
            for item, framework_item in retry_units
            if framework_item["path_id"] not in accepted_by_task[item["task_id"]]
        ]
        single_retry_jobs = unresolved_units[:retry_max_calls]
        if len(unresolved_units) > retry_max_calls:
            ctx.service("_increment_pipeline_metric")(
                "attack_path_direct_single_retry_limit_skipped",
                len(unresolved_units) - retry_max_calls,
            )

        def _run_single_retry(unit: tuple[dict, dict]):
            item, framework_item = unit
            task_id = item["task_id"]
            path_id = framework_item["path_id"]
            compact_item = {
                "task_id": task_id,
                "asset_name": item["asset_name"],
                "asset_type": item["asset_type"],
                "target_role": item["target_role"],
                "target": item["target"],
                "attribute_name": item["attribute_name"],
                "damage_scenario": str(item["damage_scenario"])[:100],
                "threat_scenario": str(item["threat_scenario"])[:100],
                "frameworks": [framework_item],
            }
            compact_prompt = (
                "仅生成这一条 task_id/path_id 攻击路径，原样返回 ID：\n"
                + orjson.dumps([compact_item]).decode("utf-8")
            )
            try:
                compact_tokens = ctx.service("_dynamic_token_budget")(
                    "attack_path_direct", 1, include_reasons=False,
                    system_prompt=system_prompt,
                    user_prompt=compact_prompt, record=True,
                )
                ctx.service("_increment_pipeline_metric")(
                    "attack_path_direct_single_retry_calls"
                )
                compact_raw = ctx.service("llm_call_with_semaphore")(
                    system_prompt, compact_prompt, max_tokens=compact_tokens,
                    response_format=_direct_attack_path_response_format(1),
                    raise_on_rejection=True,
                )
                compact_stats: dict[str, int | str] = {}
                compact_paths = _direct_paths_from_response(
                    compact_raw, {task_id},
                    expected_path_ids_by_task={task_id: {path_id}},
                    diagnostics=compact_stats,
                )
                value = compact_paths.get(task_id, {}).get(path_id, "")
                if value:
                    ctx.service("_increment_pipeline_metric")(
                        "attack_path_direct_single_context_retry_recovered"
                    )
                    return unit, value.strip(), ""
                elif compact_stats.get("parse_failures"):
                    return unit, "", "parse_failure"
                return unit, "", "missing_model_path"
            except PromptContextOverflow:
                return unit, "", "context_overflow"
            except ModelRequestRejected as exc:
                return unit, "", str(exc)
            except Exception as exc:
                logger.warning("攻击路径单路径补生成异常: %s", exc)
                return unit, "", f"retry_exception:{type(exc).__name__}"

        for unit, value, retry_reason in _run_bounded_path_retry_jobs(
            ctx, single_retry_jobs, _run_single_retry
        ):
            item, framework_item = unit
            task_id = item["task_id"]
            path_id = framework_item["path_id"]
            if value:
                accepted_by_task[task_id][path_id] = value
                source_by_task[task_id][path_id] = (
                    "llm_complete", "single_context_retry"
                )
            else:
                missing_reasons[(task_id, path_id)] = retry_reason

        missing_count = 0
        incomplete_task_ids: set[str] = set()
        for task, frameworks, _, cache_key in chunk:
            task_id = str(task.task_id).strip()
            accepted = accepted_by_task[task_id]
            for framework in frameworks:
                path_id = _normalize_text(framework.get("path_id"))
                if path_id in accepted:
                    continue
                missing_count += 1
                incomplete_task_ids.add(task_id)
                source_by_task[task_id][path_id] = (
                    "model_missing",
                    missing_reasons.get((task_id, path_id), "missing_model_path"),
                )
            results[task.task_id] = accepted
            task.attack_path_provenance = [
                _attack_path_provenance(
                    ctx,
                    framework,
                    *source_by_task[task_id].get(
                        _normalize_text(framework.get("path_id")),
                        ("unresolved", "missing_generation_record"),
                    ),
                )
                for framework in frameworks
            ]
            # 成功项也按同一身份键保存，恢复轮只请求缺失 path_id；
            # 未完整的任务绝不写入正式路径缓存或风险报告。
            if task_id not in incomplete_task_ids:
                ctx.shared("semantic_cache").set(
                    "direct_attack_path", cache_key, accepted
                )
                if partial_by_task.get(task_id):
                    ctx.shared("semantic_cache").delete(
                        "direct_attack_path_partial", cache_key
                    )
            elif accepted:
                ctx.shared("semantic_cache").set(
                    "direct_attack_path_partial", cache_key, accepted
                )
        if missing_count:
            ctx.service("_increment_pipeline_metric")(
                "attack_path_direct_missing_paths", missing_count
            )
            logger.warning(
                "完整攻击路径有 %d 条未由模型生成；已记录失败，不生成模板路径",
                missing_count,
            )
    return results

def _generate_attack_target_actions(ctx: RuntimeContext, tasks: list[TaskUnit], rag_cache: dict[str, dict[str, str]] | None=None) -> dict[str, str]:
    """一次批量调用为多个任务生成最终攻击动作，不生成或改写拓扑。"""
    rag_cache = rag_cache or {}
    system_prompt = ctx.setting('ATTACK_TARGET_SYSTEM_PROMPT', ATTACK_TARGET_SYSTEM_PROMPT)
    results: dict[str, str] = {}
    sources: dict[str, str] = {}
    misses: list[tuple[TaskUnit, str, dict]] = []
    for task in tasks:
        rag_context = rag_cache.get('attack_path', {}).get(task.task_id, '') if ctx.setting('ENABLE_RAG') else ''
        cache_key = _target_action_cache_key(ctx, task, rag_context)
        cached = ctx.shared('semantic_cache').get('attack_target_action', cache_key)
        cached_action = _normalize_target_action(ctx, cached) if isinstance(cached, str) else ''
        if cached_action and _target_action_matches_attribute(task, cached_action):
            results[task.task_id] = cached_action
            sources[task.task_id] = 'cache'
        else:
            misses.append((task, rag_context, cache_key))
    ctx.service('_increment_pipeline_metric')('attack_target_tasks', len(tasks))
    ctx.service('_increment_pipeline_metric')('attack_target_cache_hits', len(results))
    ctx.service('_increment_pipeline_metric')('attack_target_batches_planned', (len(misses) + ctx.setting('ATTACK_PATH_TASKS_PER_CALL') - 1) // ctx.setting('ATTACK_PATH_TASKS_PER_CALL') if misses else 0)
    for start in range(0, len(misses), ctx.setting('ATTACK_PATH_TASKS_PER_CALL')):
        chunk = misses[start:start + ctx.setting('ATTACK_PATH_TASKS_PER_CALL')]
        prompt_items = []
        for (index, (task, rag_context, _)) in enumerate(chunk, start=1):
            prompt_items.append({'id': f'T{index}', 'asset_name': task.asset_name, 'asset_type': task.asset_type, 'attribute_name': task.attribute_name, 'threat_type': task.threat_type, 'damage_scenario': task.damage_scenario, 'threat_scenario': task.threat_scenarios, 'asset_details': task.asset_details, 'flow_protocol': task.flow_protocol or '（无）', 'source': task.source or '（无）', 'target': task.target or '（无）', 'attribute_constraint': f'只描述{task.attribute_name}的直接破坏，不写后续二次攻击或其他安全属性', 'reference': rag_context[:400]})
        user_prompt = f'请为以下 {len(prompt_items)} 个任务分别生成最终攻击动作：\n' + orjson.dumps(prompt_items).decode('utf-8') + '\n必须返回完全相同的id，且target_actions数量与输入一致。信号类资产必须参考flow_protocol（传输协议）生成动作；每个target_action的最后必须使用“导致”或“造成”写明与damage_scenario一致的直接后果。'
        ctx.service('_increment_pipeline_metric')('attack_target_model_calls')
        attack_target_tokens = ctx.service('_dynamic_token_budget')('attack_target', len(chunk), include_reasons=False, system_prompt=system_prompt, user_prompt=user_prompt, record=True)
        raw = ctx.service('llm_call_with_semaphore')(system_prompt, user_prompt, max_tokens=attack_target_tokens, response_format={'type': 'json_schema', 'json_schema': {'name': 'tara_attack_target_batch', 'strict': True, 'schema': {'type': 'object', 'properties': {'target_actions': {'type': 'array', 'minItems': len(chunk), 'maxItems': len(chunk), 'items': {'type': 'object', 'properties': {'id': {'type': 'string', 'enum': [f'T{index}' for index in range(1, len(chunk) + 1)]}, 'target_action': {'type': 'string', 'minLength': 4, 'maxLength': 160}}, 'required': ['id', 'target_action'], 'additionalProperties': False}}}, 'required': ['target_actions'], 'additionalProperties': False}}})
        try:
            parsed = safe_parse_json(raw)
        except Exception:
            parsed = {}
        returned = parsed.get('target_actions', []) if isinstance(parsed, dict) else []
        if not isinstance(returned, list):
            returned = []
        expected_ids = [f'T{index}' for index in range(1, len(chunk) + 1)]
        by_id: dict[str, str] = {}
        for item in returned:
            if not isinstance(item, dict):
                continue
            item_id = str(item.get('id', '')).strip()
            if item_id not in expected_ids or item_id in by_id:
                continue
            action = _normalize_target_action(ctx, item.get('target_action'))
            task_for_item = chunk[expected_ids.index(item_id)][0]
            if action and not _target_action_matches_attribute(task_for_item, action):
                action = ''
            if action:
                by_id[item_id] = action
        if not by_id and len(returned) == len(chunk):
            ordered = []
            for position, item in enumerate(returned):
                action = _normalize_target_action(ctx, item.get('target_action')) if isinstance(item, dict) else ''
                if action and not _target_action_matches_attribute(chunk[position][0], action):
                    action = ''
                ordered.append(action)
        else:
            ordered = [by_id.get(item_id, '') for item_id in expected_ids]
        for ((task, _, cache_key), action) in zip(chunk, ordered):
            model_generated = bool(action)
            if not action:
                action = _fallback_target_action(ctx, task)
                sources[task.task_id] = 'fallback'
            else:
                sources[task.task_id] = 'model'
            results[task.task_id] = action
            if model_generated:
                ctx.shared('semantic_cache').set('attack_target_action', cache_key, action)
    for task in tasks:
        task.attack_target_action = results.get(task.task_id, '')
        task.attack_target_action_source = sources.get(task.task_id, 'fallback')
    return results

def _compose_hybrid_attack_path(ctx: RuntimeContext, task: TaskUnit, framework: dict, entry_action: str, target_action: str) -> str:
    """代码将两段 LLM 语义可信绑定到一条已校验拓扑框架。

    首行的 external_interface/start_component 永远来自 information Excel
    生成的拓扑框架。模型若没有同时复述这两个真实值，整段入口动作降级为
    代码模板；模型不能通过输出一个新接口或新部件改变攻击入口。
    """
    if framework.get("is_external_component_direct"):
        source = _plain_attack_text(
            ctx, framework.get("external_component_source") or task.source
        ) or "外部部件"
        target_node = _plain_attack_text(
            ctx, framework.get("external_component_target") or task.target
        ) or "目标"
        protocol = _plain_attack_text(ctx, framework.get("dfd_protocol"))
        candidate_target = _normalize_target_action(ctx, target_action)
        if not _target_action_matches_attribute(task, candidate_target):
            candidate_target = _fallback_target_action(ctx, task)
        target = _plain_attack_text(ctx, candidate_target)
        if task.asset_name and task.asset_name.lower() not in target.lower():
            target = f"针对资产{_plain_attack_text(ctx, task.asset_name)}{target}"
        if not target.startswith("攻击者"):
            target = "攻击者" + target
        connection = f"通过{protocol}通信" if protocol else "通过直接业务连接"
        return (
            f"1. 攻击者从{source}取得直接访问权限\n"
            f"2. 攻击者利用{source}与{target_node}之间的{connection}发起针对性请求\n"
            f"3. {target}"
        )

    interface = _plain_attack_text(ctx, framework.get('external_interface')) or '外部接口'
    path_nodes = framework.get('path_nodes') or []
    start_component = _plain_attack_text(ctx, framework.get('start_component') or (path_nodes[0] if path_nodes else ''))
    route_steps = _framework_route_steps(ctx, framework)
    model_entry = _plain_attack_text(ctx, entry_action)
    if (
        _entry_action_mentions_interface(ctx, interface, model_entry)
        and _entry_action_mentions_component(start_component, model_entry)
        and not _entry_action_mentions_foreign_table_interface(
            framework, interface, model_entry
        )
    ):
        technique = _entry_action_suffix(model_entry)
    else:
        technique = ''
    fallback_entry = _plain_attack_text(
        ctx,
        _fallback_entry_action(
            ctx,
            {
                'external_interface': interface,
                'start_component': start_component,
                'attack_vector': framework.get('attack_vector', ''),
            },
        ),
    )
    # 统一固定首行前缀，模型只能贡献经过绑定校验的技术尾句。
    entry = f'攻击者通过{interface}进入{start_component}'
    if technique:
        entry = f'{entry}，{technique}'
    else:
        fallback_suffix = _entry_action_suffix(fallback_entry)
        entry = f'{entry}，{fallback_suffix}' if fallback_suffix else fallback_entry
    if not entry.startswith('攻击者'):
        entry = '攻击者' + entry
    candidate_target = _normalize_target_action(ctx, target_action)
    if not _target_action_matches_attribute(task, candidate_target):
        candidate_target = _fallback_target_action(ctx, task)
    target = _plain_attack_text(ctx, candidate_target)
    if task.asset_name and task.asset_name.lower() not in target.lower():
        target = f'针对资产{_plain_attack_text(ctx, task.asset_name)}{target}'
    if not target.startswith('攻击者'):
        target = '攻击者' + target
    # 两节点框架没有中间通信步骤；将可信末端节点纳入最终攻击动作，避免
    # 因资产显示名与拓扑节点名不同而丢失路线证据。
    route_tokens = _framework_route_tokens(ctx, framework)
    terminal_node = route_tokens[-1] if route_tokens else ''
    if terminal_node and terminal_node.lower() not in target.lower():
        target = (
            f'攻击者在{terminal_node}上'
            f'{re.sub(r"^攻击者", "", target)}'
        )
    # 兜底路径也严格按真实路线逐跳描述。两节点的直接路径只需“取得入口
    # 访问 + 最终攻击”两行；不再为了凑三行而重复接口或写“传递恶意载荷”。
    if len(route_steps) > 3:
        # 保持 2～5 行上限，同时将超长路径中每个可信 token 保留在合并步骤内。
        route_steps = route_steps[:2] + ['；随后'.join(route_steps[2:])]
    path_lines = [entry, *route_steps, target]
    text = '\n'.join(
        f'{index}. {line}' for index, line in enumerate(path_lines, start=1)
    )
    if task.asset_type == '信号' and task.flow_protocol:
        protocol = _plain_attack_text(ctx, task.flow_protocol)
        if protocol and protocol.lower() not in text.lower():
            text = f'{text}（信号经{protocol}传输）'
    return text

def _hybrid_paths_valid(ctx: RuntimeContext, paths: list[str], frameworks: list[dict]) -> bool:
    if len(paths) != len(frameworks) or len(set(paths)) != len(paths):
        return False
    for (path, framework) in zip(paths, frameworks):
        if any((marker in path for marker in ('[', ']', '->', '→', '➡', '➜'))):
            return False
        lines = [line.strip() for line in path.splitlines() if line.strip()]
        route_tokens = _framework_route_tokens(ctx, framework)
        minimum_lines = 1 if len(route_tokens) <= 2 else 2
        if not minimum_lines <= len(lines) <= 5 or any((not re.match(f'^{index}\\.\\s*\\S', line) for (index, line) in enumerate(lines, start=1))):
            return False
        if not route_tokens:
            return False
        cursor = 0
        lowered_route_line = ' '.join(lines)
        for index, token in enumerate(route_tokens):
            token_text = _normalize_text(token)
            if not token_text:
                continue
            if _route_token_allows_protocol_alias(framework, token_text, index):
                position = _find_route_token(lowered_route_line, token_text, cursor)
            else:
                position = _find_exact_route_token(
                    lowered_route_line, token_text, cursor
                )
            if position < 0:
                return False
            # cursor 使用原始归一化文本的位置；别名长度可能与可信 token
            # 不同，因此必须按实际命中的写法推进，而不能按 token 长度推进。
            matched_end = (
                _route_token_match_end(lowered_route_line, token_text, position)
                if _route_token_allows_protocol_alias(framework, token_text, index)
                else position + len(token_text)
            )
            cursor = max(position + len(token_text.casefold()), matched_end)
    return True


def _dedupe_framework_path_pairs(
    ctx: RuntimeContext,
    frameworks: list[dict],
    paths: list[str],
) -> tuple[list[dict], list[str]]:
    """按可信拓扑路线和攻击向量去重，避免同一入口输出模板变体。

    入口技术是语义补充，不应把同一条最短拓扑路线拆成多条攻击路径；
    仅保留第一条确定性绑定的路线，仍保留不同接口或不同攻击向量的路径。
    """
    unique_frameworks: list[dict] = []
    unique_paths: list[str] = []
    seen: set[tuple[tuple[str, ...], str]] = set()
    for framework, path in zip(frameworks, paths):
        route_key = tuple(
            _normalize_text(token).casefold()
            for token in _framework_route_tokens(ctx, framework)
            if _normalize_text(token)
        )
        key = (route_key, normalize_attack_vector(framework.get("attack_vector", "")))
        if key in seen:
            continue
        seen.add(key)
        unique_frameworks.append(framework)
        unique_paths.append(path)
    return unique_frameworks, unique_paths

def _exec_attack_path_batch(ctx: RuntimeContext, tasks: list[TaskUnit], all_frameworks: list[dict], rag_cache: dict[str, dict[str, str]], entry_catalog: dict[str, str]) -> None:
    """每批任务一次生成完整路径，拓扑框架由代码筛选，正文直接写回。"""
    eligible: list[TaskUnit] = []
    for task in tasks:
        if not task.selected_path_frameworks:
            task.selected_path_frameworks = filter_path_frameworks(ctx, task, all_frameworks)
        if task.selected_path_frameworks:
            eligible.append(task)
    if not eligible:
        return
    # 入口目录是旧接口参数；不再允许它拼接非模型生成的路径。
    try:
        direct_paths = _generate_direct_attack_paths(ctx, eligible, rag_cache)
    except Exception as exc:
        logger.warning(
            "完整攻击路径模型调用异常，任务将标记为模型失败: %s",
            exc,
        )
        direct_paths = {}
        generation_error = f"generation_exception: {type(exc).__name__}: {exc}"
    else:
        generation_error = ""
    for task in eligible:
        # 先按可信路线+攻击向量去重。这里不再按固定数量截断，保留筛选后
        # 的全部等长最短可信框架，确保每个真实入口/路线都有对应路径。
        frameworks, _ = _dedupe_framework_path_pairs(
            ctx,
            list(task.selected_path_frameworks),
            [''] * len(task.selected_path_frameworks),
        )
        task.selected_path_frameworks = frameworks
        path_by_id = direct_paths.get(task.task_id, {})
        paths = []
        missing_ids: list[str] = []
        provenance_by_id = {
            _normalize_text(item.get("path_id")): item
            for item in task.attack_path_provenance
            if isinstance(item, dict) and _normalize_text(item.get("path_id"))
        }
        ordered_provenance: list[dict] = []
        for framework in frameworks:
            path_id = _normalize_text(framework.get("path_id"))
            path = path_by_id.get(path_id, "")
            provenance = provenance_by_id.get(path_id, {})
            if not path or provenance.get("generation_source") not in {
                "llm_complete", "cache_llm_complete"
            }:
                missing_ids.append(path_id)
                provenance_by_id.setdefault(
                    path_id,
                    _attack_path_provenance(
                        ctx, framework, "model_missing",
                        generation_error or "missing_generated_path",
                    ),
                )
            else:
                paths.append(path)
            ordered_provenance.append(
                provenance_by_id.get(
                    path_id,
                    _attack_path_provenance(
                        ctx, framework, "unresolved", "missing_generation_record"
                    ),
                )
            )
        task.selected_path_frameworks = frameworks
        task.attack_path_provenance = ordered_provenance
        task.attack_entry_actions = []
        task.attack_entry_action_sources = []
        task.attack_target_action = ""
        task.attack_target_action_source = ""
        if missing_ids:
            # 部分成功的路径也不进入正式报告，避免风险评分建立在不完整
            # 的路径集合上。失败原因和 path_id 仍保留在审计信息中。
            task.attack_paths = []
            task.attack_details = []
            task.risk_value = None
            task.risk_treatment = "需复核"
            task.analysis_status = STATUS_MODEL_FAILED
            reason = "攻击路径模型生成不完整: " + ", ".join(
                f"{path_id} ({provenance_by_id[path_id].get('fallback_reason', 'missing_model_path')})"
                for path_id in missing_ids
            )
            if reason not in task.status_reasons:
                task.status_reasons.append(reason)
            if reason not in task.errors:
                task.errors.append(reason)
            continue
        for path, provenance in zip(paths, ordered_provenance):
            lines = [line.strip() for line in path.splitlines() if line.strip()]
            if lines:
                task.attack_entry_actions.append(re.sub(r"^1\.\s*", "", lines[0]))
                task.attack_target_action = re.sub(r"^\d+\.\s*", "", lines[-1])
                source = str(provenance.get("generation_source", ""))
                task.attack_entry_action_sources.append("direct_model")
        task.attack_target_action_source = "direct_model"
        task.attack_paths = paths
        task.status_reasons = [
            reason for reason in task.status_reasons
            if not reason.startswith("攻击路径模型生成不完整:")
        ]
        task.errors = [
            error for error in task.errors
            if error != 'attack_path为空'
            and not error.startswith('攻击路径异常:')
            and not error.startswith('攻击路径模型生成不完整:')
        ]
        if task.analysis_status == STATUS_MODEL_FAILED and not task.status_reasons:
            task.analysis_status = STATUS_VALID
