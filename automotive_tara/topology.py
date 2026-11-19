"""拓扑和 DFD 路径绑定共用的规范化规则。"""

from __future__ import annotations

import copy
import logging
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Protocol

from .domain import (
    PathNodeVO,
    TopologyElementType,
    TopologyElementVO,
    normalize_attack_vector,
)


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TopologyConstraintIssue:
    """A deterministic topology-input or route validation finding."""

    code: str
    message: str
    channel_id: str = ""
    link_ids: tuple[str, ...] = field(default_factory=tuple)


@dataclass
class TopologyChannelIndex:
    """Bidirectional ECU/channel membership with raw-link provenance."""

    component_to_channels: dict[str, set[str]]
    channel_to_components: dict[str, set[str]]
    channel_to_link_ids: dict[str, set[str]]
    endpoint_link_ids: dict[tuple[str, str], set[str]]
    pair_link_ids: dict[tuple[str, str, str], set[str]]
    component_by_id: dict[str, TopologyElementVO]
    channel_to_protocol: dict[str, str]
    issues: list[TopologyConstraintIssue] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return not self.issues

    def raise_for_issues(self) -> None:
        if not self.issues:
            return
        details = "; ".join(issue.message for issue in self.issues[:8])
        if len(self.issues) > 8:
            details += f"; 另有 {len(self.issues) - 8} 项"
        raise ValueError(f"拓扑通信信道约束校验失败: {details}")


def _canonical_pair(left: str, right: str) -> tuple[str, str]:
    return (left, right) if left <= right else (right, left)


def build_topology_channel_index(
    element_vos: list[TopologyElementVO],
    protocol_legends: list[dict],
    distinct_components: list[TopologyElementVO],
) -> TopologyChannelIndex:
    """Build the project's bidirectional shared-channel representation.

    Every raw edge keeps its unique exported cell ID.  Reachability is based
    on channel membership (the topology colour), because ECUs attached to one
    vehicle bus can exchange data even when the drawing contains separate
    visual edge records.  The function rejects inputs that violate the
    project's one-connected-domain-per-channel invariant.
    """

    many_to_one = {
        old_id: component.id
        for component in distinct_components
        for old_id in component.ids
    }
    component_by_id = {
        component.id: component for component in distinct_components
    }

    channel_to_protocol: dict[str, str] = {}
    issues: list[TopologyConstraintIssue] = []
    for legend in protocol_legends:
        channel_id = normalize_text(legend.get("color"))
        if not channel_id:
            continue
        protocol = normalize_text(legend.get("name"))
        previous = channel_to_protocol.get(channel_id)
        if previous is not None and previous != protocol:
            issues.append(
                TopologyConstraintIssue(
                    "CHANNEL_LEGEND_CONFLICT",
                    f"通信信道[{channel_id}]同时映射协议[{previous}]和[{protocol}]",
                    channel_id=channel_id,
                )
            )
        else:
            channel_to_protocol[channel_id] = protocol

    component_to_channels: dict[str, set[str]] = defaultdict(set)
    channel_to_components: dict[str, set[str]] = defaultdict(set)
    channel_to_link_ids: dict[str, set[str]] = defaultdict(set)
    endpoint_link_ids: dict[tuple[str, str], set[str]] = defaultdict(set)
    pair_link_ids: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    channel_adjacency: dict[str, dict[str, set[str]]] = defaultdict(
        lambda: defaultdict(set)
    )
    seen_link_ids: set[str] = set()

    for line in element_vos:
        if line.type != TopologyElementType.LINE:
            continue
        link_id = normalize_text(line.id)
        channel_id = normalize_text(line.color)
        source_id = many_to_one.get(line.source_id, line.source_id)
        target_id = many_to_one.get(line.target_id, line.target_id)

        if not link_id:
            issues.append(
                TopologyConstraintIssue(
                    "LINK_ID_MISSING",
                    "拓扑连接缺少唯一编号",
                    channel_id=channel_id,
                )
            )
            continue
        if link_id in seen_link_ids:
            issues.append(
                TopologyConstraintIssue(
                    "LINK_ID_DUPLICATE",
                    f"拓扑连接编号重复[{link_id}]",
                    channel_id=channel_id,
                    link_ids=(link_id,),
                )
            )
            continue
        seen_link_ids.add(link_id)

        if channel_id not in channel_to_protocol:
            issues.append(
                TopologyConstraintIssue(
                    "CHANNEL_UNKNOWN",
                    f"连接[{link_id}]使用未在图例声明的通信信道[{channel_id or '空'}]",
                    channel_id=channel_id,
                    link_ids=(link_id,),
                )
            )
            continue
        missing_endpoints = [
            endpoint
            for endpoint in (source_id, target_id)
            if not endpoint or endpoint not in component_by_id
        ]
        if missing_endpoints:
            issues.append(
                TopologyConstraintIssue(
                    "LINK_ENDPOINT_UNKNOWN",
                    f"连接[{link_id}]端点未映射到拓扑部件: {missing_endpoints}",
                    channel_id=channel_id,
                    link_ids=(link_id,),
                )
            )
            continue
        if source_id == target_id:
            issues.append(
                TopologyConstraintIssue(
                    "LINK_SELF_LOOP",
                    f"连接[{link_id}]的两个端点映射为同一部件[{source_id}]",
                    channel_id=channel_id,
                    link_ids=(link_id,),
                )
            )
            continue

        for endpoint in (source_id, target_id):
            component_to_channels[endpoint].add(channel_id)
            channel_to_components[channel_id].add(endpoint)
            endpoint_link_ids[(channel_id, endpoint)].add(link_id)
        channel_to_link_ids[channel_id].add(link_id)
        pair_left, pair_right = _canonical_pair(source_id, target_id)
        pair_link_ids[(channel_id, pair_left, pair_right)].add(link_id)
        # Connections are bidirectional by the project's engineering rule.
        channel_adjacency[channel_id][source_id].add(target_id)
        channel_adjacency[channel_id][target_id].add(source_id)

    for channel_id, components in channel_to_components.items():
        if not components:
            continue
        start = next(iter(components))
        visited = {start}
        queue = deque([start])
        while queue:
            current = queue.popleft()
            for neighbour in channel_adjacency[channel_id].get(current, set()):
                if neighbour not in visited:
                    visited.add(neighbour)
                    queue.append(neighbour)
        if visited != components:
            disconnected = tuple(sorted(components - visited))
            issues.append(
                TopologyConstraintIssue(
                    "CHANNEL_DISCONNECTED",
                    f"通信信道[{channel_id}]包含互不连通的部件: {list(disconnected)}",
                    channel_id=channel_id,
                    link_ids=tuple(sorted(channel_to_link_ids[channel_id])),
                )
            )

    return TopologyChannelIndex(
        component_to_channels=dict(component_to_channels),
        channel_to_components=dict(channel_to_components),
        channel_to_link_ids=dict(channel_to_link_ids),
        endpoint_link_ids=dict(endpoint_link_ids),
        pair_link_ids=dict(pair_link_ids),
        component_by_id=component_by_id,
        channel_to_protocol=channel_to_protocol,
        issues=issues,
    )


def validate_path_channel_transitions(
    path: list[PathNodeVO],
    channel_index: TopologyChannelIndex,
) -> list[TopologyConstraintIssue]:
    """Independently validate channel membership and gateway transitions."""

    issues: list[TopologyConstraintIssue] = []
    previous_channel = ""
    previous_target = ""
    for position, node in enumerate(path, start=1):
        channel_id = normalize_text(node.channel_id or node.color)
        source_id = node.pre_component_name_id
        target_id = node.component_name_id
        members = channel_index.channel_to_components.get(channel_id, set())
        if source_id not in members or target_id not in members:
            issues.append(
                TopologyConstraintIssue(
                    "ROUTE_CHANNEL_MEMBERSHIP_INVALID",
                    f"路线第{position}跳的部件未共同挂接信道[{channel_id}]",
                    channel_id=channel_id,
                    link_ids=tuple(node.topology_link_ids),
                )
            )
        if previous_channel and channel_id != previous_channel:
            transition_id = source_id
            component = channel_index.component_by_id.get(transition_id)
            attached_channels = channel_index.component_to_channels.get(
                transition_id, set()
            )
            transition_allowed = bool(
                component
                and previous_target == transition_id
                and (
                    component.is_gateway
                    or {previous_channel, channel_id}.issubset(attached_channels)
                )
            )
            if not transition_allowed:
                transition_name = component.name if component else transition_id
                issues.append(
                    TopologyConstraintIssue(
                        "ROUTE_GATEWAY_TRANSITION_INVALID",
                        f"路线第{position}跳在部件[{transition_name}]跨信道"
                        f"[{previous_channel}]→[{channel_id}]，但缺少有效网关/控制器连接",
                        channel_id=channel_id,
                        link_ids=tuple(node.topology_link_ids),
                    )
                )
        previous_channel = channel_id
        previous_target = target_id
    return issues


class _PathNode(Protocol):
    color: str


class TopologyMapUtil:
    """将拓扑导出元素转换为部件图并生成可信 BFS 路径。"""

    @staticmethod
    def list_element_vo(cells: list[dict]) -> list[TopologyElementVO]:
        result: list[TopologyElementVO] = []
        for cell in cells:
            element = TopologyElementVO(id=cell.get("id"))
            shape = cell.get("shape", "")
            attributes = cell.get("attrs", {})
            if shape == "custom-rounded-rect":
                stroke = attributes.get("body", {}).get("stroke", "")
                if stroke == "#016AFF":
                    element.type = TopologyElementType.GATEWAY
                    element.is_gateway = True
                else:
                    element.type = TopologyElementType.COMPONENT
                element.color = stroke
                element.name = attributes.get("text", {}).get("text", "")
            elif shape == "custom-rounded-rect-dash":
                element.type = TopologyElementType.EXTERNAL_COMPONENT
                element.color = attributes.get("body", {}).get("stroke", "")
                element.name = attributes.get("text", {}).get("text", "")
            elif shape == "edge":
                element.type = TopologyElementType.LINE
                element.color = attributes.get("line", {}).get("stroke", "")
                element.source_id = cell.get("source", {}).get("cell")
                element.target_id = cell.get("target", {}).get("cell")
            result.append(element)
        return result

    @staticmethod
    def get_distinct_components(
        element_vos: list[TopologyElementVO],
    ) -> list[TopologyElementVO]:
        components = [
            element
            for element in element_vos
            if element.type in (
                TopologyElementType.COMPONENT,
                TopologyElementType.GATEWAY,
                TopologyElementType.EXTERNAL_COMPONENT,
            )
            and element.name
        ]
        name_map: dict[str, list[TopologyElementVO]] = defaultdict(list)
        for component in components:
            name_map[name_match_key(component.name)].append(component)
        distinct: list[TopologyElementVO] = []
        for elements in name_map.values():
            first = elements[0]
            first.ids = [element.id for element in elements]
            distinct.append(first)
        return distinct

    @staticmethod
    def generate_full_path(
        external_interfaces: list[dict],
        element_vos: list[TopologyElementVO],
        protocol_legends: list[dict],
        distinct_components: list[TopologyElementVO],
        *,
        channel_index: TopologyChannelIndex | None = None,
    ) -> list[list[PathNodeVO]]:
        channel_index = channel_index or build_topology_channel_index(
            element_vos, protocol_legends, distinct_components
        )
        channel_index.raise_for_issues()

        external_names = {
            name_match_key(item.get("related_component"))
            for item in external_interfaces
            if item.get("related_component")
        }
        external_ids = {
            component.id
            for component in distinct_components
            if name_match_key(component.name) in external_names
        }
        starts = {
            component_id: channel_ids
            for component_id, channel_ids in channel_index.component_to_channels.items()
            if component_id in external_ids
        }
        paths = TopologyMapUtil.get_path_by_bfs(
            starts,
            channel_index.component_to_channels,
            channel_index.channel_to_components,
            channel_index.component_by_id,
            endpoint_link_ids=channel_index.endpoint_link_ids,
            pair_link_ids=channel_index.pair_link_ids,
        )
        route_issues = [
            issue
            for path in paths
            for issue in validate_path_channel_transitions(path, channel_index)
        ]
        if route_issues:
            details = "; ".join(issue.message for issue in route_issues[:8])
            raise ValueError(f"拓扑候选路线信道/网关校验失败: {details}")
        logger.info(
            "拓扑约束校验通过: 原始连接=%d, 通信信道=%d, 部件=%d",
            sum(len(ids) for ids in channel_index.channel_to_link_ids.values()),
            len(channel_index.channel_to_components),
            len(channel_index.component_by_id),
        )
        return paths

    @staticmethod
    def get_path_by_bfs(
        starts: dict[str, set],
        component_to_lines: dict[str, set],
        line_to_components: dict[str, set],
        component_by_id: dict[str, TopologyElementVO],
        *,
        endpoint_link_ids: dict[tuple[str, str], set[str]] | None = None,
        pair_link_ids: dict[tuple[str, str, str], set[str]] | None = None,
    ) -> list[list[PathNodeVO]]:
        """Return all equal-shortest, loop-free component routes.

        A topology colour/channel is a shared bus: every component attached to
        that channel can exchange data with the other members.  The previous
        implementation marked *all* members of a channel as visited after one
        hop.  That accidentally prevented a legitimate same-protocol hop
        (for example ``ACU → VIU`` on one CAN segment followed by
        ``VIU → IC`` on another CAN segment) and, because the start component
        was not in the visited set, could emit routes such as
        ``CEM → VCU → BCU → CEM``.  Generate shortest paths on the
        bidirectional component graph instead.  Component visitation is
        path-local, so no route can contain a repeated component; equal-length
        alternatives remain available for later interface/vector filtering.

        ``paths_per_pair`` is intentionally not applied here.  The parser may
        optionally apply an explicit display/compatibility cap, but production
        selection keeps every equal-shortest route.
        """
        all_paths: list[list[PathNodeVO]] = []
        for start_id in sorted(starts):
            if start_id not in component_by_id:
                continue

            # For each destination retain only the shortest distance and all
            # routes at that distance.  This prevents factorial growth from
            # enumerating longer simple detours while preserving every
            # shortest route that can be justified by the frozen topology.
            shortest_distance: dict[str, int] = {start_id: 0}
            shortest_paths: dict[str, list[list[PathNodeVO]]] = defaultdict(list)
            queue = deque([(start_id, frozenset({start_id}), [])])

            while queue:
                current_id, visited_components, path = queue.popleft()
                distance = len(path)
                # A shorter prefix may have been discovered after this state
                # was enqueued.  Do not expand the stale longer state; this
                # keeps unrestricted shortest-path enumeration bounded by
                # the actual equal-shortest alternatives rather than by
                # obsolete queue entries.
                known_current_distance = shortest_distance.get(current_id)
                if (
                    known_current_distance is not None
                    and distance > known_current_distance
                ):
                    continue
                line_ids = sorted(component_to_lines.get(current_id, set()))
                for line_id in line_ids:
                    for next_id in sorted(line_to_components.get(line_id, set())):
                        if next_id not in component_by_id or next_id in visited_components:
                            continue
                        next_distance = distance + 1
                        known_distance = shortest_distance.get(next_id)
                        if known_distance is not None and next_distance > known_distance:
                            continue

                        pair_left, pair_right = _canonical_pair(
                            current_id, next_id
                        )
                        direct_link_ids = (
                            (pair_link_ids or {}).get(
                                (line_id, pair_left, pair_right), set()
                            )
                        )
                        if direct_link_ids:
                            evidence_link_ids = set(direct_link_ids)
                        else:
                            evidence_link_ids = set(
                                (endpoint_link_ids or {}).get(
                                    (line_id, current_id), set()
                                )
                            )
                            evidence_link_ids.update(
                                (endpoint_link_ids or {}).get(
                                    (line_id, next_id), set()
                                )
                            )
                        node = PathNodeVO(
                            component_name_id=next_id,
                            component_name=component_by_id[next_id].name,
                            pre_component_name_id=current_id,
                            pre_component_name=component_by_id[current_id].name,
                            line_id=line_id,
                            color=line_id,
                            is_gateway=component_by_id[next_id].is_gateway,
                            channel_id=line_id,
                            topology_link_ids=tuple(sorted(evidence_link_ids)),
                        )
                        new_path = [*path, node]
                        if known_distance is None or next_distance < known_distance:
                            shortest_distance[next_id] = next_distance
                            shortest_paths[next_id] = [new_path]
                        else:
                            # Avoid duplicate routes when several raw link
                            # records represent the same channel transition.
                            signature = tuple(
                                (item.pre_component_name_id, item.component_name_id, item.channel_id)
                                for item in new_path
                            )
                            if not any(
                                tuple(
                                    (item.pre_component_name_id, item.component_name_id, item.channel_id)
                                    for item in existing
                                )
                                == signature
                                for existing in shortest_paths[next_id]
                            ):
                                shortest_paths[next_id].append(new_path)

                        # A state at a known shortest distance can still be
                        # needed to reach another component through a distinct
                        # channel, so enqueue every equal-shortest state.
                        new_visited = frozenset((*visited_components, next_id))
                        queue.append((next_id, new_visited, new_path))

            for target_id in sorted(shortest_paths):
                all_paths.extend(shortest_paths[target_id])
        return all_paths


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    text = (
        str(value)
        .replace("\n", " ")
        .replace("\r", " ")
        .replace("\u3000", " ")
        .strip()
    )
    return re.sub(r"\s+", " ", text)


def name_match_key(value: Any) -> str:
    """Return a case-insensitive key for cross-file names.

    DFD exports and topology/Excel exports often differ only in casing or
    visual line wrapping (``TACHO`` vs ``Tacho``, ``WIFI`` vs ``wifi``,
    ``BDU\\nPDU`` vs ``BDU PDU``).  Keep the original text for reports, and
    use this key only for identity comparisons.
    """
    text = str(value or "")
    # Some exporters serialize a line break literally as ``\\n`` while others
    # emit an actual newline.  Both represent the same visual node label.
    text = re.sub(r"\\[nrt]", "", text, flags=re.IGNORECASE)
    # Whitespace is layout in a topology label (e.g. ``BDU\\nPDU``), not part
    # of the identity.  Keep the original spelling for display/reporting.
    return re.sub(r"\s+", "", text).casefold()


def is_checked(value: Any) -> bool:
    normalized = normalize_text(value).lower()
    if not normalized:
        return False
    if any(mark in normalized for mark in ("√", "✓", "☑", "✅")):
        return True
    return normalized in {"1", "y", "yes", "true", "是", "有", "开", "通过"}


def excel_column_index(cell_reference: str) -> int:
    letters = "".join(
        character
        for character in cell_reference
        if character.isalpha()
    ).upper()
    index = 0
    for character in letters:
        index = index * 26 + (ord(character) - ord("A") + 1)
    return max(0, index - 1)


def determine_attack_vector(
    external_interface: str,
    color_name_map: dict,
    path_nodes: list[_PathNode],
    explicit_attack_vector: str | None = None,
) -> str:
    """按统一接口映射确定向量；无法识别时返回空字符串。"""
    if explicit_attack_vector:
        explicit = normalize_attack_vector(explicit_attack_vector)
        if explicit:
            return explicit

    interface_vector = normalize_attack_vector(external_interface)
    if interface_vector:
        return interface_vector

    # 没有可用外部接口时，才检查拓扑边界协议；协议同样必须命中统一别名。
    if path_nodes:
        protocol = color_name_map.get(path_nodes[0].color, "")
        protocol_vector = normalize_attack_vector(protocol)
        if protocol_vector:
            return protocol_vector
    return ""


def external_interface_key(value: Any) -> str:
    compact = re.sub(
        r"[\s\[\]（）()_\-]",
        "",
        normalize_text(value).casefold(),
    )
    return re.sub(
        r"(externalinterface|interface|channel|network|信道|接口|网络)$",
        "",
        compact,
    )


def same_external_interface(left: Any, right: Any) -> bool:
    left_key = external_interface_key(left)
    right_key = external_interface_key(right)
    return bool(left_key and right_key and left_key == right_key)


def protocol_key(value: Any) -> str:
    return re.sub(
        r"[\s\[\]（）()_\-/]",
        "",
        normalize_text(value).casefold(),
    )


def protocol_compatibility_key(value: Any) -> str:
    """Return the comparison family used for physical channel binding.

    A CAN-FD network can carry classical CAN frames.  The topology export
    commonly labels the physical channel ``CANFD`` while a DFD flow labels
    the transported signal ``CAN``.  Treat those two spellings as one
    *compatibility family* for endpoint/channel binding only.  Channel IDs
    are still intersected separately, so this does not merge two different
    CAN or CAN-FD buses.
    """

    key = protocol_key(value)
    if key in {"can", "canfd", "canfd总线", "canfd接口"}:
        return "can"
    return key


def same_protocol(left: Any, right: Any) -> bool:
    left_key = protocol_compatibility_key(left)
    right_key = protocol_compatibility_key(right)
    return bool(left_key and right_key and left_key == right_key)


def limit_shortest_frameworks(
    frameworks: list[dict],
    limit: int | None = None,
) -> list[dict]:
    """保留等长最短路径。

    默认不设置数量上限；调用方如确实需要展示/实验采样上限，可显式传入
    ``limit``。生产攻击路径链路使用默认值，以免固定上限误删真实入口。
    """
    if not frameworks:
        return []
    shortest = min(
        len(framework.get("path_nodes", []))
        for framework in frameworks
    )
    shortest_frameworks = [
        framework
        for framework in frameworks
        if len(framework.get("path_nodes", [])) == shortest
    ]
    if limit is None or len(shortest_frameworks) <= limit:
        return shortest_frameworks

    selected: list[dict] = []
    used_vectors: set[str] = set()
    for framework in shortest_frameworks:
        vector = normalize_attack_vector(
            framework.get("attack_vector", "")
        )
        if vector not in used_vectors:
            selected.append(framework)
            used_vectors.add(vector)
    for framework in shortest_frameworks:
        if framework not in selected:
            selected.append(framework)
        if len(selected) >= limit:
            break
    return selected[:limit]
