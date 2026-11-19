"""Auditable state machine for the customer-facing TARA input Agent.

The workflow is intentionally not an autonomous free-form coder.  It exposes
small, typed tools (inspect, plan, validate, apply, verify) and requires an
explicit confirmation transition before any isolated copy is written.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from automotive_tara.data_dependency import load_project_graph, project_context, validate_project_graph
from automotive_tara.data_editor_agent import apply_confirmed_edit_plan, prepare_edit_plan


@dataclass
class AgentEvent:
    phase: str
    title: str
    detail: str = ""
    tool: str = ""
    ok: bool = True
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


class TaraAgentWorkflow:
    PHASES = ("understand", "inspect", "propose", "validate", "await_confirmation", "apply", "verify", "complete")
    TOOLS = (
        {"name": "inspect_inputs", "purpose": "读取 DFD/拓扑/接口摘要和字段映射", "mutates": False},
        {"name": "build_dependency_graph", "purpose": "解析 source/target/protocol 上下游关系", "mutates": False},
        {"name": "propose_edit_plan", "purpose": "让模型输出受限结构化操作", "mutates": False},
        {"name": "validate_plan", "purpose": "检查 JSON path、对象唯一性和级联影响", "mutates": False},
        {"name": "apply_isolated_copy", "purpose": "确认后仅写入隔离副本", "mutates": True},
        {"name": "verify_consistency", "purpose": "重新解析并报告悬空关系/需重算结果", "mutates": False},
    )

    def __init__(self, *, dfd_paths: list[Path], topology_path: Path, interfaces_path: Path, editor_root: Path) -> None:
        self.dfd_paths = dfd_paths
        self.topology_path = topology_path
        self.interfaces_path = interfaces_path
        self.editor_root = editor_root
        self.phase = "understand"
        self.plan: dict[str, Any] | None = None
        # Keep the inspected graph for the lifetime of this interaction.  A
        # preview can be followed by confirmation immediately; reparsing the
        # same large Excel/JSON inputs in both steps only adds latency.
        self.graph: dict[str, Any] | None = None
        self.events: list[AgentEvent] = []

    def _event(self, phase: str, title: str, detail: str = "", *, tool: str = "", ok: bool = True) -> None:
        self.phase = phase
        self.events.append(AgentEvent(phase, title, detail, tool, ok))

    def inspect(self) -> dict[str, Any]:
        self._event("inspect", "读取项目输入", "仅读取原始文件，不产生写入", tool="inspect_inputs")
        graph = load_project_graph(self.dfd_paths, self.topology_path, self.interfaces_path)
        self.graph = graph
        context = project_context(self.dfd_paths, self.topology_path, self.interfaces_path, graph=graph)
        self._event("inspect", "依赖图已建立", f"DFD {len(graph.get('dfd', []))} 项、拓扑 {len(graph.get('topology', {}).get('nodes', []))} 节点", tool="build_dependency_graph")
        return {"context": context, "graph": graph}

    def propose(
        self,
        instruction: str,
        *,
        model: str,
        api_base: str,
        api_key: str = "",
    ) -> dict[str, Any]:
        if self.graph is None:
            # Build the graph once when callers skip the explicit inspect
            # button.  Subsequent propose/apply transitions reuse this cache.
            self.inspect()
        self._event("understand", "理解项目和用户任务", "识别资产、资产细项、协议、source、target 等语义")
        self._event("propose", "生成声明式修改计划", "模型只输出 operations，不直接写文件", tool="propose_edit_plan")
        self.plan = prepare_edit_plan(
            self.dfd_paths,
            self.topology_path,
            self.interfaces_path,
            instruction,
            model=model,
            api_base=api_base,
            api_key=api_key,
            graph=self.graph,
        )
        self._event("validate", "计划和级联影响已校验", f"直接操作 {len(self.plan.get('operations', []))} 项", tool="validate_plan")
        self._event("await_confirmation", "等待用户确认", "确认前不会修改任何文件")
        return self.plan

    def apply(self) -> tuple[list[Path], Path, Path, dict[str, Any]]:
        if not self.plan or not self.plan.get("operations"):
            raise ValueError("没有待确认的修改计划")
        if self.phase != "await_confirmation":
            raise ValueError("必须在 await_confirmation 阶段确认")
        self._event("apply", "写入隔离副本", "生产输入只读", tool="apply_isolated_copy")
        result = apply_confirmed_edit_plan(self.plan, dfd_paths=self.dfd_paths, topology_path=self.topology_path, interfaces_path=self.interfaces_path, editor_root=self.editor_root, confirmed=True, expected_plan_id=self.plan.get("plan_id"))
        copied_dfd, copied_topology, copied_interfaces, summary = result
        self._event("verify", "重新解析并校验一致性", "检查悬空 source/target 和协议关系", tool="verify_consistency")
        # apply_edit_plan already reparses the isolated copy and places the
        # validation result in its summary.  Reuse it instead of doing a
        # second full parse; retain a defensive fallback for older/custom
        # implementations that do not provide the field.
        verification = summary.get("修改后一致性校验") if isinstance(summary, dict) else None
        if not isinstance(verification, dict):
            graph = load_project_graph(copied_dfd, copied_topology, copied_interfaces)
            verification = validate_project_graph(graph)
        # The original graph is no longer authoritative after a successful
        # apply.  Drop it so a later inspect/propose interaction cannot reuse
        # stale identities from before the edit.
        self.graph = None
        summary["修改后一致性校验"] = verification
        if verification.get("errors"):
            self._event("verify", "一致性校验发现问题", "; ".join(verification["errors"][:3]), tool="verify_consistency", ok=False)
        else:
            self._event("complete", "修改完成", "可使用隔离副本启动 TARA 分析")
        return result

    def trace(self) -> dict[str, Any]:
        return {"phase": self.phase, "phases": list(self.PHASES), "tools": list(self.TOOLS), "events": [event.to_dict() for event in self.events], "plan_id": (self.plan or {}).get("plan_id", "")}
