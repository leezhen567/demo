"""项目输入文件的默认发现规则。

目录按项目分组：``data/input/{项目}/{DFD,topology,information}``。
当前项目由 ``TARA_PROJECT`` 环境变量选择（默认 ``C808``）。
"""

from __future__ import annotations

import os
from pathlib import Path


def _project_name(default: str = "EU15") -> str:
    """返回当前 TARA 项目名（TARA_PROJECT，默认 C808）。"""
    return os.getenv("TARA_PROJECT", default).strip() or default


def newest_matching_file(
    directory: Path,
    pattern: str,
    *,
    fallback_name: str,
) -> Path:
    """选择目录中最后修改的匹配文件；没有候选时返回可诊断的回退路径。"""
    candidates = [path for path in directory.glob(pattern) if path.is_file()]
    if not candidates:
        return directory / fallback_name
    return max(
        candidates,
        key=lambda path: (path.stat().st_mtime_ns, path.name),
    )


def default_dfd_path(project_root: Path) -> Path:
    """返回默认 DFD 数据集目录（当前项目全部 DFD JSON）。"""
    return project_root / "data" / "input" / _project_name() / "DFD"


def default_topology_path(project_root: Path) -> Path:
    """自动选择拓扑目录中最新的 JSON，避免导出文件改名后入口失效。"""
    return newest_matching_file(
        project_root / "data" / "input" / _project_name() / "topology",
        "*.json",
        fallback_name="topology.json",
    )


def default_interfaces_path(project_root: Path) -> Path:
    """自动选择信息目录中最新的 Excel 接口清单。"""
    return newest_matching_file(
        project_root / "data" / "input" / _project_name() / "information",
        "*.xlsx",
        fallback_name="external_interfaces.xlsx",
    )
