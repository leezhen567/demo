"""Automotive TARA 分析包。

命令行可使用 ``python -m automotive_tara``，Python 调用方可使用
``automotive_tara.run_tara(...)``。流水线采用延迟导入，读取轻量领域模型时
不会初始化运行目录或加载可选的数据/RAG依赖。
"""

from typing import Any

from .domain import (
    PathNodeVO,
    TaskUnit,
    TopologyElementType,
    TopologyElementVO,
)

__all__ = [
    "PathNodeVO",
    "TaskUnit",
    "TopologyElementType",
    "TopologyElementVO",
    "run_tara",
]


def run_tara(*args: Any, **kwargs: Any):
    """延迟加载并运行完整 TARA 流水线。"""
    from .pipeline import run_tara as _run_tara

    return _run_tara(*args, **kwargs)
