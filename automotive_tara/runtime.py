"""流水线阶段的显式运行时依赖。

阶段模块只接收 :class:`RuntimeContext`，不反向导入 ``pipeline``，也不在
导入时复制环境变量或可变缓存。这样每次运行可以拥有独立配置、服务和指标，
测试亦可在构造上下文前替换兼容入口。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock
from typing import Any, Callable, Mapping, MutableMapping


MetricRecorder = Callable[[str, int], None]


@dataclass(slots=True)
class RuntimeContext:
    """一个 TARA 运行所需的配置、服务、共享状态和指标记录器。"""

    config: Mapping[str, Any]
    services: Mapping[str, Callable[..., Any]]
    state: MutableMapping[str, Any] = field(default_factory=dict)
    record_metric: MetricRecorder | None = None
    _lock: Lock = field(default_factory=Lock, repr=False)

    def setting(self, name: str, default: Any = None) -> Any:
        return self.config.get(name, default)

    def service(self, name: str) -> Callable[..., Any]:
        try:
            return self.services[name]
        except KeyError as exc:
            raise RuntimeError(f"RuntimeContext 缺少服务: {name}") from exc

    def shared(self, name: str, default: Any = None) -> Any:
        return self.state.get(name, default)

    def set_shared(self, name: str, value: Any) -> None:
        with self._lock:
            self.state[name] = value

    def increment(self, name: str, value: int = 1) -> None:
        if self.record_metric is not None:
            self.record_metric(name, value)


def require_settings(ctx: RuntimeContext, *names: str) -> tuple[Any, ...]:
    """读取必需配置；缺失时尽早失败，而不是在阶段中静默使用错误默认值。"""

    missing = [name for name in names if name not in ctx.config]
    if missing:
        raise RuntimeError(f"RuntimeContext 缺少配置: {', '.join(missing)}")
    return tuple(ctx.config[name] for name in names)
