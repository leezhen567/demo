"""运行输出目录的统一分配规则。"""

from __future__ import annotations

import os
import re
from datetime import datetime
from pathlib import Path
from typing import Iterable


_VERSION_RE = re.compile(r"^V(\d+)(?:_|$)")


def safe_project_name(value: object, default: str = "TARA") -> str:
    """Return a filesystem-safe project label for jobs and report files."""

    text = Path(str(value or "")).name.strip()
    if not text:
        text = default
    # Keep Unicode letters (including Chinese project names), while replacing
    # separators, control characters and whitespace with a stable underscore.
    text = re.sub(r"[^\w.-]+", "_", text, flags=re.UNICODE)
    text = text.strip("._-") or default
    return text[:80]


def infer_project_name(
    paths: Iterable[str | os.PathLike[str] | None],
    *,
    default: str = "TARA",
    use_environment: bool = True,
) -> str:
    """Infer a project label from ``data/input/<project>/...`` paths.

    The web demo copies uploads into an isolated job directory, so the
    original upload paths are examined before copying.  For command-line
    runs, the same rule derives the project from the normal input tree.  An
    explicitly set ``TARA_PROJECT`` takes precedence when requested; unknown
    ad-hoc uploads use the neutral ``TARA`` fallback instead of a temp-folder
    or function filename.
    """

    if use_environment:
        configured = os.getenv("TARA_PROJECT", "").strip()
        if configured:
            return safe_project_name(configured, default)

    for raw_path in paths:
        if not raw_path:
            continue
        try:
            parts = list(Path(raw_path).expanduser().parts)
        except (TypeError, ValueError, OSError):
            continue
        for index in range(len(parts) - 2):
            if (
                parts[index].casefold() == "data"
                and parts[index + 1].casefold() == "input"
            ):
                candidate = parts[index + 2]
                if candidate.casefold() not in {
                    "dfd", "topology", "information"
                }:
                    return safe_project_name(candidate, default)
    return safe_project_name(default, "TARA")


def build_daily_run_dir(
    output_root: str | os.PathLike[str],
    *,
    now: datetime | None = None,
    unique_suffix: str | None = None,
) -> Path:
    """返回 ``输出根/日期/V版本``，不在导入阶段创建目录。

    版本号每天从 1 重新开始；时间和唯一后缀用于避免并发进程选择同一路径。
    """
    timestamp = now or datetime.now()
    day_dir = Path(output_root).expanduser().resolve() / timestamp.strftime(
        "%Y-%m-%d"
    )
    versions: list[int] = []
    if day_dir.is_dir():
        for child in day_dir.iterdir():
            if not child.is_dir():
                continue
            match = _VERSION_RE.match(child.name)
            if match:
                versions.append(int(match.group(1)))
    version = max(versions, default=0) + 1
    suffix = str(unique_suffix or os.getpid())
    name = f"V{version}_{timestamp.strftime('%H%M%S')}_{suffix}"
    return day_dir / name


def default_run_dir(
    project_root: str | os.PathLike[str],
    *,
    now: datetime | None = None,
    unique_suffix: str | None = None,
) -> Path:
    return build_daily_run_dir(
        Path(project_root) / "outputs",
        now=now,
        unique_suffix=unique_suffix,
    )


def default_shared_cache_dir(
    project_root: str | os.PathLike[str],
) -> Path:
    """共享缓存跨日期复用，不跟随单次运行目录移动。"""
    return Path(project_root).expanduser().resolve() / "outputs" / ".shared_cache"
