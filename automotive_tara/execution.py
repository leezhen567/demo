"""Thread pools, bounded submission, metrics and phase timing."""

from __future__ import annotations

import logging
import os
import time
from collections import Counter
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from threading import Lock, Semaphore
from typing import Callable

from automotive_tara.storage import SemanticCache
from automotive_tara.llm import PROMPT_CACHE_METRIC_KEYS

logger = logging.getLogger(__name__)


class MetricsRegistry:
    def __init__(self) -> None:
        self.llm: Counter = Counter()
        self.llm_by_stage: dict[str, Counter] = {}
        self.pipeline: Counter = Counter()
        self.llm_lock = Lock()
        self.pipeline_lock = Lock()
        self.stage_lock = Lock()
        self.stage_times: dict[str, float] = {}
        self.phase_times: dict[str, float] = {
            "damage": 0.0,
            "threat": 0.0,
            "attack_path": 0.0,
            "impact": 0.0,
            "feasibility": 0.0,
        }
        self.phase_lock = Lock()

    def llm_stage_metrics(self, stage: str) -> Counter:
        """Return the per-stage counter updated under ``llm_lock``."""
        with self.llm_lock:
            return self.llm_by_stage.setdefault(stage, Counter())

    def llm_snapshot(self) -> dict[str, object]:
        with self.llm_lock:
            return {
                "http_requests": int(self.llm["http_requests"]),
                "successful_requests": int(self.llm["successful_requests"]),
                "failed_requests": int(self.llm["failed_requests"]),
                "retry_requests": int(self.llm["retry_requests"]),
                "http_seconds": round(float(self.llm["http_seconds"]), 3),
                "prompt_tokens": int(self.llm["prompt_tokens"]),
                "completion_tokens": int(self.llm["completion_tokens"]),
                "total_tokens": int(self.llm["total_tokens"]),
                **{key: int(self.llm[key]) for key in PROMPT_CACHE_METRIC_KEYS},
                "max_tokens_requested": int(
                    self.llm["max_tokens_requested"]
                ),
                "max_tokens_effective": int(
                    self.llm["max_tokens_effective"]
                ),
                "context_clamped_requests": int(
                    self.llm["context_clamped_requests"]
                ),
                "by_stage": {
                    stage: {
                        key: (
                            round(float(value), 3)
                            if key == "http_seconds"
                            else int(value)
                        )
                        for key, value in sorted(metrics.items())
                    }
                    for stage, metrics in sorted(self.llm_by_stage.items())
                },
            }

    def set_pipeline(self, name: str, value: int) -> None:
        with self.pipeline_lock:
            self.pipeline[name] = int(value)

    def increment_pipeline(self, name: str, value: int = 1) -> None:
        with self.pipeline_lock:
            self.pipeline[name] += int(value)

    def pipeline_snapshot(self) -> dict[str, int]:
        with self.pipeline_lock:
            return {
                key: int(value)
                for key, value in sorted(self.pipeline.items())
            }

    def reset(self) -> None:
        with self.llm_lock:
            self.llm.clear()
            self.llm_by_stage.clear()
        with self.pipeline_lock:
            self.pipeline.clear()
        with self.stage_lock:
            self.stage_times.clear()
        with self.phase_lock:
            self.phase_times.clear()
            self.phase_times.update({
                "damage": 0.0,
                "threat": 0.0,
                "attack_path": 0.0,
                "impact": 0.0,
                "feasibility": 0.0,
            })

    def set_stage_time(self, stage_name: str, elapsed: float) -> None:
        with self.stage_lock:
            self.stage_times[stage_name] = max(0.0, float(elapsed))

    def add_phase_time(self, phase: str, elapsed: float) -> None:
        with self.phase_lock:
            self.phase_times[phase] = (
                self.phase_times.get(phase, 0.0) + elapsed
            )


class StageTimer:
    def __init__(self, stage_name: str, registry: MetricsRegistry):
        self.stage_name = stage_name
        self.registry = registry
        self.start = 0.0

    def __enter__(self):
        self.start = time.perf_counter()
        logger.info("═══ [计时] %s 开始 ═══", self.stage_name)
        return self

    def __exit__(self, exc_type, exc_val, _exc_tb):
        elapsed = time.perf_counter() - self.start
        self.registry.set_stage_time(self.stage_name, elapsed)
        if exc_type is None:
            logger.info(
                "═══ [计时] %s 完成，耗时 %.2f 秒 (%.2f 分钟) ═══",
                self.stage_name,
                elapsed,
                elapsed / 60,
            )
        else:
            logger.error(
                "═══ [计时] %s 异常退出，耗时 %.2f 秒，错误: %s ═══",
                self.stage_name,
                elapsed,
                exc_val,
            )


class ExecutorRegistry:
    def __init__(self, max_pending_futures: int) -> None:
        self._pipeline: ThreadPoolExecutor | None = None
        self._attack_path: ThreadPoolExecutor | None = None
        self._attack_path_retry: ThreadPoolExecutor | None = None
        self._sc: ThreadPoolExecutor | None = None
        self._checkpoint: ThreadPoolExecutor | None = None
        self._lock = Lock()
        self._pending_slots = Semaphore(max_pending_futures)
        self.checkpoint_futures: list[Future] = []
        self.checkpoint_futures_lock = Lock()
        self._semantic_save_lock = Lock()
        self._semantic_save_state: dict[str, dict[str, bool]] = {}

    def pipeline(self, max_workers: int) -> ThreadPoolExecutor:
        if self._pipeline is None:
            with self._lock:
                if self._pipeline is None:
                    self._pipeline = ThreadPoolExecutor(
                        max_workers=max_workers,
                        thread_name_prefix="tara-pipeline",
                    )
                    logger.info(
                        "流水线线程池已初始化: max_workers=%d", max_workers
                    )
        return self._pipeline

    def sc(self, max_workers: int) -> ThreadPoolExecutor:
        if self._sc is None:
            with self._lock:
                if self._sc is None:
                    self._sc = ThreadPoolExecutor(
                        max_workers=max_workers,
                        thread_name_prefix="tara-sc",
                    )
                    logger.info(
                        "SC线程池已初始化: max_workers=%d", max_workers
                    )
        return self._sc

    def attack_path(self, max_workers: int) -> ThreadPoolExecutor:
        """攻击路径专用通道，避免影响评级的大队列造成隐性串行。"""
        if self._attack_path is None:
            with self._lock:
                if self._attack_path is None:
                    self._attack_path = ThreadPoolExecutor(
                        max_workers=max_workers,
                        thread_name_prefix="tara-attack-path",
                    )
                    logger.info(
                        "攻击路径线程池已初始化: max_workers=%d",
                        max_workers,
                    )
        return self._attack_path

    def attack_path_retry(self, max_workers: int = 8) -> ThreadPoolExecutor:
        """Bounded pool for missing-path repair calls, separate from producers."""
        if self._attack_path_retry is None:
            with self._lock:
                if self._attack_path_retry is None:
                    self._attack_path_retry = ThreadPoolExecutor(
                        max_workers=max(1, int(max_workers)),
                        thread_name_prefix="tara-attack-path-retry",
                    )
                    logger.info(
                        "攻击路径补生成线程池已初始化: max_workers=%d",
                        max(1, int(max_workers)),
                    )
        return self._attack_path_retry

    def checkpoint(self) -> ThreadPoolExecutor:
        if self._checkpoint is None:
            with self._lock:
                if self._checkpoint is None:
                    self._checkpoint = ThreadPoolExecutor(
                        max_workers=1,
                        thread_name_prefix="tara-checkpoint",
                    )
        return self._checkpoint

    def submit(
        self,
        executor: ThreadPoolExecutor,
        function: Callable,
        *args,
        **kwargs,
    ) -> Future:
        self._pending_slots.acquire()
        try:
            future = executor.submit(function, *args, **kwargs)
        except BaseException:
            self._pending_slots.release()
            raise
        future.add_done_callback(
            lambda _future: self._pending_slots.release()
        )
        return future

    def parallel_map(
        self,
        function: Callable,
        items: list,
        *,
        executor: ThreadPoolExecutor,
        window: int,
    ) -> None:
        for start in range(0, len(items), window):
            chunk = items[start : start + window]
            futures = {
                self.submit(executor, function, item): item for item in chunk
            }
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    logger.exception("并行重试任务异常: %s", exc)

    def save_semantic_cache_async(
        self, semantic_cache: SemanticCache, path: str
    ) -> None:
        normalized = os.path.abspath(path)
        with self._semantic_save_lock:
            state = self._semantic_save_state.setdefault(
                normalized, {"running": False, "requested": False}
            )
            state["requested"] = True
            if state["running"]:
                return
            state["running"] = True

        def drain() -> None:
            while True:
                with self._semantic_save_lock:
                    state = self._semantic_save_state[normalized]
                    state["requested"] = False
                semantic_cache.save(normalized)
                with self._semantic_save_lock:
                    state = self._semantic_save_state[normalized]
                    if state["requested"]:
                        continue
                    state["running"] = False
                    self._semantic_save_state.pop(normalized, None)
                    return

        try:
            future = self.checkpoint().submit(drain)
        except BaseException:
            with self._semantic_save_lock:
                self._semantic_save_state.pop(normalized, None)
            raise
        with self.checkpoint_futures_lock:
            self.checkpoint_futures.append(future)
