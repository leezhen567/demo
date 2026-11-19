"""线程安全、可复用的 TARA 本地持久化组件。"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import re
import sqlite3
import threading
from collections import Counter, defaultdict
from threading import Lock
from typing import Any, Optional

import orjson


logger = logging.getLogger(__name__)


def atomic_write_bytes(path: str, payload: bytes) -> None:
    """在目标目录内原子替换文件，避免中断后留下不完整结果。"""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    temp_path = os.path.join(
        directory,
        f".{os.path.basename(path)}.{os.getpid()}.{threading.get_ident()}.tmp",
    )
    try:
        with open(temp_path, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp_path, path)
    finally:
        if os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except OSError:
                pass


def save_json(data: Any, path: str) -> None:
    payload = orjson.dumps(
        data,
        option=orjson.OPT_INDENT_2 | orjson.OPT_NON_STR_KEYS,
    )
    atomic_write_bytes(path, payload)


class SemanticCache:
    """按规范化输入哈希索引的线程安全精确缓存。"""

    def __init__(self, max_bucket_size: int = 10000):
        self.max_bucket_size = max_bucket_size
        self._store: dict[str, dict[str, dict]] = defaultdict(dict)
        self._lock = Lock()
        self._revision = 0
        self._persisted_revisions: dict[str, int] = {}
        self._database: sqlite3.Connection | None = None
        self._database_path = ""
        self._legacy_path = ""
        self._model_namespaces: dict[str, str] = {}
        self.hits = 0
        self.misses = 0
        self.bucket_hits: Counter = Counter()
        self.bucket_misses: Counter = Counter()

    @staticmethod
    def _normalize(obj: Any) -> str:
        if isinstance(obj, (dict, list, tuple)):
            text = json.dumps(obj, ensure_ascii=False, sort_keys=True)
        else:
            text = str(obj)
        text = re.sub(r"\s+", "", text.lower().strip())
        return text.replace("：", ":")

    def save(self, path: str) -> bool:
        """仅在内容变化时持久化缓存；返回是否实际写盘。"""
        normalized_path = os.path.abspath(path)
        with self._lock:
            revision = self._revision
            if self._database is not None and normalized_path == self._legacy_path:
                # Each SQLite write is committed already; never overwrite a
                # concurrent worker's cache with a process-local JSON snapshot.
                changed = self._persisted_revisions.get(normalized_path) != revision
                if changed:
                    self._database.execute("PRAGMA wal_checkpoint(PASSIVE)")
                self._persisted_revisions[normalized_path] = revision
                return changed
            if (
                self._persisted_revisions.get(normalized_path) == revision
                and os.path.isfile(normalized_path)
            ):
                return False
            data = {
                bucket: [
                    {"hash": item["hash"], "value": item["value"]}
                    for item in items.values()
                ]
                for bucket, items in self._store.items()
            }
        try:
            payload = orjson.dumps(
                data,
                option=orjson.OPT_NON_STR_KEYS,
                default=str,
            )
            atomic_write_bytes(normalized_path, payload)
            with self._lock:
                self._persisted_revisions[normalized_path] = revision
            return True
        except Exception as exc:
            logger.warning("语义缓存持久化失败: %s", exc)
            return False

    def bind(self, path: str, *, model_namespaces: dict[str, str] | None = None) -> None:
        """Use a WAL database; the bucket limit applies only to hot memory.

        Import the old JSON snapshot once, retaining every stored entry. New
        requests are scoped to their provider/deployed model revision.
        """
        legacy_path = os.path.abspath(path)
        database_path = os.path.splitext(legacy_path)[0] + ".sqlite3"
        os.makedirs(os.path.dirname(database_path), exist_ok=True)
        with self._lock:
            if self._database_path != database_path:
                if self._database is not None:
                    self._database.close()
                    self._database = None
                    self._database_path = ""
                self._store.clear()
                database = sqlite3.connect(database_path, timeout=30, isolation_level=None, check_same_thread=False)
                database.execute("PRAGMA journal_mode=WAL")
                database.execute("PRAGMA synchronous=NORMAL")
                database.execute("CREATE TABLE IF NOT EXISTS cache_entries (bucket TEXT NOT NULL, key_hash TEXT NOT NULL, value BLOB NOT NULL, PRIMARY KEY(bucket,key_hash))")
                database.execute("CREATE TABLE IF NOT EXISTS cache_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                database.execute("BEGIN IMMEDIATE")
                try:
                    imported = database.execute("SELECT 1 FROM cache_meta WHERE key='legacy_json_imported'").fetchone()
                    if imported is None:
                        if os.path.isfile(legacy_path):
                            try:
                                with open(legacy_path, "rb") as source:
                                    legacy = orjson.loads(source.read())
                                if not isinstance(legacy, dict):
                                    legacy = {}
                            except (OSError, ValueError, TypeError) as exc:
                                logger.warning("旧 JSON 缓存无法导入，将使用新持久化缓存: %s", exc)
                                legacy = {}
                            for bucket, records in legacy.items():
                                if isinstance(records, dict):
                                    records = records.values()
                                database.executemany(
                                    "INSERT OR IGNORE INTO cache_entries(bucket,key_hash,value) VALUES(?,?,?)",
                                    ((bucket, item["hash"], orjson.dumps(item["value"], default=str))
                                     for item in records if isinstance(item, dict) and item.get("hash") and "value" in item),
                                )
                        database.execute("INSERT INTO cache_meta(key,value) VALUES('legacy_json_imported','1')")
                    database.commit()
                except BaseException:
                    database.rollback()
                    database.close()
                    raise
                self._database = database
                self._database_path = database_path
                self._legacy_path = legacy_path
            namespaces = dict(model_namespaces or {})
            if namespaces != self._model_namespaces:
                self._store.clear()
                self._model_namespaces = namespaces
            count = self._database.execute("SELECT COUNT(*) FROM cache_entries").fetchone()[0]
        logger.info("持久化精确缓存已连接: %s (%d items，内存上限不淘汰磁盘条目)", database_path, count)

    def close(self) -> None:
        with self._lock:
            if self._database is not None:
                self._database.close()
                self._database = None
            self._database_path = ""

    def _scoped_key_hash(self, key_obj: Any) -> str:
        model = key_obj.get("model") if isinstance(key_obj, dict) else None
        namespace = self._model_namespaces.get(model)
        if namespace:
            # New deployed-model scopes use exact canonical JSON, preserving
            # whitespace and case inside semantic strings. Legacy standalone
            # JSON caches retain their old hash contract for migration.
            payload = json.dumps({"model_namespace": namespace, "key": key_obj},
                                 ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
            return hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return self._key_hash(key_obj)

    def _remember(self, bucket: str, key_hash: str, value: Any) -> None:
        items = self._store[bucket]
        items.pop(key_hash, None)
        items[key_hash] = {"hash": key_hash, "value": copy.deepcopy(value)}
        while len(items) > self.max_bucket_size:
            items.pop(next(iter(items)))

    def _lookup(self, bucket: str, key_hash: str) -> Any:
        item = self._store.get(bucket, {}).get(key_hash)
        if item is not None:
            return item["value"]
        if self._database is not None:
            row = self._database.execute("SELECT value FROM cache_entries WHERE bucket=? AND key_hash=?", (bucket, key_hash)).fetchone()
            if row is not None:
                try:
                    value = orjson.loads(row[0])
                except (ValueError, TypeError):
                    self._database.execute("DELETE FROM cache_entries WHERE bucket=? AND key_hash=?", (bucket, key_hash))
                    return None
                self._remember(bucket, key_hash, value)
                return value
        return None

    def load(self, path: str) -> None:
        if not os.path.isfile(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as source:
                data = json.load(source)
            with self._lock:
                for bucket, items in data.items():
                    if isinstance(items, dict):
                        items = list(items.values())
                    for item in items:
                        key_hash = item.get("hash")
                        if key_hash:
                            self._store[bucket][key_hash] = item
                    while len(self._store[bucket]) > self.max_bucket_size:
                        self._store[bucket].pop(next(iter(self._store[bucket])))
            logger.info(
                "语义缓存已加载: %s (%d buckets, %d items)",
                path,
                len(data),
                sum(len(items) for items in data.values()),
            )
        except Exception as exc:
            logger.warning("语义缓存加载失败: %s", exc)

    def get(self, bucket: str, key_obj: Any) -> Optional[Any]:
        with self._lock:
            key_hash = self._scoped_key_hash(key_obj)
            value = self._lookup(bucket, key_hash)
            if value is None:
                self.misses += 1
                self.bucket_misses[bucket] += 1
                return None
            self.hits += 1
            self.bucket_hits[bucket] += 1
            self._remember(bucket, key_hash, value)
            return copy.deepcopy(value)

    def set(self, bucket: str, key_obj: Any, value: Any) -> None:
        with self._lock:
            key_hash = self._scoped_key_hash(key_obj)
            if self._database is not None:
                self._database.execute("INSERT OR REPLACE INTO cache_entries(bucket,key_hash,value) VALUES(?,?,?)", (bucket, key_hash, orjson.dumps(value, default=str)))
            self._remember(bucket, key_hash, value)
            self._revision += 1

    def delete(self, bucket: str, key_obj: Any) -> None:
        with self._lock:
            key_hash = self._scoped_key_hash(key_obj)
            removed = self._store.get(bucket, {}).pop(key_hash, None) is not None
            if self._database is not None:
                removed = bool(self._database.execute("DELETE FROM cache_entries WHERE bucket=? AND key_hash=?", (bucket, key_hash)).rowcount) or removed
            if removed:
                self._revision += 1

    def reset_metrics(self) -> None:
        """Reset hit/miss counters without clearing persisted cache entries."""
        with self._lock:
            self.hits = 0
            self.misses = 0
            self.bucket_hits.clear()
            self.bucket_misses.clear()

    def stats(self) -> dict[str, Any]:
        with self._lock:
            buckets = sorted(set(self.bucket_hits) | set(self.bucket_misses))
            total = self.hits + self.misses
            hit_rate = (self.hits / total) if total else 0.0
            by_bucket = {}
            for bucket in buckets:
                hits = int(self.bucket_hits[bucket])
                misses = int(self.bucket_misses[bucket])
                by_bucket[bucket] = {
                    "hits": hits,
                    "misses": misses,
                }
            return {
                "hits": self.hits,
                "misses": self.misses,
                "requests": total,
                "hit_rate": round(hit_rate, 4),
                "by_bucket": by_bucket,
            }

    @classmethod
    def _key_hash(cls, key_obj: Any) -> str:
        signature = cls._normalize(key_obj)
        return hashlib.sha256(signature.encode("utf-8")).hexdigest()
