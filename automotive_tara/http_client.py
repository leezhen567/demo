"""可复用的 OpenAI 兼容 HTTP 基础设施。"""

from __future__ import annotations

import http.client
import time
from threading import Lock
from urllib.parse import urlparse


def parse_api_url(url: str) -> tuple[str, int, str]:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("TARA_API_BASE 仅支持 http 或 https")
    if not parsed.hostname:
        raise ValueError("TARA_API_BASE 缺少主机名")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("TARA_API_BASE 不允许在 URL 中携带凭据")
    if parsed.query or parsed.fragment:
        raise ValueError("TARA_API_BASE 不允许包含查询参数或片段")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError(f"TARA_API_BASE 端口无效: {exc}") from exc
    return parsed.hostname, port, parsed.path.rstrip("/")


def normalize_api_base(url: str) -> str:
    """Use one base for discovery, preflight and chat requests.

    Preserve custom provider prefixes and accept full endpoint URLs. Bare local
    vLLM and SenseNova hosts use their documented OpenAI-compatible /v1 base;
    other root-host APIs are left intact instead of guessing their protocol.
    """
    base = str(url or "").strip().rstrip("/")
    parse_api_url(base)
    for suffix in ("/chat/completions", "/models"):
        if base.endswith(suffix):
            base = base[:-len(suffix)].rstrip("/")
            break
    parsed = urlparse(base)
    if not parsed.path and parsed.hostname in {
        "localhost", "127.0.0.1", "::1", "token.sensenova.cn", "token.sensenova.ai",
    }:
        base += "/v1"
    return base


def api_endpoint(api_base: str, resource: str) -> str:
    return normalize_api_base(api_base) + "/" + resource.lstrip("/")


class HTTPConnectionPool:
    """线程安全的 HTTP Keep-Alive 连接池。"""

    def __init__(
        self,
        host: str,
        port: int = 80,
        max_size: int = 32,
        timeout: float = 120,
        use_https: bool = False,
        idle_ttl: float = 3.0,
    ):
        self._host = host
        self._port = port
        self._max_size = max_size
        self._timeout = timeout
        self._use_https = use_https
        self._idle_ttl = idle_ttl
        self._pool: list[tuple[http.client.HTTPConnection, float]] = []
        self._lock = Lock()

    def get(self) -> http.client.HTTPConnection:
        with self._lock:
            while self._pool:
                connection, returned_at = self._pool.pop()
                if (
                    time.monotonic() - returned_at <= self._idle_ttl
                    and connection.sock
                    and connection.sock.fileno() != -1
                ):
                    return connection
                try:
                    connection.close()
                except Exception:
                    pass
        connection_class = (
            http.client.HTTPSConnection
            if self._use_https
            else http.client.HTTPConnection
        )
        return connection_class(
            self._host,
            self._port,
            timeout=self._timeout,
        )

    def put(self, connection: http.client.HTTPConnection) -> None:
        with self._lock:
            if len(self._pool) < self._max_size:
                self._pool.append((connection, time.monotonic()))
            else:
                try:
                    connection.close()
                except Exception:
                    pass

    def close(self) -> None:
        with self._lock:
            for connection, _ in self._pool:
                try:
                    connection.close()
                except Exception:
                    pass
            self._pool.clear()
