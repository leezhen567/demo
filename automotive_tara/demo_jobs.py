"""Durable, single-slot analysis queue for the customer demo.

The worker owns analysis processes, not the browser's Gradio event. Keep one
worker until the model service has been capacity-tested under real workloads.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import signal
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect(root: Path) -> sqlite3.Connection:
    root.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(root / "queue.sqlite3", timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS jobs ("
        "job_id TEXT PRIMARY KEY, status TEXT NOT NULL, spec_path TEXT NOT NULL,"
        "pid INTEGER, attempts INTEGER NOT NULL DEFAULT 0, return_code INTEGER,"
        "created_at TEXT NOT NULL, updated_at TEXT NOT NULL, error TEXT)"
    )
    conn.commit()
    return conn


def enqueue(root: Path, job_id: str, spec: dict[str, Any]) -> None:
    job_dir = root / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    spec_path = job_dir / "job_spec.json"
    descriptor = os.open(spec_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as target:
            json.dump(spec, target, ensure_ascii=False)
    except BaseException:
        spec_path.unlink(missing_ok=True)
        raise
    with _connect(root) as conn:
        conn.execute(
            "INSERT INTO jobs(job_id,status,spec_path,created_at,updated_at)"
            " VALUES(?,?,?,?,?)",
            (job_id, "queued", str(spec_path), _now(), _now()),
        )
    ensure_worker(root)


def register_archive(root: Path, job_id: str, spec: Path, completed_at: str) -> None:
    """Register a completed report without giving the worker a runnable task."""
    with _connect(root) as conn:
        conn.execute(
            "INSERT INTO jobs(job_id,status,spec_path,created_at,updated_at,return_code)"
            " VALUES(?,?,?,?,?,0) ON CONFLICT(job_id) DO UPDATE SET spec_path=excluded.spec_path",
            (job_id, "completed", str(spec), completed_at, completed_at),
        )


def get_job(root: Path, job_id: str) -> dict[str, Any] | None:
    if not root.is_dir():
        return None
    with _connect(root) as conn:
        row = conn.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
    return dict(row) if row else None


def cancel_job(root: Path, job_id: str) -> bool:
    with _connect(root) as conn:
        cursor = conn.execute(
            "UPDATE jobs SET status=CASE WHEN status='queued' THEN 'cancelled' "
            "ELSE 'cancelling' END, updated_at=? "
            "WHERE job_id=? AND status IN ('queued','running')",
            (_now(), job_id),
        )
        return cursor.rowcount > 0


def ensure_worker(root: Path, *, python_bin: Path | None = None) -> None:
    """Launching duplicates is safe: only one process acquires the file lock."""
    root.mkdir(parents=True, exist_ok=True)
    subprocess.Popen(
        [str(python_bin or sys.executable), "-m", "automotive_tara.demo_jobs",
         "--root", str(root)],
        cwd=Path(__file__).resolve().parents[1],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
    )


def _alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        try:
            if Path(f"/proc/{pid}/stat").read_text().split()[2] == "Z":
                return False
        except (OSError, IndexError):
            pass
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _has_complete_report(result_root: Path) -> bool:
    for manifest_path in result_root.rglob("run_manifest.json"):
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            workbook = manifest.get("outputs", {}).get("xlsx")
            if workbook and Path(workbook).is_file():
                return True
        except (OSError, ValueError, TypeError, AttributeError):
            continue
    return False


def _recover(conn: sqlite3.Connection) -> None:
    for row in conn.execute(
        "SELECT job_id,pid,spec_path,status FROM jobs "
        "WHERE status IN ('running','cancelling')"
    ):
        if _alive(row["pid"]):
            if row["status"] == "cancelling":
                try:
                    os.killpg(row["pid"], signal.SIGTERM)
                except ProcessLookupError:
                    pass
            continue
        try:
            spec = json.loads(Path(row["spec_path"]).read_text(encoding="utf-8"))
            has_manifest = _has_complete_report(Path(spec["result_root"]))
            recovered_status = (
                "cancelled" if row["status"] == "cancelling" else
                "completed" if has_manifest else "queued"
            )
        except (OSError, ValueError, KeyError):
            recovered_status = "failed"
        conn.execute(
            "UPDATE jobs SET status=?, pid=NULL, updated_at=? WHERE job_id=?",
            (recovered_status, _now(), row["job_id"]),
        )
    conn.commit()


def _claim(conn: sqlite3.Connection) -> dict[str, Any] | None:
    conn.execute("BEGIN IMMEDIATE")
    active = conn.execute(
        "SELECT 1 FROM jobs WHERE status IN ('running','cancelling') LIMIT 1"
    ).fetchone()
    if active:
        conn.commit()
        return None
    row = conn.execute(
        "SELECT * FROM jobs WHERE status='queued' ORDER BY created_at LIMIT 1"
    ).fetchone()
    if row:
        conn.execute(
            "UPDATE jobs SET status='running', attempts=attempts+1, "
            "updated_at=? WHERE job_id=?",
            (_now(), row["job_id"]),
        )
    conn.commit()
    return dict(row) if row else None


def _run_job(conn: sqlite3.Connection, row: dict[str, Any]) -> None:
    job_id = row["job_id"]
    spec = json.loads(Path(row["spec_path"]).read_text(encoding="utf-8"))
    command = list(spec["command"])
    if row["attempts"] > 0 and "--fresh" in command:
        command.remove("--fresh")
    environment = os.environ.copy()
    environment.update(spec["env_updates"])
    log_path = Path(spec["log_path"])
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as log:
        log.write(f"\n[queue] attempt {row['attempts'] + 1} started {_now()}\n")
        log.flush()
        process = subprocess.Popen(
            command, cwd=spec["cwd"], env=environment,
            stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        conn.execute(
            "UPDATE jobs SET pid=?,updated_at=? WHERE job_id=?",
            (process.pid, _now(), job_id),
        )
        conn.commit()
        while process.poll() is None:
            status = conn.execute(
                "SELECT status FROM jobs WHERE job_id=?", (job_id,)
            ).fetchone()
            if status and status["status"] == "cancelling":
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
            time.sleep(1)
        cancelled = conn.execute(
            "SELECT status FROM jobs WHERE job_id=?", (job_id,)
        ).fetchone()["status"] == "cancelling"
        has_report = _has_complete_report(Path(spec["result_root"]))
        final_status = (
            "cancelled" if cancelled else
            "completed" if process.returncode == 0 and has_report else "failed"
        )
        error = (
            "pipeline_exited_without_report"
            if process.returncode == 0 and not has_report and not cancelled
            else None
        )
        conn.execute(
            "UPDATE jobs SET status=?,return_code=?,error=?,pid=NULL,updated_at=? "
            "WHERE job_id=?",
            (final_status, process.returncode, error, _now(), job_id),
        )
        conn.commit()
        log.write(f"[queue] {final_status} code={process.returncode} {_now()}\n")


def worker(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    with (root / "worker.lock").open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        with _connect(root) as conn:
            _recover(conn)
            while True:
                _recover(conn)
                row = _claim(conn)
                if row is None:
                    time.sleep(2)
                    continue
                try:
                    _run_job(conn, row)
                except Exception as exc:
                    conn.execute(
                        "UPDATE jobs SET status='failed',error=?,pid=NULL,"
                        "updated_at=? WHERE job_id=?",
                        (f"{type(exc).__name__}: {exc}"[:500], _now(), row["job_id"]),
                    )
                    conn.commit()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    worker(args.root)


if __name__ == "__main__":
    main()
