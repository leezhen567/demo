"""Cross-process slots and estimated-token budgets for the local shared model.

These are application quotas, not proof of GPU capacity. Startup profiling and
actual workload tests remain necessary, especially for hybrid cache layouts.
"""
from contextlib import contextmanager
import os
import fcntl
from pathlib import Path
import sqlite3
import time
import uuid
from .context_policy import local_service_state, admission_budgets

ROOT = Path(__file__).resolve().parents[1]


class ModelAdmissionError(ValueError):
    """The request cannot safely enter the current shared-service quota."""


class ModelRequestCancelled(ModelAdmissionError):
    """The user stopped a request while it was waiting for quota or a switch."""


@contextmanager
def _db(path):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    db = sqlite3.connect(path, timeout=10)
    db.execute('CREATE TABLE IF NOT EXISTS leases (id TEXT PRIMARY KEY, pid INTEGER, role TEXT, tokens INTEGER)')
    try:
        with db:
            yield db
    finally:
        db.close()


def _alive(pid):
    try:
        os.kill(pid, 0)
        return Path(f'/proc/{pid}/stat').read_text().split()[2] != 'Z'
    except (OSError, ValueError):
        return False


@contextmanager
def _reserve_local_request(api_base, model, tokens, *, role='tara', timeout=240,
                    cancel_event=None, root=ROOT):
    state = local_service_state(api_base, model, root)
    if not state:
        yield
        return
    path = Path(root) / f'outputs/model_admission_private/{state.get("port",8000)}.sqlite3'
    budgets = admission_budgets(state)
    token_limit = budgets['total']
    slots = 2 if role == 'assistant' else 8
    role_budget = budgets[role]
    if tokens > role_budget:
        raise ModelAdmissionError(f'本次请求约{tokens} tokens，超过共享服务准入预算{role_budget}；请缩小窗口或拆分资料')
    identity = uuid.uuid4().hex
    deadline = time.monotonic() + timeout
    admitted = False
    try:
        while not admitted:
            if cancel_event is not None and cancel_event.is_set():
                raise ModelRequestCancelled('本轮助手请求已停止')
            with _db(path) as db:
                db.execute('BEGIN IMMEDIATE')
                rows = db.execute('SELECT id,pid,role,tokens FROM leases').fetchall()
                alive = []
                for row in rows:
                    if not _alive(row[1]):
                        db.execute('DELETE FROM leases WHERE id=?', (row[0],))
                    else:
                        alive.append(row)
                if (sum(row[2] == role for row in alive) < slots
                        and sum(row[3] for row in alive) + tokens <= token_limit
                        and (role == 'assistant' or sum(row[3] for row in alive if row[2]=='tara') + tokens <= role_budget)):
                    db.execute('INSERT INTO leases VALUES (?,?,?,?)',
                               (identity,os.getpid(),role,int(tokens)))
                    admitted = True
            if not admitted:
                if time.monotonic() >= deadline:
                    raise TimeoutError('共享模型服务繁忙，等待请求额度超时；当前任务资料仍已保存')
                time.sleep(.15)
        yield
    finally:
        if admitted:
            with _db(path) as db:
                db.execute('DELETE FROM leases WHERE id=?', (identity,))


@contextmanager
def reserve_request(api_base, model, tokens, *, role='tara', timeout=240,
                    cancel_event=None, root=ROOT):
    if not local_service_state(api_base, model, root):
        yield
        return
    path = Path(root)/'outputs/vllm/.switch.lock'
    path.parent.mkdir(parents=True,exist_ok=True)
    deadline = time.monotonic()+timeout
    with path.open('a') as lock:
        while True:
            try:
                fcntl.flock(lock,fcntl.LOCK_SH|fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if cancel_event is not None and cancel_event.is_set():
                    raise ModelRequestCancelled('本轮助手请求已停止')
                if time.monotonic() >= deadline:
                    raise TimeoutError('模型正在切换，等待服务就绪超时')
                time.sleep(.15)
        if not local_service_state(api_base,model,root):
            raise ModelAdmissionError('模型已切换，请使用当前模型重新发起任务')
        with _reserve_local_request(api_base,model,tokens,role=role,timeout=timeout,
                                    cancel_event=cancel_event,root=root):
            yield
