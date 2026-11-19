"""Bounded response-only journal for the running demo (no extra model calls)."""
from __future__ import annotations
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

_lock = threading.Lock()


def append_model_event(root, record, *, stage=''):
    if not root:
        return
    event = {'time': datetime.now(timezone.utc).isoformat(), 'stage': stage,
             'status': record.get('status'), 'model': record.get('request', {}).get('model'),
             'attempt': record.get('attempt'), 'elapsed_seconds': record.get('elapsed_seconds'),
             'usage': record.get('usage', {}),
             'output': '\n'.join(str(s) for s in record.get('choices', []))[:32000],
             'error': str(record.get('error') or '')[:1800]}
    path = Path(root) / 'model_responses_live.jsonl'
    path.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        if path.is_file() and path.stat().st_size > 4 * 1024 * 1024:
            with path.open('rb') as source:
                source.seek(-512000, 2)
                tail = source.read().split(b'\n', 1)[-1]
            path.write_bytes(tail)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(descriptor, 'w', encoding='utf-8') as target:
            target.write(json.dumps(event, ensure_ascii=False) + '\n')


def read_model_events(root, limit=4):
    paths = list(Path(root).rglob('model_responses_live.jsonl')) if root and Path(root).is_dir() else []
    if not paths:
        return []
    path = max(paths, key=lambda p: p.stat().st_mtime_ns)
    with path.open('rb') as stream:
        stream.seek(max(0, path.stat().st_size - 256000))
        lines = stream.read().decode('utf-8', errors='replace').splitlines()
    events = []
    for line in lines:
        try:
            value = json.loads(line)
            if isinstance(value, dict):
                events.append(value)
        except ValueError:
            continue
    return events[-max(1, min(12, limit)):]
