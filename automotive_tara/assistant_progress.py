"""Request-local evidence tracking; repeated decisions are not tool progress."""
import hashlib
import json


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, default=str).encode()).hexdigest()


def canonical_call(name, arguments):
    query = str(arguments.get('query') or '').strip()
    try:
        query = json.loads(query)
    except ValueError:
        pass
    limit = arguments.get('limit') or 5
    if name in {'read_repository_file', 'repository_tree'}:
        if isinstance(query, str):
            query = {'path': query or '.'}
        if isinstance(query, dict):
            query = dict(query)
            for key, default in (('start_line', 1), ('offset', 0), ('depth', 2)):
                if query.get(key) == default:
                    query.pop(key)
        limit = None  # These adapters do not use the outer search-result limit.
    return digest([name, query, limit])


def _meaningful(value):
    if isinstance(value, dict):
        return {key: _meaningful(item) for key, item in value.items()
                if key not in {'time', 'timestamp', 'updated_at', 'elapsed_seconds', 'query',
                               'evidence_version', 'duration_ms', 'start_line', 'end_line',
                               'start_row', 'end_row', 'next_offset', 'offset'}}
    if isinstance(value, list):
        return [_meaningful(item) for item in value]
    return value


class EvidenceProgress:
    def __init__(self):
        self.calls = {}
        self.results = set()
        self.executed = self.reused = self.stalled_rounds = 0

    def previous(self, name, arguments, version):
        return self.calls.get((canonical_call(name, arguments), version))

    def record(self, name, arguments, version, result):
        signature = digest(_meaningful(result))
        useful = signature not in self.results and not result.get('error') and not result.get('reused_action')
        self.results.add(signature)
        self.executed += 1
        entry = {'tool': name, 'source': result.get('source', name), 'evidence_id': signature[:16],
                 'failed': bool(result.get('error'))}
        self.calls[(canonical_call(name, arguments), version)] = entry
        return useful

    def reuse(self, previous):
        self.reused += 1
        return {'source': previous['source'], 'reused_evidence': True,
                'evidence_id': previous['evidence_id'], 'new_evidence': False,
                'notice': '相同参数对应的文件/任务证据没有变化，未再次执行。引用已有结果；换用有实质区别的工具或直接回答。'}

    def round(self, progressed):
        self.stalled_rounds = 0 if progressed else self.stalled_rounds + 1
        return self.stalled_rounds >= 2
