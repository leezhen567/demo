"""Independent serving, assistant and analysis request budgets.

Serving candidates are policy choices, not GPU-capacity measurements. vLLM's
startup profiling remains authoritative, including when adapters are enabled.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

TIERS = (262144, 131072, 65536, 32768, 16384, 8192, 4096, 2048)
TASK_DEFAULT = 16384
ASSISTANT_DEFAULT = 65536
ASSISTANT_MAX = 131072


def positive_int(value, default):
    try:
        number = int(value)
        return number if number > 0 else default
    except (TypeError, ValueError):
        return default


def local_service_state(api_base, model, root):
    """A different endpoint/model must never inherit local serving metadata."""
    try:
        url = urlsplit(api_base)
        state = json.loads((Path(root) / 'outputs/vllm/current.json').read_text())
        if (url.hostname not in {'localhost', '127.0.0.1', '::1'}
                or (url.port or 80) != int(state.get('port', 8000))
                or url.path.rstrip('/') not in {'', '/v1'}
                or model not in {state.get('served_name'), state.get('active_model'), state.get('lora_name')}):
            return {}
        return state
    except (OSError, ValueError, TypeError, AttributeError):
        return {}


def task_budget(capacity=None, requested=None):
    target = positive_int(requested, TASK_DEFAULT)
    return min(target, positive_int(capacity, 8192))


def admission_budgets(state):
    total = max(8192, int((state.get('kv_cache_tokens') or state['max_model_len']) *
                          (.70 if state.get('kv_cache_tokens') else 1)))
    reserve = min(65536,total // 4) if total >= 65536 else 0
    return {'total':total,'assistant':total,'tara':total-reserve}


def serving_candidates(model_path, *, lora_rank=0, requested=None):
    config = json.loads((Path(model_path) / 'config.json').read_text())
    text = config.get('text_config') or config
    native = positive_int(text.get('max_position_embeddings') or text.get('n_positions'), 8192)
    quantized = bool(config.get('quantization_config') or text.get('quantization_config'))
    # Keep one tier below native capacity, capped at 128K, for ordinary service.
    below_native = next((tier for tier in TIERS if tier < native), min(native, 8192))
    ceiling = min(131072 if quantized else 32768, below_native)
    if lora_rank:
        ceiling = min(ceiling, 32768 if lora_rank >= 128 else 65536)
    target = min(native, positive_int(requested, ceiling))
    candidates = [target] + [tier for tier in TIERS if 2048 <= tier < target]
    return {'native_context': native, 'quantized': quantized,
            'lora_rank': lora_rank, 'candidates': list(dict.fromkeys(candidates))}


def memory_failure(text):
    return bool(re.search(
        r'CUDA out of memory|OutOfMemoryError|No available memory for the cache blocks|'
        r'KV cache is needed|not enough GPU memory|maximum number of tokens.*KV cache|'
        r'free memory.*less than desired', text, re.I | re.S))


def next_serving_context(candidates, current, diagnostic):
    remaining = [value for value in candidates if value < current]
    match = re.search(r'estimated maximum model length is\s+(\d+)', diagnostic)
    if match:
        # Leave room beyond merely fitting one maximal request.
        safe = int(match.group(1)) * .85
        remaining = [value for value in remaining if value <= safe]
    return remaining[0] if remaining else None


def measured_kv_tokens(log_text):
    matches = re.findall(r'GPU KV cache size:\s*([\d,]+) tokens', log_text)
    return int(matches[-1].replace(',', '')) if matches else None


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('model_path')
    parser.add_argument('--lora-rank', type=int, default=0)
    args = parser.parse_args()
    print(serving_candidates(args.model_path, lora_rank=args.lora_rank)['candidates'][0])
