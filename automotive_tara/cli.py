#!/usr/bin/env python3
"""Automotive TARA 命令行入口。"""

import argparse
import http.client
import json
import os
from pathlib import Path
from urllib.parse import urlparse

from automotive_tara.http_client import normalize_api_base
from automotive_tara.input_paths import (
    default_dfd_path,
    default_interfaces_path,
    default_topology_path,
)
from automotive_tara.run_paths import build_daily_run_dir


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _apply_vllm_runtime_defaults(env_updates: dict[str, str]) -> None:
    """Resolve an independent analysis budget against the selected service."""
    from .assistant_context import task_context_profile
    endpoint = env_updates.get('TARA_API_BASE', os.getenv('TARA_API_BASE', 'http://127.0.0.1:8000/v1'))
    model = env_updates.get('TARA_MODEL', os.getenv('TARA_MODEL', 'Qwen3.8-27B-AWQ-INT4'))
    key = env_updates.get('TARA_API_KEY', os.getenv('TARA_API_KEY', 'EMPTY'))
    requested = env_updates.get('TARA_TASK_CONTEXT_TOKENS', os.getenv('TARA_TASK_CONTEXT_TOKENS'))
    profile = task_context_profile(endpoint,model,key,requested=requested,root=PROJECT_ROOT)
    env_updates['TARA_TASK_CONTEXT_TOKENS'] = str(profile['effective'])
    env_updates['TARA_SERVICE_CONTEXT_TOKENS'] = str(profile['service_capacity'] or 0)


def discover_service_model(api_base: str, timeout: float = 5) -> str:
    """从 OpenAI 兼容服务发现模型名，避免切换模型后修改项目代码。"""
    try:
        parsed = urlparse(normalize_api_base(api_base))
    except ValueError:
        return ""
    connection_class = (
        http.client.HTTPSConnection
        if parsed.scheme == "https"
        else http.client.HTTPConnection
    )
    connection = connection_class(
        parsed.hostname,
        parsed.port,
        timeout=timeout,
    )
    base_path = parsed.path.rstrip("/")
    models_path = f"{base_path}/models"
    try:
        connection.request(
            "GET",
            models_path,
            headers={
                "Authorization": (
                    f"Bearer {os.getenv('TARA_API_KEY', 'EMPTY')}"
                )
            },
        )
        response = connection.getresponse()
        body = response.read()
        if response.status != 200:
            return ""
        payload = json.loads(body)
        model_ids = [
            str(item["id"])
            for item in payload.get("data", [])
            if isinstance(item, dict) and item.get("id")
        ]
        # When vLLM exposes both a base model and a LoRA adapter, the base
        # model is usually listed first.  Prefer the adapter recorded by the
        # last safe switch so a plain ``python -m automotive_tara`` invocation
        # does not silently bypass the fine-tuned model.
        preferred: list[str] = []
        configured_lora = os.getenv("TARA_VLLM_LORA_NAME", "").strip()
        if configured_lora:
            preferred.append(configured_lora)
        try:
            state = json.loads(
                (PROJECT_ROOT / "outputs" / "vllm" / "current.json")
                .read_text(encoding="utf-8")
            )
            active_model = str(
                state.get("active_model") or state.get("lora_name") or ""
            ).strip()
            if active_model:
                preferred.append(active_model)
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            pass
        for candidate in preferred + model_ids:
            if candidate in model_ids:
                return candidate
    except Exception:
        return ""
    finally:
        connection.close()
    return ""



def _local_impact_adapter_route(api_base: str, selected_model: str) -> tuple[str, str] | None:
    """Route a locally served impact-only adapter without changing other stages."""
    parsed = urlparse(api_base)
    if parsed.hostname not in {"127.0.0.1", "localhost"}:
        return None
    try:
        state = json.loads(
            (PROJECT_ROOT / "outputs" / "vllm" / "current.json").read_text(encoding="utf-8")
        )
        if not isinstance(state, dict) or selected_model != state.get("lora_name"):
            return None
        if parsed.port != int(state.get("port", 8000)):
            return None
        base_model = str(state.get("served_name") or "").strip()
        adapter_path = str(state.get("lora_path") or "").strip()
        if not base_model or not adapter_path or base_model == selected_model:
            return None
        manifest = json.loads(
            (Path(adapter_path).parent / "run_manifest.json").read_text(encoding="utf-8")
        )
        stages = manifest.get("environment", {}).get("stages", {})
        if not isinstance(stages, dict) or set(stages) != {"impact"}:
            return None
        if int(stages["impact"]) <= 0:
            return None
        return base_model, selected_model
    except (FileNotFoundError, OSError, ValueError, TypeError, AttributeError):
        return None


def _output_filename(value: str) -> str:
    """仅接受文件名，避免 --output-name 越过所选输出目录。"""
    if not value or Path(value).name != value or value in {".", ".."}:
        raise argparse.ArgumentTypeError("--output-name 必须是不含目录的文件名")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="运行汽车网络安全 TARA 分析")
    parser.add_argument(
        "--dfd",
        default=str(default_dfd_path(PROJECT_ROOT)),
        help="DFD JSON 文件或目录",
    )
    parser.add_argument(
        "--topology",
        default=str(default_topology_path(PROJECT_ROOT)),
        help="拓扑 JSON 文件",
    )
    parser.add_argument(
        "--interfaces",
        default=str(default_interfaces_path(PROJECT_ROOT)),
        help="对外接口 Excel",
    )
    parser.add_argument(
        "--output-dir",
        help="输出根目录；程序会在其下自动创建 YYYY-MM-DD/V版本目录",
    )
    parser.add_argument(
        "--output-name", default="tara_report.json", type=_output_filename
    )
    parser.add_argument("--method", choices=("attack_potential", "attack_vector", "cvss", "heavens"))
    parser.add_argument("--impact-method", choices=("21434", "heavens", "heavens_4level"))
    parser.add_argument("--model", help="OpenAI 兼容服务中的基础模型名")
    parser.add_argument("--impact-model", help="仅影响评级阶段使用的模型名；默认与 --model 相同")
    parser.add_argument("--api-base", help="例如 http://127.0.0.1:8000/v1")
    parser.add_argument("--api-key", help="外部 OpenAI 兼容接口密钥（不写入报告）")
    parser.add_argument("--llm-retries", type=int, dest="llm_retries", help="传输层重试次数；默认 1，0 表示关闭")
    parser.add_argument("--temperature", type=float, help="请求级 Temperature")
    parser.add_argument("--top-p", type=float, dest="top_p", help="请求级 Top P")
    parser.add_argument("--top-k", type=int, dest="top_k", help="请求级 Top K")
    parser.add_argument("--frequency-penalty", type=float, dest="frequency_penalty", help="请求级 Frequency Penalty")
    parser.add_argument("--presence-penalty", type=float, dest="presence_penalty", help="请求级 Presence Penalty")
    parser.add_argument("--max-assets", type=int, help="仅分析前 N 个资产，用于冒烟测试")
    parser.add_argument("--asset-selection-file", help="交互式资产范围 JSON（精确 include/exclude 身份）")
    parser.add_argument(
        "--fast",
        action="store_true",
        help="快速可行性模式：攻击路径仍由 LLM 生成，可行性改用 attack_vector 查表",
    )
    parser.add_argument("--fresh", action="store_true", help="忽略已有检查点，仍复用有效的结果/条目缓存")
    parser.add_argument("--enable-rag", action="store_true", help="显式启用实验性 RAG")
    reason_group = parser.add_mutually_exclusive_group()
    reason_group.add_argument(
        "--reason",
        "--enable-reason",
        dest="reason",
        action="store_true",
        help="强制模型为影响评级和可行性评级输出完整理由",
    )
    reason_group.add_argument(
        "--no-reason",
        "--disable-reason",
        dest="reason",
        action="store_false",
        help="禁止模型输出影响评级和可行性评级理由",
    )
    parser.set_defaults(reason=None)
    parser.add_argument("--skip-preflight", action="store_true", help="跳过 LLM /models 预检")
    parser.add_argument(
        "--capture-training",
        action="store_true",
        help="旁路采集模型调用和最终采用结果，不增加 LLM 调用",
    )
    parser.add_argument(
        "--capture-rejected",
        action="store_true",
        help="训练采集时同时保留失败的 HTTP/解析候选",
    )
    return parser


def main() -> None:
    args = _parser().parse_args()
    if args.fast and args.method and args.method != "attack_vector":
        raise SystemExit("--fast 与非 attack_vector 的 --method 不能同时使用")
    env_updates = {
        "TARA_DFD_FILE": args.dfd,
        "TARA_TOPOLOGY_FILE": args.topology,
        "TARA_EXTERNAL_INTERFACE_EXCEL": args.interfaces,
    }
    if args.output_dir:
        env_updates["TARA_OUTPUT_DIR"] = str(
            build_daily_run_dir(args.output_dir)
        )
    if args.method:
        env_updates["TARA_FEASIBILITY_METHOD"] = args.method
    if args.fast:
        env_updates["TARA_FEASIBILITY_METHOD"] = "attack_vector"
    if args.impact_method:
        env_updates["TARA_IMPACT_METHOD"] = args.impact_method
    if args.model:
        env_updates["TARA_MODEL"] = args.model
    if args.impact_model:
        env_updates["TARA_IMPACT_MODEL"] = args.impact_model
    if args.api_base:
        env_updates["TARA_API_BASE"] = args.api_base
    if args.api_key:
        env_updates["TARA_API_KEY"] = args.api_key
    if args.llm_retries is not None:
        if args.llm_retries < 0:
            raise SystemExit("--llm-retries 必须大于等于 0")
        env_updates["TARA_LLM_RETRIES"] = str(args.llm_retries)
    if args.temperature is not None:
        env_updates["TARA_TEMPERATURE"] = str(args.temperature)
    if args.top_p is not None:
        env_updates["TARA_TOP_P"] = str(args.top_p)
    if args.top_k is not None:
        env_updates["TARA_TOP_K"] = str(args.top_k)
    if args.frequency_penalty is not None:
        env_updates["TARA_FREQUENCY_PENALTY"] = str(args.frequency_penalty)
    if args.presence_penalty is not None:
        env_updates["TARA_PRESENCE_PENALTY"] = str(args.presence_penalty)
    if not args.model and not os.getenv("TARA_MODEL"):
        api_base = args.api_base or os.getenv(
            "TARA_API_BASE", "http://127.0.0.1:8000/v1"
        )
        discovered_model = discover_service_model(api_base)
        if discovered_model:
            route = _local_impact_adapter_route(api_base, discovered_model)
            if route is None:
                env_updates["TARA_MODEL"] = discovered_model
            else:
                env_updates["TARA_MODEL"] = route[0]
                if not args.impact_model and not os.getenv("TARA_IMPACT_MODEL"):
                    env_updates["TARA_IMPACT_MODEL"] = route[1]
    if args.max_assets is not None:
        if args.max_assets <= 0:
            raise SystemExit("--max-assets 必须大于 0")
        env_updates["TARA_TEST_MAX_ASSETS"] = str(args.max_assets)
    if args.asset_selection_file:
        from automotive_tara.asset_selection import validate_selection
        with open(args.asset_selection_file, encoding='utf-8') as source:
            validate_selection(json.load(source))
        env_updates['TARA_ASSET_SELECTION_PATH'] = str(Path(args.asset_selection_file).resolve())
    if args.fresh:
        env_updates["TARA_SKIP_CHECKPOINT"] = "1"
    if args.enable_rag:
        env_updates["TARA_ENABLE_RAG"] = "1"
        env_updates.setdefault("TARA_RAG_METHOD", "bge-m3")
    if args.reason is not None:
        env_updates["TARA_ENABLE_REASON"] = "1" if args.reason else "0"
    if args.skip_preflight:
        env_updates["TARA_LLM_PREFLIGHT"] = "0"
    if args.capture_training or args.capture_rejected:
        env_updates["TARA_CAPTURE_TRAINING"] = "1"
    if args.capture_rejected:
        env_updates["TARA_CAPTURE_REJECTED"] = "1"
    _apply_vllm_runtime_defaults(env_updates)
    os.environ.update(env_updates)

    from automotive_tara import pipeline

    output_path = os.path.join(pipeline.OUTPUT_DIR, args.output_name)
    pipeline.run_tara(
        data_flow_dir=args.dfd,
        topology_file=args.topology,
        external_interface_excel=args.interfaces,
        output_path=output_path,
        feasibility_method=args.method or pipeline.FEASIBILITY_METHOD,
        max_assets_for_test=(
            args.max_assets if args.max_assets is not None else pipeline.TEST_MAX_ASSETS
        ),
        skip_checkpoint_resume=args.fresh or pipeline.SKIP_CHECKPOINT,
    )


if __name__ == "__main__":
    main()
