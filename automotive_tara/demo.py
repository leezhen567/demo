"""Brandable Gradio customer demo for the AI for TARA pipeline.

The UI deliberately exposes auditable workflow evidence (stage progress,
structured model outputs, rating reasons, validation and retry events) rather
than a model's private hidden chain-of-thought.
"""

from __future__ import annotations

import argparse
import base64
import glob
import html
import logging
import json
import math
import os
import queue
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
import zipfile
from contextlib import nullcontext
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from functools import partial, wraps
from pathlib import Path
from typing import Any, Generator, Iterable
from urllib.parse import urlparse
from urllib import request as urlrequest

os.environ.setdefault("GRADIO_ANALYTICS_ENABLED", "False")
os.environ.setdefault("MPLCONFIGDIR", "/tmp/tara-matplotlib")
_no_proxy_entries = [
    item.strip() for item in os.getenv("NO_PROXY", os.getenv("no_proxy", "")).split(",")
    if item.strip()
]
for _local_host in ("localhost", "127.0.0.1", "::1"):
    if _local_host not in _no_proxy_entries:
        _no_proxy_entries.append(_local_host)
os.environ["NO_PROXY"] = ",".join(_no_proxy_entries)
os.environ["no_proxy"] = os.environ["NO_PROXY"]

import gradio as gr

from automotive_tara.api_service import APIServiceError, check_api_service, list_service_models
from automotive_tara.http_client import normalize_api_base
from automotive_tara.llm import PROMPT_CACHE_METRIC_KEYS, extract_prompt_cache_usage
from automotive_tara.cli import _local_impact_adapter_route, discover_service_model
from automotive_tara import demo_jobs
from automotive_tara.demo_portable import API_REQUIRED, CASE_ID, configured_api, install_history, require_api
from automotive_tara.data_editor_agent import (
    DataEditError,
    apply_confirmed_edit_plan,
    prepare_edit_plan,
)
from automotive_tara.dfd_compat import (
    convert_new_dfd_directory,
    convert_new_dfd_json,
    detect_dfd_format,
    normalize_dfd_json,
    prepare_dfd_directory,
)
from automotive_tara.adaptive_runtime import derive_runtime_profile
from automotive_tara.config import _runtime_defaults_for_model
from automotive_tara.run_paths import infer_project_name
from automotive_tara.domain import (
    AP_ALLOWED_VALUES,
    CVSS_C,
    CVSS_P,
    CVSS_U,
    CVSS_V,
    HEAVENS_AP_ALLOWED_VALUES,
    HEAVENS_DIM_WEIGHTS,
)
from automotive_tara.report_editor_agent import (
    EDITABLE_REPORT_FIELDS,
    ReportEditError,
    apply_report_edit_plan,
    prepare_report_edit_plan,
    report_row_catalog,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEMO_ROOT = PROJECT_ROOT / "outputs" / "customer_demo"
DEMO_QUEUE_ROOT = PROJECT_ROOT / "outputs" / "demo_queue_private"
PYTHON_BIN = Path(os.getenv("TARA_PYTHON", sys.executable))
API_BASE = os.getenv("TARA_API_BASE", "").strip() if configured_api() else ""
GRADIO_CACHE_ROOT = Path(os.getenv("GRADIO_TEMP_DIR", "/tmp/gradio"))
BRAND_ASSET_ROOT = PROJECT_ROOT / "subprojects" / "web_demo" / "assets" / "branding"
MODEL_ROOT = Path(os.getenv("TARA_MODEL_ROOT", str(PROJECT_ROOT / "models"))).resolve()
LORA_ROOT = Path(
    os.getenv("TARA_LORA_ROOT", str(PROJECT_ROOT / "outputs" / "fine_tuning"))
).resolve()
# The 2026-10-13 impact-only adapter is an explicit opt-in; vLLM must advertise
# it alongside its base model before a job can use it.
IMPACT_LORA_RELATIVE = (
    "35b-a3b-lora/impact-rating-four-workbooks-batch-v1/adapter"
)
NO_LORA_VALUE = ""
NO_LORA_LABEL = "不加载 LoRA（仅使用基座模型）"
VLLM_SWITCH_SCRIPT = PROJECT_ROOT / "scripts" / "switch_vllm.py"
logger = logging.getLogger(__name__)

# Gradio's default event pool used to be limited to one task.  That made a
# long-running TARA analysis block uploads, validation and every other small
# UI interaction for all browser sessions.  Keep the expensive, GPU-bound
# operations in their own single-slot pool, while allowing lightweight UI
# work to remain responsive for several users.
DEMO_QUEUE_MAX_SIZE = 32
DEMO_DEFAULT_CONCURRENCY_LIMIT = 8
DEMO_HEAVY_CONCURRENCY_LIMIT = 1
DEMO_HEAVY_CONCURRENCY_ID = "tara-analysis"
DEMO_PROGRESS_INTERVAL_SECONDS = 2.0
DEMO_JOB_POLL_INTERVAL_SECONDS = 4.0
DEMO_PREVIEW_ROW_LIMIT = 20
# Customer-facing Demo runs must never write prompt/output training data.
# Keep the function argument for API compatibility with existing callers, but
# make the web product's capture policy explicit and non-overridable.
DEMO_TRAINING_CAPTURE_ENABLED = False
# The showcase and AI-analysis variants share the same UI and vLLM endpoint.
# Their security-requirement strategy is selected once when the Demo process
# starts, then passed explicitly to each child TARA process.
DEMO_SECURITY_REQUIREMENTS_LLM = os.getenv(
    "TARA_DEMO_SECURITY_REQUIREMENTS_LLM", "0"
).strip().lower() in {"1", "true", "yes", "on"}

IMPACT_CHOICES = [
    ("ISO/SAE 21434（4级）", "21434"),
    ("HEAVENS 加权（5级）", "heavens"),
    ("HEAVENS 兼容（4级）", "heavens_4level"),
]
FEASIBILITY_CHOICES = [
    ("Attack Potential", "attack_potential"),
    ("Attack Vector", "attack_vector"),
    ("CVSS", "cvss"),
    ("HEAVENS", "heavens"),
]
DFD_FORMAT_CHOICES = [
    ("自动识别 DFD（旧版直接解析，新版自动转换）", "auto"),
    ("新版 DFD（自动转换为旧版兼容格式）", "new"),
    ("旧版 DFD（直接使用）", "legacy"),
]
_VALID_IMPACT_METHODS = {value for _, value in IMPACT_CHOICES}
_VALID_FEASIBILITY_METHODS = {value for _, value in FEASIBILITY_CHOICES}
SCOPE_CHOICES = [
    ("快速演示 · 前 10 个资产", "10"),
    ("标准演示 · 每个 DFD 各取一个部件/信号/数据", "per_dfd_type"),
    ("完整项目分析 · 全部资产", "all"),
]
RUNTIME_PRESET_CHOICES = [
    ("稳定生产", "stable"),
    ("质量平衡", "balanced"),
    ("高速运行", "fast"),
]

PREVIEW_COLUMNS = (
    ("功能", 130, False),
    ("元素编号", 90, False),
    ("资产", 130, False),
    ("安全属性", 90, False),
    ("路径编号", 70, False),
    ("损害场景", 300, False),
    ("威胁场景", 300, False),
    ("影响等级", 90, False),
    ("影响评级理由", 280, True),
    ("攻击路径", 340, False),
    ("可行性等级", 100, False),
    ("可行性评级理由", 280, True),
    ("风险值", 80, False),
    ("安全需求", 260, False),
    ("国标法规编码", 180, False),
    ("附录5 Part B/C映射", 180, False),
)

# 与 ``tools/DFD数据流表格提取.html`` 保持同一提取口径。Flow 的每个
# propertyList 都是一项独立信号资产；网页不暴露内部元素类型映射。
DFD_EXTRACT_COLUMNS = ("图名称（功能）", "元素", "资产/信号", "协议")
DFD_EXTRACT_COLUMN_WIDTHS = (210, 180, 360, 140)

STAGES = [
    ("input", "01", "DFD 资产解析", "识别元素、资产与安全属性", "Step 1: DFD 资产解析"),
    ("topology", "02", "可信拓扑建模", "绑定外部接口与最短攻击链路", "Step 2: 拓扑攻击路径框架"),
    ("dst", "03", "AI 场景生成", "生成损害场景与威胁场景", "Step 4: 损害威胁场景"),
    ("impact", "04", "AI 攻击与影响评级", "生成攻击动作并输出四维评级依据", "Step 5: 攻击路径+影响评级"),
    ("feasibility", "05", "AI 可行性评级", "按所选方法计算攻击可行性", "Step 7: 批量可行性评估"),
    ("report", "06", "风险与报告", "风险矩阵计算并导出 Excel", "Step 8: 报告生成"),
]

TRACE_STAGE_USAGE_KEYS = {
    "input": (),
    "topology": (),
    "dst": ("dst",),
    # Current production generates a complete topology-bound path in one
    # request.  Keep the split entry/target keys for historical manifests and
    # compatibility runs, but show direct-path calls in the live stage too.
    "impact": (
        "attack_path_direct",
        "attack_entry",
        "attack_target",
        "impact",
        "impact_reason",
        "impact_numeric_sc",
    ),
    "feasibility": ("feasibility_attack_potential", "feasibility_cvss", "feasibility_heavens"),
    "report": (),
}

TRACE_STAGE_RUNTIME = {
    "input": "LOCAL PARSER",
    "topology": "GRAPH TOOL",
    "dst": "LLM GENERATION",
    "impact": "LLM + PATH BINDER",
    "feasibility": "LLM + RULE ENGINE",
    "report": "LOCAL EXPORTER",
}

LLM_STAGE_LABELS = {
    "dst": "损害与威胁场景",
    "attack_entry": "入口攻击技术",
    "attack_target": "目标攻击动作",
    "attack_path_direct": "完整攻击路径",
    "impact": "影响评级",
    "impact_reason": "影响评级理由",
    "impact_numeric_sc": "影响一致性采样",
    "feasibility_attack_potential": "Attack Potential",
    "feasibility_cvss": "CVSS 可行性",
    "feasibility_heavens": "HEAVENS 可行性",
    "unknown": "其他模型调用",
}

EVIDENCE_MARKERS = (
    "DFD解析完成",
    "任务单元构建完成",
    "拓扑攻击路径框架生成完成",
    "DST batch 进度",
    "Post-DST 进度",
    "影响评级",
    "攻击路径",
    "Stage C",
    "可行性",
    "Excel 报告已生成",
    "TARA 完成",
    "重试",
    "校验失败",
    "缓存命中",
    "增量缓存",
    "模型调用",
    "LLM HTTP统计",
)

AGENT_STAGE_COPY = {
    "input": (
        "正在理解项目结构",
        "解析 DFD 元素身份、数据流关系与安全属性，建立后续分析所需的任务空间。",
    ),
    "topology": (
        "正在构建可信攻击面",
        "将外部接口映射到真实拓扑，筛选协议并选择到达目标的最短可信链路。",
    ),
    "dst": (
        "正在推演损害与威胁场景",
        "结合资产语义和安全属性生成候选场景，并用结构化约束逐项验收模型输出。",
    ),
    "impact": (
        "正在判断影响并生成完整攻击路径",
        "评估安全、财产、运行和隐私影响，同时让模型依据可信拓扑框架一次生成完整路径；缺失路径仅按 path_id 做确定性补全。",
    ),
    "feasibility": (
        "正在评估攻击可行性",
        "按所选方法计算每条攻击路径的可行性；理由、ID 和数量均经过程序校验。",
    ),
    "report": (
        "正在汇总风险与证据",
        "通过风险矩阵合成最终等级，整理可追溯依据并生成客户 Excel 交付物。",
    ),
}


DEMO_CSS = r"""
:root {
  --catarc-blue: #075ca8;
  --catarc-blue-deep: #063b70;
  --catarc-green: #68ad2f;
  --ink: #17283a;
  --muted: #64748b;
  --line: #dbe6ef;
  --surface: #ffffff;
}
body, .gradio-container {
  color: var(--ink);
  color-scheme: light !important;
  font-family: Inter, "Noto Sans SC", "Microsoft YaHei", system-ui, sans-serif !important;
}
body { background:#fff !important; }
.gradio-container {
  --body-background-fill:#fff; --background-fill-primary:#fff;
  --background-fill-secondary:#f7f8f8; --block-background-fill:#fff;
  --input-background-fill:#fff; --border-color-primary:#dbe6ef;
  --body-text-color:#17283a; --body-text-color-subdued:#64748b;
  --block-title-text-color:#17283a; --block-label-text-color:#46545c;
  --block-label-background-fill:#f4f6f6; --block-label-background-fill-dark:#f4f6f6;
  --block-label-border-color:#dce3e5; --block-label-border-color-dark:#dce3e5;
  --block-title-background-fill:transparent; --block-title-background-fill-dark:transparent;
  --block-info-text-color:#64748b; --accordion-text-color:#29485f;
  --input-placeholder-color:#8b9daa; --checkbox-label-text-color:#29485f;
  --checkbox-label-text-color-selected:#173b55; --button-secondary-text-color:#24465e;
  --checkbox-background-color:#fff; --checkbox-background-color-hover:#f4f9fc;
  --checkbox-background-color-focus:#fff; --checkbox-background-color-selected:#075ca8;
  --checkbox-check:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E%3Cpath d='M3.2 8.3 6.6 11.5 12.9 4.8' fill='none' stroke='%23fff' stroke-width='2.4' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E");
  --checkbox-border-color:#91adc0; --checkbox-border-color-hover:#347fac;
  --checkbox-border-color-focus:#075ca8; --checkbox-border-color-selected:#075ca8;
  --checkbox-label-background-fill:#fff; --checkbox-label-background-fill-hover:#f7fbfd;
  --checkbox-label-background-fill-focus:#fff; --checkbox-label-background-fill-selected:#eef7fc;
  --checkbox-label-border-color:#d7e4ec; --checkbox-label-border-color-selected:#82b7d7;
  --button-secondary-text-color-hover:#075ca8; --button-primary-text-color:#fff;
  --button-primary-text-color-hover:#fff; --table-text-color:#233e52;
  --table-even-background-fill:#fff; --table-odd-background-fill:#f8fbfd;
  --code-background-fill:#f8fafc; --panel-background-fill:#fff;
  background:#fff !important; max-width:1520px !important; padding:22px 30px 44px !important;
}
.dark .gradio-container { --body-background-fill:#fff; --background-fill-primary:#fff;
  --background-fill-secondary:#f7f8f8; --block-background-fill:#fff;
  --input-background-fill:#fff; --body-text-color:#17283a; --body-text-color-subdued:#64748b;
  --block-title-text-color:#17283a; --block-label-text-color:#46545c;
  --block-label-background-fill:#f4f6f6; --block-label-background-fill-dark:#f4f6f6;
  --block-label-border-color:#dce3e5; --block-label-border-color-dark:#dce3e5;
  --block-title-background-fill:transparent; --block-title-background-fill-dark:transparent;
  --block-info-text-color:#64748b; --accordion-text-color:#29485f;
  --input-placeholder-color:#8b9daa; --checkbox-label-text-color:#29485f;
  --checkbox-label-text-color-selected:#173b55; --button-secondary-text-color:#24465e;
  --checkbox-background-color:#fff; --checkbox-background-color-hover:#f4f9fc;
  --checkbox-background-color-focus:#fff; --checkbox-background-color-selected:#075ca8;
  --checkbox-border-color:#91adc0; --checkbox-border-color-hover:#347fac;
  --checkbox-border-color-focus:#075ca8; --checkbox-border-color-selected:#075ca8;
  --checkbox-label-background-fill:#fff; --checkbox-label-background-fill-selected:#eef7fc;
  --checkbox-label-border-color:#d7e4ec; --checkbox-label-border-color-selected:#82b7d7;
  --button-primary-text-color:#fff; --table-text-color:#233e52;
  --table-even-background-fill:#fff; --table-odd-background-fill:#f8fbfd;
  color:#17283a !important; background:#fff !important; }
.gradio-container input, .gradio-container textarea, .gradio-container select { color:#17283a !important; background:#fff !important; }
.gradio-container input[type="checkbox"] { accent-color:#075ca8 !important; cursor:pointer; }
.gradio-container input[type="checkbox"]:checked {
  border-color:#075ca8 !important; background-color:#075ca8 !important;
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E%3Cpath d='M3.2 8.3 6.6 11.5 12.9 4.8' fill='none' stroke='%23fff' stroke-width='2.4' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E") !important;
  background-repeat:no-repeat !important; background-position:center !important; background-size:14px 14px !important;
  outline:3px solid rgba(7,92,168,.13); outline-offset:2px;
}
.scope-radio .wrap { display:flex !important; flex-direction:column !important; flex-wrap:nowrap !important; gap:7px; width:100% !important; }
.scope-radio label { display:flex !important; width:100% !important; flex:0 0 auto !important; min-width:0 !important; margin:0 !important; padding:8px 9px !important;
  border:1px solid #e1e8ec !important; border-radius:10px !important; background:#fff !important; transition:border-color .16s ease, background .16s ease, box-shadow .16s ease; }
.scope-radio label:hover { border-color:#b8cbd3 !important; background:#fcfdfd !important; }
.scope-radio label:has(input:checked) { border-color:#5b9b8b !important; background:#f4faf7 !important; box-shadow:inset 3px 0 0 #4f9584, 0 2px 8px rgba(55,112,96,.08); }
.scope-radio label span { color:#45657a !important; font-size:10px !important; line-height:1.25; }
.scope-radio label:has(input:checked) span { color:#075c91 !important; font-weight:750; }
.gradio-container label, .gradio-container .label-wrap, .gradio-container .info { color:#29485f !important; }
.gradio-container label.float, .gradio-container .block > label {
  border-color:#dce3e5 !important; background:#f4f6f6 !important; color:#46545c !important;
  box-shadow:none !important;
}
.gradio-container label.float svg, .gradio-container .block > label svg { color:#2779aa !important; }
.gradio-container .tab-nav { border-color:#d7e5ee !important; background:#f8fbfd !important; }
.gradio-container .tab-nav button { color:#527086 !important; background:transparent !important; }
.gradio-container .tab-nav button.selected { color:#075ca8 !important; background:#fff !important; }
.gradio-container table th { color:#244b66 !important; background:#eef6fb !important; }
.gradio-container button.secondary { color:#24465e !important; background:#fff !important; }
.brand-shell {
  position: relative; overflow: hidden; display: flex; align-items: center;
  gap: 20px; min-height: 142px; padding: 28px 34px; margin-bottom: 12px;
  color:var(--ink); border:1px solid #d5e4ef; border-radius:22px;
  background:#fff;
  box-shadow:0 16px 45px rgba(23,70,103,.09);
  isolation: isolate;
}
.brand-shell::after {
  content: ""; position: absolute; width: 380px; height: 380px; right: -120px;
  top: -210px; border:46px solid rgba(18,127,196,.07); border-radius:50%;
}
.brand-shell::before {
  content:""; position:absolute; inset:0; z-index:-1; opacity:.34;
  background-image:linear-gradient(rgba(7,92,168,.08) 1px,transparent 1px),
    linear-gradient(90deg,rgba(7,92,168,.08) 1px,transparent 1px);
  background-size: 34px 34px; mask-image:linear-gradient(90deg,transparent 32%,#000 100%);
}
.brand-mark { width: 64px; height: 64px; position: relative; flex: 0 0 64px; }
.brand-mark .orbit { position:absolute; border-radius:50%; border-style:solid; transform:rotate(-22deg); }
.brand-mark .orbit-a { inset:3px; border-width:8px; border-color:#075ca8 transparent #075ca8 #075ca8; }
.brand-mark .orbit-b { inset: 14px 0 8px 20px; border-width: 7px; border-color: var(--catarc-green) var(--catarc-green) transparent transparent; }
.brand-name { color:#073f72; font-size:27px; font-weight:780; letter-spacing:.04em; }
.brand-name span { color:#2e78a9; font-size:13px; margin-left:10px; letter-spacing:.16em; opacity:.9; }
.brand-title { margin-top: 7px; color:#0b477a; font-family:"Avenir Next", "Montserrat", "Inter", "Noto Sans SC", sans-serif;
  font-size:31px; line-height:1.18; font-weight:850; letter-spacing:.015em; text-wrap:balance; }
.brand-subtitle { color:#718697; font-size:12px; margin-top:5px; }
.brand-logo { display:block; width:150px; height:100px; object-fit:contain; flex:0 0 150px; }
.brand-text-fallback { display:flex; flex-direction:column; align-items:center; justify-content:center; width:128px; height:82px;
  border:1px solid #cbddea; border-radius:16px; background:#fff; color:#16497a; }
.brand-text-fallback b { font-size:22px; letter-spacing:.08em; }.brand-text-fallback span { margin-top:5px; font-size:12px; font-weight:700; }
.ai-pill { margin-left:auto; z-index:1; padding: 9px 14px; border: 1px solid rgba(255,255,255,.35);
  background: rgba(255,255,255,.12); border-radius:999px; font-size:12px; font-weight:700; letter-spacing:.13em; }
.hero-proof { margin-left:auto; display:grid; grid-template-columns:repeat(2,auto); gap:9px; z-index:1; }
.hero-proof span { padding:9px 12px; border:1px solid #d5e5f0; border-radius:10px;
  background:#f8fbfd; color:#3c6d8e; font-size:10px; font-weight:700; letter-spacing:.08em; text-align:center; }
.vehicle-visual { position:relative; width:350px; height:112px; margin-left:auto; z-index:1; flex:0 0 350px; }
.vehicle-visual svg { display:block; width:100%; height:100%; overflow:visible; }
.vehicle-body-line { fill:rgba(18,126,194,.035); stroke:#2d6c99; stroke-width:2.2; stroke-linejoin:round; }
.vehicle-glass { fill:#eaf5fb; stroke:#77a7c6; stroke-width:1.4; }.vehicle-wheel { fill:#fff; stroke:#1d5279; stroke-width:2.4; }
.vehicle-wheel-hub { fill:#d9ebf6; stroke:#6e9ab6; stroke-width:1.2; }.vehicle-net-line { fill:none; stroke:#78acd0; stroke-width:1.25; stroke-dasharray:4 4; }
.vehicle-net-node { fill:#fff; stroke:#1685ca; stroke-width:2; }.vehicle-net-pulse { fill:#1685ca; animation:vehicle-pulse 1.8s ease-in-out infinite; transform-origin:center; }
.vehicle-label { fill:#58778d; font-size:8px; font-family:Inter,system-ui,sans-serif; font-weight:700; letter-spacing:.08em; }
.vehicle-tags { position:absolute; right:2px; bottom:0; display:flex; gap:6px; }
.vehicle-tags span { padding:4px 7px; border:1px solid #d4e5ef; border-radius:999px; background:#fff; color:#46708c; font-size:8px; font-weight:800; letter-spacing:.06em; }
.nav-steps { display:flex; align-items:center; justify-content:center; gap:0; margin:0 6px 20px;
  padding:12px 18px; border:1px solid #d9e7f1; border-radius:0 0 16px 16px; background:rgba(255,255,255,.88);
  box-shadow:0 8px 22px rgba(31,76,110,.06); backdrop-filter:blur(12px); }
.nav-step { display:flex; align-items:center; gap:8px; color:#6c8295; font-size:11px; font-weight:700; letter-spacing:.04em; }
.nav-step b { display:grid; place-items:center; width:23px; height:23px; border-radius:50%; background:#eaf3f9; color:#075ca8; font-size:10px; }
.nav-arrow { width:54px; height:1px; margin:0 12px; background:linear-gradient(90deg,#b8cee0,#dce8f1); }
#workflow-tabs { margin-top:20px; }
#workflow-tabs > .tab-nav {
  display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); gap:8px; padding:8px;
  border:1px solid #d5e6f1 !important; border-radius:20px;
  background:linear-gradient(115deg,#edf7fb 0%,#f8fcfe 44%,#f1f8f5 100%) !important;
  box-shadow:0 14px 34px rgba(31,76,110,.09); overflow:visible;
}
#workflow-tabs > .tab-nav button {
  position:relative; min-width:0; min-height:62px; padding:10px 12px 10px 45px !important;
  border:1px solid transparent !important; border-radius:14px !important; color:#587387 !important;
  background:transparent !important; font-size:12px !important; font-weight:800 !important;
  letter-spacing:.015em; text-align:left !important; transition:transform .18s ease,box-shadow .18s ease,background .18s ease;
}
#workflow-tabs > .tab-nav button::before {
  position:absolute; left:12px; top:50%; display:grid; place-items:center; width:24px; height:24px;
  border:1px solid #c9dce9; border-radius:8px; background:#fff; color:#1871ac; font-size:10px; font-weight:850;
  transform:translateY(-50%); content:"";
}
#workflow-tabs > .tab-nav button:nth-child(1)::before { content:"01"; }
#workflow-tabs > .tab-nav button:nth-child(2)::before { content:"02"; }
#workflow-tabs > .tab-nav button:nth-child(3)::before { content:"03"; }
#workflow-tabs > .tab-nav button:nth-child(4)::before { content:"04"; }
#workflow-tabs > .tab-nav button:nth-child(5)::before { content:"05"; }
#workflow-tabs > .tab-nav button:nth-child(6)::before { content:"06"; }
#workflow-tabs > .tab-nav button:hover { color:#075ca8 !important; background:rgba(255,255,255,.76) !important; transform:translateY(-1px); }
#workflow-tabs > .tab-nav button.selected {
  color:#fff !important; background:linear-gradient(135deg,#075ca8 0%,#087fc3 56%,#0b9b91 100%) !important;
  border-color:#075ca8 !important; box-shadow:0 10px 22px rgba(7,92,168,.24);
}
#workflow-tabs > .tab-nav button.selected::before { color:#075ca8; border-color:rgba(255,255,255,.86); background:#fff; box-shadow:0 3px 8px rgba(1,48,84,.20); }
#workflow-tabs > .tabitem { padding-top:20px; }
@media (max-width: 860px) {
  #workflow-tabs > .tab-nav { grid-template-columns:repeat(2,minmax(0,1fr)); }
  #workflow-tabs > .tab-nav button:last-child { grid-column:1 / -1; }
}
@media (max-width: 520px) {
  #workflow-tabs > .tab-nav { grid-template-columns:1fr; }
  #workflow-tabs > .tab-nav button:last-child { grid-column:auto; }
}
.dfd-extract-card { margin-top:18px; padding:0 !important; overflow:hidden; border:1px solid #c7ddeb !important;
  border-radius:18px !important; background:#fff; box-shadow:0 12px 30px rgba(22,76,116,.075); }
.dfd-extract-card > .wrap { display:block !important; width:100% !important; gap:0 !important; padding:0 !important; }
.dfd-extract-head { position:relative; display:flex; align-items:center; justify-content:space-between; gap:18px; padding:18px 20px 15px 31px;
  border-bottom:1px solid #d8e7ef; background:linear-gradient(110deg,#f7fbfe 0%,#fff 58%,#f4faf8 100%); }
.dfd-extract-head::before { content:""; position:absolute; left:18px; top:20px; width:3px; height:48px; border-radius:0 4px 4px 0; background:linear-gradient(#0878c3,#6bb439); }
.dfd-extract-head > div:first-child { min-width:0; }
.dfd-extract-kicker { color:#0b8b83; font-size:10px; font-weight:850; letter-spacing:.13em; }
.dfd-extract-title { margin-top:3px; color:#163d5b; font-size:19px; font-weight:820; letter-spacing:-.015em; }
.dfd-extract-note { margin-top:4px; color:#71899c; font-size:11px; line-height:1.4; }
.dfd-extract-count { display:flex; align-items:baseline; gap:5px; padding:8px 12px; border:1px solid #cfe2ec; border-radius:11px; background:#fff; color:#668196; white-space:nowrap; }
.dfd-extract-count b { color:#1474cb; font-size:26px; line-height:1; letter-spacing:-.04em; }
.dfd-extract-count span { font-size:11px; font-weight:750; }
.dfd-extract-card .wrap > .form { width:100% !important; padding:0 !important; }
.dfd-extract-toolbar { align-items:end !important; gap:10px !important; padding:11px 16px 10px; border-bottom:1px solid #e2edf3; background:#fbfdff; }
.dfd-extract-toolbar > * { min-width:0 !important; }
.dfd-extract-toolbar .gr-textbox { flex:1 1 auto !important; width:auto !important; margin-bottom:0 !important; }
.dfd-extract-toolbar .gr-textbox input { min-height:38px !important; border-color:#d5e5ee !important; border-radius:10px !important; background:#fff !important; }
.dfd-extract-toolbar button { min-height:38px !important; margin-bottom:1px !important; border-color:#bcd5e4 !important; background:#fff !important; color:#28617f !important; }
.dfd-extract-toolbar button:hover { border-color:#74afd0 !important; background:#f2f9fd !important; }
.dfd-extract-table { width:100% !important; max-width:100% !important; overflow:hidden !important; }
.dfd-extract-card .table-container,
.dfd-extract-card .table-wrap { width:100% !important; min-width:0 !important; }
/* The virtual viewport is the only scrolling layer.  The surrounding Gradio
   block and table-wrap used to scroll too, producing two vertical rails. */
.dfd-extract-card .table-wrap { max-height:none !important; overflow:hidden !important; border:0 !important; border-radius:0 !important; background:#fff; }
.dfd-extract-card .virtual-table-viewport { max-height:460px !important; overflow:auto !important; overscroll-behavior:contain; scrollbar-gutter:stable; }
/* Keep header and virtual body in lockstep and distribute the four visible
   business columns across the available card width. */
.dfd-extract-card .header-table,
.dfd-extract-card .virtual-body { width:100% !important; min-width:100% !important; table-layout:fixed !important; }
.dfd-extract-card .virtual-row { box-sizing:border-box !important; }
.dfd-extract-card .header-table { border:0 !important; border-collapse:separate !important; border-spacing:0 !important; }
.dfd-extract-card .header-cell:nth-child(1), .dfd-extract-card .virtual-row > :nth-child(1) { width:23% !important; min-width:0 !important; max-width:none !important; flex:0 0 23% !important; }
.dfd-extract-card .header-cell:nth-child(2), .dfd-extract-card .virtual-row > :nth-child(2) { width:20% !important; min-width:0 !important; max-width:none !important; flex:0 0 20% !important; }
.dfd-extract-card .header-cell:nth-child(3), .dfd-extract-card .virtual-row > :nth-child(3) { width:42% !important; min-width:0 !important; max-width:none !important; flex:0 0 42% !important; }
.dfd-extract-card .header-cell:nth-child(4), .dfd-extract-card .virtual-row > :nth-child(4) { width:15% !important; min-width:0 !important; max-width:none !important; flex:0 0 15% !important; }
.dfd-extract-card .header-cell { box-sizing:border-box !important; border-bottom:1px solid #cddfe9 !important; background:#eaf3f8 !important; color:#31566f !important; }
.dfd-extract-card .header-content { padding:11px 13px !important; font-size:10px !important; font-weight:820 !important; letter-spacing:.03em; }
.dfd-extract-card .virtual-row { border-bottom:1px solid #edf3f6 !important; color:#29475e !important; font-size:11px !important; line-height:1.45 !important; }
.dfd-extract-card .virtual-row > td,
.dfd-extract-card .virtual-row > div { box-sizing:border-box !important; }
.dfd-extract-card .virtual-row .cell-wrap { padding:10px 13px !important; }
.dfd-extract-card .virtual-row.row-odd { background:#fbfdfe !important; }
.dfd-extract-card .virtual-row:hover { background:#f1f8fc !important; }
.dfd-extract-card .virtual-row > :nth-child(2) { color:#216aad !important; font-family:Consolas,"SFMono-Regular",monospace; font-size:10px !important; }
.dfd-extract-card .virtual-row > :nth-child(3) { color:#31566f !important; font-weight:700; }
.dfd-extract-card .virtual-row > :nth-child(4) { color:#078a81 !important; font-weight:760; }
@media (max-width: 760px) {
  /* Narrow screens retain one horizontal rail inside the table, rather than
     compressing identifiers until they become unreadable. */
  .dfd-extract-card .header-table,
  .dfd-extract-card .virtual-body { min-width:760px !important; }
  .dfd-extract-card .header-cell:nth-child(1), .dfd-extract-card .virtual-row > :nth-child(1) { width:180px !important; flex-basis:180px !important; }
  .dfd-extract-card .header-cell:nth-child(2), .dfd-extract-card .virtual-row > :nth-child(2) { width:150px !important; flex-basis:150px !important; }
  .dfd-extract-card .header-cell:nth-child(3), .dfd-extract-card .virtual-row > :nth-child(3) { width:310px !important; flex-basis:310px !important; }
  .dfd-extract-card .header-cell:nth-child(4), .dfd-extract-card .virtual-row > :nth-child(4) { width:120px !important; flex-basis:120px !important; }
}
.strategy-panel {
  /* Keep 02 aligned with the full-width input, runtime and delivery tabs.
     The former 1100px cap made this tab visibly narrower on wide screens. */
  width:100% !important;
  max-width:none !important;
  align-self:stretch !important;
  margin-inline:0 !important;
}
.agent-tab { padding:18px 20px 24px !important; border:1px solid #d8e2e7 !important; border-radius:16px !important;
  background:#fff !important; box-shadow:0 8px 26px rgba(15,35,48,.06); }
.section-kicker { color: var(--catarc-blue); font-weight: 750; font-size: 12px; letter-spacing: .12em; text-transform: uppercase; }
.section-title { margin: 4px 0 0; font-size: 22px; font-weight: 780; letter-spacing:-.02em; color: var(--ink); }
.section-desc { color: var(--muted); font-size: 13px; margin-top: 5px; }
.panel, .gr-group, .gr-box { border-color: var(--line) !important; }
.panel { background:#fff; border:1px solid var(--line); border-radius:20px; padding:21px;
  box-shadow:0 14px 38px rgba(27,74,108,.07); }
.control-panel { background:#fff; }
.analysis-cockpit { align-items:flex-start !important; gap:18px !important; margin-top:16px; }
.vertical-workflow { display:flex !important; flex-direction:column !important; align-items:stretch !important;
  gap:24px !important; }
.vertical-workflow > .left-console, .vertical-workflow > .agent-side {
  width:100% !important; min-width:0 !important; flex:0 0 auto !important; }
.vertical-workflow > .agent-side { padding:22px !important; border:1px solid #c9deed; border-radius:22px;
  background:linear-gradient(145deg,#fbfdff,#fff 42%,#f6fbfe); box-shadow:0 18px 48px rgba(22,76,116,.09); }
.left-console, .agent-side { min-width:0 !important; gap:14px !important; }
.left-console .panel { width:100%; }
.setup-panel { position:relative; overflow:hidden; }
.agent-heading { display:flex; align-items:flex-end; justify-content:space-between; gap:18px; padding:2px 4px 15px; }
.agent-heading-copy { min-width:0; }
.agent-heading-status { flex:0 0 auto; display:flex; align-items:center; gap:7px; margin-bottom:4px; padding:7px 10px;
  border:1px solid #d4e5f0; border-radius:999px; background:#f8fbfd; color:#52738a; font-size:9px; font-weight:800; letter-spacing:.08em; }
.agent-heading-status i { width:6px; height:6px; border-radius:50%; background:#168bd2; box-shadow:0 0 0 4px rgba(22,139,210,.11); }
.upload-zone { border-radius:14px !important; overflow:hidden; border-color:#d5e5ef !important;
  background:linear-gradient(145deg,#fff,#f8fbfd) !important; transition:border-color .2s ease,box-shadow .2s ease,transform .2s ease; }
.upload-zone:hover { border-color:#81b6d8 !important; box-shadow:0 8px 20px rgba(35,104,149,.09); transform:translateY(-1px); }
.upload-zone .wrap { min-height:106px !important; color:#244d68 !important; padding-top:6px !important; }
.upload-zone button { color:#244d68 !important; background:#fff !important; }
.gradio-container .accordion { border-radius:14px !important; border-color:#d6e5ee !important; overflow:hidden; }
#component-0 button, button { border-radius:11px !important; transition:transform .18s ease, box-shadow .18s ease !important; }
button:hover { transform:translateY(-1px); }
#run-button { background: linear-gradient(90deg, var(--catarc-blue-deep), var(--catarc-blue)) !important;
  min-height:50px; border: 0 !important; font-weight:750 !important; letter-spacing:.03em;
  box-shadow: 0 10px 25px rgba(7,92,168,.25); }
#stop-button { min-height:36px; }
#refresh-model-button { min-height:42px; }
#switch-model-button { min-height:42px; border-color:#75acd0 !important; color:#075c91 !important; background:#f2f9fd !important; }
#sample-button { border-color: #9ec1dc !important; color: var(--catarc-blue-deep) !important; }
.execution-dock { align-items:center !important; gap:18px !important; margin-top:18px; padding:16px 18px;
  background:linear-gradient(100deg,#fff 0%,#f8fbfd 55%,#fff 100%); }
.execution-dock .model-card { min-height:76px; }
.execution-model, .execution-state, .execution-actions { min-width:0 !important; gap:8px !important; }
.execution-state .notice { padding:0 3px; }
.execution-state .status-panel { min-height:58px; display:flex; flex-direction:column; justify-content:center; }
.execution-actions { justify-content:center; }
.model-card { display:flex; align-items:center; gap:12px; padding:16px; border-radius:15px; border:1px solid #cfe1ee;
  background:#fff; }
.model-dot { width:10px; height:10px; border-radius:50%; box-shadow:0 0 0 5px rgba(34,197,94,.12); background:#22c55e; }
.model-dot.offline { background:#ef4444; box-shadow:0 0 0 5px rgba(239,68,68,.12); }
.model-label { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.08em; }
.model-name { color:var(--ink); font-weight:700; margin-top:2px; }
.model-control-row { align-items:end !important; gap:8px !important; }
.model-control-row .block { min-width:0 !important; }
.model-switch-progress { padding:10px 12px; border:1px solid #d8e6ef; border-radius:11px; background:#f9fcfe; }
.model-switch-progress.success { border-color:#bce4c8; background:#f4fcf6; }
.model-switch-progress.error { border-color:#f1c4c4; background:#fff7f7; }
.model-switch-head { display:flex; justify-content:space-between; gap:10px; color:#315a73; font-size:10px; font-weight:750; }
.model-switch-head span:last-child { color:#6f8a9b; font-variant-numeric:tabular-nums; }
.model-switch-track { height:5px; margin-top:7px; overflow:hidden; border-radius:999px; background:#e1ebf1; }
.model-switch-value { height:100%; border-radius:999px; background:linear-gradient(90deg,#0872bc,#68ad2f); transition:width .35s ease; }
.model-switch-detail { margin-top:6px; color:#708796; font-size:9px; line-height:1.4; overflow-wrap:anywhere; }
.status-panel { padding: 14px 17px; border-radius: 14px; border: 1px solid #bfdbfe; background: #eff6ff; }
.status-panel.running { border-color:#bfdbfe; background:#eff6ff; }
.status-panel.success { border-color:#bbf7d0; background:#f0fdf4; }
.status-panel.error { border-color:#fecaca; background:#fef2f2; }
.status-title { font-weight:750; color:var(--ink); }
.status-detail { color:var(--muted); font-size:12px; margin-top:3px; }
.workflow-label { display:flex; align-items:center; justify-content:space-between; margin:20px 2px 10px; color:#6a8295;
  font-size:10px; font-weight:800; letter-spacing:.13em; }
.workflow-label em { color:#075ca8; font-style:normal; font-size:12px; }
.timeline { display:grid; grid-template-columns:repeat(6,minmax(0,1fr)); gap:10px; margin: 8px 0 4px; }
.stage { min-height:112px; padding:13px; border-radius:15px; border:1px solid var(--line); background:#fff; position:relative; }
.stage .stage-no { font-size:10px; color:#94a3b8; font-weight:800; letter-spacing:.12em; }
.stage .stage-name { font-size:13px; color:var(--ink); font-weight:750; margin-top:8px; }
.stage .stage-desc { font-size:11px; color:var(--muted); margin-top:5px; line-height:1.45; }
.stage .stage-state { position:absolute; left:13px; bottom:11px; font-size:10px; font-weight:750; color:#94a3b8; }
.stage.active { border-color:#7db7df; box-shadow:0 6px 17px rgba(7,92,168,.10); background:#f5faff; }
.stage.active .stage-state { color:var(--catarc-blue); }
.stage.done { border-color:#b8d99c; background:#f7fcf3; }
.stage.done .stage-state { color:#4f8c20; }
.stage.error { border-color:#fca5a5; background:#fff7f7; }
.stage.error .stage-state { color:#dc2626; }
.progress-track { height:7px; border-radius:999px; background:#e6eef5; overflow:hidden; margin-top:14px; }
.progress-value { height:100%; border-radius:999px; background:linear-gradient(90deg,var(--catarc-blue),var(--catarc-green)); transition:width .3s ease; }
.metric-grid { display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); gap:10px; margin:10px 0 14px; }
.metric { padding:14px; border:1px solid var(--line); border-radius:14px; background:#fff; }
.metric-value { font-size:22px; font-weight:800; color:var(--catarc-blue-deep); }
.metric-label { color:var(--muted); font-size:11px; margin-top:4px; }
.risk-bars { display:flex; flex-wrap:wrap; gap:8px; }
.risk-chip { padding:6px 10px; border-radius:999px; background:#edf4f8; color:#365268; font-size:11px; }
.token-usage-card { margin:12px 0 14px; padding:14px 16px; border:1px solid #cfe2ee; border-radius:14px;
  background:linear-gradient(110deg,#f7fbfe,#fff); box-shadow:0 5px 16px rgba(32,82,113,.045); }
.token-usage-head { display:flex; align-items:baseline; justify-content:space-between; gap:12px; }
.token-usage-head b { color:#164b70; font-size:13px; font-weight:820; }
.token-usage-head span { color:#8296a5; font-size:10px; }
.token-stat-grid { display:grid; grid-template-columns:repeat(9,minmax(0,1fr)); gap:8px; margin-top:10px; }
.token-stat { min-width:0; padding:8px 9px; border:1px solid #deebf2; border-radius:9px; background:#fff; }
.token-stat b { display:block; color:#075ca8; font-size:16px; font-variant-numeric:tabular-nums; }
.token-stat small { display:block; margin-top:3px; color:#718797; font-size:9px; }
.token-stage-list { display:flex; flex-wrap:wrap; gap:6px; margin-top:10px; }
.token-stage { padding:5px 8px; border-radius:7px; background:#edf6fb; color:#456a80; font-size:9px; }
.token-stage b { color:#17577d; font-variant-numeric:tabular-nums; }
.token-usage-note { margin-top:8px; color:#8a9ba6; font-size:9px; line-height:1.4; }
.runtime-profile { margin-top:8px; padding:10px 12px; border:1px solid #cfe2ee; border-radius:10px; background:#f7fbfe; color:#315b75; }
.runtime-profile.manual { background:#fffaf2; border-color:#f2d7a6; }
.runtime-profile-head { display:flex; justify-content:space-between; gap:8px; font-size:10px; }
.runtime-profile-head span { color:#8296a5; font-size:9px; }
.runtime-profile-grid { display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); gap:6px; margin-top:8px; }
.runtime-profile-grid span { padding:5px 4px; text-align:center; border:1px solid #deebf2; border-radius:7px; background:#fff; }
.runtime-profile-grid b { display:block; color:#075ca8; font-size:13px; font-variant-numeric:tabular-nums; }
.runtime-profile-grid small, .runtime-profile > small { color:#718797; font-size:8px; }
.runtime-settings-panel { margin-top:16px !important; padding:16px 18px 18px !important; border:1px solid #d8e2e7 !important;
  border-radius:16px !important; background:#fff !important; box-shadow:0 8px 26px rgba(15,35,48,.06); }
.runtime-settings-intro { display:flex; align-items:center; justify-content:space-between; gap:18px;
  margin:0 0 14px; padding:0 0 10px; border:0; border-bottom:1px solid #dce9f1; border-radius:0; background:transparent; }
.runtime-settings-intro > div { display:flex; align-items:baseline; gap:10px; white-space:nowrap; }
.runtime-settings-intro span { color:#0a78b9; font-size:8px; font-weight:880; letter-spacing:.12em; }
.runtime-settings-intro b { color:#244f69; font-size:12px; }
.runtime-settings-intro p { margin:0; color:#748a98; font-size:9px; line-height:1.5; text-align:right; }
.runtime-settings-grid { align-items:stretch !important; gap:0 !important; width:100% !important; }
.runtime-setting-group { min-width:0 !important; width:0 !important; flex:1 1 0 !important; padding:0 16px !important;
  border:0 !important; border-radius:0; background:transparent; box-shadow:none; }
.runtime-setting-group:first-child { padding-left:0 !important; }
.runtime-setting-group:last-child { padding-right:0 !important; }
.runtime-setting-group + .runtime-setting-group { border-left:1px solid #dce8f0 !important; }
.runtime-setting-title { display:flex; align-items:center; gap:9px; margin-bottom:9px; }
.runtime-setting-title > span { display:grid; place-items:center; width:27px; height:27px; flex:0 0 27px;
  border-radius:8px; background:#eaf6fc; color:#0877b8; font-size:9px; font-weight:900; }
.runtime-setting-title > div { display:flex; flex-direction:column; min-width:0; }
.runtime-setting-title b { color:#234c66; font-size:11px; }
.runtime-setting-title small { color:#92a3ad; font-size:8px; }
.runtime-setting-group .block { margin-top:3px !important; }
.api-action-row { align-items:center !important; gap:8px !important; }
.api-action-row button { min-height:36px !important; }
.api-inline-status { display:flex; align-items:center; gap:9px; min-height:36px; padding:7px 10px;
  border:1px solid #dce8ef; border-radius:9px; background:#f8fbfd; }
.api-inline-status > i { width:8px; height:8px; flex:0 0 8px; border-radius:50%; background:#aebfc9; }
.api-inline-status > span { min-width:0; display:flex; flex-direction:column; }
.api-inline-status b { color:#46667a; font-size:9px; }
.api-inline-status small { overflow:hidden; color:#899ba7; font-size:8px; text-overflow:ellipsis; white-space:nowrap; }
.api-inline-status.online { border-color:#cbe8d1; background:#f6fcf7; }
.api-inline-status.online > i { background:#35b86a; box-shadow:0 0 0 4px rgba(53,184,106,.12); }
.api-inline-status.online b { color:#27764a; }
.api-inline-status.warning { border-color:#f1dfb5; background:#fffbf2; }
.api-inline-status.warning > i { background:#dda82c; }
.api-inline-status.offline { border-color:#f1cece; background:#fff7f7; }
.api-inline-status.offline > i { background:#d95050; }
.sampling-guidance { display:flex; align-items:flex-start; gap:8px; margin-top:7px; padding:8px 9px;
  border-left:3px solid #73add0; border-radius:7px; background:#f5fafd; }
.sampling-guidance b { flex:0 0 auto; color:#276789; font-size:8px; }
.sampling-guidance span { color:#718796; font-size:8px; line-height:1.45; }
.runtime-preset-bar { margin:0 0 9px; padding:0; border:0; border-radius:0; background:transparent; }
.runtime-preset-bar > .wrap { gap:2px !important; }
.runtime-preset-picker { margin:0 !important; }
.runtime-preset-picker > label { margin-bottom:4px !important; color:#53748a !important; font-size:9px !important; font-weight:820 !important; letter-spacing:.07em; text-transform:uppercase; }
.runtime-preset-picker .gradio-radio { display:grid !important; grid-template-columns:repeat(3,minmax(0,1fr)); gap:5px !important; }
.runtime-preset-picker label:has(input[type="radio"]) { display:flex !important; justify-content:center; min-height:30px; padding:6px 5px !important; border:1px solid #dbe8ef; border-radius:8px; background:#fff; color:#668195; font-size:10px; font-weight:750; text-align:center; }
.runtime-preset-picker label:has(input[type="radio"]:checked) { border-color:#75b7dd; background:#eaf7ff; color:#075c9f; box-shadow:inset 0 0 0 1px rgba(7,92,168,.05); }
.runtime-setting-group .runtime-profile { margin-top:6px; padding:8px 9px; }
.runtime-setting-group .runtime-profile-grid { grid-template-columns:repeat(3,minmax(0,1fr)); }
.input-ok { padding:12px 14px; border-radius:12px; border:1px solid #bbf7d0; background:#f0fdf4; color:#166534; font-size:12px; }
.input-warn { padding:12px 14px; border-radius:12px; border:1px solid #fed7aa; background:#fff7ed; color:#9a3412; font-size:12px; }
.notice { color:var(--muted); font-size:11px; line-height:1.55; }
.download-note { padding:10px 13px; border-radius:12px; background:#f8fafc; color:var(--muted); font-size:12px; border:1px solid var(--line); }

.agent-panel { border:0 !important; background:transparent !important; padding:0 !important; }
.agent-side .agent-panel { width:100%; }
.agent-launchbar { display:flex !important; align-items:center !important; justify-content:center !important; gap:12px !important;
  margin-top:2px; padding:0 !important; border:0 !important; border-radius:0 !important;
  background:transparent !important; box-shadow:none !important; }
.agent-launchbar > * { flex:0 1 300px !important; min-width:190px !important; }
.agent-launchbar button { width:100% !important; min-height:48px !important; font-weight:800 !important; }
.agent-launchbar #stop-button { color:#a43a3a !important; border-color:#efc5c5 !important; background:#fff8f8 !important; }
.agent-overview-row { align-items:stretch !important; gap:12px !important; margin-top:14px; }
.agent-overview-copy, .agent-overview-status { min-width:0 !important; padding:0; border:0; border-radius:0; background:transparent; }
.agent-overview-copy { display:none !important; }
.agent-overview-status { display:flex; align-items:center; }
.agent-overview-row > .agent-overview-status { width:100% !important; flex:1 1 100% !important; }
.agent-overview-status .status-panel { width:100%; }
.agent-timeline-shell { margin-top:14px; padding:0 !important; border:0; border-radius:0; background:transparent; box-shadow:none; }
.agent-workspace-tabs { margin-top:16px; padding:0; border:0; border-radius:0; background:transparent; box-shadow:none; }
.agent-workspace-tabs > .tab-nav { margin-bottom:10px; padding:5px; border:1px solid #dce9f0 !important; border-radius:11px; background:#f8fbfd !important; }
.agent-workspace-tabs > .tab-nav button { min-height:36px; border-radius:8px !important; font-size:10px !important; font-weight:760 !important; }
.agent-workspace-tabs > .tab-nav button.selected { color:#075c9f !important; background:#eaf7ff !important; box-shadow:inset 0 0 0 1px #b7d9ec; }
.agent-workbench { width:100%; overflow:hidden; border:1px solid #c9deed; border-radius:22px; background:#fff;
  box-shadow:0 20px 55px rgba(22,76,116,.11), inset 0 1px 0 rgba(255,255,255,.8); position:relative; }
.agent-workbench::before { content:""; position:absolute; inset:0 0 auto; height:2px; z-index:4;
  background:linear-gradient(90deg,#075ca8,#26a0db 56%,#68ad2f); }
.agent-toolbar { height:44px; padding:0 18px; display:flex; align-items:center; justify-content:space-between;
  border-bottom:1px solid #deebf3; background:#fff; color:#36566d;
  font-size:10px; font-weight:800; letter-spacing:.13em; }
.agent-toolbar > div { display:flex; align-items:center; gap:9px; }
.agent-toolbar b { margin-left:5px; color:#0872bc; }
.runtime-ident { display:flex; align-items:center; gap:6px; min-width:0; }
.runtime-ident code { max-width:190px; padding:3px 7px; border:1px solid #dce9f1; border-radius:6px;
  background:#f7fafc; color:#638095; font-family:"JetBrains Mono",Consolas,monospace; font-size:8px; letter-spacing:.02em;
  overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.agent-telemetry { display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); border-bottom:1px solid #deebf3;
  background:linear-gradient(90deg,#f8fbfd,#fff); }
.agent-telemetry > div { min-width:0; padding:11px 15px; border-right:1px solid #e3edf4; }
.agent-telemetry > div:last-child { border-right:0; }
.agent-telemetry small { display:block; color:#8298a8; font-size:8px; font-weight:800; letter-spacing:.09em; }
.agent-telemetry b { display:block; margin-top:3px; color:#165a85; font-size:14px; font-weight:820; font-variant-numeric:tabular-nums; }
.agent-telemetry b.telemetry-live { color:#0b79bc; }
.live-dot { width:7px; height:7px; border-radius:50%; background:#2196df; box-shadow:0 0 0 5px rgba(33,150,223,.12); }
.thinking .live-dot { animation:pulse-dot 1.45s infinite; }
.completed .live-dot { background:#56a824; box-shadow:0 0 0 5px rgba(86,168,36,.12); }
.failed .live-dot { background:#dc4c4c; box-shadow:0 0 0 5px rgba(220,76,76,.12); }
.private-badge { color:#688094; letter-spacing:.08em; }
.agent-main { display:grid; grid-template-columns:220px minmax(0,1fr); min-height:270px; background:#fff; }
.agent-core { position:relative; display:flex; flex-direction:column; align-items:center; justify-content:center;
  overflow:hidden; border-right:1px solid #e2edf4; background:radial-gradient(circle at center,rgba(38,144,211,.13),transparent 57%); }
.core-brain { position:relative; z-index:3; display:grid; place-items:center; width:72px; height:72px; border-radius:24px;
  background:linear-gradient(145deg,#0872bc,#06477f); color:#fff; font-size:20px; font-weight:850; letter-spacing:.08em;
  box-shadow:0 14px 35px rgba(7,92,168,.28), inset 0 1px 0 rgba(255,255,255,.25); }
.thinking .core-brain { animation:brain-glow 2.6s ease-in-out infinite; }
.core-orbit { position:absolute; width:126px; height:126px; border:1px solid rgba(22,125,193,.23); border-radius:50%; }
.core-orbit::before { content:""; position:absolute; width:7px; height:7px; border-radius:50%; top:5px; left:35px; background:#2598df; box-shadow:0 0 14px #2598df; }
.orbit-two { width:156px; height:156px; border-style:dashed; opacity:.55; }
.thinking .orbit-one { animation:spin 8s linear infinite; }
.thinking .orbit-two { animation:spin-reverse 13s linear infinite; }
.core-state { margin-top:21px; color:#547187; font-size:9px; font-weight:850; letter-spacing:.18em; }
.reasoning-card { padding:28px 32px 23px; }
.agent-eyebrow { color:#0b78be; font-size:10px; font-weight:850; letter-spacing:.14em; }
.reasoning-card h3 { margin:9px 0 7px; font-size:24px; letter-spacing:-.025em; color:#15364e; }
.reasoning-card > p { max-width:790px; margin:0; color:#61798b; font-size:13px; line-height:1.75; }
.latest-signal { display:flex; align-items:center; gap:10px; margin-top:18px; padding:11px 13px; border:1px solid #d8e9f4;
  border-radius:11px; background:#f7fbfe; color:#47677e; font-size:11px; }
.latest-signal > i { flex:0 0 7px; width:7px; height:7px; border-radius:50%; background:#178bd3; }
.thinking-dots { display:flex; gap:3px; margin-left:auto; }
.thinking-dots i { width:4px; height:4px; border-radius:50%; background:#438dbb; animation:typing 1.15s infinite; }
.thinking-dots i:nth-child(2) { animation-delay:.15s; }.thinking-dots i:nth-child(3) { animation-delay:.3s; }
.idle .thinking-dots, .completed .thinking-dots, .failed .thinking-dots { display:none; }
.trust-strip { display:flex; flex-wrap:wrap; gap:6px; margin-top:10px; }
.trust-pill { display:inline-flex; align-items:center; gap:5px; padding:5px 7px; border:1px solid #dbe8f0;
  border-radius:999px; background:#fbfdfe; color:#668094; font-size:8px; font-weight:750; }
.trust-pill::before { content:"✓"; display:grid; place-items:center; width:12px; height:12px; border-radius:50%;
  background:#e8f5df; color:#5d9b30; font-size:8px; }
.agent-trace { padding:16px 18px 18px; border-top:1px solid #deebf3; background:linear-gradient(180deg,#fbfdfe,#fff); }
.trace-title { display:flex; align-items:center; justify-content:space-between; gap:14px; margin-bottom:11px; }
.trace-title > span { color:#315b75; font-size:10px; font-weight:850; letter-spacing:.12em; }
.trace-title > small { margin-left:auto; color:#8ca0ae; font-size:8px; }
.trace-progress { display:flex; align-items:center; gap:7px; min-width:180px; }
.trace-progress > b { color:#0872bc; font-size:12px; font-variant-numeric:tabular-nums; }
.trace-progress > span { color:#7d93a2; font-size:8px; font-weight:800; letter-spacing:.08em; white-space:nowrap; }
.trace-progress > i { flex:1; min-width:45px; height:5px; overflow:hidden; border-radius:999px; background:#e4edf3; }
.trace-progress > i > em { display:block; height:100%; border-radius:inherit; background:linear-gradient(90deg,#0872bc,#68ad2f); transition:width .3s ease; }
.trace-rail { display:grid; grid-template-columns:repeat(6,minmax(0,1fr)); gap:8px; position:relative; }
.trace-rail::before { content:""; position:absolute; left:5%; right:5%; top:24px; height:1px;
  background:linear-gradient(90deg,#bbd5e7,#8fc5e4 65%,#b9d99e); }
.trace-span { min-width:0; min-height:74px; padding:10px 10px 9px; border:1px solid #dce8ef; border-radius:11px;
  background:#fff; position:relative; z-index:1; box-shadow:0 4px 12px rgba(28,74,106,.04); }
.trace-span::before { content:""; position:absolute; top:20px; left:-7px; width:6px; height:6px; border:2px solid #fff;
  border-radius:50%; background:#b6c6d1; box-shadow:0 0 0 1px #cbdde8; }
.trace-span:first-child::before { left:9px; }
.trace-span small { display:block; color:#96a7b2; font-size:7px; font-weight:850; letter-spacing:.1em; }
.trace-span b { display:block; margin-top:6px; color:#365a70; font-size:10px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.trace-span em { display:block; margin-top:5px; color:#8499a7; font-size:8px; font-style:normal; line-height:1.35; }
.trace-span.active { border-color:#8fc6e5; background:#f4faff; box-shadow:0 6px 16px rgba(18,126,194,.10); }
.trace-span.active::before { background:#168bd2; box-shadow:0 0 0 4px rgba(22,139,210,.13); animation:pulse-dot 1.45s infinite; }
.trace-span.active small,.trace-span.active b { color:#0872bc; }
.trace-span.done { border-color:#c8e0b7; background:#f8fcf5; }.trace-span.done::before { background:#68ad2f; }
.trace-span.done small { color:#6f9c50; }.trace-span.error { border-color:#efbcbc; background:#fff7f7; }
.trace-span.error::before { background:#dc4c4c; }.trace-span.error small,.trace-span.error b { color:#b44747; }
.agent-lower { display:grid; grid-template-columns:1.12fr .88fr; border-top:1px solid #deebf3; min-height:260px; }
.agent-stream, .agent-decision { padding:20px 22px; min-width:0; }.agent-stream { border-right:1px solid #deebf3; }
.agent-stream { max-height:360px; overflow-y:auto; overscroll-behavior:contain; scrollbar-width:thin; scrollbar-color:#bdd8e8 #f5f9fb; }
.agent-stream::-webkit-scrollbar { width:7px; }.agent-stream::-webkit-scrollbar-thumb { background:#bdd8e8; border-radius:999px; }
.agent-stream::-webkit-scrollbar-track { background:#f5f9fb; border-radius:999px; }
.agent-stream > .agent-column-title { position:sticky; top:-1px; z-index:2; padding:1px 0 10px; background:linear-gradient(#fff 78%,rgba(255,255,255,0)); }
.agent-column-title { display:flex; align-items:baseline; justify-content:space-between; margin-bottom:13px; }
.agent-column-title span { color:#294c65; font-size:11px; font-weight:850; text-transform:uppercase; letter-spacing:.1em; }
.agent-column-title em { color:#93a4b0; font-size:9px; font-style:normal; }
.agent-event { position:relative; display:flex; min-height:37px; padding:0 0 10px; }
.event-rail { position:relative; flex:0 0 15px; margin-right:9px; }
.event-rail::before { content:""; position:absolute; top:5px; left:4px; width:7px; height:7px; border-radius:50%; background:#4ba2d8; box-shadow:0 0 0 3px #e7f4fb; }
.event-rail::after { content:""; position:absolute; top:14px; bottom:-5px; left:7px; width:1px; background:#dce9f1; }
.agent-event:last-child .event-rail::after { display:none; }
.agent-event.verify .event-rail::before { background:#e3a336; box-shadow:0 0 0 3px #fff4df; }
.agent-event.model .event-rail::before { background:#7568c7; box-shadow:0 0 0 3px #f0edff; }
.agent-event.cache .event-rail::before { background:#27a6a1; box-shadow:0 0 0 3px #e5f8f7; }
.agent-event.success .event-rail::before { background:#68ad2f; box-shadow:0 0 0 3px #edf7e7; }
.event-body { min-width:0; flex:1; }.event-meta { color:#4a85aa; font-size:8px; font-weight:850; letter-spacing:.1em; }
.event-meta span { float:right; color:#a0afba; font-weight:600; letter-spacing:0; }.event-message { color:#536d80; font-size:10px; margin-top:3px; line-height:1.4; overflow-wrap:anywhere; }
.decision-head { display:flex; justify-content:space-between; color:#2a7eb4; font-size:8px; font-weight:850; letter-spacing:.1em; }
.decision-head em { color:#8299a9; font-style:normal; letter-spacing:0; }.decision-asset { margin-top:13px; color:#173d58; font-size:17px; font-weight:800; }
.decision-asset span { color:#5d7c91; font-size:11px; font-weight:650; }.decision-text { margin-top:8px; color:#60798b; font-size:10px; line-height:1.55; }
.decision-facts { display:grid; grid-template-columns:1fr 90px; gap:8px; margin-top:13px; }.decision-facts > div { padding:9px; border:1px solid #dceaf3; border-radius:9px; background:#f8fbfd; min-width:0; }
.decision-facts small { display:block; color:#8699a7; font-size:8px; }.decision-facts b { display:block; margin-top:3px; color:#15577f; font-size:10px; overflow-wrap:anywhere; }
.decision-reason { margin-top:9px; color:#597386; font-size:9px; line-height:1.45; }.decision-reason span { margin-right:6px; padding:2px 5px; border-radius:4px; background:#eaf5fb; color:#0872bc; font-weight:750; }
.decision-summary { margin:12px 0 10px; color:#526f82; font-size:10px; line-height:1.45; }
.decision-summary b { color:#0b6da9; font-size:12px; }
.high-risk-list { display:flex; flex-direction:column; gap:8px; max-height:420px; overflow-y:auto; padding:0 6px 2px 0; }
.high-risk-list::-webkit-scrollbar { width:6px; }.high-risk-list::-webkit-scrollbar-thumb { background:#c5dce9; border-radius:999px; }
.high-risk-list::-webkit-scrollbar-track { background:#f4f9fc; border-radius:999px; }
.high-risk-item { padding:10px 11px; border:1px solid #f0d7bd; border-left:3px solid #e58b35; border-radius:10px; background:linear-gradient(135deg,#fffaf5,#fff); }
.high-risk-item-head { display:flex; align-items:baseline; justify-content:space-between; gap:8px; color:#6d421f; font-size:11px; font-weight:800; }
.high-risk-item-head span { color:#a06e43; font-size:9px; font-weight:650; text-align:right; }
.high-risk-item-meta { margin-top:3px; color:#8b6a52; font-size:9px; }
.high-risk-item-text { margin-top:5px; color:#62798a; font-size:10px; line-height:1.6; overflow-wrap:anywhere; white-space:pre-wrap; }
.decision-empty { display:flex; align-items:center; gap:13px; min-height:155px; padding:15px; border:1px dashed #cbdfea; border-radius:12px; background:#f9fcfe; }
.decision-empty b { color:#3c6078; font-size:11px; }.decision-empty p { margin:4px 0 0; color:#8a9da9; font-size:9px; line-height:1.5; }
.decision-scan { flex:0 0 34px; width:34px; height:34px; border-radius:10px; background:linear-gradient(135deg,#e4f4fd,#cfe8f7); position:relative; overflow:hidden; }
.decision-scan::after { content:""; position:absolute; left:5px; right:5px; height:1px; background:#178bd3; box-shadow:0 0 7px #178bd3; animation:scan 1.8s ease-in-out infinite; }
.agent-disclaimer { padding:9px 18px; border-top:1px solid #e4edf3; background:#fafcfd; color:#8b9da9; font-size:9px; text-align:right; }
.delivery-panel { padding:16px; border:1px solid #dbe7ef; border-radius:17px; background:#fff;
  box-shadow:0 10px 28px rgba(28,74,106,.06); }
.analysis-charts { margin-top:18px; padding:4px 0 0; border:0; background:transparent; box-shadow:none; position:relative; overflow:visible; }
.analysis-charts-title { display:flex; align-items:baseline; justify-content:space-between; margin:0 2px 16px; }
.analysis-charts-title span { color:#164b70; font-size:20px; font-weight:820; letter-spacing:.01em; }
.analysis-charts-title small { color:#8296a5; font-size:11px; }
.residual-risk-status { margin:0 0 20px; padding:14px 18px; border-radius:12px; background:#edf5fa; color:#244961; font-size:14px; }
.residual-risk-warning { background:#fff5e9; border:1px solid #f2d4aa; color:#8b4b12; }
.residual-risk-success { background:#eaf7f1; border:1px solid #b8dfcc; color:#1e6448; }
.chart-grid { display:grid; gap:12px; }
.chart-grid + .analysis-charts-title { margin-top:32px; padding-top:24px; border-top:1px solid #dce9f1; }
.chart-grid-three { grid-template-columns:repeat(3,minmax(0,1fr)); }
.chart-grid-two { grid-template-columns:repeat(2,minmax(0,1fr)); margin-top:12px; }
.chart-card { min-width:0; padding:19px; border:1px solid #dce9f1; border-radius:16px; background:#fff;
  box-shadow:0 7px 18px rgba(32,82,113,.045); transition:transform .18s ease,box-shadow .18s ease; }
.chart-card:hover { transform:translateY(-2px); box-shadow:0 11px 24px rgba(32,82,113,.09); }
.chart-card-title { display:flex; align-items:baseline; justify-content:space-between; gap:8px; color:#2b5670; font-size:14px; font-weight:800; }
.chart-card-title small { color:#94a5b1; font-size:10px; font-weight:600; }
.donut-layout { display:flex; align-items:center; gap:17px; margin-top:15px; min-height:142px; }
.donut { display:grid; place-items:center; flex:0 0 132px; width:132px; height:132px; border-radius:50%;
  box-shadow:0 4px 14px rgba(7,92,168,.12); }
.donut > div { display:grid; place-items:center; width:78px; height:78px; border:1px solid #e2edf3; border-radius:50%; background:#fff; color:#14557d; }
.donut b { font-size:25px; line-height:1; }.donut small { color:#91a1ad; font-size:10px; margin-top:4px; }
.chart-legend { display:flex; flex:1; flex-direction:column; gap:6px; min-width:0; margin:0; padding:0; list-style:none; }
.chart-legend li { display:flex; align-items:center; gap:7px; min-width:0; color:#647e8f; font-size:11px; }
.chart-legend li i { flex:0 0 7px; width:7px; height:7px; border-radius:50%; }
.chart-legend li span { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.chart-legend li b { display:flex; align-items:baseline; gap:3px; margin-left:auto; color:#285d7d; font-size:12px; }
.chart-legend li b small { color:#7e9aaa; font-size:10px; font-weight:700; }
.radar-layout { display:flex; align-items:center; gap:12px; margin-top:8px; }
.radar-layout svg { flex:1 1 58%; min-width:0; height:276px; overflow:visible; }
.radar-ring { fill:none; stroke:#d6e6ef; stroke-width:1.15; }.radar-axis { stroke:#dceaf2; stroke-width:1; }
.radar-value { fill:rgba(7,92,168,.27); stroke:#075ca8; stroke-width:3; stroke-linejoin:round; }
.radar-point { fill:#fff; stroke:#075ca8; stroke-width:2.5; }
.radar-score { fill:#164b70; font-size:9px; font-weight:800; paint-order:stroke; stroke:#fff; stroke-width:3px; stroke-linejoin:round; }
.radar-label { fill:#426a81; font-size:10px; font-weight:650; }.radar-legend { flex:0 0 176px; }
.radar-legend li span { white-space:normal; overflow:visible; text-overflow:clip; word-break:break-word; line-height:1.25; }
.chart-empty { display:grid; place-items:center; height:190px; color:#9aacb7; font-size:13px; }
.result-guide { margin-bottom:12px; padding:10px 13px; border-left:3px solid #178bd3; background:#f7fbfe;
  color:#526f82; font-size:11px; line-height:1.55; }
.result-preview-empty { display:flex; flex-direction:column; align-items:center; justify-content:center; min-height:170px;
  border:1px dashed #cbdce6; border-radius:14px; background:#fbfdfe; color:#718797; text-align:center; }
.result-preview-empty b { margin-bottom:5px; color:#31566f; font-size:14px; }
.result-preview-empty span { font-size:11px; }
.result-preview-shell { overflow:hidden; border:1px solid #d7e4eb; border-radius:14px; background:#fff; }
.result-preview-meta { padding:9px 13px; border-bottom:1px solid #e1ebf0; background:#f8fbfc; color:#6f8595; font-size:10px; }
.result-preview-scroll { max-height:520px; overflow:auto; overscroll-behavior:contain; }
.result-preview-table { width:max-content; min-width:100%; border-collapse:separate; border-spacing:0; color:#29475e; font-size:11px; }
.result-preview-table th { position:sticky; top:0; z-index:2; padding:10px 12px; border-right:1px solid #d7e4eb;
  border-bottom:1px solid #c9dce7; background:#edf4f8; color:#31566f; text-align:left; white-space:nowrap; }
.result-preview-table td { max-width:360px; padding:9px 12px; border-right:1px solid #e3ebef; border-bottom:1px solid #edf2f5;
  line-height:1.5; vertical-align:top; white-space:normal; overflow-wrap:anywhere; }
.result-preview-table tbody tr:nth-child(even) { background:#fafcfd; }
.result-preview-table tbody tr:hover { background:#f2f8fb; }

/* Compact console layout.  Data preparation, execution and engineering repair
   are visually separated so controls no longer compete for the same row. */
.setup-panel { padding:18px !important; }
.setup-panel .upload-zone { height:96px !important; }
.setup-panel .upload-zone .wrap { min-height:70px !important; }
.compact-upload-row { gap:10px !important; }
.compact-upload-row > * { min-width:0 !important; }
.project-upload-row { align-items:stretch !important; gap:12px !important; margin-top:10px; }
.project-upload-row > * { flex:1 1 0 !important; min-width:0 !important; }
.setup-panel .project-upload-row .upload-zone { width:100% !important; height:132px !important; }
.setup-panel .project-upload-row .upload-zone .wrap { min-height:106px !important; padding-top:14px !important; }
/* DFD accepts many files.  Use the whole component as the add-file entry
   after the first selection; the generated secondary upload button is not
   needed and makes the compact file list harder to read. */
#dfd-upload { position:relative !important; display:flex !important; flex-direction:column !important; align-items:stretch !important; height:auto !important; min-height:132px; cursor:pointer !important; }
#dfd-upload > label { order:1; flex:0 0 auto; cursor:pointer !important; }
#dfd-upload > .file-preview-holder { order:2; width:100% !important; height:132px !important; max-height:132px !important; margin-top:4px; padding-bottom:4px !important; overflow:auto !important; cursor:pointer !important; }
#dfd-upload > .top-panel { display:none !important; }
#dfd-upload > button[aria-dropeffect="copy"] { order:2; width:100% !important; flex:1 1 auto; }
.sample-loader-row { align-items:end !important; gap:8px !important; margin-top:3px; }
.sample-loader-row > * { min-width:0 !important; }
.sample-loader-row button { min-height:40px !important; white-space:nowrap; }
.input-agent-box { margin-top:10px; }
.advanced-options { margin-top:10px; border:0 !important; border-radius:0 !important; background:transparent !important; }
.advanced-options-heading { display:flex; align-items:center; justify-content:space-between; gap:16px; padding:0 0 10px; }
.advanced-options-heading-main { display:flex; align-items:center; gap:9px; }
.advanced-options-heading-main > span { display:grid; place-items:center; width:27px; height:27px; border-radius:8px; background:#eaf5fb; color:#0872bc; font-size:9px; font-weight:900; }
.advanced-options-heading-main b { display:block; color:#294f68; font-size:12px; }
.advanced-options-heading-main small { display:block; margin-top:2px; color:#879ba8; font-size:9px; }
.advanced-options-heading-note { color:#0b8b83; font-size:9px; font-weight:800; letter-spacing:.06em; white-space:nowrap; }
.advanced-feature-flags { display:grid !important; width:100% !important;
  grid-template-columns:repeat(auto-fit,minmax(min(100%,180px),1fr)); gap:7px !important; }
.advanced-feature-flags > * { width:100% !important; min-width:0 !important; padding:7px 8px;
  border:1px solid #dce8ef; border-radius:8px; background:#fff; }
.strategy-card-grid {
  display:grid !important;
  grid-template-columns:repeat(4,minmax(0,1fr));
  align-items:stretch !important;
  justify-content:stretch !important;
  gap:10px !important;
  width:100% !important;
  margin-inline:0 !important;
}
.strategy-card-grid > * { width:auto !important; min-width:0 !important; flex:none !important; }
.strategy-choice-card { min-height:216px; padding:13px !important; border:1px solid #d5e5ee;
  border-radius:15px; background:linear-gradient(160deg,#fff,#f9fcfe); box-shadow:0 5px 15px rgba(32,82,113,.045); }
.strategy-mitigation-note { margin:0 0 10px; color:#607d8c; font-size:12px; line-height:1.6; }
.strategy-choice-card:nth-child(1) { border-top:3px solid #147ac0; }
.strategy-choice-card:nth-child(2) { border-top:3px solid #0b9b91; }
.strategy-choice-card:nth-child(3) { border-top:3px solid #6a9f32; }
.strategy-choice-card:nth-child(4) { border-top:3px solid #697fa8; }
.strategy-choice-title { display:flex; align-items:flex-start; gap:8px; min-height:41px; margin-bottom:8px; }
.strategy-choice-title span { display:grid; place-items:center; width:24px; height:24px; flex:0 0 24px; border-radius:8px; background:#eaf5fb; color:#0872bc; font-size:9px; font-weight:900; }
.strategy-choice-title b { display:block; color:#234c66; font-size:12px; line-height:1.2; }
.strategy-choice-title small { display:block; margin-top:3px; color:#8499a8; font-size:9px; line-height:1.25; }
.strategy-choice-card .gradio-radio { display:flex !important; flex-direction:column !important; flex-wrap:nowrap !important; gap:5px !important; width:100% !important; }
.strategy-choice-card .gradio-radio label:has(input[type="radio"]) { display:flex !important; align-items:center !important; width:100% !important; min-width:0 !important; flex:0 0 auto !important; min-height:40px; padding:8px 10px !important; border:1px solid #e1e8ec; border-radius:10px; background:#fff; transition:border-color .16s ease, background .16s ease, box-shadow .16s ease; }
.strategy-choice-card .gradio-radio label:has(input[type="radio"]):hover { border-color:#b8cbd3; background:#fcfdfd; }
.strategy-choice-card label:has(input[type="radio"]:checked) { border-color:#5b9b8b; background:#f4faf7; box-shadow:inset 3px 0 0 #4f9584, 0 2px 8px rgba(55,112,96,.08); }
.strategy-choice-card label:has(input[type="radio"]:checked) span { color:#075c9f !important; font-weight:750; }
/* Gradio 6 renders Radio choices in a nested, unclassed flex wrapper. */
:is(.feasibility-method-picker, .risk-mitigation-picker) { overflow:visible !important; }
:is(.feasibility-method-picker, .risk-mitigation-picker) > .wrap:not(.default) {
  display:flex !important; flex-direction:column !important; align-items:stretch !important;
  flex-wrap:nowrap !important; gap:6px !important; width:100% !important;
}
:is(.feasibility-method-picker, .risk-mitigation-picker) > .wrap:not(.default) > label {
  display:flex !important; align-items:center !important; width:100% !important;
  min-width:0 !important; min-height:38px; flex:0 0 auto !important;
  padding:8px 10px !important; border:1px solid #e1e8ec !important;
  border-radius:10px !important; background:#fff !important;
}
:is(.feasibility-method-picker, .risk-mitigation-picker) > .wrap:not(.default) > label:hover { border-color:#b8cbd3 !important; background:#fcfdfd !important; }
:is(.feasibility-method-picker, .risk-mitigation-picker) > .wrap:not(.default) > label:has(input[type="radio"]:checked) {
  border-color:#5b9b8b !important; background:#f4faf7 !important;
  box-shadow:inset 3px 0 0 #4f9584, 0 2px 8px rgba(55,112,96,.08);
}
.strategy-choice-card .accordion { margin-top:0 !important; border-color:#dce8ef !important; background:#fff !important; }
.strategy-choice-card .accordion > button { min-height:36px !important; padding-inline:8px !important; font-size:11px !important; }
.strategy-choice-card .accordion > div { padding:6px !important; }
.strategy-choice-card .advanced-feature-flags { grid-template-columns:1fr !important; gap:4px !important; }
.strategy-choice-card .advanced-feature-flags > * { padding:5px 6px !important; font-size:10px; }
.strategy-summary { display:flex; align-items:center; justify-content:space-between; gap:18px; margin:14px 0 4px; padding:13px 16px;
  border:1px solid #cce2ee; border-radius:15px; background:linear-gradient(105deg,#f6fbfe,#fff 58%,#f3faf7); }
.strategy-summary-kicker { color:#0b8b83; font-size:9px; font-weight:900; letter-spacing:.13em; }
.strategy-summary h3 { margin:3px 0 0; color:#164c70; font-size:15px; }
.strategy-summary p { margin:4px 0 0; color:#718898; font-size:10px; }
.strategy-summary-matrix { display:flex; align-items:center; gap:8px; flex:0 0 auto; padding:8px 10px; border:1px solid #c5e0ed; border-radius:11px; background:#fff; }
.strategy-summary-matrix b { color:#0872bc; font-size:20px; letter-spacing:-.04em; }
.strategy-summary-matrix span { color:#6c8798; font-size:9px; font-weight:750; }
.strategy-advanced-options { margin-top:18px !important; padding:16px 18px 18px !important; border:1px solid #d8e2e7 !important; border-radius:16px !important; background:#fff !important; box-shadow:0 8px 26px rgba(15,35,48,.06); }
.advanced-options-intro { display:flex; align-items:baseline; gap:10px; margin:0 0 8px; color:#456d83; font-size:10px; }
.advanced-options-intro b { color:#17628a; font-size:11px; }
.advanced-options-intro span { color:#879ba8; }
.strategy-advanced-options .advanced-feature-flags {
  display:flex !important;
  flex-direction:row !important;
  flex-wrap:nowrap !important;
  align-items:stretch !important;
  justify-content:stretch !important;
  gap:10px !important;
  width:100% !important;
  max-width:none !important;
  margin-inline:0 !important;
  overflow:visible !important;
}
.strategy-advanced-options .advanced-feature-flags > * { display:flex !important; flex-direction:column !important; align-items:stretch !important; flex:1 1 0% !important; width:0 !important; max-width:none !important; min-width:0 !important; min-height:76px; box-sizing:border-box; padding:12px 14px !important; border:1px solid #e1e8ec !important; border-radius:12px !important; background:#fff !important; box-shadow:0 2px 8px rgba(24,50,64,.035); }
.strategy-advanced-options .advanced-feature-flags > *:first-child,
.strategy-advanced-options .advanced-feature-flags > *:last-child { padding:12px 14px !important; border-left:1px solid #e1e8ec !important; }
.strategy-advanced-options .advanced-feature-flags > *:hover { border-color:#b8cbd3 !important; background:#fcfdfd !important; box-shadow:0 5px 14px rgba(24,50,64,.07); }
.strategy-advanced-options .advanced-feature-flags > .block:has(input[type="checkbox"]:checked) { border-color:#5b9b8b !important; background:#f4faf7 !important; box-shadow:inset 3px 0 0 #4f9584, 0 3px 10px rgba(55,112,96,.08); }
.strategy-advanced-options .advanced-feature-flags > .block { grid-column:auto; }
.strategy-advanced-options .advanced-feature-flags .wrap { display:flex !important; align-items:center !important; gap:9px !important; width:100% !important; min-width:0 !important; padding:0 !important; }
.strategy-advanced-options .advanced-feature-flags .checkbox-container { display:flex !important; align-items:center !important; gap:9px !important; width:100% !important; min-width:0 !important; padding:0 !important; border:0 !important; border-radius:0 !important; background:transparent !important; box-shadow:none !important; }
.strategy-advanced-options .advanced-feature-flags .checkbox-container input { width:18px !important; height:18px !important; margin:0 !important; flex:0 0 18px !important; }
.strategy-advanced-options .advanced-feature-flags .label-text { min-width:0 !important; color:#243b49 !important; font-size:13px !important; font-weight:720 !important; white-space:nowrap !important; word-break:keep-all !important; writing-mode:horizontal-tb !important; }
.strategy-advanced-options .advanced-feature-flags .info { margin:6px 0 0 27px !important; color:#778892 !important; font-size:10px !important; line-height:1.4 !important; }
.workflow-section-heading { position:relative; display:flex; align-items:flex-end; justify-content:space-between; gap:18px; min-height:72px; margin:0 0 16px; padding:3px 4px 13px 15px; border-bottom:1px solid #dce9f1; }
.workflow-section-heading::before { content:""; position:absolute; left:0; top:6px; width:3px; height:58px; border-radius:0 4px 4px 0; background:linear-gradient(#0878c3,#6bb439); }
.workflow-section-heading .section-title { margin-top:4px; }
.workflow-section-heading .section-desc { margin-top:5px; }
.workflow-section-copy { min-width:0; }
.agent-edit-actions { gap:8px !important; margin-top:4px; }
.agent-impact-preview { margin-top:8px; padding:10px 12px; border:1px solid #d9e8f2; border-radius:10px; background:#f8fbfd; color:#456579; font-size:11px; line-height:1.5; }
.agent-impact-preview b { color:#17638a; }.agent-impact-preview ul { margin:4px 0 8px 18px; padding:0; }.agent-impact-preview small { color:#8299a8; }
.agent-confidence { margin-bottom:7px; color:#6c8798; font-size:10px; }.agent-confidence b { color:#0872bc; }
.editor-workflow { margin-top:8px; padding:9px 11px; border:1px solid #d8e8f1; border-radius:10px; background:#fbfdfe; }
.editor-workflow-head { display:flex; justify-content:space-between; gap:8px; color:#315b75; font-size:9px; font-weight:850; letter-spacing:.1em; }
.editor-workflow-head small { color:#8ba0ad; font-size:8px; font-weight:650; letter-spacing:0; }
.editor-workflow-head small.complete { color:#4f9b57; }.editor-workflow-head small.failed { color:#c54c4c; }
.editor-workflow-empty { color:#8ba0ad; font-size:9px; }.editor-workflow-steps { display:flex; flex-wrap:wrap; gap:5px; margin-top:7px; }
.editor-workflow-step { display:grid; grid-template-columns:6px auto; column-gap:5px; align-items:center; padding:5px 7px; border:1px solid #deebf2; border-radius:7px; background:#fff; }
.editor-workflow-step i { grid-row:1 / span 2; width:6px; height:6px; border-radius:50%; background:#b9c9d3; }.editor-workflow-step b { color:#668092; font-size:8px; }.editor-workflow-step small { color:#92a3ad; font-size:7px; }
.editor-workflow-step.done { border-color:#cfe4c0; background:#f8fcf6; }.editor-workflow-step.done i { background:#68ad2f; }.editor-workflow-step.waiting { border-color:#b9dcef; background:#f2f9fd; }.editor-workflow-step.waiting i { background:#178bd3; }
.execution-dock { position:sticky; bottom:10px; z-index:30; align-items:stretch !important;
  padding:14px 16px !important; background:rgba(255,255,255,.96) !important;
  backdrop-filter:blur(14px); box-shadow:0 12px 34px rgba(21,66,96,.13) !important; }
.execution-actions { display:flex !important; flex-direction:column !important; gap:8px !important; }
.execution-actions button { width:100%; }
.post-run-actions { gap:8px !important; margin:0 !important; }
.post-run-actions > * { min-width:0 !important; flex:1 1 0 !important; }
.post-run-actions button { min-height:34px !important; font-size:10px !important; }
.diagnostic-handoff-card { display:flex; align-items:center; justify-content:space-between; gap:16px;
  margin-bottom:12px; padding:15px 17px; border:1px solid #cfe2ee; border-radius:13px;
  background:linear-gradient(110deg,#f5faff,#fff); }
.diagnostic-handoff-card h3 { margin:3px 0 4px; color:#173d58; font-size:16px; }
.diagnostic-handoff-card p { margin:0; color:#6d8493; font-size:10px; line-height:1.5; }
.diagnostic-handoff-badge { flex:0 0 auto; padding:7px 9px; border:1px solid #d6e8f2; border-radius:999px;
  color:#34769b; background:#f8fcfe; font-size:8px; font-weight:850; letter-spacing:.08em; }
.agent-main { min-height:190px; }
.reasoning-card { padding:22px 26px 18px; }
.agent-lower { min-height:210px; }
.agent-stream, .agent-decision { padding:16px 18px; }
.agent-stream { max-height:420px; }
.agent-event-history { margin:-2px 0 9px; padding:5px 8px; border:1px solid #e1edf3; border-radius:7px;
  background:#f8fbfd; color:#7b909e; font-size:8px; }
.agent-event-history b { color:#21668b; }
.agent-command-grid { display:grid; grid-template-columns:minmax(0,1.14fr) minmax(340px,.86fr);
  min-height:300px; border-bottom:1px solid #deebf3; background:#fff; }
.cognitive-panel { min-width:0; padding:17px 20px 14px; border-right:1px solid #deebf3;
  background:radial-gradient(circle at 47% 48%,rgba(27,146,216,.08),transparent 39%),
    linear-gradient(145deg,#fbfdff,#f5faff); }
.cognitive-head { display:flex; align-items:center; justify-content:space-between; gap:12px; }
.cognitive-head > div { display:flex; align-items:baseline; gap:9px; min-width:0; }
.cognitive-head span { color:#205777; font-size:10px; font-weight:880; letter-spacing:.13em; }
.cognitive-head small { color:#91a3af; font-size:8px; }
.cognitive-head > b { padding:5px 9px; border:1px solid #b9dcef; border-radius:999px;
  background:#edf8fe; color:#0872bc; font-size:9px; white-space:nowrap; }
.cognitive-map { height:205px; margin:-3px auto 0; }
.cognitive-map svg { display:block; width:100%; height:100%; overflow:visible; }
.cog-route { fill:none; stroke:#bcd5e5; stroke-width:1.45; stroke-linecap:round; }
.cog-route + .cog-signal { stroke:#c7dce9; stroke-width:1; stroke-dasharray:4 5; }
.cognitive-map marker path { fill:#82b5d3; }
.cog-node circle:first-child { fill:#fff; stroke:#c8dce8; stroke-width:1.4; filter:drop-shadow(0 4px 7px rgba(30,82,115,.08)); }
.cog-node .cog-pulse { fill:none; stroke:transparent; stroke-width:1; }
.cog-node .cog-label { fill:#6d8494; font-size:8px; font-weight:850; letter-spacing:.05em; }
.cog-node .cog-sub { fill:#9aaab4; font-size:7px; }
.cog-node.done circle:first-child { fill:#f6fbf2; stroke:#a9cf8d; }
.cog-node.done .cog-label { fill:#578a34; }.cog-node.done .cog-sub { fill:#7e9e68; }
.cog-node.active circle:first-child { fill:#edf8fe; stroke:#228fce; stroke-width:2; }
.cog-node.active .cog-pulse { stroke:rgba(34,143,206,.28); }
.thinking .cog-node.active .cog-pulse { animation:cog-pulse 1.7s ease-out infinite; transform-box:fill-box; transform-origin:center; }
.cog-node.active .cog-label { fill:#086eae; }.cog-node.active .cog-sub { fill:#367fa9; }
.failed .cog-node.active circle:first-child { fill:#fff5f5; stroke:#dc4c4c; }
.failed .cog-node.active .cog-label { fill:#b64141; }
.cog-brain rect { fill:#075ca8; stroke:#075ca8; stroke-width:1.6;
  filter:drop-shadow(0 8px 10px rgba(7,92,168,.2)); }
.cog-brain text { fill:#fff; font-size:15px; font-weight:900; letter-spacing:.12em; }
.thinking .cog-brain-float { animation:brain-glow 2.6s ease-in-out infinite; }
.activity-strip { display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); overflow:hidden;
  border:1px solid #dceaf2; border-radius:10px; background:rgba(255,255,255,.9); }
.activity-strip span { min-width:0; padding:7px 8px; border-right:1px solid #e3edf3; }
.activity-strip span:last-child { border-right:0; }
.activity-strip small { display:block; color:#91a2ad; font-size:7px; font-weight:800; letter-spacing:.06em; }
.activity-strip b { display:block; margin-top:2px; color:#17668f; font-size:12px; font-variant-numeric:tabular-nums; }
.agent-focus { display:grid; grid-template-rows:minmax(0,1fr) auto; min-width:0; }
.agent-focus .reasoning-card { padding:21px 23px 14px; min-width:0; }
.agent-focus .reasoning-card h3 { margin:7px 0 5px; font-size:20px; }
.agent-focus .reasoning-card > p { font-size:11px; line-height:1.55; }
.agent-focus .latest-signal { margin-top:12px; padding:9px 11px; font-size:9px; }
.agent-plan { padding:12px 20px 15px; border-top:1px solid #e4edf3; background:#fbfdfe; }
.agent-plan-title { display:flex; align-items:baseline; justify-content:space-between; color:#315b75;
  font-size:9px; font-weight:850; letter-spacing:.11em; }
.agent-plan-title small { color:#96a6b1; font-size:7px; font-weight:650; letter-spacing:0; }
.plan-step { display:flex; align-items:center; gap:9px; margin-top:8px; min-width:0; }
.plan-step > i { flex:0 0 8px; width:8px; height:8px; border-radius:50%; background:#c8d5dd; }
.plan-step > span { display:flex; align-items:baseline; gap:8px; min-width:0; }
.plan-step small { color:#92a3ad; font-size:7px; white-space:nowrap; }
.plan-step b { overflow:hidden; color:#5c7485; font-size:9px; text-overflow:ellipsis; white-space:nowrap; }
.plan-step.done > i { background:#68ad2f; }.plan-step.done b { color:#5a873a; }
.plan-step.active > i { background:#178bd3; box-shadow:0 0 0 4px rgba(23,139,211,.12); animation:pulse-dot 1.45s infinite; }
.plan-step.active b { color:#0872bc; }.plan-step.error > i { background:#dc4c4c; }
.plan-step.error b { color:#b44747; }
.agent-capability-row { display:grid; grid-template-columns:1.3fr .9fr; gap:0;
  border-bottom:1px solid #deebf3; background:#fbfdfe; }
.agent-capability-row > div { min-width:0; padding:13px 16px; border-right:1px solid #e2edf4; }
.agent-capability-row > div:last-child { border-right:0; }
.guardrail-box > span, .ledger-title { color:#3f657d; font-size:8px; font-weight:850; letter-spacing:.1em; }
.evidence-ledger { min-width:0; }.ledger-title { display:flex; justify-content:space-between; align-items:baseline; }
.ledger-title small { color:#97a8b2; font-size:7px; font-weight:650; letter-spacing:0; }
.ledger-grid { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:5px; margin-top:8px; }
.ledger-item { display:grid; grid-template-columns:6px minmax(0,1fr); align-items:center; column-gap:5px;
  padding:5px 6px; border:1px solid #e0eaf0; border-radius:7px; background:#fff; }
.ledger-item > i { grid-row:1 / span 2; width:5px; height:5px; border-radius:50%; background:#c3d0d8; }
.ledger-item b { color:#60798a; font-size:7px; letter-spacing:.04em; }
.ledger-item small { color:#9aa8b1; font-size:7px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.ledger-item.done { border-color:#cfe2c1; background:#f9fcf7; }.ledger-item.done > i { background:#68ad2f; }
.ledger-item.active > i { background:#178bd3; }.guardrail-box .trust-strip { margin-top:8px; gap:4px; }
.guardrail-box .trust-pill { padding:4px 6px; font-size:7px; }
.guardrail-box .trust-pill::before { width:10px; height:10px; font-size:7px; }
.agent-supervisor-bar { align-items:stretch !important; gap:10px !important; margin-top:10px;
  padding:10px !important; border:1px solid #d7e7f0; border-radius:14px;
  background:linear-gradient(110deg,#f7fbfe,#fff); }
.agent-supervisor-bar > * { min-width:0 !important; }
.supervisor-status { flex:1 1 auto !important; }
.supervisor-result { height:100%; min-height:70px; padding:11px 13px; border-left:3px solid #79aed0;
  border-radius:9px; background:#fff; }
.supervisor-verdict { display:flex; align-items:baseline; gap:10px; min-width:0; }
.supervisor-verdict span { flex:0 0 auto; color:#0b78be; font-size:8px; font-weight:880; letter-spacing:.12em; }
.supervisor-verdict b { overflow:hidden; color:#244e68; font-size:12px; text-overflow:ellipsis; white-space:nowrap; }
.supervisor-result > p { margin:7px 0 0; color:#708695; font-size:9px; line-height:1.45; }
.supervisor-result.critical { border-left-color:#c73737; background:#fff8f8; }
.supervisor-result.high { border-left-color:#e17836; background:#fffaf5; }
.supervisor-result.medium { border-left-color:#daa229; background:#fffcf3; }
.supervisor-result.low { border-left-color:#559ac7; }.supervisor-result.healthy { border-left-color:#68ad2f; background:#f8fcf5; }
.supervisor-facts { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:6px; margin-top:9px; }
.supervisor-facts span { min-width:0; padding:6px 7px; border:1px solid #dfebf2; border-radius:7px; background:rgba(255,255,255,.78); }
.supervisor-facts small { display:block; color:#95a5af; font-size:7px; }
.supervisor-facts b { display:block; margin-top:2px; overflow:hidden; color:#3b667e; font-size:8px;
  text-overflow:ellipsis; white-space:nowrap; }
.supervisor-actions { display:flex !important; flex:0 0 210px !important; justify-content:center; gap:6px !important; }
.supervisor-actions button { width:100%; min-height:31px !important; font-size:10px !important; }
#handoff-repair-button { border-color:#91bee0 !important; color:#075ca8 !important; background:#f0f8fd !important; }
.repair-shell { margin:4px 0 8px; padding:18px; border:1px solid #d7e6ef; border-radius:18px;
  background:linear-gradient(135deg,#f7fbfe,#fff 58%); box-shadow:0 8px 24px rgba(28,74,106,.06); }
.repair-hero { display:flex; justify-content:space-between; gap:18px; align-items:flex-start; }
.repair-hero h3 { margin:4px 0 6px; color:#173d58; font-size:20px; }
.repair-hero p { margin:0; max-width:840px; color:#60798b; font-size:12px; line-height:1.6; }
.repair-boundary { flex:0 0 270px; display:grid; grid-template-columns:repeat(2,1fr); gap:7px; }
.repair-boundary span { padding:7px 8px; border:1px solid #cfe3ef; border-radius:8px; background:#fff;
  color:#39708f; font-size:9px; font-weight:750; text-align:center; }
.repair-console-grid { align-items:stretch !important; gap:14px !important; margin-top:14px; }
.repair-control, .repair-output { min-width:0 !important; padding:16px; border:1px solid #deebf2;
  border-radius:15px; background:#fff; }
.repair-output .status-panel { margin-bottom:10px; }
.repair-trace { max-height:500px; overflow:auto; }
.repair-artifacts { display:flex !important; flex-wrap:wrap !important; gap:8px !important; margin-top:10px; }
.repair-artifacts > * { flex:1 1 180px; min-width:150px !important; }
#repair-run-button { min-height:46px; border:0 !important; font-weight:750 !important;
  background:linear-gradient(90deg,#075ca8,#0d82c7) !important; color:#fff !important;
  box-shadow:0 8px 20px rgba(7,92,168,.2); }
.gradio-container .tabs { border-radius:16px; overflow:hidden; }

@keyframes spin { to { transform:rotate(360deg); } }
@keyframes spin-reverse { to { transform:rotate(-360deg); } }
/* Never animate transform on the positioned SVG group: CSS transform would
   override its translate(289 121) attribute and move the AI badge to (0,0). */
@keyframes brain-glow {
  0%,100% { opacity:1; filter:drop-shadow(0 8px 10px rgba(7,92,168,.20)); }
  50% { opacity:.88; filter:drop-shadow(0 11px 15px rgba(7,92,168,.34)); }
}
@keyframes pulse-dot { 50% { box-shadow:0 0 0 8px rgba(33,150,223,0); } }
@keyframes typing { 0%,60%,100% { opacity:.3; transform:translateY(0); } 30% { opacity:1; transform:translateY(-2px); } }
@keyframes scan { 0% { top:7px; opacity:.3; } 50% { top:26px; opacity:1; } 100% { top:7px; opacity:.3; } }
@keyframes cog-pulse { 0% { opacity:.8; transform:scale(.82); } 100% { opacity:0; transform:scale(1.25); } }
@keyframes vehicle-pulse { 0%,100% { opacity:.45; transform:scale(.8); } 50% { opacity:1; transform:scale(1.35); } }
@media (max-width: 1180px) {
  .analysis-cockpit { flex-direction:column !important; }
  .analysis-cockpit > * { width:100% !important; min-width:0 !important; flex-basis:auto !important; }
  .timeline, .metric-grid { grid-template-columns:repeat(2,minmax(0,1fr)); }
  .chart-grid-three, .chart-grid-two { grid-template-columns:1fr; }
  .token-stat-grid { grid-template-columns:repeat(3,minmax(0,1fr)); }
  .ai-pill, .hero-proof, .vehicle-visual { display:none; }
  .agent-main { grid-template-columns:145px 1fr; }
  .agent-lower { grid-template-columns:1fr; }.agent-stream { border-right:0; border-bottom:1px solid #deebf3; }
  .agent-telemetry { grid-template-columns:repeat(3,minmax(0,1fr)); }
  .trace-rail { grid-template-columns:repeat(3,minmax(0,1fr)); }
  .trace-rail::before { display:none; }
  .agent-command-grid { grid-template-columns:1fr; }
  .cognitive-panel { border-right:0; border-bottom:1px solid #deebf3; }
  .agent-capability-row { grid-template-columns:1fr 1fr; }
  .agent-capability-row > div:last-child { border-top:0; }
  .advanced-feature-flags { grid-template-columns:repeat(2,minmax(0,1fr)); }
  .runtime-settings-grid { flex-wrap:wrap !important; }
  .runtime-settings-grid > * { flex:1 1 340px !important; }
  .strategy-card-grid { grid-template-columns:repeat(3,minmax(0,1fr)); }
  .strategy-advanced-options .advanced-feature-flags { grid-template-columns:repeat(2,minmax(0,1fr)); }
}
@media (max-width: 980px) {
  .execution-dock { flex-direction:column !important; align-items:stretch !important; }
  .execution-dock > * { width:100% !important; min-width:0 !important; flex-basis:auto !important; }
  .repair-hero { flex-direction:column; }
  .repair-boundary { width:100%; flex-basis:auto; }
}
@media (max-width: 720px) {
  .gradio-container { padding:10px 12px 30px !important; }.brand-shell { padding:22px; min-height:118px; }
  .brand-title { font-size:21px; }.nav-steps { overflow:auto; justify-content:flex-start; }.nav-arrow { width:24px; }
  .agent-main { grid-template-columns:1fr; }.agent-core { min-height:170px; border-right:0; border-bottom:1px solid #e2edf4; }
  .reasoning-card { padding:22px; }.agent-toolbar { padding:0 12px; }.private-badge { display:none; }
  .token-stat-grid { grid-template-columns:repeat(2,minmax(0,1fr)); }
  .agent-telemetry { grid-template-columns:repeat(2,minmax(0,1fr)); }
  .trace-rail { grid-template-columns:repeat(2,minmax(0,1fr)); }
  .runtime-ident code { display:none; }
  .agent-capability-row { grid-template-columns:1fr; }
  .agent-capability-row > div, .agent-capability-row > div:nth-child(2) { border-right:0; border-bottom:1px solid #e2edf4; }
  .agent-capability-row > div:last-child { grid-column:auto; border-bottom:0; }
  .advanced-feature-flags { grid-template-columns:1fr; }
  .diagnostic-handoff-card { align-items:flex-start; flex-direction:column; gap:9px; }
  .activity-strip { grid-template-columns:repeat(3,minmax(0,1fr)); }
  .activity-strip span:nth-child(3) { border-right:0; }
  .activity-strip span:nth-child(n+4) { border-top:1px solid #e3edf3; }
}

/* Fluid layout: keep every panel inside the viewport and let typography,
   spacing and cards scale with the available width. */
*, *::before, *::after { box-sizing:border-box; }
html, body { width:100%; max-width:100%; overflow-x:hidden; }
.gradio-container {
  width:100% !important; max-width:1520px !important; margin:0 auto !important;
  padding:clamp(12px,2.1vw,30px) clamp(12px,2.4vw,30px) clamp(26px,3.4vw,44px) !important;
}
.analysis-cockpit, .execution-dock, .delivery-panel, .analysis-charts,
.agent-workbench, .panel, .chart-card { width:100%; min-width:0; }
.analysis-cockpit > *, .execution-dock > *, .delivery-panel > * { min-width:0 !important; }
.brand-shell { width:100%; min-width:0; padding:clamp(18px,2.4vw,28px) clamp(18px,2.8vw,34px); }
.brand-title { font-size:clamp(22px,2.3vw,31px); overflow-wrap:anywhere; }
.brand-logo { width:clamp(112px,11vw,150px); height:auto; flex-basis:clamp(112px,11vw,150px); }
.vehicle-visual { width:min(350px,32vw); flex-basis:min(350px,32vw); }
.section-title { font-size:clamp(18px,1.7vw,22px); }
.upload-zone { height:clamp(112px,11vw,136px) !important; }
.agent-heading, .agent-toolbar, .trace-title, .analysis-charts-title { min-width:0; }
.agent-heading-copy, .reasoning-card, .trace-title > span, .trace-title > small { min-width:0; overflow-wrap:anywhere; }
.reasoning-card h3 { font-size:clamp(19px,2vw,24px); overflow-wrap:anywhere; }
.agent-toolbar { flex-wrap:wrap; height:auto; min-height:44px; padding-block:9px; row-gap:6px; }
.agent-toolbar > div { min-width:0; max-width:100%; }
.agent-toolbar .private-badge { max-width:42%; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.trace-title { flex-wrap:wrap; }
.trace-progress { flex:1 1 180px; min-width:140px; }
.trace-title > small { flex:0 1 auto; }
.execution-dock { flex-wrap:wrap !important; }
.execution-dock > * { flex-basis:0; }
.delivery-panel { display:flex !important; flex-wrap:wrap !important; gap:10px !important; }
.delivery-panel > * { flex:1 1 170px; min-width:150px !important; }
.chart-card, .token-usage-card { overflow:hidden; }
.token-stat b { overflow-wrap:anywhere; }

@media (max-width: 900px) {
  .agent-heading { align-items:flex-start; flex-direction:column; gap:8px; }
  .agent-heading-status { margin-bottom:0; }
  .execution-dock > * { flex:1 1 100%; width:100% !important; }
  .execution-dock { position:static; backdrop-filter:none; }
  .execution-dock .execution-actions { flex-direction:row !important; }
  .execution-actions > * { flex:1 1 0; }
  .agent-toolbar .private-badge { max-width:100%; }
  .agent-supervisor-bar { flex-direction:column !important; }
  .supervisor-actions { flex:1 1 auto !important; width:100%; }
  .runtime-settings-intro { align-items:flex-start; flex-direction:column; gap:5px; }
  .runtime-settings-intro p { text-align:left; }
  .runtime-settings-grid { flex-direction:column !important; }
  .runtime-settings-grid > * { width:100% !important; min-width:0 !important; flex-basis:auto !important; }
  .project-upload-row { flex-wrap:wrap !important; }
  .project-upload-row > * { flex:1 1 min(260px,100%) !important; }
  .strategy-card-grid { grid-template-columns:repeat(2,minmax(0,1fr)); }
  .agent-overview-row { flex-direction:column !important; }
  .agent-overview-row > * { width:100% !important; }
}
@media (max-width: 520px) {
  .gradio-container { padding:8px 8px 24px !important; }
  .brand-shell { flex-direction:column; align-items:flex-start; gap:12px; min-height:0; }
  .brand-logo { align-self:flex-start; width:118px; flex-basis:auto; }
  .brand-title { font-size:clamp(19px,6vw,25px); }
  .brand-subtitle { font-size:11px; }
  .nav-steps { margin-inline:0; padding-inline:10px; }
  .nav-step { font-size:9px; white-space:nowrap; }
  .panel { padding:14px; border-radius:16px; }
  .agent-main { grid-template-columns:1fr; }
  .cognitive-panel { padding:14px 10px 12px; }
  .cognitive-head { align-items:flex-start; }
  .cognitive-head > div { align-items:flex-start; flex-direction:column; gap:2px; }
  .cognitive-map { height:180px; }
  .agent-plan-title { align-items:flex-start; flex-direction:column; gap:2px; }
  .ledger-grid { grid-template-columns:repeat(2,minmax(0,1fr)); }
  .supervisor-facts { grid-template-columns:repeat(2,minmax(0,1fr)); }
  .agent-core { min-height:150px; }
  .reasoning-card { padding:18px; }
  .reasoning-card > p { font-size:12px; line-height:1.55; }
  .agent-telemetry { grid-template-columns:repeat(2,minmax(0,1fr)); }
  .agent-telemetry > div { padding:9px 10px; }
  .agent-telemetry b { font-size:13px; }
  .trace-title { align-items:flex-start; flex-direction:column; gap:8px; }
  .trace-progress { width:100%; flex-basis:auto; }
  .trace-title > small { margin-left:0; }
  .trace-rail { grid-template-columns:1fr; }
  .trace-span { min-height:66px; }
  .agent-lower { grid-template-columns:1fr; }
  .agent-stream, .agent-decision { padding:16px; }
  .execution-actions { flex-direction:column !important; }
  .execution-actions > * { width:100% !important; }
  .delivery-panel > * { flex-basis:100%; }
  .analysis-charts-title { align-items:flex-start; flex-direction:column; gap:4px; }
  .analysis-charts-title span { font-size:18px; }
  .runtime-settings-panel { padding:12px !important; }
  .agent-tab { padding:12px !important; }
  .runtime-settings-intro > div { align-items:flex-start; flex-direction:column; gap:2px; white-space:normal; }
  .runtime-setting-group { padding:10px !important; }
  .runtime-setting-group + .runtime-setting-group { border-left:0 !important; border-top:1px solid #dce8f0 !important; padding-top:16px !important; }
  .runtime-setting-group .runtime-profile-grid { grid-template-columns:repeat(2,minmax(0,1fr)); }
  .api-action-row { align-items:stretch !important; flex-direction:column !important; }
  .api-action-row > * { width:100% !important; }
  .project-upload-row { flex-direction:column !important; }
  .project-upload-row > * { width:100% !important; flex-basis:auto !important; }
  .setup-panel .project-upload-row .upload-zone { height:118px !important; }
  .dfd-extract-head { align-items:flex-start; flex-direction:column; gap:10px; padding:16px 16px 13px 28px; }
  .dfd-extract-head::before { left:16px; top:18px; height:46px; }
  .dfd-extract-count { align-self:flex-end; }
  .dfd-extract-toolbar { flex-wrap:wrap !important; }
  .dfd-extract-toolbar .gr-textbox { flex:1 1 100% !important; width:100% !important; }
  .strategy-card-grid { grid-template-columns:1fr; }
  .strategy-advanced-options { padding:12px !important; }
  .strategy-advanced-options .advanced-feature-flags { flex-direction:column !important; flex-wrap:nowrap !important; }
  .strategy-advanced-options .advanced-feature-flags > *,
  .strategy-advanced-options .advanced-feature-flags > *:first-child,
  .strategy-advanced-options .advanced-feature-flags > *:last-child {
    flex:0 0 auto !important; width:100% !important; min-height:46px; padding:9px 0 !important;
    border-left:0; border-top:1px solid #dce8ef;
  }
  .strategy-advanced-options .advanced-feature-flags > *:first-child { border-top:0; }
  .strategy-summary { align-items:flex-start; flex-direction:column; gap:10px; }
  .agent-launchbar { flex-direction:column !important; }
  .agent-launchbar > * { width:100% !important; }
  .donut-layout { align-items:flex-start; flex-direction:column; }
  .donut { align-self:center; }
  .chart-legend { width:100%; }
}

/* Neutral surface system: one surface per area, never a blue canvas behind
   another card.  Accent colour is reserved for focus and state only. */
.gradio-container input[type="checkbox"] { accent-color:#0f766e !important; }
.gradio-container input[type="checkbox"]:checked {
  border-color:#0f766e !important; background-color:#0f766e !important;
  outline-color:rgba(15,118,110,.14) !important;
}
.strategy-panel.panel {
  padding:0 !important; border:0 !important; border-radius:0 !important;
  background:transparent !important; box-shadow:none !important;
}
.strategy-panel .workflow-section-heading { margin-inline:2px; }
.runtime-settings-panel,
.strategy-advanced-options {
  padding:0 !important; border:0 !important; border-radius:0 !important;
  background:transparent !important; box-shadow:none !important;
}
.runtime-settings-panel > .wrap,
.strategy-advanced-options > .wrap {
  width:100% !important; padding:20px !important; border:1px solid #e2e7e9 !important;
  border-radius:16px !important; background:#fff !important;
  box-shadow:0 12px 30px rgba(15,23,42,.055) !important;
}
.runtime-settings-panel > .wrap > .form,
.strategy-advanced-options > .wrap > .form,
#runtime-settings,
#runtime-settings > .wrap,
#runtime-settings > .wrap > .form {
  background:#fff !important;
}
.runtime-settings-intro {
  margin:0 0 18px !important; padding:0 0 14px !important;
  border:0 !important; border-bottom:1px solid #edf0f1 !important;
  background:transparent !important;
}
.runtime-settings-intro span { color:#0f766e !important; }
.runtime-settings-grid { gap:0 !important; background:#fff !important; }
.runtime-setting-group {
  background:transparent !important; box-shadow:none !important;
}
.runtime-setting-group + .runtime-setting-group { border-left-color:#edf0f1 !important; }
.runtime-setting-title > span,
.advanced-options-heading-main > span {
  background:#f3f5f5 !important; color:#0f766e !important;
}
.runtime-preset-bar,
.runtime-profile,
.api-inline-status,
.sampling-guidance {
  background:#fafbfb !important; border-color:#e4e9ea !important;
  box-shadow:none !important;
}
.runtime-preset-picker label:has(input[type="radio"]:checked) {
  border-color:#75a99f !important; background:#f3faf7 !important;
  color:#176b61 !important; box-shadow:inset 0 0 0 1px rgba(15,118,110,.06) !important;
}
.strategy-advanced-options .advanced-feature-flags > .block:has(input[type="checkbox"]:checked),
.strategy-choice-card label:has(input[type="radio"]:checked),
.scope-radio label:has(input:checked) {
  border-color:#75a99f !important; background:#f4faf7 !important;
  box-shadow:inset 3px 0 0 #0f766e, 0 2px 9px rgba(15,118,110,.075) !important;
}
.strategy-advanced-options .advanced-feature-flags .label-text { color:#27363a !important; }
.strategy-advanced-options .advanced-feature-flags .info { color:#7a888c !important; }

/* The Agent workbench is the only surface in 04. */
#workflow-tabs .tabitem:has(.agent-workbench),
#workflow-tabs .tabitem:has(.agent-workbench) > .wrap,
.agent-tab,
.agent-tab > .wrap {
  padding:0 !important; border:0 !important; border-radius:0 !important;
  background:transparent !important; box-shadow:none !important;
}
.agent-workbench {
  border:1px solid #e1e7e9 !important; border-radius:16px !important;
  background:#fff !important; box-shadow:0 14px 34px rgba(15,23,42,.07) !important;
}
.agent-workbench::before { height:2px !important; background:#0f766e !important; }
.agent-toolbar,
.agent-telemetry,
.agent-main,
.agent-command-grid,
.agent-capability-row,
.agent-trace,
.agent-lower,
.agent-plan {
  background:#fff !important;
}
.cognitive-panel,
.agent-core,
.latest-signal,
.decision-facts > div,
.activity-strip,
.guardrail-box,
.agent-event-history {
  background:#fafbfb !important;
}
.cognitive-panel { background-image:none !important; }
.agent-core { background-image:none !important; }
.cognitive-head > b,
.latest-signal { border-color:#dce7e5 !important; }
.cognitive-head > b { background:#f3faf7 !important; color:#176b61 !important; }
.core-brain,
.cog-brain rect { background:#0f766e !important; fill:#0f766e !important; stroke:#0f766e !important; }
.agent-workbench .agent-eyebrow,
.agent-workbench .trace-title > span,
.agent-workbench .decision-head,
.agent-workbench .agent-telemetry b.telemetry-live { color:#0f766e !important; }
.agent-workbench .agent-capability-row,
.agent-workbench .agent-command-grid,
.agent-workbench .agent-lower,
.agent-workbench .agent-telemetry,
.agent-workbench .agent-toolbar { border-color:#edf0f1 !important; }

/* Final section shells --------------------------------------------------
   Keep the workflow calm and editorial: a white page, one quiet frame per
   section, and white controls inside it. The tab/group defaults previously
   painted a large blue canvas behind those controls. */
#workflow-tabs,
#workflow-tabs > .tabitem,
#workflow-tabs > .tabitem > .wrap {
  background:#fff !important;
}
#workflow-tabs > .tabitem.workflow-tab {
  box-sizing:border-box !important;
  margin-top:18px !important;
  padding:26px 28px 30px !important;
  border:1px solid #e3e7e6 !important;
  border-radius:22px !important;
  background:#fff !important;
  box-shadow:0 16px 40px rgba(15,23,42,.055) !important;
}
#workflow-tabs > .tabitem.workflow-tab > .wrap,
#workflow-tabs > .tabitem.workflow-tab > .form {
  padding:0 !important;
  border:0 !important;
  border-radius:0 !important;
  background:transparent !important;
  box-shadow:none !important;
}
#workflow-tabs > .tabitem.workflow-tab .workflow-section-heading {
  margin-top:0 !important;
}

/* 02: the shell carries the frame; advanced controls remain an open row. */
#workflow-tabs > .tabitem.workflow-tab .strategy-panel,
#workflow-tabs > .tabitem.workflow-tab .strategy-advanced-options {
  background:transparent !important;
  box-shadow:none !important;
}
#workflow-tabs > .tabitem.workflow-tab .strategy-advanced-options {
  margin-top:24px !important;
  padding:18px 0 0 !important;
  border:0 !important;
  border-top:1px solid #edf0ef !important;
  border-radius:0 !important;
}

/* 03: no second white frame inside the section shell. */
#workflow-tabs > .tabitem.workflow-tab #runtime-settings,
#workflow-tabs > .tabitem.workflow-tab #runtime-settings > .wrap,
#workflow-tabs > .tabitem.workflow-tab #runtime-settings > .wrap > .form {
  margin-top:18px !important;
  padding:0 !important;
  border:0 !important;
  border-radius:0 !important;
  background:transparent !important;
  box-shadow:none !important;
}
#workflow-tabs > .tabitem.workflow-tab #runtime-settings .runtime-settings-intro {
  padding-top:0 !important;
}

/* 04: the workbench is content, not another outer container. */
#workflow-tabs > .tabitem.workflow-tab .agent-workbench {
  border:0 !important;
  border-radius:14px !important;
  box-shadow:none !important;
}

@media (max-width: 720px) {
  #workflow-tabs > .tabitem.workflow-tab {
    margin-top:12px !important;
    padding:18px 16px 20px !important;
    border-radius:16px !important;
  }
}

@media (max-width: 720px) {
  .runtime-settings-panel > .wrap,
  .strategy-advanced-options > .wrap { padding:14px !important; }
  .runtime-setting-group + .runtime-setting-group { border-left:0 !important; border-top:1px solid #edf0f1 !important; }
}
"""


DEMO_CSS += "\n" + Path(__file__).with_name("demo_theme.css").read_text(encoding="utf-8")


def _brand_logo_path() -> Path | None:
    configured = os.getenv("TARA_DEMO_LOGO", "").strip()
    candidates = [Path(configured)] if configured else [
        BRAND_ASSET_ROOT / filename
        for filename in (
            "catarc_logo.png",
            "catarc_logo.jpg",
            "catarc_logo.jpeg",
            "catarc_logo.webp",
        )
    ]
    return next(
        (
            path
            for path in candidates
            if path.is_file() and path.stat().st_size <= 5 * 1024 * 1024
        ),
        None,
    )


def _brand_logo_html() -> str:
    logo_path = _brand_logo_path()
    if logo_path is None:
        return (
            '<div class="brand-text-fallback" aria-label="中汽中心">'
            '<b>CATARC</b><span>中汽中心</span></div>'
        )
    mime_types = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".webp": "image/webp",
    }
    encoded = base64.b64encode(logo_path.read_bytes()).decode("ascii")
    mime_type = mime_types.get(logo_path.suffix.lower(), "image/png")
    return (
        '<img class="brand-logo" alt="中汽中心 CATARC Logo" '
        f'src="data:{mime_type};base64,{encoded}">'
    )


def _header_html() -> str:
    security_requirement_mode = (
        "AI 安全需求分析版"
        if DEMO_SECURITY_REQUIREMENTS_LLM
        else "规则匹配展示版"
    )
    return f"""
<header class="tara-hero">
  <div class="tara-hero-brand">{_brand_logo_html()}</div>
  <div class="tara-hero-copy">
    <div class="tara-hero-kicker">AI FOR TARA · 汽车</div>
    <h1>网络安全风险分析平台</h1>
    <p>Threat Analysis and Risk Assessment <span>·</span> 客户展示版 <span>·</span> {security_requirement_mode}</p>
  </div>
  <div class="tara-hero-visual" aria-hidden="true">
    <svg viewBox="0 0 620 250" role="presentation" focusable="false">
      <defs>
        <linearGradient id="hero-paint" x1="0" y1="0" x2="0.85" y2="1">
          <stop offset="0" stop-color="#ffffff"/><stop offset=".55" stop-color="#eaf6ff"/><stop offset="1" stop-color="#b8daed"/>
        </linearGradient>
        <linearGradient id="hero-glass" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stop-color="#d7f5ff"/><stop offset="1" stop-color="#6cb4dc"/>
        </linearGradient>
        <linearGradient id="hero-road" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0" stop-color="#c6e8f8" stop-opacity="0"/><stop offset=".5" stop-color="#7dbbe0" stop-opacity=".7"/><stop offset="1" stop-color="#c6e8f8" stop-opacity="0"/>
        </linearGradient>
      </defs>
      <g class="hero-hud" fill="none"><path d="M16 209H604M31 226H589"/><path d="M43 52a94 94 0 0 1 174-35M413 19a99 99 0 0 1 161 67"/></g>
      <g class="hero-connections" fill="none">
        <path d="M117 52Q183 57 278 78"/><path d="M320 44Q309 64 278 78"/><path d="M513 53Q454 57 397 76"/>
      </g>
      <g class="hero-endpoints">
        <g transform="translate(61 12)"><rect width="112" height="34" rx="17"/><path d="M56 34V40"/><circle cx="56" cy="40" r="4"/><text x="56" y="22" text-anchor="middle">CLOUD</text></g>
        <g transform="translate(277 4)"><rect width="86" height="34" rx="17"/><path d="M43 34V40"/><circle cx="43" cy="40" r="4"/><text x="43" y="22" text-anchor="middle">OTA</text></g>
        <g transform="translate(467 13)"><rect width="92" height="34" rx="17"/><path d="M46 34V40"/><circle cx="46" cy="40" r="4"/><text x="46" y="22" text-anchor="middle">V2X</text></g>
      </g>
      <ellipse class="hero-road-shadow" cx="317" cy="208" rx="255" ry="12"/>
      <g class="hero-vehicle">
        <path class="hero-car" d="M70 174L78 158Q81 153 94 150L162 138L215 95Q224 87 243 85L387 80Q402 80 415 91L468 126L531 143Q549 147 555 161L568 180L554 190H513Q510 166 489 157Q466 148 447 163Q432 175 430 193H183Q180 168 160 158Q137 148 116 162Q101 174 99 192H79L69 186Z"/>
        <path class="hero-roof-highlight" d="M168 137L216 98Q228 88 244 87L386 82Q402 82 411 91L464 127"/>
        <path class="hero-window" d="M183 135L219 102Q228 94 243 93L296 91L291 135Z"/>
        <path class="hero-window" d="M304 91L386 87Q398 87 406 96L449 129L303 135Z"/>
        <path class="hero-window-shine" d="M223 106L279 98M314 98L385 93"/>
        <path class="hero-pillar" d="M298 90L297 138M411 99L449 130"/>
        <path class="hero-body-detail" d="M95 151L164 142M181 143H514M300 141L298 184M423 136L430 185M183 183H427"/>
        <path class="hero-sill" d="M187 187H427"/>
        <rect class="hero-door-handle" x="319" y="148" width="23" height="5" rx="2.5"/>
        <rect class="hero-door-handle" x="427" y="146" width="19" height="5" rx="2.5"/>
        <path class="hero-tail-light" d="M76 158L96 154L94 164L72 167Z"/>
        <path class="hero-head-light" d="M531 148L550 154L556 164L532 161Z"/>
        <g class="hero-wheel-assembly" transform="translate(140 193)"><circle class="hero-tire" r="35"/><circle class="hero-rim" r="25"/><circle class="hero-rim-detail" r="18"/><circle class="hero-wheel-core" r="7"/><path d="M0-15V-9M15 0H9M0 15V9M-15 0h6"/></g>
        <g class="hero-wheel-assembly" transform="translate(473 193)"><circle class="hero-tire" r="35"/><circle class="hero-rim" r="25"/><circle class="hero-rim-detail" r="18"/><circle class="hero-wheel-core" r="7"/><path d="M0-15V-9M15 0H9M0 15V9M-15 0h6"/></g>
        <g class="hero-antenna-links" fill="none"><path d="M278 84V101L263 109M397 86L379 109"/></g>
        <g class="hero-car-nodes">
          <path d="M278 84V78M397 86V76"/>
          <circle cx="278" cy="78" r="4"/><circle cx="397" cy="76" r="4"/>
        </g>
        <g class="hero-vehicle-module"><rect x="223" y="109" width="65" height="20" rx="6"/><text x="255.5" y="123" text-anchor="middle">T-BOX</text></g>
        <g class="hero-vehicle-module"><rect x="335" y="109" width="60" height="20" rx="6"/><text x="365" y="123" text-anchor="middle">V2X</text></g>
      </g>
      <path class="hero-road-line" d="M34 233H602"/>
    </svg>
  </div>
</header>
"""




def _resolve_received_path(raw: Any) -> Path:
    """Recover a real upload path when Gradio sends only ``orig_name``.

    Gradio normally preprocesses FileData to an absolute cache path. A File
    value populated by another callback can, however, round-trip through the
    browser as only its display name. Resolve that name strictly inside the
    Gradio cache or the project's approved sample input tree.
    """
    path = Path(str(raw))
    if path.is_file() or path.is_absolute() or len(path.parts) != 1:
        return path
    safe_pattern = glob.escape(path.name)
    roots = (GRADIO_CACHE_ROOT, PROJECT_ROOT / "data" / "input")
    candidates: list[Path] = []
    for root in roots:
        if not root.is_dir():
            continue
        resolved_root = root.resolve()
        for candidate in root.rglob(safe_pattern):
            try:
                resolved_candidate = candidate.resolve()
                if (
                    resolved_candidate.is_file()
                    and resolved_candidate.is_relative_to(resolved_root)
                ):
                    candidates.append(resolved_candidate)
            except OSError:
                continue
    if not candidates:
        return path
    # Browser uploads are copied immediately before the callback. Selecting
    # the newest exact-name match avoids picking an expired previous session.
    return max(candidates, key=lambda item: item.stat().st_mtime_ns)


def _paths(value: Any) -> list[Path]:
    if value is None:
        return []
    values = value if isinstance(value, (list, tuple)) else [value]
    result: list[Path] = []
    for item in values:
        if isinstance(item, (str, os.PathLike)):
            raw = os.fspath(item)
        elif isinstance(item, dict):
            raw = item.get("path") or item.get("name") or item.get("orig_name")
        else:
            raw = getattr(item, "path", None) or getattr(item, "name", item)
        if raw:
            result.append(_resolve_received_path(raw))
    return result


def _safe_filename(name: str, fallback: str) -> str:
    cleaned = Path(name).name.strip() or fallback
    cleaned = re.sub(r"[\x00-\x1f]", "_", cleaned)
    return cleaned[:180]


def _validate_json(path: Path) -> None:
    with path.open("r", encoding="utf-8-sig") as source:
        payload = json.load(source)
    if not isinstance(payload, dict):
        raise ValueError("根节点必须是 JSON 对象")


def _validate_dfd_json(path: Path) -> None:
    """Validate one uploaded DFD against every supported exporter shape."""
    with path.open("r", encoding="utf-8-sig") as source:
        payload = json.load(source)
    detect_dfd_format(payload)


def validate_inputs_html(
    dfd_files: Any, topology_file: Any, interfaces_file: Any
) -> str:
    dfd_paths = _paths(dfd_files)
    topology_paths = _paths(topology_file)
    interface_paths = _paths(interfaces_file)
    issues: list[str] = []

    if not dfd_paths:
        issues.append("请上传至少一个 DFD JSON 文件")
    for path in dfd_paths:
        if not path.is_file():
            issues.append(f"DFD 上传缓存已失效：{path.name}，请重新选择文件")
            continue
        if path.suffix.lower() != ".json":
            issues.append(f"DFD 不是 JSON：{path.name}")
            continue
        try:
            _validate_dfd_json(path)
        except Exception as exc:
            issues.append(f"DFD 格式不支持：{path.name}（{exc}）")

    if len(topology_paths) != 1:
        issues.append("请上传一个拓扑 JSON 文件")
    elif not topology_paths[0].is_file():
        issues.append(
            f"拓扑上传缓存已失效：{topology_paths[0].name}，请重新选择文件"
        )
    elif topology_paths[0].suffix.lower() != ".json":
        issues.append("拓扑文件必须是 JSON")
    else:
        try:
            _validate_json(topology_paths[0])
        except Exception as exc:
            issues.append(f"拓扑文件无法解析：{exc}")

    if len(interface_paths) != 1:
        issues.append("请上传一个外部接口 Excel 文件")
    elif not interface_paths[0].is_file():
        issues.append(
            f"接口清单上传缓存已失效：{interface_paths[0].name}，请重新选择文件"
        )
    elif interface_paths[0].suffix.lower() not in {".xlsx", ".xlsm"}:
        issues.append("外部接口信息必须是 XLSX/XLSM")
    elif not zipfile.is_zipfile(interface_paths[0]):
        issues.append("外部接口 Excel 文件结构无效")

    if issues:
        return '<div class="input-warn"><b>输入待完善</b><br>' + "<br>".join(
            html.escape(item) for item in issues
        ) + "</div>"
    total_bytes = sum(path.stat().st_size for path in dfd_paths)
    return (
        '<div class="input-ok"><b>输入校验通过</b><br>'
        f"DFD：{len(dfd_paths)} 个文件 / {total_bytes / 1024:.1f} KB　·　"
        f"拓扑：{html.escape(topology_paths[0].name)}　·　"
        f"接口：{html.escape(interface_paths[0].name)}</div>"
    )


def _dfd_extract_text(value: Any) -> str:
    """Normalize display text without changing the uploaded DFD document."""

    return re.sub(
        r"\s+",
        " ",
        str(value or "").replace("\\n", " ").replace("\u3000", " "),
    ).strip()


def _dfd_extract_property_entries(cell: dict[str, Any]) -> list[str]:
    """Read asset terms in stable propertyList order from a DFD cell."""

    entries: list[tuple[int, str]] = []
    for key, value in cell.items():
        if not re.fullmatch(r"propertyList\d*", str(key), flags=re.IGNORECASE):
            continue
        if not isinstance(value, dict):
            continue
        term = _dfd_extract_text(value.get("finetermval"))
        if not term:
            continue
        index_match = re.search(r"\d+", str(key))
        entries.append((int(index_match.group()) if index_match else 0, term))
    return [term for _, term in sorted(entries, key=lambda item: item[0])]


def _dfd_extract_visible_text(cell: dict[str, Any]) -> str:
    attrs = cell.get("attrs") if isinstance(cell.get("attrs"), dict) else {}
    text_attrs = attrs.get("text") if isinstance(attrs.get("text"), dict) else {}
    return _dfd_extract_text(text_attrs.get("text"))


def _dfd_extract_flow_name(cell: dict[str, Any]) -> str:
    labels = cell.get("labels") if isinstance(cell.get("labels"), list) else []
    for label in labels:
        if not isinstance(label, dict):
            continue
        attrs = label.get("attrs") if isinstance(label.get("attrs"), dict) else {}
        text_attrs = attrs.get("text") if isinstance(attrs.get("text"), dict) else {}
        value = _dfd_extract_text(text_attrs.get("text"))
        if value:
            return value
    return _dfd_extract_visible_text(cell) or _dfd_extract_text(cell.get("id"))


def _dfd_extract_diagrams(payload: Any) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Accept the old/new DFD envelopes used by the project input exporters."""

    if isinstance(payload, list):
        return [entry for item in payload for entry in _dfd_extract_diagrams(item)]
    if not isinstance(payload, dict):
        return []
    detail = payload.get("detail")
    if isinstance(detail, dict) and isinstance(detail.get("diagrams"), list):
        return [
            (diagram, payload)
            for diagram in detail["diagrams"]
            if isinstance(diagram, dict)
        ]
    if isinstance(payload.get("diagrams"), list):
        return [
            (diagram, payload)
            for diagram in payload["diagrams"]
            if isinstance(diagram, dict)
        ]
    if isinstance(payload.get("diagramJson"), dict) or isinstance(payload.get("cells"), list):
        return [(payload, payload)]
    return []


def _dfd_extract_cells(diagram: dict[str, Any]) -> list[dict[str, Any]]:
    diagram_json = diagram.get("diagramJson")
    if isinstance(diagram_json, dict) and isinstance(diagram_json.get("cells"), list):
        return [cell for cell in diagram_json["cells"] if isinstance(cell, dict)]
    if isinstance(diagram.get("cells"), list):
        return [cell for cell in diagram["cells"] if isinstance(cell, dict)]
    return []


def _dfd_extract_summary_html(
    record_count: int = 0,
    source_count: int = 0,
    errors: Iterable[str] = (),
    total_count: int | None = None,
) -> str:
    error_list = list(errors)
    total = record_count if total_count is None else total_count
    if source_count:
        if total != record_count:
            note = (
                f"{source_count} 个输入 · 筛选显示 {record_count} / {total} 条"
                "资产/信号记录"
            )
        else:
            note = f"{source_count} 个输入 · 已提取 {record_count} 条资产/信号记录"
    else:
        note = "上传 DFD 后自动提取资产与信号，供分析前核对。"
    if error_list:
        note += " · " + "；".join(error_list[:2])
    return (
        '<div class="dfd-extract-head"><div>'
        '<div class="dfd-extract-kicker">DFD PREFLIGHT</div>'
        '<div class="dfd-extract-title">DFD 预提取结果表</div>'
        f'<div class="dfd-extract-note">{html.escape(note)}</div></div>'
        '<div class="dfd-extract-count"><b>'
        f'{record_count}</b><span>条记录</span></div></div>'
    )


def _dfd_preflight_records(
    dfd_files: Any,
) -> tuple[list[list[str]], list[str], int]:
    """Extract all rows once; filtering is applied by a separate server step."""
    dfd_paths = _paths(dfd_files)
    if not dfd_paths:
        return [], [], 0

    rows: list[list[str]] = []
    errors: list[str] = []
    parsed_sources = 0
    for source in dfd_paths:
        if not source.is_file():
            errors.append(f"{source.name} 不可读取")
            continue
        try:
            with source.open("r", encoding="utf-8-sig") as stream:
                payload = json.load(stream)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            errors.append(f"{source.name} 解析失败：{exc}")
            continue
        try:
            payload = (
                convert_new_dfd_json(payload)
                if detect_dfd_format(payload) == "new" else normalize_dfd_json(payload)
            )
        except Exception as exc:
            errors.append(f"{source.name} 格式不支持：{exc}")
            continue
        diagrams = _dfd_extract_diagrams(payload)
        if not diagrams:
            errors.append(f"{source.name} 未发现 DFD 图")
            continue
        parsed_sources += 1
        for diagram_index, (diagram, parent) in enumerate(diagrams, start=1):
            function_name = _dfd_extract_text(
                diagram.get("title")
                or diagram.get("name")
                or parent.get("title")
                or parent.get("name")
            )
            if not function_name:
                function_name = (
                    source.stem
                    if len(diagrams) == 1
                    else f"{source.stem} · 图 {diagram_index}"
                )
            for cell in _dfd_extract_cells(diagram):
                cell_type = _dfd_extract_text(cell.get("type"))
                if cell_type in {"tm.Boundary", "tm.Actor"}:
                    continue
                properties = _dfd_extract_property_entries(cell)
                if not properties:
                    continue
                if cell_type == "tm.Flow":
                    element = _dfd_extract_flow_name(cell)
                    protocol = _dfd_extract_text(cell.get("protocol"))
                    rows.extend(
                        [function_name, element, asset, protocol]
                        for asset in properties
                    )
                    continue
                element = (
                    _dfd_extract_visible_text(cell)
                    or properties[0]
                    or _dfd_extract_text(cell.get("id"))
                )
                rows.append([
                    function_name,
                    element,
                    properties[0],
                    "",
                ])
    return rows, errors, parsed_sources


def preview_dfd_extraction(
    dfd_files: Any,
    keyword: str = "",
    function_filter: str = "全部",
    protocol_filter: str = "全部",
) -> tuple[str, list[list[str]]]:
    """Apply server-side, column-aware filters to the DFD preflight table."""
    rows, errors, parsed_sources = _dfd_preflight_records(dfd_files)
    if not _paths(dfd_files):
        return _dfd_extract_summary_html(), []

    normalized_keyword = _dfd_extract_text(keyword).casefold()
    selected_function = _dfd_extract_text(function_filter)
    selected_protocol = _dfd_extract_text(protocol_filter)
    visible_rows = [
        row for row in rows
        if (not normalized_keyword or normalized_keyword in " ".join(row).casefold())
        and (selected_function in {"", "全部"} or row[0] == selected_function)
        and (selected_protocol in {"", "全部"} or row[3] == selected_protocol)
    ]
    return (
        _dfd_extract_summary_html(
            len(visible_rows), parsed_sources, errors, total_count=len(rows)
        ),
        visible_rows,
    )


def refresh_dfd_extraction(
    dfd_files: Any,
    keyword: str = "",
    function_filter: str = "全部",
    protocol_filter: str = "全部",
) -> tuple[str, list[list[str]], dict[str, Any], dict[str, Any]]:
    """Refresh rows plus dynamic function/protocol filter choices."""
    rows, _, _ = _dfd_preflight_records(dfd_files)
    functions = ["全部", *sorted({row[0] for row in rows if row[0]}, key=str.casefold)]
    protocols = ["全部", *sorted({row[3] for row in rows if row[3]}, key=str.casefold)]
    function_value = function_filter if function_filter in functions else "全部"
    protocol_value = protocol_filter if protocol_filter in protocols else "全部"
    summary, visible = preview_dfd_extraction(
        dfd_files,
        keyword,
        function_value,
        protocol_value,
    )
    return (
        summary,
        visible,
        gr.update(choices=functions, value=function_value),
        gr.update(choices=protocols, value=protocol_value),
    )


def available_sample_projects() -> list[tuple[str, str]]:
    """发现可直接载入的项目输入目录。

    只有同时存在 DFD JSON、拓扑 JSON 和 information Excel 的项目才会
    出现在网页中，避免用户选择一个不完整目录后才在分析阶段报错。
    """
    input_root = PROJECT_ROOT / "data" / "input"
    if not input_root.is_dir():
        return []
    projects: list[tuple[str, str]] = []
    for project_root in sorted(
        (path for path in input_root.iterdir() if path.is_dir()),
        key=lambda path: path.name.casefold(),
    ):
        dfd_count = len(
            [path for path in (project_root / "DFD").glob("*.json") if path.is_file()]
        )
        topology_count = len(
            [path for path in (project_root / "topology").glob("*.json") if path.is_file()]
        )
        interface_count = len(
            [
                path
                for pattern in ("*.xlsx", "*.xlsm")
                for path in (project_root / "information").glob(pattern)
                if path.is_file()
            ]
        )
        if dfd_count and topology_count and interface_count:
            projects.append((f"{project_root.name} · {dfd_count} 个 DFD", project_root.name))
    return projects


def sample_project_inputs(project: str = "C808") -> tuple[list[str], str, str, str]:
    """载入 ``data/input/{project}`` 中的一套完整演示输入。"""
    project_name = Path(str(project or "C808")).name.strip() or "C808"
    valid_projects = {value for _, value in available_sample_projects()}
    if project_name not in valid_projects:
        return ([], "", "", validate_inputs_html([], "", ""))
    project_root = PROJECT_ROOT / "data" / "input" / project_name
    dfd_dir = project_root / "DFD"
    dfd_files = [str(path) for path in sorted(dfd_dir.glob("*.json"))]
    topology_candidates = [
        path for path in (project_root / "topology").glob("*.json")
        if path.is_file()
    ]
    interface_candidates = [
        path
        for pattern in ("*.xlsx", "*.xlsm")
        for path in (project_root / "information").glob(pattern)
        if path.is_file()
    ]
    topology = str(max(
        topology_candidates,
        key=lambda path: (path.stat().st_mtime_ns, path.name),
    )) if topology_candidates else ""
    interfaces = str(max(
        interface_candidates,
        key=lambda path: (path.stat().st_mtime_ns, path.name),
    )) if interface_candidates else ""
    return (
        dfd_files,
        topology,
        interfaces,
        validate_inputs_html(dfd_files, topology, interfaces),
    )


def sample_c808_inputs() -> tuple[list[str], str, str, str]:
    """Backward-compatible C808 callback used by older integrations/tests."""
    return sample_project_inputs("C808")


def sample_eu15_inputs() -> tuple[list[str], str, str, str]:
    """Backward-compatible EU15 callback used by older integrations/tests."""
    return sample_project_inputs("EU15")


def model_status_html(api_base: str = API_BASE) -> str:
    service = configured_api()
    model = service[2] if service else ""
    if model:
        return (
            '<div class="model-card"><span class="model-dot"></span><div>'
            '<div class="model-label">API · 已配置</div>'
            f'<div class="model-name">{html.escape(model)}</div></div></div>'
        )
    return (
        '<div class="model-card"><span class="model-dot offline"></span><div>'
        '<div class="model-label">API · 浏览模式</div>'
        '<div class="model-name">历史报告可直接查看</div></div></div>'
    )


def _discover_models_for_api(api_base: str, api_key: str = "") -> list[str]:
    """Discover all model ids using the UI endpoint and optional key."""
    try:
        api_base, api_key, _ = require_api()
        return list_service_models(
            api_base, api_key,
            timeout=4, open_url=urlrequest.urlopen,
        )
    except (APIServiceError, ValueError):
        return []


def _discover_model_for_api(api_base: str, api_key: str = "") -> str:
    """Discover the first model using the UI-provided endpoint."""
    models = _discover_models_for_api(api_base, api_key)
    return models[0] if models else ""


def api_connection_status(
    api_base: str, api_key: str, model_name: str = ""
) -> str:
    """Probe an OpenAI-compatible endpoint for the settings panel."""
    try:
        endpoint, key, manual_model = require_api()
        result = check_api_service(
            endpoint, key,
            [manual_model] if manual_model else [],
            timeout=15, open_url=urlrequest.urlopen,
        )
    except (APIServiceError, ValueError) as exc:
        return (
            '<div class="api-inline-status offline"><i></i><span>'
            f'<b>API 检查未通过</b><small>{html.escape(str(exc))}</small>'
            '</span></div>'
        )
    model = manual_model or result["model_ids"][0]
    verification = "模型列表验证" if result["checked_by"] == "models" else "聊天接口验证"
    return (
        '<div class="api-inline-status online"><i></i><span>'
        f'<b>API 已连接</b><small>{html.escape(result["api_base"])} · '
        f'{html.escape(model)} · {verification}</small>'
        '</span></div>'
    )


def _is_local_api_endpoint(api_base: str) -> bool:
    """Whether an API URL points to the same machine as the client.

    GPU auto-detection is valid for the bundled local vLLM service only.  A
    remote OpenAI-compatible endpoint must not inherit the client's
    ``nvidia-smi`` result as if it described the provider's GPU.
    """
    try:
        host = (urlparse(str(api_base or "")).hostname or "").strip().lower()
    except ValueError:
        return False
    return host in {"127.0.0.1", "localhost", "::1"}


def _api_runtime_profile_html(
    api_base: str,
    model_name: str,
    adaptive_scheduling: bool,
    gpu_memory_gb: float | int | None,
    model_quantization: str | None,
    api_key: str = '',
) -> str:
    """Render the effective client scheduling profile without calling the LLM."""
    endpoint = str(api_base or API_BASE).strip() or API_BASE
    parsed = urlparse(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return '<div class="input-warn"><b>API 地址无效</b><br>请输入 http(s)://host[:port]/v1 格式。</div>'
    try:
        memory = float(gpu_memory_gb or 0)
    except (TypeError, ValueError):
        memory = 0.0
    quantization = str(model_quantization or "").strip().lower()
    if quantization == "auto":
        quantization = ""
    remote_api = not _is_local_api_endpoint(endpoint)
    from automotive_tara.assistant_context import task_context_profile
    request_context = task_context_profile(endpoint,str(model_name or ''),api_key)['effective']
    profile = derive_runtime_profile(
        str(model_name or "当前服务模型"),
        gpu_memory_gb=memory if memory > 0 else None,
        quantization=quantization,
        probe_gpu=not remote_api,
    )
    if not adaptive_scheduling:
        profile_name, model_defaults = _runtime_defaults_for_model(
            str(model_name or "")
        )
        # The UI runs in a long-lived process, so show the same model-specific
        # defaults that the child TARA process will use. Explicit environment
        # overrides remain authoritative and are reflected when present.
        env_overrides = {
            "max_concurrent_llm": "TARA_MAX_CONCURRENT_LLM",
            "stage_c_max_concurrent_llm": "TARA_STAGE_C_MAX_CONCURRENT_LLM",
            "batch_dst": "TARA_BATCH_DST",
            "batch_impact": "TARA_BATCH_IMPACT",
            "feasibility_paths_per_call": "TARA_FEASIBILITY_PATHS_PER_CALL",
        }
        limits = dict(model_defaults)
        for key, env_name in env_overrides.items():
            raw = os.getenv(env_name, "").strip()
            if raw:
                try:
                    limits[key] = int(raw)
                except ValueError:
                    pass
        limits["context_tokens"] = request_context
        if not remote_api:
            limits['max_concurrent_llm'] = min(8,limits['max_concurrent_llm'])
            limits['stage_c_max_concurrent_llm'] = min(8,limits['stage_c_max_concurrent_llm'])
        return (
            '<div class="runtime-profile manual"><div class="runtime-profile-head">'
            f'<b>固定生产配置 · {html.escape(profile_name)}</b>'
            '<span>按当前模型选择</span></div><div class="runtime-profile-grid">'
            f'<span><b>{html.escape(str(limits.get("max_concurrent_llm", "—")))}</b><small>LLM并发</small></span>'
            f'<span><b>{html.escape(str(limits.get("stage_c_max_concurrent_llm", "—")))}</b><small>Stage C并发</small></span>'
            f'<span><b>{html.escape(str(limits.get("batch_dst", "—")))}</b><small>DST批量</small></span>'
            f'<span><b>{html.escape(str(limits.get("batch_impact", "—")))}</b><small>影响批量</small></span>'
            f'<span><b>{html.escape(str(limits.get("batch_size_attack", "—")))}</b><small>Attack批量</small></span>'
            f'<span><b>{html.escape(str(limits.get("direct_attack_paths_per_call", "—")))}</b><small>完整路径/次</small></span>'
            f'<span><b>{html.escape(str(limits.get("feasibility_paths_per_call", "—")))}</b><small>可行性/次</small></span>'
            f'<span><b>{html.escape(str(limits.get("context_tokens", "—")))}</b><small>上下文上限</small></span>'
            '</div><small>自适应调度关闭；不会根据显存自动改变配置。显式 TARA_* 环境变量优先。</small></div>'
        )
    limits = dict(profile.get("limits", {}))
    limits['context_tokens'] = request_context
    if not remote_api:
        limits['max_concurrent_llm'] = min(8,limits['max_concurrent_llm'])
        limits['stage_c_max_concurrent_llm'] = min(8,limits['stage_c_max_concurrent_llm'])
    _, model_defaults = _runtime_defaults_for_model(str(model_name or ""))
    limits.setdefault("batch_size_attack", model_defaults.get("batch_size_attack", 16))
    limits.setdefault(
        "direct_attack_paths_per_call",
        model_defaults.get("direct_attack_paths_per_call", 8),
    )
    if remote_api and memory <= 0:
        memory_label = "远端显存未知"
    else:
        memory_label = f'{profile.get("gpu_memory_gb", 0):g} GB' if profile.get("gpu_memory_gb") else "自动检测/未知"
    quant_label = "量化模型" if profile.get("quantized") else "非量化或未知"
    size = profile.get("model_size_b")
    size_label = f" · 约 {float(size):g}B" if isinstance(size, (int, float)) and size else ""
    return (
        '<div class="runtime-profile"><div class="runtime-profile-head">'
        f'<b>自适应运行配置 · {html.escape(str(profile.get("tier", "unknown")))}</b>'
        f'<span>{html.escape(memory_label)} · {html.escape(quant_label)}{html.escape(size_label)}</span></div>'
        '<div class="runtime-profile-grid">'
        f'<span><b>{html.escape(str(limits.get("max_concurrent_llm", "—")))}</b><small>LLM并发</small></span>'
        f'<span><b>{html.escape(str(limits.get("stage_c_max_concurrent_llm", "—")))}</b><small>Stage C并发</small></span>'
        f'<span><b>{html.escape(str(limits.get("batch_dst", "—")))}</b><small>DST批量</small></span>'
        f'<span><b>{html.escape(str(limits.get("batch_impact", "—")))}</b><small>影响批量</small></span>'
        f'<span><b>{html.escape(str(limits.get("batch_size_attack", "—")))}</b><small>Attack批量</small></span>'
        f'<span><b>{html.escape(str(limits.get("direct_attack_paths_per_call", "—")))}</b><small>完整路径/次</small></span>'
        f'<span><b>{html.escape(str(limits.get("feasibility_paths_per_call", "—")))}</b><small>可行性/次</small></span>'
        f'<span><b>{html.escape(str(limits.get("context_tokens", "—")))}</b><small>上下文上限</small></span>'
        '</div><small>'
        + (
            "仅调整客户端调度；远端服务显存未知，请填写显存 GB 或采用保守配置。"
            if remote_api and memory <= 0
            else "仅调整客户端调度；显式 TARA_* 环境变量优先。"
        )
        + '</small></div>'
    )


def runtime_profile_status(
    api_base: str,
    external_model: str,
    selected_model: str,
    adaptive_scheduling: bool,
    gpu_memory_gb: float | int | None,
    model_quantization: str | None,
    api_key: str = '',
) -> str:
    """UI adapter: prefer a manually entered external model over local choice."""
    service = configured_api()
    if service is None:
        return '<div class="input-warn">' + html.escape(API_REQUIRED) + '</div>'
    api_base, api_key, model = service
    return _api_runtime_profile_html(
        api_base, model, adaptive_scheduling, gpu_memory_gb, model_quantization, api_key
    )


def available_model_choices(
    model_root: Path | None = None,
) -> list[tuple[str, str]]:
    """Enumerate direct, real model directories under the configured root."""
    if model_root is None:
        return []
    root = model_root.resolve()
    if not root.is_dir():
        return []
    choices: list[tuple[str, str]] = []
    for candidate in sorted(root.iterdir(), key=lambda path: path.name.casefold()):
        if candidate.is_symlink() or not candidate.is_dir():
            continue
        if not (candidate / "config.json").is_file():
            continue
        choices.append((candidate.name, candidate.name))
    return choices


def _lora_served_name(adapter_path: Path, root: Path) -> str:
    """Create a stable OpenAI model id for an allow-listed adapter."""
    relative = adapter_path.resolve().relative_to(root.resolve())
    # vLLM exposes this value through /v1/models, so keep it portable and
    # distinguish adapters with the same final directory name.
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", "-".join(relative.parts))
    return f"tara-lora-{slug.strip('-').lower() or 'adapter'}"


def _model_family_key(path: Path) -> str:
    """Return a comparable family key with common quantization suffixes removed."""
    name = path.name.casefold()
    name = re.sub(
        r"(?:[-_.](?:awq|gptq|int\d+|fp\d+|quant(?:ized)?))+$",
        "",
        name,
    )
    return re.sub(r"[^a-z0-9]+", "", name)


def _model_architecture_signature(path: Path) -> tuple[Any, ...]:
    """Read stable architecture fields without importing Transformers."""
    try:
        config = json.loads((path / "config.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ()
    architectures = config.get("architectures")
    if isinstance(architectures, list):
        architectures = tuple(str(item) for item in architectures)
    else:
        architectures = (str(architectures or ""),)
    return (
        architectures,
        str(config.get("model_type") or ""),
        config.get("hidden_size"),
        config.get("num_hidden_layers"),
        config.get("num_experts"),
        config.get("num_local_experts"),
        config.get("vocab_size"),
    )


def _runtime_base_for_lora(base_path: Path, model_root: Path) -> Path:
    """Choose a local quantized sibling when it has the same architecture.

    PEFT records the original full-precision training path in
    ``base_model_name_or_path``.  On this single-GPU demo host that model can
    load its weights but leave too little KV cache for the configured 8192
    context.  vLLM supports applying this adapter to the matching AWQ sibling;
    choose it only when the architecture signature and model family match.
    """
    if not base_path.is_dir() or not model_root.is_dir():
        return base_path
    signature = _model_architecture_signature(base_path)
    if not signature:
        return base_path
    family = _model_family_key(base_path)
    candidates: list[Path] = []
    for candidate in model_root.iterdir():
        if candidate == base_path or candidate.is_symlink() or not candidate.is_dir():
            continue
        if not (candidate / "config.json").is_file():
            continue
        candidate_config = {}
        try:
            candidate_config = json.loads(
                (candidate / "config.json").read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError):
            continue
        quantization = candidate_config.get("quantization_config")
        quantized_name = bool(
            re.search(r"(?:awq|gptq|int\d+|fp\d+|quant)", candidate.name, re.I)
        )
        if not quantization and not quantized_name:
            continue
        if _model_family_key(candidate) != family:
            continue
        if _model_architecture_signature(candidate) != signature:
            continue
        candidates.append(candidate)
    return sorted(candidates, key=lambda path: path.name.casefold())[0] if candidates else base_path


def _resolve_lora_choice(
    selected: str | None,
    lora_root: Path | None = None,
    model_root: Path | None = None,
) -> dict[str, Any] | None:
    """Resolve a UI adapter choice and verify its declared local base model.

    Adapter directories are intentionally allow-listed under ``LORA_ROOT``;
    browser input can never supply an arbitrary filesystem path to vLLM.
    """
    if not selected:
        return None
    root = (lora_root or LORA_ROOT).resolve()
    base_root = (model_root or MODEL_ROOT).resolve()
    try:
        relative = Path(str(selected))
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("LoRA 选择无效，请从列表中重新选择")
        adapter_path = (root / relative).resolve()
        adapter_path.relative_to(root)
    except (OSError, ValueError) as exc:
        raise ValueError("LoRA 路径不在允许的训练输出目录中") from exc
    config_path = adapter_path / "adapter_config.json"
    weights_path = adapter_path / "adapter_model.safetensors"
    if not adapter_path.is_dir() or not config_path.is_file() or not weights_path.is_file():
        raise ValueError(f"LoRA adapter 不完整：{adapter_path}")
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"无法读取 LoRA 配置：{config_path}") from exc
    base_raw = str(config.get("base_model_name_or_path") or "").strip()
    if not base_raw:
        raise ValueError("LoRA 配置缺少 base_model_name_or_path")
    base_path = Path(base_raw).expanduser().resolve()
    try:
        base_path.relative_to(base_root)
    except ValueError as exc:
        raise ValueError(
            f"LoRA 基础模型不在允许目录 {base_root}：{base_path}"
        ) from exc
    if not (base_path / "config.json").is_file():
        raise ValueError(f"LoRA 对应的基础模型不可用：{base_path}")
    try:
        rank = int(config.get("r", 0))
    except (TypeError, ValueError):
        rank = 0
    if rank <= 0:
        raise ValueError("LoRA 配置中的 rank 无效")
    return {
        "path": adapter_path,
        "base_path": base_path,
        "base_name": base_path.name,
        "runtime_base_path": _runtime_base_for_lora(base_path, base_root),
        "served_name": _lora_served_name(adapter_path, root),
        "rank": rank,
        "relative": relative.as_posix(),
    }


def available_lora_choices(
    lora_root: Path | None = None,
    model_root: Path | None = None,
) -> list[tuple[str, str]]:
    """List complete, locally compatible training adapters for the web UI."""
    root = (lora_root or LORA_ROOT).resolve()
    if not root.is_dir():
        return []
    choices: list[tuple[str, str]] = []
    for config_path in sorted(root.rglob("adapter_config.json")):
        adapter_path = config_path.parent
        # Training checkpoints are resumable intermediate artifacts.  The
        # exported ``adapter`` is the user-facing, completed model; hiding
        # checkpoints avoids loading an unfinished snapshot by accident.
        if adapter_path.name != "adapter":
            continue
        try:
            info = _resolve_lora_choice(
                adapter_path.relative_to(root).as_posix(), root, model_root
            )
        except ValueError:
            continue
        if info is None:
            continue
        label = (
            f"微调 LoRA · {info['relative'].removesuffix('/adapter')}"
            f"（运行：{info['runtime_base_path'].name}）"
        )
        choices.append((label, info["relative"]))
    return choices


def available_impact_lora_choices() -> list[tuple[str, str]]:
    """Expose only the approved impact-rating adapter in the customer Demo."""
    return [
        choice for choice in available_lora_choices()
        if choice[1] == IMPACT_LORA_RELATIVE
    ]


def _impact_lora_dropdown_choices() -> list[tuple[str, str]]:
    """Offer base-only operation and the approved impact adapter explicitly."""
    return [(NO_LORA_LABEL, NO_LORA_VALUE)]


def _default_impact_lora_for_model(
    selected_model: str | None,
    api_base: str = API_BASE,
) -> str:
    """Default to the impact adapter only for its compatible local base model."""
    if not _is_local_api_endpoint(api_base) or not str(selected_model or "").strip():
        return NO_LORA_VALUE
    if not any(value == IMPACT_LORA_RELATIVE for _, value in available_impact_lora_choices()):
        return NO_LORA_VALUE
    try:
        info = _resolve_lora_choice(IMPACT_LORA_RELATIVE)
    except ValueError:
        return NO_LORA_VALUE
    if info and info["runtime_base_path"].name == Path(str(selected_model)).name:
        return IMPACT_LORA_RELATIVE
    return NO_LORA_VALUE


def lora_choice_for_model_change(
    selected_model: str | None,
    selected_lora: str | None,
) -> tuple[str, str]:
    """Keep a compatible explicit choice; otherwise use that model's default."""
    try:
        info = _resolve_lora_choice(selected_lora)
    except ValueError:
        info = None
    value = (
        selected_lora
        if info and info["runtime_base_path"].name == Path(str(selected_model or "")).name
        else _default_impact_lora_for_model(selected_model)
    )
    return value, lora_selection_status(value)[1]


def lora_selection_status(selected: str | None) -> tuple[dict[str, Any], str]:
    """Show the adapter/base pairing and align the base-model picker."""
    try:
        info = _resolve_lora_choice(selected)
    except ValueError as exc:
        return gr.update(), (
            '<div class="input-warn"><b>LoRA 不可用</b><br>'
            f"{html.escape(str(exc))}</div>"
        )
    if info is None:
        return gr.update(), (
            '<div class="lora-inline-status standby"><i></i><span>'
            '<b>当前仅使用基础模型</b><small>'
            '本轮不加载 LoRA。需要适配器时，请在下拉框选择后点击“切换模型”；'
            'LoRA 只用于影响评级。'
            '</small>'
            '</span></div>'
        )
    return (
        gr.update(value=info["runtime_base_path"].name),
        '<div class="lora-inline-status online"><i></i><span>'
        f"<b>影响评级专用 LoRA · {html.escape(info['served_name'])}</b>"
        f"<small>训练底座：{html.escape(info['base_name'])} · 运行底座："
        f"{html.escape(info['runtime_base_path'].name)} · rank {info['rank']}。"
        "仅影响评级使用此 adapter；损害/威胁场景、攻击路径和可行性仍使用基础模型。"
        "若服务尚未加载该 adapter，请先点击“切换模型”。</small>"
        '</span></div>',
    )


def _current_model_choice(
    choices: list[tuple[str, str]],
    current_model: str | None = None,
) -> str | None:
    values = [value for _, value in choices]
    if not values:
        return None
    current = current_model
    if current is None:
        current = discover_service_model(API_BASE, timeout=3)
    if current in values:
        return current
    # A vLLM process serving a LoRA may report that adapter as the active
    # model. The model picker must still show its paired base model so the
    # switch controls remain consistent with the selected adapter.
    try:
        state = json.loads(
            (PROJECT_ROOT / "outputs" / "vllm" / "current.json").read_text(
                encoding="utf-8"
            )
        )
        if current == state.get("lora_name"):
            base_name = str(state.get("served_name") or "").strip()
            if base_name in values:
                return base_name
    except (OSError, json.JSONDecodeError, AttributeError):
        pass
    folded = str(current or "").casefold()
    return next(
        (value for value in values if value.casefold() == folded),
        values[0],
    )


def _resolve_model_choice(selected: str | None) -> Path:
    choices = {value for _, value in available_model_choices()}
    if not selected or selected not in choices:
        raise ValueError("模型选择无效，请刷新模型列表后重新选择")
    candidate = (MODEL_ROOT / selected).resolve()
    if candidate.parent != MODEL_ROOT or candidate.is_symlink():
        raise ValueError("模型路径不在允许的模型目录中")
    if not (candidate / "config.json").is_file():
        raise ValueError(f"模型目录缺少 config.json：{selected}")
    return candidate


def refresh_model_controls() -> tuple[str, dict[str, Any], dict[str, Any]]:
    choices = available_model_choices()
    current = discover_service_model(API_BASE, timeout=3)
    selected_model = _current_model_choice(choices, current)
    return (
        model_status_html(),
        gr.update(
            choices=choices,
            value=selected_model,
            interactive=bool(choices),
        ),
        gr.update(
            choices=_impact_lora_dropdown_choices(),
            value=_default_impact_lora_for_model(selected_model),
        ),
    )


def _model_switch_progress_html(
    state: str,
    title: str,
    detail: str,
    percent: int,
) -> str:
    bounded = max(0, min(100, int(percent)))
    return (
        f'<div class="model-switch-progress {html.escape(state)}">'
        '<div class="model-switch-head">'
        f'<span>{html.escape(title)}</span><span>{bounded}%</span></div>'
        '<div class="model-switch-track">'
        f'<div class="model-switch-value" style="width:{bounded}%"></div></div>'
        f'<div class="model-switch-detail">{html.escape(detail)}</div></div>'
    )


def _switch_progress_from_line(line: str, elapsed: int) -> int:
    if "vLLM 已就绪" in line:
        return 100
    if "等待模型就绪" in line:
        match = re.search(r"(\d+)s/(\d+)s", line)
        if match:
            spent, timeout = map(int, match.groups())
            return min(94, 45 + round(49 * spent / max(timeout, 1)))
        return min(94, 45 + elapsed // 10)
    if "日志文件" in line or "监听地址" in line or "服务名称" in line:
        return 42
    if "启动模型" in line:
        return 38
    if "停止当前 vLLM" in line or "未发现 vLLM" in line:
        return 25
    if "CUDA 预检通过" in line:
        return 12
    return min(90, max(5, elapsed // 8))


def switch_vllm_model(
    selected: str | None,
    lora_adapter: str | None = None,
) -> Generator[tuple[Any, ...], None, None]:
    """Safely switch vLLM to an allow-listed local model with live progress."""
    enabled = gr.update(interactive=False)
    yield model_status_html(), _model_switch_progress_html("idle", "使用服务端模型配置", API_REQUIRED, 0), gr.skip(), enabled, enabled
    return



def _status_html(state: str, title: str, detail: str) -> str:
    return (
        f'<div class="status-panel {html.escape(state)}">'
        f'<div class="status-title">{html.escape(title)}</div>'
        f'<div class="status-detail">{html.escape(detail)}</div></div>'
    )


def _stage_snapshot(
    lines: list[str], *, failed: bool = False, completed: bool = False
) -> list[dict[str, str]]:
    text = "\n".join(lines)
    snapshot: list[dict[str, str]] = []
    active_seen = False
    for stage_id, number, title, description, marker in STAGES:
        started = f"{marker} 开始" in text or (
            marker == "Step 4: 损害威胁场景"
            and "Step 4: 损害威胁场景 开始" in text
        )
        done = f"{marker} 完成" in text
        state = "done" if done else "pending"
        label = "已完成" if done else "等待中"
        if started and not done:
            state, label, active_seen = "active", "AI 处理中", True
        snapshot.append(
            {
                "id": stage_id,
                "number": number,
                "title": title,
                "description": description,
                "state": state,
                "label": label,
            }
        )
    if completed:
        for item in snapshot:
            item["state"], item["label"] = "done", "已完成"
    elif failed:
        active = next(
            (item for item in snapshot if item["state"] == "active"), None
        )
        if active is None:
            active = next(
                (item for item in snapshot if item["state"] == "pending"),
                snapshot[-1],
            )
        active["state"], active["label"] = "error", "执行异常"
    elif not active_seen and lines:
        pending = next(
            (item for item in snapshot if item["state"] == "pending"), None
        )
        if pending:
            pending["state"], pending["label"] = "active", "准备中"
    return snapshot


def _clean_event_line(line: str) -> tuple[str, str]:
    timestamp = ""
    match = re.match(
        r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:,\d+)?\s+"
        r"\[[A-Z]+\]\s*(.*)$",
        line.strip(),
    )
    if match:
        timestamp, line = match.group(1)[11:], match.group(2)
    return timestamp, re.sub(r"═+", "", line).strip()


def _agent_event_stream(lines: list[str], limit: int = 80) -> str:
    events: list[tuple[str, str, str, str]] = []
    # The HTML component is refreshed on every subprocess event, but the input
    # ``lines`` list is cumulative.  Read the complete evidence window first
    # and render a long scrollable tail so new events do not hide the history
    # from the current run.
    all_evidence = _evidence(lines, limit=10000)
    for raw_line in all_evidence[-limit:]:
        timestamp, message = _clean_event_line(raw_line)
        if not message:
            continue
        if "重试" in message or "校验失败" in message or "WARNING" in raw_line:
            kind, label = "verify", "规则校验 · SELF CHECK"
        elif "缓存" in message:
            kind, label = "cache", "SEMANTIC CACHE"
        elif any(marker in message for marker in ("batch", "批量调用", "模型调用", "LLM HTTP")):
            kind, label = "model", "MODEL RUN"
        elif "DFD" in message or "任务单元" in message:
            kind, label = "perceive", "PERCEPTION"
        elif "拓扑" in message or "攻击路径" in message:
            kind, label = "tool", "TOOL CALL"
        elif "完成" in message or "Excel" in message:
            kind, label = "success", "ADOPTED"
        else:
            kind, label = "reason", "INFERENCE"
        events.append((kind, label, timestamp or "LIVE", message[:280]))
    events = events[-limit:]
    if not events:
        events = [
            (
                "idle",
                "READY",
                "LIVE",
                "Agent 已装载 DFD 解析、可信拓扑、场景生成、评级与报告工具，等待分析任务。",
            )
        ]
    history_note = (
        f'<div class="agent-event-history"><b>本次运行事件历史</b> · '
        f'已记录 {len(all_evidence)} 条 · 当前显示最近 {len(events)} 条（可滚动查看）</div>'
    )
    return history_note + "".join(
        '<div class="agent-event {kind}"><span class="event-rail"></span>'
        '<div class="event-body"><div class="event-meta">{label}'
        '<span>{timestamp}</span></div><div class="event-message">{message}</div>'
        '</div></div>'.format(
            kind=kind,
            label=html.escape(label),
            timestamp=html.escape(timestamp),
            message=html.escape(message),
        )
        for kind, label, timestamp, message in events
    )


def _risk_score(value: Any) -> float | None:
    """Normalize numeric and labeled risk values to the common 1–5 scale."""
    if isinstance(value, dict):
        for key in ("risk_value_num", "risk_value", "score", "value", "等级", "值"):
            if key in value:
                score = _risk_score(value[key])
                if score is not None:
                    return score
        return None
    if isinstance(value, bool) or value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip().lower()
    labels = (
        ("严重", 5.0), ("severe", 5.0),
        ("高", 4.0), ("high", 4.0),
        ("中", 3.0), ("moderate", 3.0), ("medium", 3.0),
        ("低", 2.0), ("low", 2.0),
        ("qm", 1.0), ("可接受", 1.0),
    )
    for label, score in labels:
        if label in text:
            return score
    match = re.search(r"(?<!\d)(\d+(?:\.\d+)?)(?!\d)", text)
    if not match:
        return None
    try:
        return float(match.group(1))
    except ValueError:
        return None


def _high_risk_decision_list(samples: list[dict[str, Any]]) -> str:
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for sample in samples:
        score = _risk_score(sample.get("风险", sample.get("风险值")))
        if score is None or score < 4:
            continue
        key = (
            str(sample.get("功能", "")),
            str(sample.get("元素编号", "")),
            str(sample.get("资产", "未命名资产")),
        )
        current = grouped.setdefault(key, dict(sample))
        current_score = _risk_score(current.get("风险", current.get("风险值")))
        if current_score is None or score > current_score:
            current["风险"] = sample.get("风险", sample.get("风险值", ""))
            for field in ("影响值/等级", "影响等级", "可行性等级"):
                if field in sample:
                    current[field] = sample[field]
        for field in ("安全属性", "威胁场景", "损害场景"):
            old = str(current.get(field, "")).strip()
            new = str(sample.get(field, "")).strip()
            if new and new not in old.split("；"):
                current[field] = "；".join(item for item in (old, new) if item)
    high_risk = list(grouped.values())
    if not high_risk:
        return ""
    cards: list[str] = []
    for sample in high_risk:
        asset = str(sample.get("资产", "未命名资产"))
        element = str(sample.get("元素编号", "")).strip()
        function = str(sample.get("功能", "")).strip()
        attribute = str(sample.get("安全属性", "")).strip()
        risk = sample.get("风险", sample.get("风险值", ""))
        impact = sample.get("影响值/等级", {})
        impact_level = "待判断"
        if isinstance(impact, dict):
            impact_level = str(impact.get("level") or impact.get("等级") or "待判断")
        if impact_level == "待判断":
            impact_level = str(sample.get("影响等级", "待判断"))
        feasibility = str(
            sample.get("可行性等级")
            or sample.get("攻击可行性等级")
            or "待判断"
        )
        threat = str(sample.get("威胁场景", "")).strip()
        damage = str(sample.get("损害场景", "")).strip()
        # The live workbench is a decision summary, not a second report.
        # Prefer the impact outcome and keep one short sentence per asset.
        context = _compact_ai_summary(damage or threat)
        meta = " · ".join(
            item for item in (function, attribute, f"影响 {impact_level}", f"可行性 {feasibility}")
            if item and item not in {"待判断"}
        )
        if element:
            meta = f"{element} · {meta}" if meta else element
        cards.append(
            '<div class="high-risk-item">'
            '<div class="high-risk-item-head">'
            f'<b>{html.escape(asset)}</b><span>风险值 {html.escape(str(risk))}</span></div>'
            f'<div class="high-risk-item-meta">{html.escape(meta or "高风险任务")}</div>'
            f'<div class="high-risk-item-text">AI总结：{html.escape(context)}</div>'
            '</div>'
        )
    return (
        '<div class="decision-summary"><b>高风险资产 AI 总结</b>'
        f' · 共 {len(high_risk)} 项（风险值 ≥ 4）</div>'
        f'<div class="high-risk-list">{"".join(cards)}</div>'
    )


def _compact_ai_summary(value: Any, limit: int = 96) -> str:
    """Condense model prose for the customer-facing live conclusion card."""
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if not text:
        return "该资产达到高风险阈值，建议优先复核。"
    # Keep the first complete thought; full narratives remain in the report.
    parts = re.split(r"(?<=[。！？；;])\s*", text)
    text = next((part.strip() for part in parts if part.strip()), text)
    if len(text) > limit:
        text = text[: max(0, limit - 1)].rstrip("，,；;：:") + "…"
    return text


def _agent_decision_status_label(
    samples: list[dict[str, Any]] | None,
    *,
    completed: bool = False,
) -> str:
    """Show confirmation only when every displayed checkpoint sample is VALID."""
    if not samples:
        return "暂无结构化样例" if completed else "等待结构化结论"
    statuses: list[str] = []
    for sample in samples:
        validation = sample.get("程序校验")
        status = validation.get("分析状态") if isinstance(validation, dict) else ""
        status = str(status or "").strip().upper()
        if not status:
            return "阶段结果待复核"
        statuses.append(status)
    if statuses and all(status == "VALID" for status in statuses):
        return "已确认结论 · 程序校验通过"
    return "阶段结果待复核"


def _agent_decision_preview(
    samples: list[dict[str, Any]] | None,
    *,
    completed: bool = False,
) -> str:
    if not samples:
        return (
            '<div class="decision-empty"><span class="decision-scan"></span>'
            '<div><b>等待结构化结论</b><p>DST 阶段完成后，这里会实时出现模型已采用的判断与评级依据。</p>'
            '</div></div>'
        )
    high_risk_summary = _high_risk_decision_list(samples)
    if high_risk_summary:
        return high_risk_summary
    if completed:
        return (
            '<div class="decision-empty"><span class="decision-scan"></span>'
            '<div><b>暂无高风险资产</b>'
            '<p>本次分析中所有已确认风险值均小于 4，未发现达到高风险阈值的资产。</p>'
            '</div></div>'
        )
    sample = samples[0]
    asset = str(sample.get("资产", "—"))
    attribute = str(sample.get("安全属性", "—"))
    damage = str(sample.get("损害场景", ""))
    impact = sample.get("影响值/等级", {})
    impact_text = "待判断"
    if isinstance(impact, dict) and any(impact.values()):
        impact_text = " / ".join(
            str(value) for value in (impact.get("value"), impact.get("level"))
            if value not in (None, "")
        )
    else:
        rating = sample.get("影响评级", {})
        if isinstance(rating, dict):
            dimensions = [
                f"{key} {value}"
                for key, value in rating.items()
                if "reason" not in str(key).lower()
                and isinstance(value, (int, float, str))
                and str(value).strip()
            ]
            if dimensions:
                impact_text = " · ".join(dimensions[:4])
    risk = sample.get("风险", "待计算")
    stage = sample.get("当前完成阶段", "最终采用结果")
    reasons = sample.get("影响评级", {})
    reason = ""
    if isinstance(reasons, dict):
        reason = next(
            (
                str(value)
                for key, value in reasons.items()
                if "reason" in str(key).lower() and str(value).strip()
            ),
            "",
        )
    return (
        '<div class="decision-head"><span>STRUCTURED DECISION</span>'
        f'<em>{html.escape(str(stage))}</em></div>'
        f'<div class="decision-asset">{html.escape(asset)} <span>· {html.escape(attribute)}</span></div>'
        f'<div class="decision-text">{html.escape(_compact_ai_summary(damage, 120))}</div>'
        '<div class="decision-facts">'
        f'<div><small>影响判断</small><b>{html.escape(impact_text)}</b></div>'
        f'<div><small>风险值</small><b>{html.escape(str(risk))}</b></div></div>'
        + (
            f'<div class="decision-reason"><span>依据</span>{html.escape(reason)}</div>'
            if reason
            else ""
        )
    )


AGENT_COGNITIVE_PHASES = (
    ("perceive", "PERCEIVE", "感知输入"),
    ("plan", "PLAN", "规划任务"),
    ("act", "ACT", "调用工具"),
    ("verify", "VERIFY", "规则校验"),
    ("memory", "MEMORY", "写入记忆"),
    ("decide", "DECIDE", "形成决策"),
)


def _agent_activity_counts(lines: list[str]) -> dict[str, int]:
    """Derive auditable Agent activity counters from real runtime log lines."""
    counters = {
        "tool": 0,
        "validation": 0,
        "retry": 0,
        "cache": 0,
        "checkpoint": 0,
    }
    for raw_line in lines:
        line = raw_line.lower()
        if any(
            marker in line
            for marker in (
                "dfd解析",
                "拓扑",
                "攻击路径",
                "batch",
                "评级",
                "报告已生成",
                "report",
            )
        ):
            counters["tool"] += 1
        if any(
            marker in line
            for marker in (
                "校验",
                "验证",
                "不合格",
                "不匹配",
                "拒绝写回",
                "未完整覆盖",
            )
        ):
            counters["validation"] += 1
        if "重试" in line or "retry" in line:
            counters["retry"] += 1
        if "缓存" in line or "cache" in line:
            counters["cache"] += 1
        if "checkpoint" in line or "检查点" in line or "增量缓存" in line:
            counters["checkpoint"] += 1
    return counters


def _agent_cognitive_phase(
    lines: list[str],
    active_item: dict[str, str] | None,
    *,
    failed: bool,
    completed: bool,
) -> str:
    """Map the latest observable runtime event to an Agent loop phase."""
    if completed:
        return "decide"
    if failed:
        return "verify"
    for raw_line in reversed(lines):
        line = raw_line.lower()
        if any(
            marker in line
            for marker in (
                "重试",
                "校验失败",
                "验证失败",
                "不合格",
                "不匹配",
                "拒绝写回",
                "warning",
                "error",
            )
        ):
            return "verify"
        if any(marker in line for marker in ("checkpoint", "检查点", "增量缓存", "缓存命中")):
            return "memory"
        if any(marker in line for marker in ("报告已生成", "tara 完成", "风险矩阵", "最终报告")):
            return "decide"
        if any(marker in line for marker in ("模型调用", "llm http", "batch", "评级", "攻击路径")):
            return "act"
        if any(marker in line for marker in ("拓扑", "任务调度", "提交任务", "路径框架")):
            return "plan"
        if any(marker in line for marker in ("dfd", "任务单元", "解析输入")):
            return "perceive"
    return {
        "input": "perceive",
        "topology": "plan",
        "dst": "act",
        "impact": "act",
        "feasibility": "act",
        "report": "decide",
    }.get((active_item or {}).get("id", ""), "perceive")


def _agent_cognitive_loop_html(
    phase: str,
    *,
    visual_state: str,
    counts: dict[str, int],
) -> str:
    positions = {
        "perceive": (86, 120),
        "plan": (190, 42),
        "act": (340, 42),
        "verify": (494, 120),
        "memory": (340, 200),
        "decide": (190, 200),
    }
    phase_ids = [item[0] for item in AGENT_COGNITIVE_PHASES]
    active_index = phase_ids.index(phase) if phase in phase_ids else 0
    nodes: list[str] = []
    for index, (phase_id, label, subtitle) in enumerate(AGENT_COGNITIVE_PHASES):
        if visual_state == "idle":
            state = "pending"
        elif visual_state == "completed":
            state = "done active" if phase_id == "decide" else "done"
        elif phase_id == phase:
            state = "active"
        elif index < active_index:
            state = "done"
        else:
            state = "pending"
        x, y = positions[phase_id]
        nodes.append(
            f'<g class="cog-node {state}" data-phase="{phase_id}" '
            f'transform="translate({x} {y})">'
            '<circle r="30"></circle><circle class="cog-pulse" r="37"></circle>'
            f'<text class="cog-label" text-anchor="middle" y="-2">{label}</text>'
            f'<text class="cog-sub" text-anchor="middle" y="12">{html.escape(subtitle)}</text>'
            '</g>'
        )
    current_label = next(
        (subtitle for phase_id, _, subtitle in AGENT_COGNITIVE_PHASES if phase_id == phase),
        "等待任务",
    )
    return (
        '<div class="cognitive-panel">'
        '<div class="cognitive-head"><div><span>AGENT COGNITIVE LOOP</span>'
        '<small>真实事件驱动 · 非隐藏思维链</small></div>'
        f'<b>{html.escape(current_label)}</b></div>'
        '<div class="cognitive-map"><svg viewBox="0 0 580 242" role="img" '
        'aria-label="Agent 感知、规划、工具、校验、记忆和决策闭环">'
        '<defs><marker id="agent-arrow" markerWidth="7" markerHeight="7" refX="5" refY="3.5" orient="auto">'
        '<path d="M0,0 L0,7 L6,3.5 z"></path></marker></defs>'
        '<path class="cog-route" marker-end="url(#agent-arrow)" '
        'd="M112 97 C132 72 151 56 164 51 M220 42 L307 42 '
        'M371 54 C420 64 448 84 467 101 M467 140 C447 168 415 190 373 198 '
        'M307 200 L223 200 M165 190 C134 171 112 150 105 145"></path>'
        '<path class="cog-signal" d="M245 121 H332"></path>'
        f'{"".join(nodes)}'
        # Use absolute SVG coordinates for the center badge.  This avoids any
        # dependence on SVG group transforms, which some Gradio/browser CSS
        # combinations can override while the Agent is in the thinking state.
        '<g class="cog-brain"><g class="cog-brain-float">'
        '<rect x="250" y="97" width="78" height="48" rx="15"></rect>'
        '<text x="289" y="126" text-anchor="middle">AI</text></g></g></svg></div>'
        '<div class="activity-strip">'
        f'<span><small>TOOL EVENTS</small><b>{counts["tool"]}</b></span>'
        f'<span><small>VALIDATIONS</small><b>{counts["validation"]}</b></span>'
        f'<span><small>RETRIES</small><b>{counts["retry"]}</b></span>'
        f'<span><small>CACHE HITS</small><b>{counts["cache"]}</b></span>'
        f'<span><small>CHECKPOINTS</small><b>{counts["checkpoint"]}</b></span>'
        '</div></div>'
    )


def _agent_plan_html(
    snapshot: list[dict[str, str]],
    *,
    completed: bool,
) -> str:
    active_index = next(
        (index for index, item in enumerate(snapshot) if item["state"] in {"active", "error"}),
        None,
    )
    if completed:
        entries = (
            ("done", "已完成", "六阶段分析与报告交付"),
            ("done", "证据已固化", "结构化结果、日志与配置已落盘"),
            ("done", "可复核", "报告与运行 Trace 可用于审计"),
        )
    elif active_index is None:
        entries = (
            ("active", "等待任务", "上传输入并启动 AI TARA 分析"),
            ("pending", "下一步", snapshot[0]["title"]),
            ("pending", "最终目标", "生成可验证的风险报告"),
        )
    else:
        current = snapshot[active_index]
        previous = snapshot[active_index - 1]["title"] if active_index else "运行环境与输入准备"
        next_title = (
            snapshot[active_index + 1]["title"]
            if active_index + 1 < len(snapshot)
            else "风险报告交付"
        )
        entries = (
            ("done", "已完成", previous),
            ("active" if current["state"] == "active" else "error", "正在执行", current["title"]),
            ("pending", "下一步", next_title),
        )
    return (
        '<div class="agent-plan"><div class="agent-plan-title">CURRENT PLAN'
        '<small>Agent 根据阶段状态自动更新</small></div>'
        + "".join(
            f'<div class="plan-step {state}"><i></i><span><small>{html.escape(label)}</small>'
            f'<b>{html.escape(title)}</b></span></div>'
            for state, label, title in entries
        )
        + '</div>'
    )


def _agent_evidence_ledger_html(
    snapshot: list[dict[str, str]],
    *,
    model_calls: int,
    result_count: int,
    counts: dict[str, int],
) -> str:
    stage_state = {item["id"]: item["state"] for item in snapshot}
    facts = (
        ("DFD", stage_state.get("input", "pending"), "任务空间"),
        ("GRAPH", stage_state.get("topology", "pending"), "可信拓扑"),
        ("MODEL", "done" if model_calls else "pending", f"{model_calls} 响应"),
        ("VERIFY", "done" if counts["validation"] else "pending", f'{counts["validation"]} 事件'),
        ("MEMORY", "done" if counts["checkpoint"] or counts["cache"] else "pending", f'{counts["checkpoint"]} 检查点'),
        ("ADOPT", "done" if result_count else "pending", f"{result_count} 结果"),
    )
    return (
        '<div class="evidence-ledger"><div class="ledger-title">EVIDENCE LEDGER'
        '<small>每项均来自运行事实</small></div><div class="ledger-grid">'
        + "".join(
            f'<span class="ledger-item {html.escape(state)}"><i></i><b>{label}</b><small>{html.escape(value)}</small></span>'
            for label, state, value in facts
        )
        + '</div></div>'
    )


def _usage_number(usage: dict[str, Any] | None, key: str) -> int:
    try:
        return int((usage or {}).get(key, 0) or 0)
    except (TypeError, ValueError):
        return 0


def _stage_usage(
    stage_id: str,
    usage: dict[str, Any] | None,
) -> tuple[int, int, bool]:
    by_stage = (usage or {}).get("by_stage", {})
    if not isinstance(by_stage, dict):
        return 0, 0, False
    requests = 0
    tokens = 0
    token_available = False
    for key in TRACE_STAGE_USAGE_KEYS.get(stage_id, ()):
        item = by_stage.get(key, {})
        if not isinstance(item, dict):
            continue
        try:
            requests += int(item.get("requests", 0) or 0)
            tokens += int(item.get("total_tokens", 0) or 0)
            token_available = token_available or bool(item.get("token_available", True))
        except (TypeError, ValueError):
            continue
    return requests, tokens, token_available


def _agent_trace_html(
    snapshot: list[dict[str, str]],
    usage: dict[str, Any] | None,
    percentage: int = 0,
) -> str:
    spans: list[str] = []
    for item in snapshot:
        stage_id = item["id"]
        requests, tokens, token_available = _stage_usage(stage_id, usage)
        if requests:
            detail = (
                f"{requests} 次调用 · {_format_count(tokens)} tokens"
                if token_available else f"{requests} 次调用 · Token 见总量"
            )
        elif TRACE_STAGE_USAGE_KEYS.get(stage_id):
            detail = {
                "pending": "等待模型调用",
                "active": "正在调用模型",
                "done": "模型输出已采用",
                "error": "调用异常 · 已保留现场",
            }.get(item["state"], "等待模型调用")
        else:
            detail = "程序处理 · 无模型调用"
        spans.append(
            f'<button type="button" class="trace-span {html.escape(item["state"])}" data-workspace-stage="{html.escape(stage_id)}" title="查看阶段过程证据">'
            f'<small>SPAN {html.escape(item["number"])} · '
            f'{html.escape(TRACE_STAGE_RUNTIME.get(stage_id, "RUNTIME"))}</small>'
            f'<b>{html.escape(item["title"])}</b>'
            f'<em>{html.escape(detail)}</em></button>'
        )
    bounded_percentage = max(0, min(100, int(percentage or 0)))
    return (
        '<div class="agent-trace"><div class="trace-title">'
        '<span>AI EXECUTION TRACE</span>'
        f'<div class="trace-progress"><b>{bounded_percentage}%</b>'
        '<span>WORKFLOW PROGRESS</span>'
        f'<i><em style="width:{bounded_percentage}%"></em></i></div>'
        '<small>阶段调用 · 工具执行 · 规则校验</small></div>'
        f'<div class="trace-rail">{"".join(spans)}</div></div>'
    )


def _trust_strip_html() -> str:
    return (
        '<div class="trust-strip">'
        '<span class="trust-pill">DFD 语义锚定</span>'
        '<span class="trust-pill">拓扑路径约束</span>'
        '<span class="trust-pill">外部接口白名单</span>'
        '<span class="trust-pill">JSON Schema 校验</span>'
        '<span class="trust-pill">风险矩阵代码计算</span>'
        '</div>'
    )


def _agent_workspace_html(
    lines: list[str],
    snapshot: list[dict[str, str]],
    *,
    failed: bool,
    completed: bool,
    samples: list[dict[str, Any]] | None,
    model: str = "",
    job_id: str = "",
    llm_usage: dict[str, Any] | None = None,
    elapsed_seconds: int = 0,
    percentage: int = 0,
    api_base: str = API_BASE,
    report_metrics: dict[str, Any] | None = None,
) -> str:
    active_item = next(
        (item for item in snapshot if item["state"] in {"active", "error"}), None
    )
    if completed:
        visual_state = "completed"
        headline = "分析闭环已完成"
        reasoning = "本次分析已结束，风险报告已生成，可继续核对未评级结果与人工复核项。"
        state_label = "MISSION COMPLETE"
    elif failed:
        visual_state = "failed"
        headline = "Agent 已暂停并保留现场"
        reasoning = "当前阶段未能满足输入或输出约束；日志与已完成检查点仍可用于定位。"
        state_label = "NEEDS ATTENTION"
    elif active_item:
        visual_state = "thinking"
        headline, reasoning = AGENT_STAGE_COPY[active_item["id"]]
        state_label = "REASONING"
    else:
        visual_state = "idle"
        headline = "等待接收 TARA 分析任务"
        reasoning = "上传项目输入并选择评级策略后，Agent 将自主调用六阶段分析工具。"
        state_label = "STANDBY"
    latest = "尚未产生运行事件"
    all_evidence = _evidence(lines, limit=10000)
    evidence = all_evidence[-1:]
    if evidence:
        latest = _clean_event_line(evidence[-1])[1]
    active_stage = (
        active_item["number"]
        if active_item
        else ("06" if completed else "00")
    )
    model_calls = _usage_number(llm_usage, "http_requests")
    total_tokens = _usage_number(llm_usage, "total_tokens")
    activity_counts = _agent_activity_counts(lines)
    decision_status = _agent_decision_status_label(samples, completed=completed)
    cognitive_phase = _agent_cognitive_phase(
        lines,
        active_item,
        failed=failed,
        completed=completed,
    )
    high_risk_count = sum(
        sum(1 for value in sample["风险值列表"] if (_risk_score(value) or 0) >= 4)
        if isinstance(sample.get("风险值列表"), list)
        else int((_risk_score(sample.get("风险", sample.get("风险值"))) or 0) >= 4)
        for sample in (samples or [])
    )
    if report_metrics and isinstance(report_metrics.get("high_risk"), int):
        high_risk_count = report_metrics["high_risk"]
    result_count = len(samples or [])
    elapsed_label = (
        f"{elapsed_seconds // 60:02d}:{elapsed_seconds % 60:02d}"
        if elapsed_seconds else "00:00"
    )
    telemetry = (
        '<div class="agent-telemetry">'
        f'<div><small>当前阶段</small><b>{html.escape(active_stage)} / 06</b></div>'
        f'<div><small>MODEL CALLS</small><b class="telemetry-live">{_format_count(model_calls)}</b></div>'
        f'<div><small>TOTAL TOKENS</small><b class="telemetry-live">{_format_count(total_tokens)}</b></div>'
        f'<div><small>运行时间</small><b>{html.escape(elapsed_label)}</b></div>'
        f'<div><small title="当前已确认风险值大于等于 4 的攻击路径数量">高风险路径</small><b>{high_risk_count}</b></div>'
        '</div>'
    )
    runtime_id = job_id or "等待创建 Trace"
    model_label = model or "LOCAL MODEL"
    from automotive_tara.demo_dashboard import risk_distribution
    side_panel = (
        '<aside class="ws-execution-side" hidden><section class="ws-widget">'
        '<div class="ws-widget-heading"><h2>本次运行</h2>'
        f'<span class="ws-status {"completed" if completed else "failed" if failed else "running" if active_item else "queued"}">'
        f'{"已完成" if completed else "需处理" if failed else "分析中" if active_item else "待启动"}</span></div>'
        '<div class="ws-service-model"><small>当前任务模型</small>'
        f'<b>{html.escape(model or "启动分析后显示")}</b></div>'
        f'<div class="ws-run-id"><small>任务 ID</small><code>{html.escape(job_id or "尚未创建任务")}</code></div></section>'
        '<section class="ws-widget"><div class="ws-widget-heading"><div><h2>风险等级分布</h2>'
        '<p>按本任务报告的攻击路径统计</p></div></div>'
        + risk_distribution(report_metrics or {}) + '</section></aside>'
    )
    return (
        f'<div class="agent-workbench {visual_state}">'
        '<div class="agent-toolbar"><div class="runtime-ident" aria-label="AI AGENT CONSOLE"><span class="live-dot"></span>'
        f'TARA AGENT RUNTIME <b>{html.escape(state_label)}</b>'
        f'<code>TRACE · {html.escape(runtime_id)}</code></div>'
        f'<span class="private-badge">{html.escape(model_label)} · API {html.escape(api_base or API_BASE)} · AUDITABLE</span></div>'
        f'{telemetry}'
        '<div class="ws-execution-layout"><div class="ws-execution-main">'
        f'{_agent_trace_html(snapshot, llm_usage, percentage)}'
        '<div class="agent-current-summary"><span>当前状态</span>'
        f'<h3>{html.escape(headline)}</h3><p>{html.escape(reasoning)}</p></div>'
        f'</div>{side_panel}</div>'
        '<details class="execution-details"><summary>查看分析机制与过程证据</summary>'
        '<div class="agent-command-grid">'
        f'{_agent_cognitive_loop_html(cognitive_phase, visual_state=visual_state, counts=activity_counts)}'
        '<div class="agent-focus"><div class="reasoning-card">'
        '<div class="agent-eyebrow">CURRENT REASONING SUMMARY</div>'
        f'<h3>{html.escape(headline)}</h3><p>{html.escape(reasoning)}</p>'
        f'<div class="latest-signal"><i></i><span>{html.escape(latest[:230])}</span>'
        '<b class="thinking-dots"><i></i><i></i><i></i></b></div></div>'
        f'{_agent_plan_html(snapshot, completed=completed)}'
        '</div></div>'
        '<div class="agent-capability-row">'
        f'{_agent_evidence_ledger_html(snapshot, model_calls=model_calls, result_count=result_count, counts=activity_counts)}'
        f'<div class="guardrail-box"><span>POLICY GUARDRAILS</span>{_trust_strip_html()}</div>'
        '</div>'
        '</details>'
        '<div class="agent-lower"><div class="agent-stream">'
        '<div class="agent-column-title"><span>AI Agent 动态</span><em>实时能力调用 · 历史事件持续保留</em></div>'
        f'{_agent_event_stream(lines)}</div><div class="agent-decision">'
        '<div class="agent-column-title"><span>AI 当前结论</span>'
        f'<em>{html.escape(decision_status)}</em></div>'
        f'{_agent_decision_preview(samples, completed=completed)}</div></div>'
        '<div class="agent-disclaimer">展示的是由真实日志、检查点与结构化输出形成的可审计推理摘要，'
        '不展示模型私有隐藏思维链。</div></div>'
    )


def timeline_html(
    lines: list[str], *, failed: bool = False, completed: bool = False,
    samples: list[dict[str, Any]] | None = None,
    model: str = "",
    job_id: str = "",
    llm_usage: dict[str, Any] | None = None,
    elapsed_seconds: int = 0,
    api_base: str = API_BASE,
    report_metrics: dict[str, Any] | None = None,
) -> str:
    snapshot = _stage_snapshot(lines, failed=failed, completed=completed)
    done = sum(item["state"] == "done" for item in snapshot)
    active = any(item["state"] == "active" for item in snapshot)
    percentage = round((done + (0.35 if active else 0)) / len(snapshot) * 100)
    workspace = _agent_workspace_html(
        lines,
        snapshot,
        failed=failed,
        completed=completed,
        samples=samples,
        model=model,
        job_id=job_id,
        llm_usage=llm_usage,
        elapsed_seconds=elapsed_seconds,
        percentage=percentage,
        api_base=api_base,
        report_metrics=report_metrics,
    )
    return workspace


def _evidence(lines: Iterable[str], limit: int = 36) -> list[str]:
    selected = [
        line.strip()
        for line in lines
        if any(marker in line for marker in EVIDENCE_MARKERS)
    ]
    return selected[-limit:]


def trace_payload(
    *,
    job_id: str,
    model: str,
    impact_method: str,
    feasibility_method: str,
    enable_reason: bool,
    enable_rag: bool,
    lines: list[str],
    dfd_format: str = "auto",
    failed: bool = False,
    completed: bool = False,
    sample_judgements: list[dict[str, Any]] | None = None,
    llm_usage: dict[str, Any] | None = None,
    api_base: str = API_BASE,
) -> dict[str, Any]:
    call_stats = dict(llm_usage) if isinstance(llm_usage, dict) else {
        "状态": "运行中，最终统计将在任务完成后写入 run_manifest.json"
    }
    call_stats.setdefault("api_base", api_base or API_BASE)
    return {
        "展示说明": (
            "此处展示可审计的AI工作流、结构化结论、评级理由与校验事件；"
            "不展示模型私有隐藏思维链。"
        ),
        "运行配置": {
            "job_id": job_id,
            "model": model,
            "impact_method": impact_method,
            "feasibility_method": feasibility_method,
            "rating_reasons": enable_reason,
            "rag": enable_rag,
            "dfd_format": dfd_format,
        },
        "Agent能力编排": [
            {"能力": "项目感知", "执行者": "DFD Parser", "类型": "本地工具"},
            {"能力": "攻击面建模", "执行者": "Topology Graph", "类型": "可信图算法"},
            {"能力": "损害与威胁推演", "执行者": "Scenario Generator", "类型": "LLM"},
            {"能力": "攻击动作与影响判断", "执行者": "Impact & Path Agent", "类型": "LLM + 可信路径绑定"},
            {"能力": "攻击可行性判断", "执行者": "Feasibility Agent", "类型": "LLM + 规则引擎"},
            {"能力": "风险合成与交付", "执行者": "Risk Engine", "类型": "确定性代码"},
        ],
        "可信AI约束": {
            "输入事实源": ["DFD", "拓扑图", "外部接口白名单"],
            "输出约束": ["JSON Schema", "ID/数量匹配", "拓扑顺序", "离散评分值域"],
            "最终风险": "由代码风险矩阵计算，不由模型自由生成",
        },
        "AI调用统计": call_stats,
        "AI工作流": _stage_snapshot(
            lines, failed=failed, completed=completed
        ),
        "实时校验与决策事件": _evidence(lines),
        "结构化判断样例": sample_judgements or [],
    }


def _copy_inputs(
    job_root: Path,
    dfd_files: Any,
    topology_file: Any,
    interfaces_file: Any,
) -> tuple[Path, Path, Path]:
    dfd_paths = _paths(dfd_files)
    topology_paths = _paths(topology_file)
    interface_paths = _paths(interfaces_file)
    if not dfd_paths or len(topology_paths) != 1 or len(interface_paths) != 1:
        raise ValueError("输入文件不完整，请先完成三个上传区域")
    validation = validate_inputs_html(
        dfd_paths, topology_paths[0], interface_paths[0]
    )
    if "input-warn" in validation:
        raise ValueError(re.sub(r"<[^>]+>", " ", validation))

    input_root = job_root / "input"
    dfd_root = input_root / "DFD"
    dfd_root.mkdir(parents=True, exist_ok=False)
    seen: Counter[str] = Counter()
    for index, source in enumerate(dfd_paths, start=1):
        name = _safe_filename(source.name, f"dfd_{index}.json")
        seen[name] += 1
        if seen[name] > 1:
            name = f"{Path(name).stem}_{seen[name]}{Path(name).suffix}"
        shutil.copy2(source, dfd_root / name)
    topology_target = input_root / _safe_filename(
        topology_paths[0].name, "topology.json"
    )
    interfaces_target = input_root / _safe_filename(
        interface_paths[0].name, "external_interfaces.xlsx"
    )
    shutil.copy2(topology_paths[0], topology_target)
    shutil.copy2(interface_paths[0], interfaces_target)
    return dfd_root, topology_target, interfaces_target


def edit_uploaded_inputs(
    dfd_files: Any,
    topology_file: Any,
    interfaces_file: Any,
    instruction: str,
    selected_model: str | None,
    api_base: str = API_BASE,
    api_key: str = "",
    external_model_name: str = "",
) -> tuple[Any, Any, Any, str, dict[str, Any], Any]:
    """Apply a natural-language edit to isolated copies of the three uploads.

    The returned file values are deliberately new paths under ``DEMO_ROOT``;
    the browser's original upload cache is never changed in place.
    """
    original_dfd = _paths(dfd_files)
    original_topology = _paths(topology_file)
    original_interfaces = _paths(interfaces_file)
    unchanged = (gr.update(), gr.update(), gr.update())
    try:
        if not original_dfd or len(original_topology) != 1 or len(original_interfaces) != 1:
            raise DataEditError("请先上传 DFD、拓扑图和外部接口 Excel")
        # The service's advertised model is authoritative after a model switch;
        # the dropdown is only a fallback while the health endpoint is settling.
        api_base, api_key, explicit_model = require_api()
        model = explicit_model or str(
            _discover_model_for_api(api_base, api_key) or selected_model or ""
        ).strip()
        dfd_copy, topology_copy, interfaces_copy, trace = edit_project_inputs(
            original_dfd,
            original_topology[0],
            original_interfaces[0],
            instruction,
            model=model,
            api_base=api_base,
            api_key=api_key,
            editor_root=DEMO_ROOT / "input_editor",
        )
        if int(trace.get("操作数", 0) or 0) > 0:
            status = (
                '<div class="input-ok"><b>输入数据已按要求修改</b><br>'
                '修改写入隔离副本，原始上传文件未改变；请检查摘要后再启动分析。</div>'
            )
        else:
            status = (
                '<div class="input-warn"><b>模型未提出可执行修改</b><br>'
                '当前输入保持不变；请补充更明确的文件、对象或字段。</div>'
            )
        return (
            gr.update(value=[str(path) for path in dfd_copy]),
            gr.update(value=str(topology_copy)),
            gr.update(value=str(interfaces_copy)),
            status,
            trace,
            validate_inputs_html(dfd_copy, topology_copy, interfaces_copy),
        )
    except Exception as exc:
        logger.exception("项目输入 Agent 修改失败")
        return (
            *unchanged,
            '<div class="input-warn"><b>修改未应用</b><br>'
            + html.escape(str(exc))
            + "</div>",
            {"状态": "失败", "错误": str(exc)},
            gr.update(),
        )


def preview_uploaded_inputs(
    dfd_files: Any,
    topology_file: Any,
    interfaces_file: Any,
    instruction: str,
    selected_model: str | None,
    api_base: str = API_BASE,
    api_key: str = "",
    external_model_name: str = "",
) -> tuple[Any, ...]:
    """Generate an auditable plan only; no uploaded file is modified."""
    try:
        original_dfd = _paths(dfd_files)
        original_topology = _paths(topology_file)
        original_interfaces = _paths(interfaces_file)
        if not original_dfd or len(original_topology) != 1 or len(original_interfaces) != 1:
            raise DataEditError("请先上传 DFD、拓扑图和外部接口 Excel")
        api_base, api_key, explicit_model = require_api()
        model = explicit_model or str(
            _discover_model_for_api(api_base, api_key) or selected_model or ""
        ).strip()
        plan = prepare_edit_plan(
            original_dfd, original_topology[0], original_interfaces[0], instruction,
            model=model, api_base=api_base, api_key=api_key,
        )
        impact = plan.get("dependency_impact", {})
        operations = plan.get("operations", [])
        status = (
            '<div class="input-ok"><b>已生成修改计划，等待确认</b><br>'
            f'直接操作 {len(operations)} 项 · 可能影响 {len(impact.get("cascade", []))} 项 · '
            '原始输入尚未改变。</div>'
        ) if operations else '<div class="input-warn"><b>未生成可执行操作</b><br>请补充明确对象和文件。</div>'
        return status, plan, _dependency_impact_html(plan), _editor_workflow_html(plan), gr.update()
    except Exception as exc:
        logger.exception("项目输入 Agent 生成计划失败")
        failed_plan = {"状态": "失败", "错误": str(exc)}
        return '<div class="input-warn"><b>计划生成失败</b><br>' + html.escape(str(exc)) + '</div>', failed_plan, '<div class="download-note">没有可展示的级联影响。</div>', _editor_workflow_html(failed_plan), gr.update()


def preview_uploaded_inputs_for_ui(*args: Any) -> tuple[Any, ...]:
    """Keep the authoritative pending plan in session state, not a JSON widget."""
    result = preview_uploaded_inputs(*args)
    return (*result, result[1])


def confirm_uploaded_inputs(
    dfd_files: Any,
    topology_file: Any,
    interfaces_file: Any,
    plan: Any,
) -> tuple[Any, ...]:
    """Apply a previously previewed plan after explicit user confirmation."""
    unchanged = (gr.update(), gr.update(), gr.update())
    try:
        original_dfd = _paths(dfd_files)
        original_topology = _paths(topology_file)
        original_interfaces = _paths(interfaces_file)
        if not original_dfd or len(original_topology) != 1 or len(original_interfaces) != 1:
            raise DataEditError("请先上传 DFD、拓扑图和外部接口 Excel")
        if not isinstance(plan, dict) or not plan.get("operations"):
            raise DataEditError("没有待确认的修改计划")
        dfd_copy, topology_copy, interfaces_copy, trace = apply_confirmed_edit_plan(
            plan, dfd_paths=original_dfd, topology_path=original_topology[0],
            interfaces_path=original_interfaces[0], editor_root=DEMO_ROOT / "input_editor",
            confirmed=True, expected_plan_id=str(plan.get("plan_id") or "") or None,
        )
        consistency = trace.get("修改后一致性校验", {}) if isinstance(trace, dict) else {}
        if isinstance(consistency, dict) and consistency.get("valid", False):
            status = '<div class="input-ok"><b>修改已确认并应用</b><br>只写入隔离副本；一致性校验通过，可继续启动分析。</div>'
        else:
            errors = consistency.get("errors", []) if isinstance(consistency, dict) else []
            detail = "；".join(str(item) for item in errors[:3])
            status = '<div class="input-warn"><b>修改已写入隔离副本，但未通过一致性校验</b><br>请修复悬空关系后再启动分析。' + html.escape(detail) + '</div>'
        verified = isinstance(consistency, dict) and consistency.get("valid", False)
        workflow = dict(plan.get("agent_workflow") or {})
        workflow["state"] = "complete" if verified else "verification_failed"
        workflow["events"] = [
            {**event, "status": "done", "detail": "用户已确认修改"}
            if event.get("phase") == "await_confirmation" else dict(event)
            for event in workflow.get("events", []) if isinstance(event, dict)
        ] + [
            {"phase": "apply", "status": "done", "detail": "已写入隔离副本；原始输入未改变"},
            {"phase": "verify", "status": "done" if verified else "failed",
             "detail": "一致性校验通过" if verified else "一致性校验未通过，请查看错误"},
        ]
        return (
            gr.update(value=[str(path) for path in dfd_copy]),
            gr.update(value=str(topology_copy)),
            gr.update(value=str(interfaces_copy)),
            status,
            trace,
            _dependency_impact_html(plan),
            _editor_workflow_html({**plan, "agent_workflow": workflow}),
            validate_inputs_html(dfd_copy, topology_copy, interfaces_copy),
        )
    except Exception as exc:
        logger.exception("项目输入 Agent 应用计划失败")
        failed_plan = plan if isinstance(plan, dict) else {"状态": "失败"}
        return (*unchanged, '<div class="input-warn"><b>修改未应用</b><br>' + html.escape(str(exc)) + '</div>', failed_plan, _dependency_impact_html(failed_plan), _editor_workflow_html(failed_plan), gr.update())


def _dependency_impact_html(plan: Any) -> str:
    impact = plan.get("dependency_impact", {}) if isinstance(plan, dict) else {}
    direct = impact.get("direct", []) if isinstance(impact, dict) else []
    cascade = impact.get("cascade", []) if isinstance(impact, dict) else []
    cascade_operations = impact.get("cascade_operations", []) if isinstance(impact, dict) else []
    warnings = impact.get("warnings", []) if isinstance(impact, dict) else []
    confidence = str(impact.get("confidence", "")) if isinstance(impact, dict) else ""
    if not direct and not cascade:
        return '<div class="download-note">等待 Agent 生成依赖分析。</div>'
    direct_rows = "".join(
        f'<li><b>{html.escape(str(item.get("op", "操作")))}</b> · {html.escape(str(item.get("object", "")))}</li>'
        for item in direct if isinstance(item, dict)
    )
    cascade_rows = "".join(
        f'<li><b>{html.escape(str(item.get("kind", "关联对象")))}</b> · {html.escape(str(item.get("object", "")))}：{html.escape(str(item.get("effect", "需校验")))}</li>'
        for item in cascade[:30] if isinstance(item, dict)
    )
    if cascade_operations:
        cascade_rows += "".join(
            f'<li><b>同步操作</b> · {html.escape(str(item.get("target", "")))} / {html.escape(str(item.get("op", "")))}：{html.escape(str(item.get("old", "")))} → {html.escape(str(item.get("new", "")))}</li>'
            for item in cascade_operations if isinstance(item, dict)
        )
    warning_html = ""
    if warnings:
        warning_html = '<div class="input-warn"><b>需要人工确认的歧义</b><ul>' + "".join(
            f'<li>{html.escape(str(item))}</li>' for item in warnings[:12]
        ) + "</ul></div>"
    confidence_label = {"high": "高", "medium": "中", "low": "低"}.get(confidence, "待评估")
    return (
        '<div class="agent-impact-preview">'
        f'<div class="agent-confidence">计划置信度：<b>{confidence_label}</b></div>'
        + warning_html + '<b>直接操作</b><ul>' + (direct_rows or '<li>无</li>') +
        '</ul><b>可能的级联影响（确认后执行）</b><ul>' + (cascade_rows or '<li>无</li>') +
        '</ul><small>报告任务、攻击路径和风险值只标记为需重算，不会静默删除。</small></div>'
    )


def _editor_workflow_html(plan: Any) -> str:
    """Render the input Agent's typed tool workflow as a compact timeline."""
    workflow = plan.get("agent_workflow", {}) if isinstance(plan, dict) else {}
    events = workflow.get("events", []) if isinstance(workflow, dict) else []
    if not events:
        return '<div class="editor-workflow"><span class="editor-workflow-title">AGENT WORKFLOW</span><span class="editor-workflow-empty">等待生成计划</span></div>'
    state = str(workflow.get("state") or "await_confirmation")
    state_class = "failed" if state in {"failed", "verification_failed"} else (
        "complete" if state == "complete" else ""
    )
    rows = "".join(
        '<span class="editor-workflow-step ' + html.escape(str(event.get("status") or "")) + '">'
        '<i></i><b>' + html.escape(str(event.get("phase") or "")) + '</b>'
        '<small>' + html.escape(str(event.get("detail") or "")) + '</small></span>'
        for event in events if isinstance(event, dict)
    )
    return (
        '<div class="editor-workflow"><div class="editor-workflow-head">'
        '<span>AGENT WORKFLOW</span><small class="' + state_class + '">state: ' + html.escape(state) + '</small></div>'
        '<div class="editor-workflow-steps">' + rows + '</div></div>'
    )


def _reader_thread(stream: Any, target: queue.Queue[str | None]) -> None:
    try:
        for line in iter(stream.readline, ""):
            target.put(line.rstrip("\n"))
    finally:
        target.put(None)


def _latest_manifest(result_root: Path) -> Path | None:
    manifests = list(result_root.rglob("run_manifest.json"))
    return max(manifests, key=lambda path: path.stat().st_mtime_ns) if manifests else None


def _load_json(path: Path | str | None, default: Any) -> Any:
    if not path:
        return default
    try:
        with Path(path).open("r", encoding="utf-8") as source:
            return json.load(source)
    except Exception:
        return default


def _new_live_usage_state() -> dict[str, Any]:
    """Create incremental state for reading the live LLM audit stream."""
    return {
        "path": "",
        "offset": 0,
        "usage": {
            "http_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "retry_requests": 0,
            "http_seconds": 0.0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            **{key: 0 for key in PROMPT_CACHE_METRIC_KEYS},
        },
        "by_stage": {},
    }


def _update_live_llm_usage(
    result_root: Path,
    state: dict[str, Any],
) -> dict[str, Any]:
    """Incrementally consume ``llm_calls.jsonl`` while an analysis is running."""
    path_text = str(state.get("path") or "")
    calls_path = Path(path_text) if path_text else None
    if state.get("live_snapshot") and calls_path is not None and calls_path.is_file():
        # Prefer the richer audit stream as soon as it appears (audit capture
        # starts its writer thread after the first runtime initialization).
        audit_matches = list(result_root.rglob("training/llm_calls.jsonl"))
        if audit_matches:
            calls_path = max(audit_matches, key=lambda path: path.stat().st_mtime_ns)
            state["path"] = str(calls_path)
            state["offset"] = 0
            state.pop("live_snapshot", None)
        else:
            payload = _load_json(calls_path, {})
            live_usage = payload.get("llm", payload) if isinstance(payload, dict) else {}
            if isinstance(live_usage, dict):
                return {
                    **dict(state.get("usage", {})),
                    **{key: value for key, value in live_usage.items() if key in state.get("usage", {})},
                    "by_stage": dict(state.get("by_stage", {})),
                    "live": True,
                }
    if calls_path is None or not calls_path.is_file():
        matches = list(result_root.rglob("training/llm_calls.jsonl"))
        calls_path = max(matches, key=lambda path: path.stat().st_mtime_ns) if matches else None
        if calls_path is None:
            # Audit capture is optional.  The pipeline still writes a
            # prompt-free, throttled usage snapshot so the live workbench can
            # display real API activity without exposing request content.
            live_matches = list(result_root.rglob("llm_usage_live.json"))
            live_path = max(live_matches, key=lambda path: path.stat().st_mtime_ns) if live_matches else None
            if live_path is not None:
                payload = _load_json(live_path, {})
                live_usage = payload.get("llm", payload) if isinstance(payload, dict) else {}
                if isinstance(live_usage, dict):
                    state["path"] = str(live_path)
                    state["live_snapshot"] = True
                    return {
                        **dict(state.get("usage", {})),
                        **{key: value for key, value in live_usage.items() if key in state.get("usage", {})},
                        "by_stage": dict(state.get("by_stage", {})),
                        "live": True,
                    }
            return {
                **dict(state.get("usage", {})),
                "by_stage": dict(state.get("by_stage", {})),
                "live": False,
            }
        state["path"] = str(calls_path)
        state["offset"] = 0
        state.pop("live_snapshot", None)

    try:
        file_size = calls_path.stat().st_size
        if file_size < int(state.get("offset", 0) or 0):
            reset = _new_live_usage_state()
            reset["path"] = str(calls_path)
            state.clear()
            state.update(reset)
        with calls_path.open("r", encoding="utf-8") as source:
            source.seek(int(state.get("offset", 0) or 0))
            for line in source:
                try:
                    record = json.loads(line)
                except (TypeError, ValueError, json.JSONDecodeError):
                    continue
                if not isinstance(record, dict):
                    continue
                usage = state["usage"]
                usage["http_requests"] += 1
                status = str(record.get("status") or "")
                if status == "success":
                    usage["successful_requests"] += 1
                else:
                    usage["failed_requests"] += 1
                try:
                    if int(record.get("attempt", 1) or 1) > 1:
                        usage["retry_requests"] += 1
                except (TypeError, ValueError):
                    pass
                try:
                    usage["http_seconds"] += float(record.get("elapsed_seconds", 0) or 0)
                except (TypeError, ValueError):
                    pass
                call_usage = record.get("usage", {})
                if not isinstance(call_usage, dict):
                    call_usage = {}
                stage = str(record.get("stage") or "unknown").strip() or "unknown"
                stage_usage = state["by_stage"].setdefault(
                    stage,
                    {"requests": 0, "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                )
                stage_usage["requests"] += 1
                for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
                    try:
                        value = int(call_usage.get(key, 0) or 0)
                    except (TypeError, ValueError):
                        value = 0
                    usage[key] += value
                    stage_usage[key] += value
                for key, value in extract_prompt_cache_usage(call_usage).items():
                    usage[key] = usage.get(key, 0) + value
                    stage_usage[key] = stage_usage.get(key, 0) + value
            state["offset"] = source.tell()
    except OSError:
        pass
    return {
        **dict(state.get("usage", {})),
        "http_seconds": round(float(state.get("usage", {}).get("http_seconds", 0) or 0), 3),
        "by_stage": {
            key: dict(value) for key, value in state.get("by_stage", {}).items()
        },
        "live": True,
    }


def _checkpoint_samples(
    result_root: Path,
    previous_signature: tuple[str, int, int] | None = None,
    previous_samples: list[dict[str, Any]] | None = None,
) -> tuple[tuple[str, int, int] | None, list[dict[str, Any]]]:
    """Read a checkpoint once per stage and expose adopted structured evidence."""
    checkpoint: Path | None = None
    stage_name = ""
    for filename, label in (
        ("tasks_after_stageC.json", "可行性与风险"),
        ("tasks_after_stageAB.json", "攻击路径与影响评级"),
        ("tasks_after_stageDST.json", "损害与威胁场景"),
    ):
        matches = list(result_root.rglob(f".checkpoints/{filename}"))
        if matches:
            checkpoint = max(matches, key=lambda path: path.stat().st_mtime_ns)
            stage_name = label
            break
    if checkpoint is None:
        return previous_signature, previous_samples or []
    stat = checkpoint.stat()
    signature = (str(checkpoint), stat.st_mtime_ns, stat.st_size)
    if signature == previous_signature:
        return signature, previous_samples or []

    payload = _load_json(checkpoint, {})
    tasks = payload.get("tasks", []) if isinstance(payload, dict) else []
    samples: list[dict[str, Any]] = []
    high_risk_samples: list[dict[str, Any]] = []
    for task in tasks:
        if not isinstance(task, dict) or not task.get("damage_scenario"):
            continue
        attacks = task.get("attack_details", []) or []
        first_attack = attacks[0] if attacks else {}
        risk_values = [
            attack.get("risk_value", "")
            for attack in attacks
            if attack.get("risk_value", "") not in (None, "")
        ]
        task_risk = task.get("risk_value", "")
        risk_candidates = risk_values or [task_risk]
        best_risk = max(risk_candidates, key=lambda value: _risk_score(value) or -1)
        sample = {
            "当前完成阶段": stage_name,
            "任务ID": task.get("task_id", ""),
            "功能": task.get("function", ""),
            "元素编号": task.get("element_index", ""),
            "资产": task.get("asset_name", ""),
            "安全属性": task.get("attribute_name", ""),
            "损害场景": task.get("damage_scenario", ""),
            "威胁场景": task.get("threat_scenarios", ""),
            "影响评级": task.get("influence_parameters", {}),
            "影响值/等级": {
                "value": task.get("impact_value", ""),
                "level": task.get("impact_level", ""),
            },
            "攻击路径": (
                first_attack.get("attack_path", "")
                or next(iter(task.get("attack_paths", []) or []), "")
            ),
            "可行性评级": first_attack.get("attack_parameters", {}),
            "可行性等级": first_attack.get("feasibility_level", ""),
            "风险": best_risk,
            "风险值列表": risk_values,
            "程序校验": {
                "分析状态": task.get("analysis_status", ""),
                "状态原因": task.get("status_reasons", []),
                "输入映射冲突": task.get("input_mapping_conflicts", []),
                "低置信度标记": task.get("low_confidence_flags", []),
            },
        }
        score = _risk_score(best_risk)
        if score is not None and score >= 4:
            high_risk_samples.append(sample)
        elif len(samples) < 5:
            samples.append(sample)
    return signature, high_risk_samples or samples


def _reason_text(parameters: dict[str, Any]) -> str:
    return "；".join(
        str(value).strip()
        for key, value in parameters.items()
        if ("reason" in str(key).lower() or "理由" in str(key))
        and str(value).strip()
    )


def _format_count(value: Any) -> str:
    """Format a numeric usage value for compact customer-facing display."""
    try:
        return f"{int(value or 0):,}"
    except (TypeError, ValueError):
        return "0"


def _llm_usage_details(manifest: dict[str, Any] | None) -> tuple[dict[str, Any], dict[str, dict[str, int]]]:
    """Read the run's authoritative LLM usage and optional per-stage usage.

    The pipeline writes aggregate usage to ``run_manifest.json`` for every run.
    Per-stage totals are only available when the user enabled audit capture, so
    they are best-effort and never replace the aggregate values.
    """
    manifest = manifest if isinstance(manifest, dict) else {}
    raw = manifest.get("llm", {})
    usage = raw if isinstance(raw, dict) else {}
    normalized: dict[str, Any] = {
        key: usage.get(key, 0)
        for key in (
            "http_requests", "successful_requests", "failed_requests",
            "retry_requests", "http_seconds", "prompt_tokens",
            "completion_tokens", "total_tokens", "max_tokens_requested",
            "max_tokens_effective", "context_clamped_requests",
            *PROMPT_CACHE_METRIC_KEYS,
        )
    }
    stages: dict[str, dict[str, int]] = {}
    outputs = manifest.get("outputs", {})
    calls_path = outputs.get("training_calls_jsonl") if isinstance(outputs, dict) else None
    if calls_path and Path(str(calls_path)).is_file():
        try:
            with Path(str(calls_path)).open("r", encoding="utf-8") as source:
                for line in source:
                    try:
                        record = json.loads(line)
                    except (TypeError, ValueError, json.JSONDecodeError):
                        continue
                    if not isinstance(record, dict):
                        continue
                    stage = str(record.get("stage") or "其他调用").strip() or "其他调用"
                    item = stages.setdefault(stage, {
                        "requests": 0, "prompt_tokens": 0,
                        "completion_tokens": 0, "total_tokens": 0,
                        "token_available": True,
                    })
                    item["requests"] += 1
                    call_usage = record.get("usage", {})
                    if not isinstance(call_usage, dict):
                        call_usage = {}
                    for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
                        try:
                            item[key] += int(call_usage.get(key, 0) or 0)
                        except (TypeError, ValueError):
                            pass
        except OSError:
            pass
    if not stages:
        pipeline = manifest.get("pipeline", {})
        if isinstance(pipeline, dict):
            effective = (
                manifest.get("configuration", {}).get("effective", {})
                if isinstance(manifest.get("configuration", {}), dict)
                else {}
            )
            method = str(
                effective.get("TARA_FEASIBILITY_METHOD", "attack_potential")
                if isinstance(effective, dict) else "attack_potential"
            ).strip().lower()
            feasibility_stage = {
                "cvss": "feasibility_cvss",
                "heavens": "feasibility_heavens",
            }.get(method, "feasibility_attack_potential")
            fallback_calls = {
                "dst": pipeline.get("dst_model_calls", 0),
                "attack_entry": pipeline.get("attack_entry_model_calls", 0),
                "attack_target": pipeline.get("attack_target_model_calls", 0),
                "impact": pipeline.get("impact_model_calls", 0),
                feasibility_stage: pipeline.get("stage_c_model_calls", 0),
            }
            for stage, requests in fallback_calls.items():
                try:
                    request_count = int(requests or 0)
                except (TypeError, ValueError):
                    request_count = 0
                if request_count:
                    stages[stage] = {
                        "requests": request_count,
                        "prompt_tokens": 0,
                        "completion_tokens": 0,
                        "total_tokens": 0,
                        "token_available": False,
                    }
    return normalized, stages


def _llm_usage_html(manifest: dict[str, Any] | None) -> str:
    """Render real token/call telemetry for the completed run."""
    usage, stages = _llm_usage_details(manifest)
    model = ""
    configuration = manifest.get("configuration", {}) if isinstance(manifest, dict) else {}
    effective = configuration.get("effective", {}) if isinstance(configuration, dict) else {}
    if isinstance(effective, dict):
        model = str(effective.get("TARA_MODEL") or "").strip()
    if not model and isinstance(manifest, dict):
        model = str(manifest.get("model") or "").strip()
    api_base = ""
    if isinstance(effective, dict):
        api_base = str(effective.get("TARA_API_BASE") or "").strip()
    if not api_base and isinstance(manifest, dict):
        api_base = str(manifest.get("api_base") or "").strip()
    requests = _usage_number(usage, "http_requests")
    successful = _usage_number(usage, "successful_requests")
    retries = _usage_number(usage, "retry_requests")
    prompt_tokens = _usage_number(usage, "prompt_tokens")
    completion_tokens = _usage_number(usage, "completion_tokens")
    success_rate = (successful / requests * 100) if requests else 0.0
    retry_rate = (retries / requests * 100) if requests else 0.0
    avg_prompt = (prompt_tokens / requests) if requests else 0.0
    avg_completion = (completion_tokens / requests) if requests else 0.0
    cache = manifest.get("semantic_cache", {}) if isinstance(manifest, dict) else {}
    cache_requests = _usage_number(cache, "requests")
    cache_hits = _usage_number(cache, "hits")
    cache_rate = float(cache.get("hit_rate", 0) or 0) * 100 if isinstance(cache, dict) else 0.0
    completed_cache = manifest.get("completed_result_cache", {}) if isinstance(manifest, dict) else {}
    completed_hit = isinstance(completed_cache, dict) and bool(completed_cache.get("hit"))
    input_cache_tokens = _usage_number(usage, 'prompt_cache_input_tokens')
    input_cache_hits = _usage_number(usage, 'prompt_cache_hit_tokens')
    input_cache_reports = _usage_number(usage, 'prompt_cache_reported_requests')
    input_cache_rate = f'{100 * input_cache_hits / input_cache_tokens:.1f}%' if input_cache_tokens else '—'
    total = _format_count(usage.get("total_tokens"))
    stats = (
        (total, "总 token"),
        (_format_count(prompt_tokens), "输入 token"),
        (_format_count(completion_tokens), "输出 token"),
        (_format_count(requests), "HTTP 请求"),
        (f"{success_rate:.1f}%" if requests else "—", "成功率"),
        (f"{avg_prompt:,.0f}" if requests else "—", "平均输入/次"),
        (f"{avg_completion:,.0f}" if requests else "—", "平均输出/次"),
        (f"{retry_rate:.1f}%" if requests else "—", "重试率"),
        (("已命中" if completed_hit else f"{cache_rate:.1f}%"),
         "完整结果缓存" if completed_hit else "条目缓存命中率"),
    )
    stat_html = "".join(
        f'<div class="token-stat"><b>{html.escape(value)}</b>'
        f'<small>{html.escape(label)}</small></div>'
        for value, label in stats
    )
    stage_html = ""
    if stages:
        ranked = sorted(stages.items(), key=lambda item: -item[1]["total_tokens"])
        stage_html = '<div class="token-stage-list">' + "".join(
            f'<span class="token-stage">{html.escape(LLM_STAGE_LABELS.get(stage, stage))} · '
            f'<b>{(_format_count(item["total_tokens"]) + " token") if item.get("token_available", True) else "token 见总量"}</b> · '
            f'{_format_count(item["requests"])} 次</span>'
            for stage, item in ranked
        ) + "</div>"
        note = "阶段明细来自 AI 审计轨迹"
    else:
        note = "阶段明细需在运行前开启“保存 AI 调用审计轨迹”；总量始终来自 run_manifest.json"
    if input_cache_reports:
        note += (f' · 服务端输入缓存命中率 {input_cache_rate}'
                 f'（{_format_count(input_cache_hits)}/{_format_count(input_cache_tokens)} 输入 token，'
                 f'{_format_count(input_cache_reports)} 次请求已上报）；命中后仍会生成新答案。')
    elif requests:
        note += ' · 服务端未上报输入缓存 token，命中率未知。'
    if completed_hit:
        note = (
            "输入、模型和分析配置一致，已直接复用完成报告；本次未发起模型请求。"
            f"来源完成时间：{completed_cache.get('source_finish_time') or '已记录'}"
        )
    model_suffix = f" · {html.escape(model)}" if model else ""
    endpoint_suffix = f" · API {html.escape(api_base)}" if api_base else ""
    return (
        '<div class="token-usage-card">'
        f'<div class="token-usage-head"><b>AI 调用与 token 消耗{model_suffix}</b>'
        f'<span>{endpoint_suffix.lstrip(" ·") if endpoint_suffix else ""} · 真实服务端 usage · 结果复用不计 HTTP</span></div>'
        f'<div class="token-stat-grid">{stat_html}</div>'
        f'{stage_html}<div class="token-usage-note">{html.escape(note)}'
        f'{(" · 语义缓存 " + _format_count(cache_hits) + "/" + _format_count(cache_requests) + " 次命中") if cache_requests else ""}'
        '</div></div>'
    )


def _preview_schema(include_reasons: bool) -> tuple[list[str], list[int]]:
    columns = [
        (label, width)
        for label, width, reason_only in PREVIEW_COLUMNS
        if include_reasons or not reason_only
    ]
    return [item[0] for item in columns], [item[1] for item in columns]


def _preview_update(
    rows: list[list[Any]], include_reasons: bool
) -> str:
    headers, widths = _preview_schema(include_reasons)
    if not rows:
        return (
            '<div class="result-preview-empty">'
            '<b>等待分析结果</b><span>完成后在此展示前 20 条风险路径，完整数据请下载 Excel 报告。</span>'
            '</div>'
        )
    head = "".join(
        f'<th style="min-width:{int(width)}px">{html.escape(str(label))}</th>'
        for label, width in zip(headers, widths)
    )
    body_rows = []
    for row in rows[:DEMO_PREVIEW_ROW_LIMIT]:
        cells = list(row[: len(headers)])
        if len(cells) < len(headers):
            cells.extend([""] * (len(headers) - len(cells)))
        long_row = any(len(str(value or "")) > 160 for value in cells)
        rendered_cells = []
        for index, value in enumerate(cells):
            control = ('<button type="button" class="ws-preview-expand" data-preview-expand aria-expanded="false" hidden>展开该行</button>' if index == 0 and long_row else '')
            rendered_cells.append(f'<td><div class="ws-preview-cell">{html.escape(str(value if value is not None else ""))}</div>{control}</td>')
        body_rows.append('<tr>' + ''.join(rendered_cells) + '</tr>')
    shown = min(len(rows), DEMO_PREVIEW_ROW_LIMIT)
    return (
        '<div class="result-preview-shell">'
        f'<div class="result-preview-meta">当前展示前 {shown} 条 · 完整结果以下载报告为准</div>'
        '<div class="result-preview-scroll"><table class="result-preview-table">'
        f'<thead><tr>{head}</tr></thead><tbody>{"".join(body_rows)}</tbody>'
        '</table></div></div>'
    )


def _chart_raw_number(value: Any) -> float | None:
    """Extract the original score before radar normalization."""
    if isinstance(value, bool) or value in (None, ""):
        return None
    if isinstance(value, dict):
        for key in ("score", "value", "rating", "level", "分值", "值", "等级"):
            if key in value:
                parsed = _chart_raw_number(value[key])
                if parsed is not None:
                    return parsed
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip().lower()
    words = (
        ("negligible", 0.0), ("none", 0.0), ("可忽略", 0.0), ("无影响", 0.0),
        ("low", 1.0), ("低", 1.0), ("moderate", 2.0), ("中", 2.0),
        ("major", 3.0), ("high", 3.0), ("高", 3.0),
        ("severe", 4.0), ("严重", 4.0),
    )
    number = next((score for label, score in words if label in text), None)
    if number is None:
        match = re.search(r"-?\d+(?:\.\d+)?", text)
        if not match:
            return None
        number = float(match.group(0))
    return number


def _chart_parameter_number(key: str, value: Any) -> float | None:
    """Convert a feasibility parameter to its method-defined numeric value."""
    dimension = str(key).rsplit("·", 1)[-1].strip()
    text = str(value or "").strip().lower()
    if dimension in {"complexity", "C"}:
        if text in CVSS_C:
            return float(CVSS_C[text])
    elif dimension in {"privileges", "P"}:
        if text in CVSS_P:
            return float(CVSS_P[text])
    elif dimension in {"user_interaction", "U"}:
        if text in CVSS_U:
            return float(CVSS_U[text])
    elif dimension in {"attack_vector", "vector"}:
        if text in CVSS_V:
            return float(CVSS_V[text])
    return _chart_raw_number(value)


def _heavens_radar_level(
    dimension: str,
    value: float,
    *,
    legacy_weighted: bool = False,
) -> float:
    """Map a HEAVENS level/weighted point to an ordinal 1--4 radar score.

    The report may contain either the current level (1..4) or a legacy
    weighted point (for example 0/10/100/1000).  The chart must treat both
    representations as the same four ordered levels.
    """
    weights = HEAVENS_DIM_WEIGHTS.get(dimension, {})
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return 1.0
    if legacy_weighted:
        for level, weighted in weights.items():
            if abs(numeric - float(weighted)) < 1e-6:
                return float(level)
    # Normal report output stores the ordinal level 1..4.
    level = int(numeric)
    if level in (1, 2, 3, 4) and abs(numeric - level) < 1e-6:
        return float(level)
    # Accept legacy/report variants that already contain the weighted point.
    for level, weighted in weights.items():
        if abs(numeric - float(weighted)) < 1e-6:
            return float(level)
    return max(1.0, min(4.0, numeric))


def _chart_number(value: Any) -> float | None:
    """Extract a bounded normalized rating number for radar geometry."""
    number = _chart_raw_number(value)
    if number is None:
        return None
    if number < 0:
        return 0.0
    if number <= 4:
        return number / 4
    if number <= 5:
        return number / 5
    if number <= 10:
        return number / 10
    if number <= 100:
        return number / 100
    if number <= 1000:
        return number / 1000
    return 1.0


_CHART_NATIVE_SCALES = {
    # ISO/SAE attack-potential fields (the report stores their native points,
    # not ordinal 0--4 levels).
    "Exposure_time": 19.0,
    "T": 19.0,
    "Professional_experience": 9.0,
    "X": 9.0,
    "Required_information": 11.0,
    "I": 11.0,
    "Opportunity_window": 10.0,
    "Required_equipment": 9.0,
    "Q": 9.0,
    # HEAVENS dimensions are explicitly 0--3.
    "Expertise": 3.0,
    "Knowledge_about_TOE": 3.0,
    "Window_of_Opportunity": 3.0,
    "Equipment": 3.0,
    # CVSS C/P/U values are already in [0, 1].
    "complexity": 1.0,
    "privileges": 1.0,
    "user_interaction": 1.0,
    "C": 1.0,
    "P": 1.0,
    "U": 1.0,
}

# Radar presentation uses ordered levels rather than mixing native units.  A
# five-point AP dimension therefore contributes ranks 1..5, while a two-point
# CVSS dimension contributes ranks 1..2.  This keeps the averaging rule the
# same for every selected impact/feasibility method.
_CHART_ORDINAL_LEVELS: dict[str, tuple[float, ...]] = {
    "Safety": (1.0, 2.0, 3.0, 4.0),
    "Finance": (1.0, 2.0, 3.0, 4.0),
    "Operation": (1.0, 2.0, 3.0, 4.0),
    "Privacy": (1.0, 2.0, 3.0, 4.0),
    **{key: tuple(float(item) for item in values) for key, values in AP_ALLOWED_VALUES.items()},
    **{key: tuple(float(item) for item in values) for key, values in HEAVENS_AP_ALLOWED_VALUES.items()},
    "complexity": tuple(sorted(float(item) for item in CVSS_C.values())),
    "privileges": tuple(sorted(float(item) for item in CVSS_P.values())),
    "user_interaction": tuple(sorted(float(item) for item in CVSS_U.values())),
    "attack_vector": tuple(sorted(float(item) for item in CVSS_V.values())),
    "vector": tuple(sorted(float(item) for item in CVSS_V.values())),
}


def _chart_dimension_name(key: str) -> str:
    return str(key).rsplit("·", 1)[-1].strip()


def _chart_ordinal_rank(key: str, value: Any) -> float | None:
    """Convert one method-native score to a 1..N ordinal rank."""
    number = _chart_raw_number(value)
    if number is None:
        return None
    levels = _CHART_ORDINAL_LEVELS.get(_chart_dimension_name(key))
    if not levels:
        return number
    for rank, level in enumerate(levels, start=1):
        if abs(number - level) < 1e-6:
            return float(rank)
    # A malformed/legacy value is still placed on the nearest valid level;
    # it will not create a new scale or distort the other dimensions.
    nearest = min(range(len(levels)), key=lambda index: abs(number - levels[index]))
    return float(nearest + 1)


def _chart_dimension_scale(
    items: list[float],
    key: str = "",
    scale_overrides: dict[str, float] | None = None,
) -> float:
    """Infer a native scale while keeping every radar dimension comparable.

    Known dimensions use their ordinal level count.  The fallback keeps
    unknown/legacy dimensions bounded when a future method adds a field that
    is not yet in ``_CHART_ORDINAL_LEVELS``.
    """
    dimension = _chart_dimension_name(key)
    if scale_overrides and dimension in scale_overrides:
        return float(scale_overrides[dimension])
    ordinal_levels = _CHART_ORDINAL_LEVELS.get(dimension)
    if ordinal_levels:
        return float(len(ordinal_levels))
    if dimension in _CHART_NATIVE_SCALES:
        return _CHART_NATIVE_SCALES[dimension]
    finite = [abs(float(item)) for item in items if isinstance(item, (int, float))]
    if not finite:
        return 4.0
    maximum = max(finite)
    fractional = any(abs(item - round(item)) > 1e-6 for item in finite)
    if maximum <= 1.0 and fractional:
        return 1.0
    for scale in (4.0, 5.0, 10.0, 100.0, 1000.0):
        if maximum <= scale:
            return scale
    return maximum or 1.0


def _chart_dimensions(
    values: dict[str, list[float]],
    limit: int | None = None,
    *,
    display_max: float = 4.0,
    scale_overrides: dict[str, float] | None = None,
) -> list[tuple[str, float, float]]:
    """Aggregate dimensions after per-dimension normalization.

    ``normalized`` is always the value used by the radar geometry.  Each raw
    observation is divided by that dimension's native maximum *before* the
    observations are averaged.  ``display_max`` controls only the legend;
    production charts use 1.0 so every radar reports a normalized average.
    """
    ranked = []
    for key, items in values.items():
        if not items:
            continue
        ordinal_items = [
            rank for item in items
            if (rank := _chart_ordinal_rank(key, item)) is not None
        ]
        if not ordinal_items:
            continue
        scale = _chart_dimension_scale(ordinal_items, key, scale_overrides)
        normalized = sum(
            max(0.0, min(float(item), scale)) / scale for item in ordinal_items
        ) / len(ordinal_items)
        display_score = normalized * display_max
        ranked.append((key, normalized, display_score, len(items)))
    ranked.sort(key=lambda item: (-item[3], item[0]))
    if limit is not None:
        ranked = ranked[:limit]
    return [
        (key, round(normalized, 3), round(display_score, 3))
        for key, normalized, display_score, _ in ranked
    ]


def _severity_rank(label: Any, title: str) -> float | None:
    """Return an ordered severity rank used for green-to-red chart colors."""
    text = str(label or "").strip().lower()
    if not text or text in {"暂无数据", "未评级", "unknown", "n/a"}:
        return None
    # Check compound English levels first: ``Very Low`` must not collapse
    # into the ordinary ``Low`` bucket, and ``Medium`` is distinct from the
    # Chinese character ``中``.  These are the actual labels emitted by AP,
    # CVSS and HEAVENS methods.
    if "very low" in text:
        return 0.0
    if "very high" in text:
        return 4.0
    words = (
        ("negligible", 0.0), ("none", 0.0), ("qm", 0.0), ("可忽略", 0.0),
        ("无影响", 0.0), ("低", 1.0), ("low", 1.0),
        ("medium", 2.0), ("moderate", 2.0), ("中", 2.0),
        ("major", 3.0), ("high", 3.0), ("高", 3.0),
        ("severe", 4.0), ("critical", 4.0), ("严重", 4.0),
    )
    for token, rank in words:
        if token in text:
            return rank
    match = re.search(r"-?\d+(?:\.\d+)?", text)
    if not match:
        return None
    number = float(match.group(0))
    if title == "风险值" and 1.0 <= number <= 5.0:
        return max(0.0, min(4.0, number - 1.0))
    return max(0.0, min(4.0, number if number <= 4.0 else number / 25.0))


def _severity_palette_index(
    label: Any,
    title: str,
    rank: float,
    palette_size: int,
) -> int:
    """Map a fixed rating label to a stable green-to-red palette slot."""
    text = str(label or "").strip().lower()
    # ISO/SAE 21434 impact has four semantic labels but their ordered ranks
    # are 0/2/3/4 (there is no ``1``).  Keep the visual slots contiguous so
    # Moderate and Major can never share a color when another level is absent.
    if palette_size == 4 and any(
        token in text
        for token in ("negligible", "moderate", "major", "severe", "可忽略", "中等", "重大", "严重")
    ):
        semantic = {
            "negligible": 0, "可忽略": 0,
            "moderate": 1, "中等": 1, "中": 1,
            "major": 2, "重大": 2,
            "severe": 3, "严重": 3,
        }
        for token, index in semantic.items():
            if token in text:
                return index
    if palette_size == 5:
        return max(0, min(4, round(rank)))
    # Four-level feasibility scales use Very Low/Low/Medium/High and are
    # already represented by ranks 0..3.  Numeric 1..4 labels use 1-based
    # indexing, while any unknown value is safely clamped.
    if rank >= 1.0 and rank <= 4.0 and not any(
        token in text for token in ("low", "medium", "moderate", "high", "very", "低", "中", "高")
    ):
        return max(0, min(3, round(rank - 1.0)))
    return max(0, min(3, round(rank)))


def _donut_card(
    title: str,
    counts: Counter[str],
    *,
    level_count: int | None = None,
    chart_key: str = "",
) -> str:
    chart_attr = f' data-portrait-chart="{html.escape(chart_key, quote=True)}"' if chart_key else ""
    ranked = [(key, count) for key, count in counts.items() if count]
    ranked.sort(
        key=lambda item: (
            _severity_rank(item[0], title) is None,
            _severity_rank(item[0], title) if _severity_rank(item[0], title) is not None else 99.0,
            str(item[0]),
        )
    )
    real_total = sum(count for _, count in ranked)
    if not real_total:
        return (
            f'<div class="chart-card donut-card"{chart_attr}><div class="chart-card-title">'
            f'{html.escape(title)}<small>分布 · N=0</small></div>'
            '<div class="chart-empty chart-empty-distribution">'
            '<b>暂无评级数据</b><span>分析生成有效结果后显示分布</span>'
            '</div></div>'
        )
    entries = ranked if chart_key else ranked[:6]
    remainder = 0 if chart_key else sum(count for _, count in ranked[6:])
    if remainder:
        entries.append(("其他", remainder))
    total = real_total
    # Four-level scales use green/yellow/orange/red.  HEAVENS and risk values
    # have five levels, so a light-green transition is added.  The report
    # schema only emits fixed rating labels; the blue fallback below is used
    # solely for an empty placeholder or a non-rating remainder bucket.
    labels_text = {str(label).strip().lower() for label, _ in entries}
    five_level = level_count == 5 or (
        level_count is None
        and (
            title == "风险值"
            or any(
                label in {"none", "very high"} or "very high" in label
                for label in labels_text
            )
        )
    )
    palette = (
        # Saturated colors keep adjacent levels visually distinct on white.
        ("#2e9b45", "#f2c94c", "#f08a24", "#d62828")
        if not five_level
        else ("#2e9b45", "#8fcb3f", "#f2c94c", "#f08a24", "#d62828")
    )
    if title == "风险值":
        from automotive_tara.demo_dashboard import COLORS
        palette = tuple(COLORS[str(value)] for value in range(1, 6))
    cursor = 0.0
    stops = []
    legend = []
    for index, (label, count) in enumerate(entries):
        end = cursor + count / total * 100
        rank = _severity_rank(label, title)
        if rank is None:
            color = COLORS["unrated"] if title == "风险值" else "#8ab6d1"
        else:
            palette_index = _severity_palette_index(label, title, rank, len(palette))
            color = palette[min(len(palette) - 1, max(0, palette_index))]
        stops.append(f"{color} {cursor:.2f}% {end:.2f}%")
        legend.append(
            f'<li data-label="{html.escape(str(label), quote=True)}" data-count="{count}"><i style="background:{color}"></i>'
            f'<span>{html.escape(str(label))}</span>'
            f'<b>{count}<small>{count / total:.0%}</small></b></li>'
        )
        cursor = end
    return (
        f'<div class="chart-card donut-card"{chart_attr}><div class="chart-card-title">'
        f'{html.escape(title)}<small>分布 · N={real_total}</small></div><div class="donut-layout">'
        f'<div class="donut" style="background:conic-gradient({", ".join(stops)})">'
        f'<div><b>{real_total}</b>'
        '<small>样本</small></div></div><ul class="chart-legend">'
        f'{"".join(legend)}</ul></div></div>'
    )


def _radar_card(
    title: str,
    dimensions: list[tuple[str, float, float]],
    *,
    subtitle: str = "各维度平均分值",
    value_suffix: str = "",
) -> str:
    if not dimensions:
        return (
            '<div class="chart-card radar-card"><div class="chart-card-title">'
            f'{html.escape(title)}<small>{html.escape(subtitle)}</small></div>'
            '<div class="chart-empty">暂无可用维度分值</div></div>'
        )
    width, height, cx, cy, radius = 360, 230, 180, 112, 78
    count = len(dimensions)

    def point(index: int, value: float) -> tuple[float, float]:
        angle = -math.pi / 2 + 2 * math.pi * index / count
        return cx + radius * value * math.cos(angle), cy + radius * value * math.sin(angle)

    rings = []
    for level in (0.25, 0.5, 0.75, 1.0):
        coords = [point(index, level) for index in range(count)]
        rings.append(
            '<polygon points="' + " ".join(f"{x:.1f},{y:.1f}" for x, y in coords)
            + '" class="radar-ring" />'
        )
    axes = []
    labels = []
    for index, (label, _, _) in enumerate(dimensions):
        x, y = point(index, 1.0)
        lx, ly = point(index, 1.18)
        axes.append(f'<line x1="{cx}" y1="{cy}" x2="{x:.1f}" y2="{y:.1f}" class="radar-axis" />')
        anchor = "middle" if abs(lx - cx) < 14 else ("start" if lx > cx else "end")
        labels.append(
            f'<text x="{lx:.1f}" y="{ly:.1f}" text-anchor="{anchor}" class="radar-label">'
            f'{html.escape(str(label))}</text>'
        )
    polygon = [point(index, normalized) for index, (_, normalized, _) in enumerate(dimensions)]
    values = " ".join(f"{x:.1f},{y:.1f}" for x, y in polygon)
    point_markers = "".join(
        f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3.8" class="radar-point" />'
        for x, y in polygon
    )
    score_labels = []
    for index, (_, normalized, _) in enumerate(dimensions):
        angle = -math.pi / 2 + 2 * math.pi * index / count
        # Keep the value just outside the polygon and outline it in white so
        # it stays readable over the filled area.
        score_radius = radius * max(0.12, min(1.0, normalized)) + 11
        sx = cx + score_radius * math.cos(angle)
        sy = cy + score_radius * math.sin(angle)
        score_labels.append(
            f'<text x="{sx:.1f}" y="{sy:.1f}" text-anchor="middle" class="radar-score">'
            f'{normalized:.2f}</text>'
        )
    legend = "".join(
        f'<li><span>{html.escape(str(label))}</span><b>{raw:g}'
        f'<small>{html.escape(value_suffix)}</small></b></li>'
        for label, _, raw in dimensions
    )
    return (
        '<div class="chart-card radar-card"><div class="chart-card-title">'
        f'{html.escape(title)}<small>{html.escape(subtitle)}</small></div>'
        f'<div class="radar-layout"><svg viewBox="0 0 {width} {height}" role="img">'
        f'{"".join(rings)}{"".join(axes)}<polygon points="{values}" class="radar-value" />'
        f'{point_markers}{"".join(score_labels)}{"".join(labels)}</svg>'
        f'<ul class="chart-legend radar-legend">{legend}</ul></div></div>'
    )


def _charts_html(
    report: list[dict[str, Any]] | None = None,
    impact_method: str | None = None,
    title: str = "风险画像",
) -> str:
    """Render report-derived customer-facing charts without another model call."""
    report = report if isinstance(report, list) else []
    impact_method = str(impact_method or "21434").strip().lower()
    from automotive_tara.demo_risk_charts import portrait_data, summarize_portrait, portrait_open

    feasibility_level_count = 4
    for function_item in report:
        for asset in function_item.get("assets", []) or []:
            for attribute in asset.get("security_attributes", []) or []:
                for attack in attribute.get("attack", []) or []:
                    parameter_names = {
                        _chart_dimension_name(str(key))
                        for key in (attack.get("attack_parameters") or {})
                    }
                    if parameter_names.intersection({
                        "Expertise", "Knowledge_about_TOE", "Window_of_Opportunity",
                        "Equipment", "E", "K", "Q",
                    }):
                        feasibility_level_count = 5
    data = portrait_data(report)
    summary = summarize_portrait(data)
    return (
        f'<div class="analysis-charts-title"><span>{html.escape(title)}</span>'
        '<small>基于本次报告结果自动汇总，不新增模型请求</small></div>'
        + portrait_open(data, title)
        +
        '<div class="chart-grid chart-grid-three">'
        f'{_donut_card("影响等级", summary["impact"], level_count=(5 if impact_method == "heavens" else 4), chart_key="impact")}'
        f'{_donut_card("可行性等级", summary["feasibility"], level_count=feasibility_level_count, chart_key="feasibility")}'
        f'{_donut_card("风险值", summary["risk"], level_count=5, chart_key="risk")}</div>'
        + '<p class="risk-portrait-count-note">影响等级按资产属性统计；可行性等级、风险值按攻击路径统计。</p></div>'
    )


def _implemented_risk_charts_html(
    baseline: list[dict[str, Any]], residual: list[dict[str, Any]], impact_method: str,
    requirement_scope: str = "45",
) -> str:
    """Compare report snapshots; disclose paths that miss the acceptance target."""
    mitigation_paths = 0
    unresolved = 0
    rating_conflicts = 0
    blocked_paths = 0
    bounded_paths = 0
    bounded_valid = 0
    constructed_paths = 0
    constructed_valid = 0
    for function_index, function in enumerate(baseline):
        actual_function = residual[function_index] if function_index < len(residual) else {}
        for asset_index, asset in enumerate(function.get("assets", []) or []):
            actual_assets = actual_function.get("assets", []) or []
            actual_asset = actual_assets[asset_index] if asset_index < len(actual_assets) else {}
            for attribute_index, attribute in enumerate(asset.get("security_attributes", []) or []):
                actual_attributes = actual_asset.get("security_attributes", []) or []
                actual_attribute = actual_attributes[attribute_index] if attribute_index < len(actual_attributes) else {}
                actual_attacks = actual_attribute.get("attack", []) or []
                for path_index, attack in enumerate(attribute.get("attack", []) or []):
                    baseline_score = _risk_score(attack.get("risk_value_num", attack.get("risk_value")))
                    threshold = 3 if requirement_scope == "345" else 4
                    if baseline_score is None or baseline_score < threshold:
                        continue
                    mitigation_paths += 1
                    actual = actual_attacks[path_index] if path_index < len(actual_attacks) else {}
                    actual_score = _risk_score(actual.get("risk_value_num", actual.get("risk_value")))
                    mode = actual.get("security_requirement_reassessment_mode")
                    is_bounded = mode == "bounded_llm"
                    is_constructed = mode == "deterministic_target"
                    target_risk = 2
                    if is_constructed:
                        constructed_paths += 1
                        constructed_valid += int(
                            actual.get("security_requirement_reassessment_status")
                            == "target_constructed" and actual_score is not None
                            and actual_score <= 2
                        )
                    if is_bounded:
                        bounded_paths += 1
                        bounded_valid += int(
                            actual.get("security_requirement_reassessment_status")
                            == "target_constrained_model" and actual_score is not None
                            and actual_score <= target_risk
                        )
                    if actual.get("security_requirement_reassessment_status") == "rating_conflict":
                        rating_conflicts += 1
                    if str(actual.get("security_requirement_reassessment_status") or "").endswith("needs_review"):
                        blocked_paths += 1
                    if (actual_score is None or actual_score > target_risk
                            or str(actual.get("risk_treatment") or "").strip() != "风险接受"
                            or actual.get("security_requirement_reassessment_status") in {"failed", "rating_conflict"}):
                        unresolved += 1
    if constructed_paths:
        status_class = "residual-risk-success" if unresolved == 0 else "residual-risk-warning"
        status = (
            f'<div class="residual-risk-status {status_class}">'
            f'控制已实施目标情景：程序从合法维度组合构造并复算评分，'
            f'{constructed_valid}/{constructed_paths} 条原风险缓解路径达到风险值 ≤2。'
            '未重新生成攻击路径或调用模型复评；这不是控制有效性的实测证明，'
            '请核验安全需求实际实施情况及各维度分值依据。'
            '原风险接受路径保持基线评级。</div>'
        )
    elif bounded_paths:
        status_class = "residual-risk-success" if unresolved == 0 else "residual-risk-warning"
        status = (
            f'<div class="residual-risk-status {status_class}">'
            f'原风险缓解路径目标风险值 ≤2。程序固定攻击向量对应的机会窗口，并限定其余维度合计；'
            f'模型通过范围与风险矩阵校验 '
            f'{bounded_valid}/{bounded_paths} 条；{unresolved} 条未通过，实施后风险未评级、待复核。'
            '评级按安全需求已实施的前提生成，请核验控制实际实施情况及各维度评分依据。</div>'
        )
    elif unresolved:
        status = (
            '<div class="residual-risk-status residual-risk-warning">'
            f'实施后仍有 {unresolved}/{mitigation_paths} 条原风险缓解路径未满足验收条件'
            f'（风险值 ≤2 且处置为风险接受）；其中 {rating_conflicts} 条存在评级冲突，需人工复核。'
            f'另有 {blocked_paths} 条原路径受阻或证据不足，实施后风险未评级、待复核。'
            '这些路径不能标记为风险接受，请补充或核查安全需求后复评。</div>'
        )
    elif mitigation_paths:
        status = (
            '<div class="residual-risk-status residual-risk-success">'
            f'{mitigation_paths} 条原风险缓解路径复评后均达到风险值 ≤2，可按风险接受处置。</div>'
        )
    else:
        status = '<div class="residual-risk-status">本次报告没有需要实施安全需求的高风险路径。</div>'
    return (
        status
        + _charts_html(baseline, impact_method, title="安全需求实施前 · 风险画像")
        + _charts_html(residual, impact_method, title="安全需求实施后 · 风险画像")
    )


def _manifest_impact_method(manifest: dict[str, Any] | None) -> str:
    """Read the method that produced a report, independent of current UI state."""
    if not isinstance(manifest, dict):
        return "21434"
    configuration = manifest.get("configuration", {})
    if not isinstance(configuration, dict):
        return "21434"
    invocation = configuration.get("invocation", {})
    effective = configuration.get("effective", {})
    for source, key in (
        (invocation, "impact_method"),
        (effective, "TARA_IMPACT_METHOD"),
    ):
        if isinstance(source, dict) and source.get(key):
            return str(source[key]).strip().lower()
    return "21434"


def _manifest_security_requirements_scope(manifest: dict[str, Any] | None) -> str:
    configuration = manifest.get("configuration", {}) if isinstance(manifest, dict) else {}
    effective = configuration.get("effective", {}) if isinstance(configuration, dict) else {}
    selected = effective.get("TARA_SECURITY_REQUIREMENTS_SCOPE", "45") if isinstance(effective, dict) else "45"
    return selected if selected in {"345", "45"} else "45"


def _report_view(
    report: list[dict[str, Any]],
    manifest: dict[str, Any],
    *,
    include_reasons: bool = True,
) -> tuple[str, list[list[Any]], list[dict[str, Any]]]:
    rows: list[list[Any]] = []
    samples: list[dict[str, Any]] = []
    high_risk_samples: list[dict[str, Any]] = []
    risk_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    attribute_count = 0
    path_count = 0

    for function_item in report:
        function_name = str(function_item.get("function", ""))
        for asset in function_item.get("assets", []):
            for attribute in asset.get("security_attributes", []):
                attribute_count += 1
                status = str(attribute.get("analysis_status", ""))
                status_counts[status] += 1
                influence = attribute.get("influence_parameters", {}) or {}
                impact_reason = _reason_text(influence)
                attacks = attribute.get("attack", []) or []
                path_count += len(attacks)
                display_attacks = attacks or [{}]
                for path_index, attack in enumerate(display_attacks, start=1):
                    attack_parameters = attack.get("attack_parameters", {}) or {}
                    risk = attack.get(
                        "risk_value", attribute.get("task_risk_value", "")
                    )
                    risk_counts[str(risk or "未评级")] += 1
                    row = [
                        function_name,
                        asset.get("element_index", ""),
                        asset.get("asset_name", ""),
                        attribute.get("attribute_name", ""),
                        path_index if attacks else "—",
                        attribute.get("damage_scenario", ""),
                        attribute.get("threat_scenarios", ""),
                        attribute.get("impact_level", ""),
                    ]
                    if include_reasons:
                        row.append(impact_reason)
                    row.extend(
                        [
                            attack.get("attack_path", ""),
                            attack.get("feasibility_level", ""),
                        ]
                    )
                    if include_reasons:
                        row.append(_reason_text(attack_parameters))
                    row.append(risk)
                    attack_treatment = str(
                        attack.get("risk_treatment")
                        or attribute.get("task_risk_treatment", "")
                    ).strip().casefold()
                    # Path-level requirements are authoritative.  Do not fall
                    # back to the attribute aggregate merely because this
                    # particular mitigated path has an empty match; that
                    # would copy another path/interface's requirements.
                    requirement_source = attack if attacks else attribute
                    requirement_values = (
                        [
                            requirement_source.get("security_requirement", ""),
                            requirement_source.get("national_standard_code", ""),
                            requirement_source.get("annex5_partbc_mapping", ""),
                        ]
                        if (
                            attack_treatment in {"风险缓解", "risk mitigation", "mitigation"}
                            or attack.get("security_requirements_implemented")
                        )
                        else ["", "", ""]
                    )
                    row.extend(
                        requirement_values
                    )
                    rows.append(row)
                if status == "VALID":
                    first_attack = attacks[0] if attacks else {}
                    risk_values = [
                        attack.get("risk_value", "")
                        for attack in attacks
                        if attack.get("risk_value", "") not in (None, "")
                    ]
                    task_risk = attribute.get("task_risk_value", "")
                    risk_candidates = risk_values or [task_risk]
                    best_risk = max(
                        risk_candidates,
                        key=lambda value: _risk_score(value) or -1,
                    )
                    sample = {
                        "功能": function_name,
                        "元素编号": asset.get("element_index", ""),
                        "资产": asset.get("asset_name", ""),
                        "安全属性": attribute.get("attribute_name", ""),
                        "损害场景": attribute.get("damage_scenario", ""),
                        "威胁场景": attribute.get("threat_scenarios", ""),
                        "影响评级": {
                            key: value
                            for key, value in influence.items()
                        },
                        "影响值/等级": {
                            "value": attribute.get("impact_value", ""),
                            "level": attribute.get("impact_level", ""),
                        },
                        "影响评级置信度": attribute.get(
                            "influence_confidence", {}
                        ),
                        "攻击路径": first_attack.get("attack_path", ""),
                        "可行性评级": first_attack.get(
                            "attack_parameters", {}
                        ),
                        "可行性等级": first_attack.get("feasibility_level", ""),
                        "可行性评级置信度": first_attack.get(
                            "feasibility_confidence", {}
                        ),
                        "风险": best_risk,
                        "风险值列表": risk_values,
                        "程序校验": {
                            "分析状态": status,
                            "状态原因": attribute.get("status_reasons", []),
                            "输入映射冲突": attribute.get(
                                "input_mapping_conflicts", []
                            ),
                        },
                    }
                    if _risk_score(sample["风险"]) is not None and _risk_score(sample["风险"]) >= 4:
                        high_risk_samples.append(sample)
                    if len(samples) < 5:
                        samples.append(sample)

    counts = manifest.get("counts", {}) if isinstance(manifest, dict) else {}
    # New manifests keep the pre-report asset scope explicitly.  The report
    # builder merges attributes under an asset key and older manifests used a
    # name-level ``set(asset_name)`` count, which made this preview show fewer
    # assets than were actually analysed.  Prefer the authoritative analysed
    # instance count and retain a backwards-compatible fallback for old runs.
    analysed_assets = counts.get("assets_analyzed")
    if analysed_assets in (None, ""):
        # Older manifests only persisted the name-level unique count.  The
        # report asset objects are the best available representation of the
        # analysed input scope for those runs, and avoid displaying a smaller
        # deduplicated name count in the preview.
        report_asset_count = sum(
            len(item.get("assets", []) or [])
            for item in report
            if isinstance(item, dict)
        )
        analysed_assets = report_asset_count or counts.get("assets", "—")
    elapsed = manifest.get("elapsed_seconds", 0) if isinstance(manifest, dict) else 0
    metrics = [
        (counts.get("functions", len(report)), "功能"),
        (analysed_assets, "资产"),
        (counts.get("tasks", attribute_count), "安全属性任务"),
        (counts.get("attack_paths", path_count), "可信攻击路径"),
        (f"{float(elapsed) / 60:.1f} min" if elapsed else "—", "总耗时"),
    ]
    cards = "".join(
        f'<div class="metric"><div class="metric-value">{html.escape(str(value))}</div>'
        f'<div class="metric-label">{html.escape(label)}</div></div>'
        for value, label in metrics
    )
    risk_chips = "".join(
        f'<span class="risk-chip">风险 {html.escape(key)} · {value}</span>'
        for key, value in risk_counts.most_common()
    )
    status_chips = "".join(
        f'<span class="risk-chip">{html.escape(key)} · {value}</span>'
        for key, value in status_counts.most_common()
    )
    summary = (
        f'<div class="metric-grid">{cards}</div>'
        f'<details class="ws-usage-details"><summary>模型调用与 Token 用量</summary>{_llm_usage_html(manifest)}</details>'
        f'<div class="risk-bars">{risk_chips}{status_chips}</div>'
    )
    return summary, rows[:80], high_risk_samples or samples


def _download_update(path: str | Path | None) -> dict[str, Any]:
    usable = bool(path and Path(path).is_file())
    return gr.update(value=str(path) if usable else None, interactive=usable)


def _recent_repair_runs(limit: int = 30) -> list[tuple[str, str]]:
    """Return recent completed runs without scanning generated repair snapshots."""
    manifests = [
        path
        for path in (PROJECT_ROOT / "outputs").rglob("run_manifest.json")
        if not {"repair_agent", "agent_acceptance", "input_editor"}.intersection(
            path.relative_to(PROJECT_ROOT / "outputs").parts)
    ]
    manifests.sort(key=lambda path: path.stat().st_mtime_ns, reverse=True)
    choices: list[tuple[str, str]] = []
    for manifest in manifests[: max(1, limit)]:
        run_dir = manifest.parent
        try:
            relative = run_dir.relative_to(PROJECT_ROOT / "outputs")
            label = f"{relative.as_posix()} · {datetime.fromtimestamp(manifest.stat().st_mtime).strftime('%m-%d %H:%M')}"
        except (OSError, ValueError):
            label = run_dir.name
        choices.append((label, str(run_dir)))
    return choices


def refresh_repair_runs() -> dict[str, Any]:
    choices = _recent_repair_runs()
    return gr.update(
        choices=choices,
        value=choices[0][1] if choices else None,
        interactive=True,
    )


RUNTIME_DIAGNOSTIC_RULES = (
    {
        "id": "llm_service",
        "severity": "critical",
        "title": "LLM 服务不可用",
        "patterns": ("connection refused", "无法连接 llm 服务", "llm服务拒绝连接"),
        "action": "先恢复或切换 vLLM 服务，再从现有 Checkpoint 继续；暂不修改业务代码。",
        "mode": "service_recovery",
    },
    {
        "id": "input_mapping",
        "severity": "high",
        "title": "DFD 与拓扑输入映射冲突",
        "patterns": ("input_mapping_conflict", "输入映射冲突", "未共同挂接协议"),
        "action": "检查名称规范化、Source/Target、协议通信信道和外部实体分类；在隔离仓库修复映射逻辑。",
        "mode": "engineering_repair",
    },
    {
        "id": "topology_uncovered",
        "severity": "high",
        "title": "可信拓扑路径未覆盖",
        "patterns": ("topology_uncovered", "拓扑未找到适用攻击路径框架", "未获得可验证的攻击路径"),
        "action": "复核外部接口白名单、节点别名、换行/大小写归一化和信号 Source/Target 绑定规则。",
        "mode": "engineering_repair",
    },
    {
        "id": "model_output",
        "severity": "high",
        "title": "模型结构化结果未通过验收",
        "patterns": ("model_failed", "结果缺失、非法或未完整覆盖路径", "json内容校验失败"),
        "action": "仅重试失败 ID 子集；若同类失败持续出现，再检查 Prompt、JSON 解析和路径覆盖校验。",
        "mode": "checkpoint_retry",
    },
    {
        "id": "id_alignment",
        "severity": "medium",
        "title": "任务或路径 ID 无法对齐",
        "patterns": ("task_id无法对齐", "path_id集合不匹配", "数量不匹配"),
        "action": "统一字符串 ID 并保留前导零，只对无法对齐的失败项执行有限修复。",
        "mode": "engineering_repair",
    },
    {
        "id": "timeout",
        "severity": "medium",
        "title": "模型请求超时或传输异常",
        "patterns": ("timed out", "timeout", "broken pipe"),
        "action": "保持批量结果和 Checkpoint，降低瞬时并发后仅重放失败请求。",
        "mode": "checkpoint_retry",
    },
    {
        "id": "validation_retry",
        "severity": "low",
        "title": "规则校验触发有限重试",
        "patterns": ("校验失败", "验证失败", "重试失败子集", "拒绝写回"),
        "action": "观察有限重试能否补齐；若最终结果完整，无需工程修复。",
        "mode": "observe",
    },
)


def _diagnostic_stage(trace_data: Any, logs: str) -> tuple[str, str]:
    if isinstance(trace_data, dict):
        workflow = trace_data.get("AI工作流", [])
        if isinstance(workflow, list):
            for item in workflow:
                if isinstance(item, dict) and item.get("state") == "error":
                    return str(item.get("id", "unknown")), str(item.get("title", "未知阶段"))
            for item in workflow:
                if isinstance(item, dict) and item.get("state") == "active":
                    return str(item.get("id", "unknown")), str(item.get("title", "当前阶段"))
    lines = str(logs or "").splitlines()
    snapshot = _stage_snapshot(lines, failed=any("error" in line.lower() for line in lines))
    current = next(
        (item for item in snapshot if item["state"] in {"active", "error"}),
        snapshot[0],
    )
    return current["id"], current["title"]


def _run_path_for_trace(trace_data: Any) -> Path | None:
    if not isinstance(trace_data, dict):
        return None
    config = trace_data.get("运行配置", {})
    job_id = str(config.get("job_id", "")).strip() if isinstance(config, dict) else ""
    if not job_id or not re.fullmatch(r"[A-Za-z0-9_-]+", job_id):
        return None
    job_root = DEMO_ROOT / "jobs" / job_id
    result_root = job_root / "result"
    if not result_root.exists():
        # Early failures can happen before result/ is created; the wrapper
        # log in the job directory still belongs to this exact session.
        return job_root if job_root.is_dir() else None
    manifest = _latest_manifest(result_root)
    return manifest.parent if manifest else result_root


def diagnose_runtime(logs: str, trace_data: Any) -> dict[str, Any]:
    """Build an evidence-backed recovery decision without another LLM call."""
    log_lines = [line.strip() for line in str(logs or "").splitlines() if line.strip()]
    normalized = "\n".join(log_lines).lower()
    stage_id, stage_title = _diagnostic_stage(trace_data, str(logs or ""))
    findings: list[dict[str, Any]] = []
    for rule in RUNTIME_DIAGNOSTIC_RULES:
        matched_lines = [
            line for line in log_lines
            if any(pattern in line.lower() for pattern in rule["patterns"])
        ]
        if not matched_lines:
            continue
        findings.append({
            "id": rule["id"],
            "severity": rule["severity"],
            "title": rule["title"],
            "count": len(matched_lines),
            "action": rule["action"],
            "mode": rule["mode"],
            "evidence": matched_lines[-3:],
        })
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "healthy": 0}
    findings.sort(key=lambda item: severity_rank[item["severity"]], reverse=True)
    checkpoint_available = any(
        marker in normalized for marker in ("checkpoint", "检查点", "增量缓存")
    )
    if findings:
        primary = findings[0]
        severity = primary["severity"]
        title = primary["title"]
        recovery_mode = primary["mode"]
        next_action = primary["action"]
    elif not log_lines:
        severity = "unknown"
        title = "缺少运行证据，暂时无法诊断"
        recovery_mode = "inspect"
        next_action = "请先运行分析，或在工程修复面板选择需要检查的历史运行；没有日志不能判断运行健康。"
    else:
        severity = "healthy"
        title = "未发现已知阻断性异常"
        recovery_mode = "continue"
        next_action = "继续执行当前流水线；完成后复核异常清单与高风险结果。"
    run_path = _run_path_for_trace(trace_data)
    return {
        "诊断状态": severity,
        "主要判断": title,
        "当前阶段": {"id": stage_id, "name": stage_title},
        "恢复模式": recovery_mode,
        "Checkpoint可用": checkpoint_available,
        "关联运行": str(run_path) if run_path else "",
        "建议动作": next_action,
        "发现": findings,
        "证据范围": {
            "日志行数": len(log_lines),
            "仅使用真实运行日志": True,
            "额外LLM调用": 0,
        },
    }


def _diagnostic_issue(diagnosis: dict[str, Any]) -> str:
    if diagnosis.get("诊断状态") == "unknown":
        # Missing evidence is not a code defect to repair.  Let the user
        # select historical evidence and describe a concrete repair task.
        return ""
    findings = diagnosis.get("发现", [])
    evidence: list[str] = []
    for finding in findings[:3] if isinstance(findings, list) else []:
        if not isinstance(finding, dict):
            continue
        evidence.extend(str(line) for line in finding.get("evidence", [])[-2:])
    stage = diagnosis.get("当前阶段", {})
    stage_name = stage.get("name", "未知阶段") if isinstance(stage, dict) else str(stage)
    return (
        f"请诊断并修复本次 TARA 运行在【{stage_name}】阶段出现的“{diagnosis.get('主要判断', '未知异常')}”。\n"
        f"恢复策略：{diagnosis.get('恢复模式', 'engineering_repair')}。\n"
        f"建议方向：{diagnosis.get('建议动作', '')}\n"
        "必须先检查关联运行的日志、manifest、异常清单和相关代码；所有修改只在隔离 Git 工作副本执行，"
        "运行针对性测试并输出补丁，不直接修改生产仓库。\n"
        + ("关键证据：\n- " + "\n- ".join(evidence) if evidence else "当前没有错误证据，请先复核运行状态。")
    )


def _diagnostic_html(diagnosis: dict[str, Any]) -> str:
    severity = str(diagnosis.get("诊断状态", "healthy"))
    findings = diagnosis.get("发现", [])
    finding_count = len(findings) if isinstance(findings, list) else 0
    stage = diagnosis.get("当前阶段", {})
    stage_name = stage.get("name", "—") if isinstance(stage, dict) else str(stage)
    checkpoint = "可恢复" if diagnosis.get("Checkpoint可用") else "未检测到"
    return (
        f'<div class="supervisor-result {html.escape(severity)}">'
        '<div class="supervisor-verdict"><span>AGENT SUPERVISOR</span>'
        f'<b>{html.escape(str(diagnosis.get("主要判断", "等待诊断")))}</b></div>'
        '<div class="supervisor-facts">'
        f'<span><small>定位阶段</small><b>{html.escape(stage_name)}</b></span>'
        f'<span><small>异常模式</small><b>{finding_count}</b></span>'
        f'<span><small>Checkpoint</small><b>{checkpoint}</b></span>'
        f'<span><small>恢复模式</small><b>{html.escape(str(diagnosis.get("恢复模式", "continue")))}</b></span>'
        '</div>'
        f'<p>{html.escape(str(diagnosis.get("建议动作", "")))}</p></div>'
    )


def diagnose_current_run(logs: str, trace_data: Any) -> tuple[Any, ...]:
    diagnosis = diagnose_runtime(logs, trace_data)
    issue = _diagnostic_issue(diagnosis)
    choices = _recent_repair_runs()
    run_path = str(diagnosis.get("关联运行", "")).strip()
    if run_path and run_path not in {value for _, value in choices}:
        choices.insert(0, (f"当前运行 · {Path(run_path).name}", run_path))
    # A diagnosis belongs to this session's run, never an unrelated newest
    # historical run.  Historical evidence must be selected explicitly.
    selected = run_path or None
    return (
        _diagnostic_html(diagnosis),
        diagnosis,
        issue,
        gr.update(choices=choices, value=selected, interactive=True),
    )


def handoff_current_run(logs: str, trace_data: Any) -> tuple[Any, ...]:
    """Prepare a repair task and move to the isolated Agent tab for approval."""
    return (*diagnose_current_run(logs, trace_data), gr.update(selected="repair"))


def _repair_event_view(events: list[dict[str, Any]]) -> dict[str, Any]:
    compact: list[dict[str, Any]] = []
    for event in events[-24:]:
        item = dict(event)
        data = item.get("data")
        if data is not None:
            serialized = json.dumps(data, ensure_ascii=False)
            item["data"] = data if len(serialized) <= 6000 else {
                "truncated": True,
                "preview": serialized[:6000],
            }
        compact.append(item)
    return {
        "安全边界": [
            "生产仓库只读",
            "独立 Git 工作副本",
            "白名单工具，无任意 Shell",
            "补丁人工审阅后合入",
        ],
        "步骤数": len(events),
        "事件": compact,
    }


def run_engineering_repair(
    issue: str,
    run_path: str | None,
    selected_model: str | None,
    api_base: str = API_BASE,
    api_key: str = "",
    external_model_name: str = "",
) -> Generator[tuple[Any, ...], None, None]:
    """Keep old event bindings compatible with the portable workbench."""
    detail = "外网工作台提供报告与分析，工程修复请在维护环境中执行。"
    yield (
        _status_html("warning", "工程修复", detail),
        {"状态": "不可用"}, "", *[_download_update(None) for _ in range(3)],
    )



def _initial_outputs(
    job_id: str,
    model: str,
    impact_method: str,
    feasibility_method: str,
    enable_reason: bool,
    enable_asset_details: bool,
    enable_rag: bool,
    dfd_format: str = "auto",
    api_base: str = API_BASE,
) -> tuple[Any, ...]:
    lines: list[str] = []
    return (
        _status_html("running", "任务已创建", f"运行编号 {job_id} · 正在准备隔离输入目录"),
        timeline_html(lines, model=model, job_id=job_id, api_base=api_base),
        trace_payload(
            job_id=job_id,
            model=model,
            impact_method=impact_method,
            feasibility_method=feasibility_method,
            enable_reason=enable_reason,
            enable_rag=enable_rag,
            dfd_format=dfd_format,
            lines=lines,
            api_base=api_base,
        ),
        "",
        '<div class="download-note">分析完成后将在此显示风险概览。</div>',
        _preview_update([], enable_reason),
        _download_update(None),
        _download_update(None),
        _download_update(None),
        _download_update(None),
        _download_update(None),
        _download_update(None),
        _download_update(None),
        _charts_html([]),
    )


def _normalize_method_pair(
    impact_method: str | None,
    feasibility_method: str | None,
) -> tuple[str, str]:
    """Return a valid method pair even if UI change events arrive out of order."""
    impact = str(impact_method or "21434").strip().lower()
    feasibility = str(feasibility_method or "attack_potential").strip().lower()
    if impact not in _VALID_IMPACT_METHODS:
        impact = "21434"
    if feasibility not in _VALID_FEASIBILITY_METHODS:
        feasibility = "attack_potential"

    # Native HEAVENS uses a 5x5 matrix and must be selected on both sides.
    # Prefer the explicitly selected HEAVENS side when a stale UI event leaves
    # the two dropdowns temporarily inconsistent.
    if impact == "heavens":
        feasibility = "heavens"
    elif feasibility == "heavens":
        impact = "heavens"
    return impact, feasibility


def _normalize_dfd_format(value: Any) -> str:
    normalized = str(value or "auto").strip().lower()
    if normalized not in {"auto", "new", "legacy"}:
        raise ValueError("DFD 格式必须为 auto、new 或 legacy")
    return normalized


def run_analysis(
    dfd_files: Any,
    topology_file: Any,
    interfaces_file: Any,
    impact_method: str,
    feasibility_method: str,
    enable_reason: bool,
    scope: str,
    enable_asset_details: bool,
    enable_rag: bool,
    capture_audit: bool,
    implemented_requirement_reassessment: bool = False,
    two_stage_requirement_reassessment: bool = False,
    dfd_format: str = "auto",
    temperature: float = 0.0,
    top_p: float = 1.0,
    top_k: int = 1,
    frequency_penalty: float = 0.0,
    presence_penalty: float = 0.0,
    selected_model: str | None = None,
    lora_adapter: str | None = None,
    api_base: str = API_BASE,
    api_key: str = "",
    adaptive_scheduling: bool = False,
    gpu_memory_gb: float | int = 0,
    model_quantization: str = "auto",
    requirement_scope: str = "45",
    external_model_name: str = "",
    project_label: str = "",
    analysis_selection: dict | None = None,
    force_regenerate: bool = False,
) -> Generator[tuple[Any, ...], None, None]:
    # The customer Demo is intentionally not a training-data collection path.
    # Keep ``capture_audit`` in the signature for compatibility with older
    # callbacks, but ignore any stale or programmatically supplied True value.
    capture_audit = DEMO_TRAINING_CAPTURE_ENABLED
    dfd_format = _normalize_dfd_format(dfd_format)
    if requirement_scope not in {"345", "45"}:
        raise ValueError("风险缓解范围必须选择三缓解或二缓解")
    impact_method, feasibility_method = _normalize_method_pair(
        impact_method, feasibility_method
    )
    def empty_report_preview() -> dict[str, Any]:
        return _preview_update([], enable_reason)

    try:
        api_base, api_key, external_model_name = require_api()
        lora_adapter = NO_LORA_VALUE
        enable_rag = False
    except ValueError as exc:
        yield (
            _status_html("error", "请配置 API", str(exc)),
            timeline_html([], failed=True, api_base=api_base),
            {"错误": "API 地址无效", "api_base": api_base},
            "",
            '<div class="download-note">请检查 API Base 配置。</div>',
            empty_report_preview(),
            *[_download_update(None) for _ in range(7)],
            _charts_html([]),
        )
        return
    model_hint = str(selected_model or "").strip()
    try:
        lora_info = _resolve_lora_choice(lora_adapter)
    except ValueError as exc:
        yield (
            _status_html(
                "error",
                "LoRA 配置无效",
                str(exc),
            ),
            timeline_html([], failed=True, api_base=api_base),
            {"错误": str(exc), "api_base": api_base},
            "",
            '<div class="download-note">没有生成报告。</div>',
            empty_report_preview(),
            *[_download_update(None) for _ in range(7)],
            _charts_html([]),
        )
        return
    if lora_info is not None and not _is_local_api_endpoint(api_base):
        detail = "网页 LoRA 仅管理本机 vLLM；远端 API 请在服务端预先加载 adapter。"
        yield (
            _status_html("error", "LoRA 不能用于远端 API", detail),
            timeline_html([], failed=True, api_base=api_base),
            {"错误": detail, "api_base": api_base},
            "",
            '<div class="download-note">没有生成报告。</div>',
            empty_report_preview(),
            *[_download_update(None) for _ in range(7)],
            _charts_html([]),
        )
        return
    # Keep the imported discovery hook as a compatibility fallback (and for
    # deployments that customize it), while the direct probe handles a key
    # entered in the browser without mutating process-wide environment state.
    manual_model = str(external_model_name or "").strip()
    if not _is_local_api_endpoint(api_base):
        try:
            service = check_api_service(
                api_base, api_key, [manual_model] if manual_model else [],
                timeout=15, open_url=urlrequest.urlopen,
            )
            discovered_model = manual_model or service["model_ids"][0]
        except (APIServiceError, ValueError) as exc:
            detail = str(exc)
            yield (
                _status_html("error", "云端 API 检查未通过", detail),
                timeline_html([], failed=True, api_base=api_base),
                {"错误": detail, "api_base": api_base},
                "", '<div class="download-note">请修正 API 配置后重新启动。</div>',
                empty_report_preview(),
                *[_download_update(None) for _ in range(7)],
                _charts_html([]),
            )
            return
    elif api_base.rstrip("/") == API_BASE.rstrip("/") and not api_key:
        discovered_model = discover_service_model(api_base, timeout=4)
    else:
        discovered_model = _discover_model_for_api(api_base, api_key)
        if not discovered_model and not api_key:
            discovered_model = discover_service_model(api_base, timeout=4)
    if lora_info is not None:
        # Selecting an adapter in the UI is only a request to load it.  Do not
        # create a job that targets a model id which the current vLLM process
        # does not advertise; that used to fail later with a misleading model
        # service error after all uploaded files had already been copied.
        available_models = _discover_models_for_api(api_base, api_key)
        served_name = lora_info["served_name"]
        base_name = lora_info["runtime_base_path"].name
        if served_name not in available_models or base_name not in available_models:
            shown_models = "、".join(available_models[:4]) or "无可用模型"
            detail = (
                f"当前 vLLM 尚未同时加载基础模型（{base_name}）和 LoRA（{served_name}）。"
                f"当前服务提供：{shown_models}。"
                "请先点击“切换模型”，等待状态显示“模型加载完成”后再启动分析。"
            )
            yield (
                _status_html("error", "LoRA 尚未加载", detail),
                timeline_html([], failed=True, api_base=api_base),
                {"错误": detail, "api_base": api_base},
                "",
                '<div class="download-note">没有生成报告。</div>',
            empty_report_preview(),
                *[_download_update(None) for _ in range(7)],
                _charts_html([]),
            )
            return
    # Even when a local LoRA is the active vLLM model, an unselected adapter
    # must not silently become the global model for non-impact stages.
    if lora_info is None and discovered_model and _is_local_api_endpoint(api_base):
        local_route = _local_impact_adapter_route(api_base, discovered_model)
        if local_route and local_route[0] in _discover_models_for_api(api_base, api_key):
            discovered_model = local_route[0]
    # Impact-only LoRA must not alter DST, attack paths or feasibility.
    model = lora_info["runtime_base_path"].name if lora_info is not None else (manual_model or discovered_model or model_hint)
    impact_model = lora_info["served_name"] if lora_info is not None else ""
    source_paths = [
        *(str(path) for path in _paths(dfd_files)),
        *(str(path) for path in _paths(topology_file)),
        *(str(path) for path in _paths(interfaces_file)),
    ]
    project_name = infer_project_name(
        source_paths,
        # Ad-hoc browser uploads do not carry a reliable project directory;
        # use an explicit server setting if present, otherwise a neutral label.
        default=os.getenv("TARA_PROJECT", "TARA"),
        use_environment=False,
    )
    # Include microseconds in the time component so two users can start the
    # same project in the same second without colliding in customer_demo/jobs.
    job_id = (
        datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        + f"-{secrets.token_hex(8)}"
    )
    if not model:
        yield (
            _status_html("error", "无法启动分析", f"未发现可用模型服务：{api_base}"),
            timeline_html([], failed=True, api_base=api_base),
            {"错误": "API /v1/models 不可用", "api_base": api_base},
            "",
            '<div class="download-note">没有生成报告。</div>',
            empty_report_preview(),
            *[_download_update(None) for _ in range(7)],
            _charts_html([]),
        )
        return
    if (impact_method == "heavens") != (feasibility_method == "heavens"):
        yield (
            _status_html("error", "评级方法组合不兼容", "HEAVENS 5级影响与 HEAVENS 可行性必须成对使用"),
            timeline_html([], failed=True, api_base=api_base),
            {"错误": "风险矩阵不兼容"},
            "",
            '<div class="download-note">请调整评级方法后重新运行。</div>',
            empty_report_preview(),
            *[_download_update(None) for _ in range(7)],
            _charts_html([]),
        )
        return

    yield _initial_outputs(
        job_id,
        model,
        impact_method,
        feasibility_method,
        enable_reason,
        enable_asset_details,
        enable_rag,
        dfd_format=dfd_format,
        api_base=api_base,
    )

    job_root = DEMO_ROOT / "jobs" / job_id
    result_root = job_root / "result"
    dfd_detection: list[dict[str, str]] = []
    try:
        dfd_root, topology_target, interfaces_target = _copy_inputs(
            job_root, dfd_files, topology_file, interfaces_file
        )
        if dfd_format == "auto":
            dfd_root, dfd_detection = prepare_dfd_directory(
                dfd_root, job_root / "input" / "DFD_compatible"
            )
            with (dfd_root.parent / "dfd_format_detection.json").open("w", encoding="utf-8") as stream:
                json.dump(dfd_detection, stream, ensure_ascii=False, indent=2)
        elif dfd_format == "new":
            # 转换只发生在本次 job 的隔离目录，上传的原始 JSON 永不改写。
            legacy_root = job_root / "input" / "DFD_legacy"
            dfd_root = convert_new_dfd_directory(dfd_root, legacy_root)
        result_root.mkdir(parents=True, exist_ok=False)
    except Exception as exc:
        yield (
            _status_html("error", "输入校验失败", str(exc)),
            timeline_html([], failed=True, api_base=api_base),
            {"错误": str(exc), "job_id": job_id},
            "",
            '<div class="download-note">没有生成报告。</div>',
            empty_report_preview(),
            *[_download_update(None) for _ in range(7)],
            _charts_html([]),
        )
        return

    command = [
        str(PYTHON_BIN),
        "-u",
        "-m",
        "automotive_tara",
        "--dfd",
        str(dfd_root),
        "--topology",
        str(topology_target),
        "--interfaces",
        str(interfaces_target),
        "--model",
        model,
        "--api-base",
        api_base,
        "--method",
        feasibility_method,
        "--impact-method",
        impact_method,
        "--reason" if enable_reason else "--no-reason",
        "--fresh",
    ]
    selected_scope = bool(analysis_selection and (analysis_selection.get('include') or analysis_selection.get('exclude')))
    if selected_scope:
        from automotive_tara.asset_selection import validate_selection
        selection_path = job_root / 'asset_selection.json'
        selection_path.write_text(json.dumps(validate_selection(analysis_selection), ensure_ascii=False), encoding='utf-8')
        command.extend(['--asset-selection-file', str(selection_path)])
    if not selected_scope and scope not in {"all", "per_dfd_type"}:
        command.extend(["--max-assets", str(int(scope))])
    if enable_rag:
        command.append("--enable-rag")
    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONUNBUFFERED": "1",
            "TARA_MODEL": model,
            "TARA_IMPACT_MODEL": impact_model,
            "TARA_PROJECT": project_name,
            "TARA_API_BASE": api_base,
            # Let the child pipeline avoid probing this machine's GPU when the
            # selected endpoint is remote; its profile must describe the API
            # server (or remain conservative/unknown), not the web host.
            "TARA_REMOTE_API": "0" if _is_local_api_endpoint(api_base) else "1",
            "TARA_ADAPTIVE_SCHEDULING": "1" if adaptive_scheduling else "0",
            "TARA_GPU_MEMORY_GB": str(float(gpu_memory_gb or 0)),
            "TARA_MODEL_QUANTIZATION": "" if str(model_quantization or "auto").strip().lower() == "auto" else str(model_quantization).strip().lower(),
            "TARA_ENABLE_REASON": "1" if enable_reason else "0",
            "TARA_ENABLE_RAG": "1" if enable_rag else "0",
            "TARA_RAG_METHOD": "bge-m3" if enable_rag else "none",
            "TARA_ENABLE_R155": "0",
            "TARA_ENABLE_CONSISTENCY": "0",
            "TARA_SC_ENABLED": "0",
            "TARA_SC_SINGLE_CALL": "0",
            "TARA_ENABLE_ASSET_DETAILS": "1" if enable_asset_details else "0",
            "TARA_CAPTURE_TRAINING": "0",
            "TARA_CAPTURE_REJECTED": "0",
            "TARA_LIVE_MODEL_OUTPUT": "1",
            # Every prepared file is now ready for the canonical parser.
            "TARA_DFD_FORMAT": "legacy",
            # The launcher selects the showcase (rule) or AI-analysis
            # variant.  Both variants remain bounded by the workbook; the AI
            # variant falls back safely if the model/API is unavailable.
            "TARA_SECURITY_REQUIREMENTS_LLM": "1" if DEMO_SECURITY_REQUIREMENTS_LLM else "0",
            "TARA_SECURITY_REQUIREMENTS_SCOPE": requirement_scope,
            "TARA_SECURITY_REQUIREMENTS_IMPLEMENTED_REASSESSMENT": (
                "1"
                if implemented_requirement_reassessment
                else "0"
            ),
            "TARA_SECURITY_REQUIREMENTS_TWO_STAGE_REASSESSMENT": (
                "1" if implemented_requirement_reassessment else "0"
            ),
            "TARA_SECURITY_REQUIREMENTS_LOGIC_PATH": os.getenv("TARA_SECURITY_REQUIREMENTS_LOGIC_PATH", ""),
            "TARA_SECURITY_REQUIREMENTS_PATH": os.getenv("TARA_SECURITY_REQUIREMENTS_PATH", ""),
            "TARA_SECURITY_REQUIREMENT_ASSET_FACTS": str(
                PROJECT_ROOT
                / "data"
                / "input"
                / "C808"
                / "security_requirement_asset_facts.json"
            ) if str(project_name).strip().casefold() == "c808" else "",
            "TARA_TEST_ASSET_SELECTION": "per_dfd_type" if scope == "per_dfd_type" and not selected_scope else "",
            # Scope is mutually exclusive: do not let a stale shell setting
            # truncate the DFD after the per-type selector has run.
            "TARA_TEST_MAX_ASSETS": "0" if selected_scope or scope in {"all", "per_dfd_type"} else "",
            "TARA_TEMPERATURE": str(float(temperature)),
            "TARA_TOP_P": str(float(top_p)),
            "TARA_TOP_K": str(int(top_k)),
            "TARA_FREQUENCY_PENALTY": str(float(frequency_penalty)),
            "TARA_PRESENCE_PENALTY": str(float(presence_penalty)),
        }
    )
    if api_key:
        # Keep credentials out of the displayed command line and console log;
        # the child process receives the key only through its environment.
        environment["TARA_API_KEY"] = api_key
    if force_regenerate:
        environment['TARA_SHARED_CACHE_DIR'] = str(job_root / 'regeneration_cache')
        environment['TARA_REUSE_COMPLETED_RESULTS'] = '0'
    environment["TARA_OUTPUT_DIR"] = str(result_root / "run")

    lines = ["$ " + " ".join(command)]
    console_path = job_root / "demo_console.log"
    try:
        demo_jobs.enqueue(
            DEMO_QUEUE_ROOT,
            job_id,
            {
                "command": command,
                "cwd": str(PROJECT_ROOT),
                "env_updates": {
                    key: value for key, value in environment.items()
                    if key.startswith("TARA_") or key == "PYTHONUNBUFFERED"
                },
                "result_root": str(result_root),
                "log_path": str(console_path),
                "model": model,
                "project_name": str(project_label or project_name or "").strip()[:120],
                "impact_method": impact_method,
                "feasibility_method": feasibility_method,
                "enable_reason": bool(enable_reason),
                "enable_rag": bool(enable_rag),
                "dfd_format": dfd_format,
                "dfd_detection": dfd_detection,
                "api_base": api_base,
            },
        )
    except Exception as exc:
        yield (
            _status_html("error", "入队失败", str(exc)),
            timeline_html(lines, failed=True, api_base=api_base),
            {"错误": str(exc), "job_id": job_id},
            "", '<div class="download-note">任务未启动。</div>',
            empty_report_preview(),
            *[_download_update(None) for _ in range(7)],
            _charts_html([]),
        )
        return
    queued = list(_initial_outputs(
        job_id, model, impact_method, feasibility_method, enable_reason,
        enable_asset_details, enable_rag, dfd_format=dfd_format,
        api_base=api_base,
    ))
    queued[0] = _status_html(
        "running", "已进入后台队列", f"任务 ID：{job_id} · 可刷新后凭 ID 重新连接"
    )
    queued[1] = timeline_html(
        lines, model=model, job_id=job_id, api_base=api_base
    )
    queued[3] = "\n".join(lines)
    queued[2]["DFD自动识别"] = dfd_detection
    yield tuple(queued)


def _job_id_from_trace(trace_data: Any) -> tuple[str, Any]:
    configuration = trace_data.get("运行配置", {}) if isinstance(trace_data, dict) else {}
    job_id = str(configuration.get("job_id") or "") if isinstance(configuration, dict) else ""
    return job_id, gr.update(active=bool(job_id))


def _job_progress_snapshot(
    log_path: Path, result_root: Path, record: dict[str, Any]
) -> tuple[list[str], dict[str, Any], list[dict[str, Any]], int]:
    """Read durable progress so reconnects show the same metrics as live polling."""
    recent: deque[str] = deque(maxlen=120)
    stage_events: list[str] = []
    started_at: datetime | None = None
    try:
        with log_path.open("r", encoding="utf-8", errors="replace") as source:
            for line in source:
                line = line.rstrip("\r\n")
                recent.append(line)
                if "[计时]" in line and any(marker in line for *_, marker in STAGES):
                    stage_events.append(line)
                if started_at is None and line.startswith("[queue] attempt "):
                    match = re.search(r"started (\S+)", line)
                    if match:
                        try:
                            started_at = datetime.fromisoformat(match.group(1))
                        except ValueError:
                            pass
    except OSError:
        pass
    lines = stage_events + list(recent)
    live_payload = _load_json(result_root / "run" / "llm_usage_live.json", {})
    live_usage = live_payload.get("llm", live_payload) if isinstance(live_payload, dict) else {}
    llm_usage = live_usage if isinstance(live_usage, dict) else {}
    if record.get("status") == "completed":
        manifest_path = _latest_manifest(result_root)
        if manifest_path:
            manifest = _load_json(manifest_path, {})
            authoritative = manifest.get("llm") if isinstance(manifest, dict) else None
            if isinstance(authoritative, dict):
                llm_usage = authoritative
    samples = _checkpoint_samples(result_root)[1]
    elapsed_seconds = 0
    if record.get("job_id") == CASE_ID:
        archive = _load_json(result_root / "run" / "run_manifest.json", {})
        elapsed_seconds = round(archive.get("elapsed_seconds", 0))
    if started_at is not None:
        try:
            end_at = (
                datetime.fromisoformat(str(record["updated_at"]))
                if record.get("status") in {"completed", "failed", "cancelled"}
                else datetime.now(timezone.utc)
            )
            elapsed_seconds = max(0, int((end_at - started_at).total_seconds()))
        except (KeyError, TypeError, ValueError):
            pass
    return lines, llm_usage, samples, elapsed_seconds


def poll_analysis_job(job_id: str, enable_reason: bool, revision: dict | None = None) -> tuple[Any, ...]:
    """Reconstruct the workbench from a durable job ID after any reconnect."""
    job_id = str(job_id or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{6,180}", job_id):
        if revision and revision.get('clear'):
            return (_status_html('pending', '项目输入已更新', '可使用当前资料重新启动分析'),
                timeline_html([]), {}, '', '<div class="download-note">等待当前项目生成报告。</div>',
                _preview_update([], enable_reason), *[_download_update(None) for _ in range(7)],
                _charts_html([]), gr.update(active=False))
        return (*[gr.skip() for _ in range(14)], gr.update(active=False))
    jobs_root = (DEMO_ROOT / "jobs").resolve()
    job_root = (jobs_root / job_id).resolve()
    if job_root.parent != jobs_root:
        return (*[gr.skip() for _ in range(14)], gr.update(active=False))
    record = demo_jobs.get_job(DEMO_QUEUE_ROOT, job_id)
    if record is None:
        return (
            _status_html("error", "任务不存在", f"找不到任务 ID：{job_id}"),
            *[gr.skip() for _ in range(13)], gr.update(active=False),
        )
    spec = _load_json(record.get("spec_path"), {})
    log_path = job_root / "demo_console.log"
    lines, llm_usage, samples, elapsed_seconds = _job_progress_snapshot(
        log_path, job_root / "result", record
    )
    state = str(record["status"])
    completed = state == "completed"
    failed = state in {"failed", "cancelled"}
    model = str(spec.get("model") or "")
    api_base = str(spec.get("api_base") or API_BASE)
    state_names = {
        "queued": "排队等待模型槽位",
        "running": "AI 分析进行中",
        "cancelling": "正在停止分析",
        "completed": "TARA 分析完成",
        "failed": "TARA 分析失败",
        "cancelled": "任务已停止",
    }
    target_failure = (
        _load_json(job_root / "result" / "run" / "residual_target_failures.json", {})
        if failed else {}
    )
    target_failure_count = (
        target_failure.get("failed_paths")
        if isinstance(target_failure, dict) else None
    )
    status = _status_html(
        "success" if completed else "error" if failed else "running",
        state_names.get(state, state),
        f"任务 ID：{job_id}" + (
            f" · {record.get('error')}" if record.get("error") else ""
        ) + (
            f" · 实施后风险≤2验收失败：{target_failure_count} 条路径；详见运行日志"
            if isinstance(target_failure_count, int) and target_failure_count > 0 else ""
        ),
    )
    trace = trace_payload(
        job_id=job_id, model=model,
        impact_method=str(spec.get("impact_method") or "21434"),
        feasibility_method=str(spec.get("feasibility_method") or "attack_potential"),
        enable_reason=bool(spec.get("enable_reason")),
        enable_rag=bool(spec.get("enable_rag")),
        dfd_format=str(spec.get("dfd_format") or "auto"),
        lines=lines, failed=failed, completed=completed, api_base=api_base,
        sample_judgements=samples, llm_usage=llm_usage,
    )
    trace["DFD自动识别"] = spec.get("dfd_detection", [])
    report_widgets = (
        load_completed_analysis_result(trace, bool(spec.get("enable_reason", enable_reason)), revision)
        if completed else tuple(gr.skip() for _ in range(10))
    )
    if not completed and revision and revision.get('clear'):
        report_widgets = ('<div class="download-note">本次任务尚未生成报告。</div>',
            _preview_update([], enable_reason), *[_download_update(None) for _ in range(7)], _charts_html([]))
    report_metrics = None
    if completed:
        from automotive_tara.demo_dashboard import report_summary
        report_metrics = report_summary(DEMO_ROOT / "jobs", job_id)
    return (
        status,
        timeline_html(
            lines, model=model, job_id=job_id, failed=failed,
            completed=completed, api_base=api_base,
            samples=samples, llm_usage=llm_usage,
            elapsed_seconds=elapsed_seconds,
            report_metrics=report_metrics,
        ),
        trace, "\n".join(lines),
        *report_widgets,
        gr.update(active=state in {"queued", "running", "cancelling"}),
    )


def cancel_analysis_job(job_id: str) -> Any:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{6,180}", str(job_id or "").strip()):
        return _status_html("error", "无法停止", "请先输入有效任务 ID")
    if demo_jobs.cancel_job(DEMO_QUEUE_ROOT, str(job_id).strip()):
        return _status_html("running", "停止请求已提交", f"任务 ID：{job_id}")
    return _status_html("warning", "任务未运行", f"任务 ID：{job_id}")


def load_completed_analysis_result(
    trace_data: Any,
    enable_reason: bool,
    revision: dict | None = None,
) -> tuple[Any, ...]:
    """Load report widgets after the streaming event has fully completed.

    Keeping this in a separate Gradio event prevents the browser from having
    to reconcile a live generator, a virtual table and all report artifacts in
    one completion message.
    """
    trace_data = trace_data if isinstance(trace_data, dict) else {}
    configuration = trace_data.get("运行配置")
    configuration = configuration if isinstance(configuration, dict) else {}
    job_id = str(configuration.get("job_id") or "").strip()
    empty = (
        _preview_update([], bool(enable_reason)),
        *[_download_update(None) for _ in range(7)],
        _charts_html([]),
    )
    if not re.fullmatch(r"[A-Za-z0-9_.-]{6,180}", job_id):
        return (
            '<div class="download-note">本次运行没有可加载的报告。</div>',
            *empty,
        )
    jobs_root = (DEMO_ROOT / "jobs").resolve()
    job_root = (jobs_root / job_id).resolve()
    if job_root.parent != jobs_root or not job_root.is_dir():
        return (
            '<div class="download-note">运行目录不存在，请重新执行分析。</div>',
            *empty,
        )
    manifest_path = _latest_manifest(job_root / "result")
    manifest = _load_json(manifest_path, {}) if manifest_path else {}
    outputs = manifest.get("outputs", {}) if isinstance(manifest, dict) else {}
    if revision and revision.get('job_id') == job_id:
        allowed = (PROJECT_ROOT / 'outputs/demo_assistant_artifacts').resolve()
        revised = Path(str(revision.get('report') or '')).resolve()
        if revised.is_file() and allowed in revised.parents:
            outputs = {**outputs, 'json': str(revised), 'xlsx': revision.get('excel')}
            manifest = {**manifest, 'outputs': outputs}
    report_path = outputs.get("json")
    report = _load_json(report_path, [])
    if not isinstance(report, list) or not report:
        return (
            _llm_usage_html(manifest)
            + '<div class="download-note">未找到有效报告，请查看运行日志。</div>',
            *empty,
        )
    summary, preview_rows, _ = _report_view(
        report,
        manifest,
        include_reasons=bool(enable_reason),
    )
    actual_log = manifest_path.parent / "tara_run.log" if manifest_path else None
    is_implemented_report = (
        outputs.get("report_variant") == "security_requirements_implemented"
    )
    baseline_excel = (
        outputs.get("baseline_xlsx") if is_implemented_report else outputs.get("xlsx")
    )
    baseline_json = (
        outputs.get("baseline_json") if is_implemented_report else report_path
    )
    baseline_report = _load_json(baseline_json, []) if is_implemented_report else []
    baseline_report = baseline_report if isinstance(baseline_report, list) else []
    return (
        summary,
        _preview_update(preview_rows, bool(enable_reason)),
        _download_update(baseline_excel),
        _download_update(baseline_json),
        _download_update(outputs.get("xlsx") if is_implemented_report else None),
        _download_update(report_path if is_implemented_report else None),
        _download_update(outputs.get("errors_json")),
        _download_update(actual_log),
        _download_update(outputs.get("training_calls_jsonl")),
        (
            _implemented_risk_charts_html(
                baseline_report, report, _manifest_impact_method(manifest),
                _manifest_security_requirements_scope(manifest),
            )
            if is_implemented_report and baseline_report
            else _charts_html(report, impact_method=_manifest_impact_method(manifest))
        ),
    )


def _report_source_from_trace(trace_data: Any) -> tuple[Path, dict[str, Any]]:
    """Resolve only the current browser session's completed report artifact."""
    trace_data = trace_data if isinstance(trace_data, dict) else {}
    configuration = trace_data.get("运行配置")
    configuration = configuration if isinstance(configuration, dict) else {}
    job_id = str(configuration.get("job_id") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{6,180}", job_id):
        raise ReportEditError("当前会话没有可用的已完成报告，请先运行 TARA 分析")
    jobs_root = (DEMO_ROOT / "jobs").resolve()
    job_root = (jobs_root / job_id).resolve()
    if job_root.parent != jobs_root or not job_root.is_dir():
        raise ReportEditError("当前会话的报告目录不存在")
    manifest_path = _latest_manifest(job_root / "result")
    manifest = _load_json(manifest_path, {}) if manifest_path else {}
    outputs = manifest.get("outputs", {}) if isinstance(manifest, dict) else {}
    report_path = Path(str(outputs.get("json") or "")).resolve()
    if not report_path.is_file() or job_root not in report_path.parents:
        raise ReportEditError("当前分析尚未生成有效 JSON 报告")
    return report_path, manifest


def _report_plan_rows(plan: dict[str, Any]) -> list[list[str]]:
    source = Path(str(plan.get("source_report") or ""))
    source_report = _load_json(source, []) if source.is_file() else []
    catalog = {row["risk_id"]: row for row in report_row_catalog(source_report)}
    rows: list[list[str]] = []
    for operation in plan.get("operations", []) or []:
        risk_id = str(operation.get("risk_id") or "")
        field = str(operation.get("field") or "")
        rows.append([
            risk_id,
            EDITABLE_REPORT_FIELDS.get(field, field),
            str(catalog.get(risk_id, {}).get(field, "") or ""),
            str(operation.get("value") or ""),
            str(operation.get("reason") or ""),
        ])
    return rows


def prepare_report_revision_for_ui(
    instruction: str,
    trace_data: Any,
    history: Any,
    current_report_path: str,
    selected_model: str | None,
    api_base: str = API_BASE,
    api_key: str = "",
    external_model_name: str = "",
    job_id: str = "",
    progress: gr.Progress = gr.Progress(),
) -> tuple[Any, str, str, list[list[str]], dict[str, Any], dict[str, Any], str]:
    """Plan a report revision and pause before the first file write."""
    messages = list(history) if isinstance(history, list) else []
    prior_messages = messages[-6:]
    request_text = str(instruction or "").strip()
    if request_text:
        messages.append({"role": "user", "content": request_text})
    try:
        if not request_text:
            raise ReportEditError("请输入要询问或修改的内容")
        current_candidate = Path(str(current_report_path or "")).resolve()
        import_root = (DEMO_ROOT / "report_agent_inputs").resolve()
        if current_candidate.is_file() and import_root in current_candidate.parents:
            report_path = current_candidate
        else:
            active_trace = trace_data if isinstance(trace_data, dict) else {}
            if str(job_id or "").strip():
                active_trace = {"运行配置": {"job_id": str(job_id).strip()}}
            original_report_path, _ = _report_source_from_trace(active_trace)
            report_path = original_report_path
            if current_candidate.is_file() and original_report_path.parent in current_candidate.parents:
                report_path = current_candidate
        progress(0.1, desc="正在加载报告与连接模型")
        endpoint, key, explicit_model = require_api()
        model = explicit_model
        if not model:
            available_models = _discover_models_for_api(endpoint, key)
            selected = str(selected_model or "").strip()
            if _is_local_api_endpoint(endpoint) and selected in available_models:
                model = selected
            elif available_models:
                model = available_models[0]
            elif _is_local_api_endpoint(endpoint):
                model = selected
            else:
                raise ReportEditError("云端服务未返回模型列表，请在第三部分填写“服务模型名”及有效 API Key")
        if not model:
            raise ReportEditError("未发现可用模型，请在第三部分连接或启动模型服务")

        def message_text(content: Any) -> str:
            if isinstance(content, list):
                return "\n".join(str(part.get("text", "")) for part in content if isinstance(part, dict))
            return str(content or "")
        conversation_context = "\n".join(
            f"{item.get('role', 'unknown')}: {message_text(item.get('content'))[:800]}"
            for item in prior_messages
            if isinstance(item, dict)
        )
        contextual_request = request_text
        if conversation_context:
            contextual_request = (
                "以下是最近对话，仅用于理解代词和延续关系：\n"
                + conversation_context
                + "\n\n本轮用户任务：\n"
                + request_text
            )
        plan = prepare_report_edit_plan(
            report_path,
            contextual_request,
            model=model,
            api_base=endpoint,
            api_key=key,
            progress=lambda description: progress(0.5, desc=description),
        )
        operation_count = len(plan.get("operations", []) or [])
        assistant_text = str(plan.get("answer") or "已完成判断")
        if operation_count:
            assistant_text += f"\n\n已形成 {operation_count} 项修改建议。请核对下方差异，然后点击“确认生成修订版”。"
            status = _status_html(
                "running",
                "等待人工确认",
                f"计划 {plan.get('plan_id')} · {operation_count} 项修改 · 原报告尚未改变",
            )
        else:
            status = _status_html("success", "Agent 已回答", "本轮没有需要写入的修改")
        messages.append({"role": "assistant", "content": assistant_text})
        trace = {
            "plan_id": plan.get("plan_id"),
            "agent_trace": plan.get("agent_trace", []),
            "tool_results": plan.get("tool_results", []),
            "source_report": plan.get("source_report"),
        }
        return messages, "", status, _report_plan_rows(plan), trace, plan, str(report_path)
    except Exception as exc:
        detail = str(exc)
        messages.append({"role": "assistant", "content": f"本轮未生成修改计划：{detail}"})
        return (
            messages,
            request_text,
            _status_html("error", "报告 Agent 未完成", detail),
            [],
            {"状态": "失败", "错误": detail},
            {},
            str(current_report_path or ""),
        )


def apply_report_revision_for_ui(
    plan: Any,
    history: Any,
) -> tuple[Any, str, dict[str, Any], dict[str, Any], Any, Any, Any, Any, Any, str, dict[str, Any], str]:
    """Confirm the pending plan and promote its revision to UI downloads."""
    messages = list(history) if isinstance(history, list) else []
    try:
        result = apply_report_edit_plan(plan if isinstance(plan, dict) else {})
        revision = result["revision_manifest"]
        operation_count = len(revision.get("operations", []))
        messages.append({
            "role": "assistant",
            "content": (
                f"修订版已生成，共应用 {operation_count} 项修改。"
                "原始报告仍保留，可分别下载修订版 JSON、Excel 和审计清单。"
            ),
        })
        source_path = Path(str(revision.get("source_report") or ""))
        source_manifest_path = next(
            (
                parent / "run_manifest.json"
                for parent in (source_path.parent, *source_path.parents)
                if (parent / "run_manifest.json").is_file()
            ),
            None,
        )
        source_manifest = _load_json(source_manifest_path, {}) if source_manifest_path else {}
        impact_method = str(revision.get("impact_method") or _manifest_impact_method(source_manifest))
        _, preview_rows, _ = _report_view(
            result["report"],
            source_manifest,
            include_reasons=True,
        )
        preview_update = _preview_update(preview_rows, True)
        status = _status_html(
            "success",
            "报告修订版已生成",
            f"版本 {revision.get('revision_id')} · {operation_count} 项修改 · 原报告未覆盖",
        )
        trace = {
            "状态": "已应用",
            "revision": revision,
            "outputs": {
                "json": result["json_path"],
                "xlsx": result["excel_path"],
                "manifest": result["manifest_path"],
            },
        }
        return (
            messages,
            status,
            trace,
            preview_update,
            _download_update(result["excel_path"]),
            _download_update(result["json_path"]),
            _download_update(result["manifest_path"]),
            gr.skip(),
            gr.skip(),
            _charts_html(result["report"], impact_method=impact_method),
            {},
            result["json_path"],
        )
    except Exception as exc:
        detail = str(exc)
        messages.append({"role": "assistant", "content": f"修订版未生成：{detail}"})
        return (
            messages,
            _status_html("error", "应用修改失败", detail),
            {"状态": "失败", "错误": detail},
            gr.update(),
            *[gr.skip() for _ in range(5)],
            gr.update(),
            plan if isinstance(plan, dict) else {},
            str((plan or {}).get("source_report") or "") if isinstance(plan, dict) else "",
        )


def reset_report_agent_ui() -> tuple[Any, ...]:
    return (
        [],
        "",
        _status_html(
            "running",
            "报告 Agent 待命",
            "先完成分析；修改计划确认前不会写入任何报告文件",
        ),
        [],
        {"状态": "等待任务"},
        {},
        "",
        _download_update(None),
        _download_update(None),
        _download_update(None),
    )


def open_workspace_analysis_job_for_ui(selection: str, reasons: bool, current_job: str = "") -> tuple[Any, ...]:
    selected_id = str(selection or '').partition('|')[0]
    progress = list(poll_analysis_job(selected_id, reasons))
    if selected_id != current_job and progress[4] == gr.skip():
        progress[4:14] = [
            '<div class="download-note">本任务尚未生成报告，可在右侧助手中询问项目资料与当前进度。</div>',
            _preview_update([], reasons), *[_download_update(None) for _ in range(7)],
            '<div class="ws-widget ws-chart-empty"><span>本任务报告尚未生成</span></div>',
        ]
    return selected_id, gr.skip(), *progress


def open_workspace_job_for_ui(selection: str, reasons: bool, current_job: str = "", current_report: str = "") -> tuple[Any, ...]:
    """Open a durable job and isolate its report conversation from other jobs."""
    selected_id = str(selection or "").partition("|")[0]
    progress = list(poll_analysis_job(selected_id, reasons))
    if selected_id != current_job and progress[4] == gr.skip():
        # Unfinished jobs intentionally skip report updates during polling.
        # A task switch must clear the previous job's report/download widgets.
        progress[4:14] = [
            '<div class="download-note">本任务尚未生成报告，可在运行日志中查看进度。</div>',
            _preview_update([], reasons),
            *[_download_update(None) for _ in range(7)],
            '<div class="ws-widget ws-chart-empty"><span>本任务报告尚未生成</span></div>',
        ]
    report_state = [gr.skip() for _ in range(10)]
    same_report_scope = (
        selected_id == current_job and bool(current_report)
        and (DEMO_ROOT / "jobs" / selected_id).resolve() in Path(current_report).resolve().parents
    )
    if not same_report_scope:
        report_state = list(reset_report_agent_ui())
        try:
            report_path, _ = _report_source_from_trace(progress[2])
            report_state[6] = str(report_path)
            report_state[0] = [{"role": "assistant", "content": f"已选择任务 {selected_id} 的报告。可以查找风险行、核对安全需求或提出修订要求。"}]
            report_state[2] = _status_html("success", "报告已就绪", f"当前任务：{selected_id}")
            report_state[4] = {"状态": "已选择任务报告", "job_id": selected_id}
        except ReportEditError:
            pass
    # Navigation is immediate in the browser. A delayed report read must not
    # pull the user back after they have deliberately changed tabs again.
    return selected_id, gr.skip(), *progress, *report_state


def import_report_for_agent(uploaded_report: str | None) -> tuple[Any, ...]:
    """Stage an existing report in an isolated session directory for editing."""
    result = list(reset_report_agent_ui())
    if not uploaded_report:
        return tuple(result)
    try:
        source = Path(uploaded_report)
        if source.suffix.lower() != ".json" or source.stat().st_size > 30 * 1024 * 1024:
            raise ReportEditError("请上传不超过 30 MB 的 TARA JSON 报告")
        report = _load_json(source, None)
        if not isinstance(report, list):
            raise ReportEditError("请选择报告交付中下载的 TARA JSON 报告；DFD 输入文件不能用作报告")
        rows = report_row_catalog(report)
        if not rows:
            raise ReportEditError("报告没有可用的风险行")
        root = DEMO_ROOT / "report_agent_inputs" / secrets.token_hex(16)
        root.mkdir(parents=True, exist_ok=False)
        target = root / "report.json"
        shutil.copy2(source, target)
        result[0] = [{"role": "assistant", "content": f"已载入 {source.name}，共 {len(rows)} 条风险行。可以直接提问或指定风险ID提出修改要求。"}]
        result[2] = _status_html("success", "报告已载入", f"{source.name} · {len(rows)} 条风险行")
        result[4] = {"状态": "已载入报告", "风险行数": len(rows)}
        result[6] = str(target)
    except Exception as exc:
        result[2] = _status_html("error", "报告导入失败", str(exc))
        result[4] = {"状态": "导入失败", "错误": str(exc)}
    return tuple(result)


def report_agent_confirmation_state(plan: Any) -> dict[str, Any]:
    return gr.update(interactive=bool(isinstance(plan, dict) and plan.get("operations")))


def clear_report_agent_conversation(current_report_path: str) -> tuple[Any, ...]:
    result = list(reset_report_agent_ui())
    result[6] = current_report_path
    return tuple(result)


def _sync_feasibility(impact_method: str, feasibility_method: str) -> str:
    if impact_method == "heavens":
        return "heavens"
    if feasibility_method == "heavens":
        return "attack_potential"
    return feasibility_method


def _sync_impact(feasibility_method: str, impact_method: str) -> str:
    if feasibility_method == "heavens":
        return "heavens"
    if impact_method == "heavens":
        return "21434"
    return impact_method


def _strategy_summary_html(
    impact_method: str,
    feasibility_method: str,
    dfd_format: str,
    scope: str,
    enable_reason: bool = False,
    enable_asset_details: bool = False,
    enable_rag: bool = False,
    capture_audit: bool = False,
    implemented_requirement_reassessment: bool = False,
    two_stage_requirement_reassessment: bool = False,
    requirement_scope: str = "45",
    *,
    workspace_labels: bool = False,
) -> str:
    """Render a concise, deterministic summary of the selected assessment plan."""

    impact_label = dict(IMPACT_CHOICES).get(impact_method, str(impact_method))
    feasibility_label = dict(FEASIBILITY_CHOICES).get(
        feasibility_method, str(feasibility_method)
    )
    dfd_label = dict(DFD_FORMAT_CHOICES).get(dfd_format, str(dfd_format))
    scope_label = dict(SCOPE_CHOICES).get(scope, str(scope))
    if workspace_labels:
        impact_label = {value: label for label, value in IMPACT_CHOICES}.get(impact_method, impact_method)
        feasibility_label = {value: label for label, value in FEASIBILITY_CHOICES}.get(feasibility_method, feasibility_method)
        dfd_label = "DFD 自动识别" if dfd_format == "auto" else {value: label for label, value in DFD_FORMAT_CHOICES}.get(dfd_format, dfd_format)
        scope_label = {value: label for label, value in SCOPE_CHOICES}.get(scope, scope)
    requirement_label = "三缓解" if requirement_scope == "345" else "二缓解"
    matrix = "5 × 5" if impact_method == feasibility_method == "heavens" else "4 × 4"
    enabled = sum(
        bool(value)
        for value in (
            enable_reason,
            enable_asset_details,
            enable_rag,
            implemented_requirement_reassessment,
        )
    )
    return (
        '<div class="strategy-summary"><div>'
        '<div class="strategy-summary-kicker">CURRENT ASSESSMENT PLAN</div>'
        f'<h3>{html.escape(str(impact_label))} × {html.escape(str(feasibility_label))}</h3>'
        '<p>'
        f'{html.escape(str(dfd_label))} · {html.escape(str(scope_label))} · '
        f'{requirement_label} · 高级选项已启用 {enabled}/4'
        '</p></div><div class="strategy-summary-matrix"><b>'
        f'{matrix}</b><span>风险矩阵<br>Impact × Feasibility</span>'
        '</div></div>'
    )


def _apply_runtime_preset(preset: str) -> tuple[float, float, int, float, float, bool]:
    """Return request-level settings for the visible runtime presets.

    Presets only modify web-request parameters and the client-side adaptive
    switch; they never rewrite vLLM server settings or environment defaults.
    """

    presets = {
        "stable": (0.0, 1.0, 1, 0.0, 0.0, False),
        "balanced": (0.2, 0.9, 20, 0.0, 0.0, True),
        "fast": (0.0, 1.0, 1, 0.0, 0.0, True),
    }
    return presets.get(str(preset or "").strip().lower(), presets["stable"])


DISCLOSURE_JS = """() => {
    const root = document.documentElement;
    if (root.dataset.disclosureBound) return;
    root.dataset.disclosureBound = 'true';
    let expanded = false;
    const restoreDisclosure = () => {
        const details = root.querySelector('#agent-timeline .execution-details');
        if (details && details.open !== expanded) details.open = expanded;
    };
    const bindDfdPicker = () => {
        const upload = document.querySelector('#dfd-upload');
        if (!upload || upload.dataset.clickUploadBound) return;
        upload.dataset.clickUploadBound = 'true';
        upload.addEventListener('click', event => {
            // Keep file removal and download actions native. Every other
            // click uses the original multi-file picker.
            if (event.target.closest('button, a, input, .top-panel')) return;
            const input = upload.querySelector('input[type="file"]');
            if (input) input.click();
        });
    };
    // Record user intent, not native toggle events: a Gradio DOM patch can
    // remove `open` from the same node and emit its own asynchronous toggle.
    // Enter/Space activation on the native summary also dispatches a click.
    root.addEventListener('click', event => {
        if (event.defaultPrevented || event.button !== 0 || !(event.target instanceof Element)) return;
        const summary = event.target.closest('#agent-timeline .execution-details > summary');
        if (!summary || event.target.closest('a, button, input')) return;
        event.preventDefault();
        expanded = !expanded;
        restoreDisclosure();
    }, true);
    new MutationObserver(() => {
        bindDfdPicker();
        restoreDisclosure();
    }).observe(root, {childList: true, subtree: true, attributes: true, attributeFilter: ['open']});
    bindDfdPicker();
    restoreDisclosure();
}"""


def build_demo(*, workspace: bool = False) -> gr.Blocks:
    from automotive_tara.demo_attack_tree import AttackTreeController, MERMAID_ROOT, empty_tree
    gr.set_static_paths(paths=[MERMAID_ROOT])
    attack_trees = AttackTreeController(DEMO_ROOT / "jobs", _report_source_from_trace)
    if workspace:
        from automotive_tara.demo_workspace import WORKSPACE_JS, workspace_header, workspace_heading, workspace_source_heading, workspace_preflight_table
        from automotive_tara import demo_dashboard

        def refresh_workspace_overview():
            records = demo_dashboard.read_catalog(DEMO_QUEUE_ROOT, DEMO_ROOT / "jobs")
            featured = next((r for r in records if r["status"] in {"running", "queued", "cancelling"}), None)
            featured = featured or next((r for r in records if r["has_report"]), None) or next(iter(records), None)
            metrics, stage_lines = {}, []
            if featured:
                metrics = demo_dashboard.report_summary(DEMO_ROOT / "jobs", featured["job_id"])
                try:
                    with (DEMO_ROOT / "jobs" / featured["job_id"] / "demo_console.log").open(encoding="utf-8", errors="replace") as stream:
                        stage_lines = [line for line in stream if "[计时]" in line and "Step " in line]
                except OSError:
                    pass
            snapshot = _stage_snapshot(stage_lines, completed=bool(featured and featured["status"] == "completed"), failed=bool(featured and featured["status"] == "failed"))
            percentage = round(sum(s["state"] == "done" for s in snapshot) / len(snapshot) * 100)
            return demo_dashboard.overview_html(records, featured, metrics, _agent_trace_html(snapshot, {}, percentage), _discover_models_for_api(API_BASE))

        def refresh_workspace_history(query, status_filter, page=1, delta=0):
            records = demo_dashboard.read_catalog(DEMO_QUEUE_ROOT, DEMO_ROOT / "jobs")
            return demo_dashboard.history_html(records, query, status_filter, int(page or 1) + delta)

        def search_workspace_history(query, status_filter):
            return refresh_workspace_history(query, status_filter, 1)
    summary_renderer = partial(_strategy_summary_html, workspace_labels=True) if workspace else _strategy_summary_html
    preview_renderer = preview_dfd_extraction
    refresh_renderer = refresh_dfd_extraction
    if workspace:
        @wraps(preview_dfd_extraction)
        def preview_renderer(dfd_files, *args, **kwargs):
            summary, rows = preview_dfd_extraction(dfd_files, *args, **kwargs)
            return summary, workspace_preflight_table(rows, DFD_EXTRACT_COLUMNS, source_loaded=bool(_paths(dfd_files)))

        @wraps(refresh_dfd_extraction)
        def refresh_renderer(dfd_files, *args, **kwargs):
            summary, rows, functions, protocols = refresh_dfd_extraction(dfd_files, *args, **kwargs)
            return summary, workspace_preflight_table(rows, DFD_EXTRACT_COLUMNS, source_loaded=bool(_paths(dfd_files))), functions, protocols
    model_choices = available_model_choices()
    lora_choices = _impact_lora_dropdown_choices()
    sample_projects = available_sample_projects()
    selected_model = _current_model_choice(model_choices)
    selected_lora = _default_impact_lora_for_model(selected_model)
    try:
        selected_lora_info = _resolve_lora_choice(selected_lora)
    except ValueError:
        selected_lora_info = None
    if selected_lora_info and selected_lora_info["runtime_base_path"].name in {
        value for _, value in model_choices
    }:
        selected_model = selected_lora_info["runtime_base_path"].name
    initial_lora_status = lora_selection_status(selected_lora)[1]
    navigation = []

    def section_heading(number, kicker, title, description):
        if workspace:
            gr.HTML(workspace_heading(number, title, description))
        else:
            gr.HTML(
                '<div class="workflow-section-heading"><div class="workflow-section-copy">'
                f'<div class="section-kicker">{number} · {kicker}</div>'
                f'<div class="section-title">{title}</div>'
                f'<div class="section-desc">{description}</div></div></div>'
            )

    def section_navigation(previous=None, following=None):
        page_titles = {"input": "项目资料", "strategy": "评估方案", "runtime": "模型服务", "agent": "运行分析", "delivery": "报告交付", "attack_tree": "攻击树"}
        with gr.Row(elem_classes="section-navigation"):
            if previous:
                label = page_titles[previous[1]] if workspace else previous[0]
                navigation.append((gr.Button("← " + label, size="sm"), previous[1]))
            if following:
                label = "继续：" + page_titles[following[1]] if workspace else following[0]
                navigation.append((gr.Button(label + " →", variant="primary", size="sm"), following[1]))

    def source_upload(kind, title, legacy_label, detail, extension, *, multiple=False, file_types):
        with (gr.Column(min_width=200, elem_classes="ws-source-card") if workspace else nullcontext()):
            if workspace:
                gr.HTML(workspace_source_heading(kind, title, detail, extension))
            return gr.File(
                label=title if workspace else legacy_label,
                show_label=not workspace,
                file_count="multiple" if multiple else "single",
                file_types=file_types, type="filepath", height=144 if workspace else 96,
                scale=1, elem_id=f"{kind}-upload", elem_classes="upload-zone",
            )

    def feature_card(
        number, title, description, note, key, *, interactive=True, value=False
    ):
        # Use real columns, as for the four method cards. Checkbox blocks can
        # be wrapped in Gradio's form container and must not be grid tracks.
        with gr.Column(min_width=0, elem_classes=["strategy-choice-card", "feature-option-card"]):
            gr.HTML(
                '<div class="strategy-choice-title">'
                f'<span>{number}</span><div><b>{title}</b>'
                f'<small>{description}</small></div></div>'
                f'<p class="feature-option-note">{note}</p>'
            )
            return gr.Checkbox(
                value=value, label=title, info=note if workspace else "勾选后在本次分析中启用",
                interactive=interactive,
                elem_id=f"feature-{key}", elem_classes="feature-option-toggle",
                min_width=0,
            )

    with gr.Blocks(
        title="TARA Workspace · 汽车网络安全分析平台" if workspace else "AI for TARA · 中汽中心客户展示版",
        fill_width=True,
        delete_cache=(86400, 86400),
    ) as demo:
        dfd_format = gr.State(value="auto")
        gr.HTML(workspace_header() if workspace else _header_html(), elem_id="workspace-shell" if workspace else None)
        with gr.Tabs(
            selected="overview" if workspace else "input",
            elem_id="workflow-tabs",
            elem_classes="workflow-tabs",
        ) as workflow_tabs:
            if workspace:
                with gr.Tab("分析总览", id="overview", elem_classes="workflow-tab") as overview_tab:
                    overview_panel = gr.HTML('<div class="ws-page-heading"><div><h1>分析总览</h1><p>正在读取项目与任务记录…</p></div></div>', elem_id="workspace-overview")
                    overview_refresh = gr.Button("刷新总览", size="sm", elem_id="workspace-overview-refresh")
                with gr.Tab("历史任务", id="history", elem_classes="workflow-tab") as history_tab:
                    gr.HTML('<div class="ws-page-heading"><div><div class="ws-page-overline"><i></i>TASK HISTORY</div><h1>历史任务</h1><p>查找已有分析，直接打开进度、审阅结果或下载报告。</p></div></div>')
                    with gr.Row(elem_classes="ws-history-filters"):
                        history_search = gr.Textbox(label="搜索项目、任务或模型", placeholder="项目名称、任务 ID、模型名称；按回车搜索", scale=5, elem_id="workspace-history-search")
                        history_status = gr.Dropdown(choices=[("全部状态", "all"), *[(label, key) for key, label in demo_dashboard.STATUS_LABELS.items()]], value="all", label="任务状态", scale=2, min_width=140)
                        history_refresh = gr.Button("搜索／刷新", scale=1, min_width=110)
                    history_page = gr.State(1)
                    history_panel = gr.HTML('<div class="ws-chart-empty">正在加载任务记录…</div>', elem_id="workspace-history")
                    with gr.Row(elem_classes="ws-history-pagination"):
                        history_previous = gr.Button("上一页", size="sm", scale=0)
                        history_next = gr.Button("下一页", size="sm", scale=0)
                    history_selection = gr.Textbox(value="", show_label=False, elem_id="workspace-open-selection", elem_classes="ws-event-bridge")
                    history_open = gr.Button("打开所选历史任务", elem_id="workspace-open-job", elem_classes="ws-event-bridge")
            with gr.Tab("模型服务" if workspace else "模型与运行", id="runtime", elem_classes="workflow-tab"):

                # Runtime settings are a permanently visible section.  A Group is
                # used instead of an Accordion so the configuration is discoverable
                # at a glance and cannot be accidentally collapsed before a run.
                section_heading(
                    "runtime", "AI MODEL &amp; RUNTIME", "模型服务" if workspace else "模型与运行设置",
                    "连接本地模型或云端 API。通常保留默认参数即可开始分析。" if workspace else
                    "统一管理模型服务、采样策略与资源调度。",
                )
                with gr.Group(
                    elem_id="runtime-settings",
                    elem_classes="runtime-settings-panel",
                ):
                    gr.HTML(
                        '<div class="runtime-settings-intro"><div>'
                        '<span>MODEL RUNTIME CONTROL</span>'
                        '<b>本次任务独立配置</b></div>'
                        '<p>支持本地 vLLM 与外部 OpenAI 兼容 API。参数仅作用于下一次分析；'
                        '请求级采样不需要重启 vLLM，API Key 不写入日志或报告。</p></div>'
                    )
                    with gr.Row(equal_height=False, elem_classes="runtime-settings-grid"):
                        with gr.Column(scale=5, min_width=280, elem_classes="runtime-setting-group"):
                            gr.HTML(
                                '<div class="runtime-setting-title"><span>01</span><div>'
                                '<b>模型服务</b><small>OpenAI-compatible / vLLM</small></div></div>'
                            )
                            model_status = gr.HTML(model_status_html())
                            with gr.Row(equal_height=True, elem_classes="model-control-row"):
                                model_selector = gr.Dropdown(
                                    choices=model_choices,
                                    value=selected_model,
                                    label="本地基础模型" if workspace else f"本地模型 · {MODEL_ROOT}",
                                    allow_custom_value=False,
                                    filterable=True,
                                    interactive=bool(model_choices),
                                    scale=4,
                                    min_width=190,
                                )
                                switch_model_button = gr.Button(
                                    "切换模型", size="sm", scale=1, min_width=92,
                                    elem_id="switch-model-button", visible=False,
                                )
                                refresh_model = gr.Button(
                                    "刷新状态", size="sm", scale=1, min_width=92,
                                    elem_id="refresh-model-button",
                                )
                            lora_selector = gr.Dropdown(
                                choices=lora_choices,
                                value=selected_lora,
                                label="影响评级适配器（LoRA）" if workspace else f"影响评级专用 LoRA · {LORA_ROOT}",
                                info="Qwen3.6-35B-A3B-AWQ 默认启用影响评级 LoRA；其他模型默认不加载。可手动选择“不加载 LoRA”。",
                                allow_custom_value=False,
                                filterable=True,
                                interactive=bool(lora_choices),
                                elem_id="lora-selector",
                            )
                            with (gr.Accordion("适配器详情", open=False) if workspace else nullcontext()):
                                lora_status = gr.HTML(initial_lora_status)
                            model_switch_progress = gr.HTML(
                                _model_switch_progress_html(
                                    "idle", "模型切换待命", "选择模型后点击“切换模型”", 0
                                )
                            )
                            if workspace:
                                gr.HTML('<div class="ws-subsection-title">云端 / 自定义服务<span>使用其他服务时填写</span></div>')
                            api_base_input = gr.Textbox(
                                value=API_BASE,
                                label="LLM API Base",
                                interactive=False,
                                info="由部署者通过 TARA_API_BASE 配置。",
                            )
                            with gr.Row():
                                api_key_input = gr.Textbox(
                                    value="",
                                    type="password",
                                    label="API Key",
                                    visible=False,
                                    interactive=False,
                                    scale=1,
                                )
                                external_model_name = gr.Textbox(
                                    value=configured_api()[2] if configured_api() else "",
                                    label="服务模型名",
                                    interactive=False,
                                    scale=1,
                                )
                            with gr.Row(elem_classes="api-action-row"):
                                api_test_button = gr.Button("测试 API 连接", size="sm", scale=1)
                                api_status = gr.HTML(
                                    '<div class="api-inline-status standby"><i></i><span>等待连接测试</span></div>',
                                    scale=3,
                                )

                        with (gr.Accordion("采样参数 · 默认稳定模式", open=False, elem_classes="runtime-setting-group") if workspace else gr.Column(scale=5, min_width=280, elem_classes="runtime-setting-group")):
                            gr.HTML(
                                '<div class="runtime-setting-title"><span>02</span><div>'
                                '<b>请求采样</b><small>稳定生产默认：0 / 1 / 1 / 0 / 0</small></div></div>'
                            )
                            with gr.Group(elem_classes="runtime-preset-bar"):
                                runtime_preset = gr.Radio(
                                    choices=RUNTIME_PRESET_CHOICES,
                                    value="stable",
                                    label="运行预设",
                                    show_label=True,
                                    elem_classes="runtime-preset-picker",
                                )
                            with gr.Row(elem_classes="sampling-controls"):
                                temperature = gr.Slider(0, 2, value=0, step=0.05, label="Temperature")
                                top_p = gr.Slider(0.05, 1, value=1, step=0.05, label="Top P")
                                top_k = gr.Slider(
                                    1, 100, value=1, step=1, label="Top K",
                                    info="仅用于本机 vLLM；云端请求不发送此扩展参数",
                                )
                            with gr.Row(elem_classes="sampling-controls"):
                                frequency_penalty = gr.Slider(
                                    -2, 2, value=0, step=0.1, label="Frequency Penalty"
                                )
                                presence_penalty = gr.Slider(
                                    -2, 2, value=0, step=0.1, label="Presence Penalty"
                                )
                            gr.HTML(
                                '<div class="sampling-guidance"><b>稳定评级建议</b>'
                                '<span>Temperature=0、Top P=1、Top K=1；提高随机性会降低重复运行一致性。</span></div>'
                            )

                        with (gr.Accordion("资源与并发 · 高级设置", open=False, elem_classes="runtime-setting-group") if workspace else gr.Column(scale=4, min_width=260, elem_classes="runtime-setting-group")):
                            gr.HTML(
                                '<div class="runtime-setting-title"><span>03</span><div>'
                                '<b>资源调度</b><small>默认使用模型固定生产档；可选显存自适应</small></div></div>'
                            )
                            with gr.Row():
                                adaptive_scheduling = gr.Checkbox(
                                    value=False,
                                    label="自适应调度",
                                    info="自动调整客户端并发、批量和上下文；外部 API 无法读取服务端显存",
                                )
                                gpu_memory_gb = gr.Number(
                                    value=0,
                                    precision=1,
                                    label="显存 GB（0=自动）",
                                )
                            model_quantization = gr.Dropdown(
                                choices=[
                                    ("自动识别", "auto"),
                                    ("BF16/FP16", "none"),
                                    ("AWQ/GPTQ/4bit", "awq"),
                                ],
                                value="auto",
                                label="量化类型",
                            )
                            runtime_profile = gr.HTML(
                                _api_runtime_profile_html(
                                    API_BASE, selected_model or "", False, 0, "auto"
                                )
                            )
                        if workspace:
                            gr.HTML(
                                '<aside class="ws-connection-guide"><b>连接方式</b>'
                                '<div><span>01</span><p><strong>使用本地模型</strong>选择基础模型并切换。LoRA 仅用于影响评级，其余阶段使用基础模型。</p></div>'
                                '<div><span>02</span><p><strong>使用云端服务</strong>填写 API 地址、密钥与服务模型名，先测试连接，再进入分析。</p></div>'
                                '<small>模型服务由多个会话共享。切换本地模型前，请确认没有正在运行的分析任务。</small></aside>'
                            )
                section_navigation(following=("开始项目分析", "input"))




            with gr.Tab("项目资料" if workspace else "项目输入", id="input", elem_classes="workflow-tab"):


                # The customer workflow is deliberately vertical: users complete 01/02
                # before entering the full-width Agent workspace, rather than trying to
                # read an execution console squeezed beside input controls.
                with gr.Row(
                    equal_height=False,
                    elem_classes=["analysis-cockpit", "vertical-workflow"],
                ):
                    with gr.Column(
                        scale=6, elem_classes=["panel", "setup-panel", "left-console"]
                    ):
                        section_heading(
                            "01", "PROJECT INPUT", "项目资料" if workspace else "上传项目输入",
                            "导入项目文件，确认资产与数据流。完成后，进入评估方案。" if workspace else
                            "导入 DFD、拓扑图和外部接口信息，开始一次可追溯的 TARA 分析。",
                        )
                        if workspace:
                            project_name_input = gr.Textbox(label="项目名称", placeholder="例如：C808 整车网络安全分析", max_lines=1, elem_id="workspace-project-name")
                            gr.HTML('<div class="ws-input-heading"><div><b>导入项目文件</b><span>准备三类资料，系统将自动识别 DFD 格式。</span></div><small>支持拖拽上传</small></div>')
                        else:
                            project_name_input = gr.State("")
                        with gr.Row(elem_classes="project-upload-row"):
                            dfd_files = source_upload("dfd", "数据流图", "DFD", "识别功能、资产与数据流", "JSON", multiple=True, file_types=[".json"])
                            topology_file = source_upload("topology", "网络拓扑", "拓扑图", "建立 ECU 与通信连接关系", "JSON", file_types=[".json"])
                            interfaces_file = source_upload("interfaces", "外部接口", "外部接口信息", "确认外部访问入口与协议", "EXCEL", file_types=[".xlsx", ".xlsm"])
                        with gr.Row(elem_classes="sample-loader-row"):
                            sample_project = gr.Dropdown(
                                choices=sample_projects,
                                value=sample_projects[0][1] if sample_projects else None,
                                label="或使用已有项目" if workspace else "选择 data/input 项目",
                                info=None if workspace else "仅显示 DFD、拓扑和外部接口信息均完整的项目",
                                scale=3,
                                min_width=220,
                            )
                            sample_button = gr.Button(
                                "载入项目" if workspace else "载入所选项目数据", elem_id="sample-button", size="sm", scale=1
                            )
                            validate_button = gr.Button("校验输入", size="sm")
                        input_status = gr.HTML(
                            '<div class="input-warn">请上传 DFD、拓扑图和外部接口信息。</div>',
                            elem_id="workspace-input-status" if workspace else None,
                        )
                        with gr.Group(elem_classes="dfd-extract-card"):
                            dfd_extract_summary = gr.HTML(_dfd_extract_summary_html())
                            with gr.Row(elem_classes="dfd-extract-toolbar"):
                                dfd_extract_search = gr.Textbox(
                                    label="搜索预提取结果",
                                    placeholder="搜索功能、元素、资产或信号",
                                    scale=5,
                                    elem_classes="dfd-extract-search",
                                )
                                dfd_extract_function = gr.Dropdown(
                                    choices=["全部"],
                                    value="全部",
                                    label="功能",
                                    scale=3,
                                    min_width=150,
                                )
                                dfd_extract_protocol = gr.Dropdown(
                                    choices=["全部"],
                                    value="全部",
                                    label="协议",
                                    scale=2,
                                    min_width=130,
                                )
                                dfd_extract_apply = gr.Button(
                                    "应用筛选",
                                    size="sm",
                                    scale=1,
                                    elem_classes="dfd-extract-apply",
                                )
                                dfd_extract_clear = gr.Button(
                                    "清除筛选", size="sm", scale=1, elem_classes="dfd-extract-clear"
                                )
                            dfd_extract_table = gr.HTML(
                                workspace_preflight_table([], DFD_EXTRACT_COLUMNS),
                                elem_classes="dfd-extract-table",
                            ) if workspace else gr.Dataframe(
                                headers=list(DFD_EXTRACT_COLUMNS),
                                value=[],
                                datatype=["str"] * len(DFD_EXTRACT_COLUMNS),
                                column_widths=list(DFD_EXTRACT_COLUMN_WIDTHS),
                                interactive=False,
                                wrap=True,
                                max_height=460,
                                show_search="filter",
                                # Keep one shared virtual grid for header and
                                # rows.  Pinning columns creates a second
                                # measured layer in Gradio and can introduce
                                # a few-pixel drift between the two on resize.
                                pinned_columns=0,
                                buttons=["fullscreen", "copy"],
                                show_label=False,
                                elem_classes="dfd-extract-table",
                            )
                section_navigation(following=("下一步：评估策略", "strategy"))




            with gr.Tab("评估方案" if workspace else "评估策略", id="strategy", elem_classes="workflow-tab"):
                with gr.Column(elem_classes=["panel", "setup-panel", "strategy-panel"]):


                    section_heading(
                        "02", "ASSESSMENT STRATEGY", "评估方案" if workspace else "评估策略",
                        "选择评级方法和分析范围，按交付要求启用可选功能。" if workspace else
                        "选择影响评级、攻击可行性、风险缓解范围和分析范围，确认本次评估组合。",
                    )
                    with gr.Row(elem_classes="strategy-card-grid"):
                        with gr.Column(scale=1, min_width=0, elem_classes="strategy-choice-card"):
                            gr.HTML(
                                '<div class="strategy-choice-title"><span>01</span><div>'
                                '<b>影响评级</b><small>选择影响等级计算方法</small>'
                                '</div></div>'
                            )
                            impact_method = gr.Radio(
                                choices=IMPACT_CHOICES,
                                value="21434",
                                label="影响评级方法",
                                show_label=False,
                                elem_classes="strategy-method-picker",
                            )
                        with gr.Column(scale=1, min_width=0, elem_classes="strategy-choice-card"):
                            gr.HTML(
                                '<div class="strategy-choice-title"><span>02</span><div>'
                                '<b>攻击可行性</b><small>选择攻击难度评价方法</small>'
                                '</div></div>'
                            )
                            feasibility_method = gr.Radio(
                                choices=FEASIBILITY_CHOICES,
                                value="attack_potential",
                                label="攻击可行性方法",
                                show_label=False,
                                elem_classes=["strategy-method-picker", "feasibility-method-picker"],
                            )
                        with gr.Column(scale=1, min_width=0, elem_classes="strategy-choice-card"):
                            gr.HTML(
                                '<div class="strategy-choice-title"><span>03</span><div>'
                                '<b>风险缓解范围</b><small>选择需要匹配安全需求的风险等级</small>'
                                '</div></div>'
                            )
                            requirement_scope = gr.Radio(
                                choices=[("三缓解", "345"), ("二缓解", "45")],
                                value="45",
                                label="风险缓解范围",
                                show_label=False,
                                elem_classes=["strategy-method-picker", "risk-mitigation-picker"],
                            )
                            gr.HTML(
                                '<p class="strategy-mitigation-note">三缓解：风险 3/4/5；'
                                '二缓解：仅风险 4/5。纳入范围的路径匹配安全需求，'
                                '启用实施后复评时目标风险值 ≤2。</p>'
                            )
                        with gr.Column(scale=1, min_width=0, elem_classes="strategy-choice-card"):
                            gr.HTML(
                                '<div class="strategy-choice-title"><span>04</span><div>'
                                '<b>分析范围</b><small>选择本次 TARA 处理规模</small>'
                                '</div></div>'
                            )
                            scope = gr.Radio(
                                choices=SCOPE_CHOICES,
                                value="10",
                                label="演示分析范围",
                                show_label=False,
                                type="value",
                                elem_classes="scope-radio",
                            )
                    with gr.Group(
                        elem_classes="advanced-options strategy-advanced-options",
                    ):
                        gr.HTML(
                            '<div class="advanced-options-heading">'
                            '<div class="advanced-options-heading-main"><span>05</span><div>'
                            '<b>高级选项</b><small>可选功能开关 · 按 Demo 版本预设</small>'
                            '</div></div><span class="advanced-options-heading-note">OPTIONAL CONTROLS</span>'
                            '</div>'
                        )
                        gr.HTML(
                            '<div class="advanced-options-intro">'
                            '<span>开启后仅影响本次分析，建议根据交付要求选择。</span>'
                            '</div>'
                        )
                        with gr.Row(elem_classes="feature-options-grid"):
                            enable_reason = feature_card(
                                "01", "生成评级理由", "为评级结果补充简短依据",
                                "影响评级与攻击可行性评级均输出重点理由，便于人工复核。", "reason",
                            )
                            enable_asset_details = feature_card(
                                "02", "资产细项", "补充资产的细分对象与关联信息",
                                "需要更细粒度的资产核对与结果追溯时开启。", "assets",
                            )
                            enable_rag = gr.State(value=False)
                            capture_audit = gr.State(value=False)
                            implemented_requirement_reassessment = feature_card(
                                "04", "安全需求实施后复评", "保留原路径 · 确定性目标评分",
                                "按上方缓解范围生成实施后报告，原攻击路径、攻击向量和影响评级保留。"
                                "程序选择合法的可行性评分组合并计算目标风险≤2，不调用模型重新生成路径。"
                                "结果基于控制已实施的目标情景，评分依据和实际控制效果仍需人工核验。",
                                "implemented-requirements",
                                value=DEMO_SECURITY_REQUIREMENTS_LLM,
                            )
                            # Preserve the old callback position without exposing
                            # a duplicate switch. The single checkbox drives the
                            # complete deterministic reassessment in run_analysis.
                            two_stage_requirement_reassessment = gr.State(value=False)
                    strategy_summary = gr.HTML(
                        summary_renderer(
                            "21434", "attack_potential", "auto", "10",
                            implemented_requirement_reassessment=DEMO_SECURITY_REQUIREMENTS_LLM,
                        )
                    )
                section_navigation(("项目输入", "input"), ("进入分析工作台", "agent"))


            with gr.Tab("运行分析" if workspace else "分析工作台", id="agent", elem_classes=["workflow-tab", "agent-tab"]):
                section_heading(
                    "03", "AGENTIC AI WORKFLOW", "运行分析" if workspace else "分析工作台",
                    "启动评估，跟踪阶段进度。分析在后台运行，可凭任务 ID 恢复查看。" if workspace else
                    "启动评估，跟踪分析进度，查看风险结果与依据。",
                )
                with gr.Row(equal_height=True, elem_classes="agent-launchbar"):
                    run_button = gr.Button(
                        "启动 AI TARA 分析", variant="primary", elem_id="run-button"
                    )
                    stop_button = gr.Button(
                        "停止当前分析",
                        variant="stop",
                        size="sm",
                        elem_id="stop-button",
                    )
                with gr.Row(equal_height=True, elem_classes="ws-reconnect" if workspace else None):
                    job_id_input = gr.Textbox(
                        label="任务 ID · 刷新页面后可粘贴续查",
                        placeholder="启动后自动填写，也可粘贴已有任务 ID",
                        scale=5,
                        elem_id="workspace-job-id" if workspace else None,
                    )
                    reconnect_button = gr.Button("查询／重新连接", scale=1)
                poll_timer = gr.Timer(DEMO_JOB_POLL_INTERVAL_SECONDS, active=False)

                with gr.Row(equal_height=True, elem_classes="agent-overview-row"):
                    with gr.Column(scale=12, elem_classes="agent-overview-status"):
                        status = gr.HTML(
                            _status_html("running", "等待启动", "上传输入并选择评估策略")
                        )
                with gr.Group(elem_classes="agent-timeline-shell"):
                    timeline = gr.HTML(timeline_html([]), elem_classes="agent-panel", elem_id="agent-timeline")

                with gr.Tabs(
                    selected="results", elem_classes="agent-workspace-tabs"
                ) as workspace_tabs:
                    with gr.Tab("风险结果预览", id="results"):
                        summary = gr.HTML(
                            '<div class="download-note">分析完成后显示功能、资产、攻击路径和风险统计。</div>'
                        )
                        gr.HTML(
                            '<div class="result-guide"><b>结果说明：</b>每行对应一条可信攻击路径；'
                            '同一损害/威胁场景可能因路径不同出现多行。网页只展示轻量风险预览，'
                            '各维度分值和完整数据保留在正式报告中。</div>'
                        )
                        # A native HTML preview is intentionally used here.
                        # Gradio's virtual Dataframe can leave the whole page
                        # locked when a queued generator replaces its schema
                        # and rows in the completion event.
                        preview = gr.HTML(_preview_update([], True))
                    with gr.Tab("AI Trace 与结构化证据", id="trace"):
                        trace = gr.JSON(
                            value={"状态": "等待分析"},
                            label="Agent Trace · 调用、工具、约束与采用结果",
                            open=False,
                            max_height=620,
                            buttons=["copy"],
                        )
                    with gr.Tab("实时运行日志", id="logs"):
                        logs = gr.Code(
                            value="",
                            language="shell",
                            label="Pipeline events",
                            lines=24,
                            max_lines=800,
                            interactive=False,
                            wrap_lines=True,
                            buttons=["copy", "download"],
                        )
                    with gr.Tab("运行诊断与修复交接", id="diagnostics"):
                        gr.HTML(
                            '<div class="diagnostic-handoff-card">'
                            '<div><span class="section-kicker">RUNTIME SUPERVISION</span>'
                            '<h3>诊断当前运行 · 交接隔离修复 Agent</h3>'
                            '<p>诊断只读取当前日志和 Trace，不产生额外模型调用；确认后可将问题上下文交给工程修复 Agent。</p></div>'
                            '<span class="diagnostic-handoff-badge">LOG → DIAGNOSIS → REPAIR</span>'
                            '</div>'
                        )
                        with gr.Row(equal_height=True, elem_classes="agent-supervisor-bar"):
                            supervisor_status = gr.HTML(
                                '<div class="supervisor-result standby">'
                                '<div class="supervisor-verdict"><span>AGENT SUPERVISOR</span>'
                                '<b>等待运行事件</b></div><p>可随时诊断当前日志；不会产生额外模型调用。</p></div>',
                                elem_classes="supervisor-status",
                            )
                        with gr.Accordion("Supervisor 诊断证据 · 可审计", open=False):
                            supervisor_trace = gr.JSON(
                                value={"状态": "等待运行日志"},
                                label="异常模式、证据与恢复决策",
                                open=False,
                                max_height=360,
                            )
                        with gr.Row(elem_classes="post-run-actions"):
                            diagnose_run_button = gr.Button(
                                "诊断当前运行 Agent", size="sm", elem_id="diagnose-run-button"
                            )
                            handoff_repair_button = gr.Button(
                                "交给隔离修复 Agent", size="sm", elem_id="handoff-repair-button"
                            )
                        gr.HTML(
                            '<div class="download-note">诊断结果会显示在本面板的 Agent Supervisor 区域；交接后自动切换到“工程修复 Agent”。</div>'
                        )
                    with gr.Tab("工程修复 Agent", id="repair", visible=False):
                        gr.HTML(
                            '<div class="repair-shell"><div class="repair-hero"><div>'
                            '<div class="section-kicker">Isolated Engineering Agent</div>'
                            '<h3>让 Agent 自主检查代码、修复缺陷并运行测试</h3>'
                            '<p>选择一份异常报告或直接使用最近运行，描述问题后启动。Agent 会按“证据 → 定位 → '
                            '最小补丁 → 编译/测试 → 冒烟验证 → 差异审阅”循环调用白名单工具；生产仓库始终只读。</p>'
                            '</div><div class="repair-boundary">'
                            '<span>生产目录只读</span><span>独立 Git 副本</span>'
                            '<span>无任意 Shell</span><span>补丁人工合入</span>'
                            '</div></div></div>'
                        )
                        with gr.Row(equal_height=True, elem_classes="repair-console-grid"):
                            with gr.Column(scale=5, elem_classes="repair-control"):
                                repair_choices = _recent_repair_runs()
                                repair_run_path = gr.Dropdown(
                                    choices=repair_choices,
                                    value=repair_choices[0][1] if repair_choices else None,
                                    label="关联的 TARA 运行",
                                    allow_custom_value=True,
                                    info="留空时自动检查 outputs 中最近一次完整运行",
                                )
                                refresh_repair_runs_button = gr.Button(
                                    "刷新运行列表", size="sm"
                                )
                                repair_issue = gr.Textbox(
                                    label="需要诊断和修复的问题",
                                    placeholder=(
                                        "例如：异常清单中大量 INPUT_MAPPING_CONFLICT，"
                                        "DFD Source/Target 明明挂在同一通信信道，请定位并修复匹配逻辑。"
                                    ),
                                    lines=5,
                                    max_lines=12,
                                )
                                repair_run_button = gr.Button(
                                    "启动工程修复 Agent",
                                    variant="primary",
                                    elem_id="repair-run-button",
                                )
                                repair_stop_button = gr.Button(
                                    "停止修复任务", variant="stop", size="sm"
                                )
                            with gr.Column(scale=7, elem_classes="repair-output"):
                                repair_status = gr.HTML(
                                    _status_html(
                                        "running",
                                        "修复 Agent 待命",
                                        "等待问题描述；所有修改只会写入隔离工作副本",
                                    )
                                )
                                repair_trace = gr.JSON(
                                    value={"状态": "等待启动"},
                                    label="工具调用与验证轨迹",
                                    open=False,
                                    elem_classes="repair-trace",
                                )
                        repair_diff = gr.Code(
                            value="",
                            language=None,
                            label="隔离工作副本补丁预览",
                            lines=20,
                            max_lines=1200,
                            interactive=False,
                            wrap_lines=False,
                            buttons=["copy", "download"],
                        )
                        with gr.Row(elem_classes="repair-artifacts"):
                            repair_patch_download = gr.DownloadButton(
                                "下载 changes.patch", interactive=False
                            )
                            repair_report_download = gr.DownloadButton(
                                "下载修复报告", interactive=False
                            )
                            repair_trace_download = gr.DownloadButton(
                                "下载 Agent 审计轨迹", interactive=False
                            )
                section_navigation(("评估策略", "strategy"), ("进入资产攻击树", "attack_tree"))




            with gr.Tab("攻击树", id="attack_tree", elem_classes="workflow-tab") as attack_tree_tab:
                section_heading(
                    "04", "ASSET ATTACK TREES", "资产攻击树",
                    "从最终目标自上而下拆解攻击方式、必要子目标与具体动作。",
                )
                tree_state = gr.State({})
                tree_summary = gr.Markdown("完成分析，或从历史任务打开报告后，将自动读取当前任务的资产。", elem_id="attack-tree-summary")
                with gr.Row(elem_classes="attack-tree-controls"):
                    tree_search = gr.Textbox(label="搜索资产", placeholder="功能、资产名称、类型或收发端；按回车搜索", scale=2, min_width=180, elem_id="attack-tree-search")
                    tree_asset = gr.Dropdown(label="选择资产 · 每个资产一张图", choices=[], value=None, scale=4, min_width=240, elem_id="attack-tree-asset")
                    tree_refresh = gr.Button("刷新攻击树", size="sm", scale=0, min_width=110, elem_id="attack-tree-refresh")
                gr.HTML('<div class="attack-tree-note"><b>资产与威胁 → 攻击方式 → 必要子目标 → 具体动作</b><br>OR 表示任选一种，AND 表示全部必要条件。紫色框显示简短动作，点击节点查看完整描述与路径依据。</div>')
                tree_preview = gr.HTML(empty_tree(), elem_id="attack-tree-preview")
                with gr.Accordion("路径依据、损害场景与安全需求", open=False):
                    tree_evidence = gr.HTML("", elem_id="attack-tree-evidence")
                with gr.Accordion("完整资产 Mermaid 源码", open=False):
                    tree_code = gr.Code(value="", language="markdown", label="Mermaid", interactive=False, lines=14, elem_id="attack-tree-code")
                with gr.Row(elem_classes="attack-tree-export"):
                    tree_export = gr.Button("导出全部资产攻击树", variant="primary", elem_id="attack-tree-export")
                    tree_download = gr.File(label="全部资产攻击树 ZIP", interactive=False, visible=False, height=90, min_width=0, elem_id="attack-tree-download")
                section_navigation(previous=("返回分析工作台", "agent"), following=("进入报告交付", "delivery"))


            with gr.Tab("报告交付", id="delivery", elem_classes="workflow-tab"):


                section_heading(
                    "05", "DELIVERABLES", "报告交付" if workspace else "报告与交付",
                    "下载分析报告、核对风险分布，完成项目交付。" if workspace else
                    "分析完成后，可下载正式报告，并查看风险分布与评级概览。",
                )
                with gr.Row(elem_classes="delivery-panel"):
                    with (gr.Column(min_width=0, elem_classes="ws-delivery-file") if workspace else nullcontext()):
                        if workspace:
                            gr.HTML('<div class="ws-file-heading"><span class="ws-file-symbol">01</span><span class="ws-file-state"></span></div><h3 class="ws-file-title">原始基线报告</h3><p class="ws-file-description">安全需求实施前的风险结果。Excel 用于评审，JSON 用于数据集成。</p>')
                        excel_download = gr.DownloadButton("下载原始基线 Excel", interactive=False)
                        json_download = gr.DownloadButton("下载原始基线 JSON", interactive=False)
                    with (gr.Column(min_width=0, elem_classes="ws-delivery-file") if workspace else nullcontext()):
                        if workspace:
                            gr.HTML('<div class="ws-file-heading"><span class="ws-file-symbol">02</span><span class="ws-file-state"></span></div><h3 class="ws-file-title">安全需求实施版</h3><p class="ws-file-description">启用实施后复评时生成，用于核对风险缓解路径的残余风险。</p>')
                        implemented_excel_download = gr.DownloadButton("下载安全需求实施版 Excel", variant="primary", interactive=False)
                        implemented_json_download = gr.DownloadButton("下载安全需求实施版 JSON", interactive=False)
                    with (gr.Column(min_width=0, elem_classes="ws-delivery-file") if workspace else nullcontext()):
                        if workspace:
                            gr.HTML('<div class="ws-file-heading"><span class="ws-file-symbol">03</span><span class="ws-file-state"></span></div><h3 class="ws-file-title">异常与运行记录</h3><p class="ws-file-description">定位输入映射、生成与评级异常，保留分析过程供后续核查。</p>')
                        errors_download = gr.DownloadButton("下载异常清单", interactive=False)
                        log_download = gr.DownloadButton("下载运行日志", interactive=False)
                    audit_download = gr.DownloadButton(
                        "下载 AI 审计轨迹", interactive=False, visible=False
                    )
                gr.HTML(
                    '<div class="delivery-help"><b>交付文件说明</b>'
                    '<p>原始基线报告保留安全需求实施前的评级；安全需求实施版仅复评风险缓解路径的可行性与残余风险。'
                    'Excel 用于人工评审，JSON 用于系统集成；异常清单与运行日志用于问题排查。'
                    '按钮在对应文件生成后可用。当前 Demo 不保存 Prompt 或模型回复审计文件；可下载运行日志查看过程。</p></div>'
                )
                charts = gr.HTML(
                    ('<div class="ws-widget ws-chart-empty"><span>尚未选择报告</span><small>完成分析，或从历史任务打开报告后查看风险画像。</small></div>' if workspace else _charts_html([])), elem_classes="analysis-charts"
                )

                gr.HTML(
                    '<div class="notice" style="text-align:center;margin-top:18px">'
                    'TARA WORKSPACE · 汽车网络安全风险分析'
                    '</div>'
                )
                section_navigation(previous=("返回资产攻击树", "attack_tree"))

        from automotive_tara.demo_assistant import AssistantController
        from automotive_tara.demo_assistant_ui import ASSISTANT_UI_JS, CAPTURE_VIEW_JS, toolbar as assistant_toolbar, suggestions as assistant_suggestions
        assistant = AssistantController(PROJECT_ROOT, DEMO_ROOT / "jobs", DEMO_QUEUE_ROOT)
        assistant_browser = gr.BrowserState({}, storage_key="tara.securityAssistant.v1", secret=assistant.store.secret())
        assistant_binding = gr.State({})
        analysis_selection = gr.State({})
        assistant_report_state = gr.State({})
        with gr.Column(elem_id="project-assistant", min_width=0):
            with gr.Row(elem_classes="assistant-titlebar"):
                gr.HTML('<div class="assistant-heading"><span class="assistant-symbol">✦</span><b>安全分析助手</b></div>')
                assistant_clear = gr.Button("＋", size="sm", min_width=28, scale=0, elem_id="project-assistant-clear")
                gr.HTML(assistant_toolbar(), elem_classes='assistant-toolbar-controls')
            assistant_project = gr.HTML('<div class="assistant-project">正在连接当前项目…</div>', elem_id="project-assistant-context")
            assistant_view = gr.Textbox(value='', show_label=False, container=False,
                elem_id='project-assistant-view', elem_classes='assistant-view-input')
            with gr.Column(elem_id='project-assistant-scroll', min_width=0):
                assistant_chat = gr.Chatbot(value=[], show_label=False, layout="bubble", height=400,
                    min_height=100, elem_id="project-assistant-chat", buttons=["copy"],
                    placeholder="### 一起处理当前项目\n\n检查输入、解释风险，或直接告诉我需要修改的内容。")
                gr.HTML(assistant_suggestions(), elem_id='project-assistant-starters')
                assistant_evidence = gr.HTML('', elem_id="project-assistant-execution")
                assistant_watch = gr.HTML('', elem_id="project-assistant-watch")
                assistant_downloads = gr.File(label='本轮文件', file_count='multiple', visible=False, elem_id='project-assistant-artifacts')
            with gr.Column(elem_id="project-assistant-composer", min_width=0, scale=0):
                assistant_question = gr.Textbox(show_label=False, lines=3, max_lines=7,
                    placeholder="询问当前项目，或描述要执行的操作…", elem_id="project-assistant-question", container=False)
                with gr.Row(elem_classes="assistant-actions"):
                    assistant_mode = gr.Dropdown(choices=[("Agent", "agent"), ("问答", "ask")], value='agent',
                        show_label=False, container=False, min_width=80, scale=1, elem_id='project-assistant-mode')
                    assistant_model_badge = gr.HTML('<span class="assistant-model-meta">连接模型…</span>', elem_id='project-assistant-model')
                    assistant_stop = gr.Button("■", size="sm", min_width=32, scale=0, elem_id="project-assistant-stop")
                    assistant_send = gr.Button("↑", variant="primary", min_width=34, scale=0, elem_id="project-assistant-send")
            assistant_status = gr.Markdown("Enter 发送 · Shift+Enter 换行", elem_id="project-assistant-status")
            with gr.Accordion("助手设置", open=True, elem_id='project-assistant-settings'):
                gr.HTML('<div class="assistant-settings-head"><b>助手设置</b><button type="button" data-assistant-action="settings-close" aria-label="关闭助手设置">×</button></div>')
                assistant_context_budget = gr.Dropdown(choices=[('自动 · 64K预算','auto'),('8K',8192),('16K',16384),('32K',32768),('64K',65536),('128K · 长材料',131072)],
                    value='auto', label='请求上下文（输入＋输出合计）', elem_id='project-assistant-window')
                assistant_capacity = gr.HTML('', elem_id='project-assistant-capacity')
                assistant_skill = gr.Dropdown(choices=[("自动选择技能", "auto"), *[(item['name'], item['id']) for item in assistant.skills.catalog()]],
                    value="auto", label='技能', elem_id="project-assistant-skill", min_width=0)
                with gr.Accordion('项目记忆', open=False):
                    assistant_memory = gr.Markdown("项目记忆会在这里显示，刷新后保留。", elem_id="project-assistant-memory")
                    assistant_memory_refresh = gr.Button("刷新项目记忆", size="sm")
        gr.HTML('<button type="button" class="assistant-mobile-toggle" aria-controls="project-assistant">AI 助手</button>')
        assistant_context_inputs = [dfd_files, topology_file, interfaces_file, job_id_input, project_name_input, assistant_browser]
        assistant_context_outputs = [assistant_chat, assistant_project, assistant_binding]
        assistant_initial = demo.load(assistant.initialize, inputs=assistant_browser, outputs=assistant_browser,
                                      queue=False, show_progress="hidden")
        assistant_restored = assistant_initial.then(assistant.restore, inputs=assistant_context_inputs, outputs=assistant_context_outputs,
                               queue=False, show_progress="hidden")
        job_id_input.change(assistant.sync, inputs=assistant_context_inputs, outputs=assistant_context_outputs,
                            queue=False, show_progress="hidden")
        for assistant_source in (dfd_files, topology_file, interfaces_file):
            for assistant_file_event in (assistant_source.upload, assistant_source.delete, assistant_source.clear):
                assistant_file_event(assistant.sync_draft,
                    inputs=[dfd_files, topology_file, interfaces_file, project_name_input, assistant_browser],
                    outputs=assistant_context_outputs, queue=False, show_progress="hidden", trigger_mode="always_last")
        if workspace:
            project_name_input.input(assistant.sync_project_name,
                inputs=[dfd_files, topology_file, interfaces_file, project_name_input, assistant_browser],
                outputs=assistant_context_outputs, queue=False, show_progress='hidden', trigger_mode='always_last')
        analysis_inputs = [dfd_files, topology_file, interfaces_file, impact_method, feasibility_method,
            enable_reason, scope, enable_asset_details, enable_rag, capture_audit,
            implemented_requirement_reassessment, two_stage_requirement_reassessment, dfd_format,
            temperature, top_p, top_k, frequency_penalty, presence_penalty, model_selector, lora_selector,
            api_base_input, api_key_input, adaptive_scheduling, gpu_memory_gb, model_quantization,
            requirement_scope, external_model_name, project_name_input, analysis_selection]
        assistant_inputs = [assistant_question, assistant_browser, assistant_binding, assistant_skill,
                            assistant_mode, assistant_context_budget, assistant_view, tree_asset, tree_state, *analysis_inputs]
        assistant_outputs = [assistant_chat, assistant_question, assistant_status, assistant_evidence, assistant_send]
        assistant_apply_outputs = [dfd_files, topology_file, interfaces_file, analysis_selection, assistant_report_state,
            job_id_input, poll_timer, assistant_downloads, assistant_binding, assistant_project, project_name_input]
        assistant_restored.then(assistant.apply_workspace, inputs=[assistant_browser, assistant_binding, dfd_files],
            outputs=assistant_apply_outputs, queue=False, show_progress='hidden')
        for assistant_event in (assistant_send.click, assistant_question.submit):
            assistant_response = assistant_event(assistant.ask_from_ui, inputs=assistant_inputs, outputs=assistant_outputs,
                js=CAPTURE_VIEW_JS,
                concurrency_limit=2, concurrency_id="project-assistant", show_progress="hidden", stream_every=.12)
            assistant_response.then(assistant.apply_workspace, inputs=[assistant_browser, assistant_binding, dfd_files],
                outputs=assistant_apply_outputs, queue=False, show_progress='hidden')
            assistant_response.then(assistant.memory_view, inputs=[assistant_browser, assistant_binding],
                outputs=assistant_memory, queue=False, show_progress="hidden")
        assistant_binding.change(assistant.apply_workspace, inputs=[assistant_browser, assistant_binding, dfd_files],
            outputs=assistant_apply_outputs, queue=False, show_progress='hidden')
        assistant_observer = gr.Timer(4, active=True)
        assistant_observer.tick(assistant.watch, inputs=[assistant_browser, assistant_binding], outputs=assistant_watch,
            queue=False, show_progress='hidden')
        def assistant_context_capacity(api_base, model, external_model, api_key, requested):
            from automotive_tara.assistant_context import context_profile
            service = configured_api()
            if service is None:
                return "尚未配置 API", "历史浏览"
            endpoint, key, selected = service
            p = context_profile(endpoint, selected, key, requested)
            match = re.search(r'Qwen[\d.]+(?:-\d+B)?', selected, re.I)
            title = match.group(0) if match else selected
            return (f'<span class="assistant-capacity">实际可用 {p["effective"] // 1024}K · {html.escape(p["notice"])}</span>',
                f'<span class="assistant-model-meta" title="{html.escape(selected, quote=True)}">{html.escape(title)}<i>·</i>{p["effective"] // 1024}K</span>')
        for source in (assistant_context_budget, model_selector, external_model_name, api_base_input):
            source.change(assistant_context_capacity, inputs=[api_base_input, model_selector, external_model_name, api_key_input, assistant_context_budget],
                outputs=[assistant_capacity, assistant_model_badge], queue=False, show_progress='hidden')
        demo.load(assistant_context_capacity,
            inputs=[api_base_input, model_selector, external_model_name, api_key_input, assistant_context_budget],
            outputs=[assistant_capacity, assistant_model_badge], queue=False, show_progress='hidden')
        assistant_stop.click(assistant.cancel, inputs=assistant_binding, outputs=assistant_status, queue=False, show_progress="hidden")
        assistant_memory_refresh.click(assistant.memory_view, inputs=[assistant_browser, assistant_binding],
            outputs=assistant_memory, queue=False, show_progress="hidden")
        assistant_binding.change(assistant.memory_view, inputs=[assistant_browser, assistant_binding],
            outputs=assistant_memory, queue=False, show_progress="hidden")
        assistant_clear.click(assistant.clear, inputs=assistant_binding,
            outputs=[assistant_chat, assistant_question, assistant_status, assistant_evidence], queue=False,
            show_progress="hidden")
        demo.load(fn=None, js="""() => {
            if (window.taraAssistantToggleBound) return;
            window.taraAssistantToggleBound = true;
            const setPlacement = () => {
                const selected = document.querySelector('#workflow-tabs > .tab-wrapper [role="tab"][aria-selected="true"]')?.dataset.tabId;
                const visible = ['input', 'strategy', 'agent', 'delivery', 'attack_tree'].includes(selected);
                const tabs = document.querySelector('#workflow-tabs');
                if (tabs) tabs.dataset.page = selected || '';
                const panel = document.querySelector('#project-assistant');
                const toggle = document.querySelector('.assistant-mobile-toggle');
                if (panel) panel.dataset.visible = visible ? 'true' : 'false';
                if (toggle) toggle.dataset.visible = visible ? 'true' : 'false';
                if (!visible) {
                    document.querySelector('.gradio-container').dataset.assistantOpen = 'false';
                    if (panel) panel.dataset.open = 'false';
                    if (toggle) { toggle.textContent = 'AI 助手'; toggle.setAttribute('aria-expanded', 'false'); }
                }
            };
            new MutationObserver(setPlacement).observe(document.querySelector('.gradio-container'),
                {subtree:true, attributes:true, attributeFilter:['aria-selected']});
            setPlacement();
            const disclosures = new Map();
            let disclosureFrame = false;
            const restoreDisclosures = () => {
                disclosureFrame = false;
                for (const [selector, open] of disclosures) {
                    const details = document.querySelector(selector);
                    if (details && details.open !== open) details.open = open;
                }
            };
            new MutationObserver(() => {
                if (!disclosureFrame) { disclosureFrame = true; requestAnimationFrame(restoreDisclosures); }
            }).observe(document.querySelector('#project-assistant'),
                {subtree:true, childList:true, attributes:true, attributeFilter:['open']});
            document.addEventListener('click', event => {
                const summary = event.target.closest('.assistant-watch > summary, .assistant-execution > summary');
                if (!summary) return;
                const details = summary.parentElement;
                disclosures.set(details.classList.contains('assistant-watch') ? '.assistant-watch' : '.assistant-execution', !details.open);
            }, true);
            document.addEventListener('click', event => {
                const button = event.target.closest('.assistant-mobile-toggle');
                if (!button) return;
                const root = document.querySelector('.gradio-container');
                root.dataset.assistantOpen = root.dataset.assistantOpen === 'true' ? 'false' : 'true';
                document.querySelector('#project-assistant').dataset.open = root.dataset.assistantOpen;
                button.setAttribute('aria-expanded', root.dataset.assistantOpen);
                button.textContent = root.dataset.assistantOpen === 'true' ? '收起助手' : 'AI 助手';
            });
        }""")
        demo.load(fn=None, js=ASSISTANT_UI_JS)
        demo.load(fn=None, js=Path(__file__).with_name("static").joinpath("risk_charts.js").read_text(encoding="utf-8").replace('"__TARA_RISK_STYLES__"', json.dumps(Path(__file__).with_name("demo_risk_charts.css").read_text(encoding="utf-8"))))

        if workspace:
            demo.load(fn=None, js=WORKSPACE_JS)
            demo.load(refresh_workspace_overview, outputs=overview_panel, queue=False, show_progress="hidden")
            overview_tab.select(refresh_workspace_overview, outputs=overview_panel, queue=False, show_progress="hidden")
            overview_refresh.click(refresh_workspace_overview, outputs=overview_panel, queue=False, show_progress="hidden")
            history_inputs = [history_search, history_status, history_page]
            history_outputs = [history_panel, history_page]
            history_tab.select(refresh_workspace_history, inputs=history_inputs, outputs=history_outputs, queue=False, show_progress="hidden")
            history_refresh.click(refresh_workspace_history, inputs=history_inputs, outputs=history_outputs, queue=False, show_progress="hidden")
            history_search.input(search_workspace_history, inputs=[history_search, history_status], outputs=history_outputs, queue=False, trigger_mode="always_last", show_progress="hidden")
            history_search.submit(search_workspace_history, inputs=[history_search, history_status], outputs=history_outputs, queue=False, show_progress="hidden")
            history_status.change(search_workspace_history, inputs=[history_search, history_status], outputs=history_outputs, queue=False, show_progress="hidden")
            history_previous.click(partial(refresh_workspace_history, delta=-1), inputs=history_inputs, outputs=history_outputs, queue=False, show_progress="hidden")
            history_next.click(partial(refresh_workspace_history, delta=1), inputs=history_inputs, outputs=history_outputs, queue=False, show_progress="hidden")
        # Preserve disclosure intent across both node replacement and Gradio's
        # in-place attribute patches during timer/stream updates.
        demo.load(fn=None, js=DISCLOSURE_JS)
        tree_inputs = [trace, job_id_input, tree_state, tree_search]
        tree_outputs = [tree_state, tree_asset, tree_summary, tree_preview, tree_code, tree_evidence, tree_download]
        tree_events = dict(inputs=tree_inputs, outputs=tree_outputs, queue=False, show_progress="hidden", trigger_mode="always_last")
        attack_tree_tab.select(attack_trees.load, **tree_events)
        trace.change(attack_trees.load, **tree_events)
        job_id_input.change(attack_trees.load, **tree_events)
        tree_refresh.click(partial(attack_trees.load, force=True), **tree_events)
        tree_asset.change(attack_trees.select, inputs=[tree_asset, tree_state], outputs=[tree_preview, tree_code, tree_evidence], queue=False, show_progress="hidden", trigger_mode="always_last")
        tree_search.submit(attack_trees.search, inputs=[tree_search, tree_state, tree_asset], outputs=[tree_asset, tree_preview, tree_code, tree_evidence], queue=False, show_progress="hidden")
        tree_export.click(attack_trees.download, inputs=tree_state, outputs=tree_download, concurrency_limit=1, concurrency_id="attack-tree-export", show_progress="minimal")
        for button, target in navigation:
            button.click(
                lambda target=target: gr.update(selected=target),
                outputs=workflow_tabs, queue=False, show_progress="hidden",
            )
        file_inputs = [dfd_files, topology_file, interfaces_file]
        sample_load_event = sample_button.click(
            sample_project_inputs,
            inputs=sample_project,
            outputs=[dfd_files, topology_file, interfaces_file, input_status],
            show_progress="minimal",
        )
        sample_load_event.then(assistant.sync_draft,
            inputs=[dfd_files, topology_file, interfaces_file, project_name_input, assistant_browser],
            outputs=assistant_context_outputs, queue=False, show_progress='hidden')
        sample_load_event.then(
            refresh_renderer,
            inputs=[
                dfd_files, dfd_extract_search, dfd_extract_function,
                dfd_extract_protocol,
            ],
            outputs=[
                dfd_extract_summary, dfd_extract_table,
                dfd_extract_function, dfd_extract_protocol,
            ],
            show_progress="hidden",
        )
        if workspace:
            sample_load_event.then(lambda selected: Path(str(selected)).name if selected else "", inputs=sample_project, outputs=project_name_input, show_progress="hidden", queue=False)
        validate_button.click(
            validate_inputs_html,
            inputs=file_inputs,
            outputs=input_status,
            show_progress="minimal",
        )
        for file_component in file_inputs:
            file_component.change(
                validate_inputs_html,
                inputs=file_inputs,
                outputs=input_status,
                show_progress="hidden",
            )
        dfd_files.change(
            refresh_renderer,
            inputs=[
                dfd_files, dfd_extract_search, dfd_extract_function,
                dfd_extract_protocol,
            ],
            outputs=[
                dfd_extract_summary, dfd_extract_table,
                dfd_extract_function, dfd_extract_protocol,
            ],
            show_progress="hidden",
        )
        dfd_filter_inputs = [
            dfd_files, dfd_extract_search, dfd_extract_function,
            dfd_extract_protocol,
        ]
        dfd_extract_search.input(
            preview_renderer,
            inputs=dfd_filter_inputs,
            outputs=[dfd_extract_summary, dfd_extract_table],
            show_progress="hidden",
        )
        for dfd_filter_component in (
            dfd_extract_function, dfd_extract_protocol,
        ):
            dfd_filter_component.change(
                preview_renderer,
                inputs=dfd_filter_inputs,
                outputs=[dfd_extract_summary, dfd_extract_table],
                show_progress="hidden",
            )
        dfd_extract_apply.click(
            preview_renderer,
            inputs=dfd_filter_inputs,
            outputs=[dfd_extract_summary, dfd_extract_table],
            show_progress="minimal",
        )
        dfd_extract_clear.click(
            lambda: ("", "全部", "全部"),
            outputs=[
                dfd_extract_search, dfd_extract_function,
                dfd_extract_protocol,
            ],
            show_progress="hidden",
        ).then(
            preview_renderer,
            inputs=dfd_filter_inputs,
            outputs=[dfd_extract_summary, dfd_extract_table],
            show_progress="hidden",
        )
        refresh_model.click(
            refresh_model_controls,
            outputs=[model_status, model_selector, lora_selector],
            show_progress="minimal",
        )
        lora_selector.change(
            lora_selection_status,
            inputs=lora_selector,
            outputs=[model_selector, lora_status],
            show_progress="hidden",
        )
        model_selector.change(
            lora_choice_for_model_change,
            inputs=[model_selector, lora_selector],
            outputs=[lora_selector, lora_status],
            show_progress="hidden",
        )
        api_test_button.click(
            api_connection_status,
            inputs=[api_base_input, api_key_input, external_model_name],
            outputs=api_status,
            show_progress="minimal",
        )
        runtime_inputs = [
            api_base_input,
            external_model_name,
            model_selector,
            adaptive_scheduling,
            gpu_memory_gb,
            model_quantization,
            api_key_input,
        ]
        for setting_component in runtime_inputs:
            setting_component.change(
                runtime_profile_status,
                inputs=runtime_inputs,
                outputs=runtime_profile,
                show_progress="hidden",
            )
        runtime_preset_event = runtime_preset.change(
            _apply_runtime_preset,
            inputs=runtime_preset,
            outputs=[
                temperature,
                top_p,
                top_k,
                frequency_penalty,
                presence_penalty,
                adaptive_scheduling,
            ],
            show_progress="hidden",
        )
        runtime_preset_event.then(
            runtime_profile_status,
            inputs=runtime_inputs,
            outputs=runtime_profile,
            show_progress="hidden",
        )
        switch_event = switch_model_button.click(
            switch_vllm_model,
            inputs=[model_selector, lora_selector],
            outputs=[
                model_status,
                model_switch_progress,
                model_selector,
                switch_model_button,
                refresh_model,
            ],
            show_progress="hidden",
            concurrency_limit=DEMO_HEAVY_CONCURRENCY_LIMIT,
            concurrency_id=DEMO_HEAVY_CONCURRENCY_ID,
            stream_every=0.5,
        )
        # Switching vLLM also changes the model-specific client profile;
        # refresh the profile card after the streaming switch completes.
        switch_event.then(
            runtime_profile_status,
            inputs=runtime_inputs,
            outputs=runtime_profile,
            show_progress="hidden",
        )
        strategy_inputs = [
            impact_method,
            feasibility_method,
            dfd_format,
            scope,
            enable_reason,
            enable_asset_details,
            enable_rag,
            capture_audit,
            implemented_requirement_reassessment,
            two_stage_requirement_reassessment,
            requirement_scope,
        ]
        impact_sync_event = impact_method.change(
            _sync_feasibility,
            inputs=[impact_method, feasibility_method],
            outputs=feasibility_method,
            show_progress="hidden",
        )
        impact_sync_event.then(
            summary_renderer,
            inputs=strategy_inputs,
            outputs=strategy_summary,
            show_progress="hidden",
        )
        feasibility_sync_event = feasibility_method.change(
            _sync_impact,
            inputs=[feasibility_method, impact_method],
            outputs=impact_method,
            show_progress="hidden",
        )
        feasibility_sync_event.then(
            summary_renderer,
            inputs=strategy_inputs,
            outputs=strategy_summary,
            show_progress="hidden",
        )
        for strategy_component in (
            scope,
            requirement_scope,
            enable_reason,
            enable_asset_details,
            enable_rag,
            implemented_requirement_reassessment,
        ):
            strategy_component.change(
                summary_renderer,
                inputs=strategy_inputs,
                outputs=strategy_summary,
                show_progress="hidden",
            )
        for preview_schema_control in (
            enable_reason, enable_asset_details, impact_method, feasibility_method,
        ):
            preview_schema_control.change(
                lambda feasibility, impact, reasons, details: _preview_update(
                    [], bool(reasons)
                ),
                inputs=[feasibility_method, impact_method, enable_reason, enable_asset_details],
                outputs=preview,
                show_progress="hidden",
            )

        run_event = run_button.click(
            run_analysis,
            inputs=[
                dfd_files,
                topology_file,
                interfaces_file,
                impact_method,
                feasibility_method,
                enable_reason,
                scope,
                enable_asset_details,
                enable_rag,
                capture_audit,
                implemented_requirement_reassessment,
                two_stage_requirement_reassessment,
                dfd_format,
                temperature,
                top_p,
                top_k,
                frequency_penalty,
                presence_penalty,
                model_selector,
                lora_selector,
                api_base_input,
                api_key_input,
                adaptive_scheduling,
                gpu_memory_gb,
                model_quantization,
                requirement_scope,
                external_model_name,
                project_name_input,
                analysis_selection,
            ],
            outputs=[
                status,
                timeline,
                trace,
                logs,
                summary,
                preview,
                excel_download,
                json_download,
                implemented_excel_download,
                implemented_json_download,
                errors_download,
                log_download,
                audit_download,
                charts,
            ],
            show_progress="minimal",
            concurrency_limit=DEMO_HEAVY_CONCURRENCY_LIMIT,
            concurrency_id=DEMO_HEAVY_CONCURRENCY_ID,
            stream_every=DEMO_PROGRESS_INTERVAL_SECONDS,
        )
        run_event.then(
            _job_id_from_trace,
            inputs=[trace],
            outputs=[job_id_input, poll_timer],
            show_progress="hidden",
            concurrency_limit=DEMO_DEFAULT_CONCURRENCY_LIMIT,
        )
        poll_outputs = [
            status, timeline, trace, logs, summary, preview,
            excel_download, json_download, implemented_excel_download,
            implemented_json_download, errors_download, log_download,
            audit_download, charts, poll_timer,
        ]
        if workspace:
            history_open_event = history_open.click(
                open_workspace_analysis_job_for_ui,
                inputs=[history_selection, enable_reason, job_id_input],
                outputs=[job_id_input, workflow_tabs, *poll_outputs], queue=False, show_progress="hidden")
            history_open_event.then(fn=None, js="() => { const root = document.querySelector('.gradio-container'); if (root) delete root.dataset.openingJob; }", queue=False)
        poll_timer.tick(
            poll_analysis_job,
            inputs=[job_id_input, enable_reason, assistant_report_state],
            outputs=poll_outputs,
            queue=False,
        )
        reconnect_button.click(
            poll_analysis_job,
            inputs=[job_id_input, enable_reason, assistant_report_state],
            outputs=poll_outputs,
            queue=False,
        )
        assistant_report_state.change(poll_analysis_job,
            inputs=[job_id_input, enable_reason, assistant_report_state], outputs=poll_outputs,
            queue=False, show_progress='hidden')
        stop_button.click(
            cancel_analysis_job,
            inputs=[job_id_input],
            outputs=[status],
            queue=False,
        )
        refresh_repair_runs_button.click(
            refresh_repair_runs,
            outputs=repair_run_path,
            show_progress="minimal",
        )
        diagnose_run_button.click(
            diagnose_current_run,
            inputs=[logs, trace],
            outputs=[supervisor_status, supervisor_trace, repair_issue, repair_run_path],
            show_progress="minimal",
        )
        handoff_repair_button.click(
            handoff_current_run,
            inputs=[logs, trace],
            outputs=[
                supervisor_status,
                supervisor_trace,
                repair_issue,
                repair_run_path,
                workspace_tabs,
            ],
            show_progress="minimal",
        )
        repair_event = repair_run_button.click(
            run_engineering_repair,
            inputs=[
                repair_issue,
                repair_run_path,
                model_selector,
                api_base_input,
                api_key_input,
                external_model_name,
            ],
            outputs=[
                repair_status,
                repair_trace,
                repair_diff,
                repair_patch_download,
                repair_report_download,
                repair_trace_download,
            ],
            show_progress="minimal",
            concurrency_limit=DEMO_HEAVY_CONCURRENCY_LIMIT,
            concurrency_id=DEMO_HEAVY_CONCURRENCY_ID,
            stream_every=0.8,
        )
        repair_stop_button.click(
            fn=None,
            cancels=[repair_event],
            queue=False,
        )

    return demo


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="启动 AI for TARA 客户可视化 Demo")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7860)
    parser.add_argument("--share", action="store_true")
    parser.add_argument("--username", help="可选的 HTTP Basic 用户名")
    parser.add_argument("--password", help="可选的 HTTP Basic 密码")
    parser.add_argument("--open", action="store_true", help="启动后打开浏览器")
    parser.add_argument("--ui", choices=["classic", "workspace"], help="界面版本；7860、7868 默认 workspace，其余端口默认 classic")
    return parser


def main() -> None:
    args = _parser().parse_args()
    if not 1 <= args.port <= 65535:
        raise SystemExit("--port 必须位于 1~65535")
    username = args.username or os.getenv("TARA_DEMO_USERNAME", "")
    password = args.password or os.getenv("TARA_DEMO_PASSWORD", "")
    if bool(username) != bool(password):
        raise SystemExit("请同时配置工作台用户名和密码")
    if (args.host not in {"127.0.0.1", "::1", "localhost"} or args.share) and not username:
        raise SystemExit("外部访问工作台需要配置 TARA_DEMO_USERNAME 和 TARA_DEMO_PASSWORD")
    DEMO_ROOT.mkdir(parents=True, exist_ok=True)
    install_history(PROJECT_ROOT / "docs" / "case", DEMO_ROOT / "jobs", DEMO_QUEUE_ROOT)
    if configured_api():
        demo_jobs.ensure_worker(DEMO_QUEUE_ROOT, python_bin=PYTHON_BIN)
    workspace = (args.ui or "workspace") == "workspace"
    demo = build_demo(workspace=workspace)
    if workspace:
        from automotive_tara.demo_workspace import WORKSPACE_CSS
    from automotive_tara.demo_assistant import ASSISTANT_CSS
    attack_tree_css = Path(__file__).with_name("attack_tree.css").read_text(encoding="utf-8")
    demo.queue(
        max_size=DEMO_QUEUE_MAX_SIZE,
        default_concurrency_limit=DEMO_DEFAULT_CONCURRENCY_LIMIT,
    )
    demo.launch(
        server_name=args.host,
        server_port=args.port,
        share=args.share,
        inbrowser=args.open,
        auth=(username, password) if username else None,
        allowed_paths=[
            str(DEMO_ROOT),
            str(PROJECT_ROOT / "data" / "input"),
            str(PROJECT_ROOT / 'outputs/demo_assistant_artifacts'),
        ],
        max_file_size="100mb",
        show_error=True,
        footer_links=[],
        css=(WORKSPACE_CSS if workspace else DEMO_CSS) + ASSISTANT_CSS + attack_tree_css
        + Path(__file__).with_name("demo_risk_charts.css").read_text(encoding="utf-8"),
    )


if __name__ == "__main__":
    main()
