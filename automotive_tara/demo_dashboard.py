"""Read-only workspace views backed by the durable queue and report artifacts."""

from __future__ import annotations

import json
import math
import re
import sqlite3
from collections import Counter
from datetime import datetime
from functools import lru_cache
from html import escape
from pathlib import Path
from zoneinfo import ZoneInfo


STATUS_LABELS = {
    "queued": "排队中", "running": "分析中", "cancelling": "停止中",
    "completed": "已完成", "failed": "失败", "cancelled": "已停止",
}
METHOD_LABELS = {"attack_potential": "Attack Potential", "attack_vector": "Attack Vector", "cvss": "CVSS", "heavens": "HEAVENS"}
COLORS = {"5": "#e65768", "4": "#f3a64a", "3": "#4389ee", "2": "#45b3a6", "1": "#74b894", "unrated": "#ccd6e2"}


@lru_cache(maxsize=256)
def _json_version(path: str, modified: int, size: int):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def read_json(path: Path):
    try:
        stat = path.stat()
        return _json_version(str(path), stat.st_mtime_ns, stat.st_size)
    except (OSError, ValueError, TypeError):
        return {}


def _job_root(jobs_root: Path, job_id: str) -> Path | None:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{6,180}", job_id):
        return None
    parent = jobs_root.resolve()
    candidate = (parent / job_id).resolve()
    return candidate if candidate.parent == parent else None


def display_time(value: str) -> str:
    try:
        return datetime.fromisoformat(str(value)).astimezone(ZoneInfo("Asia/Shanghai")).strftime("%m-%d %H:%M")
    except (ValueError, TypeError):
        return "—"


def read_catalog(queue_root: Path, jobs_root: Path) -> list[dict]:
    """Never create a database or expose a job's credentials/environment."""
    database = queue_root / "queue.sqlite3"
    if not database.is_file():
        return []
    try:
        connection = sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True, timeout=2)
        connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute("SELECT job_id,status,created_at,updated_at FROM jobs ORDER BY created_at DESC,job_id DESC").fetchall()
        finally:
            connection.close()
    except sqlite3.Error:
        raise RuntimeError("暂时无法读取任务记录，请稍后刷新。") from None
    records = []
    for row in rows:
        item = dict(row)
        root = _job_root(jobs_root, item["job_id"])
        if root is None:
            continue
        spec = read_json(queue_root / item["job_id"] / "job_spec.json")
        manifest = read_json(root / "result" / "run" / "run_manifest.json")
        spec = spec if isinstance(spec, dict) else {}
        manifest = manifest if isinstance(manifest, dict) else {}
        item.update({
            "project": str(spec.get("project_name") or manifest.get("project_name") or "未命名项目"),
            "model": str(spec.get("model") or "未记录"),
            "method": str(spec.get("feasibility_method") or "attack_potential"),
            "has_report": False,
        })
        path = _report_path(root, manifest)
        item["has_report"] = path is not None and item["status"] == "completed"
        records.append(item)
    return records


def _report_path(root: Path, manifest: dict) -> Path | None:
    value = (manifest.get("outputs") or {}).get("json")
    if not value:
        return None
    try:
        path = Path(str(value)).resolve()
        if root.resolve() in path.parents and path.is_file():
            return path
    except (OSError, ValueError):
        pass
    return None


@lru_cache(maxsize=32)
def _report_summary(path: str, modified: int, size: int) -> dict:
    report = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(report, list):
        return {}
    risk = Counter()
    assets = paths = reviews = 0
    for function in report:
        for asset in function.get("assets", []) or []:
            assets += 1
            for attribute in asset.get("security_attributes", []) or []:
                for attack in attribute.get("attack", []) or []:
                    paths += 1
                    reviews += bool(attack.get("review_required") or attack.get("review_reasons"))
                    value = attack.get("risk_value_num", attack.get("risk_value"))
                    try:
                        number = float(value)
                        key = str(int(number)) if number.is_integer() and 1 <= number <= 5 else "unrated"
                    except (TypeError, ValueError, OverflowError):
                        key = "unrated"
                    if attribute.get("analysis_status", "VALID") != "VALID":
                        key = "unrated"
                    risk[key] += 1
    return {"assets": assets, "paths": paths, "high_risk": risk["4"] + risk["5"], "review": reviews, "risk_counts": dict(risk)}


def report_summary(jobs_root: Path, job_id: str) -> dict:
    root = _job_root(jobs_root, str(job_id))
    if root is None:
        return {}
    manifest = read_json(root / "result" / "run" / "run_manifest.json")
    if not isinstance(manifest, dict):
        return {}
    path = _report_path(root, manifest)
    if path is None:
        return {}
    try:
        stat = path.stat()
        result = dict(_report_summary(str(path), stat.st_mtime_ns, stat.st_size))
    except (OSError, ValueError, TypeError, AttributeError):
        return {}
    count = (manifest.get("counts") or {}).get("assets_analyzed")
    if isinstance(count, int):
        result["assets"] = count
    result["variant"] = (manifest.get("outputs") or {}).get("report_variant", "baseline")
    return result


def _nav(target: str, text: str, primary=False) -> str:
    return f'<button type="button" class="ws-action{" ws-action-primary" if primary else ""}" data-workspace-target="{target}">{escape(text)}</button>'


def _open(job_id: str, target: str, text: str) -> str:
    return f'<button type="button" class="ws-text-action" data-workspace-job="{escape(job_id, quote=True)}" data-workspace-open="{target}">{escape(text)}</button>'


def task_table(records: list[dict], *, recent=False) -> str:
    rows = []
    for item in records:
        actions = _open(item["job_id"], "agent", "查看进度")
        if item["has_report"]:
            actions += _open(item["job_id"], "delivery", "报告")
        state = item["status"] if item["status"] in STATUS_LABELS else "unknown"
        rows.append(
            '<tr><td><b>' + escape(item["project"]) + '</b><small>' + escape(item["job_id"]) + '</small></td>'
            '<td><span class="ws-status ' + state + '">' + escape(STATUS_LABELS.get(state, state)) + '</span></td>'
            '<td><span>' + escape(METHOD_LABELS.get(item["method"], item["method"])) + '</span><small>' + escape(item["model"]) + '</small></td>'
            '<td class="ws-time">' + escape(display_time(item["updated_at"])) + '</td><td class="ws-task-actions">' + actions + '</td></tr>'
        )
    body = ''.join(rows) or '<tr><td colspan="5" class="ws-table-empty">没有符合条件的任务。</td></tr>'
    return '<div class="ws-task-table-scroll" tabindex="0" role="region" aria-label="可滚动的分析任务列表"><table class="ws-task-table"><thead><tr><th>项目 / 任务</th><th>状态</th><th>评级方法 / 模型</th><th>更新时间</th><th>操作</th></tr></thead><tbody>' + body + '</tbody></table></div>'


def history_html(records: list[dict], query="", status="all", page=1) -> tuple[str, int]:
    query = str(query or "").strip().casefold()
    filtered = [r for r in records if (status == "all" or r["status"] == status) and (
        not query or query in ' '.join(str(r[k]) for k in ("job_id", "project", "model", "method")).casefold()
    )]
    pages = max(1, math.ceil(len(filtered) / 15))
    page = max(1, min(int(page or 1), pages))
    start = (page - 1) * 15
    return (
        '<section class="ws-widget ws-history-table"><div class="ws-widget-heading"><h2>任务记录</h2><span>共 '
        + str(len(filtered)) + ' 条 · 第 ' + str(page) + ' / ' + str(pages) + ' 页</span></div>'
        + task_table(filtered[start:start + 15]) + '</section>', page
    )


def risk_distribution(summary: dict) -> str:
    counts = summary.get("risk_counts", {})
    total = sum(counts.values())
    if not total:
        return '<div class="ws-chart-empty"><span>暂无风险分布</span><small>报告生成后显示已评级与待评级路径。</small></div>'
    segments, legend, position = [], [], 0.0
    for key in ("5", "4", "3", "2", "1", "unrated"):
        count = counts.get(key, 0)
        if not count:
            continue
        end = position + count / total * 100
        segments.append(f'{COLORS[key]} {position:.3f}% {end:.3f}%')
        position = end
        name = "待评级" if key == "unrated" else "风险 " + key
        legend.append(f'<li><span><i style="background:{COLORS[key]}"></i>{name}</span><b>{count:,}<small>{count / total:.1%}</small></b></li>')
    return '<div class="ws-risk-distribution"><div class="ws-risk-donut" style="background:conic-gradient(' + ','.join(segments) + ')"><div><b>' + f'{total:,}' + '</b><small>攻击路径</small></div></div><ul>' + ''.join(legend) + '</ul></div>'


def overview_html(records: list[dict], featured: dict | None, summary: dict, trace: str, models: list[str]) -> str:
    now = datetime.now(ZoneInfo("Asia/Shanghai")).strftime("%m-%d %H:%M:%S")
    actions = _nav("history", "历史任务") + _nav("input", "+ 新建 TARA 分析", True)
    heading = '<div class="ws-page-heading ws-overview-heading"><div><div class="ws-page-overline"><i></i>WORKSPACE OVERVIEW</div><h1>分析总览</h1><p>项目进度、风险结果与交付报告，集中查看。</p></div><div class="ws-overview-actions">' + actions + '</div></div>'
    scope = ('当前任务：' + escape(featured["project"]) + ' · ' + escape(featured["job_id"])) if featured else '开始你的第一项 TARA 分析'
    cards = []
    for key, label, note in (("assets", "已分析资产", "本次实际分析范围"), ("paths", "可信攻击路径", "按报告路径统计"), ("high_risk", "高风险路径", "风险值 ≥ 4"), ("review", "待复核路径", "报告标记的复核项")):
        value = f'{summary[key]:,}' if key in summary else '—'
        cards.append(f'<div class="ws-kpi"><span>{label}</span><b>{value}</b><small>{note}</small></div>')
    header = '<div class="ws-overview-scope"><span>' + scope + '</span><small>刷新于 ' + now + '</small></div><div class="ws-kpi-grid">' + ''.join(cards) + '</div>'
    current_action = _open(featured["job_id"], "agent", "打开工作台 →") if featured else _nav("input", "导入项目资料")
    stage = '<section class="ws-widget ws-overview-flow" data-featured-job="' + escape(featured['job_id'] if featured else '', quote=True) + '"><div class="ws-widget-heading"><div><h2>分析流程</h2><p>从资料解析到风险报告的六阶段分析</p></div>' + current_action + '</div>' + trace + '</section>'
    risk = '<section class="ws-widget"><div class="ws-widget-heading"><div><h2>风险等级分布</h2><p>对应上方任务的报告路径</p></div></div>' + risk_distribution(summary) + '</section>'
    recent = '<section class="ws-widget ws-overview-recent"><div class="ws-widget-heading"><div><h2>最近分析任务</h2><p>展示最近 5 项任务</p></div>' + _nav("history", "查看全部 →") + '</div>' + task_table(records[:5], recent=True) + '</section>'
    queues = Counter(r['status'] for r in records)
    model = escape(models[0]) if models else '服务暂未连接'
    model_note = '<span class="ws-status completed">可连接</span>' if models else '<span class="ws-status failed">未连接</span>'
    adapters = '<p class="ws-model-adapters">已加载适配器<br>' + '<br>'.join(escape(m) for m in models[1:]) + '</p>' if len(models) > 1 else ''
    service = '<section class="ws-widget ws-overview-service"><div class="ws-widget-heading"><h2>模型与任务状态</h2>' + model_note + '</div><div class="ws-service-model"><small>共享模型服务</small><b>' + model + '</b></div>' + adapters + '<div class="ws-queue-counts">' + ''.join(f'<div><b>{queues[state]}</b><span>{label}</span></div>' for state, label in (("running", "分析中"), ("queued", "排队中"), ("completed", "已完成"), ("failed", "失败"))) + '</div><p class="ws-service-note">共 ' + str(len(records)) + ' 项历史任务。状态来自后台队列；模型信息来自服务连接检查。</p>' + _nav("runtime", "查看模型服务 →") + '</section>'
    return heading + header + '<div class="ws-overview-grid">' + stage + risk + recent + service + '</div>'
