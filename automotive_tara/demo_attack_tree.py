"""Lazy, session-scoped attack-tree presentation and downloadable artifacts."""

from __future__ import annotations

from functools import lru_cache
from html import escape
import hashlib
import json
from pathlib import Path
import re
import tempfile
from urllib.parse import quote
import zipfile

import gradio as gr

from .attack_tree import TREE_VERSION, asset_catalog, build_asset_tree, tree_mermaid, tree_views


MERMAID_ROOT = Path(__file__).with_name("static")
MERMAID_JS = MERMAID_ROOT / "mermaid-11.4.1.min.js"
VIEWER_TEMPLATE = Path(__file__).with_name("attack_tree_viewer.html").read_text(encoding="utf-8")
ARTIFACT_REVISION = hashlib.sha256(
    VIEWER_TEMPLATE.encode() + Path(__file__).read_bytes() + Path(__file__).with_name("attack_tree.py").read_bytes()
).hexdigest()[:12]


def empty_tree(message="完成分析，或从历史任务打开报告后查看资产攻击树。") -> str:
    return f'<div class="attack-tree-empty"><span>资产攻击树</span><p>{escape(message)}</p></div>'


def viewer_document(source: str, script_url: str, views: list[dict] | None = None) -> str:
    payload = {"source": source, "views": views or [{"id": "all", "label": "完整攻击树", "source": source, "nodes": {}}]}
    data = json.dumps(payload, ensure_ascii=False).replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
    return VIEWER_TEMPLATE.replace("__MERMAID_SCRIPT_URL__", escape(script_url, quote=True)).replace("__MERMAID_DATA__", data)


def tree_iframe(source: str, views: list[dict] | None = None) -> str:
    script_url = "./gradio_api/file=" + quote(str(MERMAID_JS.resolve()), safe="/")
    document = viewer_document(source, script_url, views)
    return ('<iframe class="attack-tree-frame" title="资产攻击树 Mermaid 图" '
            'sandbox="allow-scripts allow-downloads" allowfullscreen loading="lazy" '
            f'srcdoc="{escape(document, quote=True)}"></iframe>')


def tree_details(tree: dict) -> str:
    rows = []
    for scenario in tree["scenarios"]:
        for path in scenario["paths"]:
            requirements = "\n".join(
                f"{r.get('requirement_id', '')} · {r.get('requirement') or r.get('name', '')}"
                for r in path["security_requirements"] if isinstance(r, dict)
            )
            values = [path["id"], path["path_id"] or "报告未提供", scenario["attribute"],
                      path["source"] + "；" + path["verification_status"], path["attack_path"],
                      requirements or "报告未关联安全需求"]
            rows.append("<tr>" + "".join(f"<td>{escape(str(v))}</td>" for v in values) + "</tr>")
        if not scenario["paths"]:
            message = "；".join(str(r) for r in scenario["status_reasons"]) or scenario["analysis_status"] or "报告未提供路径"
            rows.append(f'<tr><td>{scenario["id"]}</td><td colspan="5">{escape(message)}</td></tr>')
    damages = "".join(f'<li><b>{escape(s["id"] + " · " + s["attribute"])}</b> {escape(s["damage_scenario"] or "未提供损害场景")}</li>'
                      for s in tree["scenarios"])
    return ('<div class="attack-tree-evidence"><p>树顶标明资产名称与威胁类型，紫色节点使用简短攻击动作；点击节点查看完整描述和路径编号。'
            '仅完全相同的必要动作参与公共条件提取；AND 不表达执行顺序，具体时序以本表原始路径为准。'
            '攻击方式与弱点是否成立仍需设计审查或测试证据确认。</p>'
            f'<ul>{damages}</ul><div class="attack-tree-evidence-scroll"><table><thead><tr>'
            '<th>图内路径编号</th><th>原始 path_id</th><th>安全属性</th><th>来源与验证状态</th>'
            '<th>完整攻击路径</th><th>已关联安全需求</th></tr></thead><tbody>' + "".join(rows) + '</tbody></table></div></div>')


@lru_cache(maxsize=2)
def _catalog_snapshot(source: str, modified_ns: int, size: int) -> list[dict]:
    # File identity is part of the key; there is no stale path-only cache.
    report = json.loads(Path(source).read_text(encoding="utf-8"))
    if not isinstance(report, list):
        raise ValueError("当前任务的 JSON 不是 TARA 报告")
    return asset_catalog(report)


class AttackTreeController:
    def __init__(self, jobs_root: Path, resolve_report):
        self.jobs_root = jobs_root.resolve()
        self.resolve_report = resolve_report

    def _catalog(self, state: dict) -> list[dict]:
        if not state or not state.get("source"):
            return []
        path = Path(state["source"]).resolve()
        root = (self.jobs_root / str(state["job_id"])).resolve()
        if root.parent != self.jobs_root or root not in path.parents:
            raise ValueError("报告不属于当前任务")
        stat = path.stat()
        if [stat.st_mtime_ns, stat.st_size] != state.get("signature"):
            raise ValueError("报告已更新，请点击刷新攻击树后继续")
        return _catalog_snapshot(str(path), stat.st_mtime_ns, stat.st_size)

    @staticmethod
    def _matches(catalog, query):
        terms = str(query or "").casefold().split()
        return [entry for entry in catalog if all(term in entry["label"].casefold() for term in terms)]

    def load(self, trace, current_job, state, query="", *, force=False):
        """Polling only stats the report; a graph is built once per file version."""
        trace_job = str(((trace or {}).get("运行配置") or {}).get("job_id") or "") if isinstance(trace, dict) else ""
        job_id = str(current_job or trace_job or "").strip()
        trace = {"运行配置": {"job_id": job_id}}
        if not re.fullmatch(r"[A-Za-z0-9_.-]{6,180}", job_id):
            if state == {"job_id": ""} and not force:
                return (gr.skip(),) * 7
            return {"job_id": ""}, gr.update(choices=[], value=None), "尚未选择任务报告。", empty_tree(), "", "", gr.update(value=None, visible=False)
        try:
            path, _ = self.resolve_report(trace or {"运行配置": {"job_id": job_id}})
            path = path.resolve()
            stat = path.stat()
            new_state = {"job_id": job_id, "source": str(path), "signature": [stat.st_mtime_ns, stat.st_size], "version": TREE_VERSION}
            if new_state == state and not force:
                return (gr.skip(),) * 7
            catalog = self._catalog(new_state)
            matches = self._matches(catalog, query)
            selected = matches[0]["id"] if matches else None
            frame, source, details = self.select(selected, new_state)
            paths = sum(len(d.get("attack", []) or []) for e in catalog for d in e["asset"].get("security_attributes", []) if isinstance(d, dict))
            summary = f"当前任务：`{job_id}` · 报告资产 **{len(catalog)}** 个 · 路径记录 **{paths}** 条。每个资产一份竖版攻击树，可按攻击目标查看或切换完整资产总图。"
            return new_state, gr.update(choices=[(e["label"], e["id"]) for e in matches], value=selected), summary, frame, source, details, gr.update(value=None, visible=False)
        except (ValueError, OSError, TypeError) as exc:
            # ReportEditError subclasses ValueError; incomplete jobs remain useful.
            waiting = {"job_id": job_id, "waiting": str(exc)}
            if state == waiting and not force:
                return (gr.skip(),) * 7
            return waiting, gr.update(choices=[], value=None), f"当前任务：`{job_id}` · 报告尚不可用。", empty_tree(str(exc)), "", "", gr.update(value=None, visible=False)

    def select(self, asset_id, state):
        try:
            entry = next((e for e in self._catalog(state) if e["id"] == asset_id), None)
            if not entry:
                return empty_tree("没有匹配的资产，请调整搜索条件或选择任务报告。" if state.get("source") else "完成分析，或从历史任务打开报告后查看资产攻击树。"), "", ""
            tree = build_asset_tree(entry)
            source = tree_mermaid(tree)
            return tree_iframe(source, tree_views(tree)), source, tree_details(tree)
        except (ValueError, OSError) as exc:
            return empty_tree(str(exc)), "", ""

    def search(self, query, state, selected):
        try:
            matches = self._matches(self._catalog(state), query)
            if selected not in {e["id"] for e in matches}:
                selected = matches[0]["id"] if matches else None
            return gr.update(choices=[(e["label"], e["id"]) for e in matches], value=selected), *self.select(selected, state)
        except (ValueError, OSError) as exc:
            return gr.update(choices=[], value=None), empty_tree(str(exc)), "", ""

    def export(self, state):
        try:
            catalog = self._catalog(state)
            if not catalog:
                raise ValueError("请先选择已生成报告的任务")
            export_root = self.jobs_root / state["job_id"] / "attack_trees"
            export_root.mkdir(exist_ok=True)
            signature = "-".join(map(str, state["signature"]))
            target = export_root / f"{TREE_VERSION}-{ARTIFACT_REVISION}-{signature}.zip"
            if not target.is_file():
                with tempfile.NamedTemporaryFile(dir=export_root, suffix=".zip", delete=False) as temp:
                    temporary = Path(temp.name)
                try:
                    index = []
                    with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                        archive.write(MERMAID_JS, "mermaid-11.4.1.min.js")
                        archive.write(MERMAID_ROOT / "MERMAID-LICENSE.txt", "MERMAID-LICENSE.txt")
                        for number, entry in enumerate(catalog, 1):
                            tree = build_asset_tree(entry)
                            mermaid = tree_mermaid(tree)
                            title = f"{entry['identity']['function']}-{entry['identity']['asset_name']}"
                            safe_name = re.sub(r"[^\w\-\u4e00-\u9fff]+", "_", title)[:80]
                            stem = f"{number:03d}-{safe_name}-{entry['id']}"
                            archive.writestr(stem + ".mmd", mermaid)
                            archive.writestr(stem + ".json", json.dumps(tree, ensure_ascii=False, indent=2))
                            archive.writestr(stem + ".html", viewer_document(mermaid, "mermaid-11.4.1.min.js", tree_views(tree)))
                            index.append({"asset_id": entry["id"], "label": entry["label"], "file": stem})
                        archive.writestr("index.json", json.dumps({"job_id": state["job_id"], "source_report": Path(state["source"]).name,
                            "version": TREE_VERSION, "renderer_revision": ARTIFACT_REVISION, "assets": index}, ensure_ascii=False, indent=2))
                        archive.writestr("README.md", "# 资产攻击树\n\n每个资产包含 .mmd（Mermaid 源码）、.html（离线查看）和 .json（追溯数据）。\n"
                            "解压后打开资产 HTML 文件；Mermaid 已随包提供，无需联网。index.json 列出所有资产。\n"
                            "竖版自上而下拆解最终目标、攻击方式、必要子目标和具体动作。\n"
                            "默认逐攻击目标查看，可切换完整资产总图。点击节点查看原文与路径引用。\n"
                            "树顶只显示资产与威胁类型，叶子节点使用简短攻击动作，不照搬场景和路径长句。\n"
                            ".mmd 与图形保持一致；完整场景、原始攻击动作及路径编号保留在 HTML 节点详情和 JSON 中。\n"
                            "完全相同的动作可共享为必要条件；保留原路径组合，不把不同路径的前后半段交叉拼接。\n"
                            "OR：任一分支满足；AND：所有条件满足，执行顺序以原始路径步骤编号为准。\n"
                            "攻击描述来自任务报告，不代表已验证漏洞或攻击成功；缺失路径明确展示，不补造分支。\n"
                            "评级沿用原报告逐路径结果，未对叶子节点或整树重新计算分数。\n")
                    temporary.replace(target)
                finally:
                    temporary.unlink(missing_ok=True)
            return str(target)
        except (ValueError, OSError) as exc:
            raise gr.Error(str(exc)) from exc

    def download(self, state):
        return gr.update(value=self.export(state), visible=True)
