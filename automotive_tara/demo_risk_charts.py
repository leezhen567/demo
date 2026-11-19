"""Report-derived ring charts and compact, browser-local filtering data."""

import hashlib
import json
from collections import Counter
from html import escape

from automotive_tara.domain import HEAVENS_RISK_NUM, normalize_attack_vector


VECTOR_LABELS = {
    "network": "网络 · Network", "adjacent": "邻近 · Adjacent",
    "local": "本地 · Local", "physical": "物理 · Physical",
    "unknown": "未标注 / 未识别",
}


def risk_bucket(attack: dict, attribute: dict) -> str:
    if attribute.get("analysis_status", "VALID") != "VALID":
        return "unrated"
    # Explicitly missing numeric scores (failed reassessments) remain unrated.
    value = attack.get("risk_value_num", attack.get("risk_value"))
    if isinstance(value, bool):
        return "unrated"
    if isinstance(value, str):
        value = HEAVENS_RISK_NUM.get(value.strip(), value.strip())
    try:
        number = float(value)
        return str(int(number)) if number.is_integer() and 1 <= number <= 5 else "unrated"
    except (TypeError, ValueError, OverflowError):
        return "unrated"


def portrait_data(report: list) -> list[dict]:
    """Export only chart dependencies; no prompts, paths, credentials or RAG text."""
    assets = {}
    for function in report:
        function_name = str(function.get("function") or "未命名功能")
        for index, asset in enumerate(function.get("assets", []) or []):
            name = str(asset.get("asset_name") or "未命名资产")
            identity = (function_name, str(asset.get("element_id") or ""),
                        str(asset.get("element_index") or ""), name,
                        str(asset.get("asset_type") or ""),
                        str(asset.get("source") or ""), str(asset.get("target") or ""))
            if not identity[1] and not identity[2]:
                identity += (index,)
            context = " · ".join(dict.fromkeys(str(value) for value in (
                function_name, asset.get("asset_type"), asset.get("element_index"),
                asset.get("source"), asset.get("target"),
                f'ID {asset["element_id"]}' if asset.get("element_id") else None,
            ) if value))
            row = assets.setdefault(identity, {"label": name, "context": context, "attributes": []})
            for attribute in asset.get("security_attributes", []) or []:
                attacks = []
                for attack in attribute.get("attack", []) or []:
                    parameters = attack.get("attack_parameters") or {}
                    vector = normalize_attack_vector(str(attack.get("attack_vector")
                        or parameters.get("attack_vector") or parameters.get("vector") or "")) or "unknown"
                    attacks.append([risk_bucket(attack, attribute), vector,
                                    str(attack.get("feasibility_level") or "未评级")])
                row["attributes"].append({
                    "label": str(attribute.get("attribute_name") or "未标注安全属性"),
                    "impact": str(attribute.get("impact_level") or "未评级"), "attacks": attacks,
                })
    return list(assets.values())


def summarize_portrait(data: list[dict], *, assets: str = "", attributes: str = "", vectors: str = "") -> dict:
    """Impact counts asset attributes; feasibility/risk count matching paths."""
    impact, feasibility, risk = Counter(), Counter(), Counter()
    selected_assets = 0
    for index, asset in enumerate(data):
        if assets and assets != str(index):
            continue
        matched = not asset["attributes"] and not attributes and not vectors
        for attribute in asset["attributes"]:
            if attributes and attributes != attribute["label"]:
                continue
            attacks = [attack for attack in attribute["attacks"] if not vectors or vectors == attack[1]]
            if vectors and not attacks:
                continue
            matched = True
            impact[attribute["impact"]] += 1
            for bucket, _, level in attacks:
                feasibility[level] += 1
                risk["未评级" if bucket == "unrated" else bucket] += 1
        selected_assets += int(matched)
    return {"impact": impact, "feasibility": feasibility, "risk": risk,
            "assets": selected_assets, "attributes": sum(impact.values()), "paths": sum(risk.values())}


def portrait_open(data: list[dict], title: str) -> str:
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    key = hashlib.sha256((title + payload).encode()).hexdigest()[:24]
    attributes = list(dict.fromkeys(attr["label"] for asset in data for attr in asset["attributes"]))
    present_vectors = {attack[1] for asset in data for attr in asset["attributes"] for attack in attr["attacks"]}
    choices = {
        "assets": [(str(index), f'{asset["label"]} · {asset["context"]}') for index, asset in enumerate(data)],
        "attributes": [(label, label) for label in attributes],
        "vectors": [(key, label) for key, label in VECTOR_LABELS.items() if key in present_vectors],
    }
    filters = []
    for dimension, label, all_label in (
        ("assets", "资产", "全部资产"), ("attributes", "安全属性", "全部安全属性"),
        ("vectors", "攻击向量", "全部攻击向量"),
    ):
        options = ''.join(f'<option value="{escape(value, quote=True)}">{escape(text)}</option>'
                          for value, text in choices[dimension])
        filters.append(f'<label><span>{label}</span><select aria-label="风险画像筛选：{label}" data-risk-filter="{dimension}">'
                       f'<option value="">{all_label}</option>{options}</select></label>')
    summary = summarize_portrait(data)
    return (f'<div class="risk-portrait" data-risk-version="3" data-portrait-id="{key}" data-risk-payload="{escape(payload, quote=True)}">'
            '<section class="risk-portrait-toolbar" aria-label="风险画像筛选">'
            '<div class="risk-filter-heading"><div><b>分析范围</b><span>筛选条件同步应用于下方三张图</span></div>'
            '<button type="button" data-risk-reset><span aria-hidden="true">↺</span>重置筛选</button></div>'
            '<div class="risk-portrait-filters">' + ''.join(filters) + '</div>'
            f'<div class="risk-filter-summary" role="status">整份报告 · {summary["assets"]} 个资产 · '
            f'{summary["attributes"]} 项资产属性 · {summary["paths"]} 条路径</div></section>')
