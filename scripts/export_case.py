"""Export a historical run for public viewing using a strict field allowlist."""
import argparse
import json
from collections import Counter
from pathlib import Path

IMPACT = ("Safety", "Finance", "Operation", "Privacy")
FEASIBILITY = ("Exposure_time", "Professional_experience", "Required_information",
               "Required_equipment", "Opportunity_window")
ATTRIBUTES = {
    "完整性": "篡改", "机密性": "信息泄露", "真实性": "欺骗",
    "可用性": "拒绝服务", "不可抵赖性": "抵赖", "权限属性": "越权",
}
LEVELS = {"Negligible", "Moderate", "Major", "Severe", "Low", "Medium", "High", "Very Low"}
TREATMENTS = {"风险接受", "风险缓解", "风险规避", "风险转移", "风险分担"}
STATUSES = {"VALID", "NOT_APPLICABLE", "INPUT_MAPPING_CONFLICT", "TOPOLOGY_UNCOVERED", "MODEL_FAILED"}
REQUIREMENT_STATUSES = {"matched", "implemented", "not_applicable", "unmatched"}
ELEMENT_TYPES = {"tm.Flow", "tm.Process", "tm.Store", "tm.Actor"}
ASSET_TYPES = {"信号", "部件", "数据", "外部实体"}
STAGES = {
    1: "DFD 资产解析", 2: "拓扑路径框架", 3: "属性扩展与知识检索",
    4: "损害与威胁场景", 5: "影响评级与路径生成", 6: "路径生成",
    7: "攻击可行性评估", 8: "风险评估与报告生成", 9: "安全需求实施后复评",
}


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")


def numeric(row, key):
    value = row.get(key)
    return value if type(value) in {int, float} else None


def choice(row, key, values):
    value = row.get(key)
    return value if isinstance(value, str) and value in values else ""


def project_report(report, requirement_ids):
    functions = []
    asset_number = 0
    for index, function in enumerate(report, 1):
        assets = []
        for asset in function["assets"]:
            asset_number += 1
            asset_id = f"A-{asset_number:02}"
            attributes = []
            for scenario in asset["security_attributes"]:
                attribute = choice(scenario, "attribute_name", ATTRIBUTES)
                attacks = []
                for number, attack in enumerate(scenario.get("attack") or [], 1):
                    # Preserve order and hop count without publishing the route, nodes or interface.
                    hops = len((attack.get("topology_trace") or {}).get("raw_link_ids_by_hop") or [])
                    reqs = []
                    for requirement in attack.get("security_requirements") or []:
                        original = requirement.get("requirement_id")
                        if original:
                            alias = requirement_ids.setdefault(original, f"SR-{len(requirement_ids)+1:03}")
                            reqs.append({"requirement_id": alias, "name": alias})
                    params = attack.get("attack_parameters") or {}
                    attacks.append({
                        "attack_path": f"路径 {number:02} · 拓扑链路 {hops} 跳",
                        "attack_parameters": {k: numeric(params, k) for k in FEASIBILITY},
                        "feasibility_score": numeric(attack, "feasibility_score"),
                        "feasibility_level": choice(attack, "feasibility_level", LEVELS),
                        "risk_value": numeric(attack, "risk_value"),
                        "risk_treatment": choice(attack, "risk_treatment", TREATMENTS),
                        "security_requirements": reqs,
                        "security_requirement": "、".join(r["requirement_id"] for r in reqs),
                        "security_requirement_match_status": choice(attack, "security_requirement_match_status", REQUIREMENT_STATUSES),
                        "security_requirements_implemented": attack.get("security_requirements_implemented") is True,
                    })
                impact = scenario.get("influence_parameters") or {}
                attributes.append({
                    "attribute_name": attribute, "threat_type": ATTRIBUTES.get(attribute, ""),
                    "damage_scenario": f"{asset_id} 的{attribute}受损",  # Public summary, not the original text.
                    "threat_scenarios": ATTRIBUTES.get(attribute, ""),
                    "analysis_status": choice(scenario, "analysis_status", STATUSES),
                    "influence_parameters": {k: numeric(impact, k) for k in IMPACT},
                    "impact_value": numeric(scenario, "impact_value"),
                    "impact_level": choice(scenario, "impact_level", LEVELS),
                    "impact_method": "21434", "feasibility_method": "attack_potential",
                    "task_risk_value": numeric(scenario, "task_risk_value"),
                    "task_risk_treatment": choice(scenario, "task_risk_treatment", TREATMENTS),
                    "attack": attacks,
                })
            assets.append({
                "element_id": asset_id, "element_index": asset_id, "asset_name": "资产 " + asset_id,
                "dfd_element_type": choice(asset, "dfd_element_type", ELEMENT_TYPES),
                "asset_type": choice(asset, "asset_type", ASSET_TYPES),
                "security_attributes": attributes,
            })
        functions.append({"function": f"功能 F-{index:02}", "assets": assets})
    return functions


def coverage(report):
    assets = [a for f in report for a in f["assets"]]
    attributes = [s for a in assets for s in a["security_attributes"]]
    return dict(functions=len(report), assets=len(assets), tasks=len(attributes),
                attack_paths=sum(len(s["attack"]) for s in attributes),
                statuses=dict(Counter(s["analysis_status"] for s in attributes)))


def identity(report):
    return [(f["function"], [(a["element_id"], [(s["attribute_name"], len(s["attack"]))
             for s in a["security_attributes"]]) for a in f["assets"]]) for f in report]


def source_identity(report):
    return [(f["function"], [(a.get("element_id"), a.get("element_index"), [
        (s["attribute_name"], [(p.get("topology_trace") or {}).get("path_id") for p in s["attack"]])
        for s in a["security_attributes"]]) for a in f["assets"]]) for f in report]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path, help="Directory containing the historical run_manifest.json")
    parser.add_argument("--out", type=Path, default=Path("docs/case"))
    args = parser.parse_args()
    manifest = json.loads((args.run / "run_manifest.json").read_text(encoding="utf-8"))
    cfg = manifest["configuration"]["effective"]
    if any(cfg.get(k) for k in ("TARA_ASSET_SELECTION_PATH", "TARA_TEST_ASSET_SELECTION", "TARA_TEST_MAX_ASSETS")):
        parser.error("select a run that did not subset assets")
    if (cfg.get("TARA_IMPACT_METHOD"), cfg.get("TARA_FEASIBILITY_METHOD")) != ("21434", "attack_potential"):
        parser.error("this exporter supports ISO/SAE 21434 impact and Attack Potential feasibility")
    outputs = manifest["outputs"]
    if outputs.get("report_variant") != "security_requirements_implemented":
        parser.error("select a completed run with baseline and residual reports")
    ids, reports, originals = {}, {}, {}
    for variant, field in (("baseline", "baseline_json"), ("residual", "json")):
        originals[variant] = json.loads((args.run / Path(outputs[field]).name).read_text(encoding="utf-8"))
        reports[variant] = project_report(originals[variant], ids)
    baseline, residual = reports.values()
    expected = manifest["counts"]
    counts = coverage(baseline)
    if (any(counts[key] != expected[key] for key in counts)
            or coverage(residual) != counts
            or source_identity(originals["baseline"]) != source_identity(originals["residual"])
            or identity(baseline) != identity(residual)):
        parser.error("the two reports must match the manifest, cover all input assets and align by path")
    stages = {}
    for name, seconds in manifest["stage_seconds"].items():
        prefix = name.partition(":")[0].removeprefix("Step ")
        if prefix.isnumeric() and int(prefix) in STAGES:
            stages[STAGES[int(prefix)]] = round(seconds, 3)
    from datetime import datetime
    timestamp = datetime.fromisoformat(manifest["finish_time"]).isoformat(timespec="seconds")
    metadata = {
        "title": "历史案例 · 全量资产分析", "completed_at": timestamp,
        "elapsed_seconds": round(manifest["elapsed_seconds"], 3), "counts": counts,
        "input_asset_records": expected["input_asset_records"],
        "stages": stages, "impact_method": "ISO/SAE 21434", "feasibility_method": "Attack Potential",
        "reused_stage_results": bool((manifest.get("semantic_cache") or {}).get("hits")),
    }
    args.out.mkdir(parents=True, exist_ok=True)
    from automotive_tara.excel_export import ExcelExportOptions, export_tara_report_to_excel

    for variant, report in reports.items():
        out = args.out / f"{variant}.json"
        write_json(out, report)
        export_tara_report_to_excel(str(out), str(out.with_suffix(".xlsx")),
                                    options=ExcelExportOptions(enable_reason=False))
    write_json(args.out / "summary.json", metadata)


if __name__ == "__main__":
    main()
