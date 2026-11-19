"use strict";

const byId = (id) => document.getElementById(id);
const impactFields = {
  Safety: "安全", Finance: "财产", Operation: "运行", Privacy: "隐私",
};
const feasibilityFields = {
  Exposure_time: "耗时", Professional_experience: "专业知识",
  Required_information: "所需信息", Opportunity_window: "机会窗口",
  Required_equipment: "设备",
};
const levels = {
  Very_Low: "很低", Low: "低", Medium: "中", High: "高",
  Negligible: "可忽略", Moderate: "中等", Major: "严重", Severe: "非常严重",
};
const statuses = { VALID: "已评级", NOT_APPLICABLE: "不适用", INPUT_MAPPING_CONFLICT: "输入映射冲突" };
const requirements = { matched: "已匹配", implemented: "按实施假设复评", not_applicable: "无需匹配", unmatched: "未匹配" };

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text != null) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function localized(value) {
  return value ? levels[value.replaceAll(" ", "_")] || value : "—";
}

function facts(row, keys) {
  const group = element("div", null, "facts");
  for (const [key, label] of Object.entries(keys)) {
    const value = row?.[key] ?? "—";
    group.append(element("span", `${label} ${value}`));
  }
  return group;
}

function pathVariant(name, path) {
  const box = element("div");
  box.append(element("h4", name),
    element("p", `可行性 ${localized(path.feasibility_level)} · 风险 ${path.risk_value ?? "—"} · ${path.risk_treatment || "—"}`),
    facts(path.attack_parameters, feasibilityFields),
    element("p", `安全需求 ${path.security_requirement || "—"} · ${requirements[path.security_requirements_implemented ? "implemented" : path.security_requirement_match_status] || "—"}`));
  return box;
}

function scenarioCard(scenario, comparison) {
  const details = element("details", null, "scenario");
  details.append(element("summary", `${scenario.attribute_name} · ${scenario.threat_type} · ${statuses[scenario.analysis_status] || scenario.analysis_status} · ${scenario.attack.length} 条路径`));
  const body = element("div", null, "scenario-body");
  body.append(element("p", `损害摘要 ${scenario.damage_scenario} · 影响等级 ${localized(scenario.impact_level)}`),
    facts(scenario.influence_parameters, impactFields));
  scenario.attack.forEach((path, index) => {
    const after = comparison.attack[index];
    const item = element("details", null, "path");
    item.append(element("summary", `${path.attack_path} · 基线风险 ${path.risk_value ?? "—"} · 复评风险 ${after.risk_value ?? "—"}`));
    const values = element("div", null, "path-body path-data");
    values.append(pathVariant("原始基线", path), pathVariant("实施后复评", after));
    item.append(values);
    body.append(item);
  });
  if (!scenario.attack.length) body.append(element("p", "该属性在本次运行中没有路径评级。", "muted"));
  details.append(body);
  return details;
}

function renderDistribution(baseline, residual) {
  function buckets(assets) {
    const result = {};
    for (const asset of assets) {
      for (const scenario of asset.security_attributes) {
        for (const path of scenario.attack) {
          const key = path.risk_value ?? "unrated";
          result[key] = (result[key] || 0) + 1;
        }
      }
    }
    return result;
  }
  const before = buckets(baseline);
  const after = buckets(residual);
  const scale = Math.max(1, ...Object.values(before), ...Object.values(after));
  for (const risk of [5, 4, 3, 2, 1, "unrated"]) {
    const a = before[risk] || 0;
    const b = after[risk] || 0;
    if (risk === "unrated" && !a && !b) continue;
    const row = element("div", null, "risk-row");
    const track = element("div", null, "track");
    track.setAttribute("aria-hidden", "true");
    for (const count of [a, b]) {
      const rail = element("div");
      const fill = element("i");
      fill.style.width = `${100 * count / scale}%`;
      rail.append(fill);
      track.append(rail);
    }
    const label = element("span", `${a} / ${b}`, "risk-figures");
    label.title = `原始基线 ${a} 条，实施后复评 ${b} 条`;
    row.append(element("span", risk === "unrated" ? "未评级" : `风险 ${risk}`), track, label);
    byId("distribution").append(row);
  }
}

function renderCase(summary, baseline, residual) {
  byId("completed").textContent = `已完成 · ${summary.completed_at.replace("T", " ")}`;
  byId("methods").textContent = `${summary.impact_method} · ${summary.feasibility_method} · DFD 输入 ${summary.input_asset_records} 条${summary.reused_stage_results ? " · 复用了历史阶段结果" : ""}`;
  for (const [label, value] of Object.entries({
    功能: summary.counts.functions, 资产: summary.counts.assets,
    安全属性: summary.counts.tasks, 攻击路径: summary.counts.attack_paths,
  })) {
    const metric = element("div", null, "metric");
    metric.append(element("strong", value), element("span", label));
    byId("metrics").append(metric);
  }
  for (const [stage, seconds] of Object.entries(summary.stages)) {
    const row = element("li");
    row.append(element("span", stage), element("span", `${seconds.toFixed(3)} 秒`));
    byId("timeline").append(row);
  }

  const assets = baseline.flatMap((f) => f.assets.map((a) => ({ ...a, function: f.function })));
  const after = residual.flatMap((f) => f.assets);
  renderDistribution(assets, after);
  const asset = byId("asset");
  const attribute = byId("attribute");
  const functionSelect = byId("function");
  for (const entry of baseline) functionSelect.add(new Option(entry.function, entry.function));

  function populateAssets(selected) {
    const choices = assets.filter((entry) => !functionSelect.value || entry.function === functionSelect.value);
    asset.replaceChildren(...choices.map((entry) => new Option(`${entry.asset_name} · ${entry.asset_type}`, entry.element_id)));
    if (choices.some((entry) => entry.element_id === selected)) asset.value = selected;
  }

  populateAssets(new URLSearchParams(location.search).get("asset"));

  function showAsset(resetAttributes) {
    const index = assets.findIndex((entry) => entry.element_id === asset.value);
    const current = assets[index];
    if (resetAttributes) {
      attribute.replaceChildren(new Option("全部属性", ""));
      for (const s of current.security_attributes) attribute.add(new Option(s.attribute_name, s.attribute_name));
    }
    const head = element("div", null, "asset-heading");
    head.append(element("h3", current.asset_name),
      element("span", `${current.function} · ${current.asset_type} · ${current.security_attributes.length} 项安全属性`));
    const target = byId("asset-detail");
    target.replaceChildren(head);
    current.security_attributes.forEach((s, i) => {
      if (!attribute.value || attribute.value === s.attribute_name) {
        target.append(scenarioCard(s, after[index].security_attributes[i]));
      }
    });
  }
  function selectAsset() {
    const url = new URL(location.href);
    url.searchParams.set("asset", asset.value);
    history.replaceState(null, "", url);
    showAsset(true);
  }
  asset.addEventListener("change", selectAsset);
  functionSelect.addEventListener("change", () => {
    populateAssets(asset.value);
    selectAsset();
  });
  attribute.addEventListener("change", () => showAsset(false));
  showAsset(true);
}

async function load(name) {
  const response = await fetch(`./case/${name}.json`);
  if (!response.ok) throw new Error(`读取 ${name} 失败`);
  return response.json();
}

Promise.all(["summary", "baseline", "residual"].map(load)).then(
  ([summary, baseline, residual]) => renderCase(summary, baseline, residual),
).catch(() => {
  byId("notice").hidden = false;
  byId("notice").textContent = "案例加载失败。请通过部署链接打开，或从仓库运行本地静态服务。";
  byId("completed").textContent = "历史记录暂不可用";
});
