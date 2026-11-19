/* Serve the archived report to Gradio's original frontend in the browser. */
(() => {
  const site = new URL("./", location.href);
  const config = window.gradio_config;
  const fetchAsset = window.fetch.bind(window);
  const cache = new Map();
  const empty = () => ({ __type__: "update" });
  const update = (props) => ({ __type__: "update", ...props });
  const note = "当前页面为静态工作台。历史报告可直接查看。新分析和助手需启动完整工作台并配置 API。";
  const guide = "https://github.com/leezhen567/demo#ai-工作台";
  const caseId = "archive-full-assets";

  function replaceSite(value) {
    if (typeof value === "string") return value.replaceAll("__SITE_ROOT__", site.href.slice(0, -1));
    if (Array.isArray(value)) return value.map(replaceSite);
    if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, replaceSite(item)]));
    return value;
  }

  Object.assign(config, replaceSite(config), { root: site.href.slice(0, -1) });
  const deps = new Map(config.dependencies.map((dep) => [dep.id, dep]));
  const byId = new Map(config.components.map((c) => [c.id, c]));
  const memo = (path) => {
    if (!cache.has(path)) cache.set(path, fetchAsset(new URL("workspace/" + path, site)).then((response) => {
      if (!response.ok) throw new Error("历史记录加载失败");
      return response.json();
    }).then(replaceSite).catch((error) => { cache.delete(path); throw error; }));
    return cache.get(path);
  };

  let currentJob = "";
  let currentTree = null;
  const skip = (dep) => dep.outputs.map(empty);
  const archive = (name) => memo(name + ".json");
  const hasAsset = (id) => typeof id === "string" && /^[a-f0-9]+-\d+$/.test(id);
  const selectTree = (key) => hasAsset(key) ? memo("trees/" + key + ".json") : ["<p>未找到资产。</p>", "", ""];
  const treeChoices = async (query) => {
    const terms = String(query || "").toLowerCase().trim().split(/\s+/);
    return (await memo("trees/index.json")).filter(([label]) => terms.every((term) => label.toLowerCase().includes(term)));
  };

  async function run(dep, data) {
    const name = dep.api_name || "";
    if (name.startsWith("refresh_workspace_overview")) return (await archive("refresh_workspace_overview")).data;
    if (/^(refresh_workspace_history|search_workspace_history|partial(?:_1)?$)/.test(name)) {
      const [query, status] = data;
      if ((!status || status === "all" || status === "completed") && (!query || ("历史案例 · 全量资产分析 archive-full-assets 历史记录 attack_potential").includes(String(query).trim().toLowerCase()))) {
        return (await archive("refresh_workspace_history")).data;
      }
      return ['<section class="ws-widget ws-history-table"><p>没有符合条件的任务。</p></section>', 1];
    }
    if (name === "open_workspace_analysis_job_for_ui" && String(data[0]).split("|")[0] === caseId) {
      currentJob = caseId;
      return (await archive(name)).data;
    }
    if (name.startsWith("poll_analysis_job") && currentJob) return (await archive("poll_analysis_job")).data;
    if (/^load(?:_\d+)?$|^partial_2$/.test(name) && currentJob) {
      if (currentTree && name !== "partial_2") return skip(dep);
      const choices = await treeChoices(data[3]);
      currentTree = choices[0]?.[1] || null;
      return [empty(), update({choices, value: currentTree}), "历史案例 · 406 个资产 · 路径详情已脱敏",
        ...await selectTree(currentTree), update({ visible: false })];
    }
    if (name === "download" && currentJob) {
      const filename = "attack-trees.zip";
      return [update({ visible: true, value: {
        path: filename, url: new URL("case/" + filename, site).href,
        orig_name: filename, meta: { _type: "gradio.FileData" },
      } })];
    }
    if (name === "select" && currentJob) return selectTree(data[0]);
    if (name === "search" && currentJob) {
      const choices = await treeChoices(data[0]);
      currentTree = choices.some((choice) => choice[1] === data[2]) ? data[2] : choices[0]?.[1] || null;
      return [update({choices, value: currentTree}), ...await selectTree(currentTree)];
    }
    if (name.startsWith("assistant_context_capacity")) return ["历史浏览", "API 尚未配置"];
    if (name === "api_connection_status" || name.startsWith("runtime_profile_status"))
      return [`<p>${note} <a href="${guide}" target="_blank" rel="noopener">启动与配置说明</a></p>`];
    if (name.startsWith("ask_from_ui") || name === "run_analysis" || name === "download" || name === "sample_project_inputs" || name.startsWith("validate_inputs_html"))
      throw new Error(note);
    return skip(dep);
  }

  const json = (data, status = 200) => new Response(JSON.stringify(data), {
    status, headers: { "Content-Type": "application/json" },
  });
  window.fetch = async (input, init) => {
    const url = new URL(input instanceof Request ? input.url : input, location.href);
    if (url.origin !== site.origin || !url.pathname.startsWith(site.pathname + "gradio_api/")) return fetchAsset(input, init);
    const route = url.pathname.slice(site.pathname.length + "gradio_api/".length);
    if (route === "run/predict") {
      try {
        const { fn_index, data } = JSON.parse(init?.body || await input.text());
        const dep = deps.get(fn_index);
        if (!dep) throw new Error("当前操作不可用");
        return json({ data: await run(dep, data || []), is_generating: false, duration: 0, average_duration: 0, changed_state_ids: [] });
      } catch (error) { return json({ error: error.message }, 400); }
    }
    if (route === "heartbeat" || route.startsWith("heartbeat/")) return new Response("", {headers: {"Content-Type": "text/event-stream"}});
    return json({ error: note }, 400);
  };

  for (const component of byId.values()) {
    if (component.type === "file" && component.props.interactive !== false) component.props.interactive = false;
  }
})();
