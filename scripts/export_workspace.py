"""Export the original Gradio workspace and its recorded, read-only case."""
import argparse
from importlib.metadata import distribution
import json
from pathlib import Path
import re
import shutil
from urllib.request import ProxyHandler, Request, build_opener

import gradio

from automotive_tara.attack_tree import asset_catalog
from automotive_tara.demo_attack_tree import AttackTreeController
from automotive_tara.demo_portable import CASE_ID

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
FILES = {"baseline.xlsx", "baseline.json", "residual.xlsx", "residual.json", "tara_run.log"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base", help="Local standalone workbench, started without API configuration")
    base = parser.parse_args().base.rstrip("/")
    opener = build_opener(ProxyHandler({}))

    def get(path, payload=None):
        body = json.dumps(payload).encode() if payload is not None else None
        request = Request(base + path, data=body, headers={"Content-Type": "application/json"})
        with opener.open(request, timeout=30) as response:
            return response.read()

    def dump(path, value):
        path.write_text(json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")

    def public(value):
        if isinstance(value, dict):
            if value.get("meta", {}).get("_type") == "gradio.FileData":
                name = Path(value["path"]).name
                if name not in FILES:
                    raise ValueError(f"Unexpected file in workspace response: {name}")
                return {**value, "path": name, "url": f"__SITE_ROOT__/case/{name}"}
            return {key: public(item) for key, item in value.items()}
        if isinstance(value, list):
            return [public(item) for item in value]
        if isinstance(value, str):
            return value.replace(base, "__SITE_ROOT__").replace(str(ROOT) + "/outputs/customer_demo/jobs/" + CASE_ID + "/result/run", "历史案例归档目录")
        return value

    config = json.loads(get("/config"))
    deps = {dep["api_name"]: dep for dep in config["dependencies"]}
    for dep in config["dependencies"]:
        dep["queue"] = False
    config["enable_queue"] = False
    config["connect_heartbeat"] = False
    for component in config["components"]:
        component.pop("example_inputs", None)

    def predict(name, inputs):
        payload = {"fn_index": deps[name]["id"], "data": inputs}
        return public(json.loads(get("/gradio_api/run/predict", payload)))

    target = DOCS / "workspace"
    trees = target / "trees"
    trees.mkdir(parents=True, exist_ok=True)
    for name, inputs in {
        "refresh_workspace_overview": [],
        "refresh_workspace_history": ["", "all", 1],
        "open_workspace_analysis_job_for_ui": [CASE_ID + "|delivery", False, None],
        "poll_analysis_job": [CASE_ID, False, None],
    }.items():
        dump(target / f"{name}.json", predict(name, inputs))

    run = ROOT / "outputs/customer_demo/jobs" / CASE_ID / "result/run"
    path = run / "residual.json"
    report = json.loads(path.read_text())
    state = {"source": str(path), "signature": [path.stat().st_mtime_ns, path.stat().st_size], "job_id": CASE_ID}
    controller = AttackTreeController(run.parents[2], None)
    entries = asset_catalog(report)
    dump(trees / "index.json", [[entry["label"], entry["id"]] for entry in entries])
    for entry in entries:
        frame, source, details = controller.select(entry["id"], state)
        frame = re.sub(r"\./gradio_api/file=[^&]*?/mermaid-11\.4\.1\.min\.js",
                       "./workspace/mermaid-11.4.1.min.js", frame)
        dump(trees / (entry["id"] + ".json"), [frame, source, details])
    shutil.copyfile(run / "tara_run.log", DOCS / "case/tara_run.log")
    shutil.copyfile(controller.export(state), DOCS / "case/attack-trees.zip")

    if gradio.__version__ != config["version"]:
        raise ValueError("Local Gradio distribution differs from the workbench")
    frontend = Path(gradio.__file__).parent / "templates/frontend"
    shutil.copytree(frontend / "assets", DOCS / "assets", dirs_exist_ok=True, ignore=shutil.ignore_patterns("*.map"))
    for name in ("mermaid-11.4.1.min.js", "MERMAID-LICENSE.txt"):
        shutil.copyfile(ROOT / "automotive_tara/static" / name, target / name)
    shutil.copyfile(ROOT / "web/workspace.js", target / "workspace.js")
    (DOCS / "theme.css").write_bytes(get("/theme.css"))
    for family in ("SourceSansPro", "IBMPlexMono"):
        shutil.copytree(frontend / "static/fonts" / family, DOCS / "static/fonts" / family,
                        dirs_exist_ok=True)
    package = distribution("gradio")
    license_path = next(item for item in package.files if str(item).endswith(".dist-info/licenses/LICENSE"))
    shutil.copyfile(package.locate_file(license_path), DOCS / "GRADIO-LICENSE.txt")

    html = get("/").decode()
    html = re.sub(r"<script>window\.gradio_(?:config|api_info) = .*?</script>", "", html, flags=re.S)
    html = re.sub(r'<link rel="manifest"[^>]*>', "", html)
    html = re.sub(r"<script\s+src=\"[^\"]*iframeResizer[^\"]*\"\s*></script>", "", html)
    html = re.sub(r'<meta\s+property="og:image"\s+content="https://raw\.githubusercontent\.com/[^"]*"\s*/>', "", html)
    safe_config = json.dumps(public(config), ensure_ascii=False).replace("<", r"\u003c")
    setup = f'<script>window.gradio_config = {safe_config};</script>\n<script src="./workspace/workspace.js"></script>\n'
    html = html.replace('lang="en"', 'lang="zh-CN"', 1)
    html = html.replace('<script type="module"', setup + '<script type="module"', 1)
    (DOCS / "index.html").write_text(html, encoding="utf-8")


if __name__ == "__main__":
    main()
