# TARA Demo

汽车网络安全威胁分析与风险评估演示。静态网页可在外部网络浏览历史分析，完整工作台支持上传项目资料并连接 OpenAI 兼容 API。

## 历史案例

[打开在线演示](https://leezhen567.github.io/demo/)

内置 **2026 年 9 月 22 日完成的全量运行**，分析范围未设置数量上限或抽样。DFD 有 502 条输入记录，最终报告包含 31 个功能、406 个分析资产、1,847 项安全属性和 4,833 条攻击路径。报告保留了不适用和输入映射冲突等状态。

- **运行过程**展示实际记录的阶段和耗时。该次运行复用了部分缓存结果。
- **资产报告**可以逐个查看资产、安全属性、影响评级、路径可行性、风险处置、安全需求匹配与实施后复评。
- **报告交付**提供基线与复评的 JSON 和 Excel。
- 发布副本使用匿名资产、路径和需求编号。损害和威胁文字是类别摘要。数值评级、适用性、路径顺序和需求对应关系取自原报告。实施后结果来自历史模型复评。

静态页面位于 `docs/`，可部署到任意静态主机。也可在本地运行以下命令后打开 <http://127.0.0.1:8080>。

```bash
python3 -m http.server 8080 --directory docs
```

GitHub Pages 当前从 `gh-pages` 分支的根目录发布。修改 `docs/` 后，将该目录同步到发布分支。

## AI 工作台

在 Linux 或 WSL 下，进入仓库并使用 Python 3.10 或更新版本。

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[ui]'
python -m automotive_tara.demo --host 127.0.0.1 --port 7860
```

打开 <http://127.0.0.1:7860>，进入「历史任务」，打开「历史案例 · 全量资产分析」的进度或报告。「攻击树」可按资产浏览脱敏路径。

要启用新分析和 AI 助手，请在启动前配置下面三个环境变量。API 要能从工作台服务器访问，并支持 OpenAI Chat Completions。

```bash
export TARA_API_BASE='https://api.example.com/v1'
export TARA_MODEL='your-model-id'
read -rs TARA_API_KEY
export TARA_API_KEY
python -m automotive_tara.demo --host 127.0.0.1 --port 7860
```

在「模型服务」点击「测试 API 连接」。通过后上传 DFD JSON、拓扑 JSON 和外部接口 Excel，选择评估方案并启动分析。输入格式见 [项目输入格式](subprojects/web_demo/docs/project_input_formats.md)。如需让新分析匹配自己的安全需求库，在启动前设置 `TARA_SECURITY_REQUIREMENTS_PATH` 指向合适的 Excel，在所需时提供 `TARA_SECURITY_REQUIREMENTS_LOGIC_PATH`。历史案例内置的匹配结果可直接查看。

远程部署时，将静态目录发布供访客访问。完整工作台面向授权操作人员，绑定 `0.0.0.0` 前配置 `TARA_DEMO_USERNAME` 与 `TARA_DEMO_PASSWORD`，并通过 HTTPS 反向代理访问。所有授权操作人员共享同一工作台和历史目录。

```bash
docker build -t tara-demo .
docker run --rm --env-file .env -p 127.0.0.1:7860:7860 \
  -v tara-demo-output:/app/outputs tara-demo
```

按 `.env.example` 准备本地 `.env`。`outputs/` 保存运行记录和私有队列，部署时将该目录作为私有数据卷。静态站点只发布 `docs/`。历史数据导出命令为 `python -m scripts.export_case <原运行目录>`。
