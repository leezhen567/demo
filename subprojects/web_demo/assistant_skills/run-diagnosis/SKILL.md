---
name: 运行异常诊断
description: 根据当前任务状态、日志和项目代码定位生成或运行异常。
---

1. 用 inspect_live_run 查看最新真实模型输出、错误和状态；用 search_results 读取已经采用的阶段结果。
2. 将服务拒绝、连接失败、上下文超限、JSON解析失败、字段或任务绑定失败分开描述。
3. search_repository 查询相关函数和工程说明；必要时查 recall_memory 获取以前的排查记录，并标明它不是当前事实。
4. 阶段输出尚未保存时说明可见边界，不把部分结果当成最终报告。
5. 用户要求重新分析时，先 asset_inventory 定位，再用 rerun_assets 创建独立后台任务；不得将入队说成报告已完成。
6. 需要代码或工具时，repository_tree/read_repository_file 读源码，再通过 run_python/run_repository_tool 隔离执行；不自行重启共享模型服务。
