---
name: 项目输入检查
description: 检查资产、DFD端点、通信协议、拓扑与接口对应关系。
---

1. 使用 project_overview 确认当前项目及输入是否齐全。
2. 用 search_inputs 定位用户指定的资产、信号或数据；名称相同的对象要结合文件、ID和端点区分。
3. 用 validate_inputs 调用工程的一致性校验。对协议、端点及悬空关系的结论引用实际校验记录。
4. 询问修改影响时用 analyze_dependencies 分析；用户要求修改/删除时，用 read_project_file/asset_inventory 定位后调用 edit_project_inputs 真正修改副本。
5. 用户说“不分析某资产”时用 set_analysis_scope 排除分析身份，保留拓扑；要求开始分析时调用 start_analysis。
5. 引用文件和对象位置，列出确定事实、缺失资料及下一步建议。记忆中的约束不能覆盖新输入。
