---
name: 评级与风险复核
description: 核对原始评级维度、方法、风险矩阵和实施前后差异。
---

1. 用 search_results 查风险行及实际影响、可行性维度和所用方法。
2. 需要解释标准时用 retrieve_knowledge；检查完整维度是否存在，不补猜缺失分值。
3. 使用 calculate_risk 调用 automotive_tara.domain 的现有评分函数复算；query传入 method、impact 和完整 parameters。
4. Attack Potential 的原始分数越高通常代表攻击越难，不能把“降低等级”误写成“降低原始分数”。
5. 对实施前后结果逐路径对齐；解释评分依据和不一致，不为满足风险目标擅自改分。
6. 给出事实、复算结果及仍需人工判断的证据缺口。
7. 用户明确给出分值调整时，调用 revise_report 的 ratings，以 risk_id 和维度键定位；项目函数会回算风险并导出修订报告，不能只口头说已修改。
