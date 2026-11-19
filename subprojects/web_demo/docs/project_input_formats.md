# TARA 项目输入格式与数据修改 Agent

网页端的“AI 数据修改 Agent”读取上传的三个事实源：DFD JSON、拓扑 JSON、外部接口 Excel。
Agent 只返回声明式 `operations`，程序把操作应用到隔离副本；原始上传文件不会被覆盖。

## DFD JSON

新版和旧版都使用以下核心结构：

```text
detail.diagrams[].diagramJson.cells[]
```

常见元素类型如下：

| `type` | 含义 | 常用字段 |
|---|---|---|
| `tm.Process` | 部件/处理节点 | `attrs.text.text`、`propertyList0.finetermval`、`propertyList0.assetDetails` |
| `tm.Store` | 数据存储 | 同上 |
| `tm.Actor` | 外部接口或外部部件 | `attrs.text.text`、`outOfScope` |
| `tm.Flow` | 数据流/信号 | `source.id`、`target.id`、`protocol`、`attrs.text.text`、`propertyList0...` |

一个 `tm.Flow` 可以包含多个 `propertyListN`，每个带有 `finetermval` 的属性项都可能是一个独立信号资产。
`source.id` 和 `target.id` 引用同一 `cells` 数组中的节点 `id`，不要把它们当作显示名称。

新版通常只有 `attrs.text.text`；旧版还可能依赖 Flow 的 `labels[].attrs.text.text` 和 `description`。
网页选择“新版 DFD”时，系统会在运行目录生成旧版兼容副本，不会改写上传文件。

可修改示例：

```json
{"target":"dfd","file":"充放电控制.json","op":"replace_text","old":"旧资产名","new":"新资产名"}
{"target":"dfd","file":"充放电控制.json","op":"set",
 "path":"/detail/diagrams/0/diagramJson/cells/8/protocol","value":"CANFD"}
```

也可以使用语义操作 `rename_asset(old,new)` 修改 DFD 资产名称，或使用
`rename_flow_protocol(old,new)` 批量修改数据流协议；程序会同时更新 DFD 中对应的显示名/属性值。

## 拓扑 JSON

拓扑导出通常是：

```text
data.cells[]
data.lineData[]
```

节点是 `shape != "edge"` 的 cell，显示名称通常位于 `attrs.text.text`；边是 `shape == "edge"`，通过
`source.cell`、`target.cell` 连接节点，通信线路位于 `attrs.line.id` / `attrs.line.stroke`。
`lineData[].name` 是线路语义名称；如果导出文件只保存 `line1`、`line2`，代码不能安全推断真实协议。

Agent 支持修改节点名称、线路颜色/名称，以及删除节点。删除节点时必须同时删除引用该节点的边，避免产生悬空拓扑。
新增完整节点或边需要用户提供可复制的模板；Agent 不会凭空构造未知拓扑格式。

语义操作示例：

```json
{"target":"topology","op":"rename_node","name":"旧节点","new":"新节点"}
{"target":"topology","op":"delete_node","name":"待删除节点"}
{"target":"topology","op":"add_protocol","name":"CANFD","color":"#016AFF"}
```

`add_protocol` 只新增线路定义；如果要把已有拓扑边切换到该线路，还需要根据真实边的 JSON Pointer
修改 `attrs.line.id`/`attrs.line.stroke`。代码不会根据颜色猜测协议含义。

## 外部接口 Excel

默认读取第一个工作表。第一行是表头，HT602 等项目通常包含：

```text
外部接口信息 | 外部接口关联部件
```

行级修改使用表头和值精确匹配，避免因同名接口误改多行：

```json
{"target":"interfaces","op":"update_row",
 "match":{"外部接口信息":"OBD"},
 "set":{"外部接口关联部件":"VCM"}}
```

## 安全边界

- 只允许 `dfd`、`topology`、`interfaces` 三类目标。
- JSON 修改使用真实 JSON Pointer；禁止路径跳转和任意文件路径。
- Excel 只能操作已有列；新增行不能创建未知列。
- 每次修改最多 100 个操作，修改失败时保留原输入并显示错误。
- 修改完成后返回隔离副本路径和操作摘要，用户检查后再点击“启动 AI TARA 分析”。

## 名称匹配规则

DFD、拓扑和外部接口 Excel 的跨文件名称匹配采用 Unicode `casefold`，并忽略布局空白及转义换行符，
因此 `TACHO` 与 `Tacho`、`WIFI` 与 `wifi`、`BDU\\nPDU` 与 `BDU PDU` 会被视为同一节点/接口；
报告输出仍保留输入文件中的原始大小写和换行样式。
