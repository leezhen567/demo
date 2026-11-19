"""Build traceable asset attack trees from completed TARA reports.

The report remains the authority. Exact common actions are factored out of its
OR-of-AND path expressions. Nodes name the asset, threat and concrete actions;
complete report prose, step order and path references stay in node evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from typing import Any


TREE_VERSION = "asset-attack-tree-v3"


def _text(value: Any) -> str:
    return str(value or "").strip()


def asset_catalog(report: list[dict]) -> list[dict]:
    """Keep engineering identity, including flow endpoints, separate from name."""
    catalog, occurrences = [], {}
    for function in report:
        if not isinstance(function, dict):
            continue
        for asset in function.get("assets", []) or []:
            if not isinstance(asset, dict):
                continue
            identity = {key: asset.get(key, "") for key in (
                "element_id", "element_index", "dfd_element_type", "asset_name",
                "asset_type", "source", "target",
            )}
            identity["function"] = _text(function.get("function"))
            digest = hashlib.sha256(json.dumps(identity, ensure_ascii=False, sort_keys=True).encode()).hexdigest()[:20]
            occurrences[digest] = occurrences.get(digest, 0) + 1
            key = f"{digest}-{occurrences[digest]}"
            name = _text(asset.get("asset_name")) or "未命名资产"
            endpoint = " → ".join(filter(None, [_text(asset.get("source")), _text(asset.get("target"))]))
            label = f"{len(catalog) + 1:03d} · {identity['function']} / {name} · {asset.get('asset_type', '')}"
            if endpoint:
                label += f" · {endpoint}"
            catalog.append({"id": key, "label": label, "identity": identity, "asset": asset})
    return catalog


def attack_steps(path: str) -> list[str]:
    """Extract numbered actions without splitting protocol names or inventing hops.

    A legacy unnumbered paragraph stays intact. Semicolons and Chinese periods
    are not reliable hop boundaries, so they must not be used as such.
    """
    value = _text(path).replace("\r\n", "\n")
    if not value:
        return []
    marker = re.compile(r"(?:^|\n)\s*(?:\*\*)?(?:\d{1,3}[.、．)）]|[（(]\d{1,3}[)）])\s*(?:\*\*)?")
    matches = list(marker.finditer(value))
    if not matches or value[:matches[0].start()].strip():
        return [value]
    parts = [value[m.end():matches[i + 1].start() if i + 1 < len(matches) else len(value)].strip()
             for i, m in enumerate(matches)]
    return [part for part in parts if part]


def _action_label(text: str, path: dict, context: dict) -> str:
    """Name the recorded operation, rather than taking a prose prefix.

    Protocols, ECU identifiers and method names must occur in this action's
    own text. Context supplies a target name only when that name also occurs
    in the action, so labels cannot manufacture a missing hop or technique.
    """
    body = re.split(r"[，,](?:导致|造成|进而|从而|可能)", text, maxsplit=1)[0]
    protocol = re.search(r"(?<![A-Za-z0-9])(?:CAN(?:[ -]?FD)?|FlexRay|SOME/IP|DoIP|UDS|LIN|Ethernet|以太网|UART|JTAG|BLE|HTTPS?|TCP|UDP)(?![A-Za-z0-9])", body, re.I)
    protocol_name = protocol.group(0) if protocol else ""
    component = path.get("start_component", "")
    interface = path.get("external_interface", "")
    is_entry = bool(component and interface and component in body and interface in body)
    access = re.search(r"(?:获取|获得)(?:对)?([A-Za-z][A-Za-z0-9_-]*)(?:的)?(?:初始)?(?:访问|控制)权限", body)
    if is_entry and access:
        methods = []
        for pattern, label in [
            (r"服务漏洞|代码执行|溢出", "利用服务漏洞"),
            (r"认证绕过|绕过.{0,6}认证", "绕过认证"),
            (r"诊断会话滥用", "滥用诊断会话"),
            (r"物理访问漏洞", "利用物理访问弱点"),
            (r"调试接口(?:滥用|未禁用)", "利用调试接口"),
            (r"协议解析缺陷", "利用协议解析缺陷"),
            (r"定位数据注入", "注入定位数据"),
        ]:
            if re.search(pattern, body):
                methods.append(label)
        operation = "／".join(methods) if methods else "获取访问权限"
        return f"{interface} → {component}\n{operation}"

    source_match = re.match(r"([A-Za-z][A-Za-z0-9_-]*)(?=在|利用|通过|向|接收|发送|转发|执行|处理|对)", body)
    target_match = re.search(r"(?:发送至|发送给|转发至|传递至|传输至|向)([A-Za-z][A-Za-z0-9_-]*)", body)
    source = source_match.group(1) if source_match else ""
    target = target_match.group(1) if target_match else ""
    if not target:
        candidate = _text(context.get("target"))
        if candidate and candidate in body:
            target = candidate
    host_match = re.search(r"(?:在|对)([A-Za-z][A-Za-z0-9_-]*)(?:上|内部|的|部件)", body)
    access_host = re.search(r"(?:访问|控制)([A-Za-z][A-Za-z0-9_-]*)", body)
    host = source or target or (host_match.group(1) if host_match else access_host.group(1) if access_host else "")
    object_match = re.search(r"验签逻辑|信任锚|升级包|固件|图像数据|感知数据|雷达数据|诊断请求|控制指令|控制报文|CAN帧|数据帧|密钥|证书|敏感数据|配置数据|个人信息|日志|记录文件|控制信号|状态信号", body)
    obj = object_match.group(0) if object_match else "数据" if "数据" in body else "报文" if re.search(r"报文|帧|消息", body) else "攻击输入"
    log_action = _log_operation(body)
    if log_action:
        operation = log_action + "日志记录"
    elif re.search(r"(?:修改|篡改|替换).{0,12}(?:验签|验证逻辑|信任锚|信任根)", body):
        operation = "篡改验签逻辑／信任锚" if "验签" in body and "信任锚" in body else "篡改信任锚" if "信任锚" in body else "篡改验证逻辑"
    elif re.search(r"提权|提升.{0,6}权限|获取.{0,6}(?:root|管理员)权限", body):
        operation = "获取高权限"
    elif re.search(r"(?:绕过|规避).{0,10}(?:验签|签名|来源|合法性)", body):
        operation = "绕过升级包验签" if "升级" in body else "绕过合法性校验"
    elif re.search(r"利用.{0,24}(?:认证缺陷|认证漏洞)", body):
        operation = "利用认证缺陷获取访问能力"
    elif re.search(r"接收并处理|接收并执行|接受并执行|(?:接收|接受).{0,28}(?:错误|虚假|异常|恶意|篡改)", body):
        operation = "接收并执行" if re.search(r"(?:接收|接受)并执行", body) else "接收并处理" if "接收并处理" in body else "接收"
        modifier = next((word for word in ("篡改", "伪造", "虚假", "错误", "异常") if word in body), "")
        operation += modifier + obj
    elif re.search(r"洪泛|泛洪", body):
        operation = "发送洪泛报文"
    elif re.search(r"阻断|丢弃", body):
        operation = "阻断报文传递" if re.search(r"信号|报文|帧", body) else "阻断正常处理"
    elif re.search(r"拒绝服务", body):
        operation = "实施拒绝服务攻击"
    elif "读写" in body:
        operation = "读写固件与数据" if "固件" in body and "数据" in body else "读写存储内容"
    elif re.search(r"读取|窃取|窃听|提取|监听|解密|截获", body):
        verbs = [word for word in ("监听", "解密", "截获", "窃听", "提取", "读取") if word in body]
        operation = "／".join(verbs) + obj if verbs else "读取" + obj
    elif re.search(r"重放", body):
        operation = "重放" + obj
    elif re.search(r"伪造|注入|虚假", body):
        operation = ("注入" if "注入" in body else "伪造") + obj
    elif re.search(r"(?:投放|投递|上传|发送).{0,12}(?:升级包|固件|升级内容)", body):
        operation = "投递" + obj
    elif re.search(r"发送|传递|转发", body) and "篡改" in body:
        operation = "发送篡改" + obj
    elif re.search(r"篡改|修改|写入", body):
        operation = ("写入" if "写入" in body else "篡改") + obj
    elif access:
        host, operation = access.group(1), "获取访问权限"
    elif re.search(r"(?:访问|控制)(?:[A-Za-z][A-Za-z0-9_-]*|网关|目标)|访问权限|控制权限", body):
        operation = "获取入口访问能力"
        if not host and interface and interface in body:
            host = interface
    elif re.search(r"获取|获得", body):
        operation = "获取" + obj
    elif re.search(r"泄露|外泄", text):
        operation = "使敏感信息泄露"
    elif "发送" in body or "传递" in body or "转发" in body:
        operation = "传送" + ("篡改" if "篡改" in body else "") + obj
    else:
        operation = "实施" + (_text(context.get("threat_type")) or "路径所述") + "攻击"

    if is_entry:
        location = f"{interface} → {component}"
    elif source and target and source != target:
        location = f"{source} → {target}"
    else:
        location = host
    if protocol_name and protocol_name not in operation and protocol_name not in location:
        location = " · ".join(filter(None, [location, protocol_name]))
    return "\n".join(filter(None, [location, operation]))


def _method(path: dict) -> tuple[str, str]:
    text = path["attack_path"]
    # Names classify only mechanisms explicitly present in this report path.
    rules = [
        (r"(?:修改|篡改|替换).{0,12}(?:验签|验证逻辑|信任锚|信任根)", "verification", "篡改验证机制"),
        (r"提权|提升.{0,6}权限|获取.{0,6}(?:root|管理员)权限", "privilege", "利用高权限实施攻击"),
        (r"(?:冒充|冒用|伪装).{0,16}(?:身份|账户|升级包|合法)|伪造.{0,8}(?:签名|来源)", "identity", "伪装合法身份或来源"),
    ]
    for pattern, key, label in rules:
        if re.search(pattern, text, re.I):
            if key == "identity":
                label = "伪装合法升级来源" if re.search(r"升级包|签名|来源", text) else "冒用合法身份"
            return key, label
    first = path["steps"][0] if path["steps"] else text
    if re.search(r"服务漏洞|代码执行|溢出", first) and "认证绕过" in first:
        return "service_auth", "利用入口服务或认证弱点"
    for pattern, key, label in [
        (r"调试|UART|JTAG", "debug", "经调试入口实施攻击"),
        (r"诊断|OBD|UDS", "diagnostic", "经诊断入口实施攻击"),
        (r"认证绕过", "authentication", "绕过入口认证"),
        (r"凭据|口令|会话令牌", "credentials", "利用凭据相关弱点"),
        (r"服务漏洞|代码执行|溢出", "service", "利用入口服务漏洞"),
    ]:
        if re.search(pattern, first, re.I):
            return key, label
    return "entry:" + path["external_interface"], f"经{path['external_interface']}入口实施攻击" if path["external_interface"] else "按报告路径实施攻击"


def _evidence_host(text: str, context: dict) -> str:
    """Use a target/actor only when it occurs in this particular action."""
    for field in ("target", "asset_name"):
        value = _text(context.get(field))
        if value and value in text:
            return value
    match = re.search(r"(?:在|对|访问|控制|从)([A-Za-z][A-Za-z0-9_-]*)", text)
    if not match:
        match = re.match(r"(?:导致)?([A-Za-z][A-Za-z0-9_-]*)(?=通过|接收|接受|处理|无法|不能|因|相关|中|利用|执行|的)", text)
    return match.group(1) if match else ""


def _log_operation(text: str) -> str:
    if not re.search(r"日志|记录文件|审计记录|操作记录", text):
        return ""
    if re.search(r"删除|清除|擦除|清空", text):
        return "删除"
    if re.search(r"破坏|损毁", text):
        return "破坏"
    if re.search(r"禁用|关闭|停止记录", text):
        return "禁用"
    return ""


def _subgoal(text: str, path: dict | None = None, context: dict | None = None) -> str:
    context = context or {}
    original = text
    text = re.split(r"[，,](?:导致|造成|进而|从而|可能)", text, maxsplit=1)[0]
    host = _evidence_host(text, context)
    log_action = _log_operation(text)
    if log_action:
        return f"{log_action}{host}日志记录"
    access = re.search(r"(?:获取|获得)(?:对)?([A-Za-z][A-Za-z0-9_-]*)(?:的)?(?:初始)?(?:访问|控制)权限", text)
    if access:
        return f"获得{access.group(1)}访问能力"
    direct_access = re.search(r"(?:直接)?访问([A-Za-z][A-Za-z0-9_-]*)", text)
    if direct_access:
        return f"获得{direct_access.group(1)}访问能力"
    if re.search(r"提取|读取|窃取|窃听|监听|解密|截获|外传|泄露|外泄", text):
        return f"获取{host}敏感信息" if re.search(r"提取|读取|窃取|窃听|监听|解密|截获", text) else f"使{host}敏感信息泄露"
    if "读写" in text:
        return f"读写{host}固件与数据" if "固件" in text and "数据" in text else f"读写{host}存储内容"
    if re.search(r"接管|控制权", text):
        return f"取得{host}控制权"
    if re.search(r"加载|运行|执行|植入", text) and re.search(r"恶意代码|恶意软件|恶意程序", text):
        actor = re.search(r"([A-Za-z][A-Za-z0-9_-]*)(?:上|中|内部)?(?:加载|运行|执行|植入)", text)
        return f"在{actor.group(1)}运行恶意代码" if actor else "运行恶意代码"
    if not re.search(r"转发|传递|发送", text) and re.search(r"(?:接收|接受).{0,28}(?:错误|虚假|异常|恶意|篡改)", text):
        receiver = re.search(r"([A-Za-z][A-Za-z0-9_-]*)(?:接收|接受)", text)
        return f"使{receiver.group(1) if receiver else host}接收异常数据"
    rules = [
        (r"(?:修改|篡改|替换).{0,12}(?:验签|验证逻辑|信任锚|信任根)", f"改变{host or '目标'}验证机制"),
        (r"提权|提升.{0,6}权限|获取.{0,6}(?:root|管理员)权限", f"取得{host or '目标'}高权限"),
        (r"(?:绕过|规避).{0,10}(?:验签|签名|来源|合法性)", "绕过内容合法性检查"),
        (r"(?:投放|投递|上传|发送|获得).{0,12}(?:升级包|固件|升级内容)", "使攻击载荷就绪"),
        (r"接收并处理|接收并执行|接受并执行", f"使{host or '目标'}接受并处理攻击输入"),
        (r"拒绝服务|洪泛|丢弃|阻断", f"使{host or '目标'}服务不可用"),
        (r"伪造|注入|重放", "构造并送达攻击报文"),
        (r"读取|窃取|窃听|外泄", "获取目标敏感信息"),
        (r"篡改|修改|写入", "改变目标数据或执行内容"),
        (r"获取|获得|访问权限|控制权限", "获得攻击所需访问能力"),
    ]
    for pattern, label in rules:
        if re.search(pattern, text, re.I):
            return label
    if re.search(r"转发|传递|发送|传输|传送|上传|外传", text):
        destination = re.search(r"(?:至|给|向)([A-Za-z][A-Za-z0-9_-]*)", text)
        target = destination.group(1) if destination else "云端" if "云端" in text else host
        payload = "恶意报文" if re.search(r"恶意|虚假|异常|错误", text) else "信号" if "信号" in text else "数据"
        return f"将{payload}送达{target}" if target else f"传递{payload}"
    if re.search(r"可用性|无法正常|不能正常|服务失效|功能失效|停止响应|崩溃|耗尽", text):
        return f"使{host}服务不可用"
    if ("未授权访问" in original or "未授权控制" in original) and re.search(r"权限|访问|控制", text):
        return f"取得{host}未授权访问能力"
    # Without enough evidence for a named subgoal, show the existing action
    # directly. A generic parent box adds no useful meaning to the tree.
    return ""


def decompose_paths(paths: list[dict], context: dict | None = None) -> dict:
    """Factor the report's OR-of-ANDs without creating new path combinations.

    Only identical full actions (whitespace/punctuation normalized) can share
    a condition. Summaries and method classifications never determine equality.
    A residual with no conditions is NOT simplified away: retain that original
    clause instead of claiming a partially specified route is sufficient.
    """
    conditions, clauses = {}, []
    for path in paths:
        atoms, occurrences = [], {}
        for ordinal, text in enumerate(path["steps"], 1):
            canonical = re.sub(r"\s+", " ", text).strip().rstrip("。；;")
            occurrences[canonical] = occurrences.get(canonical, 0) + 1
            key = "c" + hashlib.sha256(f"{canonical}|{occurrences[canonical]}".encode()).hexdigest()[:18]
            summary = _action_label(text, path, context or {})
            atom = conditions.setdefault(key, {"text": text, "title": _subgoal(text, path, context), "summary": summary, "refs": []})
            atom["refs"].append({"path": path["id"], "path_id": path["path_id"], "step": ordinal})
            atoms.append(key)
        if atoms:
            method_key, method_label = _method(path)
            clauses.append({"atoms": atoms, "path": path["id"], "method": method_key, "method_label": method_label})

    def gate(op, children):
        return children[0] if len(children) == 1 else {"op": op, "children": children}

    def factor(items, methods=True):
        if len(items) == 1:
            return gate("AND", [{"op": "condition", "id": key} for key in items[0]["atoms"]])
        common = set(items[0]["atoms"]).intersection(*(set(c["atoms"]) for c in items[1:]))
        if common and all(set(c["atoms"]) - common for c in items):
            ordered = [key for key in items[0]["atoms"] if key in common]
            residual = [{**c, "atoms": [k for k in c["atoms"] if k not in common]} for c in items]
            return gate("AND", [factor(residual, methods), *({"op": "condition", "id": k} for k in ordered)])
        groups = {}
        if methods:
            for clause in items:
                groups.setdefault(clause["method"], []).append(clause)
            if len(groups) > 1:
                return gate("OR", [{"op": "method", "title": group[0]["method_label"],
                                    "paths": [c["path"] for c in group], "children": [factor(group, False)]}
                                   for group in groups.values()])
        # Group clauses with a shared endpoint action before expanding whole routes.
        suffix_groups = {}
        for clause in items:
            suffix_groups.setdefault(clause["atoms"][-1], []).append(clause)
        if 1 < len(suffix_groups) < len(items):
            return gate("OR", [factor(group, False) for group in suffix_groups.values()])
        return gate("OR", [{"op": "route", "paths": [c["path"]], "title": c["path"],
                            "children": [factor([c], False)]} for c in items])

    return {"conditions": conditions, "expression": factor(clauses) if clauses else None}


def build_asset_tree(entry: dict) -> dict:
    asset = entry["asset"]
    scenarios = []
    for index, detail in enumerate(asset.get("security_attributes", []) or []):
        if not isinstance(detail, dict):
            continue
        scenario_id = f"TS-{index + 1:02d}"
        paths = []
        for path_index, attack in enumerate(detail.get("attack", []) or []):
            if not isinstance(attack, dict):
                continue
            body = _text(attack.get("attack_path"))
            if not body:
                continue
            trace = attack.get("topology_trace") or {}
            trace = trace if isinstance(trace, dict) else {}
            paths.append({
                "id": f"{scenario_id}-AP-{path_index + 1:02d}",
                "path_id": _text(trace.get("path_id")) or _text(attack.get("path_id")),
                "attack_path": body,
                "steps": attack_steps(body),
                "external_interface": _text(trace.get("external_interface")),
                "start_component": _text(trace.get("start_component")),
                "topology_trace": trace,
                "source": _text(attack.get("attack_path_source")) or "报告记录",
                "verification_status": "未提供攻击验证结论",
                "feasibility_level": attack.get("feasibility_level"),
                "feasibility_score": attack.get("feasibility_score"),
                "risk_value": attack.get("risk_value"),
                "risk_treatment": attack.get("risk_treatment"),
                "security_requirements": attack.get("security_requirements") or [],
            })
        scenario = {
            "id": scenario_id, "task_id": _text(detail.get("task_id")),
            "attribute": _text(detail.get("attribute_name")),
            "threat_type": _text(detail.get("threat_type")),
            "goal": _text(detail.get("threat_scenarios")),
            "damage_scenario": _text(detail.get("damage_scenario")),
            "analysis_status": _text(detail.get("analysis_status")),
            "status_reasons": detail.get("status_reasons") or [],
            "paths": paths,
        }
        scenario["decomposition"] = decompose_paths(paths, {**entry["identity"], "threat_type": scenario["threat_type"]})
        scenarios.append(scenario)
    return {"version": TREE_VERSION, "asset_id": entry["id"],
            "identity": entry["identity"], "scenarios": scenarios,
            "logic": {"alternatives": "OR", "path_actions": "AND",
                      "order": "step ordinal; AND alone does not encode order"},
            "evidence_note": "按报告中的候选攻击路径组织；模型描述不代表已验证漏洞或已成功攻击。"}


def _wrapped_lines(value: str, columns: int = 36) -> list[str]:
    """Wrap Chinese by glyph width while keeping ECU/protocol identifiers intact."""
    lines = []
    for paragraph in str(value).splitlines():
        current, width = "", 0
        for token in re.findall(r"[A-Za-z0-9_]+(?:[-./][A-Za-z0-9_]+)*|.", paragraph):
            chunks = [token[i:i + columns] for i in range(0, len(token), columns)]
            for chunk in chunks:
                size = sum(0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in {"W", "F"} else 1 for c in chunk)
                if current and width + size > columns:
                    lines.append(current.rstrip())
                    current, width = "", 0
                if not current and chunk.isspace():
                    continue
                current += chunk
                width += size
        lines.append(current.rstrip())
    return lines or [""]


def _label(value: str) -> str:
    lines = []
    for part in _wrapped_lines(value):
        lines.append("".join(f"#{ord(c)};" if c in '&<>"\\`{}[]|' or ord(c) < 32 else c for c in part))
    return "<br/>".join(lines)


def _goal_title(tree: dict, scenario: dict) -> str:
    name = _text(tree["identity"].get("asset_name")) or "未命名资产"
    return f"资产：{name}\n威胁：{scenario['threat_type'] or '未提供'}"


def tree_diagram(tree: dict, scenario_id: str | None = None) -> dict:
    """Use semantic action names; complete prose remains in node evidence."""
    lines, nodes = ["flowchart TD"], {}
    count = 0

    def node(title, kind, *, text="", refs=None):
        nonlocal count
        key = f"n{count}"; count += 1
        encoded = _label(title)
        shape = f'{key}{{"{encoded}"}}' if kind in {"or", "and"} else f'{key}["{encoded}"]'
        lines.append(f"    {shape}:::{kind}")
        nodes[key] = {"title": title, "kind": kind, "text": text or title, "refs": refs or []}
        return key

    def edge(parent, child):
        lines.append(f"    {parent} --> {child}")

    def roles(expr, conditions):
        if expr["op"] == "condition":
            return {conditions[expr["id"]]["title"]}
        return set().union(*(roles(child, conditions) for child in expr["children"]))

    def expression(expr, parent, conditions, active_subgoal=None):
        op = expr["op"]
        if op == "condition":
            atom = conditions[expr["id"]]
            sg = parent
            if atom["title"] and active_subgoal != atom["title"]:
                sg = node(atom["title"], "subgoal", text=atom["text"], refs=atom["refs"])
                edge(parent, sg)
            action = node(atom["summary"], "action", text=atom["text"], refs=atom["refs"])
            edge(sg, action)
        elif op in {"method", "route"}:
            if op == "route" and expr["children"][0]["op"] == "condition":
                expression(expr["children"][0], parent, conditions, active_subgoal)
                return
            title = expr["title"] if op == "method" else "完整条件组合 " + "/".join(expr["paths"])
            key = node(title, "method", refs=[{"path": p} for p in expr["paths"]])
            edge(parent, key)
            expression(expr["children"][0], key, conditions, active_subgoal)
        else:
            child_roles = roles(expr, conditions)
            if op == "OR" and len(child_roles) == 1 and all(child_roles) and active_subgoal not in child_roles:
                active_subgoal = next(iter(child_roles))
                sg = node(active_subgoal, "subgoal", text="实现这一子目标可选择以下完整方法；具体成立条件见叶子节点原文。")
                edge(parent, sg); parent = sg
            # This is a logical gate, so keep it small and free of paragraph text.
            key = node(op, op.lower(), text="以下条件全部成立" if op == "AND" else "以下方法任一成立")
            edge(parent, key)
            for child in expr["children"]:
                expression(child, key, conditions, active_subgoal)

    scenarios = [s for s in tree["scenarios"] if not scenario_id or s["id"] == scenario_id]
    if scenario_id and not scenarios:
        raise ValueError("攻击目标不属于当前资产")
    if scenario_id:
        parent = None
    else:
        name = _text(tree["identity"].get("asset_name")) or "未命名资产"
        threats = list(dict.fromkeys(s["threat_type"] for s in scenarios if s["threat_type"]))
        parent = node(f"资产：{name}\n威胁：{'、'.join(threats) or '未提供'}", "asset", text=tree["evidence_note"])
        if len(scenarios) > 1:
            gate = node("OR", "or", text="任一安全属性对应的攻击目标实现")
            edge(parent, gate); parent = gate
    if not scenarios:
        key = node("尚未提供攻击目标与路径", "missing")
        if parent:
            edge(parent, key)
    for scenario in scenarios:
        goal = node(_goal_title(tree, scenario), "asset" if scenario_id else "goal", text=scenario["goal"] or "报告未提供威胁场景正文",
                    refs=[{"scenario": scenario["id"], "path": p["id"], "path_id": p["path_id"]} for p in scenario["paths"]])
        if parent:
            edge(parent, goal)
        decomposition = scenario.get("decomposition") or decompose_paths(scenario["paths"])
        if decomposition["expression"]:
            expression(decomposition["expression"], goal, decomposition["conditions"])
        else:
            key = node("尚无完整路径\n" + (scenario["analysis_status"] or "未提供分析状态"), "missing", text="；".join(map(str, scenario["status_reasons"])))
            edge(goal, key)
    lines.extend([
        "    classDef asset fill:#123f68,color:#fff,stroke:#123f68,stroke-width:2px,rx:8,ry:8",
        "    classDef goal fill:#e9f2fd,color:#193d64,stroke:#84acd4,rx:6,ry:6",
        "    classDef or fill:#eaf7f2,color:#126851,stroke:#63ad95,stroke-width:1.5px",
        "    classDef and fill:#fff4dd,color:#82500b,stroke:#d7ac50,stroke-width:1.5px",
        "    classDef method fill:#f0f5ff,color:#25476a,stroke:#aec6e5,rx:5,ry:5",
        "    classDef subgoal fill:#edf5ff,color:#29547d,stroke:#9fbfdd,rx:4,ry:4",
        "    classDef action fill:#f5f1fc,color:#54416c,stroke:#c2b4d6,rx:3,ry:3",
        "    classDef missing fill:#f6f7f9,color:#6b7785,stroke:#c2cbd4,stroke-dasharray:4 3",
    ])
    return {"source": "\n".join(lines) + "\n", "nodes": nodes}


def tree_mermaid(tree: dict, scenario_id: str | None = None) -> str:
    return tree_diagram(tree, scenario_id)["source"]


def tree_views(tree: dict) -> list[dict]:
    """One asset document; inspect one concrete goal at a time by default."""
    views = [{"id": s["id"], "label": s["attribute"] + " · " + s["threat_type"], **tree_diagram(tree, s["id"])}
             for s in tree["scenarios"]]
    views.append({"id": "all", "label": "完整资产总图 · 全部攻击目标", **tree_diagram(tree)})
    return views
