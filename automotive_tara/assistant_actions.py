"""Executable, project-scoped actions behind the safety-analysis Agent."""
from __future__ import annotations
import json
import os
import re
import uuid
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from .asset_selection import validate_selection, matches
from .assistant_repository import RepositoryWorkspace
from .assistant_report import revise_report
from .data_dependency import (analyze_dependency_impacts, derive_cascade_operations, plan_id)
from .data_editor_agent import (validate_edit_plan, apply_confirmed_edit_plan, _input_fingerprint)
from .live_model_output import read_model_events
from .storage import atomic_write_bytes

ACTION_TOOLS = [
    ('repository_tree', '查看项目结构', 'query=路径或JSON{path,depth,offset,page_size,pattern}；目录按页浏览，可定位data/experiments/deliverables及当前任务全部产物；next_offset继续下一页。', 'automotive_tara.assistant_repository'),
    ('read_repository_file', '阅读代码与说明', 'query=路径或JSON{path,start_line,end_line}；源码/JSON/日志流式分页，Excel加sheet/start_row/end_row，Word按行，PDF加page；可读取当前任务报告、检查点和公共资料，权重只看元数据。', 'automotive_tara.assistant_repository'),
    ('asset_inventory', '定位分析资产', 'query=资产关键词；返回真实分析资产身份，修改/排除/重跑前先定位。', 'automotive_tara.dfd.parse_dfd_json'),
    ('read_project_file', '读取待修改字段', 'query=JSON{target:dfd/topology,file:文件名,query:字段值关键词,pointer:可选JSON指针}；返回当前选定输入的真实JSON指针/值，供set/delete操作使用。', 'automotive_tara.data_editor_agent'),
    ('edit_project_inputs', '修改项目数据', 'query=JSON{operations:[{target:"dfd",file:"文件.json",op:"rename_asset",old:"原名",new:"新名"}]}。删除用op:"delete_asset",name:"名称"；字段修改用op:"set",path:"/真实JSON指针",value:值。自动级联同步拓扑和接口，无需另改每一处引用。校验后立即写副本并接入当前输入。', 'automotive_tara.data_editor_agent.apply_confirmed_edit_plan'),
    ('set_analysis_scope', '设置分析资产范围', 'query=JSON{include:[{asset_name,function,element_index}],exclude:[...]}；精确定位，仅调整分析范围，保留拓扑。空数组恢复全部。', 'automotive_tara.asset_selection'),
    ('inspect_live_run', '查看实时输出与异常', 'query=可选关键词；读取当前任务最新模型输出、服务错误、日志、阶段状态和诊断建议。', 'automotive_tara.live_model_output'),
    ('start_analysis', '启动当前项目分析', 'query=JSON{selection:{include:[],exclude:[]},force_regenerate:false}；使用当前输入和页面方案创建真实后台任务。', 'automotive_tara.demo.run_analysis'),
    ('rerun_assets', '重新分析指定资产', 'query=JSON{include:[{asset_name,function,element_index}],force_regenerate:true}；创建独立后台任务，仅重算选定资产并生成新报告。', 'automotive_tara.demo.run_analysis'),
    ('revise_report', '修改报告或评级维度', 'query=JSON{ratings:[{risk_id,impact_parameters:{Safety:2},feasibility_parameters:{Exposure_time:4},reason}],operations:[{risk_id,field,value,reason}]}；维度合并原值，项目评分函数同步回算等级/风险并导出JSON和Excel。', 'automotive_tara.assistant_report'),
    ('run_repository_tool', '执行项目工具文件', 'query=JSON{path:相对Python文件,args:[字符串]}；隔离执行项目工具，输入副本在/inputs，代码在/repo，输出写/work；TARA模型分析使用start_analysis/rerun_assets。', 'automotive_tara.assistant_repository'),
    ('run_python', '编写并运行Python', 'query=JSON{code:完整Python代码,args:[]}；可import automotive_tara计算/处理选定输入。/inputs有输入文件副本，已生成报告为/inputs/report.json（优先当前修订版），用glob发现文件。生成文件写/work；返回日志/产物。', 'automotive_tara.assistant_repository'),
    ('undo_last_action', '撤销上次项目修改', '恢复上次输入、资产范围或报告版本；新旧文件均保留。不能撤销已开始的模型任务。', 'automotive_tara.assistant_actions'),
]
MUTATING = {'edit_project_inputs', 'set_analysis_scope', 'start_analysis', 'rerun_assets', 'revise_report',
            'run_repository_tool', 'run_python', 'undo_last_action'}


class WorkspaceActions:
    def __init__(self, evidence, store, scope, root, *, question='', mode='agent', runtime=None, request_id=''):
        self.evidence, self.store, self.scope = evidence, store, scope
        self.root = Path(root)
        self.question, self.mode, self.runtime = question, mode, runtime or {}
        self.request_id = request_id or uuid.uuid4().hex
        self.original_job = evidence.job_id
        self.private = Path(store.root) / 'workspaces' / scope
        self.artifacts = self.root / 'outputs/demo_assistant_artifacts' / scope
        self.private.mkdir(parents=True, exist_ok=True)
        self.state = self.load()
        if 'inputs' not in self.state:
            self.state['inputs'] = {'dfd': [str(p) for p in evidence.dfd_paths],
                                    'topology': str(evidence.topology), 'interfaces': str(evidence.interfaces)}
            self._save()
        self.state.setdefault('job_id', evidence.job_id)
        self.state.setdefault('detach_job', False)
        self._save()
        self.effects = {}
        self._restore_evidence()
        self.repository = RepositoryWorkspace(root, self.artifacts, self.evidence)

    def load(self):
        path = self.private / 'state.json'
        return json.loads(path.read_text(encoding='utf-8')) if path.is_file() else {}

    def _save(self):
        atomic_write_bytes(self.private / 'state.json', json.dumps(self.state, ensure_ascii=False, default=str).encode('utf-8'))

    def _restore_evidence(self):
        job_id = self.state.get('job_id')
        if self.state.get('detach_job'):
            self.evidence.job_id, self.evidence.job_root = '', None
        elif job_id and self.evidence.jobs_root and job_id != self.evidence.job_id:
            current = type(self.evidence)(job_id=job_id, jobs_root=self.evidence.jobs_root,
                queue_root=self.evidence.queue_root, project_name=self.evidence.project_name)
            self.evidence.__dict__.update(current.__dict__)
        inputs = self.state.get('inputs')
        if inputs and all(Path(p).is_file() for p in inputs['dfd'] + [inputs['topology'], inputs['interfaces']]):
            self.evidence.dfd_paths = [Path(p) for p in inputs['dfd']]
            self.evidence.topology, self.evidence.interfaces = Path(inputs['topology']), Path(inputs['interfaces'])
        report = self.state.get('report')
        if report and Path(report).is_file():
            self.evidence.report_override = report
        elif hasattr(self.evidence, 'report_override'):
            del self.evidence.report_override

    def _changed(self, changes, result, *, undoable=True):
        if changes.get('artifacts'):
            changes['artifacts'] = list(dict.fromkeys([*self.effects.get('artifacts', []), *changes['artifacts']]))[-20:]
        if undoable:
            previous = {key: self.state.get(key) for key in ('inputs', 'selection', 'report', 'excel', 'job_id', 'detach_job')}
            self.state.setdefault('undo', []).append(previous)
            self.state['undo'] = self.state['undo'][-12:]
        self.state.update(changes)
        self.state['last_action'] = {'time': datetime.now(timezone.utc).isoformat(), 'question': self.question[:1000],
                                     'result': result}
        self._save()
        self.effects.update(changes)
        self._restore_evidence()
        return result

    def report_path(self):
        if self.state.get('report') and Path(self.state['report']).is_file():
            return Path(self.state['report'])
        manifest, _ = self.evidence.manifest()
        path = Path(str(manifest.get('outputs', {}).get('json') or ''))
        if self.evidence.job_root and path.is_file() and self.evidence.job_root.resolve() in path.resolve().parents:
            return path
        raise ValueError('当前任务尚无可修改报告，请先完成分析或打开历史报告')

    def inventory(self, query='', limit=8):
        rows = self._all_assets()
        selected = [r for r in rows if not query or query.casefold() in json.dumps(r, ensure_ascii=False).casefold()]
        return {'source': '当前项目真实资产解析', 'total_count': len(rows), 'matched_count': len(selected),
                'matches': selected[:max(1, min(80, limit))], 'selection': self.state.get('selection', {}),
                'truncated': len(selected) > limit}

    def _validate_scope(self, selection):
        selection = validate_selection(selection)
        # Build a full inventory when there are more than the displayed 80 rows.
        all_rows = self._all_assets()
        for selector in selection['include'] + selection['exclude']:
            found = [row for row in all_rows if matches(row, selector)]
            if len(found) != 1:
                raise ValueError(f'资产定位匹配{len(found)}项：{selector}；请先 asset_inventory 补充功能/元素编号')
        return selection

    def _all_assets(self):
        # Inventory's internal bound is for UI payloads, not scope resolution.
        from .dfd import parse_dfd_json
        rows = []
        for source in self.evidence.dfd_paths:
            functions = parse_dfd_json(str(source), strict_inputs=False)
            for function in functions:
                for asset in function.get('assets', []):
                    rows.append({'function': function.get('function', ''), 'element_index': str(asset.get('element_index') or ''),
                        'asset_name': asset.get('name') or asset.get('asset_name') or '', 'asset_type': asset.get('type') or asset.get('asset_type') or '',
                        'source': asset.get('source'), 'target': asset.get('target'), 'file': source.name})
        return rows

    def live(self, query='', limit=4):
        status = self.evidence.status(query=query)
        events = read_model_events(self.evidence.job_root, limit) if self.evidence.job_root else []
        if query:
            events = [e for e in events if query.casefold() in json.dumps(e, ensure_ascii=False).casefold()]
        from .demo import diagnose_runtime
        logs = '\n'.join(status.get('log_excerpt', []))
        diagnosis = diagnose_runtime(logs + '\n' + '\n'.join(e.get('error', '') for e in events), {})
        return {'source': '当前任务真实模型响应与运行日志', 'status': status,
                'model_outputs': [{**e, 'output': e.get('output', '')[:9000]} for e in events],
                'diagnosis': diagnosis, 'notice': '模型原始响应不是最终采用结果；生成后立即可读，阶段结果另查search_results'}

    def execute(self, name, arguments):
        raw = str(arguments.get('query') or '').strip()
        if name in MUTATING and self.mode != 'agent':
            raise ValueError('当前为问答模式；切换到 Agent 后可以执行项目操作')
        limit = min(8, max(1, int(arguments.get('limit') or 5)))
        if name == 'repository_tree':
            return self.repository.tree(raw, 60)
        if name == 'read_repository_file':
            return self.repository.read(raw)
        if name == 'asset_inventory':
            return self.inventory(raw, limit)
        if name == 'read_project_file':
            from .data_editor_agent import _target_file, _get_pointer, _walk_values
            params = json.loads(raw)
            _, path = _target_file(params, self.evidence.dfd_paths, self.evidence.topology, self.evidence.interfaces)
            if path.suffix.lower() != '.json':
                raise ValueError('Excel接口使用search_inputs定位行号，再调用edit_project_inputs接口表操作')
            payload = json.loads(path.read_text(encoding='utf-8-sig'))
            if params.get('pointer'):
                return {'source': path.name, 'pointer': params['pointer'], 'value': _get_pointer(payload, params['pointer'])}
            query = str(params.get('query') or '')
            found = [{'pointer': pointer, 'value': value} for pointer, value in _walk_values(payload)
                     if query and query.casefold() in str(value).casefold()]
            return {'source': path.name, 'root_keys': list(payload) if isinstance(payload, dict) else [],
                    'matches': found[:limit], 'matched_count': len(found),
                    'edit_examples': [{'target':params.get('target'), 'file':path.name, 'op':'rename_asset' if params.get('target')=='dfd' else 'rename_node', 'old':query, 'new':'用户要求的新名'},
                                      {'target':params.get('target'), 'file':path.name, 'op':'set', 'path':'上方真实pointer', 'value':'用户要求的值'}],
                    'notice':'edit_project_inputs 对DFD资产改名/删除会自动同步拓扑和接口；已定位目标后可直接执行，无需重复读取所有引用'}
        if name == 'inspect_live_run':
            return self.live(raw, limit)
        params = json.loads(raw or '{}')
        if not isinstance(params, dict):
            raise ValueError('操作参数必须是JSON对象')
        key = self.request_id + ':' + name + ':' + hashlib.sha256(json.dumps(params, ensure_ascii=False, sort_keys=True).encode()).hexdigest()[:24]
        # A repeated model tool call must not duplicate a job or apply a second revision.
        with self.store.lock(self.scope + '.actions'):
            self.state = self.load()
            if key in self.state.get('executed', {}):
                return {**self.state['executed'][key], 'reused_action': True}
            result = self._execute(name, params)
            self.state.setdefault('executed', {})[key] = result
            self.state['executed'] = dict(list(self.state['executed'].items())[-30:])
            self._save()
            return result

    def _execute(self, name, params):
        if name == 'set_analysis_scope':
            selection = self._validate_scope(params)
            return self._changed({'selection': selection}, {'source': '当前项目分析范围', 'selection': selection,
                'applied': True, 'notice': '已应用到下一次启动；完整拓扑保留，正在运行的任务不受更改'})
        if name == 'edit_project_inputs':
            plan = {'operations': params.get('operations', []), 'summary': self.question}
            if not isinstance(plan['operations'], list) or not plan['operations'] or len(plan['operations']) > 100:
                raise ValueError('请提供1~100项 operations')
            for operation in plan['operations']:
                if isinstance(operation, dict):
                    if 'old_name' in operation and 'old' not in operation:
                        operation['old'] = operation.pop('old_name')
                    if 'new_name' in operation and 'new' not in operation:
                        operation['new'] = operation.pop('new_name')
            errors = validate_edit_plan(plan, dfd_paths=self.evidence.dfd_paths,
                topology_path=self.evidence.topology, interfaces_path=self.evidence.interfaces)
            if errors:
                raise ValueError('修改计划不可执行：' + '；'.join(errors[:5]))
            graph = self.evidence.graph()
            plan['cascade_operations'] = derive_cascade_operations(plan, graph)
            if plan['cascade_operations']:
                errors = validate_edit_plan({'operations': plan['operations'] + plan['cascade_operations']},
                    dfd_paths=self.evidence.dfd_paths, topology_path=self.evidence.topology, interfaces_path=self.evidence.interfaces)
                if errors:
                    raise ValueError('级联关系校验失败：' + '；'.join(errors[:5]))
            plan['input_fingerprint'] = _input_fingerprint(self.evidence.dfd_paths, self.evidence.topology, self.evidence.interfaces)
            plan['plan_id'] = plan_id(plan)
            copied, topology, interfaces, summary = apply_confirmed_edit_plan(plan,
                dfd_paths=self.evidence.dfd_paths, topology_path=self.evidence.topology, interfaces_path=self.evidence.interfaces,
                editor_root=self.artifacts / 'inputs', confirmed=True, expected_plan_id=plan['plan_id'])
            if not summary.get('可用于分析'):
                raise ValueError('已生成副本但校验未通过，未替换当前输入：' + json.dumps(summary.get('修改后一致性校验'), ensure_ascii=False)[:1500])
            changes = {'inputs': {'dfd': [str(p) for p in copied], 'topology': str(topology), 'interfaces': str(interfaces)},
                       'selection': {}, 'detach_job': True, 'job_id': '', 'report': None, 'excel': None}
            result = {'source': '项目数据编辑器', 'applied': True, 'summary': summary,
                      'operations': plan['operations'], 'cascade_operations': plan['cascade_operations'],
                      'impact': analyze_dependency_impacts(plan, graph)}
            return self._changed(changes, result)
        if name == 'revise_report':
            result = revise_report(self.report_path(), params, self.artifacts, instruction=self.question)
            return self._changed({'report': result['report'], 'excel': result['excel'], 'artifacts': result['artifacts']}, result)
        if name in {'run_python', 'run_repository_tool'}:
            result = self.repository.execute(params, generated=name == 'run_python')
            return self._changed({'artifacts': result['artifacts']}, result, undoable=False)
        if name == 'undo_last_action':
            history = self.state.get('undo', [])
            if not history:
                raise ValueError('当前项目没有可撤销修改')
            old = history.pop()
            for key, value in old.items():
                self.state[key] = value
            self.effects.update(old)
            self.effects['undo'] = True
            self._save()
            self._restore_evidence()
            return {'source': '项目操作记录', 'restored': True, 'notice': '已恢复上次输入/范围/报告；原文件和修订文件均保留'}
        if name in {'start_analysis', 'rerun_assets'}:
            from . import demo, demo_jobs
            if name == 'rerun_assets' and not params.get('include'):
                raise ValueError('重跑必须明确选择 include 资产；请先查询 asset_inventory')
            selection = self._validate_scope({'include': params.get('include', []), 'exclude': []}) if name == 'rerun_assets' else self._validate_scope(params.get('selection', self.state.get('selection') or {}))
            values = dict(self.runtime)
            values.update(dfd_files=[str(p) for p in self.evidence.dfd_paths], topology_file=str(self.evidence.topology),
                interfaces_file=str(self.evidence.interfaces), project_label=self.evidence.project_name,
                analysis_selection=selection, force_regenerate=params.get('force_regenerate', name == 'rerun_assets'))
            values.setdefault('impact_method', self.evidence.settings.get('impact_method') or '21434')
            values.setdefault('feasibility_method', self.evidence.settings.get('feasibility_method') or 'attack_potential')
            values.setdefault('enable_reason', True)
            values.setdefault('scope', 'all')
            values.setdefault('enable_asset_details', True)
            values.setdefault('enable_rag', False)
            values.setdefault('capture_audit', False)
            updates = list(demo.run_analysis(**values))
            last = updates[-1] if updates else None
            job_id = (last[2].get('运行配置', {}).get('job_id') if last else '')
            if not job_id or not demo_jobs.get_job(self.evidence.queue_root or demo.DEMO_QUEUE_ROOT, job_id):
                raise ValueError('分析未入队：' + str(last[2] if last else '未返回启动结果')[:1400])
            result = {'source': '持久化后台分析队列', 'job_id': job_id, 'status': 'queued',
                      'selection': selection, 'force_regenerate': values['force_regenerate'],
                      'notice': '已创建真实任务；运行分析页面可查看进度，新报告独立保存，原任务保留'}
            return self._changed({'job_id': job_id, 'selection': selection, 'detach_job': False, 'report': None, 'excel': None}, result, undoable=False)
        raise ValueError('不支持的项目操作')
