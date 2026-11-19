"""Gradio bindings for the persistent project assistant sidebar."""

from __future__ import annotations

import html
import secrets
import queue
import threading
import json
import uuid
from functools import lru_cache
from pathlib import Path

import gradio as gr

from .analysis_assistant import AssistantError, ConversationStore, ProjectEvidence, answer_question
from .assistant_runtime import SkillLibrary, TOOL_CATALOG
from .demo_portable import API_REQUIRED, configured_api

ASSISTANT_CSS = Path(__file__).with_name('demo_assistant.css').read_text(encoding='utf-8')


@lru_cache(maxsize=96)
def _content_identity(path, size, mtime):
    from .analysis_cache import file_digest
    return Path(path).name, file_digest(path)


def _same_files(left, right):
    if left == right:
        return True
    if len(left) != len(right):
        return False
    def identities(paths):
        result = []
        for value in paths:
            path = Path(value)
            if not path.is_file():
                return None
            stat = path.stat()
            result.append(_content_identity(str(path), stat.st_size, stat.st_mtime_ns))
        return sorted(result)
    a, b = identities(left), identities(right)
    return a is not None and a == b


def render_agent_trace(events, plan=()):
    events = [item for item in events if item.get('phase') != 'delta']
    labels = {name: title for name, title, *_ in TOOL_CATALOG}
    if not events:
        return ''
    items = []
    for item in events[-7:]:
        title = labels.get(item.get('tool'), item.get('title', '核查'))
        state = item.get('status', item.get('phase', ''))
        detail = item.get('error') or item.get('source') or item.get('title', '')
        items.append('<div class="assistant-run-step ' + html.escape(str(state), quote=True) + '"><i></i><div><b>'
                     + html.escape(title) + '</b><small>' + html.escape(str(detail)[:180]) + '</small></div></div>')
    plan_html = '<ol class="assistant-plan">' + ''.join('<li>' + html.escape(str(step)) + '</li>' for step in plan[:5]) + '</ol>' if plan else ''
    count = sum(event.get('phase') == 'observation' and event.get('status') != 'reused' for event in events)
    reused = sum(event.get('phase') == 'observation' and event.get('status') == 'reused' for event in events)
    summary = str(count)+' 次工具调用' if count else '已完成' if events[-1].get('phase')=='complete' else '正在核查'
    if reused:
        summary += f' · 跳过 {reused} 次重复'
    return '<details class="assistant-execution"><summary><span>执行过程</span><small>' + summary + '</small></summary><div class="assistant-execution-body">' + plan_html + ''.join(items) + '</div></details>'


class AssistantController:
    def __init__(self, project_root, jobs_root, queue_root):
        self.root = Path(project_root)
        self.jobs_root, self.queue_root = Path(jobs_root), Path(queue_root)
        self.store = ConversationStore(Path(project_root) / 'outputs/demo_assistant_private')
        self.skills = SkillLibrary(self.root / 'subprojects/web_demo/assistant_skills')
        self._cancellations = {}
        self._watch_versions = {}

    @staticmethod
    def initialize(browser):
        browser = browser if isinstance(browser, dict) else {}
        token = str(browser.get('client_id') or '')
        if len(token) != 32 or any(character not in '0123456789abcdef' for character in token):
            token = secrets.token_hex(16)
        return {'client_id': token}

    @staticmethod
    def paths(value):
        values = value if isinstance(value, list) else [value] if value else []
        return [Path(item if isinstance(item, str) else item.get('path', '') if isinstance(item, dict) else item.name) for item in values]

    def evidence(self, dfd, topology, interfaces, job_id, name, settings=None):
        return ProjectEvidence(dfd_paths=self.paths(dfd), topology=next(iter(self.paths(topology)), None),
                               interfaces=next(iter(self.paths(interfaces)), None), job_id=job_id,
                               jobs_root=self.jobs_root, queue_root=self.queue_root,
                               project_name=name, settings=settings)

    @staticmethod
    def heading(evidence):
        state = '任务已关联' if evidence.job_id else f'{len(evidence.dfd_paths)} 份 DFD' if evidence.dfd_paths else '未导入资料'
        name = evidence.project_name or '尚未命名的项目'
        detail = evidence.job_id or '项目资料、分析结果和已保存约束作为上下文'
        return (f'<div class="assistant-project" data-assistant-job-id="{html.escape(evidence.job_id or "",quote=True)}" title="{html.escape(detail,quote=True)}"><span class="assistant-connected"></span><div><b>{html.escape(name)}</b>'
                f'<small><span data-assistant-page>当前项目</span> · {html.escape(state)}</small></div></div>')

    def sync(self, dfd, topology, interfaces, job_id, name, browser):
        if not isinstance(browser, dict) or not browser.get('client_id'):
            return gr.skip(), gr.skip(), gr.skip()
        try:
            evidence = self.evidence(dfd, topology, interfaces, job_id, name)
            scope = self.store.scope(browser['client_id'], evidence.project_key)
            previous = self.store.current_context(browser['client_id'])
            current_files = [str(path) for path in self.paths(dfd)]
            same = (previous.get('job_id') == evidence.job_id and previous.get('name') == name
                    and _same_files(previous.get('dfd', []), current_files)
                    and _same_files([previous.get('topology', '')], [str(next(iter(self.paths(topology)), ''))])
                    and _same_files([previous.get('interfaces', '')], [str(next(iter(self.paths(interfaces)), ''))]))
            if same and previous.get('workspace_scope'):
                scope = previous.get('scope', scope)
            binding = {'job_id': evidence.job_id, 'scope': scope, 'name': name,
                       'workspace_scope': previous.get('workspace_scope', scope) if same else scope,
                       'memory_scope': self.store.scope(browser['client_id'], evidence.memory_key),
                       'dfd': [str(path) for path in self.paths(dfd)],
                       'topology': str(next(iter(self.paths(topology)), '')),
                       'interfaces': str(next(iter(self.paths(interfaces)), ''))}
            if same:
                for key in ('pending_effects', 'report_override', 'selection', 'report_excel'):
                    if key in previous:
                        binding[key] = previous[key]
            self.store.remember_context(browser['client_id'], binding)
            return self.store.history(scope), self.heading(evidence), binding
        except AssistantError as exc:
            return [], '<div class="assistant-project">' + html.escape(str(exc)) + '</div>', {}

    def sync_draft(self, dfd, topology, interfaces, name, browser):
        if browser and browser.get('client_id'):
            saved = self.store.current_context(browser['client_id'])
            # File postprocessing can fire while a restored name component is
            # still mounting. Only a real name-input event clears that label.
            name = name or saved.get('name') or ''
            if (saved.get('job_id') and _same_files(saved.get('dfd', []), [str(p) for p in self.paths(dfd)])
                    and _same_files([saved.get('topology', '')], [str(next(iter(self.paths(topology)), ''))])
                    and _same_files([saved.get('interfaces', '')], [str(next(iter(self.paths(interfaces)), ''))])):
                return self.sync(dfd, topology, interfaces, saved['job_id'], name, browser)
        return self.sync(dfd, topology, interfaces, '', name, browser)

    def sync_project_name(self, dfd, topology, interfaces, name, browser):
        return self.sync(dfd, topology, interfaces, '', name, browser)

    def restore(self, dfd, topology, interfaces, job_id, name, browser):
        if isinstance(browser, dict) and browser.get('client_id') and not any((dfd, topology, interfaces, job_id, name)):
            saved = self.store.current_context(browser['client_id'])
            if saved:
                result = self.sync(saved.get('dfd'), saved.get('topology'), saved.get('interfaces'),
                                   saved.get('job_id'), saved.get('name'), browser)
                if saved.get('scope') and not saved.get('job_id'):
                    binding = {**result[2], 'scope': saved['scope']}
                    self.store.remember_context(browser['client_id'], binding)
                    return self.store.history(saved['scope']), result[1], binding
                return result
        return self.sync(dfd, topology, interfaces, job_id, name, browser)

    def clear(self, binding):
        if isinstance(binding, dict) and binding.get('scope'):
            self.store.clear(binding['scope'])
        return [], '', '本项目的对话已清空，项目记忆保留。', render_agent_trace([])

    def memory_view(self, browser, binding):
        if not isinstance(browser, dict) or not (binding or {}).get('memory_scope'):
            return '连接项目后，可以保存和检索项目约束与历史问答。'
        rows = self.store.recall(binding['memory_scope'], '', 8)
        if not rows:
            return '暂无项目记忆。可以说“记住：这个项目……”。完成问答后会保存标明来源的历史摘要。'
        return '\n\n'.join('**' + ('项目约束' if row['kind'] == 'fact' else '历史问答') + '** · '
            + row['updated_at'][:10] + '\n\n' + row['text'].replace('<', '&lt;') + '\n\n*' + row['source'] + '*'
            for row in rows)

    def cancel(self, binding):
        event = self._cancellations.get((binding or {}).get('scope'))
        if event:
            event.set()
            return '正在结束本轮助手操作，已有检索结果会保留。'
        return '当前没有正在执行的助手任务。'

    def ask(self, question, dfd, topology, interfaces, name, browser, binding,
            model, api_base, api_key, external_model, impact, feasibility, skill='auto',
            mode='agent', requested_context='auto', runtime=None):
        question = str(question or '').strip()
        if not question:
            yield gr.skip(), gr.skip(), '请输入问题。', gr.skip(), gr.update(interactive=True)
            return
        service = configured_api()
        if service is None:
            yield gr.skip(), gr.skip(), API_REQUIRED, gr.skip(), gr.update(interactive=True)
            return
        api_base, api_key, external_model = service
        scope = ''
        try:
            if len(question) > 200000:
                raise AssistantError('问题超过20万字符，请将大段资料作为项目文件导入后按需读取')
            if not isinstance(browser, dict):
                raise AssistantError('会话尚未初始化，请刷新页面')
            if not any((dfd, topology, interfaces)) and binding:
                dfd, topology, interfaces = binding.get('dfd'), binding.get('topology'), binding.get('interfaces')
            evidence = self.evidence(dfd, topology, interfaces, (binding or {}).get('job_id', ''), name or (binding or {}).get('name'),
                                     {'impact_method': impact, 'feasibility_method': feasibility})
            scope = self.store.scope(browser.get('client_id'), evidence.project_key)
            if (binding or {}).get('scope'):
                scope = binding['scope']
            selected = str(external_model or model or '').strip()
            if not selected:
                raise AssistantError('请先在模型服务中选择可用模型或填写云端模型名称')
            with self.store.lock(scope):
                prior = self.store.history(scope)
                self.store.append(scope, 'user', question)
                yield self.store.history(scope), '', '正在连接项目、记忆与技能…', render_agent_trace([]), gr.update(interactive=False)
                mailbox = queue.Queue()
                stop = threading.Event()
                self._cancellations[scope] = stop
                memory_scope = self.store.scope(browser['client_id'], evidence.memory_key)
                options = dict(runtime or {})
                options.update(selected_model=selected, api_base=api_base, api_key=api_key,
                    external_model_name=external_model, impact_method=impact, feasibility_method=feasibility)

                def run():
                    try:
                        result = answer_question(evidence, question, prior, model=selected, api_base=api_base,
                            api_key=api_key, memory_store=self.store, memory_scope=memory_scope, skill=skill,
                            root=self.root, cancel_event=stop, workspace_scope=(binding or {}).get('workspace_scope', scope),
                            runtime=options, mode=mode, requested_context=requested_context, request_id=uuid.uuid4().hex,
                            progress=lambda event: mailbox.put(('event', event)))
                        mailbox.put(('result', result))
                    except Exception as exc:
                        mailbox.put(('error', exc))
                worker = threading.Thread(target=run, daemon=True)
                worker.start()
                events, plan = [], []
                try:
                    while True:
                        try:
                            kind, value = mailbox.get(timeout=.5)
                        except queue.Empty:
                            continue
                        if kind == 'error':
                            raise value
                        if kind == 'result':
                            result = value
                            break
                        if value.get('phase') == 'delta':
                            if self.store.current_context(browser['client_id']).get('scope') == scope:
                                draft = [*self.store.history(scope), {'role': 'assistant', 'content': value['text']}]
                                yield draft, gr.skip(), '正在生成…', gr.skip(), gr.update(interactive=False)
                            continue
                        events.append(value)
                        if value.get('steps'):
                            plan = value['steps']
                        if self.store.current_context(browser['client_id']).get('scope') == scope:
                            yield gr.skip(), gr.skip(), value.get('title', '正在核查…'), render_agent_trace(events, plan), gr.update(interactive=False)
                finally:
                    stop.set()
                    if self._cancellations.get(scope) is stop:
                        self._cancellations.pop(scope, None)
                self.store.append(scope, 'assistant', result['answer'])
                if self.store.current_context(browser['client_id']).get('scope') != scope:
                    # A slow answer belongs to its original conversation;
                    # switching projects must never paint it into the new one.
                    yield gr.skip(), gr.skip(), gr.skip(), gr.skip(), gr.update(interactive=True)
                    return
                current = self.store.current_context(browser['client_id'])
                if result.get('effects'):
                    current['pending_effects'] = result['effects']
                    self.store.remember_context(browser['client_id'], current)
                state = '回答已保存 · 可继续追问' if result.get('status', 'complete') == 'complete' else '本轮执行已结束 · 可继续追问'
                yield self.store.history(scope), '', state, render_agent_trace(result['trace'], result.get('plan', [])), gr.update(interactive=True)
        except Exception as exc:
            message = str(exc) if isinstance(exc, AssistantError) else f'助手暂时无法完成回答（{type(exc).__name__}），请重试'
            if api_key:
                message = message.replace(api_key, '[已隐藏]')
            if scope:
                self.store.append(scope, 'assistant', message)
                if self.store.current_context(browser['client_id']).get('scope') != scope:
                    yield gr.skip(), gr.skip(), gr.skip(), gr.skip(), gr.update(interactive=True)
                    return
            yield self.store.history(scope) if scope else gr.skip(), question, message, render_agent_trace([]), gr.update(interactive=True)

    def view_context(self, page, asset_id, tree_state, binding):
        preview = None
        if isinstance(page, str) and page.startswith('{') and len(page) <= 24000:
            try:
                payload = json.loads(page)
                page = payload.get('page', '')
                if payload.get('job_id', '') == (binding or {}).get('job_id', ''):
                    preview = str(payload.get('preview') or '')[:14000]
            except (ValueError, TypeError):
                page = ''
        view = {'page': page} if page in {'input','strategy','agent','delivery','attack_tree'} else {}
        if preview and view:
            view['browser_preview'] = {'text': preview, 'source': '当前网页可见内容摘录',
                                       'untrusted_document_content': True}
        if page != 'attack_tree' or not asset_id:
            return view
        if not binding or not tree_state or tree_state.get('job_id') != binding.get('job_id'):
            return view
        from .demo_attack_tree import AttackTreeController
        try:
            catalog = AttackTreeController(self.jobs_root, None)._catalog(tree_state)
            entry = next((item for item in catalog if item['id']==asset_id),None)
            if entry:
                view['selected_asset'] = {key:entry['asset'].get(key,'') for key in
                    ('asset_name','asset_type','element_id','source','target')}
                view['selected_asset']['label'] = entry['label']
                view['asset_id'] = asset_id
        except (ValueError,OSError,KeyError):
            view['notice'] = '攻击树报告已更新，请刷新后重新选择资产'
        return view

    def ask_from_ui(self, question, browser, binding, skill, mode, requested_context, page, asset_id, tree_state, *run_values):
        import inspect
        from .demo import run_analysis
        keys = list(inspect.signature(run_analysis).parameters)
        options = dict(zip(keys, run_values))
        options['assistant_view_context'] = self.view_context(page,asset_id,tree_state,binding)
        yield from self.ask(question, options.pop('dfd_files', None), options.pop('topology_file', None),
            options.pop('interfaces_file', None), options.pop('project_label', ''), browser, binding,
            options.get('selected_model'), options.get('api_base'), options.get('api_key'),
            options.get('external_model_name'), options.get('impact_method'), options.get('feasibility_method'),
            skill, mode, requested_context, options)

    def apply_workspace(self, browser, binding, current_dfd=None):
        """Connect successful actions to real Gradio input/report/job components."""
        if not browser or not binding:
            return (gr.skip(),) * 11
        with self.store.lock(str(binding.get('scope') or 'unbound') + '.ui'):
            return self._apply_workspace(browser, binding, current_dfd)

    def _apply_workspace(self, browser, binding, current_dfd=None):
        if not browser or not binding:
            return (gr.skip(),) * 11
        saved = self.store.current_context(browser['client_id'])
        if saved.get('scope') != binding.get('scope'):
            return (gr.skip(),) * 11
        effects = saved.pop('pending_effects', {})
        if not effects:
            canonical = {key: saved.get(key) for key in ('dfd', 'topology', 'interfaces')}
            state_path = self.store.root / 'workspaces' / saved.get('workspace_scope', saved['scope']) / 'state.json'
            if state_path.is_file():
                try:
                    state = json.loads(state_path.read_text(encoding='utf-8'))
                    canonical = state.get('inputs') or canonical
                except (OSError, ValueError):
                    pass
            if not current_dfd and canonical.get('dfd') and all(Path(p).is_file() for p in canonical['dfd']):
                effects = {'inputs': canonical}
                if saved.get('selection'):
                    effects['selection'] = saved['selection']
                if saved.get('report_override'):
                    effects.update(report=saved['report_override'], excel=saved.get('report_excel'))
            else:
                return (gr.skip(),) * 11
        result = [gr.skip() for _ in range(11)]
        if effects.get('inputs'):
            values = effects['inputs']
            result[:3] = [values['dfd'], values['topology'], values['interfaces']]
            saved.update(values)
        if 'selection' in effects:
            result[3] = effects.get('selection') or {}
            saved['selection'] = result[3]
        if effects.get('report'):
            result[4] = {'job_id': saved.get('job_id', ''), 'report': effects['report'], 'excel': effects.get('excel')}
            saved['report_override'] = effects['report']
            saved['report_excel'] = effects.get('excel')
        elif effects.get('undo') and 'report' in effects:
            result[4] = {'clear': True}
            saved.pop('report_override', None)
        if effects.get('detach_job'):
            saved['job_id'] = ''
            result[5:7] = ['', gr.update(active=False)]
            result[4] = {'clear': True}
            saved.pop('report_override', None)
            saved.pop('report_excel', None)
        if effects.get('job_id'):
            job_id = effects['job_id']
            new_evidence = self.evidence(None, None, None, job_id, saved.get('name'))
            new_scope = self.store.scope(browser['client_id'], new_evidence.project_key)
            if not self.store.history(new_scope):
                for item in self.store.history(saved['scope']):
                    self.store.append(new_scope, item['role'], item['content'])
            saved.update(job_id=job_id, scope=new_scope)
            if not effects.get('report'):
                result[4] = {'clear': True, 'job_id': job_id}
                saved.pop('report_override', None)
                saved.pop('report_excel', None)
            result[5:7] = [job_id, gr.update(active=True)]
        if effects.get('artifacts'):
            result[7] = gr.update(value=[p for p in effects['artifacts'] if Path(p).is_file()], visible=True)
        self.store.remember_context(browser['client_id'], saved)
        result[8] = saved
        evidence = self.evidence(saved.get('dfd'), saved.get('topology'), saved.get('interfaces'), saved.get('job_id'), saved.get('name'))
        result[9] = self.heading(evidence)
        result[10] = saved.get('name') or ''
        return tuple(result)

    def watch(self, browser, binding):
        if not browser or not binding or not binding.get('job_id'):
            return '<div class="assistant-watch-idle">项目资料、当前任务与报告自动作为上下文</div>'
        try:
            from .live_model_output import read_model_events
            evidence = self.evidence(None, None, None, binding['job_id'], binding.get('name'))
            from .assistant_progress import digest
            status = evidence.status(include_logs=False)
            paths = sorted(evidence.job_root.rglob('*')) if evidence.job_root and evidence.job_root.is_dir() else []
            stamps = []
            for path in paths[:4000]:
                try:
                    stat = path.stat()
                    if path.is_file():
                        stamps.append((str(path), stat.st_size, stat.st_mtime_ns))
                except OSError:
                    pass
            token = (binding['job_id'], digest([status, stamps]))
            client = browser.get('client_id') or binding.get('scope') or binding['job_id']
            if self._watch_versions.get(client) == token:
                return gr.skip()
            status = evidence.status()
            events = read_model_events(evidence.job_root, 1)
            event = events[-1] if events else {}
            output = event.get('error') or event.get('output') or '\n'.join(status.get('log_excerpt', [])[-3:]) or '等待模型输出'
            from .demo import diagnose_runtime
            diagnosis = diagnose_runtime(event.get('error', '') + '\n' + '\n'.join(status.get('log_excerpt', [])), {})
            advice = diagnosis.get('建议动作', '')
            state = {'queued':'排队中','running':'进行中','completed':'已完成','failed':'需处理','cancelled':'已取消','cancelling':'正在停止'}.get(status.get('status'),'状态待确认')
            self._watch_versions[client] = token
            if len(self._watch_versions) > 128:
                self._watch_versions.pop(next(iter(self._watch_versions)))
            return '<details class="assistant-watch" data-model-calls="0"><summary><i></i><span>任务观察</span><small>' + html.escape(state) + '</small></summary><pre>' + html.escape(output[-7000:]) + '</pre>' + ('<p>' + html.escape(advice) + '</p>' if advice else '') + '</details>'
        except Exception:
            return '<div class="assistant-watch-idle">正在等待当前任务状态</div>'
