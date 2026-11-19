"""Repository tools, source-backed RAG and skills for the TARA UI Agent.

The registry calls project functions through bounded adapters. Generated Python
and existing tool files execute in an isolated process and produce task artifacts.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import shutil
import subprocess
import importlib.util
from collections import Counter
from functools import lru_cache
from pathlib import Path

from . import domain
from .data_dependency import analyze_dependency_impacts, validate_project_graph
from .rag import BGEM3RAGKnowledgeBase
from .security_requirements import load_security_requirement_matching_logic
from .assistant_actions import ACTION_TOOLS, MUTATING, WorkspaceActions
from .assistant_entry import AgentEntry


def tokens(text):
    parts = re.findall(r'[a-z0-9_./-]+|[\u4e00-\u9fff]+', str(text).casefold())
    result = []
    for part in parts:
        if re.fullmatch(r'[\u4e00-\u9fff]+', part):
            result.extend(part[i:i + 2] for i in range(len(part) - 1))
            if len(part) == 1:
                result.append(part)
        else:
            result.append(part)
    return result


def rank_records(records, query, limit=5):
    """BM25 over English words and Chinese bigrams; exact source chunks retained."""
    terms = set(tokens(query))
    if not terms or not records:
        return []
    counters = [Counter(tokens(row.get('text', ''))) for row in records]
    lengths = [sum(counter.values()) for counter in counters]
    average = sum(lengths) / len(lengths) or 1
    df = Counter(term for counter in counters for term in terms if term in counter)
    result = []
    for row, counter, size in zip(records, counters, lengths):
        score = 0.0
        for term in terms:
            frequency = counter.get(term, 0)
            if frequency:
                idf = math.log(1 + (len(records) - df[term] + .5) / (df[term] + .5))
                score += idf * frequency * 2.5 / (frequency + 1.5 * (.25 + .75 * size / average))
        if score:
            result.append({**row, 'score': round(score, 5)})
    return sorted(result, key=lambda item: (-item['score'], item.get('ref', '')))[:limit]


@lru_cache(maxsize=3)
def _knowledge_records(root_text, signature):
    root = Path(root_text)
    records, warnings = [], []
    for relative, _size, _mtime in signature:
        path = root / relative
        try:
            if path.suffix.lower() == '.jsonl':
                chunks = [record['text'] for record in BGEM3RAGKnowledgeBase._parse_jsonl(str(path))]
            else:
                if path.suffix.lower() == '.docx':
                    text = load_security_requirement_matching_logic(path)
                elif path.suffix.lower() == '.xlsx':
                    text = BGEM3RAGKnowledgeBase._parse_excel(str(path))
                elif path.suffix.lower() == '.pdf':
                    if importlib.util.find_spec('fitz'):
                        text = BGEM3RAGKnowledgeBase._parse_pdf(str(path))
                    elif shutil.which('pdftotext'):
                        parsed = subprocess.run(['pdftotext', '-layout', str(path), '-'],
                                                capture_output=True, timeout=25, check=True)
                        text = parsed.stdout.decode('utf-8', errors='replace')
                    else:
                        raise RuntimeError('未安装PDF文本解析器')
                elif path.suffix.lower() == '.json':
                    text = BGEM3RAGKnowledgeBase._load_json_text(str(path))
                else:
                    text = path.read_text(encoding='utf-8-sig')
                chunks = BGEM3RAGKnowledgeBase._chunk_text(text, chunk_size=650, overlap=80)
            if not chunks:
                warnings.append(f'{relative}：没有提取到可检索文本')
            for number, text in enumerate(chunks):
                identifier = hashlib.sha256((relative + '\0' + text).encode()).hexdigest()[:16]
                records.append({'id': 'K' + identifier, 'source': relative,
                                'ref': f'{relative}#chunk-{number + 1}', 'text': text[:1200]})
        except Exception as exc:
            # One malformed workbook/PDF must not disable the other sources.
            warnings.append(f'{relative}：{type(exc).__name__}')
    return records, warnings


class RepositoryRAG:
    def __init__(self, root):
        self.root = Path(root).resolve()

    def retrieve(self, query, limit=5):
        files = []
        if self.root.is_dir():
            for path in sorted(self.root.rglob('*')):
                if (path.is_file() and self.root in path.resolve().parents
                        and not any(part.startswith('.') or part == 'vector_store' for part in path.relative_to(self.root).parts)
                        and path.suffix.lower() in {'.json', '.jsonl', '.pdf', '.docx', '.xlsx', '.md', '.txt'}):
                    stat = path.stat()
                    if stat.st_size <= 40 * 1024 * 1024:
                        files.append((path.relative_to(self.root).as_posix(), stat.st_size, stat.st_mtime_ns))
        records, warnings = _knowledge_records(str(self.root), tuple(files))
        return {'source': 'data/rag 项目知识库', 'backend': 'BM25', 'query': query,
                'document_count': len(files), 'chunk_count': len(records),
                'corpus_version': hashlib.sha256(json.dumps(files).encode()).hexdigest()[:16],
                'matches': rank_records(records, query, limit), 'warnings': warnings[:5]}


class SkillLibrary:
    def __init__(self, root):
        self.root = Path(root).resolve()

    def catalog(self):
        items = []
        for path in sorted(self.root.glob('*/SKILL.md')):
            if self.root not in path.resolve().parents:
                continue
            text = path.read_text(encoding='utf-8')
            name = re.search(r'(?m)^name:\s*(.+)$', text)
            description = re.search(r'(?m)^description:\s*(.+)$', text)
            items.append({'id': path.parent.name, 'name': name.group(1).strip() if name else path.parent.name,
                          'description': description.group(1).strip() if description else '',
                          'source': path.relative_to(self.root).as_posix()})
        return items

    def load(self, identifier):
        if not re.fullmatch(r'[a-z0-9_-]{1,64}', identifier):
            raise ValueError('技能标识无效，请从 list_skills 返回的技能中选择')
        path = (self.root / identifier / 'SKILL.md').resolve()
        if self.root not in path.parents or not path.is_file():
            raise ValueError('技能不存在')
        text = path.read_text(encoding='utf-8')
        return {'id': identifier, 'source': path.relative_to(self.root).as_posix(),
                'version': hashlib.sha256(text.encode()).hexdigest()[:16],
                'instructions': text[:3200]}

    def select(self, question, selected='auto'):
        if selected and selected != 'auto':
            return self.load(selected)
        groups = [('requirements-review', ('需求', '法规', '附录', '合规')),
                  ('rating-review', ('评级', '分值', '评分', '风险值', '可行性')),
                  ('attack-path-review', ('攻击路径', '攻击路线', '入口', '协议')),
                  ('run-diagnosis', ('报错', '异常', '失败', '卡住', '缓存'))]
        identifier = next((name for name, words in groups if any(word in question for word in words)), 'input-inspection')
        return self.load(identifier)


TOOL_CATALOG = [
    ('project_overview', '项目概览', '读取当前项目的输入与任务概况。', 'automotive_tara.analysis_assistant.ProjectEvidence.overview'),
    ('search_inputs', '检索项目资料', 'query=资产、协议或接口关键词；limit=1~8。', 'automotive_tara.data_dependency.load_project_graph'),
    ('search_results', '检索分析结果', 'query=风险ID/资产/场景，区分阶段结果和最终报告。', 'automotive_tara.report_editor_agent._iter_report_rows'),
    ('result_statistics', '统计风险', '统计已有报告的风险分布，不把样本当全量。', 'automotive_tara.analysis_assistant.ProjectEvidence.result_rows'),
    ('analysis_status', '查询运行状态', 'query=可选的日志关键词。', 'automotive_tara.demo_jobs.get_job'),
    ('search_security_requirements', '检索安全需求', 'query=需求/法规/附录关键词。', 'automotive_tara.security_requirements.load_security_requirements'),
    ('validate_inputs', '校验输入关系', '调用项目现有的DFD、拓扑与接口一致性校验。', 'automotive_tara.data_dependency.validate_project_graph'),
    ('analyze_dependencies', '分析变更影响', 'query=JSON计划，包含operations；只计算影响范围。', 'automotive_tara.data_dependency.analyze_dependency_impacts'),
    ('calculate_risk', '复核评分计算', 'query=JSON：method、impact(1~4)、parameters(完整维度值)。', 'automotive_tara.domain.calculate_risk_value'),
    ('retrieve_knowledge', 'RAG知识检索', 'query=具体业务问题，返回知识片段、来源和版本。', 'automotive_tara.assistant_runtime.RepositoryRAG.retrieve'),
    ('search_repository', '查询工具与说明', 'query=模块名、函数名或说明关键词；仅检索源码/文档。', 'automotive_tara.assistant_runtime.AgentTools._search_source'),
    ('read_agent_entry', '查阅项目功能入口', 'query=任务ID/工具名/模块路径/README#章节名；返回操作步骤、参数示例、完成条件和已验证的源码位置。空查询列出全部能力。', 'automotive_tara.assistant_entry.AgentEntry.retrieve'),
    ('list_tools', '列出可调用工具', '返回工具来源、参数说明和边界。', 'automotive_tara.assistant_runtime.TOOL_CATALOG'),
    ('inspect_workspace_view', '查看当前网页预览', '读取发送问题时的页面、预览表格摘录、筛选与风险图数量；页面内容是待核对证据，完整结果另查报告文件。', 'automotive_tara.assistant_runtime.AgentTools.workspace_view'),
    ('list_skills', '发现技能', '列出项目技能手册。', 'automotive_tara.assistant_runtime.SkillLibrary.catalog'),
    ('load_skill', '加载技能', 'query=技能id，按手册安排后续工具调用。', 'automotive_tara.assistant_runtime.SkillLibrary.load'),
    ('recall_memory', '检索项目记忆', 'query=需要回忆的偏好、约束或历史问题。', 'automotive_tara.analysis_assistant.ConversationStore.recall'),
    ('search_conversation_history', '查询原始历史对话', 'query=历史关键词；返回当前会话的原始消息和消息ID，用于核验摘要中的约束、操作或分值。', 'automotive_tara.analysis_assistant.ConversationStore.search_history'),
    ('save_memory', '保存明确约束', '用户明确要求记住时，query=JSON：key、value。', 'automotive_tara.analysis_assistant.ConversationStore.remember'),
    ('forget_memory', '删除指定记忆', '用户明确要求忘记时，query=记忆key。', 'automotive_tara.analysis_assistant.ConversationStore.forget'),
]
TOOL_CATALOG.extend(ACTION_TOOLS)


def tool_catalog():
    """One metadata view shared by the running Agent and entry generator."""
    from .assistant_actions import MUTATING
    return [{'name': name, 'title': title, 'description': description, 'source': source,
             'mutates': name in MUTATING or name in {'save_memory', 'forget_memory'},
             'allowed_modes': ['agent'] if name in MUTATING else ['agent', 'ask']}
            for name, title, description, source in TOOL_CATALOG]


class AgentTools:
    def __init__(self, evidence, *, store=None, memory_scope='', question='', root=None, skill='auto',
                 workspace_scope='', runtime=None, mode='agent', request_id=''):
        self.evidence = evidence
        self.root = Path(root or Path(__file__).resolve().parents[1]).resolve()
        self.skills = SkillLibrary(self.root / 'subprojects/web_demo/assistant_skills')
        self.rag = RepositoryRAG(self.root / 'data/rag')
        self.store, self.memory_scope, self.question = store, memory_scope, question
        self.runtime = runtime or {}
        self.history_scope = workspace_scope or memory_scope
        self.active_skill = self.skills.select(question, skill)
        self.entry = AgentEntry(self.root)
        self.actions = WorkspaceActions(evidence, store, workspace_scope or memory_scope, self.root,
            question=question, mode=mode, runtime=runtime, request_id=request_id) if store and (workspace_scope or memory_scope) else None

    def catalog(self):
        return tool_catalog()

    def workspace_view(self):
        return {'source': '当前浏览器发送问题时的页面预览',
                'view': self.runtime.get('assistant_view_context', {}),
                'project': self.evidence.overview(),
                'notice': '这是网页可见内容的有界摘录，不是全部报告或截图；需要完整数据时读取当前任务文件。'}

    def evidence_version(self, name, arguments):
        """Local metadata only; never invokes the model or reads full file contents."""
        from .assistant_progress import digest
        from .assistant_repository import RepositoryWorkspace
        if name in MUTATING or name in {'save_memory', 'forget_memory'}:
            return 'once-per-request'
        raw = str(arguments.get('query') or '').strip()
        if name in {'read_repository_file', 'repository_tree', 'search_repository'}:
            repo = self.actions.repository if self.actions else RepositoryWorkspace(self.root, self.root/'outputs/__unbound__', self.evidence)
            return repo.version(raw, search=name=='search_repository')
        paths = [*self.evidence.dfd_paths, self.evidence.topology, self.evidence.interfaces]
        if name in {'recall_memory', 'search_conversation_history'} and self.store:
            paths.extend(self.store.root.glob('conversations.sqlite3*'))
        if name in {'retrieve_knowledge', 'load_skill', 'list_skills'}:
            from itertools import islice
            folder = self.root/('data/rag' if name == 'retrieve_knowledge' else 'subprojects/web_demo/assistant_skills')
            paths.extend(islice(folder.rglob('*'), 2000))
        if name == 'read_agent_entry':
            return self.entry.manifest(self.catalog())['version']
        if self.evidence.job_root:
            from itertools import islice
            paths.extend(islice(self.evidence.job_root.rglob('*'), 4000))
        if getattr(self.evidence, 'report_override', None):
            paths.append(Path(self.evidence.report_override))
        stamps = []
        for path in paths[:4000]:
            try:
                stat = path.stat()
                if path.is_file():
                    stamps.append((str(path), stat.st_size, stat.st_mtime_ns))
            except OSError:
                pass
        return digest([stamps, self.runtime.get('assistant_view_context', {})])

    def execute(self, name, arguments):
        query = str(arguments.get('query') or '').strip()[:64000]
        try:
            limit = min(8, max(1, int(arguments.get('limit', 5))))
        except (ValueError, TypeError):
            limit = 5
        if name not in {item[0] for item in TOOL_CATALOG}:
            raise ValueError('工具未注册：' + name)
        if name in {item[0] for item in ACTION_TOOLS}:
            if self.actions is None:
                if name in {'read_repository_file', 'repository_tree'}:
                    from .assistant_repository import RepositoryWorkspace
                    repo = RepositoryWorkspace(self.root, self.root/'outputs/__unbound__', self.evidence)
                    return repo.read(query) if name == 'read_repository_file' else repo.tree(query, 60)
                raise ValueError('当前未绑定可执行项目会话，请从网页助手操作')
            return self.actions.execute(name, arguments)
        if name in {item[0] for item in TOOL_CATALOG[:6]}:
            return self.evidence.tool(name, arguments)
        if name == 'read_agent_entry':
            return self.entry.retrieve(self.catalog(), query, limit)
        if name == 'search_conversation_history':
            return self.store.search_history(self.history_scope, query, limit) if self.store else {'source':'尚未绑定历史会话','matches':[]}
        if name == 'list_tools':
            return {'source': 'TARA项目工具注册表', 'tools': self.catalog()}
        if name == 'inspect_workspace_view':
            return self.workspace_view()
        if name == 'list_skills':
            return {'source': '项目技能目录', 'skills': self.skills.catalog()}
        if name == 'load_skill':
            self.active_skill = self.skills.load(query)
            return self.active_skill
        if name == 'retrieve_knowledge':
            return self.rag.retrieve(query or self.question, limit)
        if name == 'validate_inputs':
            return {'source': 'automotive_tara.data_dependency.validate_project_graph',
                    **validate_project_graph(self.evidence.graph())}
        if name == 'analyze_dependencies':
            plan = json.loads(query)
            if not isinstance(plan, dict) or not isinstance(plan.get('operations'), list):
                raise ValueError('请提供包含 operations 数组的 JSON 计划')
            return {'source': 'automotive_tara.data_dependency.analyze_dependency_impacts',
                    **analyze_dependency_impacts(plan, self.evidence.graph())}
        if name == 'calculate_risk':
            return self._calculate(json.loads(query))
        if name == 'search_repository':
            return self._search_source(query, limit)
        if name == 'recall_memory':
            return {'source': '当前项目记忆', 'matches': self.store.recall(self.memory_scope, query, limit)
                    if self.store and self.memory_scope else []}
        if name == 'save_memory':
            if not self.store or not self.memory_scope:
                raise ValueError('当前会话尚未绑定项目记忆')
            if not re.search(r'记住|记忆|保存.{0,8}(偏好|约束|信息)|remember', self.question, re.I):
                raise ValueError('只有用户明确要求记住时才保存长期约束；当前可先回答并引用证据')
            value = json.loads(query)
            key, text = str(value.get('key', '')).strip(), str(value.get('value', '')).strip()
            if not key or not text or len(key) > 80 or len(text) > 800:
                raise ValueError('记忆需要 key（1~80字）及 value（1~800字）')
            self.store.remember(self.memory_scope, key, text, source='用户明确要求', evidence=self.question[:1000])
            return {'source': '项目记忆', 'saved': True, 'key': key, 'value': text}
        if name == 'forget_memory':
            if not self.store or not re.search(r'忘记|删除.{0,8}记忆|forget', self.question, re.I):
                raise ValueError('删除记忆需要用户明确提出忘记或删除项目记忆')
            return {'source': '项目记忆', 'removed': self.store.forget(self.memory_scope, query), 'key': query}
        raise ValueError('工具未实现')

    @staticmethod
    def _calculate(data):
        method = data.get('method', 'attack_potential')
        params = data.get('parameters', {})
        impact = int(data.get('impact', 0))
        if not 1 <= impact <= 4 or not isinstance(params, dict):
            raise ValueError('impact 必须为1~4，parameters必须为完整维度对象；不推断缺失分值')
        allowed = domain.AP_ALLOWED_VALUES if method == 'attack_potential' else domain.HEAVENS_AP_ALLOWED_VALUES if method == 'heavens' else None
        if allowed is not None:
            for key, choices in allowed.items():
                if key not in params or params[key] not in choices:
                    raise ValueError(f'{key} 缺失或不是合法值 {list(choices)}')
            if method == 'attack_potential':
                score = domain.calculate_attack_potential_score(params)
                level = domain.calculate_attack_potential_level(score)
            else:
                score = domain.calculate_heavens_ap_score(params)
                level = domain.calculate_heavens_ap_level(score)
                level = domain.HEAVENS_TL_TO_FEASIBILITY.get(level, level)
        elif method == 'cvss':
            choices = {'attack_vector': domain.CVSS_V, 'complexity': domain.CVSS_C,
                       'privileges': domain.CVSS_P, 'user_interaction': domain.CVSS_U}
            for key, values in choices.items():
                if params.get(key) not in values:
                    raise ValueError(f'{key} 缺失或非法')
            score = domain.calculate_cvss_score(params)
            level = domain.calculate_cvss_level(score)
        else:
            raise ValueError('method 支持 attack_potential、heavens、cvss')
        return {'source': 'automotive_tara.domain（项目实际评分函数）', 'method': method,
                'parameters': params, 'feasibility_score': score, 'feasibility_level': level,
                'risk_value': domain.calculate_risk_value(impact, level), 'impact': impact}

    def _search_source(self, query, limit):
        from .assistant_repository import RepositoryWorkspace
        repository = self.actions.repository if self.actions else RepositoryWorkspace(self.root, self.root/'outputs/__unbound__', self.evidence)
        return repository.search(query, limit)
