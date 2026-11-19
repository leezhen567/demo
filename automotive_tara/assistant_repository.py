"""Repository navigation and isolated execution for the workspace Agent."""
from __future__ import annotations
import ast
import fnmatch
import hashlib
from itertools import islice
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import uuid
from pathlib import Path

CODE_ROOTS = ('automotive_tara', 'scripts', 'tools', 'docs', 'subprojects', 'tests')
SKIP = {'.git', '__pycache__', 'node_modules', '.venv', 'venv', '.cache', 'outputs', 'vector_store', 'data'}
TEXT_TYPES = {'.py', '.md', '.txt', '.toml', '.json', '.yaml', '.yml', '.html', '.css', '.js', '.sh', '.cjs', '.log', '.csv', '.jsonl', '.xml', '.ini', '.cfg'}
PURPOSES = {
    'automotive_tara': 'TARA 主流程、领域评分、模型网关、阶段任务及网页服务',
    'scripts': '模型切换、LoRA 准备、数据整理与实验执行脚本',
    'tools': '独立数据转换、校验和加工工具',
    'docs': '使用、交接、业务和架构说明',
    'subprojects': '网页 Demo、工程修复代理及研究子项目',
    'tests': '代码回归和行为验证', 'data': '项目输入、专家标注和检索知识资料',
    'outputs': '分析报告、检查点、日志和持久化队列',
    'experiments': '实验协议、固定样本和评测结果', 'deliverables': '对外交付材料',
}


class RepositoryWorkspace:
    def __init__(self, root, artifacts, evidence=None):
        self.root, self.artifacts = Path(root).resolve(), Path(artifacts).resolve()
        self.evidence = evidence

    def path(self, relative, *, file=False):
        text = str(relative or '.')
        value = Path(text)
        if value.is_absolute():
            try:
                value = value.relative_to(self.root)
            except ValueError:
                raise ValueError('路径必须在 TARA 项目内')
        parts = value.parts
        checkpoint = '.checkpoints' in parts and self.evidence and self.evidence.job_root
        if any((p.startswith('.') and not (p == '.checkpoints' and checkpoint)) or p in {'node_modules', '__pycache__'} for p in parts):
            raise ValueError('不读取隐藏配置、依赖或凭据目录')
        path = (self.root / value).resolve()
        if path != self.root and self.root not in path.parents:
            raise ValueError('路径超出项目目录')
        parts = path.relative_to(self.root).parts
        if any(part.startswith('.') and part != '.checkpoints' for part in parts):
            raise ValueError('不读取隐藏配置、依赖或凭据目录')
        selected_output = path == self.artifacts or self.artifacts in path.parents
        job = Path(self.evidence.job_root).resolve() if self.evidence and self.evidence.job_root else None
        selected_job = job and (path == job or job in path.parents)
        jobs = Path(self.evidence.jobs_root).resolve() if self.evidence and self.evidence.jobs_root else None
        if jobs and jobs in path.parents and not selected_job and not (job and path in job.parents):
            raise ValueError('只读取当前绑定任务的产物，不读取其他会话任务')
        queue = Path(self.evidence.queue_root).resolve() if self.evidence and self.evidence.queue_root else None
        if queue and (path == queue or queue in path.parents):
            raise ValueError('队列凭据不通过通用文件读取工具暴露')
        if any(part in {'demo_assistant_private', 'demo_queue_private', 'repair_agent_private'} for part in parts):
            raise ValueError('私有会话、队列凭据请通过当前任务工具读取')
        if parts[:3] == ('outputs', 'customer_demo', 'jobs') and len(parts) > 3 and not selected_job:
            raise ValueError('只读取当前绑定任务的产物，不读取其他会话任务')
        if parts[:2] == ('outputs', 'demo_assistant_artifacts') and len(parts) > 2 and not selected_output:
            raise ValueError('只读取当前助手会话的工具产物')
        if re.search(r'(?i)(secret|credential|token|private.key|\.env)(?:[._-]|$)', path.name) and path.suffix != '.py':
            raise ValueError('不读取凭据文件')
        if '.checkpoints' in parts and not selected_job:
            raise ValueError('只读取当前任务检查点')
        if file and not path.is_file():
            raise ValueError('文件不存在')
        return path

    def version(self, query='', *, search=False):
        try:
            params = json.loads(query) if str(query).startswith('{') else {'path': query or '.'}
            base = self.path(params.get('path', '.')) if not search or str(query).startswith('{') else self.root
            paths = [base]
            if base.is_dir():
                if search and base == self.root:
                    paths.extend(path for folder in CODE_ROOTS for path in islice((self.root/folder).rglob('*'), 1000))
                else:
                    paths.extend(islice(base.rglob('*') if search else base.iterdir(), 4000))
            stamps = []
            for path in paths:
                try:
                    self.path(str(path))
                    stat = path.stat()
                    stamps.append((str(path), stat.st_size, stat.st_mtime_ns))
                except (OSError, ValueError):
                    continue
            return hashlib.sha256(json.dumps(stamps, sort_keys=True).encode()).hexdigest()
        except (ValueError, OSError):
            return 'unavailable'

    def tree(self, query='', limit=60):
        params = json.loads(query) if str(query).startswith('{') else {'path': query or '.'}
        base = self.path(params.get('path', '.'))
        depth = max(1, min(5, int(params.get('depth', 2))))
        offset = max(0, int(params.get('offset', 0)))
        pattern = str(params.get('pattern') or '*')
        size = min(200, max(20, int(params.get('page_size', limit))))
        entries, skipped = [], 0
        for folder, dirs, files in os.walk(base, followlinks=False):
            relative = Path(folder).relative_to(base)
            safe = []
            for name in sorted(dirs):
                try:
                    self.path(str(Path(folder)/name))
                    if not (Path(folder)/name).is_symlink():
                        safe.append(name)
                except ValueError:
                    pass
            dirs[:] = safe
            for name in safe + sorted(files):
                path = Path(folder)/name
                try:
                    self.path(str(path))
                    if path.is_symlink() or not fnmatch.fnmatch(name, pattern):
                        continue
                    stat = path.stat()
                except (OSError, ValueError):
                    continue
                if skipped < offset:
                    skipped += 1
                    continue
                if len(entries) >= size:
                    return {'source': '当前 TARA 项目文件目录', 'entries': entries, 'truncated': True,
                            'next_offset': offset+size, 'path': str(base), 'pattern': pattern}
                rel = path.relative_to(self.root).as_posix()
                entries.append({'path': rel, 'kind': 'directory' if path.is_dir() else 'file',
                                'purpose': PURPOSES.get(rel, ''), 'bytes': stat.st_size,
                                'mtime_ns': stat.st_mtime_ns})
            dirs[:] = [] if len(relative.parts) >= depth-1 else [d for d in safe if d not in SKIP or base != self.root]
        return {'source': '当前 TARA 项目文件目录', 'entries': entries, 'truncated': False, 'next_offset': None}

    def search(self, query, limit=5):
        params = json.loads(query) if str(query).startswith('{') else {'query': query}
        text = str(params.get('query') or '').casefold()
        if not text:
            return {'source': 'TARA项目源码与说明', 'matches': [], 'notice': '请指定关键词'}
        base = self.path(params.get('path', '.'))
        offset, count = max(0, int(params.get('offset', 0))), 0
        found = []
        for folder, dirs, files in os.walk(base, followlinks=False):
            safe = []
            for name in sorted(dirs):
                try:
                    path = Path(folder)/name
                    self.path(str(path))
                    if not path.is_symlink() and (name not in SKIP or base != self.root):
                        safe.append(name)
                except ValueError:
                    pass
            dirs[:] = safe
            for name in sorted(files):
                path = Path(folder)/name
                try:
                    self.path(str(path), file=True)
                    if path.suffix not in TEXT_TYPES or path.stat().st_size > 500000:
                        continue
                    with path.open(encoding='utf-8', errors='replace') as stream:
                        for line_number, line in enumerate(stream, 1):
                            if text not in line.casefold():
                                continue
                            count += 1
                            if count <= offset:
                                continue
                            if len(found) >= limit:
                                return {'source': 'TARA项目源码与说明', 'matches': found,
                                        'truncated': True, 'next_offset': offset+limit}
                            found.append({'source': path.relative_to(self.root).as_posix(),
                                          'line': line_number, 'text': line.strip()[:500]})
                except (ValueError, OSError):
                    continue
        return {'source': 'TARA项目源码与说明', 'matches': found, 'truncated': False, 'next_offset': None}

    def read(self, query):
        params = json.loads(query) if str(query).startswith('{') else {'path': query}
        path = self.path(params.get('path'), file=True)
        if path.suffix.lower() in {'.xlsx', '.xlsm'}:
            from openpyxl import load_workbook
            book = load_workbook(path, read_only=True, data_only=True)
            try:
                sheet_name = params.get('sheet') or book.sheetnames[0]
                sheet = book[sheet_name]
                start = max(1, int(params.get('start_row', 1)))
                end = min(start+79, int(params.get('end_row', start+39)))
                rows = [[str(value)[:1000] if value is not None else '' for value in row[:40]]
                        for row in sheet.iter_rows(min_row=start, max_row=end, values_only=True)]
                return {'source': path.relative_to(self.root).as_posix(), 'sheets': book.sheetnames,
                        'sheet': sheet_name, 'start_row': start, 'end_row': end, 'rows': rows,
                        'truncated': sheet.max_row is None or sheet.max_row > end,
                        'evidence_version': self.version(str(path))}
            finally:
                book.close()
        if path.suffix.lower() == '.docx':
            from docx import Document
            document = Document(path)
            lines = [p.text for p in document.paragraphs]
            for table in document.tables:
                lines.extend(' | '.join(cell.text for cell in row.cells) for row in table.rows)
        elif path.suffix.lower() == '.pdf':
            import fitz
            with fitz.open(path) as document:
                page = max(1, min(len(document), int(params.get('page', 1))))
                return {'source': path.relative_to(self.root).as_posix(), 'page': page,
                        'pages': len(document), 'content': document[page-1].get_text()[:18000],
                        'evidence_version': self.version(str(path))}
        elif path.suffix.lower() not in TEXT_TYPES:
            return {'source': path.relative_to(self.root).as_posix(), 'bytes': path.stat().st_size,
                    'format': path.suffix, 'notice': '二进制文件返回真实元数据；不把模型权重、图片等作为文本灌入上下文'}
        else:
            # Stream pages instead of loading multi-GB training/runtime logs.
            start = max(1, int(params.get('start_line', 1)))
            end = min(start+179, int(params.get('end_line', start+119)))
            with path.open(encoding='utf-8', errors='replace') as stream:
                lines = list(islice(stream, start-1, end+1))
            content = ''.join(f'{start+i}: {line[:4000]}' for i,line in enumerate(lines[:end-start+1]))[:18000]
            result = {'source': path.relative_to(self.root).as_posix(), 'start_line': start,
                      'end_line': start+min(len(lines),end-start+1)-1, 'content': content,
                      'truncated': len(lines)>end-start+1, 'evidence_version': self.version(str(path))}
            if path.suffix != '.py' or path.stat().st_size > 2_000_000:
                return result
            lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
        start = max(1, int(params.get('start_line', 1)))
        end = min(len(lines), start + 179, int(params.get('end_line', start + 119)))
        result = {'source': path.relative_to(self.root).as_posix(), 'start_line': start,
                  'end_line': end, 'total_lines': len(lines),
                  'content': '\n'.join(f'{i + 1}: {line}' for i, line in enumerate(lines[start - 1:end], start - 1))[:18000]}
        result['evidence_version'] = self.version(str(path))
        result['truncated'] = end < len(lines)
        if path.suffix == '.py':
            try:
                tree = ast.parse(path.read_text(encoding='utf-8-sig'))
                result['purpose'] = ast.get_docstring(tree) or ''
                result['symbols'] = [{'name': node.name, 'line': node.lineno,
                                      'purpose': (ast.get_docstring(node) or '')[:180]}
                                     for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))][:40]
                result['runnable'] = any(isinstance(node, ast.If) and '__main__' in ast.unparse(node.test) for node in tree.body)
            except (SyntaxError, UnicodeError):
                result['notice'] = '源码不能作为 Python AST 解析，已返回原文'
        return result

    def execute(self, params, *, generated=False):
        if not shutil.which('bwrap'):
            raise ValueError('隔离执行器 bwrap 不可用，未在主服务进程执行代码')
        run = self.artifacts / ('python-' + uuid.uuid4().hex[:12])
        run.mkdir(parents=True, exist_ok=False)
        view = run / 'repository'
        view.mkdir()
        # A code-only view excludes credentials, other clients' outputs and training data.
        def ignore(folder, names):
            return {n for n in names if n in SKIP or n.startswith('.') or (Path(folder) / n).is_symlink()
                    or ((Path(folder) / n).is_file() and (Path(n).suffix.lower() not in TEXT_TYPES
                        or (Path(folder) / n).stat().st_size > 2_000_000))}
        for name in CODE_ROOTS:
            source = self.root / name
            if source.is_dir():
                shutil.copytree(source, view / name, ignore=ignore)
        for path in self.root.iterdir():
            if path.is_file() and not path.name.startswith('.') and path.suffix in {'.py', '.md', '.toml'}:
                shutil.copy2(path, view / path.name)
        if generated:
            code = str(params.get('code') or '')
            if not code or len(code) > 50000:
                raise ValueError('请提供1~50000字符的 Python 代码')
            ast.parse(code)
            script = run / 'task.py'
            script.write_text(code, encoding='utf-8')
            target = '/work/task.py'
        else:
            source = self.path(params.get('path'), file=True)
            if source.suffix != '.py':
                raise ValueError('目前支持执行项目 Python 工具；数据分析通过 start_analysis/rerun_assets')
            target = '/repo/' + source.relative_to(self.root).as_posix()
            selected = view/source.relative_to(self.root)
            if not selected.exists():
                selected.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, selected)
        args = params.get('args', [])
        if not isinstance(args, list) or len(args) > 40 or any(not isinstance(a, str) or len(a) > 1000 for a in args):
            raise ValueError('args 必须为最多40项的字符串数组')
        inputs = run / 'inputs'
        inputs.mkdir()
        if self.evidence:
            for i, source in enumerate([*self.evidence.dfd_paths, self.evidence.topology, self.evidence.interfaces]):
                if source.is_file():
                    shutil.copy2(source, inputs / (str(i) + '-' + source.name))
            report = getattr(self.evidence, 'report_override', None)
            if not report:
                manifest, _ = self.evidence.manifest()
                candidate = Path(str(manifest.get('outputs', {}).get('json') or '')).resolve()
                if (self.evidence.job_root and candidate.is_file()
                        and self.evidence.job_root.resolve() in candidate.parents):
                    report = candidate
            if report and Path(report).is_file():
                shutil.copy2(report, inputs / 'report.json')
        command = ['bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv']
        for name in ('/usr', '/bin', '/lib', '/lib64', str(Path(sys.prefix).parent.parent)):
            if Path(name).exists():
                command += ['--ro-bind', name, name]
        command += ['--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
                    '--ro-bind', str(view), '/repo', '--bind', str(run), '/work',
                    '--ro-bind', str(inputs), '/inputs', '--chdir', '/work',
                    '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8',
                    '--setenv', 'PYTHONPATH', '/repo', '--setenv', 'PYTHONDONTWRITEBYTECODE', '1',
                    '--setenv', 'HOME', '/tmp']
        if self.evidence and self.evidence.job_root and self.evidence.job_root.is_dir():
            command += ['--ro-bind', str(self.evidence.job_root), '/run']
        knowledge = self.root/'data/rag'
        if knowledge.is_dir():
            command += ['--ro-bind', str(knowledge), '/knowledge']
        wrapper = ('import resource,runpy,sys;'
                   'resource.setrlimit(resource.RLIMIT_CPU,(20,20));'
                   'resource.setrlimit(resource.RLIMIT_AS,(4*1024**3,4*1024**3));'
                   'resource.setrlimit(resource.RLIMIT_FSIZE,(8*1024**2,8*1024**2));'
                   'resource.setrlimit(resource.RLIMIT_NPROC,(32,32));'
                   'sys.argv=sys.argv[1:];runpy.run_path(sys.argv[0],run_name="__main__")')
        command += [sys.executable, '-u', '-c', wrapper, target, *args]
        output = run / 'execution.log'
        with output.open('w') as stream:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stream,
                                       stderr=subprocess.STDOUT, start_new_session=True, env={'PATH': '/usr/bin:/bin'})
            try:
                code = process.wait(timeout=35)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                code = -9
        text = output.read_text(encoding='utf-8', errors='replace')
        artifacts = [str(p) for p in run.iterdir() if p.is_file() and p.stat().st_size <= 8 * 1024**2]
        return {'source': '隔离 Python 执行器', 'return_code': code, 'stdout': text[-10000:],
                'artifacts': artifacts, 'error': text[-1800:] if code else '',
                'workspace': str(run), 'notice': '工程代码只读挂载；新文件保存在本次任务目录，未改写源项目'}
