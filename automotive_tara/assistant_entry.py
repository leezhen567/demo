"""Live project entry guide: business routes, registered tools and verified code."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
from functools import lru_cache
from pathlib import Path

RESOURCE_PATH = Path('subprojects/web_demo/assistant_entry')
DIRECTORIES = {
    'automotive_tara': 'TARA 主流程、阶段任务、领域评分、模型网关与网页服务',
    'scripts': '模型/LoRA 部署、数据整理和实验运行脚本',
    'tools': '数据转换与独立加工工具',
    'data/input': '可选择的工程输入样例',
    'data/rag': '安全需求模板、匹配逻辑和技术知识资料',
    'subprojects/web_demo': '网页启动器、Agent 技能、工程修复和浏览器检查',
    'tests': '行为与回归测试',
    'experiments': '实验协议和评测记录',
    'deliverables': '交付材料',
    'docs': '项目说明与交接文档',
}
ENTRY_CHAIN = [('tara.py', ''), ('automotive_tara/cli.py', 'main'), ('automotive_tara/pipeline.py', 'run_tara')]


def _stamp(path):
    try:
        stat = path.stat()
        return str(path.resolve()), stat.st_size, stat.st_mtime_ns
    except OSError:
        return str(path), -1, -1


@lru_cache(maxsize=128)
def _text(path, size, mtime):
    return Path(path).read_text(encoding='utf-8-sig') if size >= 0 else ''


def _read(path):
    return _text(*_stamp(path))


@lru_cache(maxsize=96)
def _python_index(path, size, mtime):
    content = _text(path, size, mtime)
    digest = hashlib.sha256(content.encode()).hexdigest()[:16]
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return {'digest': digest, 'error': 'Python 语法不能解析', 'symbols': {}, 'purpose': ''}
    symbols = {}
    def visit(body, prefix=''):
        for node in body:
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                name = prefix + node.name
                signature = node.name
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    signature += '(' + ast.unparse(node.args) + ')'
                symbols[name] = {'symbol': name, 'line': node.lineno,
                    'kind': 'class' if isinstance(node, ast.ClassDef) else 'function',
                    'signature': signature[:300], 'purpose': (ast.get_docstring(node) or '').split('\n\n')[0][:220]}
                if isinstance(node, ast.ClassDef):
                    visit(node.body, name + '.')
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        symbols[prefix + target.id] = {'symbol': prefix + target.id, 'line': node.lineno, 'kind': 'constant'}
    visit(tree.body)
    return {'digest': digest, 'purpose': (ast.get_docstring(tree) or '').split('\n\n')[0][:240],
            'symbols': symbols, 'error': ''}


def _keyword_match(keyword, query):
    keyword, query = keyword.casefold(), query.casefold()
    if re.fullmatch(r'[a-z]{1,3}', keyword):
        return bool(re.search(r'(?<![a-z0-9_])' + re.escape(keyword) + r'(?![a-z0-9_])', query))
    return keyword in query


class AgentEntry:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.resources = self.root / RESOURCE_PATH

    def reference(self, path, symbol=''):
        candidate = (self.root / path).resolve()
        exists = self.root in candidate.parents and candidate.exists()
        result = {'path': path, 'exists': exists}
        if not exists:
            return {**result, 'symbol': symbol, 'error': '引用文件不存在'}
        if candidate.is_dir():
            return {**result, 'kind': 'directory'}
        if candidate.suffix == '.py':
            index = _python_index(*_stamp(candidate))
            result.update(digest=index['digest'], purpose=index['purpose'])
            if index['error']:
                return {**result, 'exists': False, 'error': index['error']}
            if symbol:
                found = index['symbols'].get(symbol)
                return {**result, **found} if found else {**result, 'symbol': symbol, 'exists': False, 'error': '源码未定义该符号'}
            result.update(kind='module', symbols=[v for k, v in index['symbols'].items()
                          if '.' not in k and v['kind'] in {'function', 'class'}][:20])
        else:
            result.update(kind='document', digest=hashlib.sha256(_read(candidate).encode()).hexdigest()[:16])
        return result

    def binding(self, source):
        if '/' in source:
            return self.reference(source)
        pieces = source.split('.')
        for length in range(len(pieces), 0, -1):
            path = '/'.join(pieces[:length]) + '.py'
            if (self.root / path).is_file():
                return self.reference(path, '.'.join(pieces[length:]))
        return {'path': source, 'exists': False, 'error': '工具来源不能映射到当前源码'}

    def _routes(self):
        raw = _read(self.resources / 'routes.json')
        if not raw:
            return [], ['缺少 Agent routes.json，未加载任务路由']
        try:
            body = json.loads(raw)
            routes = body['routes']
            if not isinstance(routes, list) or any(not isinstance(r, dict) for r in routes):
                raise ValueError('routes不是对象数组')
            return routes, []
        except (ValueError, KeyError, TypeError) as exc:
            return [], ['Agent 路由格式错误：' + str(exc)]

    def manifest(self, catalog):
        routes, warnings = self._routes()
        guide = _read(self.resources / 'AGENT_GUIDE.md')
        if not guide:
            warnings.append('缺少 AGENT_GUIDE.md，未加载专用业务说明')
        tools = [{**item, 'binding': self.binding(item['source'])} for item in catalog]
        names = {item['name'] for item in tools}
        resolved = []
        for route in routes:
            code = [self.reference(ref['path'], symbol) for ref in route.get('code', [])
                    for symbol in (ref.get('symbols') or [''])]
            missing = [name for name in route.get('tools', []) if name not in names]
            resolved.append({**route, 'code': code, 'available': not missing and all(r['exists'] for r in code),
                             'missing_tools': missing})
        directories = [{'path': path, 'purpose': purpose} for path, purpose in DIRECTORIES.items()
                       if (self.root / path).is_dir()]
        material = {'guide': guide, 'routes': resolved, 'tools': tools, 'directories': directories}
        version = hashlib.sha256(json.dumps(material, ensure_ascii=False, sort_keys=True).encode()).hexdigest()[:20]
        return {'schema_version': 'tara-agent-entry-v1', 'version': version,
                'source': (RESOURCE_PATH / 'AGENT_GUIDE.md').as_posix(), 'guide': guide,
                'entry_chain': [self.reference(path, symbol) for path, symbol in ENTRY_CHAIN],
                'directories': directories, 'routes': resolved, 'tools': tools, 'warnings': warnings}

    @staticmethod
    def select(routes, question, limit=2):
        scored = []
        for route in routes:
            score = 100 if question.strip().casefold() == route['id'].casefold() else 0
            score += sum(3 for word in route.get('keywords', []) if _keyword_match(word, question))
            score += sum(2 for pattern in route.get('patterns', []) if re.search(pattern, question, re.I))
            if score:
                scored.append((score, route))
        scored.sort(key=lambda item: -item[0])
        return [route for _, route in scored[:limit]] or [r for r in routes if r['id'] == 'project_overview'][:1]

    def bootstrap(self, catalog, question):
        manifest = self.manifest(catalog)
        selected = self.select(manifest['routes'], question)
        return {'source': manifest['source'], 'version': manifest['version'], 'level': 'focused',
                'guide': manifest['guide'],
                'entry_chain': [{key: ref[key] for key in ('path', 'symbol', 'exists') if key in ref}
                                for ref in manifest['entry_chain']],
                'directories': manifest['directories'],
                'route_index': [{'id': r['id'], 'title': r['title'], 'available': r['available']} for r in manifest['routes']],
                'focus': [{key: route[key] for key in ('id', 'title', 'available', 'steps', 'tools', 'done_when')}
                          for route in selected],
                'references': [{key: ref[key] for key in ('path', 'symbol', 'line', 'exists') if key in ref}
                               for route in selected for ref in route['code']],
                'warnings': manifest['warnings'],
                'next_lookup': 'read_agent_entry(query=任务ID/工具名/模块路径/README#章节名)读取详细参数示例与源码引用'}

    def retrieve(self, catalog, query='', limit=5):
        manifest = self.manifest(catalog)
        query = str(query).strip()
        result = {'source': 'TARA Agent 专用入口与当前代码注册表', 'version': manifest['version'], 'warnings': manifest['warnings']}
        if query.casefold().startswith('readme'):
            path = self.root / 'README.md'
            lines = _read(path).splitlines()
            headings, fence = [], False
            for i, line in enumerate(lines):
                if re.match(r'^\s*(```|~~~)', line):
                    fence = not fence
                match = re.match(r'^(#{1,3})\s+(.+)$', line) if not fence else None
                if match:
                    headings.append({'title': match.group(2).strip(), 'line': i + 1, 'level': len(match.group(1))})
            section = query.split('#', 1)[1].strip() if '#' in query else ''
            if section:
                heading = next((h for h in headings if section.casefold() in h['title'].casefold()), None)
                if heading is None:
                    return {**result, 'headings': headings, 'notice': '未匹配到该章节，请使用实际标题'}
                start = heading['line']
                end = next((h['line'] - 1 for h in headings if h['line'] > start and h['level'] <= heading['level']), len(lines))
                return {**result, 'path': 'README.md', 'start_line': start, 'end_line': min(end, start + 119),
                        'content': '\n'.join(lines[start - 1:min(end, start + 119)])[:14000], 'truncated': end > start + 119}
            return {**result, 'path': 'README.md', 'headings': headings, 'notice': '按README#章节名读取，不全文注入上下文'}
        if not query:
            return {**result, 'entry_chain': manifest['entry_chain'], 'directories': manifest['directories'],
                    'routes': [{key: r[key] for key in ('id', 'title', 'tools', 'available')} for r in manifest['routes']],
                    'tools': [{'name': t['name'], 'title': t['title']} for t in manifest['tools']]}
        route_matches = [r for r in manifest['routes'] if query.casefold() == r['id'].casefold()
                         or query.casefold() in (r['title'] + json.dumps(r.get('code', []), ensure_ascii=False)).casefold()]
        tool_matches = [t for t in manifest['tools'] if query.casefold() in json.dumps(t, ensure_ascii=False).casefold()]
        if not route_matches and not tool_matches:
            route_matches = self.select(manifest['routes'], query, limit)
        return {**result, 'routes': route_matches[:limit], 'tools': tool_matches[:limit],
                'truncated': len(route_matches) > limit or len(tool_matches) > limit}

    def validate(self, catalog):
        manifest = self.manifest(catalog)
        errors = list(manifest['warnings'])
        names = {tool['name'] for tool in manifest['tools']}
        seen = set()
        for route in manifest['routes']:
            if route['id'] in seen:
                errors.append('重复路由：' + route['id'])
            seen.add(route['id'])
            if not route['available']:
                errors.append('不可用路由：' + route['id'])
            if not route.get('done_when'):
                errors.append('路由缺少完成条件：' + route['id'])
            for example in route.get('examples', []):
                if example['tool'] not in names:
                    errors.append('示例引用未注册工具：' + example['tool'])
                arguments = example.get('arguments', {})
                query = arguments.get('query')
                if not isinstance(query, str) or not 1 <= arguments.get('limit', 0) <= 8:
                    errors.append('示例参数格式错误：' + route['id'])
                elif query.startswith('{'):
                    try:
                        parsed = json.loads(query)
                        if example['tool'] == 'run_python':
                            ast.parse(parsed['code'])
                    except (ValueError, KeyError, SyntaxError):
                        errors.append('示例JSON/代码不能解析：' + route['id'])
        errors.extend('工具来源未验证：' + t['name'] for t in manifest['tools'] if not t['binding']['exists'])
        return {'valid': not errors, 'errors': errors, 'version': manifest['version'],
                'routes': len(manifest['routes']), 'tools': len(manifest['tools'])}


def compact_entry(entry):
    return {'source': entry.get('source'), 'version': entry.get('version'), 'level': 'compact',
            'entry_chain': entry.get('entry_chain', []),
            'focus': [{key: route[key] for key in ('id', 'title', 'tools', 'done_when')} for route in entry.get('focus', [])],
            'next_lookup': '需要参数或源码时用read_agent_entry读取对应任务；用户任务和当前证据必须保留'}


def main():
    parser = argparse.ArgumentParser(description='生成并校验网页 Agent 专用入口清单')
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    from .assistant_runtime import tool_catalog
    catalog = tool_catalog()
    entry = AgentEntry(args.root)
    validation = entry.validate(catalog)
    if args.output:
        manifest = entry.manifest(catalog)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
        text = ['# TARA Agent 功能与工具清单', '', '从当前资源、注册表与源码生成；版本：' + manifest['version'], '', manifest['guide'], '', '## 任务路由', '']
        for route in manifest['routes']:
            text.extend(['### ' + route['title'] + ' · ' + route['id'], '', ' → '.join(route['tools']), '',
                         '完成条件：' + '；'.join(route['done_when']), '',
                         '代码：' + '、'.join(ref['path'] + (':' + str(ref['line']) if ref.get('line') else '') for ref in route['code']), ''])
        text.extend(['## 当前工具', '', '| 工具 | 用途 | 源码 |', '|---|---|---|'])
        for tool in manifest['tools']:
            binding = tool['binding']
            text.append('| ' + tool['name'] + ' | ' + tool['description'].replace('|', '/') + ' | '
                        + binding['path'] + (':' + str(binding['line']) if binding.get('line') else '') + ' |')
        args.output.with_suffix('.md').write_text('\n'.join(text) + '\n', encoding='utf-8')
    print(json.dumps(validation, ensure_ascii=False))
    if args.check and not validation['valid']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
