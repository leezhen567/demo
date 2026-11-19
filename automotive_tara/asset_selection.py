"""Exact engineering identities for interactive analysis scope and reruns."""
from __future__ import annotations

FIELDS = ('function', 'element_index', 'asset_name', 'asset_type')


def validate_selection(selection):
    if not isinstance(selection, dict) or set(selection) - {'include', 'exclude'}:
        raise ValueError('分析范围需要 include/exclude 对象')
    result = {}
    for group in ('include', 'exclude'):
        values = selection.get(group, [])
        if not isinstance(values, list) or len(values) > 500:
            raise ValueError('每组最多选择500个资产')
        result[group] = []
        for item in values:
            if not isinstance(item, dict) or set(item) - set(FIELDS):
                raise ValueError('资产选择仅支持 function、element_index、asset_name、asset_type')
            item = {key: str(value).strip() for key, value in item.items() if value is not None and str(value).strip()}
            if not (item.get('asset_name') or item.get('element_index')):
                raise ValueError('资产选择必须指定 asset_name 或 element_index，不能使用模糊匹配')
            result[group].append(item)
    return result


def matches(asset, selector):
    return all(str(asset.get(key, '')).strip() == value for key, value in selector.items())


def filter_tasks(tasks, selection):
    selection = validate_selection(selection)
    identities = [dict(zip(FIELDS, (task.function, task.element_index, task.asset_name, task.asset_type))) for task in tasks]
    # Resolve names before running: duplicated display names need a function/id.
    for selector in selection['include'] + selection['exclude']:
        selected = {tuple(row.get(key, '') for key in FIELDS) for row in identities if matches(row, selector)}
        if len(selected) != 1:
            raise ValueError(f'资产选择未唯一定位（匹配{len(selected)}项）：{selector}；请补充功能或元素编号')
    kept = [task for task, identity in zip(tasks, identities)
            if (not selection['include'] or any(matches(identity, s) for s in selection['include']))
            and not any(matches(identity, s) for s in selection['exclude'])]
    if not kept:
        raise ValueError('当前分析范围没有可分析的资产')
    return kept
