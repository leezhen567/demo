"""Apply user-requested report edits and recalculate dependent ratings."""
from __future__ import annotations
import copy
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import domain
from .excel_export import export_tara_report_to_excel
from .report_editor_agent import (_iter_report_rows, _manifest_options, _validate_operations,
                                  report_row_catalog, _ATTRIBUTE_FIELDS, _ROW_FIELDS)
from .reporting import cybersecurity_fields_for_treatment


def _impact_parameters(parameters, method):
    result = dict(parameters)
    if method in {'heavens', 'heavens_4level'}:
        for key, weights in domain.HEAVENS_DIM_WEIGHTS.items():
            value = result.get(key)
            reverse = {score: level for level, score in weights.items()}
            if value in reverse:
                result[key] = reverse[value]
    return result


def _cvss_parameters(parameters):
    result = dict(parameters)
    for key, choices in {'complexity': domain.CVSS_C, 'privileges': domain.CVSS_P, 'user_interaction': domain.CVSS_U}.items():
        result[key] = next((name for name, score in choices.items() if result.get(key) == score), result.get(key))
    return result


def _recalculate(attribute, impact_method, feasibility_method, *, impact_changed=False, changed_attacks=(), threshold=4):
    params = _impact_parameters(attribute.get('influence_parameters', {}), impact_method)
    impact, label = domain.compute_impact_for_method(params, impact_method)
    attribute.update(impact_value=impact, impact_level=label)
    risks = []
    for attack in attribute.get('attack', []):
        if not impact_changed and id(attack) not in changed_attacks:
            raw = attack.get('risk_value_num') or attack.get('risk_value') or 1
            risks.append(domain.HEAVENS_RISK_NUM.get(str(raw), int(raw) if str(raw).isdigit() else 1))
            continue
        ap = attack.get('attack_parameters', {})
        if feasibility_method == 'attack_potential':
            score = domain.calculate_attack_potential_score(ap)
            level = domain.calculate_attack_potential_level(score)
        elif feasibility_method == 'heavens':
            score = domain.calculate_heavens_ap_score(ap)
            level = domain.calculate_heavens_ap_level(score)
        elif feasibility_method == 'cvss':
            score = domain.calculate_cvss_score(_cvss_parameters(ap))
            level = domain.calculate_cvss_level(score)
        elif feasibility_method == 'attack_vector':
            level = domain.ATTACK_VECTOR_TO_LEVEL.get(domain.normalize_attack_vector(attack.get('attack_vector') or ap.get('attack_vector')))
            if not level:
                raise ValueError('攻击向量缺失，无法回算可行性')
            score = attack.get('feasibility_score', 0)
        else:
            raise ValueError('报告中的可行性方法不受支持')
        if impact_method == 'heavens' and feasibility_method == 'heavens':
            risk, number = domain.calculate_heavens_risk_value(label, level)
        else:
            risk_level = domain.HEAVENS_TL_TO_FEASIBILITY.get(level, level) if feasibility_method == 'heavens' else level
            number = risk = domain.calculate_risk_value(impact, risk_level)
        treatment = '风险缓解' if number >= threshold else '风险接受'
        attack.update(feasibility_score=score, feasibility_level=level, risk_value=risk,
                      risk_value_num=number, risk_treatment=treatment)
        if treatment == '风险接受':
            attack.update(security_requirements=[], security_requirement='', national_standard_code='', annex5_partbc_mapping='')
        attack['rating_revision'] = {'source': '用户要求修改维度并由项目评分函数回算', 'time': datetime.now(timezone.utc).isoformat()}
        risks.append(number)
    if risks:
        attribute.update(task_risk_value=max(risks), task_risk_treatment='风险缓解' if max(risks) >= threshold else '风险接受')


def revise_report(source, request, destination, *, instruction=''):
    source = Path(source)
    report = json.loads(source.read_text(encoding='utf-8'))
    revised = copy.deepcopy(report)
    rows = {row['risk_id']: row for row in _iter_report_rows(revised)}
    feasibility, impact, options = _manifest_options(source)
    threshold = 4
    for parent in (source.parent, *source.parents):
        manifest_path = parent / 'run_manifest.json'
        if manifest_path.is_file():
            manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
            if manifest.get('configuration', {}).get('effective', {}).get('TARA_SECURITY_REQUIREMENTS_SCOPE') == '345':
                threshold = 3
            break
    updates = request.get('ratings', [])
    operations = _validate_operations(request.get('operations', []), report_row_catalog(revised))
    if not isinstance(updates, list) or len(updates) > 100 or not (updates or operations):
        raise ValueError('请提供 ratings 或 operations，单次最多修改100项评级')
    before_after, affected = [], {}
    seen = set()
    for item in updates:
        row = rows.get(str(item.get('risk_id', '')).upper())
        if row is None:
            raise ValueError('报告中没有该风险ID，请先 search_results 精确定位')
        attribute, attack = row['_attribute'], row['_attack']
        imethod = attribute.get('impact_method') or impact
        fmethod = attribute.get('feasibility_method') or feasibility
        for field, target in (('impact_parameters', attribute), ('feasibility_parameters', attack)):
            if field not in item:
                continue
            if target is None or not isinstance(item[field], dict) or not item[field]:
                raise ValueError('维度修改需要非空对象及已有评级/路径')
            storage = 'influence_parameters' if field == 'impact_parameters' else 'attack_parameters'
            # Reports store HEAVENS weighted contributions; convert to raw levels before merging.
            existing = target.get(storage, {})
            values = _impact_parameters(existing, imethod) if field == 'impact_parameters' else _cvss_parameters(existing) if fmethod == 'cvss' else dict(existing)
            if field == 'impact_parameters':
                choices = {key: [1, 2, 3, 4] for key in ('Safety', 'Finance', 'Operation', 'Privacy')}
            elif fmethod == 'attack_potential':
                choices = domain.AP_ALLOWED_VALUES
            elif fmethod == 'heavens':
                choices = domain.HEAVENS_AP_ALLOWED_VALUES
            elif fmethod == 'cvss':
                choices = {'attack_vector': domain.CVSS_V, 'complexity': domain.CVSS_C,
                           'privileges': domain.CVSS_P, 'user_interaction': domain.CVSS_U}
            else:
                raise ValueError('attack_vector 方法请通过 operations 修改攻击向量后重跑；没有自由数值维度')
            for key, value in item[field].items():
                if key not in choices or isinstance(value, bool) or value not in choices[key]:
                    raise ValueError(f'{key} 不是合法维度/值；合法值：{choices.get(key)}')
                identity = (id(target), key)
                if identity in seen and values.get(key) != value:
                    raise ValueError(f'同一评级维度出现冲突修改：{key}')
                seen.add(identity)
                before_after.append({'risk_id': row['risk_id'], 'field': field + '.' + key, 'before': values.get(key), 'after': value})
                values[key] = value
                values[key + '_reason'] = item.get('reason') or '用户明确调整，非模型自动评级'
            if any(key not in values for key in choices):
                raise ValueError('原报告缺少完整评级维度，不能猜测未提供的分值；请补齐维度或重新分析该资产')
            if field == 'impact_parameters' and imethod in {'heavens', 'heavens_4level'}:
                values = domain.calculate_heavens_dimension_values(values)
            target[storage] = values
            record = affected.setdefault(id(attribute), [attribute, imethod, fmethod, False, set()])
            if field == 'impact_parameters':
                record[3] = True
            else:
                record[4].add(id(attack))
    for attribute, imethod, fmethod, changed, attacks in affected.values():
        _recalculate(attribute, imethod, fmethod, impact_changed=changed, changed_attacks=attacks, threshold=threshold)
    rematch = []
    for row in _iter_report_rows(revised):
        record = affected.get(id(row['_attribute']))
        attack = row['_attack']
        if not record or attack is None or (not record[3] and id(attack) not in record[4]):
            continue
        attack.update(cybersecurity_fields_for_treatment(risk_treatment=attack['risk_treatment'], asset_name=row['asset'],
            attribute_name=row['security_attribute'], threat_type=row['_attribute'].get('threat_type', ''), function_name=row['function']))
        if attack['risk_treatment'] == '风险缓解' and not attack.get('security_requirement'):
            rematch.append(row['risk_id'])
    # Text changes share the existing field whitelist and authoritative requirement triple validator.
    for op in operations:
        row = rows[op['risk_id']]
        target = row['_attribute'] if op['field'] in _ATTRIBUTE_FIELDS else row['_attack'] or row['_attribute']
        key = _ATTRIBUTE_FIELDS.get(op['field']) or _ROW_FIELDS[op['field']]
        before_after.append({'risk_id': op['risk_id'], 'field': key, 'before': target.get(key), 'after': op['value']})
        target[key] = op['value']
        if op['field'] == 'risk_treatment':
            target.update(cybersecurity_fields_for_treatment(risk_treatment=op['value'], asset_name=row['asset'],
                attribute_name=row['security_attribute'], threat_type=row['_attribute'].get('threat_type', ''), function_name=row['function']))
            if op['value'] == '风险接受':
                target.update(security_requirements=[], security_requirement='', national_standard_code='', annex5_partbc_mapping='')
    destination = Path(destination) / ('revision-' + uuid.uuid4().hex[:12])
    destination.mkdir(parents=True, exist_ok=False)
    json_path, xlsx_path = destination / 'report.json', destination / 'report.xlsx'
    json_path.write_text(json.dumps(revised, ensure_ascii=False, indent=2), encoding='utf-8')
    export_tara_report_to_excel(str(json_path), str(xlsx_path), options=options)
    manifest = {'source_report': str(source), 'instruction': instruction, 'changes': before_after,
                'time': datetime.now(timezone.utc).isoformat(), 'outputs': {'json': str(json_path), 'xlsx': str(xlsx_path)},
                'impact_method': impact, 'feasibility_method': feasibility}
    (destination / 'revision_manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
    return {'source': '项目报告修订与评分函数', 'changes': before_after, 'report': str(json_path),
            'excel': str(xlsx_path), 'artifacts': [str(json_path), str(xlsx_path)],
            'security_requirements_need_rematch': rematch,
            'notice': '已生成修订版并回算受影响路径；原始报告保留'}
