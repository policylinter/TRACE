"""Evidence-bound report contracts for TRACE model completions."""
from __future__ import annotations
from typing import Any
import json
from datetime import datetime, timezone

REPORT_SCHEMA = {
    "observations": [{"statement": "Observation grounded in the supplied artifacts", "evidenceRefs": ["advisory", "frame-1"]}],
    "exploitationConditions": ["Required condition; explicitly state if unverified"],
    "assumptions": ["Unverified hypothesis; never present as a fact"],
    "missingEvidence": ["Specific missing artifact or deployment fact"],
    "impact": "Potential impact and limits of what is proven",
    "verificationSteps": ["Safe verification or regression check with expected result"],
    "remediationPlan": [{"action": "Concrete change", "rationale": "Why it helps", "verification": "How to check the change"}],
}

def context_for(candidate, reached, dependency_path, profile, cfg, extra=None):
    frames = [{"evidenceId": f"frame-{i+1}", **{k: str(f.get(k) or '')[:600] for k in ('symbol','location','kind','note','edge')}, "line": f.get('line'), "vulnerable": bool(f.get('vulnerable'))} for i,f in enumerate(reached.frames[:24])]
    context = {
        "advisory": {"evidenceId":"advisory", "id":candidate.cve, "package":candidate.package, "version":candidate.version, "ecosystem":candidate.ecosystem, "severity":candidate.severity, "cvss":candidate.cvss, "scannerNames":sorted(candidate.scanners)},
        "reachability": {"status":reached.reachability, "source":str(reached.taint_source or "")[:1000], "sink":str(reached.sink or "")[:600], "rule":reached.rule, "propagation":[str(item)[:250] for item in reached.propagation[:20]]},
        "frames":frames,
        "usage":{"evidenceId":"usage", "kind":reached.usage, "hits":[str(h)[:160] for h in reached.usage_hits[:20]], "note":str(reached.usage_note or "")[:1000]},
        "barrier":{"evidenceId":"barrier", "description":str(reached.blocker)[:2000]} if reached.blocker else None,
        "dependencyPath":[str(item)[:250] for item in dependency_path[:20]],
        "deploymentProfile":{"label":profile, "runtimeVerified":False},
        "operatorContext":{"text":cfg.get('analyst_context',''), "verified":False},
        "additionalMetadata":extra or {},
        "analysisDepth":cfg.get('analysis_depth','deep'),
        "responseLanguage":cfg.get('response_language','ru'),
        "limitations":["No live runtime observation", "No repository checkout is attached to this request", "Only the supplied artifact fields are evidence"],
    }
    context['framesTotal'] = len(reached.frames)
    while len(context['frames']) > 1 and len(json.dumps(context, ensure_ascii=False)) > 20000:
        context['frames'].pop()
    context['framesIncluded'] = len(context['frames'])
    if context['framesIncluded'] < context['framesTotal']:
        context['limitations'].append('Call-path evidence was truncated to fit the analysis context budget')
    return context


def text_list(value: Any, limit=12) -> list[str]:
    if not isinstance(value,list): return []
    return [v.strip()[:1800] for v in value[:limit] if isinstance(v,str) and v.strip()]

def normalize_report(value, context, reached, source):
    data=value if isinstance(value,dict) else {}
    allowed={'advisory','usage'}|{f['evidenceId'] for f in context['frames']}
    if context.get('barrier'): allowed.add('barrier')
    observations=[]; invalid_refs=False
    for item in (data.get('observations') or [])[:15] if isinstance(data.get('observations'),list) else []:
        if not isinstance(item,dict) or not isinstance(item.get('statement'),str):continue
        refs=text_list(item.get('evidenceRefs'),8)
        valid=[ref for ref in refs if ref in allowed]
        if len(valid)!=len(refs) or not valid:
            invalid_refs=True
            continue
        observations.append({'statement':item['statement'][:2000], 'evidenceRefs':valid})
    missing=text_list(data.get('missingEvidence'))
    if context.get('framesIncluded',0)<context.get('framesTotal',0):missing.append('В запрос включена только часть шагов пути; проверьте полный отчёт.')
    if not reached.frames:missing.insert(0,'Не представлен путь от входных данных к уязвимой операции.')
    if not context.get('additionalMetadata',{}).get('fixedVersion'):missing.append('В предоставленных метаданных не указана исправленная версия пакета.')
    if invalid_refs:missing.append('Часть наблюдений модели исключена: ссылки на доказательства отсутствуют или не распознаны.')
    if not observations:
        observations=[{'statement':f"В отчёте указан пакет {context['advisory']['package']}@{context['advisory']['version']} и идентификатор {context['advisory']['id']}.", 'evidenceRefs':['advisory']}]
    if source == 'rules' and context['frames']:
        first,last=context['frames'][0],context['frames'][-1]
        observations.append({'statement':f"В отчёте указан начальный шаг: {first['symbol']} · {first['location']}.", 'evidenceRefs':[first['evidenceId']]})
        if last['evidenceId']!=first['evidenceId']:
            observations.append({'statement':f"Последний представленный шаг: {last['symbol']} · {last['location']}.", 'evidenceRefs':[last['evidenceId']]})
        missing.append('Не проверены фактическая доступность входной точки и условия развёртывания.')
    plan=[]
    for item in data.get('remediationPlan',[]) if isinstance(data.get('remediationPlan'),list) else []:
        if isinstance(item,dict) and isinstance(item.get('action'),str):
            plan.append({k:str(item.get(k) or '')[:2000] for k in ('action','rationale','verification')})
    if not plan and context.get('additionalMetadata',{}).get('fixedVersion'):
        plan=[{'action':f"Проверьте обновление {context['advisory']['package']} до версии {context['additionalMetadata']['fixedVersion']} из метаданных отчёта.", 'rationale':'Указанная версия должна устранять проблему; применимость и совместимость требуют проверки.', 'verification':'Повторите сканирование и регрессионные тесты затронутых вызовов.'}]
    return {
        'schemaVersion':1, 'source':source, 'generatedAt':datetime.now(timezone.utc).isoformat(),
        'observations':observations,
        'exploitationConditions':text_list(data.get('exploitationConditions')) or ['Проверьте доступность входной точки и возможность передать контролируемые атакующим данные в уязвимую операцию.'],
        'assumptions':text_list(data.get('assumptions')),
        'missingEvidence':list(dict.fromkeys(missing))[:15],
        'impact':str(data.get('impact') or 'Влияние на развёртывание не подтверждено. Требуется проверить условия уязвимости и контекст использования.')[:4000],
        'verificationSteps':text_list(data.get('verificationSteps')) or ['Проверьте точку вызова и ограничения входных данных.', 'После исправления повторите проверку и регрессионные тесты.'],
        'remediationPlan':plan[:10],
        'evidenceIndex':[{'id':f['evidenceId'],'label':f"{f['symbol']} · {f['location']}:{f['line'] or '—'}"} for f in context['frames']]+[{'id':'advisory','label':context['advisory']['id']},{'id':'usage','label':'Использование зависимости'}]+([{'id':'barrier','label':'Описание барьера'}] if context.get('barrier') else []),
    }
