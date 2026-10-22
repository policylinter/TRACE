"""Convert a local Semgrep Code JSON report to individual TRACE intake files. No scan or upload."""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from trace_api.module_intake import IntakeInput
from trace_api.result_contracts import digest

MAX_BYTES = 1048576
MAX_RESULTS = 100


def convert(raw, *, source_id, asset_id, run_id, commit, observed_at):
    if len(raw) > MAX_BYTES:
        raise ValueError('report too large')
    def invalid_constant(_): raise ValueError('invalid JSON constant')
    report = json.loads(raw, parse_constant=invalid_constant)
    if (not isinstance(report, dict) or not isinstance(report.get('results'), list)
            or not isinstance(report.get('errors'), list) or not isinstance(report.get('version'), str)
            or not report['version'].strip() or len(report['version']) > 128):
        raise ValueError('unsupported report shape')
    if len(report['results']) > MAX_RESULTS:
        raise ValueError('too many results; no truncation is performed')
    observed = datetime.fromisoformat(observed_at.replace('Z', '+00:00'))
    if observed.utcoffset() is None:
        raise ValueError('observation time requires timezone')
    paths = report.get('paths')
    skipped_rules = report.get('skipped_rules')
    if paths is not None and (not isinstance(paths, dict) or
            any(key in paths and not isinstance(paths[key], list) for key in ('scanned', 'skipped'))):
        raise ValueError('invalid path summary')
    if skipped_rules is not None and not isinstance(skipped_rules, list):
        raise ValueError('invalid skipped rules')
    state = 'unknown'
    if report['errors'] or (paths or {}).get('skipped') or skipped_rules:
        state = 'partial'
    elif isinstance(paths, dict) and 'scanned' in paths and 'skipped' in paths and skipped_rules is not None:
        state = 'no_reported_errors'
    report_sha = hashlib.sha256(raw).hexdigest()
    severity_map = dict(CRITICAL='critical', HIGH='high', MEDIUM='medium', LOW='low', INFO='info')
    accepted_severities = set(severity_map) | {'ERROR', 'WARNING', 'UNKNOWN'}
    origin = dict(adapter='semgrep-json/1', runId=run_id, commit=commit,
                  reportSha256=report_sha, reportState=state, reportedSeverity='UNKNOWN')
    # Validate operator context even when the report has no findings.
    base = dict(schemaVersion='trace.intake/1', objectType='finding', sourceId=source_id, assetId=asset_id,
                externalId='context-validation-only', ruleId='context-validation-only', title='context validation',
                severity='unknown', observedAt=observed.isoformat(),
                analysis=dict(kind='sast', scanner='semgrep', location=dict(path='context-validation-only', startLine=1, endLine=1), origin=origin),
                evidence=[dict(label='Original Semgrep report (not uploaded)', reference='semgrep-report:sha256:'+report_sha, sha256=report_sha)])
    IntakeInput.model_validate(base)
    documents, seen, ignored = [], set(), 0
    for index, result in enumerate(report['results']):
        if not isinstance(result, dict) or not isinstance(result.get('extra'), dict):
            raise ValueError('invalid result')
        extra = result['extra']
        if type(extra.get('is_ignored', False)) is not bool:
            raise ValueError('invalid ignore flag')
        fingerprint = hashlib.sha256(json.dumps(result, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
        if fingerprint in seen:
            raise ValueError('duplicate report result')
        seen.add(fingerprint)
        severity = extra.get('severity', 'UNKNOWN')
        if not isinstance(severity, str) or severity not in accepted_severities:
            raise ValueError('unsupported severity')
        if not isinstance(result.get('start'), dict) or not isinstance(result.get('end'), dict):
            raise ValueError('missing location')
        location = dict(path=result.get('path'), startLine=result['start'].get('line'), endLine=result['end'].get('line'))
        identity = hashlib.sha256(json.dumps([run_id, report_sha, index], separators=(',', ':')).encode()).hexdigest()
        body = {**base, 'externalId':'semgrep:'+identity, 'ruleId':result.get('check_id'), 'title':result.get('check_id'),
                'description':'Normalized Semgrep Code observation. No scanner execution or code-version verification is attested. Report state: '+state+'.',
                'severity':severity_map.get(severity, 'unknown'),
                'analysis':dict(kind='sast', scanner='semgrep', location=location, origin={**origin, 'reportedSeverity':severity})}
        document = IntakeInput.model_validate(body)
        if document.analysis.location.endLine < document.analysis.location.startLine:
            raise ValueError('invalid line range')
        if extra.get('is_ignored'):
            ignored += 1
        else:
            documents.append(document.model_dump(mode='json', exclude_none=True))
    manifest = dict(schemaVersion='trace.semgrep-conversion/1', adapter='semgrep-json/1', runId=run_id,
                    commit=commit, commitVerification='operator_declared', observedAt=base['observedAt'],
                    sourceId=source_id, assetId=asset_id, reportSha256=report_sha,
                    reportState=state, inputResults=len(report['results']), outputResults=len(documents),
                    ignoredResults=ignored, reportedErrorCount=len(report['errors']),
                    skippedFileCount=len(paths['skipped']) if isinstance(paths, dict) and 'skipped' in paths else None,
                    skippedRuleCount=len(skipped_rules) if skipped_rules is not None else None,
                    coverageVerified=False, documentSha256=[digest(document) for document in documents], files=[f'finding-{i+1:03d}.json' for i in range(len(documents))])
    return manifest, documents


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--source-id', required=True)
    parser.add_argument('--asset-id', required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--commit', required=True, help='Full operator-declared 40/64-character lowercase hexadecimal commit')
    parser.add_argument('--observed-at', required=True, help='Report observation time with timezone; not inferred from file mtime')
    parser.add_argument('--output-dir', type=Path, required=True, help='New directory; never overwrite a conversion')
    args = parser.parse_args()
    try:
        if args.output_dir.exists():
            raise ValueError('output exists')
        with args.report.open('rb') as source:
            raw = source.read(MAX_BYTES+1)
        manifest, documents = convert(raw, source_id=args.source_id, asset_id=args.asset_id,
            run_id=args.run_id, commit=args.commit, observed_at=args.observed_at)
        args.output_dir.mkdir()  # All parsing/validation finishes before creating output.
        for filename, document in zip(manifest['files'], documents):
            with (args.output_dir/filename).open('x', encoding='utf-8') as output:
                output.write(json.dumps(document, ensure_ascii=False, indent=2)+'\n')
        # A manifest is written last; absence means an interrupted/incomplete export.
        with (args.output_dir/'manifest.json').open('x', encoding='utf-8') as output:
            output.write(json.dumps(manifest, ensure_ascii=False, indent=2)+'\n')
    except (OSError, ValueError, TypeError, RecursionError, OverflowError):
        parser.error('Conversion failed. Check the bounded Semgrep Code report, IDs, full commit, timestamp and new output directory. No report contents are logged; an interrupted directory without manifest must not be imported.')
    print('Converted findings: '+str(manifest['outputResults'])+'; report state: '+manifest['reportState']+'; coverage is not verified.')
    return 0 if manifest['reportState']=='no_reported_errors' else 2


if __name__ == '__main__':
    raise SystemExit(main())
