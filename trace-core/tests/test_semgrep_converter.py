import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from pydantic import ValidationError
import test_access as fixtures

SCRIPT=Path(__file__).resolve().parents[1]/'tools/convert_semgrep_report.py'
spec=importlib.util.spec_from_file_location('semgrep_converter',SCRIPT)
converter=importlib.util.module_from_spec(spec);spec.loader.exec_module(converter)

def report():
    return dict(version='fixture-only',errors=[],paths=dict(scanned=['src/api.py'],skipped=[]),skipped_rules=[],results=[dict(
        check_id='qa.python.rule',path='src/api.py',start=dict(line=4,col=1),end=dict(line=6,col=8),
        extra=dict(severity='ERROR',message='DO_NOT_EXPORT_SECRET',lines='DO_NOT_EXPORT_CODE',metavars={'secret':'DO_NOT_EXPORT_SECRET'}))])

def convert(value=None,**kwargs):
    options=dict(source_id='source',asset_id='asset',run_id='qa-run',commit='a'*40,observed_at='2026-10-19T12:00:00Z')
    options.update(kwargs)
    return converter.convert(json.dumps(report() if value is None else value).encode(),**options)

class SemgrepConverterTests(unittest.TestCase):
    def test_mapping_redaction_severity_and_determinism(self):
        manifest,documents=convert();again=convert()
        self.assertEqual((manifest,documents),again)
        self.assertEqual(documents[0]['analysis']['location'],dict(path='src/api.py',startLine=4,endLine=6))
        self.assertEqual(documents[0]['severity'],'unknown')
        self.assertEqual(documents[0]['analysis']['origin']['reportedSeverity'],'ERROR')
        self.assertFalse(manifest['coverageVerified'])
        self.assertNotIn('DO_NOT_EXPORT',json.dumps([manifest,documents]))
        other=report();other['results'][0]['extra']['severity']='HIGH'
        self.assertEqual(convert(other)[1][0]['severity'],'high')

    def test_partial_unknown_empty_and_ignored_are_explicit(self):
        value=report();value['errors']=[{'message':'DO_NOT_EXPORT_SECRET'}]
        manifest,documents=convert(value);self.assertEqual(manifest['reportState'],'partial')
        self.assertEqual(documents[0]['analysis']['origin']['reportState'],'partial')
        value=report();del value['paths']
        self.assertEqual(convert(value)[0]['reportState'],'unknown')
        value=report();value['results'][0]['extra']['is_ignored']=True
        manifest,documents=convert(value);self.assertEqual(documents,[]);self.assertEqual(manifest['ignoredResults'],1)
        value=report();value['results']=[]
        self.assertEqual(convert(value)[1],[])
        value=report();value['paths']['skipped']=[{'path':'private','reason':'DO_NOT_EXPORT_SECRET'}]
        self.assertEqual(convert(value)[0]['reportState'],'partial')

    def test_invalid_rows_duplicates_and_context_fail_closed(self):
        for field,bad in [('path','../secret'),('start',{'line':True}),('end',{'line':1}),('check_id','')]:
            value=report();value['results'][0][field]=bad
            with self.subTest(field=field),self.assertRaises((ValueError,ValidationError)):convert(value)
        value=report();value['results']*=2
        with self.assertRaises(ValueError):convert(value)
        value=report();value['results']*=101
        with self.assertRaises(ValueError):convert(value)
        for commit in ('main','a'*7,'A'*40,'a'*41):
            with self.assertRaises((ValueError,ValidationError)):convert(commit=commit)
        with self.assertRaises(ValueError):convert(observed_at='2026-10-19T12:00:00')

    def test_cli_exclusive_output_and_errors_are_not_logged(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);source=root/'report.json';source.write_text(json.dumps(report()))
            output=root/'converted'
            args=[sys.executable,str(SCRIPT),'--report',str(source),'--source-id','source','--asset-id','asset','--run-id','qa',
                  '--commit','a'*40,'--observed-at','2026-10-19T12:00:00Z','--output-dir',str(output)]
            result=subprocess.run(args,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(len(list(output.glob('finding-*.json'))),1)
            self.assertTrue((output/'manifest.json').exists())
            original=(output/'finding-001.json').read_bytes()
            self.assertNotEqual(subprocess.run(args,capture_output=True).returncode,0)
            self.assertEqual((output/'finding-001.json').read_bytes(),original)
            source.write_text('DO_NOT_EXPORT_SECRET')
            args[-1]=str(root/'invalid')
            result=subprocess.run(args,capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0);self.assertFalse((root/'invalid').exists())
            self.assertNotIn('DO_NOT_EXPORT',result.stdout+result.stderr)

    def test_input_shape_and_byte_limits(self):
        for value in ({},[],{'results':[],'version':'x','errors':'bad'}):
            with self.assertRaises(ValueError):convert(value)
        with self.assertRaises(ValueError):converter.convert(b' '*1048577,source_id='s',asset_id='a',run_id='r',commit='a'*40,observed_at='2026-10-19T12:00:00Z')

class SemgrepApiRoundtripTests(unittest.TestCase):
    setUp=fixtures.AccessTests.setUp
    tearDown=fixtures.AccessTests.tearDown
    headers=fixtures.AccessTests.headers
    def test_conversion_intake_replay_and_immutable_commit(self):
        root='/api/v1/platform/'
        source=self.client.post(root+'result-sources',headers=self.headers(),json=dict(name='QA converter',module='appsec')).json()
        asset=self.client.post(root+'assets',headers=self.headers(),json=dict(name='QA repo',kind='repository',externalKey='qa:converter')).json()
        manifest,documents=convert(source_id=source['id'],asset_id=asset['id'])
        body=documents[0]
        response=self.client.post(root+'module-results',headers=self.headers(),json=body)
        self.assertEqual(response.status_code,201,response.text)
        self.assertEqual(self.client.post(root+'module-results',headers=self.headers(),json=body).status_code,200)
        changed=copy.deepcopy(body);changed['analysis']['origin']['commit']='b'*40
        self.assertEqual(self.client.post(root+'module-results',headers=self.headers(),json=changed).status_code,409)
        invalid=copy.deepcopy(body);invalid['analysis']['origin']['reportSha256']='bad'
        self.assertEqual(self.client.post(root+'module-results',headers=self.headers(),json=invalid).status_code,422)
        rows=self.client.get(root+'module-results?analysisKind=sast',headers=self.headers('viewer')).json()
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['payload']['analysis']['origin']['commit'],'a'*40)
        self.assertEqual(rows[0]['verification'],'not_attested')

if __name__=='__main__':unittest.main()
