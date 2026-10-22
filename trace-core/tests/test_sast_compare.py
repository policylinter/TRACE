import copy,json,unittest
from unittest.mock import patch
from sqlalchemy import text
import test_sast_jobs as fixtures
from test_semgrep_converter import report,convert
from trace_api import job_store

class SastComparisonTests(unittest.TestCase):
    setUp=fixtures.SastJobsTests.setUp
    tearDown=fixtures.SastJobsTests.tearDown
    setUpBase=fixtures.SastJobsTests.setUpBase
    tearDownBase=fixtures.SastJobsTests.tearDownBase
    headers=fixtures.SastJobsTests.headers
    submit=fixtures.SastJobsTests.submit
    fake=fixtures.SastJobsTests.fake
    root=fixtures.SastJobsTests.root
    def execute(self,commit,value=None):
        original=self.fake
        def execute(**kwargs):
            with patch('test_sast_jobs.report',return_value=value or report()):return original(**kwargs)
        id=self.submit(commit=commit).json()['jobId']
        with patch('tools.run_sast_local.execute',side_effect=execute):
            result=job_store.execute(self.factory,id)
        self.assertEqual(result['status'],'completed',result)
        return result['executionId']
    def comparison(self,current,baseline,role='viewer'):
        return self.client.get(self.root+'executions/'+current+'/compare',params={'baselineId':baseline},headers=self.headers(role))
    def test_differences_are_read_only_and_line_sensitive(self):
        old=self.execute('a'*40)
        value=report();item=copy.deepcopy(value['results'][0]);item['check_id']='qa.new.rule';value['results'].append(item)
        current=self.execute('b'*40,value)
        result=self.comparison(current,old);self.assertEqual(result.status_code,200,result.text)
        data=result.json();self.assertEqual(data['counts'],dict(appeared=1,repeated=1,not_observed=0))
        self.assertFalse(data['remediationVerified']);self.assertFalse(data['coverageVerified'])
        self.assertEqual(data['currentCommit'],'b'*40)
        moved=report();moved['results'][0]['start']['line']=7;moved['results'][0]['end']['line']=8
        latest=self.execute('c'*40,moved)
        self.assertEqual(self.comparison(latest,old).json()['counts'],dict(appeared=1,repeated=0,not_observed=1))
        self.assertEqual(self.comparison(current,old).json(),data)
    def test_partial_and_empty_never_claim_fixed(self):
        old=self.execute('a'*40);value=report();value['results']=[];value['errors']=[{'message':'test'}]
        current=self.execute('b'*40,value);data=self.comparison(current,old).json()
        self.assertEqual(data['currentReportState'],'partial');self.assertEqual(data['counts']['not_observed'],1)
        self.assertFalse(data['remediationVerified'])
    def test_changed_rules_or_configuration_rejected(self):
        old=self.execute('a'*40)
        self.target['name']='changed configuration';self.config.write_text(json.dumps([self.target]))
        current=self.execute('b'*40)
        self.assertEqual(self.comparison(current,old).status_code,409)
    def test_scope_and_direction_and_missing(self):
        old=self.execute('a'*40);current=self.execute('b'*40)
        self.assertEqual(self.comparison(old,current).status_code,422)
        self.assertEqual(self.comparison(old,old).status_code,422)
        self.assertEqual(self.comparison(current,'missing').status_code,404)
        response=self.client.get(self.root+'executions/'+current+'/compare',params={'baselineId':old},headers={**self.headers('viewer'),'X-Trace-Workspace':'foreign'})
        self.assertIn(response.status_code,(403,404))
    def test_evidence_corruption_is_rejected(self):
        old=self.execute('a'*40);current=self.execute('b'*40)
        with self.factory() as db:
            db.execute(text("UPDATE sast_executions SET sha256='broken' WHERE id=:id"),{'id':old});db.commit()
        self.assertEqual(self.comparison(current,old).status_code,409)
