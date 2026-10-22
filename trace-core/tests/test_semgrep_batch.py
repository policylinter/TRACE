import copy
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from sqlalchemy import select,func,update
import test_access as fixtures
from test_semgrep_converter import convert,report
from trace_api.semgrep_batch import SemgrepBatch
from trace_api.module_intake import ModuleResult
from trace_api.result_provenance import ResultIntakeReceipt
from trace_api.platform import PlatformAudit
from trace_api.workspace_models import Workspace

class SemgrepBatchTests(unittest.TestCase):
    setUp=fixtures.AccessTests.setUp
    tearDown=fixtures.AccessTests.tearDown
    headers=fixtures.AccessTests.headers
    root='/api/v1/platform/'
    def body(self,empty=False):
        source=self.client.post(self.root+'result-sources',headers=self.headers(),json=dict(name='QA batch',module='appsec')).json()
        asset=self.client.post(self.root+'assets',headers=self.headers(),json=dict(name='QA repo',kind='repository',externalKey='qa:'+source['id'])).json()
        value=report()
        if empty:value['results']=[]
        else:
            other=copy.deepcopy(value['results'][0]);other['path']='src/other.py';value['results'].append(other)
        manifest,results=convert(value,source_id=source['id'],asset_id=asset['id'])
        return dict(manifest=manifest,results=results)
    def send(self,body,role='admin'):
        return self.client.post(self.root+'semgrep-batches',headers=self.headers(role),json=body)
    def test_atomic_success_replay_and_conflict(self):
        body=self.body();first=self.send(body)
        self.assertEqual(first.status_code,201,first.text)
        self.assertEqual(first.json()['createdCount'],2)
        replay=self.send(body);self.assertEqual(replay.status_code,200)
        self.assertEqual(first.json(),replay.json())
        changed=copy.deepcopy(body);changed['manifest']['reportState']='unknown'
        for item in changed['results']:item['analysis']['origin']['reportState']='unknown'
        from trace_api.result_contracts import digest
        changed['manifest']['documentSha256']=[digest(r) for r in changed['results']]
        self.assertEqual(self.send(changed).status_code,409)
        with self.factory() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(ModuleResult)),2)
            self.assertEqual(db.scalar(select(func.count()).select_from(SemgrepBatch)),1)
    def test_late_conflict_rolls_back_earlier_result_receipt_and_audit(self):
        body=self.body();existing=copy.deepcopy(body['results'][1]);existing['title']='Previously received different data'
        self.assertEqual(self.client.post(self.root+'module-results',headers=self.headers(),json=existing).status_code,201)
        with self.factory() as db:before=[r.id for r in db.scalars(select(PlatformAudit))]
        self.assertEqual(self.send(body).status_code,409)
        with self.factory() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(ModuleResult)),1)
            self.assertEqual(db.scalar(select(func.count()).select_from(ResultIntakeReceipt)),1)
            self.assertEqual(db.scalar(select(func.count()).select_from(SemgrepBatch)),0)
            self.assertEqual(before,[r.id for r in db.scalars(select(PlatformAudit))])
    def test_hash_context_counts_and_schema_fail_before_writes(self):
        body=self.body()
        variants=[]
        changed=copy.deepcopy(body);changed['results'][0]['title']='tampered';variants.append(changed)
        changed=copy.deepcopy(body);changed['manifest']['outputResults']=1;variants.append(changed)
        changed=copy.deepcopy(body);changed['manifest']['files'][0]='../finding.json';variants.append(changed)
        changed=copy.deepcopy(body);changed['manifest']['commit']='b'*40;variants.append(changed)
        changed=copy.deepcopy(body);changed['manifest']['reportedErrorCount']=1;variants.append(changed)
        changed=copy.deepcopy(body);changed['manifest']['coverageVerified']=True;variants.append(changed)
        for changed in variants:self.assertEqual(self.send(changed).status_code,422)
        self.assertEqual(self.client.post(self.root+'semgrep-batches',headers=self.headers(),content=b'a'*1048577).status_code,413)
        with self.factory() as db:self.assertEqual(db.scalar(select(func.count()).select_from(ModuleResult)),0)
    def test_roles_scope_and_disabled_sources(self):
        body=self.body()
        for role in ('analyst','viewer'):self.assertEqual(self.send(body,role).status_code,403)
        with self.factory() as db:db.add(Workspace(id='other',organization_id='default',name='Other'));db.commit()
        headers={**self.headers(),'X-Trace-Workspace':'other'}
        self.assertEqual(self.client.post(self.root+'semgrep-batches',headers=headers,json=body).status_code,404)
        first=self.send(body);self.assertEqual(first.status_code,201)
        self.assertEqual(self.client.get(self.root+'semgrep-batches',headers=headers).json(),[])
        self.assertEqual(len(self.client.get(self.root+'semgrep-batches',headers=self.headers('viewer')).json()),1)
        self.client.put(self.root+'result-sources/'+body['manifest']['sourceId'],headers=self.headers(),json={'active':False})
        self.assertEqual(self.send(body).status_code,200)
        body['manifest']['runId']='next-run'
        for item in body['results']:item['analysis']['origin']['runId']='next-run'
        from trace_api.result_contracts import digest
        body['manifest']['documentSha256']=[digest(r) for r in body['results']]
        self.assertEqual(self.send(body).status_code,409)
    def test_concurrent_batch_creates_one_receipt(self):
        body=self.body()
        with ThreadPoolExecutor(max_workers=2) as pool:responses=list(pool.map(lambda _:self.send(body),range(2)))
        self.assertEqual(sorted(r.status_code for r in responses),[200,201])
        with self.factory() as db:self.assertEqual(db.scalar(select(func.count()).select_from(SemgrepBatch)),1)
    def test_empty_report_has_receipt_without_fake_findings(self):
        result=self.send(self.body(empty=True));self.assertEqual(result.status_code,201,result.text)
        self.assertEqual(result.json()['resultIds'],[])
        with self.factory() as db:self.assertEqual(db.scalar(select(func.count()).select_from(ModuleResult)),0)
    def test_audit_rollback_and_orm_immutability(self):
        body=self.body()
        with patch('trace_api.semgrep_batch.audit',side_effect=RuntimeError('audit failed')):
            with self.assertRaises(RuntimeError):self.send(body)
        with self.factory() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(ModuleResult)),0)
        self.assertEqual(self.send(body).status_code,201)
        with self.factory() as db:
            with self.assertRaises(ValueError):db.execute(update(SemgrepBatch).values(run_id='changed'))
            row=db.scalar(select(SemgrepBatch));row.run_id='changed'
            with self.assertRaises(ValueError):db.commit()

if __name__=='__main__':unittest.main()
