import hashlib
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from sqlalchemy import select,func,update
import test_module_intake as fixtures
from trace_api.module_intake import ModuleResult
from trace_api.result_evidence import ResultEvidence
from trace_api.platform import PlatformAudit

class ResultEvidenceTests(unittest.TestCase):
    setUp=fixtures.ModuleIntakeTests.setUp
    tearDown=fixtures.ModuleIntakeTests.tearDown
    headers=fixtures.ModuleIntakeTests.headers
    prepare=fixtures.ModuleIntakeTests.prepare
    ingest=fixtures.ModuleIntakeTests.ingest
    root=fixtures.ModuleIntakeTests.root
    content=b'local isolated evidence\x00\xff'
    def report(self,content=None):
        content=self.content if content is None else content
        body=self.prepare();body['evidence'][0]['sha256']=hashlib.sha256(content).hexdigest()
        response=self.ingest(body);self.assertEqual(response.status_code,201,response.text)
        self.result=response.json();self.url=self.root+'module-results/'+self.result['id']+'/evidence'
        return body
    def upload(self,content=None,role='analyst',index=0):
        return self.client.put(self.url+'/'+str(index),content=self.content if content is None else content,
            headers={**self.headers(role),'Content-Type':'application/octet-stream'})
    def test_roundtrip_hash_provenance_and_unchanged_report(self):
        self.report()
        before=self.client.get(self.url,headers=self.headers('viewer')).json()
        self.assertEqual(before['items'][0]['status'],'not_stored')
        self.assertEqual(self.client.get(self.url+'/0/content',headers=self.headers()).status_code,404)
        stored=self.upload();self.assertEqual(stored.status_code,201,stored.text)
        self.assertEqual(stored.json()['status'],'hash_matches');self.assertEqual(stored.json()['storedBy'],'user:analyst')
        response=self.client.get(self.url+'/0/content',headers=self.headers('viewer'))
        self.assertEqual(response.content,self.content)
        self.assertEqual(response.headers['content-type'],'application/octet-stream')
        self.assertIn('attachment;',response.headers['content-disposition'])
        self.assertEqual(response.headers['x-content-type-options'],'nosniff')
        self.assertEqual(response.headers['cache-control'],'no-store')
        with self.factory() as db:
            row=db.get(ModuleResult,self.result['id']);self.assertEqual(row.sha256,self.result['sha256']);self.assertEqual(row.payload,self.result['payload'])
    def test_wrong_hash_schema_media_type_and_missing_reference(self):
        self.report()
        self.assertEqual(self.upload(b'wrong').status_code,422)
        self.assertEqual(self.upload(index=1).status_code,404)
        self.assertEqual(self.upload(index=-1).status_code,422)
        self.assertEqual(self.upload(index=20).status_code,422)
        self.assertEqual(self.client.put(self.url+'/0',json={'file':'bad'},headers=self.headers()).status_code,415)
        with self.factory() as db:self.assertEqual(db.scalar(select(func.count()).select_from(ResultEvidence)),0)
    def test_auth_roles_and_service_account_denied(self):
        self.report()
        self.assertEqual(self.client.get(self.url).status_code,401)
        self.assertEqual(self.client.put(self.url+'/0',content=self.content).status_code,401)
        self.assertEqual(self.upload(role='viewer').status_code,403)
        token=self.client.post('/api/v1/access/service-accounts',headers=self.headers(),json={'name':'Inventory','scopes':['inventory:read','inventory:write']}).json()['token']
        self.assertEqual(self.client.get(self.url,headers={'Authorization':'Bearer '+token}).status_code,403)
    def test_idempotent_and_concurrent_uploads_one_record_one_audit(self):
        self.report()
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses=list(pool.map(lambda _:self.upload(),range(2)))
        self.assertEqual(sorted(row.status_code for row in responses),[200,201])
        self.assertEqual(responses[0].json(),responses[1].json())
        self.assertEqual(self.upload().status_code,200)
        with self.factory() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(ResultEvidence)),1)
            self.assertEqual(db.scalar(select(func.count()).select_from(PlatformAudit).where(PlatformAudit.action=='module-result.evidence-stored')),1)
    def test_limits_and_empty_file(self):
        large=b'a'*65536;self.report(large)
        self.assertEqual(self.upload(large+b'a').status_code,413)
        self.assertEqual(self.upload(large).status_code,201)
        body=self.result['payload'];body={**body,'externalId':'empty-report','evidence':[{**body['evidence'][0],'sha256':hashlib.sha256(b'').hexdigest()}]}
        empty=self.ingest(body).json();self.url=self.root+'module-results/'+empty['id']+'/evidence'
        self.assertEqual(self.upload(b'').status_code,201)
        self.assertEqual(self.client.get(self.url+'/0/content',headers=self.headers()).content,b'')
    def test_audit_failure_rolls_back_and_retry_works(self):
        self.report()
        with patch('trace_api.result_evidence.audit',side_effect=RuntimeError('audit unavailable')):
            with self.assertRaises(RuntimeError):self.upload()
        with self.factory() as db:self.assertEqual(db.scalar(select(func.count()).select_from(ResultEvidence)),0)
        self.assertEqual(self.upload().status_code,201)
    def test_immutable_orm_bulk_and_integrity_check(self):
        self.report();self.upload()
        with self.factory() as db:
            row=db.get(ResultEvidence,(self.result['id'],0));row.content=b'changed'
            with self.assertRaises(ValueError):db.commit()
        with self.factory() as db:
            with self.assertRaises(ValueError):db.execute(update(ResultEvidence).values(content=b'changed'))
        with self.factory() as db:
            db.delete(db.get(ResultEvidence,(self.result['id'],0)))
            with self.assertRaises(ValueError):db.commit()
        # Simulate corruption outside the ORM: mismatched bytes are never downloaded/replaced.
        with self.engine.begin() as connection:
            connection.execute(ResultEvidence.__table__.update().values(content=b'corrupted'))
        state=self.client.get(self.url,headers=self.headers()).json()
        self.assertEqual(state['items'][0]['status'],'integrity_error')
        self.assertEqual(self.client.get(self.url+'/0/content',headers=self.headers()).status_code,409)
        self.assertEqual(self.upload().status_code,409)
    def test_cross_workspace_and_foreign_reference_rejected(self):
        from trace_api.workspace_models import Workspace
        self.report();self.upload()
        with self.factory() as db:db.add(Workspace(id='other',organization_id='default',name='Other'));db.commit()
        headers={**self.headers(),'X-Trace-Workspace':'other'}
        self.assertEqual(self.client.get(self.url,headers=headers).status_code,404)
        self.assertEqual(self.client.get(self.url+'/0/content',headers=headers).status_code,404)
        self.assertEqual(self.client.put(self.url+'/0',content=self.content,headers={**headers,'Content-Type':'application/octet-stream'}).status_code,404)
        with self.factory() as db:
            db.info['workspace_id']='other'
            db.add(ResultEvidence(result_id=self.result['id'],evidence_index=1,content=b'',sha256='a'*64,byte_count=0,stored_at='test',stored_by='test'))
            with self.assertRaises(ValueError):db.commit()
