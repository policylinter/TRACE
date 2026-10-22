import hashlib
import hmac
import json
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from sqlalchemy import select,func,update
import test_module_intake as fixtures
from trace_api.signed_intake import environment_name,signing_message,WebhookDelivery
from trace_api.module_intake import ResultSource,ModuleResult

class SignedIntakeTests(unittest.TestCase):
    setUp=fixtures.ModuleIntakeTests.setUp
    tearDown=fixtures.ModuleIntakeTests.tearDown
    headers=fixtures.ModuleIntakeTests.headers
    prepare=fixtures.ModuleIntakeTests.prepare
    root=fixtures.ModuleIntakeTests.root
    key='isolated-test-key-never-production'
    def setup_hook(self):
        body=self.prepare();self.source_id=body['sourceId']
        self.url='/api/v1/hooks/results/'+self.source_id
        self.config_url=self.root+'result-sources/'+self.source_id+'/webhook'
        with self.factory() as db:
            self.source=db.get(ResultSource,self.source_id)
            name=environment_name(self.source,'env:CI_KEY')
        self.stack.enter_context(patch.dict('os.environ',{name:self.key}))
        result=self.client.put(self.config_url,headers=self.headers(),json={'enabled':True,'secretRef':'env:CI_KEY'})
        self.assertEqual(result.status_code,200,result.text)
        self.assertNotIn(self.key,result.text)
        self.assertTrue(result.json()['secretAvailable'])
        return body
    def send(self,body,delivery='test-1',timestamp=None,key=None):
        raw=json.dumps(body,ensure_ascii=False,separators=(',',':')).encode()
        timestamp=str(int(time.time()) if timestamp is None else timestamp)
        signature=hmac.new((key or self.key).encode(),signing_message(self.source,timestamp,delivery,raw),hashlib.sha256).hexdigest()
        return self.client.post(self.url,content=raw,headers={'X-Trace-Timestamp':timestamp,'X-Trace-Delivery':delivery,'X-Trace-Signature':'v1='+signature})
    def test_signed_delivery_idempotency_and_conflicts(self):
        body=self.setup_hook();first=self.send(body)
        self.assertEqual(first.status_code,201,first.text)
        replay=self.send(body);self.assertEqual(replay.status_code,200);self.assertTrue(replay.json()['replayed'])
        self.assertEqual(self.send({**body,'title':'changed'}).status_code,409)
        self.assertEqual(self.send(body,'second-delivery').status_code,200)
        with self.factory() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(ModuleResult)),1)
            self.assertEqual(db.scalar(select(func.count()).select_from(WebhookDelivery)),2)
            self.assertEqual(db.get(ModuleResult,first.json()['resultId']).received_by,'source:'+self.source_id)
        self.assertEqual(self.client.get(self.config_url,headers=self.headers()).json()['acceptedDeliveryCount'],2)
    def test_authentication_expiry_and_disabled_source(self):
        body=self.setup_hook()
        self.assertEqual(self.client.post(self.url,json=body).status_code,401)
        for kwargs in ({'key':'wrong'},{'timestamp':int(time.time())-400},{'timestamp':int(time.time())+90}):
            self.assertEqual(self.send(body,**kwargs).status_code,401)
        self.client.put(self.root+'result-sources/'+self.source_id,headers=self.headers(),json={'active':False})
        self.assertEqual(self.send(body).status_code,401)
    def test_config_roles_disabled_default_and_no_secret_storage(self):
        body=self.prepare();self.source_id=body['sourceId'];url=self.root+'result-sources/'+self.source_id+'/webhook'
        self.assertFalse(self.client.get(url,headers=self.headers()).json()['enabled'])
        for role in ('viewer','analyst'):
            self.assertEqual(self.client.get(url,headers=self.headers(role)).status_code,403)
            self.assertEqual(self.client.put(url,headers=self.headers(role),json={'enabled':True,'secretRef':'env:KEY'}).status_code,403)
        self.assertEqual(self.client.put(url,headers=self.headers(),json={'enabled':True,'secretRef':''}).status_code,422)
        self.assertEqual(self.client.put(url,headers=self.headers(),json={'enabled':True,'secretRef':'raw-secret'}).status_code,422)
        configured=self.client.put(url,headers=self.headers(),json={'enabled':True,'secretRef':'env:MISSING'})
        self.assertFalse(configured.json()['secretAvailable'])
    def test_signed_invalid_schema_bound_source_and_size(self):
        body=self.setup_hook()
        for document in ({**body,'sourceId':'different'},{**body,'actor':'forged'},{**body,'evidence':[]}):
            self.assertEqual(self.send(document).status_code,422)
        self.assertEqual(self.send({**body,'description':'a'*65536}).status_code,413)
        with self.factory() as db:self.assertEqual(db.scalar(select(func.count()).select_from(WebhookDelivery)),0)
    def test_atomic_audit_failure_and_immutable_ledger(self):
        body=self.setup_hook()
        with patch('trace_api.signed_intake.audit',side_effect=RuntimeError('audit unavailable')):
            with self.assertRaises(RuntimeError):self.send(body)
        with self.factory() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(ModuleResult)),0)
            self.assertEqual(db.scalar(select(func.count()).select_from(WebhookDelivery)),0)
        self.assertEqual(self.send(body).status_code,201)
        with self.factory() as db:
            with self.assertRaises(ValueError):db.execute(update(WebhookDelivery).values(result_sha256='f'*64))
        with self.factory() as db:
            row=db.get(WebhookDelivery,(self.source_id,'test-1'));db.delete(row)
            with self.assertRaises(ValueError):db.commit()
    def test_concurrent_retry_and_disable_rotation(self):
        body=self.setup_hook()
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses=list(pool.map(lambda _:self.send(body),range(2)))
        self.assertEqual(sorted(r.status_code for r in responses),[200,201])
        self.client.put(self.config_url,headers=self.headers(),json={'enabled':False,'secretRef':'env:CI_KEY'})
        self.assertEqual(self.send(body).status_code,401)
        self.client.put(self.config_url,headers=self.headers(),json={'enabled':True,'secretRef':'env:ROTATED'})
        self.assertEqual(self.send(body).status_code,401)

    def test_workspace_binding_unknown_source_and_reference_scope(self):
        from trace_api.workspace_models import Workspace
        from trace_api.platform import Asset
        body=self.setup_hook()
        with self.factory() as db:
            db.add(Workspace(id='other',organization_id='default',name='Other'));db.commit()
        with self.factory() as db:
            db.info['workspace_id']='other'
            db.add(Asset(id='foreign-asset',name='Foreign',kind='server',external_key='foreign'));db.commit()
        self.assertEqual(self.send({**body,'assetId':'foreign-asset'}).status_code,404)
        self.assertEqual(self.client.get(self.config_url,headers={**self.headers(),'X-Trace-Workspace':'other'}).status_code,404)
        old_url=self.url;self.url='/api/v1/hooks/results/missing'
        self.assertEqual(self.send(body).status_code,401)
        self.url=old_url
        # Browser scope headers cannot change the signed source's stored scope.
        result=self.send(body)
        self.assertEqual(result.status_code,201,result.text)
        with self.factory() as db:
            row=db.get(ModuleResult,result.json()['resultId'])
            self.assertEqual(row.workspace_id,'default')
