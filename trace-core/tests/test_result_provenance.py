import unittest
from unittest.mock import patch
from sqlalchemy import select,func,update
import test_signed_intake as fixtures
from trace_api.result_provenance import ResultIntakeReceipt
from trace_api.module_intake import ModuleResult
from trace_api.signed_intake import WebhookDelivery

class ProvenanceTests(unittest.TestCase):
    setUp=fixtures.SignedIntakeTests.setUp
    tearDown=fixtures.SignedIntakeTests.tearDown
    headers=fixtures.SignedIntakeTests.headers
    prepare=fixtures.SignedIntakeTests.prepare
    setup_hook=fixtures.SignedIntakeTests.setup_hook
    send=fixtures.SignedIntakeTests.send
    key=fixtures.SignedIntakeTests.key
    root=fixtures.SignedIntakeTests.root
    def manual(self,body):
        response=self.client.post(self.root+'module-results',headers=self.headers(),json=body)
        self.assertIn(response.status_code,(200,201),response.text)
        return response.json()
    def view(self,id,**kwargs):return self.client.get(self.root+'module-results/'+id+'/provenance',headers=kwargs.pop('headers',self.headers()),**kwargs)
    def test_manual_first_receipt_is_not_promoted_by_later_signed_delivery(self):
        body=self.setup_hook();report=self.manual(body)
        first=self.view(report['id']).json()
        self.assertEqual(first['initialIntake']['record']['method'],'manual')
        self.assertEqual(first['initialIntake']['status'],'consistent')
        self.assertEqual(first['report']['status'],'hash_matches')
        self.assertEqual(first['signedDeliveries']['total'],0)
        self.assertEqual(self.send(body).status_code,200)
        after=self.view(report['id']).json()
        self.assertEqual(after['initialIntake'],first['initialIntake'])
        self.assertEqual(after['signedDeliveries']['total'],1)
        self.assertEqual(after['attestation'],'not_performed')
    def test_signed_first_receipt_bound_to_ledger_and_read_only(self):
        body=self.setup_hook();result=self.send(body).json();self.result_id=result['resultId']
        with self.factory() as db:before=db.scalar(select(func.count()).select_from(ResultIntakeReceipt))
        state=self.view(self.result_id).json()
        receipt=state['initialIntake'];self.assertEqual(receipt['status'],'consistent')
        self.assertEqual(receipt['record']['method'],'signed_hmac')
        self.assertEqual(receipt['record']['actor'],'source:'+body['sourceId'])
        self.assertEqual(receipt['record']['delivery']['id'],'test-1')
        self.assertEqual(receipt['record']['delivery']['bodySha256'],state['signedDeliveries']['items'][0]['bodySha256'])
        self.assertNotIn(self.key,str(state));self.assertNotIn('secretRef',str(state))
        self.assertEqual(state['evidence']['items'][0]['status'],'not_stored')
        self.assertEqual(self.send(body).status_code,200)
        with self.factory() as db:self.assertEqual(db.scalar(select(func.count()).select_from(ResultIntakeReceipt)),before)
    def test_legacy_receipt_not_fabricated_by_replay(self):
        body=self.setup_hook();report=self.manual(body)
        with self.engine.begin() as connection:connection.execute(ResultIntakeReceipt.__table__.delete())
        self.assertEqual(self.view(report['id']).json()['initialIntake'],{'status':'not_recorded','record':None})
        self.assertEqual(self.send(body).status_code,200)
        self.assertEqual(self.view(report['id']).json()['initialIntake']['status'],'not_recorded')
        with self.factory() as db:self.assertEqual(db.scalar(select(func.count()).select_from(ResultIntakeReceipt)),0)
    def test_scope_roles_and_service_account(self):
        from trace_api.workspace_models import Workspace
        report=self.manual(self.prepare());url=self.root+'module-results/'+report['id']+'/provenance'
        self.assertEqual(self.client.get(url).status_code,401)
        for role in ('analyst','viewer'):self.assertEqual(self.view(report['id'],headers=self.headers(role)).status_code,200)
        with self.factory() as db:db.add(Workspace(id='other',organization_id='default',name='Other'));db.commit()
        self.assertEqual(self.view(report['id'],headers={**self.headers(),'X-Trace-Workspace':'other'}).status_code,404)
        token=self.client.post('/api/v1/access/service-accounts',headers=self.headers(),json={'name':'Inventory','scopes':['inventory:read']}).json()['token']
        self.assertEqual(self.client.get(url,headers={'Authorization':'Bearer '+token}).status_code,403)
    def test_pagination_deliveries_and_receipt_immutability(self):
        body=self.setup_hook();result=self.send(body).json()
        for delivery in ('second','third'):self.assertEqual(self.send(body,delivery=delivery).status_code,200)
        first=self.view(result['resultId'],params={'limit':2}).json()['signedDeliveries']
        second=self.view(result['resultId'],params={'limit':2,'offset':2}).json()['signedDeliveries']
        self.assertEqual(first['total'],3);self.assertEqual(len(second['items']),1)
        self.assertEqual(len({item['id'] for item in first['items']+second['items']}),3)
        self.assertEqual(self.view(result['resultId'],params={'limit':51}).status_code,422)
        with self.factory() as db:
            row=db.get(ResultIntakeReceipt,result['resultId']);row.record={}
            with self.assertRaises(ValueError):db.commit()
        with self.factory() as db:
            with self.assertRaises(ValueError):db.execute(update(ResultIntakeReceipt).values(record={}))
        with self.factory() as db:
            db.delete(db.get(ResultIntakeReceipt,result['resultId']))
            with self.assertRaises(ValueError):db.commit()
    def test_corruption_is_reported_without_trust_promotion(self):
        body=self.setup_hook();result=self.send(body).json();id=result['resultId']
        with self.engine.begin() as connection:connection.execute(ResultIntakeReceipt.__table__.update().values(record={'method':'signed_hmac','actor':'forged'}))
        self.assertEqual(self.view(id).json()['initialIntake']['status'],'integrity_error')
        with self.engine.begin() as connection:
            connection.execute(WebhookDelivery.__table__.update().values(result_sha256='0'*64))
        self.assertEqual(self.view(id).json()['signedDeliveries']['items'][0]['status'],'integrity_error')
    def test_atomic_receipt_failure_rolls_back_import_and_delivery(self):
        body=self.setup_hook()
        with patch('trace_api.result_provenance.record_intake',side_effect=RuntimeError('receipt failed')):
            with self.assertRaises(RuntimeError):self.send(body)
        with self.factory() as db:
            for model in (ModuleResult,WebhookDelivery,ResultIntakeReceipt):self.assertEqual(db.scalar(select(func.count()).select_from(model)),0)
        self.assertEqual(self.send(body).status_code,201)

    def test_report_tampering_is_detected_and_get_does_not_write(self):
        from trace_api.platform import PlatformAudit
        body=self.prepare();report=self.manual(body)
        with self.factory() as db:before=db.scalar(select(func.count()).select_from(PlatformAudit))
        self.assertEqual(self.view(report['id']).json()['report']['status'],'hash_matches')
        with self.factory() as db:self.assertEqual(db.scalar(select(func.count()).select_from(PlatformAudit)),before)
        with self.engine.begin() as connection:
            connection.execute(ModuleResult.__table__.update().values(payload={**report['payload'],'title':'tampered'}))
        state=self.view(report['id']).json()
        self.assertEqual(state['report']['status'],'integrity_error')
        self.assertEqual(state['attestation'],'not_performed')

    def test_foreign_keys_and_receipt_reference_scope(self):
        from trace_api.workspace_models import Workspace
        with self.engine.connect() as connection:
            connection.exec_driver_sql('PRAGMA foreign_keys=ON');connection.commit()
        report=self.manual(self.prepare())
        self.assertEqual(self.view(report['id']).json()['initialIntake']['status'],'consistent')
        with self.factory() as db:db.add(Workspace(id='other',organization_id='default',name='Other'));db.commit()
        with self.factory() as db:
            db.info['workspace_id']='other';db.add(ResultIntakeReceipt(result_id=report['id'],record={}))
            with self.assertRaises(ValueError):db.commit()
