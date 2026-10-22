import unittest
from unittest.mock import patch
from sqlalchemy import select,func,update,delete
import test_access as fixtures
from trace_api.security_work import SecurityRecord,SecurityChange,SecurityLink
from trace_api.platform import PlatformAudit

class SecurityWorkTests(unittest.TestCase):
    setUp=fixtures.AccessTests.setUp
    tearDown=fixtures.AccessTests.tearDown
    headers=fixtures.AccessTests.headers
    root='/api/v1/platform/security-records'
    def create(self,kind='incident',role='analyst',**fields):
        return self.client.post(self.root,headers=self.headers(role),json=dict(kind=kind,title='QA '+kind,description='Operator assertion only',**fields))
    def decide(self,row,status,role='analyst',**fields):
        return self.client.put(self.root+'/'+row['id']+'/decision',headers=self.headers(role),json=dict(expectedRevision=row['revision'],status=status,reason='QA decision basis',**fields))
    def test_chain_and_read_only_history(self):
        event=self.create('event').json();detection=self.create('detection',links=[dict(targetKind='record',targetId=event['id'],reason='Source observation')]).json()
        incident=self.create(links=[dict(targetKind='record',targetId=detection['id'],reason='Operator investigation')]).json()
        risk=self.create('risk',links=[dict(targetKind='record',targetId=incident['id'],reason='Risk basis')]).json()
        task=self.create('task',links=[dict(targetKind='record',targetId=risk['id'],reason='Remediation task')]).json()
        result=self.decide(task,'done');self.assertEqual(result.status_code,200,result.text)
        detail=self.client.get(self.root+'/'+task['id'],headers=self.headers('viewer')).json()
        self.assertEqual(detail['historyTotal'],2);self.assertEqual(detail['history'][0]['actor'],'user:analyst')
        self.assertEqual(detail['record']['payload'],task['payload']);self.assertEqual(detail['record']['sha256'],task['sha256'])
        self.assertEqual(self.decide(event,'recorded').status_code,409)
    def test_roles_invalid_kind_state_and_spoofing(self):
        self.assertEqual(self.create(role='viewer').status_code,403)
        self.assertEqual(self.create(actor='admin').status_code,422)
        row=self.create().json();self.assertEqual(self.decide(row,'invented').status_code,422)
        self.assertEqual(self.decide(row,'investigating',role='viewer').status_code,403)
        schema=self.client.get(self.root+'/schema',headers=self.headers('viewer')).json();self.assertFalse(schema['automaticResponse']);self.assertFalse(schema['exceptionEnforcement'])
    def test_dedup_and_stale_revision(self):
        first=self.create(externalKey='qa:key');second=self.create(externalKey='qa:key');self.assertEqual(first.status_code,201);self.assertEqual(second.status_code,200);self.assertEqual(first.json()['id'],second.json()['id'])
        self.assertEqual(self.create('risk',externalKey='qa:key').status_code,409)
        row=first.json();self.assertEqual(self.decide(row,'investigating').status_code,200)
        self.assertEqual(self.decide(row,'contained').status_code,409)
    def test_exception_separation_expiry_and_no_enforcement(self):
        self.assertEqual(self.create('exception').status_code,422)
        row=self.create('exception',dueDate='2099-01-01').json()
        self.assertEqual(self.decide(row,'approved').status_code,403)
        approved=self.decide(row,'approved',role='admin');self.assertEqual(approved.status_code,200,approved.text)
        self.assertEqual(self.decide(approved.json(),'rejected',role='admin').status_code,409)
        own=self.create('exception',role='admin',dueDate='2099-01-01').json();self.assertEqual(self.decide(own,'approved',role='admin').status_code,403)
        self.assertEqual(self.create('exception',dueDate='2000-01-01').status_code,422)
    def test_evidence_required_and_risk_acceptance(self):
        row=self.create().json();self.assertEqual(self.decide(row,'resolved').status_code,409)
        risk=self.create('risk').json();self.assertEqual(self.decide(risk,'accepted').status_code,403)
        self.assertEqual(self.decide(risk,'accepted',role='admin').status_code,200)
        control=self.create('control').json();self.assertEqual(self.decide(control,'evidence_recorded').status_code,409)
    def test_links_scope_duplicates_and_missing(self):
        row=self.create().json();url=self.root+'/'+row['id']+'/links'
        self.assertEqual(self.client.post(url,headers=self.headers(),json=dict(targetKind='record',targetId=row['id'],reason='self')).status_code,422)
        self.assertEqual(self.client.post(url,headers=self.headers(),json=dict(targetKind='asset',targetId='missing',reason='missing')).status_code,404)
        body=dict(targetKind='finding',targetId='FND-8F21A3',reason='QA source finding')
        self.assertEqual(self.client.post(url,headers=self.headers(),json=body).status_code,201)
        self.assertEqual(self.client.post(url,headers=self.headers(),json=body).status_code,409)
        related=self.client.get(self.root+'/related',headers=self.headers('viewer'),params=dict(targetKind='finding',targetId='FND-8F21A3'))
        self.assertEqual(related.status_code,200,related.text);self.assertEqual([x['id'] for x in related.json()],[row['id']])
        self.assertEqual(self.client.get(self.root+'/related',headers=self.headers(),params=dict(targetKind='asset',targetId='missing')).status_code,404)
        self.assertEqual(self.decide(row,'resolved').status_code,200)
        h={**self.headers(),'X-Trace-Workspace':'foreign'};self.assertIn(self.client.get(self.root+'/'+row['id'],headers=h).status_code,(403,404))
    def test_audit_failure_rolls_back_everything(self):
        with patch('trace_api.security_work.audit',side_effect=RuntimeError('QA audit failure')):
            with self.assertRaises(RuntimeError):self.create(externalKey='qa:rollback')
        with self.factory() as db:self.assertEqual(db.scalar(select(func.count()).select_from(SecurityRecord)),0)
        row=self.create().json()
        with patch('trace_api.security_work.audit',side_effect=RuntimeError('QA audit failure')):
            with self.assertRaises(RuntimeError):self.decide(row,'investigating')
        value=self.client.get(self.root+'/'+row['id'],headers=self.headers()).json();self.assertEqual(value['record']['revision'],0);self.assertEqual(value['historyTotal'],1)
    def test_history_and_record_payload_immutable(self):
        row=self.create().json()
        with self.factory() as db:
            db.info.update(organization_id='default',workspace_id='default')
            obj=db.get(SecurityRecord,row['id']);obj.payload={'changed':True}
            with self.assertRaises(ValueError):db.commit()
            db.rollback()
            with self.assertRaises(ValueError):db.execute(delete(SecurityRecord))
            db.rollback()
            with self.assertRaises(ValueError):db.execute(update(SecurityChange).values(actor='spoof'))

    def test_concurrent_dedup_and_decisions(self):
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(lambda _:self.create(externalKey='qa:concurrent'),range(2)))
        self.assertEqual(sorted(r.status_code for r in results),[200,201])
        row=results[0].json()
        with ThreadPoolExecutor(max_workers=2) as pool:
            decisions=list(pool.map(lambda status:self.decide(row,status),['investigating','contained']))
        self.assertEqual(sorted(r.status_code for r in decisions),[200,409])
        value=self.client.get(self.root+'/'+row['id'],headers=self.headers()).json();self.assertEqual(value['historyTotal'],2)
