import unittest
from datetime import datetime,timezone,timedelta
from sqlalchemy import select,func
import test_inventory_intake as fixtures
from trace_api.inventory_intake import InventoryRun,InventoryObservation
from trace_api.platform import Asset,PlatformAudit

class InventoryComparisonTests(unittest.TestCase):
    setUp=fixtures.InventoryTests.setUp
    tearDown=fixtures.InventoryTests.tearDown
    headers=fixtures.InventoryTests.headers
    source=fixtures.InventoryTests.source
    body=fixtures.InventoryTests.body
    send=fixtures.InventoryTests.send
    detail=fixtures.InventoryTests.detail
    root=fixtures.InventoryTests.root
    def pair(self,status='complete'):
        source=self.source();old=datetime.now(timezone.utc)-timedelta(hours=3)
        before_items=[{'externalId':'changed','name':'Node','owner':'old','version':'1'},{'externalId':'same','name':'Same'},{'externalId':'absent','name':'Absent'}]
        after_items=[{'externalId':'changed','name':'Node','owner':'new','version':'2'},{'externalId':'same','name':'Same'},{'externalId':'added','name':'Added'}]
        a=self.send(source,self.body('before',at=old,items=before_items));self.assertEqual(a.status_code,201,a.text)
        errors=[] if status=='complete' else [{'code':'collection_failed','message':'Test collection failure'}]
        b=self.send(source,self.body('after',at=old+timedelta(hours=1),items=[] if status=='error' else after_items,status=status,errors=errors))
        self.assertEqual(b.status_code,201,b.text)
        return source,a.json()['id'],b.json()['id']
    def compare(self,source,a,b,**kwargs):
        return self.client.get(self.root+'/'+source+'/compare',headers=kwargs.pop('headers',self.headers()),params={'before':a,'after':b,**kwargs})
    def test_complete_changes_only_new_missing_and_unchanged(self):
        source,a,b=self.pair();response=self.compare(source,a,b)
        self.assertEqual(response.status_code,200,response.text);data=response.json()
        self.assertEqual(data['counts'],dict(only_after=1,changed=1,not_in_after=1,not_observed_partial=0,unchanged=1))
        self.assertEqual(data['total'],3)
        rows={row['externalId']:row for row in data['items']}
        self.assertEqual([change['field'] for change in rows['changed']['changes']],['owner','version'])
        self.assertEqual(rows['absent']['kind'],'not_in_after');self.assertIsNone(rows['absent']['after'])
        self.assertEqual(rows['added']['kind'],'only_after');self.assertIsNone(rows['added']['before'])
        self.assertTrue(all(row['assetId'] for row in data['items']))
    def test_partial_does_not_imply_absence_error_is_unavailable(self):
        source,a,b=self.pair('partial');data=self.compare(source,a,b).json()
        self.assertEqual(data['counts']['not_in_after'],0)
        self.assertEqual(data['counts']['not_observed_partial'],1)
        source,a,b=self.pair('error');data=self.compare(source,a,b).json()
        self.assertEqual(data['status'],'unavailable');self.assertEqual(data['reason'],'collection_error')
        self.assertIsNone(data['counts']);self.assertEqual(data['items'],[])
    def test_partial_baseline_and_empty_complete_target(self):
        source=self.source();old=datetime.now(timezone.utc)-timedelta(hours=3)
        a=self.send(source,self.body('partial-base',at=old,status='partial',errors=[{'code':'limit_reached','message':'QA'}])).json()['id']
        b=self.send(source,self.body('empty-full',at=old+timedelta(hours=1),items=[])).json()['id']
        data=self.compare(source,a,b).json();self.assertEqual(data['before']['status'],'partial')
        self.assertEqual(data['counts']['not_in_after'],1)
        self.assertEqual(self.detail(source)['total'],1)
    def test_pagination_stable_and_order_validation(self):
        source,a,b=self.pair()
        first=self.compare(source,a,b,limit=2,includeUnchanged=True).json()
        second=self.compare(source,a,b,limit=2,offset=2,includeUnchanged=True).json()
        self.assertEqual(first['total'],4)
        self.assertEqual(len({row['externalId'] for row in first['items']+second['items']}),4)
        self.assertEqual(self.compare(source,b,a).status_code,422)
        self.assertEqual(self.compare(source,a,a).status_code,422)
        self.assertEqual(self.compare(source,a,b,limit=101).status_code,422)
        self.assertEqual(self.compare(source,a,b,offset=-1).status_code,422)
    def test_reads_do_not_change_registry_observations_or_audit(self):
        source,a,b=self.pair()
        with self.factory() as db:before={model.__name__:db.scalar(select(func.count()).select_from(model)) for model in (Asset,InventoryRun,InventoryObservation,PlatformAudit)}
        self.assertEqual(self.compare(source,a,b).status_code,200)
        self.client.put(self.root+'/'+source,headers=self.headers(),json={'active':False,'freshnessHours':24})
        self.assertEqual(self.compare(source,a,b).status_code,200)
        with self.factory() as db:
            for model in (Asset,InventoryRun,InventoryObservation):self.assertEqual(db.scalar(select(func.count()).select_from(model)),before[model.__name__])
            self.assertEqual(db.scalar(select(func.count()).select_from(PlatformAudit)),before['PlatformAudit']+1)
            original=db.scalar(select(Asset).where(Asset.id==self.compare(source,a,b).json()['items'][1]['assetId']))
            self.assertEqual(original.owner,'')
    def test_scopes_roles_foreign_source_and_unknown(self):
        from trace_api.workspace_models import Workspace
        source,a,b=self.pair();other=self.source()
        self.assertEqual(self.compare(other,a,b).status_code,404)
        self.assertEqual(self.compare(source,a,'unknown').status_code,404)
        url=self.root+'/'+source+'/compare?before='+a+'&after='+b
        self.assertEqual(self.client.get(url).status_code,401)
        for role in ('analyst','viewer'):self.assertEqual(self.compare(source,a,b,headers=self.headers(role)).status_code,200)
        with self.factory() as db:db.add(Workspace(id='other',organization_id='default',name='Other'));db.commit()
        self.assertEqual(self.compare(source,a,b,headers={**self.headers(),'X-Trace-Workspace':'other'}).status_code,404)
        token=self.client.post('/api/v1/access/service-accounts',headers=self.headers(),json={'name':'Inventory','scopes':['inventory:read']}).json()['token']
        self.assertEqual(self.compare(source,a,b,headers={'Authorization':'Bearer '+token}).status_code,403)
    def test_corruption_does_not_create_false_changes(self):
        source,a,b=self.pair()
        with self.engine.begin() as connection:connection.execute(InventoryRun.__table__.update().where(InventoryRun.id==b).values(payload={}))
        data=self.compare(source,a,b).json()
        self.assertEqual(data['status'],'unavailable');self.assertEqual(data['reason'],'integrity_error');self.assertIsNone(data['counts'])
    def test_unchanged_fields_ignore_item_order_and_older_snapshot_stays_pinned(self):
        source=self.source();old=datetime.now(timezone.utc)-timedelta(hours=3)
        items=[{'externalId':'a','name':'A'},{'externalId':'b','name':'B'}]
        a=self.send(source,self.body('a',at=old,items=items)).json()['id']
        b=self.send(source,self.body('b',at=old+timedelta(hours=1),items=items[::-1])).json()['id']
        first=self.compare(source,a,b).json();self.assertEqual(first['counts']['unchanged'],2);self.assertEqual(first['items'],[])
        self.send(source,self.body('newer',at=old+timedelta(hours=2),items=[]))
        again=self.compare(source,a,b).json()
        self.assertEqual(first['items'],again['items']);self.assertEqual(first['counts'],again['counts'])
