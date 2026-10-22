"""Workspace/team grants, context propagation, and legacy asset migration."""
import unittest
from unittest.mock import patch
from sqlalchemy import select, delete, update, create_engine, text, event, inspect
from sqlalchemy.orm import Session
from types import SimpleNamespace
import test_access as fixtures
from trace_api import database, main, jobs, services
from trace_api.workspace_models import Workspace, WorkspaceMember, TeamMember, WorkspaceTeam
from trace_api.access_models import Membership
from trace_api.models import Project, Scan, Finding, User
from trace_api.platform import Asset

class WorkspaceTests(unittest.TestCase):
    setUp=fixtures.AccessTests.setUp
    tearDown=fixtures.AccessTests.tearDown
    headers=fixtures.AccessTests.headers
    def h(self,space='default',user='admin'):
        return {**self.headers(user),'X-Trace-Workspace':space}
    def space(self,name):
        response=self.client.post('/api/v1/workspaces',headers=self.h(),json={'name':name})
        self.assertEqual(response.status_code,201,response.text)
        return response.json()['id']
    def uid(self,name):
        with self.factory() as db:return db.scalar(select(User.id).where(User.username==name))
    def grant(self,space,user='analyst',role='analyst',active=True):
        return self.client.put(f'/api/v1/workspaces/{space}/members/{self.uid(user)}',headers=self.h(),json={'role':role,'active':active})
    def project(self,space,name):
        response=self.client.post('/api/v1/projects',headers=self.h(space),json={'name':name,'repoUrl':'local:'+name})
        self.assertEqual(response.status_code,201,response.text)
        return response.json()['id']
    def scan(self,space,project):
        payload={'projectId':project,'repository':'scope:'+space,'files':[{'name':'trivy.json','json':{'Results':[{'Target':'local','Vulnerabilities':[{'VulnerabilityID':'CVE-SCOPE-'+space[:6],'PkgName':'test-lib','InstalledVersion':'1','Severity':'HIGH'}]}]}}]}
        response=self.client.post('/api/v1/scans',headers=self.h(space),json=payload)
        self.assertEqual(response.status_code,201,response.text)
        sid=response.json()['id']
        finding=self.client.get('/api/v1/scans/'+sid+'/findings',headers=self.h(space)).json()[0]
        return sid,finding['id']
    def asset(self,space,key='same:external',project=None):
        response=self.client.post('/api/v1/platform/assets',headers=self.h(space),json={'name':'asset '+space,'kind':'service','externalKey':key,'projectId':project,'workspaceId':'forged'})
        self.assertEqual(response.status_code,201,response.text)
        self.assertEqual(response.json()['workspaceId'],space)
        return response.json()['id']
    def test_direct_grants_discovery_and_role_ceiling(self):
        a=self.space('private-A');b=self.space('private-B')
        self.assertEqual(self.grant(a,role='viewer').status_code,200)
        visible=self.client.get('/api/v1/workspaces',headers=self.h(user='analyst')).json()
        self.assertEqual({w['id'] for w in visible},{'default',a})
        self.assertEqual(self.client.get('/api/v1/projects',headers=self.h(b,'analyst')).status_code,403)
        self.assertEqual(self.client.get('/api/v1/projects',headers=self.h(a,'analyst')).status_code,200)
        self.assertEqual(self.client.post('/api/v1/projects',headers=self.h(a,'analyst'),json={'name':'blocked'}).status_code,403)
        self.assertEqual(self.client.get('/api/v1/auth/me',headers=self.h(a,'analyst')).json()['user']['role'],'viewer')
        self.assertEqual(self.grant(a,'viewer','analyst').status_code,200)
        self.assertEqual(self.client.post('/api/v1/platform/assets',headers=self.h(a,'viewer'),json={}).status_code,403)
        self.assertEqual(self.grant(a,active=False).status_code,200)
        self.assertEqual(self.client.get('/api/v1/projects',headers=self.h(a,'analyst')).status_code,403)
    def test_team_grants_and_revocations_are_effective_on_next_request(self):
        a=self.space('team-space')
        team=self.client.post('/api/v1/teams',headers=self.h(),json={'name':'Platform'}).json()['id']
        uid=self.uid('analyst')
        self.assertEqual(self.client.put(f'/api/v1/teams/{team}/members/{uid}',headers=self.h(),json={'active':True}).status_code,200)
        self.assertEqual(self.client.put(f'/api/v1/workspaces/{a}/teams/{team}',headers=self.h(),json={'role':'analyst','active':True}).status_code,200)
        self.assertEqual(self.client.post('/api/v1/projects',headers=self.h(a,'analyst'),json={'name':'from-team'}).status_code,201)
        self.grant(a,role='viewer')
        self.assertEqual(self.client.put(f'/api/v1/teams/{team}/members/{uid}',headers=self.h(),json={'active':False}).status_code,200)
        self.assertEqual(self.client.get('/api/v1/projects',headers=self.h(a,'analyst')).status_code,200)
        self.assertEqual(self.client.post('/api/v1/projects',headers=self.h(a,'analyst'),json={}).status_code,403)
        self.grant(a,role='viewer',active=False)
        self.assertEqual(self.client.get('/api/v1/projects',headers=self.h(a,'analyst')).status_code,403)
        self.assertEqual(self.client.put(f'/api/v1/workspaces/{a}/teams/{team}',headers=self.h(),json={'role':'analyst','active':False}).status_code,200)
    def test_scoped_ids_lists_and_exports_do_not_cross_workspaces(self):
        a=self.space('A');b=self.space('B');pa=self.project(a,'project-A');pb=self.project(b,'project-B')
        sa,fa=self.scan(a,pa);sb,fb=self.scan(b,pb)
        aa=self.asset(a,project=pa);ab=self.asset(b,project=pb)
        self.assertEqual(len(self.client.get('/api/v1/platform/assets',headers=self.h(a)).json()),1)
        self.assertEqual(self.client.get('/api/v1/health',headers=self.h(a)).json()['scanCount'],1)
        for path in [f'scans/{sb}',f'scans/{sb}/findings',f'scans/{sb}/sbom',f'scans/{sb}/reachability',f'scans/{sb}/compliance',f'scans/{sb}/progress',f'findings/{fb}',f'platform/assets/{ab}',f'vex?scan_id={sb}',f'vex/meta?scan_id={sb}']:
            with self.subTest(path=path):self.assertEqual(self.client.get('/api/v1/'+path,headers=self.h(a)).status_code,404)
        for path in ['projects','scans','advisories','events','platform/assets']:
            body=self.client.get('/api/v1/'+path,headers=self.h(a)).text
            self.assertNotIn('project-B',body);self.assertNotIn(sb,body);self.assertNotIn(ab,body)
        self.assertEqual(self.client.get('/api/v1/scans/active',headers=self.h(a)).json()['id'],sa)
        self.assertEqual(self.client.get('/api/v1/scans/active',headers=self.h()).json()['id'],'scan-8f21a3c')
        self.assertEqual(self.client.post('/api/v1/projects',headers=self.h(a),json={'id':pb}).status_code,404)
        self.assertEqual(self.client.post(f'/api/v1/scans/{sb}/rescan?wait=false',headers=self.h(a)).status_code,404)
        self.assertEqual(self.client.post('/api/v1/platform/links',headers=self.h(a),json={'sourceId':aa,'targetId':ab,'relation':'depends_on','evidence':'forged cross-space'}).status_code,404)
    def test_scope_cannot_be_forged_by_resource_body_or_bulk_update(self):
        a=self.space('scope-A');b=self.space('scope-B');pa=self.project(a,'A');pb=self.project(b,'B')
        self.asset(a,project=pa)
        ab=self.asset(b,project=pb)
        self.assertEqual(self.client.post('/api/v1/platform/assets',headers=self.h(a),json={'name':'bad','kind':'service','externalKey':'bad','projectId':pb}).status_code,404)
        with self.factory() as db:
            db.info['workspace_id']=a
            db.add(Asset(id='bad-ref',name='bad',kind='server',external_key='bad-ref',project_id=pb))
            with self.assertRaises(ValueError):db.commit()
            db.rollback()
            with self.assertRaises(ValueError):db.execute(update(Asset).values(workspace_id=b))
            db.rollback()
            db.execute(delete(Asset));db.commit()
        self.assertEqual(self.client.get('/api/v1/platform/assets/'+ab,headers=self.h(b)).status_code,200)
        self.assertEqual(self.client.get('/api/v1/platform/assets',headers=self.h(a)).json(),[])
    def test_same_external_key_is_unique_only_inside_its_workspace(self):
        a=self.space('first');b=self.space('second')
        self.asset(a);self.asset(b)
        self.assertEqual(self.client.post('/api/v1/platform/assets',headers=self.h(a),json={'name':'duplicate','kind':'service','externalKey':'same:external'}).status_code,409)
    def test_services_are_bound_to_one_workspace_and_import_requires_local_project(self):
        a=self.space('service-A');b=self.space('service-B');pa=self.project(a,'A');pb=self.project(b,'B')
        result=self.client.post('/api/v1/access/service-accounts',headers=self.h(a),json={'name':'CI A','scopes':['inventory:read','scans:import']}).json()
        token={'Authorization':'Bearer '+result['token']}
        aid=result['account']['id']
        self.assertEqual(self.client.get('/api/v1/access/service-accounts',headers=self.h(b)).json(),[])
        self.assertEqual(self.client.post('/api/v1/access/service-accounts/'+aid+'/revoke',headers=self.h(b)).status_code,404)
        self.assertEqual(result['account']['workspaceId'],a)
        self.assertEqual(self.client.get('/api/v1/platform/assets',headers={**token,'X-Trace-Workspace':a}).status_code,200)
        self.assertEqual(self.client.get('/api/v1/platform/assets',headers=token).status_code,403)
        self.assertEqual(self.client.get('/api/v1/platform/assets',headers={**token,'X-Trace-Workspace':b}).status_code,403)
        payload={'projectId':pb,'files':[{'name':'trivy.json','json':{'Results':[]}}]}
        self.assertEqual(self.client.post('/api/v1/scans',headers={**token,'X-Trace-Workspace':a},json=payload).status_code,404)
        payload['projectId']=pa
        self.assertEqual(self.client.post('/api/v1/scans',headers={**token,'X-Trace-Workspace':a},json=payload).status_code,201)
    def test_jobs_and_worker_restore_scope_and_validate_project_before_scanning(self):
        a=self.space('job-A');b=self.space('job-B');pa=self.project(a,'A');pb=self.project(b,'B')
        with patch.object(jobs,'queue_mode',return_value='in-process'),patch('trace_api.job_store.threading.Thread'):
            jid=jobs.submit_scan(source='local-test',project_id=pa,_workspace_id=a,_actor='user:admin')['jobId']
        try:
            self.assertEqual(self.client.get('/api/v1/jobs/'+jid,headers=self.h(a)).status_code,200)
            self.assertEqual(self.client.get('/api/v1/jobs/'+jid,headers=self.h(b)).status_code,404)
            self.assertEqual(self.client.get('/api/v1/jobs',headers=self.h()).json(),[])
            observed=[]
            def fake(db,**params):
                observed.append((db.info['workspace_id'],params));return SimpleNamespace(id='job-result',status='completed'),{},[]
            with patch.object(jobs,'SessionLocal',self.factory),patch.object(services,'scan_source',side_effect=fake):
                result=jobs._run_pipeline(jid,{'source':'local-test','project_id':pa,'_workspace_id':a,'_actor':'user:admin','_user_id':self.uid('admin')})
                denied=jobs._run_pipeline(jid,{'source':'local-test','project_id':pb,'_workspace_id':a,'_actor':'user:admin','_user_id':self.uid('admin')})
                jobs._run_pipeline(jid,{'source':'local-test','project_id':pa,'_workspace_id':a,'_actor':'user:admin','_user_id':self.uid('admin')})
            self.assertEqual(result['status'],'completed');self.assertEqual(denied['status'],'failed')
            self.assertEqual(observed,[(a,{'source':'local-test','project_id':pa}),(a,{'source':'local-test','project_id':pa})])
        finally:
            pass
    def test_worker_rechecks_revoked_and_downgraded_permissions(self):
        space=self.space('queued-permissions')
        self.grant(space)
        with self.factory() as db:
            member=db.scalar(select(Membership).where(Membership.user_id==self.uid('analyst')))
            member.role='admin';db.commit()
        params={'source':'local-fixture','_workspace_id':space,'_actor':'user:analyst','_user_id':self.uid('analyst')}
        with patch.object(jobs,'SessionLocal',self.factory), patch.object(services,'scan_source',return_value=(SimpleNamespace(id='fixture',status='completed'),{},[])) as scanner:
            self.assertEqual(jobs._run_pipeline('permission-test',params)['status'],'completed')
            with self.factory() as db:
                member=db.scalar(select(Membership).where(Membership.user_id==self.uid('analyst')))
                member.role='analyst';db.commit()
            self.grant(space,role='viewer')
            self.assertEqual(jobs._run_pipeline('permission-test',params)['status'],'failed')
            self.grant(space,active=False)
            self.assertEqual(jobs._run_pipeline('permission-test',params)['status'],'failed')
            self.grant(space)
            with self.factory() as db:
                user=db.get(User,self.uid('analyst'));user.is_active=False;db.commit()
            self.assertEqual(jobs._run_pipeline('permission-test',params)['status'],'failed')
            self.assertEqual(scanner.call_count,1)
            self.assertEqual(jobs._run_pipeline('denied-fixture',params)['status'],'failed')
            self.assertEqual(scanner.call_count,1)


    def test_async_rescan_rechecks_author_before_pipeline(self):
        uid=self.uid('analyst')
        with patch('trace_api.job_store.dispatch_one'):
            response=self.client.post('/api/v1/scans/scan-8f21a3c/rescan?wait=false',headers=self.h(user='analyst'))
        self.assertEqual(response.status_code,200,response.text)
        with patch.object(services,'rescan') as pipeline:
            with self.factory() as db:
                user=db.get(User,uid);user.is_active=False;db.commit()
            self.assertEqual(jobs.run_scan_job(response.json()['jobId'])['status'],'failed')
            pipeline.assert_not_called()
            progress=self.client.get('/api/v1/scans/scan-8f21a3c/progress',headers=self.h()).json()
            self.assertEqual(progress['phase'],'error')
            self.assertFalse(progress['active'])

    def test_worker_rejects_missing_identity_and_revoked_membership(self):
        from trace_api import config
        with self.factory() as db:
            uid=self.uid('analyst')
            member=db.scalar(select(Membership).where(Membership.user_id==uid))
            member.is_active=False;db.commit()
        with self.factory() as db:
            db.info['workspace_id']='default'
            with self.assertRaises(PermissionError): jobs.authorize_execution(db,'user:analyst',uid)
            with self.assertRaises(PermissionError): jobs.authorize_execution(db,'user:admin')
            with self.assertRaises(PermissionError): jobs.authorize_execution(db,'local-operator')
            with patch.object(config,'AUTH_ENABLED',False),patch.object(config,'ADMIN_TOKEN',''):
                jobs.authorize_execution(db,'local-operator')
                with self.assertRaises(PermissionError): jobs.authorize_execution(db,'system:worker')
            with patch.object(config,'AUTH_ENABLED',False),patch.object(config,'ADMIN_TOKEN','fixture-only'):
                jobs.authorize_execution(db,'static-admin')
                with self.assertRaises(PermissionError): jobs.authorize_execution(db,'local-operator')

    def test_admin_boundaries_and_invalid_grant_targets(self):
        a=self.space('admin-only')
        for path in ['workspaces','teams']:
            self.assertEqual(self.client.post('/api/v1/'+path,headers=self.h(user='analyst'),json={'name':'no'}).status_code,403)
        self.assertEqual(self.client.get('/api/v1/teams',headers=self.h(user='viewer')).status_code,403)
        self.assertEqual(self.client.put(f'/api/v1/workspaces/{a}/members/{self.uid("analyst")}',headers=self.h(user='analyst'),json={'role':'analyst'}).status_code,403)
        self.assertEqual(self.client.put(f'/api/v1/workspaces/{a}/members/9999',headers=self.h(),json={'role':'viewer'}).status_code,404)
        self.assertEqual(self.client.post('/api/v1/workspaces',headers=self.h(),json={'name':'admin-only'}).status_code,409)
        self.assertEqual(self.client.post('/api/v1/workspaces',headers=self.h(),json={'name':'   '}).status_code,422)
        self.assertEqual(self.client.get('/api/v1/projects',headers=self.h('absent')).status_code,403)
        self.assertEqual(self.client.get('/api/v1/projects',headers={**self.h(a),'X-Trace-Organization':'other'}).status_code,403)
    def test_inactive_members_can_still_have_their_old_grants_revoked(self):
        a=self.space('cleanup')
        team=self.client.post('/api/v1/teams',headers=self.h(),json={'name':'cleanup-team'}).json()['id']
        uid=self.uid('analyst')
        self.grant(a)
        self.client.put(f'/api/v1/teams/{team}/members/{uid}',headers=self.h(),json={'active':True})
        member=next(m for m in self.client.get('/api/v1/access/members',headers=self.h()).json() if m['userId']==uid)
        self.client.put('/api/v1/access/members/'+str(member['id']),headers=self.h(),json={'role':'analyst','active':False})
        self.assertEqual(self.grant(a,active=False).status_code,200)
        self.assertEqual(self.client.put(f'/api/v1/teams/{team}/members/{uid}',headers=self.h(),json={'active':False}).status_code,200)

    def test_grants_migration_does_not_restore_revoked_permissions(self):
        from trace_api.workspaces import ensure_legacy_workspace_grants
        with self.factory() as db:
            grant=db.scalar(select(WorkspaceMember).where(WorkspaceMember.user_id==self.uid('analyst'),WorkspaceMember.workspace_id=='default'))
            grant.active=False;db.commit();ensure_legacy_workspace_grants(db)
        self.assertEqual(self.client.get('/api/v1/projects',headers=self.h(user='analyst')).status_code,403)
        self.assertEqual(self.client.get('/api/v1/workspaces',headers=self.h(user='analyst')).status_code,200)

class AssetMigrationTests(unittest.TestCase):
    def make_legacy(self):
        engine=create_engine('sqlite://')
        @event.listens_for(engine,'connect')
        def enable(dbapi,record):dbapi.execute('PRAGMA foreign_keys=ON')
        with engine.begin() as conn:
            conn.exec_driver_sql('CREATE TABLE projects (id INTEGER PRIMARY KEY,name VARCHAR(255),repo_url VARCHAR(512),created_at DATETIME,updated_at DATETIME)')
            conn.exec_driver_sql("INSERT INTO projects(id,name,repo_url) VALUES(1,'legacy','local')")
            conn.exec_driver_sql("CREATE TABLE platform_assets (id VARCHAR(64) PRIMARY KEY,name VARCHAR(255),kind VARCHAR(32),external_key VARCHAR(512),owner VARCHAR(128),project_id INTEGER REFERENCES projects(id),source VARCHAR(32),organization_id VARCHAR(64) DEFAULT 'default',custom_value TEXT, UNIQUE (external_key))")
            conn.exec_driver_sql("INSERT INTO platform_assets VALUES('old-a','A','service','key:a','team',1,'manual','default','keep-a')")
            conn.exec_driver_sql("INSERT INTO platform_assets VALUES('old-b','B','service','key:b','team',1,'manual','default','keep-b')")
            conn.exec_driver_sql('CREATE TABLE platform_asset_links (id VARCHAR(64) PRIMARY KEY,source_id VARCHAR(64) REFERENCES platform_assets(id),target_id VARCHAR(64) REFERENCES platform_assets(id),relation VARCHAR(32),evidence TEXT)')
            conn.exec_driver_sql("INSERT INTO platform_asset_links VALUES('old-link','old-a','old-b','depends_on','manifest')")
            conn.exec_driver_sql('CREATE INDEX asset_owner_search ON platform_assets(owner)')
            conn.exec_driver_sql('CREATE TABLE asset_changes (asset_id TEXT)')
            conn.exec_driver_sql('CREATE TRIGGER preserve_asset_changes AFTER UPDATE ON platform_assets BEGIN INSERT INTO asset_changes VALUES(NEW.id); END')
        return engine
    def test_legacy_rebuild_preserves_ids_links_extensions_and_foreign_keys(self):
        engine=self.make_legacy()
        from sqlalchemy.orm import sessionmaker
        factory=sessionmaker(bind=engine,class_=database.OrganizationSession)
        with patch.object(database,'engine',engine),patch.object(database,'SessionLocal',factory):
            database.init_db();database.init_db()
        with engine.begin() as conn:
            self.assertEqual(conn.exec_driver_sql('PRAGMA foreign_keys').scalar(),1)
            self.assertEqual(conn.exec_driver_sql("SELECT custom_value,workspace_id FROM platform_assets WHERE id='old-a'").one(),('keep-a','default'))
            self.assertEqual(conn.exec_driver_sql('SELECT source_id,target_id,evidence FROM platform_asset_links').one(),('old-a','old-b','manifest'))
            conn.exec_driver_sql("INSERT INTO workspaces(id,organization_id,name) VALUES('b','default','B')")
            conn.exec_driver_sql("INSERT INTO platform_assets(id,name,kind,external_key,workspace_id) VALUES('new-b','B','service','key:a','b')")
            conn.exec_driver_sql("UPDATE platform_assets SET owner='new' WHERE id='old-a'")
            self.assertEqual(conn.exec_driver_sql('SELECT asset_id FROM asset_changes').scalar(),'old-a')
            self.assertEqual(conn.exec_driver_sql('PRAGMA foreign_key_check').all(),[])
        self.assertIn('asset_owner_search',{i['name'] for i in inspect(engine).get_indexes('platform_assets')})
        engine.dispose()
    def test_failed_rebuild_rolls_back_without_losing_original_assets(self):
        engine=self.make_legacy()
        with patch.object(database,'engine',engine):database._migrate()
        from trace_api.workspace_migrations import migrate_asset_identity
        def fail(conn,cursor,statement,params,context,many):
            if statement.startswith('ALTER TABLE platform_assets_workspace_migration RENAME'):
                raise RuntimeError('injected migration failure')
        event.listen(engine,'before_cursor_execute',fail)
        with self.assertRaises(RuntimeError):migrate_asset_identity(engine)
        event.remove(engine,'before_cursor_execute',fail)
        with engine.connect() as conn:
            self.assertEqual(conn.exec_driver_sql('SELECT count(*) FROM platform_assets').scalar(),2)
            self.assertEqual(conn.exec_driver_sql('SELECT count(*) FROM platform_asset_links').scalar(),1)
            self.assertEqual(conn.exec_driver_sql('PRAGMA foreign_keys').scalar(),1)
        self.assertNotIn('platform_assets_workspace_migration',inspect(engine).get_table_names())
        engine.dispose()
