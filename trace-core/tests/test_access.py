"""Authorization contract tests against real API, middleware and isolated databases."""
import os
import sys
import tempfile
import unittest
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
_suite_dir = tempfile.TemporaryDirectory(prefix="trace-access-suite-")
os.environ['TRACE_DATABASE_URL'] = 'sqlite:///' + str(Path(_suite_dir.name)/'suite.db').replace('\\','/')
os.environ['TRACE_AI_PROVIDER'] = 'rules'
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session, sessionmaker
from trace_api import access, config, database, rbac
from trace_api import main
from trace_api.database import Base, OrganizationSession
from trace_api.access_models import AuthSession, Membership, Organization, ServiceAccount
from trace_api.models import Project, Scan, Finding, TriageEvent, User
from trace_api.platform import Asset, PlatformAudit
from trace_api.workspace_models import WorkspaceMember

class AccessTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='trace-access-')
        self.engine=create_engine('sqlite:///'+str(Path(self.temp.name)/'test.db').replace('\\','/'),connect_args={'check_same_thread':False})
        self.factory=sessionmaker(bind=self.engine,class_=OrganizationSession,autoflush=False)
        self.stack=ExitStack()
        from trace_api import job_dispatcher
        self.stack.enter_context(patch.object(job_dispatcher,'ENABLED',False))
        from trace_api import jobs
        for module in (database,access,rbac,main,jobs):
            self.stack.enter_context(patch.object(module,'SessionLocal',self.factory))
        self.stack.enter_context(patch.object(database,'engine',self.engine))
        self.stack.enter_context(patch.object(config,'AUTH_ENABLED',True))
        self.stack.enter_context(patch.object(main,'AUTH_ENABLED',True))
        self.stack.enter_context(patch.object(rbac,'AUTH_ENABLED',False))
        self.stack.enter_context(patch.object(config,'ADMIN_TOKEN',''))
        self.stack.enter_context(patch.object(config,'TRACE_ADMIN_PASSWORD',''))
        self.client=self.stack.enter_context(TestClient(main.app))
        self.tokens={}
        with self.factory() as db:
            for name,role in [('admin','admin'),('analyst','analyst'),('viewer','viewer')]:
                u=User(username=name,password_hash=rbac.hash_password('test-password-only'),role='user')
                db.add(u);db.flush()
                db.add(Membership(organization_id='default',user_id=u.id,role=role,is_active=True))
                db.add(WorkspaceMember(organization_id='default',workspace_id='default',user_id=u.id,role='viewer' if role=='viewer' else 'analyst',active=True))
            db.commit()
        for name in ['admin','analyst','viewer']:
            self.tokens[name]=rbac.issue_token(name)
    def tearDown(self):
        self.stack.close();self.engine.dispose();self.temp.cleanup()
    def headers(self,name='admin'):
        return {'Authorization':'Bearer '+self.tokens[name]}
    def test_all_data_routes_require_authentication(self):
        paths=['health','projects','scans','events','advisories','jobs','integrations','ai/settings','settings/policy','platform/assets','platform/modules','access/context','vex','vex/meta']
        paths += ['scans/scan-8f21a3c/'+suffix for suffix in ['findings','sbom','reachability','compliance','funnel','policy','progress']]
        for path in paths:
            with self.subTest(path=path):
                self.assertEqual(self.client.get('/api/v1/'+path).status_code,401)
        for path in ['projects','scans','findings/FND-8F21A3/review','findings/batch-review','scans/scan-8f21a3c/rescan']:
            self.assertEqual(self.client.post('/api/v1/'+path,json={}).status_code,401)
    def test_viewer_is_read_only_including_legacy_and_exports(self):
        h=self.headers('viewer')
        for path in ['projects','scans','events','vex?scan_id=scan-8f21a3c','scans/scan-8f21a3c/sbom','scans/scan-8f21a3c/compliance?download=true','platform/assets','access/context']:
            self.assertEqual(self.client.get('/api/v1/'+path,headers=h).status_code,200,path)
        for method,path in [('POST','projects'),('POST','findings/FND-8F21A3/review'),('POST','findings/batch-review'),('POST','scans/scan-8f21a3c/rescan'),('DELETE','scans/scan-8f21a3c'),('PUT','findings/FND-8F21A3/workflow'),('POST','platform/assets')]:
            self.assertEqual(self.client.request(method,'/api/v1/'+path,json={},headers=h).status_code,403,path)
        self.assertEqual(self.client.get('/api/v1/access/service-accounts',headers=h).status_code,403)
        with patch.object(main,'registry',return_value={'integrations':[{'id':'test','label':'Test','detail':'sensitive-internal-url','available':True}]}):
            public=self.client.get('/api/v1/integrations',headers=h)
            self.assertEqual(public.status_code,200)
            self.assertNotIn('sensitive-internal-url',public.text)
    def test_analyst_and_audit_actor_cannot_be_spoofed(self):
        h=self.headers('analyst')
        a=self.client.post('/api/v1/platform/assets',headers=h,json={'name':'asset','kind':'service','externalKey':'local:asset','actor':'admin','organization_id':'other'})
        self.assertEqual(a.status_code,201)
        self.assertEqual(self.client.post('/api/v1/findings/FND-8F21A3/review',headers=h,json={'actor':'admin'}).status_code,200)
        self.assertEqual(self.client.put('/api/v1/findings/FND-8F21A3/workflow',headers=h,json={'status':'in_progress'}).status_code,200)
        self.assertEqual(self.client.put('/api/v1/settings/policy',headers=h,json={}).status_code,403)
        self.assertEqual(self.client.delete('/api/v1/projects/99',headers=h).status_code,403)
        with self.factory() as db:
            self.assertEqual(db.scalar(select(PlatformAudit).where(PlatformAudit.object_id==a.json()['id'])).actor,'user:analyst')
            self.assertTrue(all(e.actor=='user:analyst' for e in db.scalars(select(TriageEvent).where(TriageEvent.action.in_(['review','workflow'])))))
            self.assertEqual(db.get(Asset,a.json()['id']).organization_id,'default')
    def test_service_scope_expiry_revocation_and_no_secret_echo(self):
        result=self.client.post('/api/v1/access/service-accounts',headers=self.headers(),json={'name':'inventory reader','scopes':['inventory:read'],'expiresInDays':1})
        self.assertEqual(result.status_code,201)
        data=result.json();token=data['token'];h={'Authorization':'Bearer '+token}
        self.assertEqual(self.client.get('/api/v1/platform/assets',headers=h).status_code,200)
        self.assertEqual(self.client.post('/api/v1/platform/assets',headers=h,json={}).status_code,403)
        self.assertEqual(self.client.get('/api/v1/scans',headers=h).status_code,403)
        self.assertEqual(self.client.get('/api/v1/access/service-accounts',headers=h).status_code,403)
        public=self.client.get('/api/v1/access/service-accounts',headers=self.headers()).text
        self.assertNotIn(token,public);self.assertNotIn('token_hash',public)
        with self.factory() as db:
            account=db.get(ServiceAccount,data['account']['id'])
            self.assertNotEqual(account.token_hash,token)
            account.expires_at=datetime.now(timezone.utc)-timedelta(seconds=1);db.commit()
        self.assertEqual(self.client.get('/api/v1/platform/assets',headers=h).status_code,401)
        self.assertEqual(self.client.post('/api/v1/access/service-accounts/'+data['account']['id']+'/revoke',headers=self.headers()).status_code,200)
        with self.factory() as db:
            self.assertTrue(db.get(ServiceAccount,data['account']['id']).revoked)
    def test_service_inventory_cannot_read_project_findings_through_asset(self):
        a=self.client.post('/api/v1/platform/assets',headers=self.headers(),json={'name':'repository','kind':'repository','externalKey':'repo:demo','projectId':1}).json()
        result=self.client.post('/api/v1/access/service-accounts',headers=self.headers(),json={'name':'inventory','scopes':['inventory:read']}).json()
        h={'Authorization':'Bearer '+result['token']}
        detail=self.client.get('/api/v1/platform/assets/'+a['id'],headers=h).json()
        self.assertEqual(detail['scans'],[]);self.assertEqual(detail['findings'],[])
        self.assertEqual(self.client.post('/api/v1/access/service-accounts/'+result['account']['id']+'/revoke',headers=self.headers()).status_code,200)
        self.assertEqual(self.client.get('/api/v1/platform/assets',headers=h).status_code,401)

    def test_service_import_is_explicit_and_cannot_run_source_scanners(self):
        result=self.client.post('/api/v1/access/service-accounts',headers=self.headers(),json={'name':'CI import','scopes':['scans:import','scans:read']}).json()
        h={'Authorization':'Bearer '+result['token']}
        payload={'projectId':1,'repository':'local-test','files':[{'name':'trivy.json','json':{'Results':[]}}]}
        response=self.client.post('/api/v1/scans',headers=h,json=payload)
        self.assertEqual(response.status_code,201,response.text)
        self.assertEqual(response.json()['triggeredBy'],'service:'+result['account']['id'])
        payload.pop('projectId')
        self.assertEqual(self.client.post('/api/v1/scans',headers=h,json=payload).status_code,422)
        self.assertEqual(self.client.post('/api/v1/scans/from-source',headers=h,json={'source':'C:/any'}).status_code,403)

    def test_login_returns_membership_role_and_disabling_user_revokes_access(self):
        response=self.client.post('/api/v1/auth/login',json={'username':'viewer','password':'test-password-only'})
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json()['user']['role'],'viewer')
        self.assertEqual(response.headers.get('cache-control'),'no-store')
        with self.factory() as db:
            user=db.scalar(select(User).where(User.username=='viewer'));user.is_active=False;db.commit()
        self.assertEqual(self.client.get('/api/v1/projects',headers=self.headers('viewer')).status_code,401)

    def test_static_mode_protects_reads_and_local_mode_cannot_issue_tokens(self):
        with patch.object(config,'AUTH_ENABLED',False),patch.object(config,'ADMIN_TOKEN','local-static-test'):
            self.assertEqual(self.client.get('/api/v1/projects').status_code,401)
            self.assertEqual(self.client.get('/api/v1/projects',headers={'X-Admin-Token':'local-static-test'}).status_code,200)
        with patch.object(config,'AUTH_ENABLED',False),patch.object(config,'ADMIN_TOKEN',''):
            self.assertEqual(self.client.get('/api/v1/projects').status_code,200)
            self.assertEqual(self.client.post('/api/v1/access/service-accounts',json={'name':'not allowed','scopes':['inventory:read']}).status_code,409)
            self.assertEqual(self.client.get('/api/v1/projects',headers={'X-Trace-Organization':'other'}).status_code,403)

    def test_tokens_survive_new_session_but_expire_and_logout_revokes(self):
        h=self.headers('viewer')
        self.assertEqual(self.client.get('/api/v1/projects',headers=h).status_code,200)
        with self.factory() as db:
            session=db.scalar(select(AuthSession).join(User,User.id==AuthSession.user_id).where(User.username=='viewer'))
            self.assertNotEqual(session.token_hash,self.tokens['viewer'])
            session.expires_at=datetime.now(timezone.utc)-timedelta(seconds=1);db.commit()
        self.assertEqual(self.client.get('/api/v1/projects',headers=h).status_code,401)
        h=self.headers('analyst')
        self.assertEqual(self.client.post('/api/v1/auth/logout',headers=h).status_code,200)
        self.assertEqual(self.client.get('/api/v1/projects',headers=h).status_code,401)
    def test_membership_revocation_is_immediate_and_last_admin_is_protected(self):
        with self.factory() as db:
            admin=db.scalar(select(Membership).join(User).where(User.username=='admin'))
            viewer=db.scalar(select(Membership).join(User).where(User.username=='viewer'))
            admin_id,viewer_id=admin.id,viewer.id
        path='/api/v1/access/members/'
        self.assertEqual(self.client.put(path+str(admin_id),headers=self.headers(),json={'role':'viewer','active':True}).status_code,409)
        self.assertEqual(self.client.put(path+str(viewer_id),headers=self.headers(),json={'role':'viewer','active':False}).status_code,200)
        self.assertEqual(self.client.get('/api/v1/projects',headers=self.headers('viewer')).status_code,403)
        with self.factory() as db:
            access.ensure_default_identity(db)
            self.assertFalse(db.get(Membership,viewer_id).is_active)
    def test_foreign_ownership_and_organization_header_are_denied(self):
        with Session(self.engine) as db:
            db.add(Project(id=99,name='FOREIGN-SECRET',organization_id='other'))
            db.add(Scan(id='foreign',project_id=99,repository='FOREIGN-SECRET',organization_id='other'))
            db.add(Finding(id='foreign-f',scan_id='foreign',cve='CVE-FOREIGN',package_name='foreign',severity='high',reachability='unknown',verdict='needs_review',organization_id='other'))
            db.add(Asset(id='foreign-a',name='FOREIGN-SECRET',kind='server',external_key='foreign:a',organization_id='other'))
            db.commit()
        h=self.headers()
        for path in ['projects','scans','advisories','events','platform/assets','vex']:
            response=self.client.get('/api/v1/'+path,headers=h)
            self.assertNotIn('FOREIGN',response.text)
        for path in ['scans/foreign','findings/foreign-f','scans/foreign/sbom','scans/foreign/progress','platform/assets/foreign-a','vex?scan_id=foreign']:
            self.assertEqual(self.client.get('/api/v1/'+path,headers=h).status_code,404,path)
        self.assertEqual(self.client.post('/api/v1/projects',headers=h,json={'id':99,'name':'hijack'}).status_code,404)
        self.assertEqual(self.client.get('/api/v1/projects',headers={**h,'X-Trace-Organization':'other'}).status_code,403)
        with self.factory() as db:
            db.add(Asset(id='bad',name='bad',kind='service',external_key='bad',project_id=99))
            with self.assertRaises(ValueError):db.commit()
            db.rollback()
    def test_missing_scan_never_creates_demo_or_starts_background_work(self):
        h=self.headers('analyst')
        with self.factory() as db:
            db.add(Project(id=78,name='empty'));db.commit()
        self.assertEqual(self.client.get('/api/v1/scans/active?project_id=78',headers=h).status_code,404)
        with patch.object(main.jobs,'submit_rescan') as thread:
            self.assertEqual(self.client.post('/api/v1/scans/absent/rescan?wait=false',headers=h).status_code,404)
            thread.assert_not_called()
    def test_legacy_migration_preserves_data_and_marks_old_audit_unknown(self):
        legacy=create_engine('sqlite://')
        with legacy.begin() as conn:
            conn.execute(text('CREATE TABLE projects (id INTEGER PRIMARY KEY,name VARCHAR(255),repo_url VARCHAR(512),created_at DATETIME,updated_at DATETIME)'))
            conn.execute(text("INSERT INTO projects(id,name,repo_url) VALUES(42,'legacy','local')"))
            conn.execute(text('CREATE TABLE platform_audit (id VARCHAR(64) PRIMARY KEY,action VARCHAR(32),object_id VARCHAR(64),detail TEXT,occurred_at VARCHAR(64))'))
            conn.execute(text("INSERT INTO platform_audit VALUES('old','asset.created','a','old record','2026-01-01')"))
        with patch.object(database,'engine',legacy):
            database.init_db();database.init_db()
        with legacy.connect() as conn:
            self.assertEqual(conn.execute(text('SELECT name,organization_id FROM projects WHERE id=42')).one(),('legacy','default'))
            self.assertEqual(conn.execute(text("SELECT actor FROM platform_audit WHERE id='old'")).scalar(),'legacy-unattributed')
        legacy.dispose()

    def test_fresh_bootstrap_membership_is_created_once(self):
        isolated=create_engine('sqlite://')
        Base.metadata.create_all(isolated)
        with Session(isolated,autoflush=False) as db:
            user=User(username='bootstrap',role='admin',password_hash='test')
            db.add(user);db.commit()
            with patch.object(config,'TRACE_ADMIN_PASSWORD','test-bootstrap-only'),patch.object(config,'TRACE_ADMIN_USERNAME','bootstrap'):
                access.ensure_default_identity(db);access.ensure_default_identity(db)
                members=db.scalars(select(Membership)).all()
                self.assertEqual(len(members),1)
                members[0].is_active=False;db.commit()
                access.ensure_default_identity(db)
                self.assertFalse(db.get(Membership,members[0].id).is_active)
        isolated.dispose()

    def test_local_user_provisioning_does_not_overwrite_existing_account(self):
        import io
        from contextlib import redirect_stderr, redirect_stdout
        from trace_api import manage_user
        password='isolated-cli-password'
        args=['trace_api.manage_user','provisioned','--role','viewer']
        with patch.object(manage_user,'SessionLocal',self.factory),patch.object(manage_user,'init_db',lambda:None),patch.object(sys,'argv',args),patch.object(manage_user.getpass,'getpass',side_effect=[password,password]),redirect_stdout(io.StringIO()):
            manage_user.main()
        with self.factory() as db:
            user=db.scalar(select(User).where(User.username=='provisioned'))
            original_hash=user.password_hash
            self.assertTrue(rbac.verify_password(password,original_hash))
            self.assertEqual(db.scalar(select(Membership).where(Membership.user_id==user.id)).role,'viewer')
        with patch.object(manage_user,'SessionLocal',self.factory),patch.object(manage_user,'init_db',lambda:None),patch.object(sys,'argv',args),patch.object(manage_user.getpass,'getpass',side_effect=[password,password]),redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):manage_user.main()
        with self.factory() as db:
            self.assertEqual(db.scalar(select(User).where(User.username=='provisioned')).password_hash,original_hash)

    def test_background_paths_keep_authenticated_actor_without_passing_internal_params(self):
        from types import SimpleNamespace
        from trace_api import jobs, services
        observed=[]
        def fake_scan(db, **params):
            observed.append((db.info.get('actor'),params))
            return SimpleNamespace(id='isolated-job-scan',status='partial'),{},[]
        with self.factory() as db:
            uid=db.scalar(select(User.id).where(User.username=='admin'))
        with patch.object(jobs,'SessionLocal',self.factory),patch.object(services,'scan_source',side_effect=fake_scan):
            jobs._run_pipeline('test-access-actor',{'source':'local-test','_actor':'user:admin','_user_id':uid})
            result=jobs._run_pipeline('test-access-celery',{'source':'local-test','_actor':'service:test'})
        self.assertEqual(result['status'],'failed')
        self.assertEqual(observed,[('user:admin',{'source':'local-test'})])

    def test_concurrent_demotions_preserve_one_active_administrator(self):
        from concurrent.futures import ThreadPoolExecutor
        with self.factory() as db:
            members={u.username:m for m,u in db.execute(select(Membership,User).join(User,User.id==Membership.user_id)).all()}
            members['analyst'].role='admin';db.commit()
            ids={name:members[name].id for name in ['admin','analyst']}
        def demote(name):
            return self.client.put('/api/v1/access/members/'+str(ids[name]),headers=self.headers(name),json={'role':'viewer','active':True}).status_code
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(demote,['admin','analyst']))
        self.assertEqual(sorted(results),[200,409])
        with self.factory() as db:
            self.assertEqual(len(db.scalars(select(Membership).where(Membership.role=='admin',Membership.is_active.is_(True))).all()),1)
