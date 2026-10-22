"""Isolated additive migration, provenance and authorization regressions."""
import unittest
import os, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
_test_dir = tempfile.TemporaryDirectory(prefix="trace-platform-")
os.environ["TRACE_DATABASE_URL"] = "sqlite:///" + str(Path(_test_dir.name)/"test.db").replace("\\", "/")
os.environ["TRACE_AI_PROVIDER"] = "rules"
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from trace_api.database import Base, get_db
from trace_api.models import Project, Scan, Finding
from trace_api.platform import make_router, PlatformAudit

class PlatformTests(unittest.TestCase):
    def setUp(self):
        self.engine=create_engine("sqlite://",connect_args={"check_same_thread":False},poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        with Session(self.engine) as db:
            db.add(Project(id=77,name="existing"));db.commit()
        self.app=FastAPI();self.app.include_router(make_router(lambda:None))
        def session():
            with Session(self.engine) as db: yield db
        self.app.dependency_overrides[get_db]=session
        self.client=TestClient(self.app)
    def tearDown(self): self.engine.dispose()
    def create(self,key,**extra):
        return self.client.post('/api/v1/platform/assets',json=dict(name=key,externalKey=key,kind='service',**extra))
    def test_links_conflicts_provenance_and_existing_project(self):
        a=self.create('service:a',projectId=77).json();b=self.create('artifact:b').json()
        self.assertEqual(self.create('service:a').status_code,409)
        self.assertEqual(self.create('bad',projectId=999).status_code,404)
        body=dict(sourceId=a['id'],targetId=b['id'],relation='depends_on',evidence='local manifest')
        self.assertEqual(self.client.post('/api/v1/platform/links',json=body).status_code,201)
        self.assertEqual(self.client.post('/api/v1/platform/links',json=body).status_code,409)
        result=self.client.get('/api/v1/platform/assets/'+a['id']).json()
        self.assertEqual(result['links'][0]['evidence'],'local manifest')
        self.assertEqual(len(result['history']),2);self.assertEqual(result['findings'],[])
        with Session(self.engine) as db:
            self.assertEqual(db.get(Project,77).name,'existing')
            self.assertEqual(len(db.scalars(select(PlatformAudit)).all()),3)
        Base.metadata.create_all(self.engine)
        self.assertEqual(len(self.client.get('/api/v1/platform/assets').json()),2)
    def test_validation_and_unknown_assets(self):
        self.assertEqual(self.create('   ').status_code,422)
        a=self.create('a').json()
        for target,expected in [(a['id'],422),('missing',404)]:
            self.assertEqual(self.client.post('/api/v1/platform/links',json=dict(sourceId=a['id'],targetId=target,relation='depends_on',evidence='x')).status_code,expected)
        self.assertEqual(self.client.get('/api/v1/platform/assets/missing').status_code,404)
        self.assertEqual(self.client.get('/api/v1/platform/assets?limit=501').status_code,422)
    def test_guard_applies_to_reads_and_writes(self):
        def deny(): raise HTTPException(401,'denied')
        app=FastAPI();app.include_router(make_router(deny));client=TestClient(app)
        self.assertEqual(client.get('/api/v1/platform/modules').status_code,401)
        self.assertEqual(client.post('/api/v1/platform/assets',json={}).status_code,401)

    def test_project_findings_never_fall_back_to_other_project(self):
        with Session(self.engine) as db:
            db.add(Scan(id='local', project_id=77, repository='test'))
            db.commit()
            db.add(Finding(id='f', scan_id='local', cve='CVE-LOCAL', package_name='test', severity='high', reachability='unknown', verdict='needs_review'))
            db.add(Project(id=78,name='empty'));db.commit()
        a=self.create('with-results',projectId=77).json()
        b=self.create('empty',projectId=78).json()
        result=self.client.get('/api/v1/platform/assets/'+a['id']).json()
        self.assertEqual(result['findings'][0]['id'],'f')
        self.assertFalse(result['scans'][0]['demo'])
        empty=self.client.get('/api/v1/platform/assets/'+b['id']).json()
        self.assertEqual(empty['findings'],[]);self.assertEqual(empty['scans'],[])

    def test_additive_schema_preserves_legacy_rows(self):
        from sqlalchemy import inspect, text
        engine=create_engine('sqlite://')
        with engine.begin() as conn:
            conn.execute(text('CREATE TABLE projects (id INTEGER PRIMARY KEY, name VARCHAR(255), repo_url VARCHAR(512), created_at DATETIME, updated_at DATETIME)'))
            conn.execute(text("INSERT INTO projects(id,name,repo_url) VALUES (1,'legacy','local')"))
        before=[c['name'] for c in inspect(engine).get_columns('projects')]
        Base.metadata.create_all(engine);Base.metadata.create_all(engine)
        self.assertEqual(before,[c['name'] for c in inspect(engine).get_columns('projects')])
        with engine.connect() as conn:
            self.assertEqual(conn.execute(text('SELECT name FROM projects WHERE id=1')).scalar(),'legacy')
        self.assertIn('platform_assets',inspect(engine).get_table_names())
        engine.dispose()
