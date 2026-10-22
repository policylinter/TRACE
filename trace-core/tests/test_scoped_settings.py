import os
import unittest
from unittest.mock import patch
from sqlalchemy import select
import test_access as fixtures
from trace_api import settings
from trace_api.scoped_settings import WorkspaceSetting, environment_name
from trace_api.workspace_models import Workspace
from trace_api.models import AppSetting
from trace_api.platform import PlatformAudit

class ScopedSettingsTests(unittest.TestCase):
    setUp=fixtures.AccessTests.setUp
    tearDown=fixtures.AccessTests.tearDown
    headers=fixtures.AccessTests.headers

    def other(self):
        with self.factory() as db:
            db.add(Workspace(id='second',organization_id='default',name='Second'));db.commit()

    def test_legacy_is_default_only_and_writes_are_scoped(self):
        self.other()
        with self.factory() as db:
            db.add(AppSetting(key='ai',value={'provider':'openai','api_key':'legacy-fixture-secret','models':['legacy']}));db.commit()
            self.assertEqual(settings.get_ai_settings(db)['api_key'],'legacy-fixture-secret')
            settings.set_ai_settings(db,{'analystContext':'default context'})
            self.assertNotIn('legacy-fixture-secret',str(db.scalar(select(WorkspaceSetting)).value))
        with self.factory() as db:
            db.info['workspace_id']='second'
            data=settings.get_ai_settings(db)
            self.assertEqual(data['provider'],'rules');self.assertEqual(data['api_key'],'')
            settings.set_ai_settings(db,{'analystContext':'second context','provider':'rules'})
            settings.set_policy_settings(db,{'name':'Second policy'})
        with self.factory() as db:
            self.assertEqual(settings.get_ai_settings(db)['analyst_context'],'default context')
            self.assertNotEqual(settings.get_policy_settings(db)['name'],'Second policy')

    def test_reference_is_workspace_bound_and_never_persisted_or_returned(self):
        self.other()
        with self.factory() as db:
            name=environment_name(db,'env:AI_KEY')
            with patch.dict(os.environ,{name:'test-resolved-value'}):
                settings.set_ai_settings(db,{'secretRef':'env:AI_KEY'})
                self.assertEqual(settings.get_ai_settings(db)['api_key'],'test-resolved-value')
                public=settings.public_ai_settings(db)
                self.assertTrue(public['secretRefReady'])
                self.assertNotIn('test-resolved-value',str(public))
                self.assertNotIn('test-resolved-value',str(db.scalar(select(WorkspaceSetting)).value))
                self.assertNotIn('test-resolved-value',str([a.detail for a in db.scalars(select(PlatformAudit))]))
                with self.factory() as other:
                    other.info['workspace_id']='second'
                    settings.set_ai_settings(other,{'secretRef':'env:AI_KEY'})
                    self.assertNotEqual(environment_name(other,'env:AI_KEY'),name)
                    self.assertEqual(settings.get_ai_settings(other)['api_key'],'')

    def test_invalid_references_and_inline_keys_rejected_without_changes(self):
        for body in ({'apiKey':'raw-test-key'},{'secretRef':'env:PATH'+'/'},{'secretRef':'file:/tmp/key'},{'secretRef':123}):
            response=self.client.put('/api/v1/ai/settings',headers=self.headers(),json=body)
            self.assertEqual(response.status_code,422,response.text)
        with self.factory() as db:self.assertIsNone(db.scalar(select(WorkspaceSetting)))

    def test_audit_failure_rolls_back_settings(self):
        with self.factory() as db:
            with patch('trace_api.platform.audit',side_effect=RuntimeError('test')):
                with self.assertRaises(RuntimeError):settings.set_policy_settings(db,{'name':'not committed'})
        with self.factory() as db:self.assertIsNone(db.scalar(select(WorkspaceSetting)))

    def test_non_admin_cannot_write_and_foreign_row_is_rejected(self):
        for role in ('viewer','analyst'):
            self.assertEqual(self.client.put('/api/v1/ai/settings',headers=self.headers(role),json={'provider':'rules'}).status_code,403)
        self.other()
        with self.factory() as db:
            db.add(WorkspaceSetting(organization_id='default',workspace_id='second',key='ai',value={}))
            with self.assertRaises(ValueError):db.commit()
