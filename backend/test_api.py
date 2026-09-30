import json
import unittest
from pathlib import Path
from fastapi.testclient import TestClient
from backend.api import create_app

TOKEN = 'test-only-token-never-used-in-deployment-12345'

class ApiTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(create_app(TOKEN))
        self.headers = {'Authorization': 'Bearer ' + TOKEN}
        self.fixture = json.loads((Path(__file__).parent / 'fixtures.json').read_text())

    def test_authentication_required(self):
        for path in ['/api/health', '/api/events', '/api/alerts', '/api/alerts/TG-1001', '/api/readiness', '/api/case-policy', '/api/access-protection-policy', '/api/access-control-policy', '/api/auth/configuration', '/api/production-readiness', '/api/system-health', '/api/executive-brief']:
            self.assertEqual(self.client.get(path).status_code, 401)

    def test_wrong_token_rejected(self):
        self.assertEqual(self.client.get('/api/events', headers={'Authorization': 'Bearer wrong'}).status_code, 401)

    def test_browser_origin_rejected(self):
        self.assertEqual(self.client.get('/api/events', headers={**self.headers, 'Origin': 'https://example.com'}).status_code, 403)

    def test_import_and_minimized_response(self):
        self.assertEqual(self.client.post('/api/events', headers=self.headers, json=self.fixture).status_code, 200)
        response = self.client.get('/api/events', headers=self.headers)
        self.assertEqual(len(response.json()['events']), 162)
        self.assertNotIn('ip', response.json()['events'][0])
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertEqual(len(self.client.get('/api/alerts', headers=self.headers).json()['alerts']), 8)

    def test_alert_detail_is_redacted_and_evidence_linked(self):
        self.assertEqual(self.client.post('/api/events', headers=self.headers, json=self.fixture).status_code, 200)
        alert = self.client.get('/api/alerts', headers=self.headers).json()['alerts'][0]
        response = self.client.get(f"/api/alerts/{alert['id']}", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        detail = response.json()
        self.assertEqual(detail['alert'], alert)
        self.assertEqual(detail['redaction'], {'source_addresses': 'excluded'})
        self.assertEqual([event['id'] for event in detail['evidence']], alert['evidence'])
        self.assertTrue(detail['evidence'])
        self.assertNotIn('ip', detail['alert'])
        self.assertTrue(all('ip' not in event for event in detail['evidence']))

    def test_alert_detail_returns_not_found_for_unknown_alert(self):
        self.assertEqual(self.client.post('/api/events', headers=self.headers, json=self.fixture).status_code, 200)
        response = self.client.get('/api/alerts/TG-9999', headers=self.headers)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {'detail': 'Alert not found.'})

    def test_readiness_is_explicit_and_uses_current_counts(self):
        empty = self.client.get('/api/readiness', headers=self.headers)
        self.assertEqual(empty.status_code, 200)
        self.assertEqual(empty.json()['label'], 'TraceGuard synthetic-only readiness summary')
        self.assertEqual(empty.json()['mode'], 'synthetic-only')
        self.assertFalse(empty.json()['production_ready'])
        self.assertFalse(empty.json()['browser_connected'])
        self.assertFalse(empty.json()['ai_connected'])
        self.assertEqual(empty.json()['current_counts'], {'events': 0, 'alerts': 0})
        self.assertIn('Synthetic data boundary', [item['component'] for item in empty.json()['components']])
        self.assertIn('Production identity and tenancy', [item['component'] for item in empty.json()['components']])

        self.assertEqual(self.client.post('/api/events', headers=self.headers, json=self.fixture).status_code, 200)
        populated = self.client.get('/api/readiness', headers=self.headers)
        self.assertEqual(populated.status_code, 200)
        self.assertEqual(populated.json()['current_counts'], {'events': 162, 'alerts': 8})

    def test_case_policy_is_static_and_explicitly_prototype_only(self):
        response = self.client.get('/api/case-policy', headers=self.headers)
        self.assertEqual(response.status_code, 200)
        policy = response.json()
        self.assertEqual(policy['label'], 'TraceGuard prototype case policy')
        self.assertEqual(policy['classification'], 'portfolio prototype — not a live incident-response service')
        self.assertIn('Static synthetic-lab policy only', policy['policy_scope'])
        self.assertIn('sends no notifications', policy['policy_scope'])
        self.assertEqual(
            [item['severity'] for item in policy['service_levels']],
            ['critical', 'high', 'medium'],
        )
        self.assertEqual(policy['service_levels'][0]['review_target'], 'Review within 30 minutes during the pilot')
        self.assertTrue(any('Live email' in item for item in policy['not_provided_by_lab']))
        self.assertTrue(any('durable audit records' in item for item in policy['not_provided_by_lab']))

        # It must remain static even after lab fixtures are loaded and never
        # disclose individual synthetic data or operational delivery details.
        self.assertEqual(self.client.post('/api/events', headers=self.headers, json=self.fixture).status_code, 200)
        populated = self.client.get('/api/case-policy', headers=self.headers)
        self.assertEqual(populated.status_code, 200)
        self.assertEqual(populated.json(), policy)
        serialized = populated.text
        for key in ('id', 'account', 'timestamp', 'ip', 'events', 'alerts'):
            self.assertNotIn(f'\"{key}\":', serialized)
        for value in (self.fixture[0]['id'], self.fixture[0]['account'], self.fixture[0]['timestamp'], self.fixture[0]['ip']):
            self.assertNotIn(value, serialized)

    def test_access_protection_policy_is_static_and_explicit_about_its_limits(self):
        response = self.client.get('/api/access-protection-policy', headers=self.headers)
        self.assertEqual(response.status_code, 200)
        policy = response.json()
        self.assertEqual(policy['label'], 'TraceGuard prototype access-protection policy')
        self.assertEqual(
            policy['classification'],
            'portfolio prototype — not an identity provider or endpoint-management service',
        )
        self.assertIn('Static synthetic-lab policy only', policy['policy_scope'])
        self.assertIn('performs no containment action', policy['policy_scope'])
        controls = {item['control']: item['production_expectation']
                    for item in policy['production_control_requirements']}
        self.assertIn('Suspicious session containment', controls)
        self.assertIn('Verified recovery and MFA reauthentication', controls)
        self.assertIn('Server-enforced tenant isolation and RBAC', controls)
        self.assertIn('Separated connector credentials', controls)
        self.assertIn('Durable audit and review requirements', controls)
        self.assertIn('Endpoint and removable-media boundary', controls)
        limitations = ' '.join(policy['not_provided_by_lab'])
        self.assertIn('does not revoke sessions', limitations)
        self.assertIn('does not change passwords', limitations)
        self.assertIn('does not connect to an identity provider', limitations)
        self.assertIn('does not manage USB devices', limitations)

        # The endpoint must remain static after fixtures are loaded and never
        # return individual synthetic identifiers or operational records.
        self.assertEqual(self.client.post('/api/events', headers=self.headers, json=self.fixture).status_code, 200)
        populated = self.client.get('/api/access-protection-policy', headers=self.headers)
        self.assertEqual(populated.status_code, 200)
        self.assertEqual(populated.json(), policy)
        serialized = populated.text
        for key in ('id', 'account', 'timestamp', 'ip', 'events', 'alerts'):
            self.assertNotIn(f'\"{key}\":', serialized)
        for value in (self.fixture[0]['id'], self.fixture[0]['account'], self.fixture[0]['timestamp'], self.fixture[0]['ip']):
            self.assertNotIn(value, serialized)

    def test_access_control_policy_is_static_and_describes_a_production_only_owner_model(self):
        response = self.client.get('/api/access-control-policy', headers=self.headers)
        self.assertEqual(response.status_code, 200)
        policy = response.json()
        self.assertEqual(policy['label'], 'TraceGuard prototype access-control policy')
        self.assertEqual(
            policy['classification'],
            'portfolio prototype — not an authentication, authorization, or identity-provider service',
        )
        self.assertIn('Static synthetic-lab policy only', policy['policy_scope'])
        self.assertIn('performs no sign-in, approval, or revocation action', policy['policy_scope'])

        access_model = policy['production_access_model']
        self.assertIn('Deny access', access_model['default'])
        self.assertEqual(
            [role['role'] for role in access_model['allowed_principal_roles']],
            ['Organization owner', 'Authorized lab assistant'],
        )
        self.assertIn('must not receive workspace', access_model['unapproved_employee_rule'])
        self.assertIn('Company administrators should record', access_model['approval_lifecycle'])

        authentication_controls = {
            item['control']: item['production_expectation']
            for item in policy['production_authentication_requirements']
        }
        self.assertIn('Organization-managed SSO', authentication_controls)
        self.assertIn('OIDC or SAML', authentication_controls['Organization-managed SSO'])
        self.assertIn('Phishing-resistant MFA', authentication_controls)
        self.assertIn('SMS OTP alone is not sufficient', authentication_controls['Phishing-resistant MFA'])
        self.assertIn('Step-up verification', authentication_controls)

        authorization_controls = {
            item['control']: item['production_expectation']
            for item in policy['production_authorization_requirements']
        }
        self.assertIn('Server-side default-deny RBAC', authorization_controls)
        self.assertIn('browser role selector is never authorization', authorization_controls['Server-side default-deny RBAC'])
        self.assertIn('Tenant boundary enforcement', authorization_controls)
        self.assertIn('one company must not be able to enumerate or access another company tenant', authorization_controls['Tenant boundary enforcement'])
        self.assertIn('Administrative separation', authorization_controls)

        session_controls = {
            item['control']: item['production_expectation']
            for item in policy['production_session_requirements']
        }
        self.assertIn('Short-lived server-side sessions', session_controls)
        self.assertIn('Immediate revocation', session_controls)
        self.assertIn('revoke active sessions and refresh tokens server-side', session_controls['Immediate revocation'])
        self.assertIn('Protected access audit trail', session_controls)

        limitations = ' '.join(policy['not_provided_by_lab'])
        self.assertIn('does not authenticate a person', limitations)
        self.assertIn('does not store users, roles, sessions', limitations)
        self.assertIn('does not connect to SSO', limitations)
        self.assertIn('does not grant, change, or revoke access', limitations)

        # The policy must remain a static, non-sensitive explanation after
        # synthetic data is imported. It cannot contain a user, account,
        # event, session, or tenant record from the lab.
        self.assertEqual(self.client.post('/api/events', headers=self.headers, json=self.fixture).status_code, 200)
        populated = self.client.get('/api/access-control-policy', headers=self.headers)
        self.assertEqual(populated.status_code, 200)
        self.assertEqual(populated.json(), policy)
        serialized = populated.text
        for key in ('id', 'account', 'timestamp', 'ip', 'events', 'alerts'):
            self.assertNotIn(f'\"{key}\":', serialized)
        for value in (self.fixture[0]['id'], self.fixture[0]['account'], self.fixture[0]['timestamp'], self.fixture[0]['ip']):
            self.assertNotIn(value, serialized)

    def test_oidc_foundation_fails_closed_by_default_without_exposing_identity_data(self):
        response = self.client.get('/api/auth/configuration', headers=self.headers)
        self.assertEqual(response.status_code, 200)
        status = response.json()
        self.assertEqual(status['label'], 'TraceGuard OIDC/SSO integration foundation')
        self.assertEqual(status['mode'], 'unconfigured')
        self.assertFalse(status['sign_in_available'])
        self.assertEqual(status['provider_connection'], 'not-attempted')
        self.assertEqual(
            status['missing_configuration'],
            [
                'TRACEGUARD_PUBLIC_ORIGIN',
                'TRACEGUARD_OIDC_PROVIDER',
                'TRACEGUARD_OIDC_ISSUER',
                'TRACEGUARD_OIDC_CLIENT_ID',
                'TRACEGUARD_OIDC_REDIRECT_URI',
                'TRACEGUARD_OIDC_POST_LOGOUT_REDIRECT_URI',
                'TRACEGUARD_OIDC_EXPECTED_TENANT_ID',
                'TRACEGUARD_OIDC_EXPECTED_AUDIENCE',
                'TRACEGUARD_OIDC_CLIENT_SECRET',
                'TRACEGUARD_SESSION_SECRET',
                'TRACEGUARD_OIDC_ROLE_CLAIM',
                'TRACEGUARD_OWNER_ROLE_VALUE',
                'TRACEGUARD_LAB_ASSISTANT_ROLE_VALUE',
            ],
        )
        self.assertEqual(status['invalid_configuration'], [])
        self.assertEqual(status['access_model']['default'], 'deny')
        self.assertEqual(status['access_model']['allowed_application_roles'], ['Owner', 'Lab Assistant'])
        self.assertEqual(status['access_model']['unapproved_employee_access'], 'denied')
        self.assertIn('exact configured issuer', status['access_model']['tenant_boundary'])
        self.assertIn('server-side', status['access_model']['session_requirement'])
        self.assertIn('PKCE', status['activation_gate'])
        self.assertIn('never returns issuer', status['safety_boundary'])

        # Login and callback are intentionally public only because an IdP
        # cannot know the local bearer token. They remain fail-closed.
        login = self.client.get('/auth/login')
        self.assertEqual(login.status_code, 503)
        self.assertEqual(login.json()['code'], 'oidc_not_configured')
        callback = self.client.get('/auth/oidc/callback?code=untrusted-value')
        self.assertEqual(callback.status_code, 503)
        self.assertEqual(callback.json()['code'], 'oidc_callback_disabled')
        self.assertNotIn('untrusted-value', callback.text)

    def test_oidc_foundation_validates_setup_without_disclosing_values_or_starting_sign_in(self):
        configured_environment = {
            'TRACEGUARD_PUBLIC_ORIGIN': 'https://traceguard-config.example.test',
            'TRACEGUARD_OIDC_PROVIDER': 'entra',
            'TRACEGUARD_OIDC_ISSUER': 'https://login-config.example.test/tenant-72',
            'TRACEGUARD_OIDC_CLIENT_ID': 'traceguard-config-client',
            'TRACEGUARD_OIDC_REDIRECT_URI': 'https://traceguard-config.example.test/auth/oidc/callback',
            'TRACEGUARD_OIDC_POST_LOGOUT_REDIRECT_URI': 'https://traceguard-config.example.test/sign-in',
            'TRACEGUARD_OIDC_EXPECTED_TENANT_ID': 'tenant-config-72',
            'TRACEGUARD_OIDC_EXPECTED_AUDIENCE': 'traceguard-config-client',
            'TRACEGUARD_OIDC_CLIENT_SECRET': 'client-secret-material-that-is-long-enough-0123456789',
            'TRACEGUARD_SESSION_SECRET': 'session-secret-material-that-is-long-enough-0123456789',
            'TRACEGUARD_OIDC_ROLE_CLAIM': 'traceguard_roles_config',
            'TRACEGUARD_OWNER_ROLE_VALUE': 'traceguard-owner-config',
            'TRACEGUARD_LAB_ASSISTANT_ROLE_VALUE': 'traceguard-assistant-config',
        }
        client = TestClient(create_app(TOKEN, oidc_environment=configured_environment))
        status = client.get('/api/auth/configuration', headers=self.headers)
        self.assertEqual(status.status_code, 200)
        body = status.json()
        self.assertEqual(body['mode'], 'configuration-ready')
        self.assertFalse(body['sign_in_available'])
        self.assertEqual(body['missing_configuration'], [])
        self.assertEqual(body['invalid_configuration'], [])
        self.assertTrue(all(item['configured'] for item in body['required_environment']))
        for value in configured_environment.values():
            self.assertNotIn(value, status.text)

        login = client.get('/auth/login')
        self.assertEqual(login.status_code, 503)
        self.assertEqual(login.json()['code'], 'oidc_activation_required')

        invalid_environment = dict(configured_environment)
        invalid_environment['TRACEGUARD_OIDC_ISSUER'] = 'http://not-secure.example.test'
        invalid_environment['TRACEGUARD_OIDC_REDIRECT_URI'] = 'https://traceguard-config.example.test/not-the-callback'
        invalid_environment['TRACEGUARD_SESSION_SECRET'] = 'too-short'
        invalid_client = TestClient(create_app(TOKEN, oidc_environment=invalid_environment))
        invalid = invalid_client.get('/api/auth/configuration', headers=self.headers).json()
        self.assertEqual(invalid['mode'], 'unconfigured')
        self.assertEqual(
            invalid['invalid_configuration'],
            [
                'TRACEGUARD_OIDC_ISSUER',
                'TRACEGUARD_OIDC_REDIRECT_URI',
                'TRACEGUARD_SESSION_SECRET',
            ],
        )
        self.assertEqual(invalid['missing_configuration'], [])

    def test_executive_brief_is_aggregate_only_and_explicit_about_scope(self):
        empty = self.client.get('/api/executive-brief', headers=self.headers)
        self.assertEqual(empty.status_code, 200)
        brief = empty.json()
        self.assertEqual(brief['label'], 'TraceGuard synthetic-only executive brief')
        self.assertEqual(brief['classification'], 'portfolio prototype — not a customer-data service')
        self.assertEqual(brief['metrics']['synthetic_event_count'], 0)
        self.assertEqual(brief['metrics']['synthetic_account_count'], 0)
        self.assertEqual(brief['metrics']['detected_alert_count'], 0)
        self.assertEqual(brief['metrics']['alerts_by_severity'], {'critical': 0, 'high': 0, 'medium': 0})
        self.assertEqual([item['detected_alert_count'] for item in brief['metrics']['alerts_by_rule']], [0, 0, 0])
        self.assertIn('not production controls', brief['pilot_assumptions']['label'])
        self.assertTrue(any('Tenant isolation' in item
                            for item in brief['governance_scope']['not_provided_by_lab']))
        self.assertTrue(all(item['status'] == 'required before customer data'
                            for item in brief['production_requirements']['items']))

        self.assertEqual(self.client.post('/api/events', headers=self.headers, json=self.fixture).status_code, 200)
        populated = self.client.get('/api/executive-brief', headers=self.headers)
        self.assertEqual(populated.status_code, 200)
        metrics = populated.json()['metrics']
        self.assertEqual(metrics['synthetic_event_count'], 162)
        self.assertEqual(metrics['synthetic_account_count'], 17)
        self.assertEqual(metrics['detected_alert_count'], 8)
        self.assertEqual(metrics['alerts_by_severity'], {'critical': 2, 'high': 4, 'medium': 2})
        self.assertEqual(
            {item['rule_id']: item['detected_alert_count'] for item in metrics['alerts_by_rule']},
            {'TG-001': 4, 'TG-002': 2, 'TG-003': 2},
        )

        # The owner-facing endpoint must never expose individual synthetic identifiers.
        serialized = populated.text
        for key in ('id', 'account', 'timestamp', 'ip'):
            self.assertNotIn(f'"{key}":', serialized)
        for value in (self.fixture[0]['id'], self.fixture[0]['account'], self.fixture[0]['timestamp'], self.fixture[0]['ip']):
            self.assertNotIn(value, serialized)

    def test_invalid_import_not_echoed(self):
        response = self.client.post('/api/events', headers=self.headers, json=[{'secret': 'sensitive-text'}])
        self.assertEqual(response.status_code, 400)
        self.assertNotIn('sensitive-text', response.text)

    def test_large_payload_rejected(self):
        response = self.client.post('/api/events', headers={**self.headers, 'Content-Type': 'application/json'}, content=b' ' * 1048577)
        self.assertEqual(response.status_code, 413)

    def test_secure_startup(self):
        with self.assertRaises(RuntimeError):
            create_app('short')

if __name__ == '__main__':
    unittest.main()
