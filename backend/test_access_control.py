"""Tests for the disconnected server-side production access-control foundation."""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from backend.access_control import (
    AccessDenied,
    ProductionAccessStore,
    RequestRateLimiter,
)
from backend.api import create_app


TOKEN = 'test-only-token-never-used-in-deployment-12345'


class MutableClock:
    def __init__(self, start=1_760_000_000):
        self.value = start

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


class ProductionAccessStoreTests(unittest.TestCase):
    def setUp(self):
        self.clock = MutableClock()
        self.store = ProductionAccessStore(
            secret=b'access-control-test-secret-material-0123456789',
            clock=self.clock,
        )
        self.store.create_tenant('tenant-alpha')
        self.store.register_principal('tenant-alpha', 'owner-alpha', 'validated-owner-subject')
        self.store.bootstrap_owner('tenant-alpha', 'owner-alpha')
        self.store.register_principal('tenant-alpha', 'assistant-alpha', 'validated-assistant-subject')

    def tearDown(self):
        self.store.close()

    def test_owner_approval_session_and_revocation_are_server_enforced(self):
        approval_id = self.store.approve_access(
            'tenant-alpha',
            'owner-alpha',
            'assistant-alpha',
            'Lab Assistant',
            purpose='lab-review',
        )
        self.assertTrue(approval_id.startswith('apr_'))

        grant = self.store.issue_session('tenant-alpha', 'assistant-alpha')
        # The raw session value is returned once, while SQLite stores only a
        # keyed digest that cannot be replayed as the bearer value.
        persisted = self.store._connection.execute(
            'SELECT session_digest FROM access_sessions'
        ).fetchone()['session_digest']
        self.assertNotEqual(grant.token, persisted)
        self.assertNotIn(grant.token, persisted)

        context = self.store.authorize_session(
            grant.token,
            'tenant-alpha',
            {'Lab Assistant'},
        )
        self.assertEqual(context.principal_id, 'assistant-alpha')
        self.assertEqual(context.role, 'Lab Assistant')
        with self.assertRaises(AccessDenied):
            self.store.authorize_session(grant.token, 'tenant-alpha', {'Owner'})

        revoked_sessions = self.store.revoke_access('tenant-alpha', 'owner-alpha', 'assistant-alpha')
        self.assertEqual(revoked_sessions, 1)
        with self.assertRaises(AccessDenied):
            self.store.authorize_session(grant.token, 'tenant-alpha', {'Lab Assistant'})
        self.assertTrue(self.store.verify_audit_chain())

    def test_tenant_boundaries_and_last_owner_protection_fail_closed(self):
        self.store.create_tenant('tenant-bravo')
        self.store.register_principal('tenant-bravo', 'owner-bravo', 'other-owner-subject')

        with self.assertRaises(AccessDenied):
            self.store.approve_access(
                'tenant-bravo',
                'owner-alpha',
                'owner-bravo',
                'Lab Assistant',
                purpose='lab-review',
            )
        with self.assertRaises(AccessDenied):
            self.store.revoke_access('tenant-alpha', 'owner-alpha', 'owner-alpha')

    def test_audit_rows_cannot_be_updated_or_deleted_and_verify_after_reopen(self):
        with self.assertRaises(sqlite3.DatabaseError):
            self.store._connection.execute("UPDATE access_audit_log SET action = 'changed'")
        with self.assertRaises(sqlite3.DatabaseError):
            self.store._connection.execute('DELETE FROM access_audit_log')
        self.assertTrue(self.store.verify_audit_chain())

        self.store.close()
        with tempfile.TemporaryDirectory() as temporary:
            database_path = str(Path(temporary) / 'access-control.sqlite3')
            secret = b'durable-access-control-test-secret-0123456789'
            first = ProductionAccessStore(database_path, secret=secret, clock=self.clock)
            first.create_tenant('tenant-durable')
            first.register_principal('tenant-durable', 'owner-durable', 'durable-owner-subject')
            first.bootstrap_owner('tenant-durable', 'owner-durable')
            first.close()

            reopened = ProductionAccessStore(database_path, secret=secret, clock=self.clock)
            self.assertTrue(reopened.durable_storage_configured)
            self.assertTrue(reopened.verify_audit_chain())
            reopened.close()

        # tearDown may safely close an already closed sqlite connection only
        # once, so replace it with a fresh store for the remainder of teardown.
        self.store = ProductionAccessStore(secret=b'access-control-test-secret-material-0123456789')

    def test_expired_idle_session_and_unapproved_principal_are_denied(self):
        with self.assertRaises(AccessDenied):
            self.store.issue_session('tenant-alpha', 'assistant-alpha')

        self.store.approve_access(
            'tenant-alpha',
            'owner-alpha',
            'assistant-alpha',
            'Lab Assistant',
            purpose='lab-review',
        )
        grant = self.store.issue_session(
            'tenant-alpha',
            'assistant-alpha',
            absolute_lifetime_seconds=120,
            idle_timeout_seconds=60,
        )
        self.clock.advance(60)
        with self.assertRaises(AccessDenied):
            self.store.authorize_session(grant.token, 'tenant-alpha', {'Lab Assistant'})
        with self.assertRaises(AccessDenied):
            self.store.authorize_session('é' * 32, 'tenant-alpha', {'Lab Assistant'})


class RequestRateLimiterTests(unittest.TestCase):
    def test_sliding_window_limiter_recovers_after_window(self):
        clock = MutableClock(start=0)
        limiter = RequestRateLimiter(api_limit=2, api_window_seconds=10, auth_limit=1, auth_window_seconds=20, clock=clock)
        self.assertTrue(limiter.consume('api', 'peer-a').allowed)
        self.assertTrue(limiter.consume('api', 'peer-a').allowed)
        rejected = limiter.consume('api', 'peer-a')
        self.assertFalse(rejected.allowed)
        self.assertEqual(rejected.retry_after_seconds, 10)
        self.assertTrue(limiter.consume('api', 'peer-b').allowed)
        clock.advance(10)
        self.assertTrue(limiter.consume('api', 'peer-a').allowed)

    def test_api_middleware_returns_safe_rate_limit_response(self):
        clock = MutableClock(start=0)
        limiter = RequestRateLimiter(api_limit=1, api_window_seconds=30, clock=clock)
        app = create_app(TOKEN, rate_limiter=limiter)
        client = TestClient(app)
        headers = {'Authorization': 'Bearer ' + TOKEN}

        self.assertEqual(client.get('/api/health', headers=headers).status_code, 200)
        limited = client.get('/api/health', headers=headers)
        self.assertEqual(limited.status_code, 429)
        self.assertEqual(limited.json(), {'detail': 'Too many requests. Try again later.'})
        self.assertEqual(limited.headers['Retry-After'], '30')
        self.assertEqual(limited.headers['Cache-Control'], 'no-store')

    def test_production_readiness_discloses_no_records_and_stays_disabled(self):
        app = create_app(TOKEN)
        app.state.access_store.create_tenant('tenant-hidden')
        client = TestClient(app)
        response = client.get('/api/production-readiness', headers={'Authorization': 'Bearer ' + TOKEN})
        self.assertEqual(response.status_code, 200)
        status = response.json()
        self.assertEqual(status['label'], 'TraceGuard server-side access-control foundation')
        self.assertFalse(status['production_ready'])
        self.assertFalse(status['live_sign_in_enabled'])
        self.assertEqual(status['identity_provider_connection'], 'not-connected')
        self.assertTrue(status['audit_chain_valid'])
        self.assertEqual(
            status['system_controls']['storage']['state'],
            'ephemeral-local-lab',
        )
        self.assertNotIn('tenant-hidden', response.text)

    def test_system_health_is_activation_gated_and_discloses_no_tenant_records(self):
        app = create_app(TOKEN)
        app.state.access_store.create_tenant('tenant-hidden')
        client = TestClient(app)

        self.assertEqual(client.get('/api/system-health').status_code, 401)
        response = client.get('/api/system-health', headers={'Authorization': 'Bearer ' + TOKEN})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        status = response.json()
        self.assertEqual(status['label'], 'TraceGuard owner system-control overview')
        self.assertEqual(
            status['classification'],
            'synthetic-only deployment planning view — not a live production health report',
        )
        self.assertFalse(status['production_ready'])
        self.assertFalse(status['customer_data_permitted'])
        self.assertEqual(status['overall_state'], 'activation-gated')
        self.assertEqual(
            status['identity_integration']['configuration_state'],
            'configuration-incomplete',
        )
        self.assertEqual(status['identity_integration']['provider_connection'], 'not-attempted')
        self.assertFalse(status['identity_integration']['live_sign_in_enabled'])
        controls = status['server_controls']
        self.assertEqual(controls['authorization']['state'], 'implemented-disconnected')
        self.assertEqual(controls['sessions']['state'], 'implemented-disconnected')
        self.assertEqual(controls['audit_integrity']['state'], 'current-chain-verifies')
        self.assertEqual(controls['storage']['state'], 'ephemeral-local-lab')
        self.assertEqual(controls['rate_limiting']['state'], 'in-process-active')
        self.assertEqual(
            [gate['id'] for gate in status['owner_activation_gates']],
            [
                'identity-and-mfa',
                'protected-storage-and-audit',
                'monitoring-and-traffic-protection',
                'backup-and-recovery-evidence',
                'deployment-security-review',
            ],
        )
        self.assertTrue(all(gate['priority'] == 'blocking' for gate in status['owner_activation_gates']))
        self.assertIn('no network calls', status['verification_boundary'])
        self.assertNotIn('tenant-hidden', response.text)

    def test_system_health_keeps_complete_oidc_configuration_inactive_and_secret_free(self):
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
        response = client.get('/api/system-health', headers={'Authorization': 'Bearer ' + TOKEN})
        self.assertEqual(response.status_code, 200)
        status = response.json()
        self.assertEqual(
            status['identity_integration']['configuration_state'],
            'configuration-present-but-inactive',
        )
        self.assertEqual(status['identity_integration']['provider_connection'], 'not-attempted')
        self.assertFalse(status['identity_integration']['live_sign_in_enabled'])
        self.assertFalse(status['production_ready'])
        for value in configured_environment.values():
            self.assertNotIn(value, response.text)

    def test_durable_access_store_requires_a_stable_server_secret(self):
        with tempfile.TemporaryDirectory() as temporary:
            database_path = str(Path(temporary) / 'access-control.sqlite3')
            with self.assertRaises(RuntimeError):
                create_app(TOKEN, oidc_environment={}, access_database_path=database_path)


if __name__ == '__main__':
    unittest.main()
