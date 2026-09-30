"""Optional localhost API. It is deliberately not connected to the hosted site."""
import hmac
import json
import os
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware
from backend.access_control import ProductionAccessStore, RequestRateLimiter
from backend.core import LabStore, RULES, detect
from backend.oidc import load_oidc_configuration

MAX_BYTES = 1048576

# This is deliberately a static description of the local lab's boundary.  It
# lets a reviewer see both the implemented safeguards and the work that still
# needs to happen before a customer-data deployment.
READINESS_COMPONENTS = (
    {
        'component': 'Synthetic data boundary',
        'status': 'implemented',
        'scope': 'Demo accounts and documentation-only IP ranges are required.',
    },
    {
        'component': 'Explainable detection rules',
        'status': 'implemented',
        'scope': 'Three deterministic identity detections run in the local lab.',
    },
    {
        'component': 'Local API access control',
        'status': 'implemented',
        'scope': 'Single-user localhost bearer token; this is not tenant authorization.',
    },
    {
        'component': 'Browser-to-API connection',
        'status': 'not-connected',
        'scope': 'The hosted browser lab does not call this local API.',
    },
    {
        'component': 'Production identity and tenancy',
        'status': 'foundation-only',
        'scope': (
            'A disconnected server-side tenant, role, approval, opaque-session, and audit foundation is present. '
            'No customer identity provider, person, tenant, or live sign-in is connected.'
        ),
    },
    {
        'component': 'Durable protected storage',
        'status': 'configuration-required',
        'scope': (
            'The access-control foundation supports a protected SQLite file path, but the local lab defaults '
            'to ephemeral in-memory storage and requires encrypted durable deployment storage before activation.'
        ),
    },
    {
        'component': 'Request rate limiting',
        'status': 'implemented',
        'scope': 'The local API applies an in-process peer-address rate limit; a production service also needs shared edge limiting and monitoring.',
    },
    {
        'component': 'Live customer integrations',
        'status': 'not-implemented',
        'scope': 'Only synthetic fixtures are accepted by this lab.',
    },
)

# The executive brief is deliberately static wherever it describes the pilot.
# It is returned alongside aggregate detector counts only: no event, account,
# timestamp, or source-address values are included in the response.
EXECUTIVE_PILOT_ASSUMPTIONS = (
    {
        'assumption': 'Controlled synthetic evaluation data',
        'scope': 'The lab accepts only the documented synthetic identity-event schema and documentation-only network ranges.',
    },
    {
        'assumption': 'Human review remains the decision point',
        'scope': 'Detections prioritize a review queue; they do not suspend accounts, change permissions, or make automated security decisions.',
    },
    {
        'assumption': 'Local, single-user demonstration environment',
        'scope': 'The API runs on loopback with one locally configured bearer token and has no production tenant model.',
    },
)

EXECUTIVE_GOVERNANCE_SCOPE = {
    'implemented_in_lab': (
        {
            'control': 'Synthetic-data validation',
            'scope': 'Imports are size-bounded, schema-validated, and reject non-lab account and address formats.',
        },
        {
            'control': 'Minimized API responses',
            'scope': 'Event and alert responses exclude source addresses, and the executive brief returns aggregates only.',
        },
        {
            'control': 'Local API boundary',
            'scope': 'Bearer authentication is required, browser-origin requests are rejected, and no CORS access is enabled.',
        },
        {
            'control': 'Ephemeral storage',
            'scope': 'The in-memory lab dataset is discarded when the local API process stops.',
        },
    ),
    'not_provided_by_lab': (
        'Customer identity verification or server-enforced role authorization',
        'Tenant isolation, retention enforcement, or customer data processing',
        'Persistent audit logging, monitoring, backups, or incident-response operations',
        'Live identity, cloud, code-hosting, or AI-provider integrations',
    ),
}

EXECUTIVE_PRODUCTION_REQUIREMENTS = (
    {
        'requirement': 'Customer identity, authorization, and tenant isolation',
        'status': 'required before customer data',
        'reason': 'Every request must be scoped and authorized by a production identity and tenancy model.',
    },
    {
        'requirement': 'Encrypted durable storage and audit records',
        'status': 'required before customer data',
        'reason': 'A deployable service needs protected persistence, traceable access, retention controls, and recovery procedures.',
    },
    {
        'requirement': 'Operational security controls',
        'status': 'required before customer data',
        'reason': 'Monitoring, rate limits, vulnerability management, backups, and an incident-response process must be operated and reviewed.',
    },
    {
        'requirement': 'Reviewed connector and AI governance',
        'status': 'required before customer data',
        'reason': 'Each integration needs least-privilege scopes, data handling review, and a documented owner before it is enabled.',
    },
)

# This is deliberately a static operating-policy preview. It explains how an
# owner could set response expectations during a synthetic pilot without
# implying that the local lab tracks real cases, clocks, or notifications.
CASE_POLICY = {
    'label': 'TraceGuard prototype case policy',
    'classification': 'portfolio prototype — not a live incident-response service',
    'policy_scope': 'Static synthetic-lab policy only. It returns no individual case records and sends no notifications.',
    'service_levels': (
        {
            'severity': 'critical',
            'review_target': 'Review within 30 minutes during the pilot',
            'default_owner_role': 'Security lead',
            'escalation': 'Surface the case in the local review queue if it remains unresolved.',
        },
        {
            'severity': 'high',
            'review_target': 'Review within 4 business hours during the pilot',
            'default_owner_role': 'Investigation analyst',
            'escalation': 'Request security-lead review in the local workflow if priority changes.',
        },
        {
            'severity': 'medium',
            'review_target': 'Review within 1 business day during the pilot',
            'default_owner_role': 'Investigation analyst',
            'escalation': 'Include in the next local review cycle when evidence warrants follow-up.',
        },
    ),
    'decision_path': (
        'Assign a named reviewer in the future production workflow.',
        'Review linked evidence and record a human decision.',
        'Escalate priority when the evidence suggests greater impact.',
        'Close only after the reviewer documents the reason.',
    ),
    'not_provided_by_lab': (
        'Case-specific due-date tracking or overdue calculations',
        'Live email, chat, pager, or webhook notifications',
        'On-call rotations, customer escalation contacts, or production incident handling',
        'Server-enforced assignment, access control, or durable audit records',
    ),
}

# This static policy preview makes the intended containment boundary visible
# without pretending the lab can take action in a customer identity system.
# It must remain independent of events, alerts, accounts, tenants, connectors,
# or endpoint inventory.
ACCESS_PROTECTION_POLICY = {
    'label': 'TraceGuard prototype access-protection policy',
    'classification': 'portfolio prototype — not an identity provider or endpoint-management service',
    'policy_scope': (
        'Static synthetic-lab policy only. It returns no account, session, tenant, '
        'connector, or endpoint records and performs no containment action.'
    ),
    'production_control_requirements': (
        {
            'control': 'Suspicious session containment',
            'production_expectation': (
                'A production service should verify the risk signal, apply an approved '
                'containment policy, and record a human or policy-authorized decision before '
                'requesting a server-side session response.'
            ),
        },
        {
            'control': 'Verified recovery and MFA reauthentication',
            'production_expectation': (
                'A production identity provider should require a verified password-recovery '
                'flow and MFA reauthentication before restoring sensitive access.'
            ),
        },
        {
            'control': 'Server-enforced tenant isolation and RBAC',
            'production_expectation': (
                'Every request must be authorized server-side, scoped to one tenant, and '
                'limited by least-privilege roles rather than browser-only checks.'
            ),
        },
        {
            'control': 'Separated connector credentials',
            'production_expectation': (
                'Each customer connector needs isolated, least-privilege credentials, '
                'rotation, revocation, and a documented owner.'
            ),
        },
        {
            'control': 'Durable audit and review requirements',
            'production_expectation': (
                'Containment decisions, policy changes, access attempts, and recovery actions '
                'need protected, tenant-scoped audit records and regular review.'
            ),
        },
        {
            'control': 'Endpoint and removable-media boundary',
            'production_expectation': (
                'USB and endpoint restrictions require a separately managed endpoint-security '
                'or device-management control plane with approved organizational policy.'
            ),
        },
    ),
    'not_provided_by_lab': (
        'The lab does not revoke sessions or force sign-outs.',
        'The lab does not change passwords, issue reset links, or perform MFA challenges.',
        'The lab does not connect to an identity provider, directory, or customer tenant.',
        'The lab does not manage USB devices, endpoint policies, or device inventory.',
        'The lab does not store connector credentials or provide production RBAC.',
    ),
}

# This endpoint is intentionally descriptive rather than an authentication
# implementation.  It documents the access model an organization would need
# before it grants a person access to a production tenant.  It has no identity
# records, passwords, phone numbers, OTP seeds, sessions, or tenant data.
ACCESS_CONTROL_POLICY = {
    'label': 'TraceGuard prototype access-control policy',
    'classification': 'portfolio prototype — not an authentication, authorization, or identity-provider service',
    'policy_scope': (
        'Static synthetic-lab policy only. It returns no user, tenant, device, session, '
        'phone-number, OTP, or credential records and performs no sign-in, approval, or revocation action.'
    ),
    'production_access_model': {
        'default': 'Deny access until a company administrator approves an eligible named person for one tenant.',
        'allowed_principal_roles': (
            {
                'role': 'Organization owner',
                'access': 'May administer the organization tenant, approve or suspend authorized lab assistants, and review protected audit records.',
            },
            {
                'role': 'Authorized lab assistant',
                'access': 'May use only the tenant-scoped lab capabilities explicitly approved by the organization owner.',
            },
        ),
        'unapproved_employee_rule': (
            'An employee without an active company-administrator approval and one of the allowed roles '
            'must not receive workspace, tenant, API, export, or administration access.'
        ),
        'approval_lifecycle': (
            'Company administrators should record the business purpose, tenant, approved role, start date, '
            'review date, and revocation owner before granting access; access should be reviewed regularly and removed promptly when no longer needed.'
        ),
    },
    'production_authentication_requirements': (
        {
            'control': 'Organization-managed SSO',
            'production_expectation': (
                'Authenticate through the organization identity provider using OIDC or SAML; do not use a prototype-local password store as the production authority.'
            ),
        },
        {
            'control': 'Phishing-resistant MFA',
            'production_expectation': (
                'Require a phishing-resistant authenticator such as WebAuthn/FIDO2 security keys or platform passkeys for privileged access. '
                'A phone-number or SMS OTP alone is not sufficient for owner-level access.'
            ),
        },
        {
            'control': 'Step-up verification',
            'production_expectation': (
                'Require a fresh MFA challenge before sensitive actions such as changing access, exporting data, altering policy, or recovering a privileged account.'
            ),
        },
    ),
    'production_authorization_requirements': (
        {
            'control': 'Server-side default-deny RBAC',
            'production_expectation': (
                'Enforce the approved role and least-privilege permissions on every server-side request; a hidden page, local storage flag, or browser role selector is never authorization.'
            ),
        },
        {
            'control': 'Tenant boundary enforcement',
            'production_expectation': (
                'Bind every authenticated request, query, export, connector, and audit record to exactly one server-verified tenant. '
                'A principal from one company must not be able to enumerate or access another company tenant.'
            ),
        },
        {
            'control': 'Administrative separation',
            'production_expectation': (
                'Only the organization owner or delegated company administrator may approve, change, or remove another person\'s access; changes require durable, protected audit records.'
            ),
        },
    ),
    'production_session_requirements': (
        {
            'control': 'Short-lived server-side sessions',
            'production_expectation': (
                'Use secure, HttpOnly, SameSite cookies or equivalent server-side sessions with idle and absolute expiry; do not treat a browser-only state as a trusted session.'
            ),
        },
        {
            'control': 'Immediate revocation',
            'production_expectation': (
                'When a company administrator disables a person, detects suspicious access, or completes account recovery, revoke active sessions and refresh tokens server-side and require fresh SSO plus MFA.'
            ),
        },
        {
            'control': 'Protected access audit trail',
            'production_expectation': (
                'Record sign-in attempts, approvals, role changes, denials, exports, MFA resets, and revocations in protected, tenant-scoped audit records with regular review.'
            ),
        },
    ),
    'not_provided_by_lab': (
        'The lab does not authenticate a person or validate a password, authenticator, phone number, OTP, passkey, or MFA challenge.',
        'The browser lab does not store users, roles, sessions, tenant memberships, approval records, or audit records. The disconnected server-side foundation starts without live identity data and is not connected to SSO.',
        'The lab does not connect to SSO, an identity provider, a directory, an email service, an SMS service, or an authenticator provider.',
        'The lab does not grant, change, or revoke access and cannot force a person to sign out.',
    ),
}


def redact_event(event):
    """Return the API-safe representation of one synthetic event."""
    return {key: value for key, value in event.items() if key != 'ip'}


def redact_alert(alert):
    """Keep alert responses safe if a future detector adds a source address."""
    return {key: value for key, value in alert.items() if key != 'ip'}


def executive_metrics(events):
    """Return a stable, aggregate-only view for an owner-facing demo brief."""
    alerts = detect(events)
    severity_counts = {severity: 0 for severity in ('critical', 'high', 'medium')}
    rule_counts = {rule_id: 0 for rule_id in RULES}
    for alert in alerts:
        severity_counts[alert['severity']] += 1
        rule_counts[alert['ruleId']] += 1
    return {
        'synthetic_event_count': len(events),
        'synthetic_account_count': len({event['account'] for event in events}),
        'detected_alert_count': len(alerts),
        'alerts_by_severity': severity_counts,
        'alerts_by_rule': [
            {
                'rule_id': rule_id,
                'rule_name': rule_name,
                'detected_alert_count': rule_counts[rule_id],
            }
            for rule_id, (rule_name, _severity) in RULES.items()
        ],
        'redaction': 'Aggregate counts only; no event IDs, account labels, timestamps, or source addresses are included.',
    }


def owner_system_control_overview(oidc, access_store):
    """Return a safe deployment-planning view, never a live service claim.

    The local API can report its own configuration shape and access-control
    foundation.  It cannot observe an identity provider, a managed database,
    a backup system, a monitoring service, or a deployment review, so those
    remain explicit operator gates rather than inferred green checks.
    """
    oidc_configuration_state = (
        'configuration-present-but-inactive'
        if oidc.ready_for_integration
        else 'configuration-incomplete'
    )
    return {
        'label': 'TraceGuard owner system-control overview',
        'classification': 'synthetic-only deployment planning view — not a live production health report',
        'mode': 'synthetic-only',
        'production_ready': False,
        'customer_data_permitted': False,
        'overall_state': 'activation-gated',
        'identity_integration': {
            'configuration_state': oidc_configuration_state,
            'provider_connection': 'not-attempted',
            'live_sign_in_enabled': False,
            'scope': (
                'Configuration presence does not validate a provider, a tenant, an MFA policy, or a token. '
                'Live sign-in remains disabled.'
            ),
        },
        'server_controls': access_store.system_control_status(rate_limiting_active=True),
        'owner_activation_gates': [
            {
                'id': 'identity-and-mfa',
                'owner': 'Identity administrator',
                'priority': 'blocking',
                'requirement': (
                    'Register and review the Entra or Okta integration, then validate authorization-code PKCE, token '
                    'signature, issuer, audience, nonce, exact tenant, role mapping, and phishing-resistant MFA.'
                ),
            },
            {
                'id': 'protected-storage-and-audit',
                'owner': 'Platform and security owner',
                'priority': 'blocking',
                'requirement': (
                    'Provide encrypted durable storage, secret and key management, restrictive service permissions, '
                    'audit retention, and an independent audit-review process.'
                ),
            },
            {
                'id': 'monitoring-and-traffic-protection',
                'owner': 'Security operations owner',
                'priority': 'blocking',
                'requirement': (
                    'Deploy shared edge rate limiting, trusted-proxy handling, monitoring, alert routing, and an '
                    'incident-response owner before serving a production tenant.'
                ),
            },
            {
                'id': 'backup-and-recovery-evidence',
                'owner': 'Platform owner',
                'priority': 'blocking',
                'requirement': (
                    'Document backup scope and retention, run a recovery exercise, and retain evidence that recovery '
                    'objectives were met before customer data is accepted.'
                ),
            },
            {
                'id': 'deployment-security-review',
                'owner': 'Security owner',
                'priority': 'blocking',
                'requirement': (
                    'Complete tenant-isolation, authorization, session-revocation, dependency, and deployment tests; '
                    'record accountable approval for the intended data scope.'
                ),
            },
        ],
        'verification_boundary': (
            'This endpoint makes no network calls and returns no identity, tenant, session, audit, secret, provider, '
            'backup, monitoring, or customer-data record. Operator evidence is required for every activation gate.'
        ),
    }


def create_app(
    token=None,
    oidc_environment=None,
    access_database_path=None,
    rate_limiter=None,
):
    token = token or os.environ.get('TRACEGUARD_LAB_TOKEN', '')
    if len(token) < 32:
        raise RuntimeError('Set TRACEGUARD_LAB_TOKEN to a random token of at least 32 characters.')
    # Configuration is parsed once at startup.  It has no network, provider,
    # credential, or identity side effects; live OIDC remains disabled until a
    # dedicated token-validation and server-session implementation is ready.
    oidc = load_oidc_configuration(oidc_environment)
    app = FastAPI(title='TraceGuard synthetic lab', docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=['127.0.0.1', 'localhost', 'testserver'])
    # In-memory SQL is the default; the hosted demo never calls this API.
    store = LabStore()
    # This store contains no principals in the local lab.  It is a tested
    # server-side authorization foundation for a later validated SSO callback,
    # never a replacement for token validation or an actual login service.
    configured_session_secret = oidc.values.get('TRACEGUARD_SESSION_SECRET', '').encode('utf-8')
    configured_access_database_path = (
        access_database_path or os.environ.get('TRACEGUARD_ACCESS_DB_PATH', ':memory:')
    )
    if configured_access_database_path != ':memory:' and len(configured_session_secret) < 32:
        raise RuntimeError(
            'Set TRACEGUARD_SESSION_SECRET to at least 32 characters before using a durable access-control database.'
        )
    access_store = ProductionAccessStore(
        configured_access_database_path,
        secret=configured_session_secret if len(configured_session_secret) >= 32 else None,
    )
    rate_limiter = rate_limiter or RequestRateLimiter()
    app.state.access_store = access_store
    app.state.rate_limiter = rate_limiter

    def hardened(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Permissions-Policy'] = 'camera=(), geolocation=(), microphone=()'
        return response

    @app.middleware('http')
    async def security(request: Request, call_next):
        # The peer address comes from the ASGI connection.  We deliberately do
        # not trust X-Forwarded-For in a local deployment without a configured
        # trusted reverse proxy.
        peer = request.client.host if request.client else 'unknown-peer'
        limit = rate_limiter.consume_request(request.url.path, peer)
        if not limit.allowed:
            return hardened(JSONResponse(
                {'detail': 'Too many requests. Try again later.'},
                status_code=429,
                headers={'Retry-After': str(limit.retry_after_seconds)},
            ))
        # Fail closed on browser cross-origin requests. No CORS middleware is enabled.
        if request.headers.get('origin'):
            return hardened(JSONResponse(
                {'detail': 'Browser origins are not supported by this lab API.'}, status_code=403
            ))
        # These future OIDC entry points intentionally remain public because a
        # real identity provider cannot send the lab bearer token.  They return
        # only generic, non-sensitive readiness errors until a reviewed OIDC
        # integration exists; every API endpoint still requires the lab token.
        if request.url.path not in {'/auth/login', '/auth/oidc/callback'}:
            auth = request.headers.get('authorization', '')
            if not hmac.compare_digest(auth.encode(), ('Bearer ' + token).encode()):
                return hardened(JSONResponse({'detail': 'Unauthorized'}, status_code=401))
        response = await call_next(request)
        return hardened(response)

    @app.get('/auth/login')
    async def oidc_login():
        """Fail closed until a reviewed provider and session implementation exists."""
        if not oidc.ready_for_integration:
            return JSONResponse(
                {
                    'detail': 'OIDC SSO is not configured for this TraceGuard deployment.',
                    'code': 'oidc_not_configured',
                },
                status_code=503,
            )
        return JSONResponse(
            {
                'detail': (
                    'OIDC configuration is present, but live sign-in is disabled until token validation '
                    'and server-side session controls are deployed and reviewed.'
                ),
                'code': 'oidc_activation_required',
            },
            status_code=503,
        )

    @app.get('/auth/oidc/callback')
    async def oidc_callback():
        """Never accept authorization codes before validated OIDC is implemented."""
        return JSONResponse(
            {
                'detail': 'OIDC callback handling is not enabled in the synthetic lab.',
                'code': 'oidc_callback_disabled',
            },
            status_code=503,
        )

    @app.get('/api/health')
    async def health():
        return {
            'status': 'ok',
            'mode': 'synthetic-only',
            'storage': 'in-memory SQLite',
            'ai_connected': False,
            'access_control_foundation': {
                'live_sign_in_enabled': False,
                'durable_storage_configured': access_store.durable_storage_configured,
                'audit_chain_valid': access_store.verify_audit_chain(),
                'rate_limiting_active': True,
            },
        }

    @app.post('/api/events')
    async def import_events(request: Request):
        if request.headers.get('content-type', '').split(';')[0] != 'application/json':
            raise HTTPException(415, 'Expected application/json.')
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > MAX_BYTES:
                raise HTTPException(413, 'File exceeds 1 MB.')
        try:
            count = store.replace(json.loads(body))
        except (ValueError, UnicodeError):
            raise HTTPException(400, 'Invalid synthetic dataset. No events were changed.') from None
        return {'imported': count}

    @app.get('/api/events')
    async def get_events(account: str | None = None):
        # Minimize the API response: IPs are not returned.
        return {'events': [redact_event(event) for event in store.events(account)]}

    @app.get('/api/alerts')
    async def get_alerts():
        return {'alerts': [redact_alert(alert) for alert in detect(store.events())]}

    @app.get('/api/alerts/{alert_id}')
    async def get_alert(alert_id: str):
        events = store.events()
        # Alert IDs are synthetic public identifiers, not secrets. Ordinary
        # equality also handles arbitrary Unicode route input safely.
        alert = next((candidate for candidate in detect(events)
                      if candidate['id'] == alert_id), None)
        if alert is None:
            raise HTTPException(404, 'Alert not found.')
        evidence_ids = set(alert['evidence'])
        return {
            'alert': redact_alert(alert),
            'evidence': [redact_event(event) for event in events if event['id'] in evidence_ids],
            'redaction': {'source_addresses': 'excluded'},
        }

    @app.get('/api/readiness')
    async def readiness():
        events = store.events()
        alert_count = len(detect(events))
        return {
            'label': 'TraceGuard synthetic-only readiness summary',
            'mode': 'synthetic-only',
            'production_ready': False,
            'browser_connected': False,
            'ai_connected': False,
            'components': READINESS_COMPONENTS,
            'current_counts': {'events': len(events), 'alerts': alert_count},
        }

    @app.get('/api/case-policy')
    async def case_policy():
        """Return static pilot expectations without exposing case information."""
        return CASE_POLICY

    @app.get('/api/access-protection-policy')
    async def access_protection_policy():
        """Return static containment guidance without accessing identity systems."""
        return ACCESS_PROTECTION_POLICY

    @app.get('/api/access-control-policy')
    async def access_control_policy():
        """Return static production access guidance without handling identities."""
        return ACCESS_CONTROL_POLICY

    @app.get('/api/auth/configuration')
    async def oidc_configuration():
        """Expose only safe SSO readiness details to a local lab administrator."""
        return oidc.public_status()

    @app.get('/api/production-readiness')
    async def production_readiness():
        """Expose safe access-control implementation readiness without live records."""
        return access_store.public_status(rate_limiting_active=True)

    @app.get('/api/system-health')
    async def system_health():
        """Expose owner activation gates without probing or claiming live services."""
        return owner_system_control_overview(oidc, access_store)

    @app.get('/api/executive-brief')
    async def executive_brief():
        """A safe portfolio briefing for an owner; it is not a production report."""
        return {
            'label': 'TraceGuard synthetic-only executive brief',
            'classification': 'portfolio prototype — not a customer-data service',
            'metrics': executive_metrics(store.events()),
            'pilot_assumptions': {
                'label': 'Pilot assumptions — not production controls',
                'items': EXECUTIVE_PILOT_ASSUMPTIONS,
            },
            'governance_scope': {
                'label': 'Governance scope of this local lab',
                **EXECUTIVE_GOVERNANCE_SCOPE,
            },
            'production_requirements': {
                'label': 'Required before processing customer data',
                'items': EXECUTIVE_PRODUCTION_REQUIREMENTS,
            },
        }

    @app.delete('/api/events')
    async def clear():
        store.clear()
        return {'cleared': True}

    return app

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(create_app(), host='127.0.0.1', port=8000, access_log=False)
