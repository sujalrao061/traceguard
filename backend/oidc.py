"""Configuration-only OIDC foundation for a future TraceGuard deployment.

This module deliberately does not contact an identity provider, parse tokens,
redirect a browser, or create a session.  It provides a small, testable
configuration boundary so that a production integration can fail closed before
those capabilities are added and independently reviewed.
"""
from dataclasses import dataclass
import os
import re
from typing import Mapping
from urllib.parse import urlparse


OIDC_ENVIRONMENT = (
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
)

# There are only two application roles by design.  A future identity adapter
# must map validated provider memberships to these values before any request is
# authorized; raw browser state and arbitrary provider groups are never roles.
ALLOWED_APPLICATION_ROLES = ('Owner', 'Lab Assistant')

_SAFE_OPAQUE_ID = re.compile(r'^[A-Za-z0-9._-]{1,128}$')
_SAFE_CLIENT_ID = re.compile(r'^[\x21-\x7e]{1,256}$')
_SAFE_CLAIM_NAME = re.compile(r'^[A-Za-z_][A-Za-z0-9_.-]{0,63}$')


def _environment_value(environment: Mapping[str, str], name: str) -> str:
    """Read one string setting without accepting non-string values."""
    value = environment.get(name, '')
    return value if isinstance(value, str) and value.strip() else ''


def _is_https_url(value: str) -> bool:
    parsed = urlparse(value)
    return (
        parsed.scheme == 'https'
        and bool(parsed.hostname)
        and not parsed.username
        and not parsed.password
        and not parsed.params
        and not parsed.query
        and not parsed.fragment
    )


def _valid_redirect_uri(value: str) -> bool:
    """Require an exact, HTTPS callback registration for the future flow."""
    parsed = urlparse(value)
    return _is_https_url(value) and parsed.path == '/auth/oidc/callback'


def _is_https_origin(value: str) -> bool:
    parsed = urlparse(value)
    return _is_https_url(value) and parsed.path in ('', '/')


@dataclass(frozen=True)
class OIDCConfiguration:
    """Validated OIDC settings, intentionally without any login behavior."""

    values: Mapping[str, str]
    missing: tuple[str, ...]
    invalid: tuple[str, ...]

    @property
    def ready_for_integration(self) -> bool:
        """Configuration is complete; live sign-in remains intentionally off."""
        return not self.missing and not self.invalid

    def public_status(self) -> dict:
        """Return safe readiness metadata without values or secret material."""
        configured = self.ready_for_integration
        return {
            'label': 'TraceGuard OIDC/SSO integration foundation',
            'classification': 'configuration foundation — live provider sign-in remains disabled',
            'mode': 'configuration-ready' if configured else 'unconfigured',
            'provider_connection': 'not-attempted',
            'sign_in_available': False,
            'required_environment': [
                {'name': name, 'configured': name not in self.missing and name not in self.invalid}
                for name in OIDC_ENVIRONMENT
            ],
            'missing_configuration': list(self.missing),
            'invalid_configuration': list(self.invalid),
            'access_model': {
                'default': 'deny',
                'tenant_boundary': 'A future token-validation layer must require an exact configured issuer, audience, and tenant before assigning application access.',
                'allowed_application_roles': list(ALLOWED_APPLICATION_ROLES),
                'unapproved_employee_access': 'denied',
                'session_requirement': (
                    'Use server-side, short-lived sessions with secure HttpOnly SameSite cookies, '
                    'idle and absolute expiry, and server-side revocation.'
                ),
            },
            'activation_gate': (
                'Before sign-in can be enabled, deploy and independently review OIDC discovery, '
                'authorization-code flow with PKCE, token signature and issuer/audience/nonce/expiry '
                'validation, exact tenant verification, server-side role approval, durable audit '
                'records, and server-side session revocation.'
            ),
            'safety_boundary': (
                'This endpoint never returns issuer, client ID, tenant ID, audience, redirect URI, '
                'client secret, session secret, tokens, passwords, phone numbers, OTP values, or user records.'
            ),
        }


def load_oidc_configuration(environment: Mapping[str, str] | None = None) -> OIDCConfiguration:
    """Validate environment-only setup and fail closed on omissions or unsafe values.

    The caller may pass a mapping in tests.  No configuration is written to
    disk, and values are never serialized by :meth:`OIDCConfiguration.public_status`.
    """
    env = os.environ if environment is None else environment
    values = {name: _environment_value(env, name) for name in OIDC_ENVIRONMENT}
    missing = tuple(name for name, value in values.items() if not value)
    invalid = []

    if values['TRACEGUARD_PUBLIC_ORIGIN'] and not _is_https_origin(values['TRACEGUARD_PUBLIC_ORIGIN']):
        invalid.append('TRACEGUARD_PUBLIC_ORIGIN')
    if values['TRACEGUARD_OIDC_PROVIDER'] and values['TRACEGUARD_OIDC_PROVIDER'] not in {'entra', 'okta'}:
        invalid.append('TRACEGUARD_OIDC_PROVIDER')
    if values['TRACEGUARD_OIDC_ISSUER'] and not _is_https_url(values['TRACEGUARD_OIDC_ISSUER']):
        invalid.append('TRACEGUARD_OIDC_ISSUER')
    if values['TRACEGUARD_OIDC_CLIENT_ID'] and not _SAFE_CLIENT_ID.fullmatch(values['TRACEGUARD_OIDC_CLIENT_ID']):
        invalid.append('TRACEGUARD_OIDC_CLIENT_ID')
    if values['TRACEGUARD_OIDC_REDIRECT_URI'] and not _valid_redirect_uri(values['TRACEGUARD_OIDC_REDIRECT_URI']):
        invalid.append('TRACEGUARD_OIDC_REDIRECT_URI')
    if values['TRACEGUARD_OIDC_POST_LOGOUT_REDIRECT_URI'] and not _is_https_url(values['TRACEGUARD_OIDC_POST_LOGOUT_REDIRECT_URI']):
        invalid.append('TRACEGUARD_OIDC_POST_LOGOUT_REDIRECT_URI')
    if values['TRACEGUARD_OIDC_EXPECTED_TENANT_ID'] and not _SAFE_OPAQUE_ID.fullmatch(values['TRACEGUARD_OIDC_EXPECTED_TENANT_ID']):
        invalid.append('TRACEGUARD_OIDC_EXPECTED_TENANT_ID')
    if values['TRACEGUARD_OIDC_EXPECTED_AUDIENCE'] and not _SAFE_CLIENT_ID.fullmatch(values['TRACEGUARD_OIDC_EXPECTED_AUDIENCE']):
        invalid.append('TRACEGUARD_OIDC_EXPECTED_AUDIENCE')
    if values['TRACEGUARD_OIDC_ROLE_CLAIM'] and not _SAFE_CLAIM_NAME.fullmatch(values['TRACEGUARD_OIDC_ROLE_CLAIM']):
        invalid.append('TRACEGUARD_OIDC_ROLE_CLAIM')
    for name in ('TRACEGUARD_OWNER_ROLE_VALUE', 'TRACEGUARD_LAB_ASSISTANT_ROLE_VALUE'):
        if values[name] and not _SAFE_CLIENT_ID.fullmatch(values[name]):
            invalid.append(name)
    for name in ('TRACEGUARD_OIDC_CLIENT_SECRET', 'TRACEGUARD_SESSION_SECRET'):
        if values[name] and len(values[name]) < 32:
            invalid.append(name)

    origin = values['TRACEGUARD_PUBLIC_ORIGIN'].rstrip('/')
    if origin and values['TRACEGUARD_OIDC_REDIRECT_URI'] and values['TRACEGUARD_OIDC_REDIRECT_URI'] != origin + '/auth/oidc/callback':
        invalid.append('TRACEGUARD_OIDC_REDIRECT_URI')
    if origin and values['TRACEGUARD_OIDC_POST_LOGOUT_REDIRECT_URI'] and values['TRACEGUARD_OIDC_POST_LOGOUT_REDIRECT_URI'] != origin + '/sign-in':
        invalid.append('TRACEGUARD_OIDC_POST_LOGOUT_REDIRECT_URI')

    return OIDCConfiguration(
        values=values,
        missing=missing,
        invalid=tuple(dict.fromkeys(invalid)),
    )
