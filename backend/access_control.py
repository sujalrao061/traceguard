"""Server-side access-control primitives for a future TraceGuard deployment.

The hosted TraceGuard portfolio stays synthetic-only and does not call these
primitives to sign anyone in.  This module is intentionally separate from an
identity-provider adapter: an adapter must validate an SSO assertion before it
can create a principal or issue a session here.

The code exists so the production design has concrete, testable safeguards:

* SQLite records are tenant-scoped and can use a durable database path.
* Subject identifiers are converted to keyed digests before persistence.
* Sessions are random opaque values; only keyed digests are stored.
* Authorization checks the server-side tenant, approval, and allowed role.
* Audit records form a keyed hash chain and SQLite rejects application-level
  updates and deletes from the audit table.

This is a foundation, not a complete authentication service.  It never
contacts Entra, Okta, an email service, an SMS service, or an authenticator.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import math
import re
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Callable, Iterable


ALLOWED_ROLES = frozenset({'Owner', 'Lab Assistant'})
_SAFE_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]{2,63}$')
_SAFE_PURPOSE = re.compile(r'^[a-z0-9][a-z0-9-]{2,63}$')


class AccessControlError(ValueError):
    """Raised when a caller supplies an invalid access-control value."""


class AccessDenied(PermissionError):
    """Raised when server-side tenant or role authorization fails."""


class AuditIntegrityError(RuntimeError):
    """Raised when an audit-chain verification cannot succeed."""


@dataclass(frozen=True)
class SessionGrant:
    """The one-time return value from a trusted session issuer.

    ``token`` is deliberately omitted from the database and must be sent only
    in a Secure, HttpOnly, SameSite cookie by a future web adapter.
    """

    token: str
    tenant_id: str
    principal_id: str
    role: str
    issued_at: int
    expires_at: int


@dataclass(frozen=True)
class AuthorizationContext:
    """A server-verified identity scope for one authorized request."""

    tenant_id: str
    principal_id: str
    role: str
    session_id: str


@dataclass(frozen=True)
class RateLimitResult:
    """A result returned without exposing any account or token information."""

    allowed: bool
    retry_after_seconds: int
    limit: int


def _validate_id(value: str, label: str) -> str:
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
        raise AccessControlError(f'{label} must be an opaque identifier.')
    return value


def _validate_role(value: str) -> str:
    if value not in ALLOWED_ROLES:
        raise AccessControlError('role is not allowed.')
    return value


def _validate_purpose(value: str) -> str:
    if not isinstance(value, str) or not _SAFE_PURPOSE.fullmatch(value):
        raise AccessControlError('purpose must be a short, non-sensitive purpose code.')
    return value


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


class SessionTokenService:
    """Issues random, opaque session values and produces keyed storage digests."""

    def __init__(self, secret: bytes):
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise AccessControlError('session secret must contain at least 32 bytes.')
        self._secret = secret

    def issue(self) -> tuple[str, str]:
        # 256 bits of randomness avoids readable or predictable session IDs.
        token = secrets.token_urlsafe(32)
        return token, self.digest(token)

    def digest(self, token: str) -> str:
        if not isinstance(token, str) or not 32 <= len(token) <= 256:
            raise AccessDenied('Session is not authorized.')
        try:
            encoded_token = token.encode('ascii', 'strict')
        except UnicodeEncodeError as exc:
            raise AccessDenied('Session is not authorized.') from exc
        return hmac.new(
            self._secret,
            b'traceguard-session-v1\\x00' + encoded_token,
            hashlib.sha256,
        ).hexdigest()


class RequestRateLimiter:
    """Small in-process sliding-window limiter for the local API.

    It keys on the ASGI peer address and never trusts X-Forwarded-For.  A
    deployed multi-instance service should replace this with a shared limiter
    at the trusted edge, while keeping this application-level defense.
    """

    def __init__(
        self,
        *,
        api_limit: int = 120,
        api_window_seconds: int = 60,
        auth_limit: int = 12,
        auth_window_seconds: int = 60,
        clock: Callable[[], float] | None = None,
    ):
        for value, label in (
            (api_limit, 'api_limit'),
            (api_window_seconds, 'api_window_seconds'),
            (auth_limit, 'auth_limit'),
            (auth_window_seconds, 'auth_window_seconds'),
        ):
            if not isinstance(value, int) or value < 1:
                raise AccessControlError(f'{label} must be a positive integer.')
        self._limits = {
            'api': (api_limit, api_window_seconds),
            'auth': (auth_limit, auth_window_seconds),
        }
        self._clock = clock or time.monotonic
        self._buckets: dict[tuple[str, str], deque[float]] = {}
        self._lock = threading.Lock()

    def consume(self, scope: str, client_key: str) -> RateLimitResult:
        if scope not in self._limits:
            raise AccessControlError('unknown rate-limit scope.')
        # A host supplied by ASGI may be IPv4, IPv6, or an internal test peer.
        # It never becomes a response field.
        if not isinstance(client_key, str) or not client_key or len(client_key) > 255:
            client_key = 'unknown-peer'
        limit, window = self._limits[scope]
        now = self._clock()
        with self._lock:
            bucket = self._buckets.setdefault((scope, client_key), deque())
            threshold = now - window
            while bucket and bucket[0] <= threshold:
                bucket.popleft()
            if len(bucket) >= limit:
                retry_after = max(1, math.ceil(bucket[0] + window - now))
                return RateLimitResult(False, retry_after, limit)
            bucket.append(now)
            return RateLimitResult(True, 0, limit)

    def consume_request(self, path: str, client_key: str) -> RateLimitResult:
        return self.consume('auth' if path.startswith('/auth/') else 'api', client_key)


class ProductionAccessStore:
    """Tenant, approval, opaque-session, and tamper-evident audit storage.

    ``database_path`` can be a SQLite file for durable storage.  The default
    ``:memory:`` path is appropriate only for tests and the disconnected local
    lab.  A future deployment must use protected encrypted storage, a
    separately managed secret, backups, and an external audit-review process.
    """

    def __init__(
        self,
        database_path: str = ':memory:',
        *,
        secret: bytes | None = None,
        clock: Callable[[], float] | None = None,
    ):
        if not isinstance(database_path, str) or not database_path:
            raise AccessControlError('database_path must be a SQLite path.')
        self.database_path = database_path
        self._durable = database_path != ':memory:'
        if self._durable:
            # Resolve the path before SQLite opens it so status output cannot
            # mistake an in-memory URI for protected persistence.  The path is
            # never returned from a public endpoint.
            Path(database_path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
        self._secret = secret or secrets.token_bytes(32)
        if not isinstance(self._secret, bytes) or len(self._secret) < 32:
            raise AccessControlError('access-control secret must contain at least 32 bytes.')
        self._token_service = SessionTokenService(
            hmac.new(self._secret, b'traceguard-session-key-v1', hashlib.sha256).digest()
        )
        self._identity_key = hmac.new(self._secret, b'traceguard-identity-key-v1', hashlib.sha256).digest()
        self._audit_key = hmac.new(self._secret, b'traceguard-audit-key-v1', hashlib.sha256).digest()
        self._clock = clock or time.time
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(database_path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute('PRAGMA foreign_keys = ON')
        if self._durable:
            # WAL improves crash resilience. Encryption and file permissions
            # remain deployment responsibilities and are reported as such.
            self._connection.execute('PRAGMA journal_mode = WAL')
            self._connection.execute('PRAGMA synchronous = FULL')
        self._create_schema()

    @property
    def durable_storage_configured(self) -> bool:
        return self._durable

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _create_schema(self) -> None:
        with self._lock, self._connection:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS access_tenants (
                    tenant_id TEXT PRIMARY KEY,
                    created_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS access_principals (
                    principal_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL REFERENCES access_tenants(tenant_id),
                    subject_digest TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    UNIQUE (tenant_id, subject_digest)
                );
                CREATE INDEX IF NOT EXISTS idx_access_principals_tenant
                    ON access_principals(tenant_id, principal_id);

                CREATE TABLE IF NOT EXISTS access_approvals (
                    approval_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL REFERENCES access_tenants(tenant_id),
                    principal_id TEXT NOT NULL REFERENCES access_principals(principal_id),
                    role TEXT NOT NULL CHECK(role IN ('Owner', 'Lab Assistant')),
                    purpose_code TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('active', 'revoked')),
                    approved_by_principal_id TEXT REFERENCES access_principals(principal_id),
                    approved_at INTEGER NOT NULL,
                    expires_at INTEGER,
                    revoked_at INTEGER,
                    revoked_by_principal_id TEXT REFERENCES access_principals(principal_id),
                    CHECK((status = 'active' AND revoked_at IS NULL AND revoked_by_principal_id IS NULL)
                        OR (status = 'revoked' AND revoked_at IS NOT NULL AND revoked_by_principal_id IS NOT NULL))
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_access_approval
                    ON access_approvals(tenant_id, principal_id) WHERE status = 'active';
                CREATE INDEX IF NOT EXISTS idx_access_approvals_principal
                    ON access_approvals(tenant_id, principal_id, status);

                CREATE TABLE IF NOT EXISTS access_sessions (
                    session_digest TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL REFERENCES access_tenants(tenant_id),
                    principal_id TEXT NOT NULL REFERENCES access_principals(principal_id),
                    approval_id TEXT NOT NULL REFERENCES access_approvals(approval_id),
                    issued_at INTEGER NOT NULL,
                    absolute_expires_at INTEGER NOT NULL,
                    idle_expires_at INTEGER NOT NULL,
                    idle_timeout_seconds INTEGER NOT NULL,
                    last_seen_at INTEGER NOT NULL,
                    revoked_at INTEGER,
                    revocation_reason_code TEXT,
                    CHECK(absolute_expires_at > issued_at),
                    CHECK(idle_expires_at >= issued_at),
                    CHECK(idle_timeout_seconds >= 60)
                );
                CREATE INDEX IF NOT EXISTS idx_access_sessions_principal
                    ON access_sessions(tenant_id, principal_id, revoked_at);

                CREATE TABLE IF NOT EXISTS access_audit_log (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    audit_id TEXT NOT NULL UNIQUE,
                    occurred_at INTEGER NOT NULL,
                    tenant_id TEXT NOT NULL REFERENCES access_tenants(tenant_id),
                    actor_principal_id TEXT,
                    action TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE
                );
                CREATE TRIGGER IF NOT EXISTS prevent_access_audit_update
                BEFORE UPDATE ON access_audit_log
                BEGIN
                    SELECT RAISE(ABORT, 'access audit records are append-only');
                END;
                CREATE TRIGGER IF NOT EXISTS prevent_access_audit_delete
                BEFORE DELETE ON access_audit_log
                BEGIN
                    SELECT RAISE(ABORT, 'access audit records are append-only');
                END;
                """
            )

    def _now(self) -> int:
        return int(self._clock())

    @staticmethod
    def _new_id(prefix: str) -> str:
        # token_urlsafe uses URL-safe opaque data and the prefix keeps record
        # kinds clear in protected administrator tooling without exposing data.
        return prefix + secrets.token_urlsafe(18)

    def _subject_digest(self, validated_subject: str) -> str:
        if not isinstance(validated_subject, str) or not 1 <= len(validated_subject) <= 512:
            raise AccessControlError('validated_subject must be a non-empty value from a trusted identity adapter.')
        return hmac.new(
            self._identity_key,
            b'traceguard-subject-v1\\x00' + validated_subject.encode('utf-8'),
            hashlib.sha256,
        ).hexdigest()

    def _tenant_exists(self, tenant_id: str) -> bool:
        return self._connection.execute(
            'SELECT 1 FROM access_tenants WHERE tenant_id = ?', (tenant_id,)
        ).fetchone() is not None

    def _principal_in_tenant(self, tenant_id: str, principal_id: str) -> bool:
        return self._connection.execute(
            'SELECT 1 FROM access_principals WHERE tenant_id = ? AND principal_id = ?',
            (tenant_id, principal_id),
        ).fetchone() is not None

    def _active_approval(self, tenant_id: str, principal_id: str, now: int | None = None) -> sqlite3.Row | None:
        now = self._now() if now is None else now
        return self._connection.execute(
            """
            SELECT approval_id, tenant_id, principal_id, role, purpose_code, approved_at, expires_at
            FROM access_approvals
            WHERE tenant_id = ? AND principal_id = ? AND status = 'active'
              AND (expires_at IS NULL OR expires_at > ?)
            """,
            (tenant_id, principal_id, now),
        ).fetchone()

    def _require_owner(self, tenant_id: str, principal_id: str, now: int | None = None) -> sqlite3.Row:
        approval = self._active_approval(tenant_id, principal_id, now)
        if approval is None or approval['role'] != 'Owner':
            raise AccessDenied('Access is not authorized.')
        return approval

    def _append_audit(
        self,
        *,
        tenant_id: str,
        actor_principal_id: str | None,
        action: str,
        target_type: str,
        target_id: str,
        details: dict[str, object],
        occurred_at: int,
    ) -> str:
        """Append one tamper-evident audit record inside the caller transaction."""
        last = self._connection.execute(
            'SELECT event_hash FROM access_audit_log ORDER BY sequence DESC LIMIT 1'
        ).fetchone()
        previous_hash = last['event_hash'] if last else '0' * 64
        audit_id = self._new_id('aud_')
        details_json = _canonical_json(details)
        signed = {
            'audit_id': audit_id,
            'occurred_at': occurred_at,
            'tenant_id': tenant_id,
            'actor_principal_id': actor_principal_id,
            'action': action,
            'target_type': target_type,
            'target_id': target_id,
            'details_json': details_json,
            'previous_hash': previous_hash,
        }
        event_hash = hmac.new(
            self._audit_key,
            _canonical_json(signed).encode('ascii'),
            hashlib.sha256,
        ).hexdigest()
        self._connection.execute(
            """
            INSERT INTO access_audit_log(
                audit_id, occurred_at, tenant_id, actor_principal_id, action,
                target_type, target_id, details_json, previous_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                audit_id,
                occurred_at,
                tenant_id,
                actor_principal_id,
                action,
                target_type,
                target_id,
                details_json,
                previous_hash,
                event_hash,
            ),
        )
        return audit_id

    def create_tenant(self, tenant_id: str) -> None:
        """Create a tenant namespace from a deployment-controlled opaque ID."""
        tenant_id = _validate_id(tenant_id, 'tenant_id')
        now = self._now()
        with self._lock, self._connection:
            try:
                self._connection.execute(
                    'INSERT INTO access_tenants(tenant_id, created_at) VALUES (?, ?)',
                    (tenant_id, now),
                )
            except sqlite3.IntegrityError as exc:
                raise AccessControlError('tenant already exists.') from exc

    def register_principal(self, tenant_id: str, principal_id: str, validated_subject: str) -> None:
        """Persist a tenant-bound principal without storing its raw IdP subject."""
        tenant_id = _validate_id(tenant_id, 'tenant_id')
        principal_id = _validate_id(principal_id, 'principal_id')
        subject_digest = self._subject_digest(validated_subject)
        now = self._now()
        with self._lock, self._connection:
            if not self._tenant_exists(tenant_id):
                raise AccessControlError('tenant does not exist.')
            try:
                self._connection.execute(
                    """
                    INSERT INTO access_principals(principal_id, tenant_id, subject_digest, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (principal_id, tenant_id, subject_digest, now),
                )
            except sqlite3.IntegrityError as exc:
                raise AccessControlError('principal already exists for this tenant.') from exc

    def bootstrap_owner(self, tenant_id: str, principal_id: str, *, purpose: str = 'initial-owner') -> str:
        """Create the one initial owner via a trusted deployment-only bootstrap.

        This is deliberately not exposed as an HTTP endpoint.  A real service
        would run it once from a protected provisioning workflow after SSO
        identity validation and record the change in an external review log.
        """
        tenant_id = _validate_id(tenant_id, 'tenant_id')
        principal_id = _validate_id(principal_id, 'principal_id')
        purpose = _validate_purpose(purpose)
        now = self._now()
        with self._lock, self._connection:
            if not self._principal_in_tenant(tenant_id, principal_id):
                raise AccessControlError('principal does not belong to tenant.')
            existing = self._connection.execute(
                """
                SELECT 1 FROM access_approvals
                WHERE tenant_id = ? AND role = 'Owner' AND status = 'active'
                  AND (expires_at IS NULL OR expires_at > ?)
                """,
                (tenant_id, now),
            ).fetchone()
            if existing is not None:
                raise AccessDenied('An initial owner already exists for this tenant.')
            approval_id = self._new_id('apr_')
            self._connection.execute(
                """
                INSERT INTO access_approvals(
                    approval_id, tenant_id, principal_id, role, purpose_code,
                    status, approved_by_principal_id, approved_at, expires_at,
                    revoked_at, revoked_by_principal_id
                ) VALUES (?, ?, ?, 'Owner', ?, 'active', NULL, ?, NULL, NULL, NULL)
                """,
                (approval_id, tenant_id, principal_id, purpose, now),
            )
            self._append_audit(
                tenant_id=tenant_id,
                actor_principal_id=None,
                action='owner_bootstrapped',
                target_type='access_approval',
                target_id=approval_id,
                details={'role': 'Owner', 'purpose_code': purpose},
                occurred_at=now,
            )
            return approval_id

    def approve_access(
        self,
        tenant_id: str,
        actor_principal_id: str,
        target_principal_id: str,
        role: str,
        *,
        purpose: str,
        expires_at: int | None = None,
    ) -> str:
        """Approve one principal after an active owner authorizes the request."""
        tenant_id = _validate_id(tenant_id, 'tenant_id')
        actor_principal_id = _validate_id(actor_principal_id, 'actor_principal_id')
        target_principal_id = _validate_id(target_principal_id, 'target_principal_id')
        role = _validate_role(role)
        purpose = _validate_purpose(purpose)
        now = self._now()
        if expires_at is not None and (not isinstance(expires_at, int) or expires_at <= now):
            raise AccessControlError('expires_at must be a future Unix timestamp.')
        with self._lock, self._connection:
            self._require_owner(tenant_id, actor_principal_id, now)
            if not self._principal_in_tenant(tenant_id, target_principal_id):
                raise AccessDenied('Access is not authorized.')
            if self._active_approval(tenant_id, target_principal_id, now) is not None:
                raise AccessControlError('target principal already has active access.')
            approval_id = self._new_id('apr_')
            self._connection.execute(
                """
                INSERT INTO access_approvals(
                    approval_id, tenant_id, principal_id, role, purpose_code,
                    status, approved_by_principal_id, approved_at, expires_at,
                    revoked_at, revoked_by_principal_id
                ) VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, NULL, NULL)
                """,
                (
                    approval_id,
                    tenant_id,
                    target_principal_id,
                    role,
                    purpose,
                    actor_principal_id,
                    now,
                    expires_at,
                ),
            )
            self._append_audit(
                tenant_id=tenant_id,
                actor_principal_id=actor_principal_id,
                action='access_approved',
                target_type='access_approval',
                target_id=approval_id,
                details={'role': role, 'purpose_code': purpose, 'expires_at': expires_at},
                occurred_at=now,
            )
            return approval_id

    def revoke_access(self, tenant_id: str, actor_principal_id: str, target_principal_id: str) -> int:
        """Revoke active access and all corresponding sessions in one transaction."""
        tenant_id = _validate_id(tenant_id, 'tenant_id')
        actor_principal_id = _validate_id(actor_principal_id, 'actor_principal_id')
        target_principal_id = _validate_id(target_principal_id, 'target_principal_id')
        now = self._now()
        with self._lock, self._connection:
            self._require_owner(tenant_id, actor_principal_id, now)
            approval = self._active_approval(tenant_id, target_principal_id, now)
            if approval is None:
                raise AccessDenied('Access is not authorized.')
            if approval['role'] == 'Owner':
                owner_count = self._connection.execute(
                    """
                    SELECT COUNT(*) AS count FROM access_approvals
                    WHERE tenant_id = ? AND role = 'Owner' AND status = 'active'
                      AND (expires_at IS NULL OR expires_at > ?)
                    """,
                    (tenant_id, now),
                ).fetchone()['count']
                if owner_count <= 1:
                    raise AccessDenied('A tenant must retain an active owner.')
            self._connection.execute(
                """
                UPDATE access_approvals
                SET status = 'revoked', revoked_at = ?, revoked_by_principal_id = ?
                WHERE approval_id = ?
                """,
                (now, actor_principal_id, approval['approval_id']),
            )
            sessions = self._connection.execute(
                """
                UPDATE access_sessions
                SET revoked_at = ?, revocation_reason_code = 'access-revoked'
                WHERE tenant_id = ? AND principal_id = ? AND revoked_at IS NULL
                """,
                (now, tenant_id, target_principal_id),
            ).rowcount
            self._append_audit(
                tenant_id=tenant_id,
                actor_principal_id=actor_principal_id,
                action='access_revoked',
                target_type='access_approval',
                target_id=approval['approval_id'],
                details={'revoked_session_count': sessions},
                occurred_at=now,
            )
            return sessions

    def issue_session(
        self,
        tenant_id: str,
        principal_id: str,
        *,
        absolute_lifetime_seconds: int = 8 * 60 * 60,
        idle_timeout_seconds: int = 15 * 60,
    ) -> SessionGrant:
        """Issue a server-side session after a trusted SSO adapter validates identity.

        This method performs authorization but does *not* authenticate a caller.
        It must be called only by a reviewed callback after token validation,
        PKCE/nonce verification, tenant validation, and MFA policy enforcement.
        """
        tenant_id = _validate_id(tenant_id, 'tenant_id')
        principal_id = _validate_id(principal_id, 'principal_id')
        for value, label in (
            (absolute_lifetime_seconds, 'absolute_lifetime_seconds'),
            (idle_timeout_seconds, 'idle_timeout_seconds'),
        ):
            if not isinstance(value, int) or value < 60 or value > 24 * 60 * 60:
                raise AccessControlError(f'{label} must be between 60 seconds and 24 hours.')
        if idle_timeout_seconds > absolute_lifetime_seconds:
            raise AccessControlError('idle timeout cannot exceed absolute session lifetime.')
        now = self._now()
        with self._lock, self._connection:
            approval = self._active_approval(tenant_id, principal_id, now)
            if approval is None:
                raise AccessDenied('Access is not authorized.')
            token, session_digest = self._token_service.issue()
            absolute_expires_at = now + absolute_lifetime_seconds
            idle_expires_at = min(absolute_expires_at, now + idle_timeout_seconds)
            self._connection.execute(
                """
                INSERT INTO access_sessions(
                    session_digest, tenant_id, principal_id, approval_id, issued_at,
                    absolute_expires_at, idle_expires_at, idle_timeout_seconds,
                    last_seen_at, revoked_at, revocation_reason_code
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
                """,
                (
                    session_digest,
                    tenant_id,
                    principal_id,
                    approval['approval_id'],
                    now,
                    absolute_expires_at,
                    idle_expires_at,
                    idle_timeout_seconds,
                    now,
                ),
            )
            self._append_audit(
                tenant_id=tenant_id,
                actor_principal_id=principal_id,
                action='session_issued',
                target_type='server_session',
                target_id=session_digest,
                details={'role': approval['role'], 'absolute_expires_at': absolute_expires_at},
                occurred_at=now,
            )
            return SessionGrant(
                token=token,
                tenant_id=tenant_id,
                principal_id=principal_id,
                role=approval['role'],
                issued_at=now,
                expires_at=absolute_expires_at,
            )

    def authorize_session(
        self,
        token: str,
        tenant_id: str,
        required_roles: Iterable[str] | None = None,
    ) -> AuthorizationContext:
        """Resolve an opaque token and enforce tenant plus least-privilege role."""
        tenant_id = _validate_id(tenant_id, 'tenant_id')
        allowed_roles = ALLOWED_ROLES if required_roles is None else frozenset(required_roles)
        if not allowed_roles or not allowed_roles.issubset(ALLOWED_ROLES):
            raise AccessControlError('required_roles must be a non-empty subset of allowed roles.')
        try:
            session_digest = self._token_service.digest(token)
        except (AccessDenied, UnicodeError):
            raise AccessDenied('Session is not authorized.') from None
        now = self._now()
        with self._lock, self._connection:
            session = self._connection.execute(
                """
                SELECT session_digest, tenant_id, principal_id, approval_id,
                       absolute_expires_at, idle_expires_at, idle_timeout_seconds, revoked_at
                FROM access_sessions WHERE session_digest = ?
                """,
                (session_digest,),
            ).fetchone()
            if (
                session is None
                or session['tenant_id'] != tenant_id
                or session['revoked_at'] is not None
                or now >= session['absolute_expires_at']
                or now >= session['idle_expires_at']
            ):
                raise AccessDenied('Session is not authorized.')
            approval = self._active_approval(tenant_id, session['principal_id'], now)
            if approval is None or approval['approval_id'] != session['approval_id'] or approval['role'] not in allowed_roles:
                raise AccessDenied('Session is not authorized.')
            next_idle_expiry = min(session['absolute_expires_at'], now + session['idle_timeout_seconds'])
            self._connection.execute(
                """
                UPDATE access_sessions SET last_seen_at = ?, idle_expires_at = ?
                WHERE session_digest = ?
                """,
                (now, next_idle_expiry, session_digest),
            )
            return AuthorizationContext(
                tenant_id=tenant_id,
                principal_id=session['principal_id'],
                role=approval['role'],
                session_id=session_digest,
            )

    def verify_audit_chain(self) -> bool:
        """Verify the append-only, keyed audit chain without returning records."""
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT audit_id, occurred_at, tenant_id, actor_principal_id, action,
                       target_type, target_id, details_json, previous_hash, event_hash
                FROM access_audit_log ORDER BY sequence ASC
                """
            ).fetchall()
            previous_hash = '0' * 64
            for row in rows:
                try:
                    # Parsing ensures a database value cannot exploit a
                    # different serialization form during verification.
                    details = json.loads(row['details_json'])
                    details_json = _canonical_json(details)
                except (TypeError, ValueError, json.JSONDecodeError):
                    return False
                if details_json != row['details_json'] or row['previous_hash'] != previous_hash:
                    return False
                signed = {
                    'audit_id': row['audit_id'],
                    'occurred_at': row['occurred_at'],
                    'tenant_id': row['tenant_id'],
                    'actor_principal_id': row['actor_principal_id'],
                    'action': row['action'],
                    'target_type': row['target_type'],
                    'target_id': row['target_id'],
                    'details_json': row['details_json'],
                    'previous_hash': row['previous_hash'],
                }
                expected_hash = hmac.new(
                    self._audit_key,
                    _canonical_json(signed).encode('ascii'),
                    hashlib.sha256,
                ).hexdigest()
                if not hmac.compare_digest(expected_hash, row['event_hash']):
                    return False
                previous_hash = row['event_hash']
            return True

    def system_control_status(self, *, rate_limiting_active: bool) -> dict[str, object]:
        """Return safe, local control evidence for an owner-facing status view.

        The result intentionally describes only what this process can observe:
        its access-control implementation, the current audit-chain check, the
        selected SQLite mode, and the local limiter.  It never treats a
        configuration choice as proof that an operator has enabled encryption,
        backups, external monitoring, or a live identity integration.
        """
        audit_chain_valid = self.verify_audit_chain()
        return {
            'authorization': {
                'state': 'implemented-disconnected',
                'scope': (
                    'The foundation can enforce tenant-scoped, default-deny approval and allowed-role checks after '
                    'a trusted identity adapter validates a person. It does not authenticate a person or grant live access.'
                ),
            },
            'sessions': {
                'state': 'implemented-disconnected',
                'scope': (
                    'Opaque server-side session records support idle expiry, absolute expiry, and revocation, but no '
                    'browser session or identity-provider callback is enabled in this lab.'
                ),
            },
            'audit_integrity': {
                'state': 'current-chain-verifies' if audit_chain_valid else 'integrity-check-failed',
                'scope': (
                    'This checks the locally reachable access-audit hash chain. It is not evidence of audit retention, '
                    'independent review, archival, backup, or disaster recovery.'
                ),
            },
            'storage': {
                'state': 'durable-path-configured-unverified' if self._durable else 'ephemeral-local-lab',
                'scope': (
                    'A durable SQLite path is not proof of encryption, restrictive filesystem permissions, key management, '
                    'backups, or recovery testing.'
                ),
            },
            'rate_limiting': {
                'state': 'in-process-active' if rate_limiting_active else 'not-reported',
                'scope': (
                    'This describes the local application instance only. Shared edge limiting, trusted-proxy configuration, '
                    'and distributed monitoring require separate operator evidence.'
                ),
            },
        }

    def public_status(self, *, rate_limiting_active: bool) -> dict[str, object]:
        """Return implementation status without identifiers, records, or secrets."""
        system_controls = self.system_control_status(rate_limiting_active=rate_limiting_active)
        return {
            'label': 'TraceGuard server-side access-control foundation',
            'classification': 'synthetic-only foundation — live SSO remains disconnected',
            'production_ready': False,
            'live_sign_in_enabled': False,
            'identity_provider_connection': 'not-connected',
            'storage': 'durable SQLite configured' if self._durable else 'ephemeral SQLite for local lab',
            'durable_storage_configured': self._durable,
            'implemented_controls': [
                'Default-deny tenant-scoped approvals for Owner and Lab Assistant roles',
                'Opaque server-side session records with idle, absolute, and revocation checks',
                'Tamper-evident append-only audit records with SQLite update/delete protection',
                'In-process request rate limiting without trusting forwarded client addresses',
            ],
            'activation_gates': [
                'Validate OIDC or SAML assertions, issuer, audience, tenant, nonce, PKCE, and MFA policy before calling this module.',
                'Use encrypted durable storage with restrictive operating-system permissions, backups, retention rules, and key management.',
                'Set a separately managed session/audit secret and run external audit review plus monitoring.',
                'Deploy shared edge rate limiting and monitoring before serving more than one application instance.',
            ],
            'audit_chain_valid': system_controls['audit_integrity']['state'] == 'current-chain-verifies',
            'rate_limiting_active': rate_limiting_active,
            'system_controls': system_controls,
            'safety_boundary': (
                'No real tenant, person, device, session, token, password, passkey, phone number, OTP, '
                'provider claim, or audit record is returned by this status endpoint.'
            ),
        }
