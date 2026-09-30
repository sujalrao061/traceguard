# Production operations and launch runbook

TraceGuard is still a synthetic portfolio lab. This runbook describes the controls that must be operating before a company connects real identities, events, or systems. It is not evidence that those controls are active in the browser demo.

## Owners and approvals

| Responsibility | Accountable party | Required decision |
|---|---|---|
| Tenant access | Organization Owner | Approves each named Owner or Lab Assistant and removes access when it is no longer needed. |
| Identity integration | Company identity administrator | Reviews the exact issuer, tenant, callback addresses, MFA policy, and app-role assignments. |
| Platform operation | Service operator | Maintains the deployment, secret manager, database, backups, monitoring, and incident response. |
| Security launch review | Security reviewer | Approves the threat model, cross-tenant tests, session-revocation drill, retention policy, and rollback plan. |

No shared owner account, browser-selected role, email address, phone number, or office network can grant access.

## Durable storage and audit

Use a managed database with encryption at rest and in transit. Every application record needs a server-verified tenant key, and every query, export, connector action, and audit lookup must apply that key before returning data.

Keep audit data in a protected append-only store or a database table that ordinary application roles cannot alter. Record the event type, time, tenant, immutable actor identifier, request correlation ID, target category, decision, and safe reason. Do not write raw access tokens, client secrets, passwords, OTP values, or unnecessary personal data to audit records.

Minimum audit events include sign-in success or denial, MFA recovery, access approval/removal, role change, session creation/revocation, export, connector authorization, policy change, and privileged admin action.

## Monitoring and rate limits

Send structured, redacted application logs and service health metrics to the company monitoring system. Alert on repeated sign-in denials, failed callback validation, tenant-mismatch attempts, rate-limit spikes, failed exports, session-revocation failures, backup failures, and unexpected permission denials.

Apply rate limits at the edge and application level. Sensitive endpoints such as sign-in, callback, recovery, export, admin changes, and ingestion need separate limits. Use a shared, reviewed rate-limit store in a multi-instance deployment; process-memory limits alone are not enough.

Health checks must distinguish a running process from a healthy database, audit store, identity configuration, and backup path. Never include configuration values, secrets, tokens, tenant lists, or user details in an unauthenticated status response.

## Backup and recovery

- Encrypt backups and store them separately from the primary environment.
- Set retention, deletion, and legal-hold policy with the company before storing customer data.
- Test a full restore into an isolated environment on a regular schedule.
- Record the restore result, recovery time, and any gaps in the protected audit trail.
- Keep an approved, time-limited break-glass procedure that is separately audited. It must not become a permanent shared owner account.

## Staged launch checklist

1. Configure Microsoft Entra or Okta using [the SSO guide](PRODUCTION_SSO.md), with exact HTTPS callback addresses and server-only secrets.
2. Implement and independently review authorization-code flow with PKCE, token signature/issuer/audience/tenant validation, server-side sessions, and IdP-led revocation.
3. Provision one test tenant and named pilot accounts only. Confirm that an unapproved employee and a token from another company are denied.
4. Exercise Owner and Lab Assistant permissions, session revocation, step-up MFA, tenant boundary, audit, rate-limit, backup, restore, and incident-response tests in staging.
5. Obtain company-owner and security-reviewer approval. Launch the smallest approved pilot and review access/audit signals regularly.

If an identity, tenant, session, audit, or backup control fails, pause the pilot, revoke active sessions where appropriate, preserve evidence, and follow the company incident-response process.
