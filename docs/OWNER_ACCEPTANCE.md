# Owner acceptance and rollout checklist

TraceGuard is a synthetic portfolio lab. This checklist describes what a company owner should expect before approving a real pilot. It does not mean the local browser preview has live SSO, backups, monitoring, or company data.

## What an owner needs to see

| Area | Owner question | Evidence required before approval |
|---|---|---|
| Identity | Who can enter the workspace? | Company SSO is configured for the exact tenant, MFA is required, and only named people have approved roles. |
| Access | Can an employee grant themselves more access? | Server-side role checks deny self-approval, prevent removal of the final Owner, and revoke access immediately when approved. |
| Tenant boundary | Can one company see another company's work? | Adversarial tests show that every query, export, audit record, and connector action is scoped to authenticated tenant context. |
| Audit | Can we explain who made a sensitive decision? | Durable append-only audit records show the actor, time, tenant, action, target category, and safe reason. |
| Resilience | Can we recover after an outage or mistake? | Encrypted backups, a documented retention policy, and a tested restore result with recovery time. |
| Operations | Will we know when protection is failing? | Monitored health checks and alert routing for identity failures, revocation failures, audit problems, backup failures, and suspicious access. |
| Data handling | What information leaves our environment? | Approved data-flow, least-privilege connector scopes, retention/deletion rules, and an owner-reviewed pilot agreement. |

## Owner control-center view

An owner-facing dashboard should make status understandable without exposing secrets, tokens, tenant lists, or personal details. Its health cards should answer:

1. **Identity readiness** — Is SSO configured for the intended company tenant, and is MFA required?
2. **Access posture** — How many named people hold each approved role, and are there pending approvals or revocations?
3. **Audit health** — Is the protected audit path receiving records and being reviewed?
4. **Backup readiness** — When was the last successful restore exercise, and who owns the next test?
5. **Monitoring** — Where do critical service and suspicious-access alerts go, and has that route been tested?
6. **Pilot decision** — Which launch gates are complete, blocked, or awaiting an accountable owner?

The local Owner Control Center may demonstrate these decisions with synthetic, session-only status. A real deployment must obtain status from protected server-side services rather than browser state.

## Two-minute onboarding for a pilot

1. The Organization Owner names the security reviewer, identity administrator, and service operator.
2. The identity administrator connects the approved Microsoft Entra or Okta tenant and maps only the approved Owner and Lab Assistant roles.
3. The security reviewer verifies MFA, cross-tenant denial, revocation, audit, rate-limit, and export tests in a non-production tenant.
4. The service operator proves a backup restore and configures monitored alerts for failed identity, audit, backup, and service-health conditions.
5. The Owner approves a smallest-possible, time-bounded pilot with synthetic or approved test-tenant events and a named stop/go decision date.

## Owner notification expectations

The Owner should receive a secure, reviewed notification for:

- a new privileged-role request;
- a role removal or session-revocation failure;
- a cross-tenant authorization denial or repeated sign-in denial spike;
- a broken audit path, failed backup, or failed restore exercise;
- a critical investigation that crosses the agreed response target; and
- a material policy, connector, retention, or export change.

Notifications must contain only the minimum safe context. The linked application view must perform the authorization check again; a notification itself must never grant access.

## Approval decision

An Owner may approve a pilot only after the responsible people provide the evidence above, document any remaining risk, and agree on the rollback and incident-response path. If identity, tenant isolation, audit, monitoring, or backup controls fail, pause the pilot and follow the company response process.

For implementation details, see the [production SSO guide](PRODUCTION_SSO.md) and [production operations runbook](PRODUCTION_OPERATIONS.md).
