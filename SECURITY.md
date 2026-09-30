# Security scope and threat model

## Boundary

TraceGuard v0.1 is a synthetic-data portfolio lab. It does not promise zero leaks and must not be used with customer security logs, credentials, personal data, or production systems.

The local role-selection screen and local API are not an OIDC implementation. A production deployment needs a server-side identity integration, verified issuer/tenant/audience claims, trusted role mapping, protected sessions, revocation, and durable tenant-scoped audit records. See [the production SSO deployment guide](docs/PRODUCTION_SSO.md); [`.env.example`](.env.example) contains placeholders only and must never be treated as live authentication configuration for this lab.

## Implemented controls

| Risk | Current control | Remaining limitation |
|---|---|---|
| Accidental real-data import | Exact schema, demo-prefixed account names, documentation IPs, bounded size and record count | A user could encode sensitive information in allowed identifiers or notes; validation is not a DLP system |
| Browser exfiltration | No fetch, analytics, external fonts, CDN scripts, or model API; CSP `connect-src 'none'` | Browser extensions, compromised devices, and hosting infrastructure are outside this application boundary |
| Stored or DOM XSS | User-controlled strings HTML-escaped; no imported markup execution; restrictive script policy | Browser security testing is limited; not an independent penetration test |
| Unintended persistence | Hosted app keeps records and notes in tab memory only; no localStorage, cookies, IndexedDB, or service worker in app code | Exported files persist; browsers/OS may retain memory, history, or crash data |
| Demo sign-in mistaken for real access control | The local sign-in screen is labeled as a synthetic onboarding and role simulation; it accepts no password and creates no authenticated account, cookie, or server session | It cannot prove identity, enforce tenant access, or protect customer data; a browser-selected role is never a production authorization decision |
| Unapproved employee or cross-company access | The browser lab has no live organization or user. A disconnected server-side foundation tests tenant-scoped approvals, allowed roles, opaque sessions, revocation, and audit integrity without accepting a real identity. | Production must default-deny access, validate the IdP token and exact tenant before invoking the foundation, use named IdP-managed accounts, prohibit shared accounts and browser-selected roles, and enforce tenant/role checks on every server operation. |
| Weak second factor | No real sign-in occurs in the lab | Production should prefer passkeys/WebAuthn and may use authenticator-app TOTP; SMS/phone OTP and network/Wi-Fi presence must never be the sole factor because they do not reliably prove the person is authorized |
| Excess export | Source addresses replaced; analyst notes excluded; summary includes only identifiers/severity/status/time | Downloaded files can be copied or shared by the recipient |
| Unauthenticated API access | Localhost binding, required random bearer token, constant-time comparison, no CORS, Origin rejection | Single-user local lab only; bearer token is not tenant authorization |
| Cross-company data exposure | The lab accepts only synthetic fixtures and has no customer tenants, live connector, or production identity data | A real tenant boundary does not exist until server-enforced tenant authorization, scoped queries, scoped exports, and adversarial isolation tests are implemented |
| Unsafe account or device remediation | Account Containment is a local demonstration with no identity-provider, EDR, MDM, or device-control connection | No password reset, session revocation, account disablement, endpoint isolation, or USB restriction can occur from this build |
| SQL injection | Parameterized insert/select queries, fixed schema | No production database deployment or encryption-at-rest configuration |
| Partial dataset corruption | Complete validation before transaction, atomic replacement | No persistent recovery system |
| Prompt injection | No LLM or free-form tool executor connected | Future AI integration requires a separate assessment |

The `_headers` file requests HTTP protections on compatible static hosts; the HTML includes a CSP and referrer-policy fallback. Frame restrictions require response headers. Production header behavior should be verified on the final hosting environment before treating it as a security guarantee. Source repository access and the hosted site's audience must remain private unless deliberately changed.

## Important behavior

- Profiles are session-only display preferences, not authenticated accounts. Name and bio values are length-bounded and escaped before HTML rendering; no credentials, email fields, photo uploads, or external profile service are used.
- The sign-in page is a local, synthetic onboarding and role simulation. It does not collect, store, or verify passwords; issue cookies; create a server-side session; or authenticate a real user or company. Its selected role is presentation state only.
- In a production organization, the starting policy should be default-deny: an Organization Owner or delegated administrator provisions a named user through the identity provider, then assigns a narrowly scoped role. A small deployment may intentionally authorize only the Owner and Lab Assistant. An employee must not be able to grant themselves access, choose another company's tenant, or use a shared administrative account.
- A Wi-Fi connection or a phone number alone is not proof that the approved person is signing in. Production should prefer passkeys/WebAuthn, allow authenticator-app TOTP where required, and treat SMS as a guarded recovery path rather than the only factor.
- Bookmarks reference the current rule/account/IP combination and are cleared when replacing a dataset to avoid carrying them to unrelated events. They are not exported.

- Dataset replacement and clearing are destructive only to the current disposable lab session and have UI confirmations.
- Rule changes may discard the removed rule's case notes. A visible notice explains this behavior.
- Dispositions, notes, and the session audit log are client-side state, not tamper-proof records or enforceable authorization.
- AI is not connected; do not describe the generated brief as an AI result.
- Detection rules emit one alert per rule/account/IP per dataset. They do not segment repeated incidents or establish malicious intent.
- No automatic remediation, shell execution, network scanning, email, or account blocking exists.
- The Account Containment & Tenant Boundary experience is a design demonstration, not an authentication system or a real tenant boundary. Do not present an on-screen workflow step as an executed action.
- This build cannot terminate an account session, reset or set a password, change MFA, disable an account, isolate an endpoint, or block a USB device. A successful sign-in after failed attempts remains an investigation signal until evidence and an approved response policy support containment.
- Identity containment and endpoint/USB protection are separate control planes. Production identity actions should be performed through a least-privilege identity-provider integration; endpoint isolation and USB policy should be enforced by reviewed EDR, MDM, or operating-system device controls.
- The local API disables raw request/access logging and returns generic validation errors without echoing input. Server errors and infrastructure logging still require review before production.

## Before any customer-data deployment

1. Define accepted data, classification, retention, deletion, and processor agreements.
2. Add established authentication through company SSO using OIDC or SAML. Default-deny each company: the Organization Owner or delegated administrator must provision named accounts and narrowly scoped roles (for example, only Owner and Lab Assistant during a pilot), with no shared administrator account or client-side role selection. Prefer passkeys/WebAuthn, allow authenticator-app TOTP where needed, and do not use SMS/phone OTP or Wi-Fi/network presence as the sole factor.
3. Verify the identity-provider token server-side; derive tenant and role from trusted claims; issue short-lived server-side sessions; require fresh MFA for sensitive actions; support IdP-led session/device revocation; and keep durable login, logout, failed-login, role-change, and revocation audit records.
4. Enforce authorization and tenant isolation with adversarial tests. Scope every query, export, audit record, and connector operation to authenticated server context, and verify that a request cannot cross into another company.
5. Define reviewed containment playbooks with confidence thresholds, approval requirements, emergency exceptions, notification paths, recovery steps, audit retention, and a tested rollback path.
6. Integrate with an identity provider using least-privilege scopes for session revocation and recovery workflows. Do not collect or directly manage end-user passwords.
7. Integrate endpoint isolation and USB/device controls through separately governed EDR, MDM, or operating-system policy; test permissions, audit events, and recovery for each action.
8. Use a managed database, encryption, secrets management, backups, and tested deletion procedures.
9. Add rate limits, ingestion queues, strict upload parsing, trusted proxies, suspicious-access monitoring, audit retention, and monitoring.
10. Minimize/redact model input, scope read-only tools, prevent arbitrary execution, and evaluate injection attempts.
11. Perform dependency review, security testing, and an independent review; document residual risks.

## Verification in this build

Automated tests exercise detection thresholds/windows/order/source separation; strict schema and real-address rejection; evidence references; SQL query parameterization; atomic import; API auth; cross-origin denial; request-size limits; tenant-scoped approval checks; opaque-session expiry and revocation; final-owner protection; append-only audit-chain integrity; durable-store reopening with a stable secret; and request-rate limiting. Browser checks exercise investigation generation, safe text rendering, case decisions, evaluations, responsive layouts, and the read-only WebMCP tool. These checks do not verify live IdP token validation, password resets, endpoint isolation, USB control, a distributed rate limiter, production monitoring, managed backups, or a real multi-company deployment. They support a lab demonstration and a tested server-side foundation, not a production security certification.
