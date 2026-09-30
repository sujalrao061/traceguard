# Production SSO deployment guide

TraceGuard's current website is a **synthetic, browser-only portfolio lab**. Its role picker is a presentation feature and is not an authentication system. This guide is a deployment blueprint for a future server-side service; it does not make the current lab authenticate users or connect to Microsoft Entra or Okta.

Use this guide before any organization data, real identities, tenant records, or production connectors are introduced.

## What a production login must guarantee

The sign-in flow must answer four questions on the server for every request:

1. **Who is this person?** Verify a signed identity-provider token.
2. **Which organization do they belong to?** Bind the person to exactly one server-verified tenant.
3. **Which approved role do they hold?** Permit only `Organization Owner` or `Lab Assistant` during the pilot.
4. **Is the session still allowed?** Enforce expiry, revocation, and fresh MFA for sensitive actions.

An employee must be denied by default. A browser role picker, hidden route, email address, shared admin account, Wi-Fi connection, or phone number cannot grant access.

## Safe configuration boundary

Copy [`.env.example`](../.env.example) into your deployment platform's secret configuration only after replacing its placeholders. The current lab does not read it.

Keep the following values server-side:

| Value | Purpose | Handling rule |
|---|---|---|
| OIDC issuer | Identifies the exact Entra or Okta authorization server | Allow-list one issuer per organization; verify it on every token. |
| Client ID | Identifies the server's OIDC application | May be treated as an identifier, but do not expose configuration unnecessarily. |
| Client secret or certificate | Lets a confidential server complete the authorization-code flow | Secret manager only; never browser code, `dist/`, Git, screenshots, or logs. |
| Redirect URI | Where the provider returns the authorization response | Exact HTTPS URI registered at the provider; no wildcards or open redirects. |
| Expected tenant ID and audience | Prevents another company from using its own token to enter | Compare server-side to the token's trusted claims. |
| Role/group identifiers | Maps approved identity-provider roles to TraceGuard permissions | Use immutable app-role values or group IDs, never names or email text. |
| Session secret and revocation data | Protects short-lived server-side sessions | Store in a managed secret store and protected database. |

Use a different client credential and tenant binding for each company connection, or a carefully reviewed multi-tenant control plane that stores each approved tenant separately. The client must never choose a tenant by URL parameter, form value, or local storage.

## Microsoft Entra setup

1. In **App registrations**, create a server-side web application. Choose **Accounts in this organizational directory only** for a single-company deployment.
2. Register the exact production callback: `https://<your-domain>/auth/oidc/callback`. Register the exact post-logout address, such as `https://<your-domain>/sign-in`. HTTPS is required outside a local development environment.
3. Enable the authorization-code flow. The server must use PKCE, `state`, and `nonce`; do not use the implicit flow.
4. Create app roles such as `traceguard.owner` and `traceguard.lab_assistant`. Assign them to named people or approved groups through the company administrator. Do not use an employee-controlled display name as the role source.
5. Record the directory (tenant) ID, application (client) ID, and issuer. Configure the application to accept tokens only from that directory. The server must reject `common`, `organizations`, or any other unapproved issuer for a tenant-restricted deployment.
6. Store a certificate or client secret in the deployment secret manager. Give the service identity only the permissions it needs. Do not place any secret in the frontend bundle or this repository.
7. Configure a Conditional Access or authentication-strength policy: require passkeys/FIDO2 or another phishing-resistant method for `traceguard.owner`. An authenticator-app TOTP can be a reviewed fallback. SMS/phone OTP and Wi-Fi/network presence must not be the only factor.

## Okta setup

1. Create an OIDC **Web Application** integration using the authorization-code flow with PKCE.
2. Register the exact HTTPS callback and post-logout redirect URI. Disable unused redirect URIs.
3. Use your organization-specific Okta issuer, for example `https://<org>.okta.com/oauth2/default`; do not accept an issuer supplied by the browser.
4. Assign the integration only to approved users or groups. Emit a reviewed, bounded groups or custom role claim and map only allow-listed immutable identifiers to `traceguard.owner` and `traceguard.lab_assistant`.
5. Keep the client secret or private key in the deployment secret manager. Require phishing-resistant MFA for owners through Okta policy; do not treat SMS or network presence as sufficient owner authentication.

## Server-side callback and token validation

The frontend should only redirect to `/auth/login`; the backend owns the authorization response and session.

1. Generate a cryptographically random `state`, `nonce`, and PKCE verifier, bind them to a short-lived pre-authentication server record, and redirect to the configured issuer.
2. On `/auth/oidc/callback`, reject a missing or mismatched `state`, failed provider response, reused callback, or expired pre-authentication record.
3. Exchange the authorization code only from the server. Validate the ID token signature with the provider's discovery document and JWKS. Validate `iss`, `aud`, `exp`, `nbf`, `nonce`, and the exact tenant/directory claim. Do not rely on a token decoded in JavaScript.
4. Identify the person by immutable `(issuer, subject)` values, not by email or display name. Look up their server-side tenant membership and approved role. Deny the session if either is absent or inactive.
5. Create a new opaque session identifier, rotate it at sign-in, persist session state server-side, and send only a `Secure`, `HttpOnly`, `SameSite` cookie. Apply an idle timeout and absolute expiry.
6. Write a protected tenant-scoped audit record for the outcome without logging raw tokens, client secrets, OTP values, or unnecessary personal data.

For every protected endpoint, derive tenant, principal, role, and session status from server-side authenticated context. Scope every query, report export, audit entry, and connector action to that tenant. Never accept these values from a request body, path, query, local storage, or frontend role state.

## Role mapping and approvals

During an initial pilot, permit exactly two roles:

| Identity-provider assignment | TraceGuard role | Allowed responsibility |
|---|---|---|
| `traceguard.owner` | Organization Owner | Approve or suspend Lab Assistants, review audit records, and make organization-level configuration decisions. |
| `traceguard.lab_assistant` | Lab Assistant | Use only the tenant-scoped investigation capabilities explicitly approved by the Owner. |

The Owner or delegated company administrator must approve each named account and record the business purpose, tenant, role, start date, review date, and revocation owner. Only an Owner or delegated administrator can change another person's access. Avoid shared administrator accounts.

If Entra or Okta returns a role/group claim that is not in the server allow-list, deny access. Roles must be evaluated on every request or through a server-side session whose role membership is actively invalidated after a change.

## MFA, sensitive actions, and revocation

- Require phishing-resistant MFA for Organization Owners. Prefer platform passkeys or FIDO2 security keys. Support authenticator-app TOTP only under a reviewed fallback policy.
- Require a fresh authentication or MFA step-up before privilege changes, exports, policy changes, recovery of a privileged account, connector authorization, and session-revocation actions.
- On a role removal, employee departure, suspicious access, or recovery event, revoke that person's application sessions and refresh tokens immediately, invalidate any active device sessions, and require fresh SSO plus MFA.
- Offer logout that ends the local server session and redirects through the identity provider's approved logout flow when supported.
- Store protected, tenant-scoped audit records for sign-in successes and failures, approvals, denials, role changes, MFA recovery, exports, logout, and revocation. Give audit access to the Owner or an approved auditor role only.

Phone/SMS OTP may be a guarded recovery option under company policy; it is never sufficient by itself for privileged access. A Wi-Fi connection, IP range, or office network can be an additional restriction but is never an authenticator.

## Pre-production test plan

Run these checks in a staging tenant before enabling production access:

1. A person with no approved tenant membership is denied even if they work for the company.
2. A valid token from a different Entra directory or Okta organization is denied.
3. An Organization Owner can perform approved administrative actions; a Lab Assistant cannot reach owner-only routes or APIs.
4. A browser request that changes a tenant, role, subject, or export scope is denied; every server query remains tenant-scoped.
5. Bad `state`, replayed callback, expired token, wrong issuer, wrong audience, missing nonce, and unsigned/altered token are denied and audited.
6. A role removal or session-revocation action ends an already active session promptly. A sensitive action requires fresh MFA when policy calls for it.
7. Redirect URIs, cookies, CSP, TLS, secret injection, logging, audit retention, and recovery paths receive an independent review.
8. A controlled break-glass procedure is documented, time-limited, separately audited, and tested. It must not become a permanent shared owner account.

## Activation checklist

1. Review the exact public HTTPS domain, redirect URI, issuer, expected audience, tenant binding, and role allow-list with the company's identity administrator.
2. Load client secrets/certificates and session secrets from a managed secret service. Verify none appear in source control, frontend assets, browser logs, or diagnostic output.
3. Configure server-side tenant and role authorization, protected session storage, revocation, audit retention, monitoring, backups, and incident ownership.
4. Complete the staging tests above, including cross-tenant adversarial tests and a revocation drill.
5. Obtain security and company-owner approval, enable the application for assigned pilot users only, and review sign-in/audit events regularly.

Do not claim this work is complete until the production server, identity provider, session store, tenant authorization, and audit system are implemented and independently verified.
