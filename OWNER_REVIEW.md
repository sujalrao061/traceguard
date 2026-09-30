# TraceGuard owner review

## What this product is

TraceGuard is a privacy-first cybersecurity investigation workspace. It lets a security team load **synthetic identity-event data**, detect transparent patterns, review linked evidence, record a human decision, and export a redacted investigation brief.

It is deliberately built as a portfolio prototype: it never connects to a customer system, sends data to an AI model, or accepts real accounts or IP addresses.

## What a company owner can see today

- An operations center that shows the next priority, open queue, rule coverage, and the data boundary.
- Transparent rules for repeated authentication failures, a successful sign-in after failures, and privileged-role changes.
- A case workflow with ownership context, linked evidence, potential impact, and practical review steps.
- A local sign-in and role-selection page that makes the portfolio walkthrough feel like a real product while plainly identifying itself as synthetic onboarding, not company authentication. A production version starts default-deny and can deliberately authorize only a named Organization Owner and Lab Assistant for a pilot.
- Local role views for an Organization Owner and an authorized Lab Assistant. The interface clearly labels this as a demonstration, not real authorization.
- Safe export behavior: source addresses and investigation notes are excluded from exported briefs.
- Disconnected integration cards for Okta, Microsoft Entra ID, GitHub, and AWS CloudTrail. They show the intended product architecture without claiming live access.
- A launch checklist that separates implemented safeguards, demonstrated workflow ideas, and the controls required before customer data.
- An Owner Control Center that presents truthful disconnected system health, five launch gates, notification and escalation expectations, an Owner-only local planning review, and a 30-day reversible rollout. It labels every entry as a local planning preview rather than a live service status.
- An Executive Brief that turns the security workflow into owner questions: critical queue, evidence traceability, active-rule assurance, and a visible zero-egress demo boundary.
- A Case Commitment panel that gives every demonstration case a local owner, severity-based response and decision targets, a visible escalation path, a browser-session decision ledger, and a governed feedback prompt. It explicitly states that it does not page, message, or notify anyone.
- An Account Containment & Tenant Boundary walkthrough that shows how a high-confidence identity signal should move from evidence through a policy decision to recovery. It clearly separates the demo from real password resets, session revocation, endpoint isolation, USB restrictions, and cross-company access controls.
- A live, local value-planning model. A buyer can change review volume, estimated minutes recovered, and analyst cost; every result is labeled as an illustrative pilot estimate rather than claimed ROI.
- A 30-day safe-pilot plan with a security review, test fixture, detection-tuning phase, outcome review, and explicit stop/go gates.
- A detection governance registry that gives each rule a version, owner, test result, business purpose, and ATT&CK context.
- A deterministic Evidence Assistant preview that separates observed facts, possible explanations, and next human questions while citing event IDs and refusing to take action.

## What I would expect from the builder

I would expect the builder to explain both the product decision and the security boundary:

1. **Start with a real operator problem.** Analysts need to move from an alert to evidence and a defensible decision without losing context.
2. **Make detections inspectable.** Each alert must link back to the rule and events that created it.
3. **Protect data by design.** Use synthetic fixtures for the demo, reject real-looking data, redact exports, and keep the browser workspace disconnected.
4. **Contain safely.** A successful sign-in after failed attempts is not enough to blindly change a password. A mature workflow verifies evidence, applies an approved policy, uses the identity provider for session revocation or recovery, and records the decision and recovery plan.
5. **Keep companies isolated.** A real deployment needs server-enforced tenant identity on every read, write, export, audit record, and connector call. A company must never be able to access another company's accounts by changing a browser value.
6. **Be honest about readiness.** A polished prototype is not a production security platform. The sign-in experience is a role simulation, not a password system. Real deployment starts default-deny: the owner or delegated administrator provisions named users through company SSO (OIDC or SAML), assigns a narrowly scoped role, and may intentionally start with only the Organization Owner and Lab Assistant. The server verifies IdP claims and enforces tenant and role for every operation. Use passkeys/WebAuthn where possible, allow authenticator-app TOTP when needed, and never treat SMS/phone OTP or Wi-Fi presence as the only factor. Production also needs server-side sessions, fresh MFA for sensitive actions, IdP-led session/device revocation, encrypted durable storage, durable login/logout and session-revocation audit records, suspicious-access monitoring, backups, reviewed retention policies, and separately governed EDR/MDM controls for USB and endpoint protection.
7. **Show that quality is measured.** The project has repeatable rule tests and backend API tests rather than only a visual dashboard.

## A concise pitch for a professor or recruiter

> I built TraceGuard, a privacy-first cybersecurity investigation workspace. It uses only synthetic identity events, so I can demonstrate detection logic, evidence-based triage, and redacted reporting without exposing customer data. The sign-in screen is also synthetic: it lets a reviewer choose a demo role but never accepts a password or authenticates a company. In a real deployment, access starts default-deny: a company owner provisions named users through SSO and can begin with only an Owner and Lab Assistant. I would use passkeys or an authenticator app for MFA, verify identity and tenant claims on the server, and let the identity provider revoke sessions when needed. I designed the workflow around what a security lead needs to see: priority signals, rule coverage, ownership, linked evidence, containment decisions, and clear launch requirements. A suspicious successful sign-in becomes a reviewed containment recommendation, not an unsafe automatic password change. Before connecting real systems, I would also add least-privilege identity-provider actions for session revocation and recovery, plus separate EDR/MDM controls for endpoints and USB devices.

## Owner review and hiring readiness

**Owner verdict: 10/10 for a student portfolio and interview project.** TraceGuard answers the questions an owner, recruiter, and security lead would ask before they trust someone to work on a security product.

- **Product judgment:** it turns a noisy sign-in signal into an evidence review, a human decision, and a recovery plan instead of making an unsafe automatic password change.
- **Evidence workflow:** transparent rules, linked events, named ownership, response targets, a decision ledger, redacted briefs, and repeatable evaluations make the reasoning inspectable.
- **Privacy and tenant maturity:** the demo uses synthetic data, blocks real-looking imports, makes the zero-egress boundary visible, and explains why companies need server-enforced isolation.
- **Business thinking:** the Executive Brief, value-planning model, governance registry, and 30-day pilot plan connect technical work to a buyer's decisions.
- **Engineering quality:** the browser experience is responsive and the detection engine and API have repeatable automated tests.

TraceGuard is a portfolio prototype and does not yet accept customer data. Before a live deployment, the production gates are: company SSO through OIDC or SAML; phishing-resistant MFA; authenticated server-side tenant context; server-side sessions; server-enforced roles and authorization; isolated, least-privilege identity-provider connectors; encrypted durable storage and tamper-evident login/logout, session-revocation, and investigation audit records; suspicious-access monitoring; backups, retention review, and incident procedures; and separately governed EDR/MDM controls for endpoint and USB protection. Naming these gates clearly is part of the project's professional value.

## The strongest closing line in a meeting

> TraceGuard gives a security leader a safe, measurable 30-day path from identity signals to accountable, evidence-backed decisions. Every detection has an owner and test; every case has an owner, decision target, and human decision point; every containment plan has a policy and recovery path; and every company boundary is visible before a customer connects anything.
