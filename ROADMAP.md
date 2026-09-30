# Next milestones

## 1. Connect the complete local application
- Migrate the UI to React + TypeScript once the feature contract is stable.
- Implement authenticated browser sessions and server-side authorization before allowing browser access to the API.
- Move case status, notes, evidence links, and immutable audit records to PostgreSQL with migrations.
- Preserve browser/Python detector parity through shared input/output fixtures.

## 2. Add a constrained AI investigator
- Use server-side secrets and a provider abstraction; never accept a provider key in the frontend.
- Implement narrow tools: get_alert, get_events_for_account, get_approved_runbook.
- Treat log content as untrusted data, separate instructions, bound tool calls and model cost.
- Require structured output with evidence IDs and validate every citation.
- Maintain the deterministic baseline and an explicit disconnected state.
- Add failure handling, timeouts, cancellation, and provider data-processing controls.

## 3. Demonstrate value
- Build a labeled, held-out set of normal and suspicious identity activity.
- Compare rules-only, analyst review, and AI-assisted review.
- Measure false positives/negatives, unsupported claims, review time, latency, and cost.
- Ask the professor and classmates to test the workflow; record changes resulting from feedback.

## 4. Production-readiness assessment
- Follow SECURITY.md before allowing customer logs or live integrations.
- Expand beyond synthetic identity logs only after tenancy, access controls, and data policy exist.
- Do not add autonomous account changes until a reviewed approval and rollback system is in place.

## Honest portfolio description today

Built a synthetic security investigation lab with three identity detection rules, evidence-linked reports, privacy-minimized exports, a responsive interface, and a separate authenticated Python/SQLite API. Implemented functional and security-boundary tests. AI integration and production customer-data handling remain future work.
