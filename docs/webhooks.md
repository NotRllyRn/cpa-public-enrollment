# Enrollment notifications

Optional admin-only native setting: `webhook_url: https://hooks.example.com/enrollment`.
Standalone equivalent: `ENROLL_WEBHOOK_URL`. Empty disables delivery. Restart to change.
The URL stays server-side. HTTPS is required; credentials and fragments are rejected.
Private/internal destinations are intentionally allowed: only trusted administrators should set this URL.

Discord webhook URLs (`discord.com/api/webhooks/…` and `discordapp.com/api/webhooks/…`) receive a readable message with mentions disabled. Other destinations receive generic JSON:

```json
{"event":"enrollment","status":"complete","timestamp":"2026-01-01T00:00:00Z","email":"person@example.com"}
```

`event` is `enrollment` for server outcomes or `client_failure` for browser-reported failures.
`status` is `complete`, `duplicate`, `error`, `operator-review`, or `expired`.
Duplicate means an existing matching CPA credential was found; no new upload was made.
It is not a new successful enrollment; local recovery evidence is retained for explicit reset.
`error` includes the failed operation and sanitized reason for server failures, or a fixed summary for expiry/browser reports. Raw upstream responses and credential secrets are never included.
`email` is omitted until known from the server token exchange. It is personal data:
configure a trusted destination and suitable access/retention controls. Token claims are decoded,
not cryptographically verified (see prototype limitations).

Browser failures are explicitly unverified client reports, never proof of a provider failure.
Only creation/poll stage codes are accepted with exact Origin, JSON, session cookie, CSRF,
and a live matching lease in the corresponding state. Reports cannot supply email, success,
or arbitrary error text. A report ends that attempt and is accepted at most once. Client notifications also have a
process-wide limit of one per second (excess events are dropped), bounding reset abuse. Browser
transport failures delivering approvals are not reported as enrollment failures: saving may
already be underway. A lost connection to this service cannot reliably report itself.

Terminal outcomes are queued at most once per in-memory attempt. The single worker has a
32-event queue and a 3-second request timeout, no redirects and no retries. Full queues drop
events; shutdown cancels delivery and discards pending events. Delivery is best effort,
not durable or guaranteed. Webhook errors do not block authentication, saving, or cleanup.
Delivery failures log only HTTP status or a generic network failure. Response bodies and destination URLs are never logged. Existing reset/retention
rules still apply; notifications do not delete recovery evidence or revoke access.
