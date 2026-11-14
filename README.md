# CPA public enrollment prototype

A small Go companion for consenting visitors to grant CPA ongoing ChatGPT access. Plain UI, no dependencies. Runnable locally; not deployed or production-ready.

## Run

Requires Go 1.23+, private CPA v8 management (reference: v8.0.63), and an HTTPS reverse proxy. Restrict direct listener access. Run **one instance**:

```sh
export ENROLL_PUBLIC_ORIGIN=https://enroll.example.com
export ENROLL_CPA_URL=http://cpa.internal:8317
export ENROLL_CPA_KEY_FILE=/run/secrets/cpa-management-key
export ENROLL_STATE_DIR=/var/lib/cpa-enrollment
# Optional: ENROLL_LISTEN=0.0.0.0:8318 (default)
go run .
```

These are companion settings, not CPA keys. Origin has no trailing slash. Keep the key server-only (0600); state is 0700, pending files 0600. Use trusted HTTPS for management outside an isolated network. Allow 110 seconds for shutdown.

**Browser → OpenAI:** create/poll device codes. **Go → OpenAI:** exchange approved code + verifier; long-lived tokens never enter JS. **Go → CPA:** one durable import and adoption check; CPA owns refresh. No token-upload API or server-originated device adapter.

See [security, recovery and prototype limitations](docs/prototype.md) before use. Actual browser CORS/login and deployed CPA import still need authorized manual testing. JWT claims are decoded, **not cryptographically verified**. Ambiguous imports require operator review, never blind reupload.

## Checks

```sh
go test ./...
go test -race ./...
go vet ./...
node --test browser_test.mjs
```

Tests use mocked transports, not real login requests.
