# Native CPA plugin

Targets CPA v8.0.63, native ABI 1 / wire schema 10. This is a C shared library, not a Go `plugin` library. The ABI shim is adapted from Willxup/cpa-plugin-usage-keeper under [MIT](native-bridge-LICENSE).

Build on the target libc (Alpine requires a musl toolchain), with Go 1.23+, C compiler, CGO enabled:

```sh
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -tags native -buildmode=c-shared -o public-enrollment.so .
```

Install the library through CPA's native plugin loader. Configure these plugin fields (not top-level CPA settings):

```yaml
listen: "0.0.0.0:8318"
public_origin: "https://enroll.example.com"
cpa_url: "http://127.0.0.1:8317"
management_key_file: "/run/secrets/cpa-management-key"
state_dir: "/var/lib/cpa-enrollment"
operator_name: "Example Operator" # optional public display name
```

All six fields are strings; `operator_name` is optional and defaults to “Not specified”. It is displayed as plain text, not HTML or a verified identity. Set it to a name visitors recognize. Changing it requires CPA restart, just like the other runtime settings; a live change is rejected and the previous name remains in use. `listen` and `cpa_url` have the defaults shown. `public_origin`, `management_key_file`, and `state_dir` are required. The origin must be exact HTTPS with no trailing slash, path, query, credentials or fragment. Both file/directory paths must be absolute. Keep the management key in a mounted 0600 file, never a config value. State must be private (0700) and writable. The CPA URL must resolve to a private management endpoint; network privacy is the operator's responsibility.

Empty configuration is metadata-only discovery and does not start a listener. Nonempty configuration validates and binds synchronously, reporting errors to CPA. Identical live reconfiguration is a no-op; changes to any runtime field require CPA restart (including key-file path). Key-file contents are read at startup only. CPA-owned `enabled`, `priority`, and `store` fields are accepted; the host owns enable/disable lifecycle. The plugin retains the host-required `management_api` capability but registers no dashboard menus, routes, or public resources. Plugin configuration remains available. Reverse proxy the enrollment listener directly with HTTPS, restricting direct access.

## Replacement and recovery

On the verified CPA host, `plugin.quiesce` stops public admission and session cleanup, closes the HTTP listener, and drains the admitted save before replacement registration. HTTP drain is capped at 15 seconds and total quiesce at 105 seconds; the save has its own 90-second context. A drain timeout returns `quiesce_failed`, aborting replacement. The host cleans up a failed candidate, then calls the old image's `plugin.reconfigure` with its previous configuration. This rebinds a fresh HTTP server and resumes the same sessions and any outstanding save. Resume bind failures are reported, not hidden. No separate `plugin.resume` method exists on this host.

Successful replacement need not preserve sessions. A surviving cookie gets a structured `session_lost` response and a service-updated/session-unavailable warning, not an automatic reset. **Reset session to review access** explicitly clears only that cookie's local pending records, rotates the cookie and CSRF, and returns to consent without creating a code. Reset is also available after error, operator-review, duplicate, or expiry, but never during a save. A surviving high-entropy HttpOnly cookie identifies pending files through its SHA-256 hash in server-generated filenames, including after restart. A missing cookie cannot recover ownership; legacy unowned files are never assigned to a visitor. Pending credentials are never replayed. Local pending files expire after **10 minutes** (file modification age), checked at startup, every second, and before pending checks. Adoption serializes cleanup, reset, and saving, so active saves are not deleted. This policy includes uncertain uploads and legacy pending files. Deleting local evidence neither revokes OpenAI access nor rolls back an import or deletes CPA-adopted credentials. Cleanup failures are logged; reset/save failures are shown to the visitor. Only one process may own the private state directory. Existing open tabs recover from changed CSRF by fetching the shared session, without resending old approval proof.

**The first upgrade from a build without quiesce still requires a controlled CPA restart.** This minimal support applies to subsequent distinct native builds on a host with the verified quiesce/rollback contract; it is not zero-downtime or session migration. During the listener gap a reverse proxy may return a temporary upstream error. Go C-shared images remain mapped by the host even after retirement; repeated replacements still consume host memory. Allow at least 110 seconds for CPA/container graceful shutdown. Shutdown uses the same bounded drain; unusual blocked I/O retains the stopped runtime rather than discarding an unfinished save. Run only one instance against a state directory; do not run CLI and plugin together. See [prototype limitations](prototype.md).

CLI remains available without the `native` tag. Native checks:

```sh
go test -tags native ./...
go test -race -tags native ./...
go vet -tags native ./...
# Actual host metadata/resource validation and two-image replacement/rollback:
# Overlay tests do not edit host source or contact a deployed CPA.
CPA_HOST_SOURCE=/path/to/cpa-v8.0.63 go test -tags native -run 'TestActualCPAHost(Contract|Replacement)$' .
```
