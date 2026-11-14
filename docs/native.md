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
```

All five fields are strings. `listen` and `cpa_url` have the defaults shown. The other three are required. The origin must be exact HTTPS with no trailing slash, path, query, credentials or fragment. Both file/directory paths must be absolute. Keep the management key in a mounted 0600 file, never a config value. State must be private (0700) and writable. The CPA URL must resolve to a private management endpoint; network privacy is the operator's responsibility.

Empty configuration is metadata-only discovery and does not start a listener. Nonempty configuration validates and binds synchronously, reporting errors to CPA. Identical reconfiguration is a no-op; changes to any runtime field require CPA restart (including key-file path). Key-file contents are read at startup only. CPA-owned `enabled`, `priority`, and `store` fields are accepted; the host owns enable/disable lifecycle. The plugin advertises `management_api` and registers a Public Enrollment menu resource at `/v0/resource/plugins/public-enrollment/open`. CPA serves this resource without authentication; it contains only a plain link to the configured public enrollment origin (or an unconfigured message), never keys, state, or management operations. It does not embed an iframe or proxy enrollment routes: reverse proxy the enrollment listener directly with HTTPS, restricting direct access.

Shutdown stops admission, shuts down HTTP, and waits for the bounded in-flight save before releasing runtime state. Allow at least 110 seconds for CPA/container graceful shutdown. Run only one instance against a state directory; do not run CLI and plugin together. Browser-originated authentication behavior is unchanged. See [prototype limitations](prototype.md).

CLI remains available without the `native` tag. Native checks:

```sh
go test -tags native ./...
go test -race -tags native ./...
go vet -tags native ./...
# Also run the real CPA host metadata/resource validators using a test overlay:
CPA_HOST_SOURCE=/path/to/cpa-v8.0.63 go test -tags native -run TestActualCPAHostContract .
```
