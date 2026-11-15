//go:build native

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

const schemaVersion = 10

type pluginConfig struct {
	Enabled           *bool  `yaml:"enabled"`
	Priority          int    `yaml:"priority"`
	Store             any    `yaml:"store"`
	Listen            string `yaml:"listen"`
	PublicOrigin      string `yaml:"public_origin"`
	CPAURL            string `yaml:"cpa_url"`
	ManagementKeyFile string `yaml:"management_key_file"`
	StateDir          string `yaml:"state_dir"`
	OperatorName      string `yaml:"operator_name"`
	WebhookURL        string `yaml:"webhook_url"`
}
type runningPlugin struct {
	config pluginConfig
	app    *app
	server *http.Server
	cancel context.CancelFunc
	done   chan struct{}
}

var nativeRuntime struct {
	sync.Mutex
	current *runningPlugin
}

func parsePluginConfig(raw []byte) (pluginConfig, error) {
	var c pluginConfig
	d := yaml.NewDecoder(bytes.NewReader(raw))
	d.KnownFields(true)
	if err := d.Decode(&c); err != nil {
		return c, errors.New("invalid plugin configuration")
	}
	if d.Decode(new(any)) != io.EOF {
		return c, errors.New("expected one configuration document")
	}
	if c.Listen == "" {
		c.Listen = "0.0.0.0:8318"
	}
	if c.CPAURL == "" {
		c.CPAURL = "http://127.0.0.1:8317"
	}
	u, e := url.Parse(c.PublicOrigin)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return c, errors.New("public_origin must be an exact HTTPS origin without trailing slash")
	}
	u, e = url.Parse(c.CPAURL)
	if e != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return c, errors.New("cpa_url must be a private management origin")
	}
	if !filepath.IsAbs(c.StateDir) || !filepath.IsAbs(c.ManagementKeyFile) {
		return c, errors.New("state_dir and management_key_file must be absolute paths")
	}
	if err := validateWebhook(c.WebhookURL); err != nil {
		return c, err
	}
	return c, nil
}
func configure(raw []byte) error {
	nativeRuntime.Lock()
	defer nativeRuntime.Unlock()
	// CPA discovers metadata with an empty configuration. Discovery must not bind.
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	c, err := parsePluginConfig(raw)
	if err != nil {
		return err
	}
	if r := nativeRuntime.current; r != nil {
		old := r.config
		if old.Listen != c.Listen || old.PublicOrigin != c.PublicOrigin || old.CPAURL != c.CPAURL || old.ManagementKeyFile != c.ManagementKeyFile || old.StateDir != c.StateDir || old.OperatorName != c.OperatorName || old.WebhookURL != c.WebhookURL {
			return errors.New("runtime configuration changes require CPA restart")
		}
		// The host rolls back a quiesced image with plugin.reconfigure and
		// the previous config. Rebind without replacing sessions or saves.
		if r.server == nil {
			return r.listen()
		}
		return nil
	}
	key, err := os.ReadFile(c.ManagementKeyFile)
	if err != nil || strings.TrimSpace(string(key)) == "" {
		return errors.New("cannot read nonempty management_key_file")
	}
	device := newDevice(c.StateDir)
	if device.prepare() != nil {
		return errors.New("state_dir must be private and writable (0700)")
	}
	a := &app{sessions: make(map[string]*flow), origin: c.PublicOrigin, operatorName: c.OperatorName, device: device, management: NewManagement(c.CPAURL, string(key))}
	r := &runningPlugin{config: c, app: a}
	if err := r.listen(); err != nil {
		return err
	}
	nativeRuntime.current = r
	return nil
}

// Called with nativeRuntime locked. A shut-down http.Server cannot be reused.
func (r *runningPlugin) listen() error {
	r.app.cleanupPending(time.Now())
	listener, err := net.Listen("tcp", r.config.Listen)
	if err != nil {
		return errors.New("cannot bind enrollment listener: " + err.Error())
	}
	srv := &http.Server{Handler: r.app, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	done := make(chan struct{})
	r.server, r.done = srv, done
	r.app.mu.Lock()
	// A failed drain can roll back with the previous worker still running.
	r.app.webhook.stop()
	r.app.webhook = newWebhook(r.config.WebhookURL, nil)
	r.app.closing = false
	r.app.mu.Unlock()
	go func() { defer close(done); _ = srv.Serve(listener) }()
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				r.app.cleanupPending(now)
				r.app.mu.Lock()
				r.app.pruneSessions(now)
				r.app.mu.Unlock()
			}
		}
	}()
	return nil
}

const quiesceTimeout = 105 * time.Second

// Stop public admission and release the listener BEFORE replacement registration.
// Preserve the app for the host's rollback reconfigure callback. A timeout fails
// replacement rather than claiming it is safe to overlap a still-running save.
func (r *runningPlugin) quiesce(timeout time.Duration) error {
	r.app.mu.Lock()
	r.app.closing = true
	drained := r.app.saveDone
	r.app.mu.Unlock()
	r.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if r.server != nil {
		httpCtx, stop := context.WithTimeout(ctx, 15*time.Second)
		if r.server.Shutdown(httpCtx) != nil {
			_ = r.server.Close()
		}
		stop()
		<-r.done
		r.server = nil
	}
	if drained == nil {
		r.app.webhook.stop()
		return nil
	}
	select {
	case <-drained:
		r.app.webhook.stop()
		return nil
	case <-ctx.Done():
		return errors.New("save drain timed out; replacement must be aborted")
	}
}
func quiesce() error {
	nativeRuntime.Lock()
	defer nativeRuntime.Unlock()
	if r := nativeRuntime.current; r != nil {
		return r.quiesce(quiesceTimeout)
	}
	return nil
}
func shutdown() {
	nativeRuntime.Lock()
	defer nativeRuntime.Unlock()
	r := nativeRuntime.current
	if r == nil {
		return
	}
	if r.quiesce(quiesceTimeout) != nil {
		// The actual host keeps Go c-shared images mapped. Keep runtime state
		// too if unusual blocked I/O outlives the bounded drain.
		return
	}
	r.cancel()
	nativeRuntime.current = nil
}
func errorEnvelope(code, message string) []byte {
	raw, _ := json.Marshal(map[string]any{"ok": false, "error": map[string]string{"code": code, "message": message}})
	return raw
}
func handleMethod(method string, request []byte) ([]byte, error) {
	if method == "plugin.quiesce" {
		if err := quiesce(); err != nil {
			return errorEnvelope("quiesce_failed", err.Error()), nil
		}
		return []byte(`{"ok":true,"result":{}}`), nil
	}
	if method == "management.register" {
		return json.Marshal(map[string]any{"ok": true, "result": map[string]any{"resources": []any{}, "menus": []any{}}})
	}
	if method == "management.handle" {
		var req struct{ Method string }
		if json.Unmarshal(request, &req) != nil {
			return errorEnvelope("invalid_request", "invalid resource request"), nil
		}
		status, body := http.StatusMethodNotAllowed, "method not allowed"
		if req.Method == http.MethodGet {
			status = http.StatusOK
			body = `<!doctype html><html lang="en"><meta charset="utf-8"><title>Public Enrollment</title><h1>Public Enrollment</h1><p>Public enrollment is not configured.</p></html>`
			nativeRuntime.Lock()
			origin := ""
			if r := nativeRuntime.current; r != nil {
				origin = r.config.PublicOrigin
			}
			nativeRuntime.Unlock()
			// Resource routes are unauthenticated. Publish only the public URL,
			// never configuration, credentials, or enrollment/session state.
			if origin != "" {
				body = `<!doctype html><html lang="en"><meta charset="utf-8"><title>Public Enrollment</title><h1>Public Enrollment</h1><p><a rel="noreferrer" href="` + html.EscapeString(origin) + `/">Open public enrollment</a></p></html>`
			}
		}
		return json.Marshal(map[string]any{"ok": true, "result": struct {
			StatusCode int
			Headers    http.Header
			Body       []byte
		}{status, http.Header{"Content-Type": {"text/html; charset=utf-8"}, "Cache-Control": {"no-store"}, "X-Content-Type-Options": {"nosniff"}, "Content-Security-Policy": {"default-src 'none'; base-uri 'none'; frame-ancestors 'self'"}, "Referrer-Policy": {"no-referrer"}}, []byte(body)}})
	}
	if method != "plugin.register" && method != "plugin.reconfigure" {
		return errorEnvelope("unknown_method", "unsupported plugin method"), nil
	}
	var req struct {
		SchemaVersion uint32 `json:"schema_version"`
		ConfigYAML    []byte `json:"config_yaml"`
	}
	if json.Unmarshal(request, &req) != nil || req.SchemaVersion != schemaVersion {
		return errorEnvelope("unsupported_schema", "requires CPA schema 10"), nil
	}
	if err := configure(req.ConfigYAML); err != nil {
		return errorEnvelope("configuration_error", err.Error()), nil
	}
	fields := []map[string]string{}
	for _, f := range [][2]string{{"listen", "HTTP bind address; default 0.0.0.0:8318"}, {"public_origin", "Exact public HTTPS origin without trailing slash"}, {"cpa_url", "Private CPA management origin; default http://127.0.0.1:8317"}, {"management_key_file", "Absolute path to mounted management key file (not the key)"}, {"state_dir", "Absolute private persistent directory (0700)"}, {"operator_name", "Optional public operator display name; plain text, requires CPA restart to change"}, {"webhook_url", "Optional HTTPS URL for enrollment result JSON notifications; includes email when known; requires CPA restart to change"}} {
		fields = append(fields, map[string]string{"Name": f[0], "Type": "string", "Description": f[1]})
	}
	return json.Marshal(map[string]any{"ok": true, "result": map[string]any{"schema_version": schemaVersion, "metadata": map[string]any{"Name": "Public Enrollment", "Version": "0.1.0", "Author": "NotRllyRn", "GitHubRepository": "https://github.com/NotRllyRn/cpa-public-enrollment", "ConfigFields": fields}, "capabilities": map[string]bool{"management_api": true}}})
}
