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
		if old.Listen != c.Listen || old.PublicOrigin != c.PublicOrigin || old.CPAURL != c.CPAURL || old.ManagementKeyFile != c.ManagementKeyFile || old.StateDir != c.StateDir {
			return errors.New("runtime configuration changes require CPA restart")
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
	listener, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return errors.New("cannot bind enrollment listener: " + err.Error())
	}
	a := &app{sessions: make(map[string]*flow), origin: c.PublicOrigin, device: device, management: NewManagement(c.CPAURL, string(key))}
	srv := &http.Server{Handler: a, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	ctx, cancel := context.WithCancel(context.Background())
	r := &runningPlugin{config: c, app: a, server: srv, cancel: cancel, done: make(chan struct{})}
	nativeRuntime.current = r
	go func() { defer close(r.done); _ = srv.Serve(listener) }()
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				a.mu.Lock()
				a.pruneSessions(now)
				a.mu.Unlock()
			}
		}
	}()
	return nil
}
func shutdown() {
	nativeRuntime.Lock()
	defer nativeRuntime.Unlock()
	r := nativeRuntime.current
	if r == nil {
		return
	}
	r.app.mu.Lock()
	r.app.closing = true
	r.app.mu.Unlock()
	r.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if r.server.Shutdown(ctx) != nil {
		_ = r.server.Close()
	}
	r.app.wg.Wait()
	<-r.done
	nativeRuntime.current = nil
}
func errorEnvelope(code, message string) []byte {
	raw, _ := json.Marshal(map[string]any{"ok": false, "error": map[string]string{"code": code, "message": message}})
	return raw
}
func handleMethod(method string, request []byte) ([]byte, error) {
	if method == "management.register" {
		return json.Marshal(map[string]any{"ok": true, "result": map[string]any{"resources": []map[string]string{{"Path": "/open", "Menu": "Public Enrollment", "Description": "Open the public enrollment page."}}}})
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
	for _, f := range [][2]string{{"listen", "HTTP bind address; default 0.0.0.0:8318"}, {"public_origin", "Exact public HTTPS origin without trailing slash"}, {"cpa_url", "Private CPA management origin; default http://127.0.0.1:8317"}, {"management_key_file", "Absolute path to mounted management key file (not the key)"}, {"state_dir", "Absolute private persistent directory (0700)"}} {
		fields = append(fields, map[string]string{"Name": f[0], "Type": "string", "Description": f[1]})
	}
	return json.Marshal(map[string]any{"ok": true, "result": map[string]any{"schema_version": schemaVersion, "metadata": map[string]any{"Name": "Public Enrollment", "Version": "0.1.0", "Author": "NotRllyRn", "GitHubRepository": "https://github.com/NotRllyRn/cpa-public-enrollment", "ConfigFields": fields}, "capabilities": map[string]bool{"management_api": true}}})
}
