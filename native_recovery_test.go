//go:build native

package main

import (
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"
)

func nativeTestAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}
func TestNativeQuiesceDrainsSaveAndReconfigureResumes(t *testing.T) {
	defer shutdown()
	addr := nativeTestAddress(t)
	raw := testNativeConfig(t, addr)
	if err := configure(raw); err != nil {
		t.Fatal(err)
	}
	r := nativeRuntime.current
	cookie, initial := bootstrap(t, r.app)
	r.app.mu.Lock()
	s := r.app.sessions[cookie.Value]
	s.Status = "waiting"
	s.Lease = "proof"
	s.Until = time.Now().Add(time.Minute)
	r.app.mu.Unlock()
	entered, release := make(chan struct{}), make(chan struct{})
	r.app.device.HTTP = &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
		close(entered)
		<-release
		return &http.Response{StatusCode: 400, Body: http.NoBody}, nil
	})}
	if w := request(r.app, "/approved", map[string]any{"CSRF": initial.CSRF, "Lease": "proof", "AuthorizationCode": "code", "Verifier": "proof"}, cookie, r.app.origin); w.Code != 200 {
		t.Fatal(w.Body)
	}
	<-entered
	finished := make(chan error, 1)
	go func() { finished <- quiesce() }()
	// Quiesce must release the real port while the admitted save is still draining.
	deadline := time.Now().Add(5 * time.Second)
	for {
		l, err := net.Listen("tcp", addr)
		if err == nil {
			l.Close()
			break
		}
		if time.Now().After(deadline) {
			close(release)
			t.Fatal("listener not released before save drain", err)
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case err := <-finished:
		close(release)
		t.Fatal("quiesce returned before save", err)
	default:
	}
	requireSessionError(t, request(r.app, "/session", map[string]any{}, cookie, r.app.origin), "service_updating")
	close(release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if r.server != nil {
		t.Fatal("quiesced server retained")
	}
	// Host rollback calls reconfigure, not a made-up plugin.resume method.
	req, _ := json.Marshal(map[string]any{"schema_version": 10, "config_yaml": raw})
	var result map[string]any
	nativeResult(t, "plugin.reconfigure", string(req), &result)
	r.app.mu.Lock()
	preserved := r.app.sessions[cookie.Value] == s
	r.app.mu.Unlock()
	if nativeRuntime.current != r || !preserved {
		t.Fatal("rollback lost sessions")
	}
	w := request(r.app, "/status", map[string]any{"CSRF": initial.CSRF}, cookie, r.app.origin)
	r.app.mu.Lock()
	status := s.Status
	r.app.mu.Unlock()
	if w.Code != 200 || status != "error" {
		t.Fatal(w.Body)
	}
	res, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatal("listener did not resume", err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
	nativeResult(t, "plugin.quiesce", "{}", &result)
	nativeResult(t, "plugin.quiesce", "{}", &result) // idempotent
	if err := configure(raw); err != nil {
		t.Fatal(err)
	}
}
func TestNativeFailedDrainAndBindCanResume(t *testing.T) {
	defer shutdown()
	addr := nativeTestAddress(t)
	raw := testNativeConfig(t, addr)
	if err := configure(raw); err != nil {
		t.Fatal(err)
	}
	r := nativeRuntime.current
	cookie, s := bootstrap(t, r.app)
	blocked := make(chan struct{})
	r.app.mu.Lock()
	r.app.saveDone = blocked
	r.app.mu.Unlock()
	started := time.Now()
	nativeRuntime.Lock()
	err := r.quiesce(20 * time.Millisecond)
	nativeRuntime.Unlock()
	if err == nil || time.Since(started) > time.Second {
		close(blocked)
		t.Fatal("drain was not bounded", err)
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		close(blocked)
		t.Fatal(err)
	}
	if err := configure(raw); err == nil {
		l.Close()
		close(blocked)
		t.Fatal("failed resume bind reported success")
	}
	l.Close()
	if err := configure(raw); err != nil {
		close(blocked)
		t.Fatal(err)
	}
	// A timed-out save can still finish after rollback; the same app is retained.
	close(blocked)
	r.app.mu.Lock()
	preserved := r.app.sessions[cookie.Value].CSRF == s.CSRF
	r.app.mu.Unlock()
	if nativeRuntime.current != r || !preserved {
		t.Fatal("failed drain lost state")
	}
}
