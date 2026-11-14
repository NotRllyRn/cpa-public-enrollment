package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestApprovalAtMostOneExchangeAndShutdownFence(t *testing.T) {
	a := testApp(t)
	cookie, s := bootstrap(t, a)
	active := a.sessions[cookie.Value]
	active.Status = "waiting"
	active.Lease = "poll-proof"
	active.Until = time.Now().Add(time.Minute)
	var exchanges atomic.Int32
	a.device.HTTP = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		exchanges.Add(1)
		return &http.Response{StatusCode: 400, Body: http.NoBody, Header: make(http.Header)}, nil
	})}
	input := map[string]any{"CSRF": s.CSRF, "Lease": "poll-proof", "AuthorizationCode": "code", "Verifier": "proof"}
	if request(a, "/approved", input, cookie, a.origin).Code != 200 {
		t.Fatal("approval")
	}
	a.wg.Wait()
	// Failed exchange is terminal too: no retry of a possibly consumed authorization code.
	if request(a, "/approved", input, cookie, a.origin).Code != 409 {
		t.Fatal("failed exchange retried")
	}
	if exchanges.Load() != 1 {
		t.Fatal("multiple exchanges")
	}
	a.mu.Lock()
	a.closing = true
	a.mu.Unlock()
	if request(a, "/session", map[string]any{}, cookie, a.origin).Code != 503 {
		t.Fatal("shutdown accepted admission")
	}
}

func TestDeadlineRetainsSaveResult(t *testing.T) {
	a := testApp(t)
	cookie, initial := bootstrap(t, a)
	if cookie.MaxAge != 0 {
		t.Fatal("server must own retention; surviving cookie explains lost state")
	}
	s := a.sessions[cookie.Value]
	s.Status, s.Lease = "waiting", "proof"
	s.Until = time.Now().Add(time.Minute)
	s.Expires = time.Now().Add(time.Second)
	entered, release := make(chan struct{}), make(chan struct{})
	a.device.HTTP = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		close(entered)
		<-release
		return response(tokenResponse()), nil
	})}
	// Persistence fails after exchange; uncertain evidence must remain untouched.
	evidence := filepath.Join(a.device.Dir, "evidence.json")
	if err := os.WriteFile(evidence, []byte("secret evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(a.device.Dir, 0755); err != nil {
		t.Fatal(err)
	}
	input := map[string]any{"CSRF": initial.CSRF, "Lease": "proof", "AuthorizationCode": "code", "Verifier": "proof", "Consent": true}
	if w := request(a, "/approved", input, cookie, a.origin); w.Code != 200 {
		t.Fatal(w.Body)
	}
	<-entered
	a.mu.Lock()
	s.Expires = time.Now().Add(-sessionGrace - time.Second)
	a.pruneSessions(time.Now())
	a.mu.Unlock()
	for _, path := range []string{"/status", "/session"} {
		w := request(a, path, input, cookie, a.origin)
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"saving"`) || len(w.Result().Cookies()) != 0 {
			t.Fatalf("lost in-flight session: %s", w.Body)
		}
	}
	for _, path := range []string{"/start", "/created", "/poll", "/approved"} {
		if w := request(a, path, input, cookie, a.origin); w.Code != 409 {
			t.Fatalf("expired %s: %d", path, w.Code)
		}
	}
	close(release)
	a.wg.Wait()
	w := request(a, "/status", input, cookie, a.origin)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"operator-review"`) {
		t.Fatal(w.Body)
	}
	data, err := os.ReadFile(evidence)
	if err != nil || string(data) != "secret evidence" {
		t.Fatal("lost evidence", err)
	}
	// No management client is configured: any upload would panic. Exchange transport
	// also panics on a second call, ensuring expired approval never replays it.
	if request(a, "/approved", input, cookie, a.origin).Code != 409 {
		t.Fatal("replayed")
	}
	a.mu.Lock()
	a.pruneSessions(s.retainedUntil())
	remaining := len(a.sessions)
	a.mu.Unlock()
	if remaining != 0 {
		t.Fatal("unbounded retention")
	}
}
