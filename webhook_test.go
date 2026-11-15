package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWebhookValidation(t *testing.T) {
	for _, s := range []string{"http://example.com", "https://u:p@example.com", "https://example.com/#secret", "https://", ":bad"} {
		if validateWebhook(s) == nil {
			t.Fatal("accepted invalid URL")
		}
	}
	for _, s := range []string{"", "https://example.com/hook?key=private", "https://127.0.0.1/hook"} {
		if validateWebhook(s) != nil {
			t.Fatal("rejected valid URL")
		}
	}
}
func TestWebhookPayloadOnceAndNoRedirect(t *testing.T) {
	received := make(chan []byte, 8)
	redirects := make(chan bool, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirects <- true }))
	defer target.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		received <- b
		w.Header().Set("Location", target.URL)
		w.WriteHeader(302)
	}))
	defer srv.Close()
	h := newWebhook(srv.URL, srv.Client().Transport)
	defer h.stop()
	a := &app{webhook: h}
	s := &flow{Email: "person@example.test", ID: "secret-id", Code: "secret-code", CSRF: "secret-csrf", Lease: "secret-lease"}
	a.fail(s, "operator-review", "Save failed", errors.New("raw-secret-upstream"))
	a.state(s, "complete")
	select {
	case raw := <-received:
		var n notification
		if json.Unmarshal(raw, &n) != nil || n.Status != "operator-review" || n.Email != s.Email || n.Timestamp.IsZero() || n.Error != "Save failed: operation failed." {
			t.Fatal(string(raw))
		}
		if strings.Contains(string(raw), "secret") {
			t.Fatal("secret leaked")
		}
	case <-time.After(time.Second):
		t.Fatal("no delivery")
	}
	select {
	case <-received:
		t.Fatal("duplicate")
	case <-redirects:
		t.Fatal("redirect followed")
	case <-time.After(50 * time.Millisecond):
	}
}
func TestWebhookBoundedAndStop(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { started <- struct{}{}; <-release }))
	defer srv.Close()
	defer close(release)
	h := newWebhook(srv.URL, srv.Client().Transport)
	a := &app{webhook: h}
	for i := 0; i < 1000; i++ {
		a.state(&flow{}, "complete")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("worker not started")
	}
	done := make(chan struct{})
	go func() { h.stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker leaked")
	}
	h.stop()
}
