package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testApp(t *testing.T) *app {
	t.Helper()
	d := newDevice(filepath.Join(t.TempDir(), "state"))
	if d.prepare() != nil {
		t.Fatal("prepare")
	}
	return &app{sessions: map[string]*flow{}, origin: "https://enroll.example", device: d}
}
func request(a *app, path string, v any, c *http.Cookie, origin string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(v)
	r := httptest.NewRequest("POST", path, bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", origin)
	if c != nil {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}
func bootstrap(t *testing.T, a *app) (*http.Cookie, flow) {
	t.Helper()
	w := request(a, "/session", map[string]any{}, nil, a.origin)
	var s flow
	if json.Unmarshal(w.Body.Bytes(), &s) != nil || w.Code != 200 {
		t.Fatal(w.Body)
	}
	return w.Result().Cookies()[0], s
}
func TestSecurity(t *testing.T) {
	a := testApp(t)
	c, s := bootstrap(t, a)
	if request(a, "/approved", map[string]any{"CSRF": s.CSRF, "access_token": "forbidden"}, c, a.origin).Code != 400 {
		t.Fatal("token upload accepted")
	}
	if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
		t.Fatal("cookie flags")
	}
	for _, origin := range []string{"", "https://evil.example", "https://enroll.example.evil"} {
		if request(a, "/start", map[string]any{"CSRF": s.CSRF, "Consent": true}, c, origin).Code != 403 {
			t.Fatal("origin")
		}
	}
	if request(a, "/start", map[string]any{"Consent": true}, c, a.origin).Code != 403 {
		t.Fatal("csrf")
	}
	if request(a, "/start", map[string]any{"CSRF": s.CSRF}, c, a.origin).Code != 400 {
		t.Fatal("consent")
	}
	if request(a, "/created", map[string]any{"CSRF": s.CSRF, "ID": strings.Repeat("a", 9000)}, c, a.origin).Code != 400 {
		t.Fatal("body bound")
	}
	r := httptest.NewRequest("POST", "/session", strings.NewReader("{}"))
	r.Header.Set("Origin", a.origin)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 415 {
		t.Fatal("content type")
	}
}
func TestConcurrentTabs(t *testing.T) {
	a := testApp(t)
	c, s := bootstrap(t, a)
	var wg sync.WaitGroup
	leases := make(chan string, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := request(a, "/start", map[string]any{"CSRF": s.CSRF, "Consent": true}, c, a.origin)
			var v flow
			_ = json.Unmarshal(w.Body.Bytes(), &v)
			if v.Lease != "" {
				leases <- v.Lease
			}
		}()
	}
	wg.Wait()
	close(leases)
	if len(leases) != 1 {
		t.Fatalf("creation permissions: %d", len(leases))
	}
	lease := <-leases
	w := request(a, "/created", map[string]any{"CSRF": s.CSRF, "Lease": lease, "ID": "device-secret", "Code": "CODE", "Interval": 5}, c, a.origin)
	if w.Code != 200 {
		t.Fatal(w.Body)
	}
	w = request(a, "/session", map[string]any{}, c, a.origin)
	if !strings.Contains(w.Body.String(), "device-secret") {
		t.Fatal("resume")
	}
	a.sessions[c.Value].Until = time.Now().Add(-time.Second)
	w = request(a, "/poll", map[string]any{"CSRF": s.CSRF}, c, a.origin)
	var poll flow
	_ = json.Unmarshal(w.Body.Bytes(), &poll)
	if poll.Lease == "" {
		t.Fatal("no poll lease")
	}
	w = request(a, "/poll", map[string]any{"CSRF": s.CSRF}, c, a.origin)
	if strings.Contains(w.Body.String(), "lease") {
		t.Fatal("duplicate poll")
	}
	w = request(a, "/status", map[string]any{"CSRF": s.CSRF}, c, a.origin)
	if strings.Contains(w.Body.String(), poll.Lease) {
		t.Fatal("lease leaked")
	}
	if request(a, "/approved", map[string]any{"CSRF": s.CSRF, "Lease": "wrong", "AuthorizationCode": "x", "Verifier": "y"}, c, a.origin).Code != 409 {
		t.Fatal("approval fencing")
	}
}
func TestAbandonedReservation(t *testing.T) {
	a := testApp(t)
	c, s := bootstrap(t, a)
	v := map[string]any{"CSRF": s.CSRF, "Consent": true}
	w := request(a, "/start", v, c, a.origin)
	var old flow
	_ = json.Unmarshal(w.Body.Bytes(), &old)
	a.sessions[c.Value].Until = time.Now().Add(-time.Second)
	w = request(a, "/start", v, c, a.origin)
	var next flow
	_ = json.Unmarshal(w.Body.Bytes(), &next)
	if next.Lease == old.Lease || next.Lease == "" {
		t.Fatal("reservation not renewed")
	}
	if request(a, "/created", map[string]any{"CSRF": s.CSRF, "Lease": old.Lease, "ID": "x", "Code": "y"}, c, a.origin).Code != 409 {
		t.Fatal("stale creator accepted")
	}
}
func TestExpiry(t *testing.T) {
	a := testApp(t)
	c, s := bootstrap(t, a)
	a.sessions[c.Value].Expires = time.Now().Add(-sessionGrace - time.Second)
	if request(a, "/status", map[string]any{"CSRF": s.CSRF}, c, a.origin).Code != 403 {
		t.Fatal("expired session accepted")
	}
}
