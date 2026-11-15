package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func requireSessionError(t *testing.T, w *httptest.ResponseRecorder, code string) {
	t.Helper()
	var v struct {
		Error struct{ Code, Message string }
	}
	if w.Code < 400 || json.Unmarshal(w.Body.Bytes(), &v) != nil || v.Error.Code != code || v.Error.Message == "" || strings.Contains(strings.ToLower(v.Error.Message), "reload") {
		t.Fatalf("expected structured %s: %d %s", code, w.Code, w.Body)
	}
}
func TestExpiredRecoveryRotatesIdentityAndFencesTabs(t *testing.T) {
	for _, status := range []string{"idle", "creating", "waiting"} {
		t.Run(status, func(t *testing.T) {
			a := testApp(t)
			cookie, initial := bootstrap(t, a)
			s := a.sessions[cookie.Value]
			s.Status = status
			s.ID = "secret-device"
			s.Code = "CODE"
			s.Lease = "proof"
			s.Expires = time.Now().Add(-time.Second)
			input := map[string]any{"CSRF": initial.CSRF}
			for _, path := range []string{"/session", "/status"} {
				w := request(a, path, input, cookie, a.origin)
				var got flow
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil || got.Status != "expired" || got.ID != "" || got.Code != "" || got.Lease != "" || len(w.Result().Cookies()) != 0 {
					t.Fatal(w.Body)
				}
			}
			requireSessionError(t, request(a, "/poll", input, cookie, a.origin), "session_expired")
			w := request(a, "/restart", input, cookie, a.origin)
			var next flow
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &next) != nil {
				t.Fatal(w.Body)
			}
			cookies := w.Result().Cookies()
			if len(cookies) != 1 || cookies[0].Value == cookie.Value || next.CSRF == initial.CSRF || next.Status != "idle" || len(a.sessions) != 1 || !next.Expires.After(time.Now().Add(14*time.Minute)) {
				t.Fatal("did not rotate session")
			}
			// A stale tab now sends the browser's NEW shared cookie but its OLD CSRF.
			requireSessionError(t, request(a, "/restart", input, cookies[0], a.origin), "session_changed")
			requireSessionError(t, request(a, "/approved", input, cookies[0], a.origin), "session_changed")
			resumed := request(a, "/session", input, cookies[0], a.origin)
			if !strings.Contains(resumed.Body.String(), next.CSRF) || len(resumed.Result().Cookies()) != 0 {
				t.Fatal("stale tab cannot synchronize")
			}
			requireSessionError(t, request(a, "/status", input, cookie, a.origin), "session_lost")
		})
	}
}
func TestRecoveryCannotResetSaveOrResult(t *testing.T) {
	for _, status := range []string{"idle", "creating", "waiting", "saving", "verifying", "complete"} {
		t.Run(status, func(t *testing.T) {
			a := testApp(t)
			cookie, s := bootstrap(t, a)
			active := a.sessions[cookie.Value]
			active.Status = status
			if status != "idle" && status != "creating" && status != "waiting" {
				active.Expires = time.Now().Add(-time.Second)
			}
			requireSessionError(t, request(a, "/restart", map[string]any{"CSRF": s.CSRF}, cookie, a.origin), "session_active")
			if active.Status != status || len(a.sessions) != 1 {
				t.Fatal("reset active/result")
			}
		})
	}
}
func TestMissingSessionRequiresExplicitRecovery(t *testing.T) {
	a := testApp(t)
	cookie, s := bootstrap(t, a)
	delete(a.sessions, cookie.Value)
	for _, path := range []string{"/session", "/status", "/start", "/approved"} {
		w := request(a, path, map[string]any{"CSRF": s.CSRF}, cookie, a.origin)
		requireSessionError(t, w, "session_lost")
		if len(w.Result().Cookies()) != 0 || len(a.sessions) != 0 || !strings.Contains(w.Body.String(), "session is unavailable") {
			t.Fatal("silently reset missing session")
		}
	}
	if request(a, "/restart", map[string]any{}, cookie, "https://evil.example").Code != 403 {
		t.Fatal("cross-origin recovery")
	}
	w := request(a, "/restart", map[string]any{}, cookie, a.origin)
	if w.Code != 200 || len(w.Result().Cookies()) != 1 || len(a.sessions) != 1 {
		t.Fatal(w.Body)
	}
}
func TestRetentionProtectsSavesAndKeepsTerminalResults(t *testing.T) {
	for _, status := range []string{"saving", "verifying"} {
		a := testApp(t)
		cookie, _ := bootstrap(t, a)
		s := a.sessions[cookie.Value]
		s.Status = status
		s.Expires = time.Now().Add(-time.Hour)
		a.pruneSessions(time.Now())
		if a.sessions[cookie.Value] != s || s.Status != status {
			t.Fatal("pruned in-flight save")
		}
		for _, terminal := range []string{"complete", "duplicate", "error", "operator-review"} {
			a.state(s, terminal)
			a.pruneSessions(s.Finished.Add(sessionGrace - time.Nanosecond))
			if a.sessions[cookie.Value] != s || s.Status != terminal {
				t.Fatal("lost terminal result")
			}
		}
		a.pruneSessions(s.Finished.Add(sessionGrace))
		if len(a.sessions) != 0 {
			t.Fatal("unbounded terminal retention")
		}
	}
}
