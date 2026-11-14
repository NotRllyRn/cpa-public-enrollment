package main

import (
	"testing"
	"time"
)

func TestExpiredFlowCannotAuthorize(t *testing.T) {
	for _, status := range []string{"idle", "creating", "waiting", "saving", "verifying", "complete", "operator-review", "duplicate", "error"} {
		t.Run(status, func(t *testing.T) {
			a := testApp(t)
			cookie, initial := bootstrap(t, a)
			s := a.sessions[cookie.Value]
			s.Status, s.Lease = status, "lease"
			s.Expires = time.Now().Add(-time.Second)
			s.Until = time.Now().Add(time.Minute)
			in := map[string]any{"CSRF": initial.CSRF, "Consent": true, "Lease": "lease", "ID": "id", "Code": "code", "AuthorizationCode": "approval", "Verifier": "proof"}
			for _, path := range []string{"/start", "/created", "/poll", "/approved"} {
				if w := request(a, path, in, cookie, a.origin); w.Code != 409 {
					t.Fatalf("%s accepted expired %s", path, status)
				}
			}
			if w := request(a, "/status", in, cookie, a.origin); w.Code != 200 {
				t.Fatal("result unavailable")
			}
			if status == "idle" || status == "creating" || status == "waiting" {
				if s.Status != "expired" || s.Lease != "" {
					t.Fatal("unfinished flow did not expire")
				}
			} else if s.Status != status || s.Lease != "lease" {
				t.Fatal("save/result mutated")
			}
		})
	}
}
