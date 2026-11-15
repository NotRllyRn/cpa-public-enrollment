package main

import (
	"encoding/json"
	"testing"
	"time"
)

func TestClientFailureContract(t *testing.T) {
	a := testApp(t)
	// No worker is needed to inspect admission and the exact queued payload.
	a.webhook = &webhook{queue: make(chan notification, 8)}
	c, s := bootstrap(t, a)
	w := request(a, "/start", map[string]any{"CSRF": s.CSRF, "Consent": true}, c, a.origin)
	if json.Unmarshal(w.Body.Bytes(), &s) != nil || s.Lease == "" {
		t.Fatal(w.Body)
	}
	for _, data := range []map[string]any{
		{"Stage": "creation", "Lease": s.Lease},
		{"CSRF": s.CSRF, "Stage": "success", "Lease": s.Lease},
		{"CSRF": s.CSRF, "Stage": "poll", "Lease": s.Lease},
		{"CSRF": s.CSRF, "Stage": "creation", "Lease": "wrong"},
		{"CSRF": s.CSRF, "Stage": "creation", "Lease": s.Lease, "Email": "spoof@example.test"},
		{"CSRF": s.CSRF, "Stage": "creation", "Lease": s.Lease, "Error": "secret"},
	} {
		if request(a, "/client-failure", data, c, a.origin).Code == 200 {
			t.Fatal("accepted invalid report")
		}
	}
	data := map[string]any{"CSRF": s.CSRF, "Stage": "creation", "Lease": s.Lease}
	if request(a, "/client-failure", data, c, a.origin).Code != 200 {
		t.Fatal("report rejected")
	}
	if request(a, "/client-failure", data, c, a.origin).Code == 200 {
		t.Fatal("duplicate accepted")
	}
	select {
	case n := <-a.webhook.queue:
		if n.Event != "client_failure" || n.Status != "error" || n.Email != "" || n.Error != "Browser reported a device creation failure." {
			t.Fatal(n)
		}
	case <-time.After(time.Second):
		t.Fatal("missing event")
	}
	if len(a.webhook.queue) != 0 {
		t.Fatal("extra notification")
	}
}
