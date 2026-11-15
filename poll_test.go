package main

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func TestPollLeaseAndPendingDeadline(t *testing.T) {
	for _, interval := range []int{0, 3, 5, 901, 90001} {
		a := testApp(t)
		c, initial := bootstrap(t, a)
		s := a.sessions[c.Value]
		s.Status, s.Lease, s.Until = "creating", "create", time.Now().Add(time.Minute)
		w := request(a, "/created", map[string]any{"CSRF": initial.CSRF, "Lease": "create", "ID": "id", "Code": "code", "Interval": interval}, c, a.origin)
		if w.Code != 200 {
			t.Fatal(w.Body)
		}
		want := interval
		if want < 3 {
			want = 3
		}
		if s.Interval != want {
			t.Fatalf("interval %d became %d", interval, s.Interval)
		}
		s.Until = time.Now().Add(-time.Second)
		var wg sync.WaitGroup
		leases := make(chan string, 12)
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				w := request(a, "/poll", map[string]any{"CSRF": initial.CSRF}, c, a.origin)
				var out flow
				_ = json.Unmarshal(w.Body.Bytes(), &out)
				if out.Lease != "" {
					leases <- out.Lease
				}
			}()
		}
		wg.Wait()
		close(leases)
		if len(leases) != 1 {
			t.Fatalf("poll claims: %d", len(leases))
		}
		lease := <-leases
		if d := time.Until(s.PollUntil); d < 19*time.Second || d > 20*time.Second {
			t.Fatalf("lease safety deadline %v", d)
		}
		if d := time.Until(s.Until); d > time.Duration(want)*time.Second {
			t.Fatalf("normal deadline includes reservation: %v", d)
		}
		// Passing the next-check deadline does not allow another in-flight check.
		s.Until = time.Now().Add(-time.Second)
		request(a, "/poll", map[string]any{"CSRF": initial.CSRF}, c, a.origin)
		if s.Lease != lease {
			t.Fatal("live lease replaced")
		}
		if request(a, "/pending", map[string]any{"CSRF": initial.CSRF, "Lease": "wrong"}, c, a.origin).Code != 409 {
			t.Fatal("stale pending accepted")
		}
		w = request(a, "/pending", map[string]any{"CSRF": initial.CSRF, "Lease": lease, "Interval": want + 5}, c, a.origin)
		if w.Code != 200 || s.Lease != "" || !s.PollUntil.IsZero() {
			t.Fatalf("pending release: %s", w.Body)
		}
		if d := time.Until(s.Until); d < time.Duration(want+4)*time.Second || d > time.Duration(want+5)*time.Second {
			t.Fatalf("pending backoff %v", d)
		}
		s.Until = time.Now().Add(-time.Second)
		request(a, "/poll", map[string]any{"CSRF": initial.CSRF}, c, a.origin)
		next := s.Lease
		if request(a, "/pending", map[string]any{"CSRF": initial.CSRF, "Lease": lease}, c, a.origin).Code != 409 || s.Lease != next {
			t.Fatal("late acknowledgement changed current lease")
		}
		s.PollUntil = time.Now().Add(-time.Second)
		if request(a, "/approved", map[string]any{"CSRF": initial.CSRF, "Lease": next, "AuthorizationCode": "proof", "Verifier": "proof"}, c, a.origin).Code != 409 {
			t.Fatal("expired approval accepted")
		}
		request(a, "/poll", map[string]any{"CSRF": initial.CSRF}, c, a.origin)
		if s.Status != "error" || s.Lease != "" {
			t.Fatal("ambiguous poll replayed")
		}
	}
}
