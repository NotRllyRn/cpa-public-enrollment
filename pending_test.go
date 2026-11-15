package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPendingRetentionAndOwnership(t *testing.T) {
	d := &Device{Dir: t.TempDir()}
	os.Chmod(d.Dir, 0700)
	now := time.Now()
	owner := pendingOwner(nonce())
	other := pendingOwner(nonce())
	names := []string{"codex-device-" + owner + "-" + nonce() + ".json", "codex-device-" + other + "-" + nonce() + ".json", "codex-device-" + nonce() + ".json", "codex-device-" + nonce() + ".json", "unrelated.json"}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(d.Dir, n), []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	old := now.Add(-pendingTTL - time.Second)
	os.Chtimes(filepath.Join(d.Dir, names[2]), old, old)
	if err := d.cleanupPending(now, owner); err != nil {
		t.Fatal(err)
	}
	if err := d.cleanupPending(now, ""); err != nil {
		t.Fatal(err)
	}
	for i, n := range names {
		_, err := os.Stat(filepath.Join(d.Dir, n))
		if (i == 0 || i == 2) != os.IsNotExist(err) {
			t.Fatalf("wrong retention %s: %v", n, err)
		}
	}
	if pendingName("../"+names[0]) || pendingName("codex-device-../../x.json") {
		t.Fatal("traversal")
	}
	target := filepath.Join(t.TempDir(), "target")
	os.WriteFile(target, []byte("keep"), 0600)
	os.Symlink(target, filepath.Join(d.Dir, "codex-device-"+nonce()+".json"))
	if d.cleanupPending(now, owner) == nil {
		t.Fatal("accepted symlink")
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Fatal("followed link")
	}
}
func TestResetOwnedPendingAfterRestart(t *testing.T) {
	a := testApp(t)
	cookie, s := bootstrap(t, a)
	own := "codex-device-" + pendingOwner(cookie.Value) + "-" + nonce() + ".json"
	other := "codex-device-" + pendingOwner(nonce()) + "-" + nonce() + ".json"
	for _, n := range []string{own, other} {
		os.WriteFile(filepath.Join(a.device.Dir, n), []byte("{}"), 0600)
	}
	old := time.Now().Add(-pendingTTL - time.Second)
	if err := os.Chtimes(filepath.Join(a.device.Dir, other), old, old); err != nil {
		t.Fatal(err)
	}
	delete(a.sessions, cookie.Value) // runtime restart loses all in-memory state
	if w := request(a, "/restart", map[string]any{}, cookie, "https://evil.example"); w.Code != 403 {
		t.Fatal(w.Body)
	}
	a.adopt.Lock()
	if w := request(a, "/restart", map[string]any{}, cookie, a.origin); w.Code != 409 {
		t.Fatal(w.Body)
	}
	a.cleanupPending(time.Now().Add(time.Hour)) // active save keeps even expired evidence
	a.adopt.Unlock()
	if _, err := os.Stat(filepath.Join(a.device.Dir, own)); err != nil {
		t.Fatal(err)
	}
	w := request(a, "/restart", map[string]any{}, cookie, a.origin)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"idle"`) {
		t.Fatal(w.Body)
	}
	if _, err := os.Stat(filepath.Join(a.device.Dir, own)); !os.IsNotExist(err) {
		t.Fatal("own retained")
	}
	if _, err := os.Stat(filepath.Join(a.device.Dir, other)); err != nil {
		t.Fatal("cross-session deletion", err)
	}
	requireSessionError(t, request(a, "/restart", map[string]any{"CSRF": s.CSRF}, w.Result().Cookies()[0], a.origin), "session_changed")
}
func TestResetCleanupFailureKeepsSession(t *testing.T) {
	a := testApp(t)
	c, s := bootstrap(t, a)
	a.sessions[c.Value].Status = "error"
	if err := os.Chmod(a.device.Dir, 0755); err != nil {
		t.Fatal(err)
	}
	w := request(a, "/restart", map[string]any{"CSRF": s.CSRF}, c, a.origin)
	requireSessionError(t, w, "cleanup_failed")
	if len(w.Result().Cookies()) != 0 || a.sessions[c.Value] == nil {
		t.Fatal("rotated failed reset")
	}
}
func TestBlockedRetryDoesNotAccumulateOrUpload(t *testing.T) {
	a := testApp(t)
	name := "codex-device-" + nonce() + ".json"
	if err := a.device.persist(name, &nativeToken{Account: "acct", Email: "person@example.com", Access: "secret"}); err != nil {
		t.Fatal(err)
	}
	a.device.HTTP = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) { return response(tokenResponse()), nil })}
	a.management = NewManagement("https://private.example", "key")
	calls := 0
	a.management.HTTP.Transport = roundTrip(func(r *http.Request) (*http.Response, error) { calls++; return response(`{"files":[]}`), nil })
	for i := 0; i < 2; i++ {
		s := &flow{Status: "saving"}
		a.adopt.Lock()
		a.save(s, "approval", "proof")
		if s.Status != "operator-review" {
			t.Fatal(s.Status)
		}
	}
	entries, err := os.ReadDir(a.device.Dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != name || calls != 0 {
		t.Fatalf("retry accumulated or contacted CPA: %v %d", entries, calls)
	}
}
func TestTerminalReset(t *testing.T) {
	for _, status := range []string{"error", "operator-review", "duplicate"} {
		t.Run(status, func(t *testing.T) {
			a := testApp(t)
			c, s := bootstrap(t, a)
			a.sessions[c.Value].Status = status
			w := request(a, "/restart", map[string]any{"CSRF": s.CSRF}, c, a.origin)
			if w.Code != 200 {
				t.Fatal(w.Body)
			}
		})
	}
}
