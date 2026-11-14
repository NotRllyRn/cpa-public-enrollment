package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveDiagnosticBeforeUpload(t *testing.T) {
	for _, tc := range []struct{ name, inventory, pending, want string }{
		{"inventory", `<html>SECRET</html>`, "", "Checking CPA inventory before upload failed"},
		{"pending", `{"files":[]}`, `{"account_id":"account","email":"member@example.test"}`, "Checking pending enrollments failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := testApp(t)
			var token nativeToken
			if err := json.Unmarshal([]byte(tokenResponse()), &token); err != nil {
				t.Fatal(err)
			}
			if err := token.identity(); err != nil {
				t.Fatal(err)
			}
			if tc.pending != "" {
				raw, _ := json.Marshal(token)
				if err := os.WriteFile(filepath.Join(a.device.Dir, "old.json"), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			posts := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "POST" {
					posts++
				}
				_, _ = w.Write([]byte(tc.inventory))
			}))
			defer srv.Close()
			a.management = NewManagement(srv.URL, "")
			a.device.HTTP = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) { return response(tokenResponse()), nil })}
			s := &flow{}
			a.adopt.Lock()
			a.save(s, "code", "verifier")
			if s.Status != "operator-review" || !strings.Contains(s.Message, tc.want) || posts != 0 {
				t.Fatalf("%+v posts=%d", s, posts)
			}
			if strings.Contains(s.Message, "SECRET") || strings.Contains(s.Message, token.Email) || strings.Contains(s.Message, a.device.Dir) {
				t.Fatal(s.Message)
			}
		})
	}
}

func TestDeviceRequestDiagnosticSafety(t *testing.T) {
	for _, tc := range []struct {
		body   string
		status int
		want   string
	}{
		{"<html>SECRET member@example.test /private/path</html>", 401, "HTTP 401 (Unauthorized)"},
		{"<html>SECRET member@example.test /private/path</html>", 200, "invalid JSON"},
	} {
		d := newDevice(t.TempDir())
		d.HTTP = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			res := response(tc.body)
			res.StatusCode = tc.status
			return res, nil
		})}
		var token nativeToken
		status, err := d.request(context.Background(), exchangeEndpoint, "application/json", nil, &token)
		if err == nil {
			err = httpFailure(status)
		}
		reason := safeReason(err)
		if !strings.Contains(reason, tc.want) || strings.Contains(reason, "SECRET") || strings.Contains(reason, "member@") || strings.Contains(reason, "/private") {
			t.Fatal(reason)
		}
	}
}

func TestSafeDiagnostics(t *testing.T) {
	secret := "<html>token=SECRET person@example.test /private/secret stack trace</html>"
	for _, status := range []int{401, 403, 429, 500} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status); _, _ = w.Write([]byte(secret)) }))
		err := NewManagement(srv.URL, "SECRET").Call(context.Background(), "GET", "/credentials", nil, &struct{}{})
		srv.Close()
		if !strings.Contains(safeReason(err), http.StatusText(status)) || strings.Contains(safeReason(err), "SECRET") {
			t.Fatal(err)
		}
	}
	a := &app{}
	s := &flow{}
	a.fail(s, "operator-review", "Checking inventory failed", errors.New(secret))
	raw, _ := json.Marshal(s)
	if strings.Contains(string(raw), "SECRET") || !strings.Contains(s.Message, "Checking inventory failed") {
		t.Fatal(string(raw))
	}
}
func TestInventoryDiagnosticBranches(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{`<html>SECRET</html>`, "invalid inventory JSON"},
		{`{}`, "missing the files list"},
		{`{"files":[{"type":"codex","account_id":"secret-account"}]}`, "without a member identity"},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(tc.body)) }))
		a := &app{management: NewManagement(srv.URL, "")}
		_, err := a.inventory(context.Background())
		srv.Close()
		if err == nil || !strings.Contains(safeReason(err), tc.want) || strings.Contains(safeReason(err), "SECRET") || strings.Contains(safeReason(err), "secret-account") {
			t.Fatal(err)
		}
	}
}
func TestPendingDiagnosticBranches(t *testing.T) {
	d := newDevice(t.TempDir())
	path := filepath.Join(d.Dir, "old.json")
	for _, tc := range []struct{ body, want string }{
		{`{"account_id":"account","email":"member@example.test"}`, "earlier pending enrollment"},
		{`{"account_id":"account"}`, "incomplete member identity"},
		{`<html>SECRET</html>`, "unreadable"},
	} {
		if err := os.WriteFile(path, []byte(tc.body), 0600); err != nil {
			t.Fatal(err)
		}
		err := d.checkPending("new.json", "account", "member@example.test")
		if err == nil || !strings.Contains(safeReason(err), tc.want) || strings.Contains(safeReason(err), "member@example.test") || strings.Contains(safeReason(err), "SECRET") {
			t.Fatal(err)
		}
	}
}
