package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(body string) *http.Response {
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}
func tokenResponse() string {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"email":"person@example.com","https://api.openai.com/auth":{"chatgpt_account_id":"acct","chatgpt_plan_type":"plus"}}`))
	return fmt.Sprintf(`{"access_token":"access-secret","refresh_token":"refresh-secret","id_token":"a.%s.c","expires_in":3600}`, payload)
}
func TestImportAdoption(t *testing.T) {
	for _, duplicate := range []bool{false, true} {
		t.Run(fmt.Sprint(duplicate), func(t *testing.T) {
			a := testApp(t)
			posts := 0
			gets := 0
			name := ""
			a.device.HTTP = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() != exchangeEndpoint {
					t.Fatal("unexpected endpoint")
				}
				body, _ := io.ReadAll(r.Body)
				if !strings.Contains(string(body), "code_verifier=proof") {
					t.Fatal("exchange proof")
				}
				return response(tokenResponse()), nil
			})}
			a.management = NewManagement("https://private.example", "admin-secret")
			a.management.HTTP.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
				if r.Header.Get("Authorization") != "Bearer admin-secret" {
					t.Fatal("missing admin auth")
				}
				if r.Method == "POST" {
					posts++
					name = r.URL.Query().Get("name")
					return nil, fmt.Errorf("ambiguous transport failure")
				}
				gets++
				if duplicate {
					return response(`{"files":[{"provider":"codex","account_id":"acct","name":"existing"}]}`), nil
				}
				if gets == 1 {
					return response(`{"files":[]}`), nil
				}
				return response(fmt.Sprintf(`{"files":[{"name":%q,"provider":"codex","account_id":"acct","source":"file","adopted":true}]}`, name)), nil
			})
			s := &flow{Status: "saving"}
			a.adopt.Lock()
			a.save(s, "approval", "proof")
			entries, _ := os.ReadDir(a.device.Dir)
			if duplicate {
				if posts != 0 || s.Status != "duplicate" || len(entries) != 1 {
					t.Fatalf("duplicate: %d %s %d", posts, s.Status, len(entries))
				}
			} else if posts != 1 || s.Status != "complete" || len(entries) != 0 {
				t.Fatalf("adoption: %d %s %d", posts, s.Status, len(entries))
			}
		})
	}
}
func TestPendingIsDurableAndNeverReplayed(t *testing.T) {
	a := testApp(t)
	tok := nativeToken{Account: "acct", Access: "secret"}
	if a.device.persist("pending.json", &tok) != nil {
		t.Fatal("persist")
	}
	info, _ := os.Stat(filepath.Join(a.device.Dir, "pending.json"))
	if info.Mode().Perm() != 0600 {
		t.Fatal("permissions")
	}
	if a.device.persist("pending.json", &tok) == nil {
		t.Fatal("overwrite")
	}
	if a.device.checkPending("other.json", "acct") == nil {
		t.Fatal("pending duplicate")
	}
	if a.device.checkPending("other.json", "different") != nil {
		t.Fatal("unrelated account")
	}
	if _, err := a.device.request(context.Background(), "http://evil.example", "application/json", nil, nil); err == nil {
		t.Fatal("arbitrary outbound accepted")
	}
}
func TestIdentityRequiresFields(t *testing.T) {
	for _, v := range []nativeToken{{}, {Access: "a", Refresh: "b", ID: "a.e30.c", Expires: 3600}} {
		if v.identity() == nil {
			t.Fatal("invalid identity")
		}
	}
}
