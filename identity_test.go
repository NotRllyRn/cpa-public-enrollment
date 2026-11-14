package main

import (
	"context"
	"net/http"
	"testing"
)

func TestInventoryRequiresMemberIdentity(t *testing.T) {
	for _, body := range []string{
		`{"files":[{"provider":"codex","account_id":"workspace"}]}`,
		`{"files":[{"provider":"codex","email":"member@example.com"}]}`,
		`{"files":[{"provider":"codex","account_id":"workspace","email":"  "}]}`,
	} {
		a := testApp(t)
		a.management = NewManagement("https://private.example", "key")
		a.management.HTTP.Transport = roundTrip(func(*http.Request) (*http.Response, error) { return response(body), nil })
		if _, err := a.inventory(context.Background()); err == nil {
			t.Fatal("accepted incomplete identity")
		}
	}
}

func TestPendingRequiresMemberIdentity(t *testing.T) {
	a := testApp(t)
	if err := a.device.persist("unknown.json", &nativeToken{Account: "workspace"}); err != nil {
		t.Fatal(err)
	}
	if a.device.checkPending("new.json", "workspace", "member@example.com") == nil {
		t.Fatal("accepted unknown pending member")
	}
}
