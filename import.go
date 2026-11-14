package main

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

func (a *app) inventory(ctx context.Context) ([]enrollmentCredential, error) {
	var v struct {
		Files *[]enrollmentCredential `json:"files"`
	}
	if a.management.Call(ctx, "GET", "/credentials", nil, &v) != nil || v.Files == nil {
		return nil, errDevice
	}
	for _, c := range *v.Files {
		if (c.Type == "codex" || c.Provider == "codex") && c.account() == "" {
			return nil, errDevice
		}
	}
	return *v.Files, nil
}
func (a *app) state(s *flow, status string) { a.mu.Lock(); s.Status = status; a.mu.Unlock() }
func (a *app) save(s *flow, code, verifier string) {
	// Independent from the HTTP request: shutdown waits for this bounded operation.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	defer a.adopt.Unlock()
	var t nativeToken
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {"https://auth.openai.com/deviceauth/callback"}}
	status, err := a.device.request(ctx, exchangeEndpoint, "application/x-www-form-urlencoded", []byte(form.Encode()), &t)
	if err != nil || status != 200 || t.identity() != nil {
		a.state(s, "error")
		return
	}
	name := "codex-device-" + nonce() + ".json"
	if a.device.persist(name, &t) != nil {
		// The code was consumed and a partial or complete secret file may exist.
		// Preserve it for review rather than suggesting that enrollment is retryable.
		a.state(s, "operator-review")
		return
	}
	// Keep evidence on every uncertain outcome. Pending files are never replayed.
	files, err := a.inventory(ctx)
	if err != nil || a.device.checkPending(name, t.Account) != nil {
		a.state(s, "operator-review")
		return
	}
	for _, c := range files {
		if c.account() == t.Account || c.Name == name || c.ID == name {
			a.state(s, "duplicate")
			return
		}
	}
	_ = a.management.Call(ctx, "POST", "/credentials?name="+url.QueryEscape(name), &t, nil)
	a.state(s, "verifying")
	for ctx.Err() == nil {
		files, err = a.inventory(ctx)
		if err == nil {
			for _, c := range files {
				if c.Name == name && c.account() == t.Account && c.Source == "file" && c.Adopted {
					if os.Remove(filepath.Join(a.device.Dir, name)) != nil {
						a.state(s, "operator-review")
					} else {
						a.state(s, "complete")
					}
					return
				}
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
		}
	}
	a.state(s, "operator-review")
}
