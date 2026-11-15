package main

import (
	"context"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (a *app) inventory(ctx context.Context) ([]enrollmentCredential, error) {
	var v struct {
		Files *[]enrollmentCredential `json:"files"`
	}
	if err := a.management.Call(ctx, "GET", "/credentials", nil, &v); err != nil {
		return nil, err
	}
	if v.Files == nil {
		return nil, diagnostic("inventory response is missing the files list")
	}
	for _, c := range *v.Files {
		if (c.Type == "codex" || c.Provider == "codex") && (c.account() == "" || strings.TrimSpace(c.Email) == "") {
			return nil, diagnostic("inventory contains a Codex credential without a member identity; duplicate checking is unsafe")
		}
	}
	return *v.Files, nil
}
func (a *app) state(s *flow, status string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s.Status = status
	if status != "saving" && status != "verifying" {
		s.Finished = time.Now()
		a.notify(s, "enrollment")
	}
}
func (a *app) fail(s *flow, status, operation string, err error) {
	message := operation + ": " + safeReason(err) + "."
	log.Print(message)
	a.mu.Lock()
	defer a.mu.Unlock()
	s.Message = message
	s.Status = status
	s.Finished = time.Now()
	a.notify(s, "enrollment")
}
func (a *app) save(s *flow, code, verifier string) {
	// Independent from the HTTP request: shutdown waits for this bounded operation.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	defer a.adopt.Unlock()
	var t nativeToken
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {"https://auth.openai.com/deviceauth/callback"}}
	status, err := a.device.request(ctx, exchangeEndpoint, "application/x-www-form-urlencoded", []byte(form.Encode()), &t)
	if err != nil {
		a.fail(s, "error", "Token exchange failed", err)
		return
	}
	if status != 200 {
		a.fail(s, "error", "Token exchange failed", httpFailure(status))
		return
	}
	if t.identity() != nil {
		a.fail(s, "error", "Token exchange failed", diagnostic("response is missing valid token or member identity fields"))
		return
	}
	a.mu.Lock()
	s.Email = t.Email
	a.mu.Unlock()
	if err := a.device.cleanupPending(time.Now(), ""); err != nil {
		a.fail(s, "operator-review", "Cleaning expired pending credentials failed", err)
		return
	}
	// Check before persisting: a blocked retry must not leave another token.
	if err := a.device.checkPending("", t.Account, t.Email); err != nil {
		a.fail(s, "operator-review", "Checking pending enrollments failed", err)
		return
	}
	name := "codex-device-" + nonce() + ".json"
	if s.Owner != "" {
		name = "codex-device-" + s.Owner + "-" + nonce() + ".json"
	}
	if err := a.device.persist(name, &t); err != nil {
		// Preserve evidence: the code was consumed, and a partial secret file may exist.
		a.fail(s, "operator-review", "Saving local recovery credentials failed", err)
		return
	}
	// Pending files are recovery evidence, never a replay queue.
	files, err := a.inventory(ctx)
	if err != nil {
		a.fail(s, "operator-review", "Checking CPA inventory before upload failed", err)
		return
	}
	if err := a.device.checkPending(name, t.Account, t.Email); err != nil {
		a.fail(s, "operator-review", "Checking pending enrollments failed", err)
		return
	}
	for _, c := range files {
		if sameMember(c.account(), c.Email, t.Account, t.Email) || c.Name == name || c.ID == name {
			a.state(s, "duplicate")
			return
		}
	}
	uploadErr := a.management.Call(ctx, "POST", "/credentials?name="+url.QueryEscape(name), &t, nil)
	a.state(s, "verifying")
	var inventoryErr error
	for ctx.Err() == nil {
		files, err = a.inventory(ctx)
		inventoryErr = err
		if err == nil {
			for _, c := range files {
				if c.Name == name && sameMember(c.account(), c.Email, t.Account, t.Email) && c.Source == "file" && c.Adopted {
					if err := os.Remove(filepath.Join(a.device.Dir, name)); err != nil {
						a.fail(s, "operator-review", "CPA adopted the account but removing local recovery credentials failed", err)
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
	if inventoryErr != nil && uploadErr != nil {
		a.fail(s, "operator-review", "Credential upload failed", diagnostic(safeReason(uploadErr)+"; checking CPA inventory after upload also failed: "+safeReason(inventoryErr)))
	} else if inventoryErr != nil {
		a.fail(s, "operator-review", "Checking CPA inventory after upload failed", inventoryErr)
	} else if uploadErr != nil {
		a.fail(s, "operator-review", "Credential upload failed and CPA adoption was not confirmed", uploadErr)
	} else {
		a.fail(s, "operator-review", "Confirming CPA adoption failed", diagnostic("CPA did not report the uploaded credential as adopted before the deadline"))
	}
}
