package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const clientID = "app_EMoamEEZ73f0CkXaXp7hrann"
const exchangeEndpoint = "https://auth.openai.com/oauth/token"

var errDevice = errors.New("device enrollment unavailable")

type Device struct {
	HTTP *http.Client
	Dir  string
}

func newDevice(dir string) *Device {
	return &Device{Dir: dir, HTTP: &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}
func (d *Device) request(ctx context.Context, endpoint, content string, body []byte, out any) (int, error) {
	if endpoint != exchangeEndpoint {
		return 0, errDevice
	}
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, errDevice
	}
	req.Header.Set("Content-Type", content)
	req.Header.Set("Accept", "application/json")
	// Enforce redirect refusal even if a caller supplies a custom transport.
	client := *d.HTTP
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client.Timeout = 20 * time.Second
	res, err := client.Do(req)
	if err != nil {
		return 0, errDevice
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return 0, errDevice
	}
	if res.StatusCode == 200 && out != nil {
		if json.Unmarshal(raw, out) != nil {
			return 0, errDevice
		}
	}
	return res.StatusCode, nil
}

type nativeToken struct {
	Access      string `json:"access_token"`
	Refresh     string `json:"refresh_token"`
	ID          string `json:"id_token"`
	Account     string `json:"account_id"`
	Email       string `json:"email"`
	Plan        string `json:"plan_type"`
	Type        string `json:"type"`
	Expired     string `json:"expired"`
	LastRefresh string `json:"last_refresh"`
	Expires     int64  `json:"expires_in,omitempty"`
}

func (t *nativeToken) identity() error {
	parts := strings.Split(t.ID, ".")
	if len(parts) != 3 {
		return errDevice
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return errDevice
	}
	var c struct {
		Email string `json:"email"`
		Auth  struct {
			Account string `json:"chatgpt_account_id"`
			Plan    string `json:"chatgpt_plan_type"`
		} `json:"https://api.openai.com/auth"`
	}
	if json.Unmarshal(raw, &c) != nil || c.Email == "" || c.Auth.Account == "" || t.Access == "" || t.Refresh == "" || t.Expires <= 0 || t.Expires > 31536000 {
		return errDevice
	}
	t.Account = c.Auth.Account
	t.Email = c.Email
	t.Plan = c.Auth.Plan
	if t.Plan == "" {
		t.Plan = "free"
	}
	t.Type = "codex"
	t.LastRefresh = time.Now().UTC().Format(time.RFC3339)
	t.Expired = time.Now().Add(time.Duration(t.Expires) * time.Second).UTC().Format(time.RFC3339)
	t.Expires = 0
	return nil
}

// CPA v8 runtime inventory, not a token verification result.
type enrollmentCredential struct {
	Name     string `json:"name"`
	ID       string `json:"id"`
	Provider string `json:"provider"`
	Type     string `json:"type"`
	Account  string `json:"account_id"`
	Email    string `json:"email"`
	Source   string `json:"source"`
	Adopted  bool   `json:"adopted"`
	Claims   struct {
		Account string `json:"chatgpt_account_id"`
		Auth    struct {
			Account string `json:"chatgpt_account_id"`
		} `json:"https://api.openai.com/auth"`
	} `json:"id_token"`
}

// Account IDs can identify a shared workspace, not an individual member.
func sameMember(account, email, otherAccount, otherEmail string) bool {
	return account != "" && account == otherAccount && strings.TrimSpace(email) != "" && strings.EqualFold(strings.TrimSpace(email), strings.TrimSpace(otherEmail))
}

func (c enrollmentCredential) account() string {
	if c.Account != "" {
		return c.Account
	}
	if c.Claims.Account != "" {
		return c.Claims.Account
	}
	return c.Claims.Auth.Account
}
func (d *Device) prepare() error {
	if d.Dir == "" {
		return errDevice
	}
	if err := os.MkdirAll(d.Dir, 0700); err != nil {
		return errDevice
	}
	info, err := os.Lstat(d.Dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errDevice
	}
	f, err := os.CreateTemp(d.Dir, ".probe-")
	if err != nil {
		return errDevice
	}
	name := f.Name()
	err = f.Sync()
	closeErr := f.Close()
	removeErr := os.Remove(name)
	if err != nil || closeErr != nil || removeErr != nil {
		return errDevice
	}
	return nil
}

// Never retry a write, even after restart. Pending files are recovery evidence, not a replay queue.
func (d *Device) persist(name string, t *nativeToken) error {
	if d.Dir == "" {
		return errDevice
	}
	if err := os.MkdirAll(d.Dir, 0700); err != nil {
		return errDevice
	}
	info, err := os.Lstat(d.Dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errDevice
	}
	f, err := os.OpenFile(filepath.Join(d.Dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errDevice
	}
	err = json.NewEncoder(f).Encode(t)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return errDevice
	}
	dir, err := os.Open(d.Dir)
	if err != nil {
		return errDevice
	}
	defer dir.Close()
	return dir.Sync()
}
func (d *Device) checkPending(name, account, email string) error {
	entries, err := os.ReadDir(d.Dir)
	if err != nil {
		return errDevice
	}
	for _, entry := range entries {
		if entry.Name() == name || strings.HasPrefix(entry.Name(), ".probe-") {
			continue
		}
		if entry.IsDir() {
			return errDevice
		}
		f, err := os.Open(filepath.Join(d.Dir, entry.Name()))
		if os.IsNotExist(err) {
			continue // A successful reconciliation may remove a pending file.
		}
		if err != nil {
			return errDevice
		}
		var t nativeToken
		err = json.NewDecoder(io.LimitReader(f, 1<<20)).Decode(&t)
		_ = f.Close()
		if err != nil || t.Account == "" || strings.TrimSpace(t.Email) == "" || sameMember(t.Account, t.Email, account, email) {
			return errDevice
		}
	}
	return nil
}
