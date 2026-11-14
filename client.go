package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// Only this private client knows the management key. Public routes never proxy input paths.
type Management struct {
	Base, Key string
	HTTP      *http.Client
}

func NewManagement(base, key string) *Management {
	return &Management{strings.TrimRight(base, "/"), strings.TrimSpace(key), &http.Client{Timeout: 70 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}
func (m *Management) Call(ctx context.Context, method, path string, body, result any) error {
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return diagnostic("could not encode management request")
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, m.Base+"/v8/management"+path, bytes.NewReader(data))
	if err != nil {
		return diagnostic("could not construct management request")
	}
	req.Header.Set("Authorization", "Bearer "+m.Key)
	req.Header.Set("Content-Type", "application/json")
	res, err := m.HTTP.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return diagnostic(safeReason(ctx.Err()))
		}
		return diagnostic("management service could not be reached")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return httpFailure(res.StatusCode)
	}
	if result == nil {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 4<<20)).Decode(result); err != nil {
		return diagnostic("management service returned invalid inventory JSON")
	}
	return nil
}
