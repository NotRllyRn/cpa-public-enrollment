package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Notifications are deliberately lossy and never participate in saving credentials.
type notification struct {
	Event     string    `json:"event"`
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
	Email     string    `json:"email,omitempty"`
	Error     string    `json:"error,omitempty"`
}
type webhook struct {
	queue  chan notification
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
}

func validateWebhook(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return errors.New("webhook_url must be HTTPS without credentials or fragments")
	}
	return nil
}
func newWebhook(raw string, transport http.RoundTripper) *webhook {
	if raw == "" {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &webhook{queue: make(chan notification, 32), cancel: cancel, done: make(chan struct{})}
	client := &http.Client{Timeout: 3 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	go func() {
		defer close(h.done)
		defer client.CloseIdleConnections()
		for {
			select {
			case <-ctx.Done():
				return
			case n := <-h.queue:
				body, _ := json.Marshal(n)
				req, err := http.NewRequestWithContext(ctx, "POST", raw, bytes.NewReader(body))
				if err != nil {
					continue
				}
				req.Header.Set("Content-Type", "application/json")
				resp, err := client.Do(req)
				if err == nil {
					resp.Body.Close()
				}
			}
		}
	}()
	return h
}
func (h *webhook) stop() {
	if h != nil {
		h.once.Do(h.cancel)
		<-h.done
	}
}

// Caller holds app.mu. Only fixed messages and server-verified email enter here.
func (a *app) notify(s *flow, event string) {
	if s.Reported {
		return
	}
	s.Reported = true
	if a.webhook == nil {
		return
	}
	// Client-controlled resets cannot flood the destination across attempts.
	if event == "client_failure" {
		now := time.Now()
		if now.Sub(a.lastClientReport) < time.Second {
			return
		}
		a.lastClientReport = now
	}
	n := notification{Event: event, Status: s.Status, Timestamp: time.Now().UTC(), Email: s.Email}
	switch s.Status {
	case "error":
		n.Error = "Enrollment failed."
	case "operator-review":
		n.Error = "Enrollment requires operator review."
	case "expired":
		n.Error = "Enrollment authorization expired."
	}
	// Message is constructed by fail using safeReason, or from fixed client stages.
	if s.Message != "" && (s.Status == "error" || s.Status == "operator-review") {
		n.Error = s.Message
	}
	select {
	case a.webhook.queue <- n:
	default:
	}
}
