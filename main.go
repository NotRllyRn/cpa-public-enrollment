//go:build !native

package main

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func env(key, fallback string) string {
	if s := os.Getenv(key); s != "" {
		return s
	}
	return fallback
}
func main() {
	origin := os.Getenv("ENROLL_PUBLIC_ORIGIN")
	u, e := url.Parse(origin)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		log.Fatal("ENROLL_PUBLIC_ORIGIN must be an exact HTTPS origin without trailing slash")
	}
	base := os.Getenv("ENROLL_CPA_URL")
	b, e := url.Parse(base)
	if e != nil || (b.Scheme != "http" && b.Scheme != "https") || b.Host == "" || b.User != nil || b.RawQuery != "" || b.Fragment != "" || (b.Path != "" && b.Path != "/") {
		log.Fatal("ENROLL_CPA_URL must be a private management origin")
	}
	key, e := os.ReadFile(os.Getenv("ENROLL_CPA_KEY_FILE"))
	if e != nil || strings.TrimSpace(string(key)) == "" {
		log.Fatal("management key file required")
	}
	d := newDevice(env("ENROLL_STATE_DIR", "./state"))
	if d.prepare() != nil {
		log.Fatal("private writable state directory required (0700)")
	}
	a := &app{sessions: make(map[string]*flow), origin: origin, device: d, management: NewManagement(base, string(key))}
	srv := &http.Server{Addr: env("ENROLL_LISTEN", "0.0.0.0:8318"), Handler: a, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				a.mu.Lock()
				a.pruneSessions(now)
				a.mu.Unlock()
			}
		}
	}()
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe() }()
	select {
	case <-ctx.Done():
	case err := <-done:
		if err != http.ErrServerClosed {
			log.Print("listener stopped")
		}
	}
	a.mu.Lock()
	a.closing = true
	a.mu.Unlock()
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
	// Shutdown closes public admission before waiting for the sole bounded save.
	a.wg.Wait()
}
