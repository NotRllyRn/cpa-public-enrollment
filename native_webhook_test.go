//go:build native

package main

import (
	"testing"
	"time"
)

func TestNativeWebhookReplacementLifecycle(t *testing.T) {
	defer shutdown()
	raw := append(testNativeConfig(t, "127.0.0.1:0"), []byte("\nwebhook_url: https://hooks.example.test/enrollment\n")...)
	if err := configure(raw); err != nil {
		t.Fatal(err)
	}
	first := nativeRuntime.current.app.webhook
	if first == nil {
		t.Fatal("disabled")
	}
	if err := quiesce(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-first.done:
	case <-time.After(time.Second):
		t.Fatal("worker survived quiesce")
	}
	if err := configure(raw); err != nil {
		t.Fatal(err)
	}
	second := nativeRuntime.current.app.webhook
	if first == second {
		t.Fatal("rollback reused stopped worker")
	}
	shutdown()
	select {
	case <-second.done:
	case <-time.After(time.Second):
		t.Fatal("worker survived shutdown")
	}
}
