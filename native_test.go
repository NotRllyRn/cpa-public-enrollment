//go:build native

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func testNativeConfig(t *testing.T, listen string) []byte {
	t.Helper()
	root := t.TempDir()
	key := filepath.Join(root, "key")
	if err := os.WriteFile(key, []byte("test-key"), 0600); err != nil {
		t.Fatal(err)
	}
	return []byte(fmt.Sprintf("listen: %q\npublic_origin: https://enroll.example.com\nmanagement_key_file: %q\nstate_dir: %q\n", listen, key, filepath.Join(root, "state")))
}
func TestNativeLifecycle(t *testing.T) {
	defer shutdown()
	if err := configure(nil); err != nil || nativeRuntime.current != nil {
		t.Fatal("discovery bound listener", err)
	}
	raw := testNativeConfig(t, "127.0.0.1:0")
	if err := configure(raw); err != nil {
		t.Fatal(err)
	}
	first := nativeRuntime.current
	if err := configure(raw); err != nil || first != nativeRuntime.current {
		t.Fatal("identical configure restarted", err)
	}
	if err := configure(testNativeConfig(t, "127.0.0.1:0")); err == nil || first != nativeRuntime.current {
		t.Fatal("accepted state replacement")
	}
	shutdown()
	shutdown()
	if !first.app.closing || nativeRuntime.current != nil {
		t.Fatal("shutdown did not close admission")
	}
	if err := configure(raw); err != nil {
		t.Fatal(err)
	}
}
func TestNativeBindFailure(t *testing.T) {
	defer shutdown()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := configure(testNativeConfig(t, l.Addr().String())); err == nil || nativeRuntime.current != nil {
		t.Fatal("bind failure not reported")
	}
}
func TestNativeWireAndConfig(t *testing.T) {
	for _, raw := range []string{"{}", "public_origin: http://example.com", "unknown: value", "---\n{}\n---\n{}"} {
		if _, err := parsePluginConfig([]byte(raw)); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
	for _, request := range []string{`{}`, `{"schema_version":9}`, `invalid`} {
		raw, err := handleMethod("plugin.register", []byte(request))
		if err != nil {
			t.Fatal(err)
		}
		var result struct{ OK bool }
		if json.Unmarshal(raw, &result) != nil || result.OK {
			t.Fatal(string(raw))
		}
	}
	raw, err := handleMethod("plugin.register", []byte(`{"schema_version":10}`))
	if err != nil {
		t.Fatal(err)
	}
	var result struct{ OK bool }
	_ = json.Unmarshal(raw, &result)
	if !result.OK {
		t.Fatal(string(raw))
	}
}
