//go:build native

package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNativeOperatorSetting(t *testing.T) {
	defer shutdown()
	raw := append(testNativeConfig(t, "127.0.0.1:0"), []byte("operator_name: '<script>alert(1)</script> & Example'\n")...)
	if err := configure(raw); err != nil {
		t.Fatal(err)
	}
	first := nativeRuntime.current
	if first.config.OperatorName != "<script>alert(1)</script> & Example" {
		t.Fatal("operator setting not parsed")
	}
	w := httptest.NewRecorder()
	first.app.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(w.Body.String(), `<span id="operator-name">&lt;script&gt;alert(1)&lt;/script&gt; &amp; Example</span>`) {
		t.Fatal("configured display name was not safely rendered")
	}
	if err := configure(raw); err != nil || nativeRuntime.current != first {
		t.Fatal("identical UI setting restarted runtime", err)
	}
	changed := []byte(strings.Replace(string(raw), "<script>alert(1)</script> & Example", "Different operator", 1))
	if err := configure(changed); err == nil || !strings.Contains(err.Error(), "restart") {
		t.Fatal("UI change must follow restart contract", err)
	}
	if first.app.operatorName != "<script>alert(1)</script> & Example" {
		t.Fatal("rejected reconfigure changed public name")
	}
	// Quiesce/rollback must preserve both public settings and session state.
	if err := quiesce(); err != nil {
		t.Fatal(err)
	}
	if err := configure(raw); err != nil || nativeRuntime.current != first {
		t.Fatal("UI setting broke rollback", err)
	}
}

func TestNativeOperatorMetadataAndFallback(t *testing.T) {
	defer shutdown()
	raw, err := handleMethod("plugin.register", []byte(`{"schema_version":10}`))
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Result struct {
			Metadata struct {
				ConfigFields []struct{ Name, Type, Description string }
			}
		}
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, field := range envelope.Result.Metadata.ConfigFields {
		if field.Name == "operator_name" {
			found = field.Type == "string" && strings.Contains(field.Description, "restart")
		}
	}
	if !found {
		t.Fatal("native settings do not advertise operator_name")
	}
	if err := configure(testNativeConfig(t, "127.0.0.1:0")); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	nativeRuntime.current.app.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(w.Body.String(), `<span id="operator-name">Not specified</span>`) {
		t.Fatal("missing neutral operator fallback")
	}
}
