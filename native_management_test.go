//go:build native

package main

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func nativeResult(t *testing.T, method, request string, result any) []byte {
	t.Helper()
	raw, err := handleMethod(method, []byte(request))
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		OK     bool
		Result json.RawMessage
	}
	if err := json.Unmarshal(raw, &envelope); err != nil || !envelope.OK {
		t.Fatalf("%s: %s (%v)", method, raw, err)
	}
	if err := json.Unmarshal(envelope.Result, result); err != nil {
		t.Fatal(err)
	}
	return envelope.Result
}

func TestNativeManagement(t *testing.T) {
	defer shutdown()
	var registration struct {
		Metadata     map[string]any
		Capabilities map[string]bool
	}
	nativeResult(t, "plugin.register", `{"schema_version":10}`, &registration)
	if len(registration.Capabilities) != 1 || !registration.Capabilities["management_api"] {
		t.Fatal(registration.Capabilities)
	}
	for _, key := range []string{"Name", "Version", "Author", "GitHubRepository"} {
		if registration.Metadata[key] == "" || registration.Metadata[key] == nil {
			t.Fatal(key)
		}
	}
	var resources struct {
		Resources []struct{ Path, Menu string }
		Routes    []any
	}
	nativeResult(t, "management.register", `{}`, &resources)
	if len(resources.Resources) != 0 || len(resources.Routes) != 0 {
		t.Fatalf("%+v", resources)
	}
	var response struct {
		StatusCode int
		Headers    http.Header
		Body       []byte
	}
	nativeResult(t, "management.handle", `{"Method":"GET"}`, &response)
	if response.StatusCode != 200 || !strings.Contains(string(response.Body), "not configured") || nativeRuntime.current != nil {
		t.Fatal("discovery started runtime or incorrect unconfigured page")
	}
	if err := configure(testNativeConfig(t, "127.0.0.1:0")); err != nil {
		t.Fatal(err)
	}
	nativeResult(t, "management.handle", `{"Method":"GET","Path":"/open","Headers":{"Authorization":["secret-input"]},"Query":{"token":["secret-input"]}}`, &response)
	body := string(response.Body)
	if !strings.Contains(body, `href="https://enroll.example.com/"`) {
		t.Fatal(body)
	}
	for _, forbidden := range []string{"test-key", "secret-input", "state_dir", "management_key", "127.0.0.1", "iframe"} {
		if strings.Contains(body, forbidden) {
			t.Fatal("leaked " + forbidden)
		}
	}
	if response.Headers.Get("Cache-Control") != "no-store" || response.Headers.Get("Content-Security-Policy") == "" {
		t.Fatal(response.Headers)
	}
	// Exercise escaping independently of URL validation (defense in depth).
	nativeRuntime.Lock()
	nativeRuntime.current.config.PublicOrigin = `https://example.com/"<>&`
	nativeRuntime.Unlock()
	nativeResult(t, "management.handle", `{"Method":"GET"}`, &response)
	if !strings.Contains(string(response.Body), "&#34;&lt;&gt;&amp;") {
		t.Fatal(string(response.Body))
	}
	nativeResult(t, "management.handle", `{"Method":"POST"}`, &response)
	if response.StatusCode != 405 {
		t.Fatal(response.StatusCode)
	}
}

// Runs assertions inside the actual CPA host package, not a local copy of its
// validator. An overlay adds only this temporary test; host source is untouched.
func TestActualCPAHostContract(t *testing.T) {
	host := os.Getenv("CPA_HOST_SOURCE")
	if host == "" {
		t.Skip("set CPA_HOST_SOURCE to the CPA v8.0.63 source checkout")
	}
	var registration, resources json.RawMessage
	nativeResult(t, "plugin.register", `{"schema_version":10}`, &registration)
	nativeResult(t, "management.register", `{}`, &resources)
	dir := t.TempDir()
	source := `package pluginhost
import (
 "encoding/json"
 "testing"
 "github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)
func TestPublicEnrollmentActualContract(t *testing.T) {
 var reg rpcRegistration
 if err := json.Unmarshal([]byte(REGISTRATION), &reg); err != nil { t.Fatal(err) }
 p := pluginapi.Plugin{Metadata: reg.Metadata, SchemaVersion: reg.SchemaVersion}
 if reg.Capabilities.ManagementAPI { p.Capabilities.ManagementAPI = &rpcPluginAdapter{} }
 if !validPlugin(p) { t.Fatal("actual host rejected metadata/capabilities") }
 if reg.SchemaVersion != 10 { t.Fatal(reg.SchemaVersion) }
 var resources rpcManagementRegistrationResponse
 if err := json.Unmarshal([]byte(RESOURCES), &resources); err != nil { t.Fatal(err) }
 if len(resources.Resources) != 0 || len(resources.Routes) != 0 { t.Fatal(resources) }
 // Management capability remains valid without public resources or menus.
}
`
	quote := func(raw []byte) string { b, _ := json.Marshal(string(raw)); return string(b) }
	source = strings.ReplaceAll(source, "REGISTRATION", quote(registration))
	source = strings.ReplaceAll(source, "RESOURCES", quote(resources))
	testFile := filepath.Join(dir, "contract_test.go")
	if err := os.WriteFile(testFile, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	overlay, _ := json.Marshal(map[string]any{"Replace": map[string]string{filepath.Join(host, "internal/pluginhost/public_enrollment_contract_test.go"): testFile}})
	overlayFile := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(overlayFile, overlay, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "test", "-overlay", overlayFile, "./internal/pluginhost", "-run", "^TestPublicEnrollmentActualContract$", "-count=1")
	cmd.Dir = host
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("actual host contract: %v\n%s", err, output)
	}
}
