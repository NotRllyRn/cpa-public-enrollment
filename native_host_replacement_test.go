//go:build native

package main

import (
	_ "embed"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

//go:embed testdata/native_host_replacement.go.txt
var hostReplacementTest string

// Build two distinct Go c-shared images, then exercise the real host loader and
// ApplyConfig lifecycle. An overlay adds a test only; host source stays untouched.
func TestActualCPAHostReplacement(t *testing.T) {
	host := os.Getenv("CPA_HOST_SOURCE")
	if host == "" {
		t.Skip("set CPA_HOST_SOURCE to the CPA source checkout")
	}
	dir := t.TempDir()
	source := hostReplacementTest
	for _, version := range []string{"ONE", "TWO"} {
		out := filepath.Join(dir, version+".so")
		cmd := exec.Command("go", "build", "-tags", "native", "-buildmode=c-shared", "-ldflags=-buildid=public-enrollment-test-"+version, "-o", out, ".")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build native image %s: %v\n%s", version, err, output)
		}
		source = strings.ReplaceAll(source, "PLUGIN_"+version, strconv.Quote(out))
	}
	testFile := filepath.Join(dir, "replacement_test.go")
	if err := os.WriteFile(testFile, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	overlay, _ := json.Marshal(map[string]any{"Replace": map[string]string{filepath.Join(host, "internal/pluginhost/public_enrollment_replacement_test.go"): testFile}})
	overlayFile := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(overlayFile, overlay, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "test", "-overlay", overlayFile, "./internal/pluginhost", "-run", "^TestPublicEnrollmentActualReplacement$", "-count=1", "-v")
	cmd.Dir = host
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("actual host replacement: %v\n%s", err, output)
	} else {
		t.Log(string(output))
	}
}
