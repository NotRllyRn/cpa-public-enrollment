package main

import (
	"html"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOperatorNameIsPlainText(t *testing.T) {
	for _, name := range []string{"", "  ", "Example Operator", `<img src=x onerror=alert(1)> & \"quoted\" 'name'`, "{{OPERATOR_NAME}}"} {
		a := testApp(t)
		a.operatorName = name
		w := httptest.NewRecorder()
		a.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
		want := strings.TrimSpace(name)
		if want == "" {
			want = "Not specified"
		}
		if !strings.Contains(w.Body.String(), `<span id="operator-name">`+html.EscapeString(want)+`</span>`) {
			t.Fatalf("operator name not escaped: %q", name)
		}
		if strings.Contains(w.Body.String(), "<img") {
			t.Fatal("operator name became markup")
		}
	}
}

func TestEmbeddedEnrollmentAssets(t *testing.T) {
	a := testApp(t)
	for _, asset := range []struct{ path, contentType, body string }{
		{"/", "text/html; charset=utf-8", enrollmentPage("")},
		{"/app.js", "text/javascript; charset=utf-8", script},
		{"/enroll.css", "text/css; charset=utf-8", stylesheet},
	} {
		t.Run(asset.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			a.ServeHTTP(w, httptest.NewRequest("GET", asset.path, nil))
			if w.Code != 200 || w.Header().Get("Content-Type") != asset.contentType || w.Body.String() != asset.body {
				t.Fatal("embedded asset not served correctly")
			}
			if !strings.Contains(w.Header().Get("Content-Security-Policy"), "style-src 'self'") {
				t.Fatal("same-origin styles blocked")
			}
			if len(w.Result().Cookies()) != 0 || len(a.sessions) != 0 {
				t.Fatal("static page initialized a session")
			}
		})
	}
}
