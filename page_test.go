package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEmbeddedEnrollmentAssets(t *testing.T) {
	a := testApp(t)
	for _, asset := range []struct{ path, contentType, body string }{
		{"/", "text/html; charset=utf-8", page},
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
