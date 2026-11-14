package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"sync"
	"time"
)

func nonce() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("random source unavailable")
	}
	return hex.EncodeToString(b[:])
}

const sessionGrace = 5 * time.Minute

// Expires is the authorization deadline; retention never extends authorization.
func (s *flow) retainedUntil() time.Time { return s.Expires.Add(sessionGrace) }

func (a *app) pruneSessions(now time.Time) {
	for id, s := range a.sessions {
		if !now.Before(s.retainedUntil()) {
			delete(a.sessions, id)
		}
	}
}

type flow struct {
	CSRF     string    `json:"csrf"`
	Status   string    `json:"status"`
	ID       string    `json:"device_auth_id,omitempty"`
	Code     string    `json:"user_code,omitempty"`
	Lease    string    `json:"lease,omitempty"`
	Until    time.Time `json:"until"`
	Expires  time.Time `json:"expires"`
	Interval int       `json:"interval"`
}
type app struct {
	closing    bool
	mu         sync.Mutex
	sessions   map[string]*flow
	origin     string
	device     *Device
	management *Management
	adopt      sync.Mutex
	wg         sync.WaitGroup
}

func (a *app) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self' https://auth.openai.com; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	if r.Method == "GET" && (r.URL.Path == "/" || r.URL.Path == "/app.js") {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			io.WriteString(w, page)
		} else {
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			io.WriteString(w, script)
		}
		return
	}
	if r.Method != "POST" || r.Header.Get("Origin") != a.origin {
		http.Error(w, "forbidden", 403)
		return
	}
	media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if media != "application/json" {
		http.Error(w, "JSON required", 415)
		return
	}
	var in struct {
		CSRF, Lease, ID, Code, AuthorizationCode, Verifier string
		Interval                                           int
		Consent                                            bool
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF {
		http.Error(w, "invalid request", 400)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closing {
		http.Error(w, "shutting down", 503)
		return
	}
	now := time.Now()
	a.pruneSessions(now)
	var s *flow
	if c, e := r.Cookie("__Host-enroll"); e == nil {
		s = a.sessions[c.Value]
	}
	if r.URL.Path == "/session" {
		if s == nil {
			if len(a.sessions) >= 2048 {
				http.Error(w, "busy", 503)
				return
			}
			id := nonce()
			s = &flow{CSRF: nonce(), Status: "idle", Expires: now.Add(15 * time.Minute)}
			a.sessions[id] = s
			http.SetCookie(w, &http.Cookie{Name: "__Host-enroll", Value: id, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int((15*time.Minute + sessionGrace) / time.Second)})
		}
	} else {
		if s == nil || in.CSRF != s.CSRF {
			http.Error(w, "forbidden", 403)
			return
		}
		if !now.Before(s.Expires) && (r.URL.Path == "/start" || r.URL.Path == "/created" || r.URL.Path == "/poll" || r.URL.Path == "/approved") {
			http.Error(w, "authorization expired", http.StatusConflict)
			return
		}
		switch r.URL.Path {
		case "/start":
			if !in.Consent {
				http.Error(w, "consent required", 400)
				return
			}
			if s.Status == "idle" || (s.Status == "creating" && now.After(s.Until)) {
				s.Status = "creating"
				s.Lease = nonce()
				s.Until = now.Add(45 * time.Second)
			} else { // Only the reservation holder receives the creation permission.
				respond(w, map[string]any{"status": s.Status})
				return
			}
		case "/created":
			if s.Status == "waiting" && in.ID == s.ID && in.Code == s.Code {
				out := *s
				out.Lease = ""
				respond(w, out)
				return
			}
			if s.Status != "creating" || in.Lease != s.Lease || now.After(s.Until) || in.ID == "" || in.Code == "" || len(in.ID) > 1024 || len(in.Code) > 128 {
				http.Error(w, "stale reservation", 409)
				return
			}
			s.ID = in.ID
			s.Code = in.Code
			s.Status = "waiting"
			s.Lease = ""
			s.Interval = in.Interval
			if s.Interval < 5 {
				s.Interval = 5
			}
			if s.Interval > 900 {
				s.Interval = 86400 // Session expires before another poll; never shorten a long provider interval.
			}
			s.Until = now.Add(time.Duration(s.Interval) * time.Second)
		case "/poll":
			if s.Status != "waiting" || now.Before(s.Until) {
				respond(w, map[string]any{"status": s.Status})
				return
			}
			s.Lease = nonce()
			s.Until = now.Add(time.Duration(s.Interval)*time.Second + 20*time.Second)
		case "/approved":
			if s.Status == "saving" || s.Status == "verifying" || s.Status == "complete" || s.Status == "operator-review" || s.Status == "duplicate" {
				out := *s
				out.Lease = ""
				respond(w, out)
				return
			}
			if s.Status != "waiting" || s.Lease == "" || in.Lease != s.Lease || now.After(s.Until) || in.AuthorizationCode == "" || in.Verifier == "" {
				http.Error(w, "stale approval", 409)
				return
			}
			if !a.adopt.TryLock() {
				http.Error(w, "save busy; retry approval", 503)
				return
			}
			s.Status = "saving"
			s.ID = ""
			s.Code = ""
			s.Lease = ""
			a.wg.Add(1)
			go func() { defer a.wg.Done(); a.save(s, in.AuthorizationCode, in.Verifier) }()
		case "/status":
		default:
			http.NotFound(w, r)
			return
		}
	}
	// Never hand another tab a live lease via status/resume.
	out := *s
	if r.URL.Path != "/start" && r.URL.Path != "/poll" {
		out.Lease = ""
	}
	respond(w, out)
}
func respond(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
