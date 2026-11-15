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

// Retention never extends authorization. In-flight saves keep their identity
// until they publish a result; terminal results then remain visible for 5 minutes.
func (s *flow) retainedUntil() time.Time {
	if !s.Finished.IsZero() {
		return s.Finished.Add(sessionGrace)
	}
	return s.Expires.Add(sessionGrace)
}
func (s *flow) expire(now time.Time) {
	if !now.Before(s.Expires) && (s.Status == "idle" || s.Status == "creating" || s.Status == "waiting") {
		s.Status = "expired"
		s.ID, s.Code, s.Lease = "", "", ""
	}
}
func (a *app) pruneSessions(now time.Time) {
	for id, s := range a.sessions {
		s.expire(now)
		if s.Status != "saving" && s.Status != "verifying" && !now.Before(s.retainedUntil()) {
			delete(a.sessions, id)
		}
	}
}
func (a *app) newSession(w http.ResponseWriter, now time.Time) *flow {
	id := nonce()
	s := &flow{Owner: pendingOwner(id), CSRF: nonce(), Status: "idle", Expires: now.Add(15 * time.Minute)}
	a.sessions[id] = s
	// Server-owned retention lets a surviving cookie explain lost state after
	// expiry or replacement instead of silently starting another enrollment.
	http.SetCookie(w, &http.Cookie{Name: "__Host-enroll", Value: id, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	return s
}
func sessionError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": message}})
}

const lostSessionMessage = "Your sign-in session is unavailable. Reset to clear its local pending credentials and review access. This does not revoke access or undo a CPA import."

type flow struct {
	Owner    string    `json:"-"`
	CSRF     string    `json:"csrf"`
	Status   string    `json:"status"`
	Message  string    `json:"message,omitempty"`
	ID       string    `json:"device_auth_id,omitempty"`
	Code     string    `json:"user_code,omitempty"`
	Lease    string    `json:"lease,omitempty"`
	Until    time.Time `json:"until"`
	Expires  time.Time `json:"expires"`
	Interval int       `json:"interval"`
	Finished time.Time `json:"-"`
}
type app struct {
	closing      bool
	mu           sync.Mutex
	sessions     map[string]*flow
	origin       string
	operatorName string
	device       *Device
	management   *Management
	adopt        sync.Mutex
	wg           sync.WaitGroup
	saveDone     <-chan struct{}
}

func (a *app) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self' https://auth.openai.com; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	a.mu.Lock()
	closing := a.closing
	a.mu.Unlock()
	if closing {
		sessionError(w, 503, "service_updating", "Service is updating. Check sign-in status shortly; do not start another sign-in while saving.")
		return
	}
	if r.Method == "GET" && (r.URL.Path == "/" || r.URL.Path == "/app.js" || r.URL.Path == "/enroll.css") {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			io.WriteString(w, enrollmentPage(a.operatorName))
		} else if r.URL.Path == "/enroll.css" {
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
			io.WriteString(w, stylesheet)
		} else {
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			io.WriteString(w, script)
		}
		return
	}
	if r.Method != "POST" || r.Header.Get("Origin") != a.origin {
		sessionError(w, 403, "forbidden", "Request origin is not allowed.")
		return
	}
	media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if media != "application/json" {
		sessionError(w, 415, "invalid_request", "JSON required.")
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
		sessionError(w, 400, "invalid_request", "Invalid request.")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closing {
		sessionError(w, 503, "service_updating", "Service is updating. Check sign-in status shortly; do not start another sign-in while saving.")
		return
	}
	now := time.Now()
	a.pruneSessions(now)
	cookie, _ := r.Cookie("__Host-enroll")
	var s *flow
	if cookie != nil {
		s = a.sessions[cookie.Value]
	}
	if r.URL.Path == "/restart" {
		// Missing state cannot validate the old CSRF. Exact Origin + JSON still
		// protect this explicit recovery action; it never imports credentials.
		if s != nil {
			if in.CSRF != s.CSRF {
				sessionError(w, 409, "session_changed", "Another tab changed the sign-in session. Checking its current status.")
				return
			}
			if s.Status != "expired" && s.Status != "error" && s.Status != "operator-review" && s.Status != "duplicate" {
				sessionError(w, 409, "session_active", "This sign-in cannot be reset. Check its status; contact the operator if review is needed.")
				return
			}
		}
		if s == nil && len(a.sessions) >= 2048 {
			sessionError(w, 503, "busy", "Service is busy. Try again shortly.")
			return
		}
		// Never wait for adoption while holding mu: save publishes under mu.
		if !a.adopt.TryLock() {
			sessionError(w, 409, "save_busy", "A save is still running. Check status before resetting.")
			return
		}
		owner := ""
		if cookie != nil {
			owner = pendingOwner(cookie.Value)
		}
		var err error
		if owner != "" {
			err = a.device.cleanupPending(now, owner)
		}
		a.adopt.Unlock()
		if err != nil {
			sessionError(w, 500, "cleanup_failed", "Could not clear local pending credentials. Ask the operator to check storage before retrying.")
			return
		}
		if cookie != nil {
			delete(a.sessions, cookie.Value)
		}
		s = a.newSession(w, now)
	} else if r.URL.Path == "/session" {
		if s == nil {
			if cookie != nil {
				sessionError(w, 409, "session_lost", lostSessionMessage)
				return
			}
			if len(a.sessions) >= 2048 {
				sessionError(w, 503, "busy", "Service is busy. Try again shortly.")
				return
			}
			s = a.newSession(w, now)
		}
	} else {
		if s == nil {
			sessionError(w, 409, "session_lost", lostSessionMessage)
			return
		}
		if in.CSRF != s.CSRF {
			sessionError(w, 409, "session_changed", "Another tab changed the sign-in session. Checking its current status.")
			return
		}
		if !now.Before(s.Expires) && (r.URL.Path == "/start" || r.URL.Path == "/created" || r.URL.Path == "/poll" || r.URL.Path == "/approved") {
			sessionError(w, 409, "session_expired", "The sign-in authorization window has ended. Check its status before starting again.")
			return
		}
		switch r.URL.Path {
		case "/start":
			if !in.Consent {
				sessionError(w, 400, "consent_required", "Consent required.")
				return
			}
			if s.Status == "idle" || (s.Status == "creating" && now.After(s.Until)) {
				s.Status = "creating"
				s.Lease = nonce()
				s.Until = now.Add(45 * time.Second)
			} else {
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
				sessionError(w, 409, "stale_reservation", "Another tab or an expired reservation changed this sign-in. Check its status.")
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
				s.Interval = 86400
			} // Never shorten a long provider interval.
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
				sessionError(w, 409, "stale_approval", "This approval is no longer current. Check sign-in status before taking further action.")
				return
			}
			if !a.adopt.TryLock() {
				sessionError(w, 503, "save_busy", "Another save is in progress. Retrying approval delivery shortly.")
				return
			}
			s.Status = "saving"
			s.ID = ""
			s.Code = ""
			s.Lease = ""
			a.wg.Add(1)
			done := make(chan struct{})
			a.saveDone = done
			go func() { defer a.wg.Done(); defer close(done); a.save(s, in.AuthorizationCode, in.Verifier) }()
		case "/status":
		default:
			sessionError(w, 404, "not_found", "Unknown sign-in endpoint.")
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
