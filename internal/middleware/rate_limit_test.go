package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimitPerEndpointIsolation(t *testing.T) {
	rl := NewRateLimiter()
	defer rl.Stop()

	loginHits := 0
	profileHits := 0

	login := rl.Limit("auth:login", 2, time.Minute)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loginHits++
		w.WriteHeader(http.StatusOK)
	}))
	profile := rl.Limit("profile", 2, time.Minute)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		profileHits++
		w.WriteHeader(http.StatusOK)
	}))

	addr := "203.0.113.10:54321"
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = addr
		w := httptest.NewRecorder()
		login.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("login request %d: status %d", i, w.Code)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = addr
	w := httptest.NewRecorder()
	login.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("login third request: status %d, want 429", w.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = addr
	w2 := httptest.NewRecorder()
	profile.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("profile should not be limited by login bucket: status %d", w2.Code)
	}

	if loginHits != 2 || profileHits != 1 {
		t.Fatalf("hits login=%d profile=%d", loginHits, profileHits)
	}
}
