package middleware

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTrustedRealIPIgnoresXFFFromUntrustedPeer(t *testing.T) {
	trusted, err := ParseTrustedProxyCIDRs("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}

	var seen string
	h := TrustedRealIP(trusted)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.RemoteAddr
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:1234"
	req.Header.Set("X-Forwarded-For", "198.51.100.5")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if seen != "203.0.113.9:1234" {
		t.Fatalf("RemoteAddr = %q, want direct peer unchanged", seen)
	}
}

func TestTrustedRealIPUsesXFFFromTrustedPeer(t *testing.T) {
	trusted, err := ParseTrustedProxyCIDRs("127.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}

	var seen string
	h := TrustedRealIP(trusted)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.RemoteAddr
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = net.JoinHostPort("127.0.0.1", "9999")
	req.Header.Set("X-Forwarded-For", "198.51.100.5")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	want := net.JoinHostPort("198.51.100.5", "0")
	if seen != want {
		t.Fatalf("RemoteAddr = %q, want %q", seen, want)
	}
}
