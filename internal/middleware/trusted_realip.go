package middleware

import (
	"net"
	"net/http"
	"strings"

	"github.com/nijatsdev/go-jwt-auth/internal/utils"
)

// TrustedRealIP rewrites RemoteAddr from forwarding headers only when the direct peer is trusted.
// When no trusted CIDRs are configured, forwarding headers are ignored (same as a direct client connection).
func TrustedRealIP(trusted []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(trusted) > 0 && trustedPeer(r.RemoteAddr, trusted) {
				if client := forwardedClientIP(r); client != "" {
					r.RemoteAddr = net.JoinHostPort(client, "0")
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func trustedPeer(remoteAddr string, trusted []*net.IPNet) bool {
	ip := net.ParseIP(utils.HostFromAddr(remoteAddr))
	if ip == nil {
		return false
	}
	for _, n := range trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func forwardedClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			candidate := strings.TrimSpace(parts[0])
			if ip := net.ParseIP(candidate); ip != nil {
				return ip.String()
			}
		}
	}
	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		if ip := net.ParseIP(xri); ip != nil {
			return ip.String()
		}
	}
	if tci := strings.TrimSpace(r.Header.Get("True-Client-IP")); tci != "" {
		if ip := net.ParseIP(tci); ip != nil {
			return ip.String()
		}
	}
	return ""
}

// ParseTrustedProxyCIDRs parses comma-separated CIDRs (e.g. 10.0.0.0/8,127.0.0.1/32).
func ParseTrustedProxyCIDRs(raw string) ([]*net.IPNet, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var out []*net.IPNet
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			ip := net.ParseIP(part)
			if ip == nil {
				return nil, err
			}
			if ip.To4() != nil {
				n = &net.IPNet{IP: ip.To4(), Mask: net.CIDRMask(32, 32)}
			} else {
				n = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
			}
		}
		out = append(out, n)
	}
	return out, nil
}
