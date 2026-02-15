package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/nijatsdev/go-jwt-auth/internal/response"
)

// RateLimiter holds dependencies for rate limiting logic
type RateLimiter struct {
	mu      sync.Mutex
	clients map[string]*clientInfo
}

type clientInfo struct {
	count     int
	resetTime time.Time
}

// NewRateLimiter creates new RateLimiter middleware
func NewRateLimiter() *RateLimiter {
	rl := &RateLimiter{
		clients: make(map[string]*clientInfo),
	}

	// Cleanup expired entries every minute
	go rl.cleanup()

	return rl
}

// cleanup periodically removes expired client entries
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, info := range rl.clients {
			if now.After(info.resetTime) {
				delete(rl.clients, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// Limit creates a middleware that limits requests by IP address
// blocks requests if they exceed 'limit' within 'window' duration
func (rl *RateLimiter) Limit(limit int, window time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr // Note: specific implementation depends on proxy setup (X-Forwarded-For etc.)

			rl.mu.Lock()
			defer rl.mu.Unlock()

			now := time.Now()
			client, exists := rl.clients[ip]

			if !exists || now.After(client.resetTime) {
				// New client or window expired
				rl.clients[ip] = &clientInfo{
					count:     1,
					resetTime: now.Add(window),
				}
				next.ServeHTTP(w, r)
				return
			}

			if client.count >= limit {
				// Rate limit exceeded
				response.WriteTooManyRequestsError(w, r, "Rate limit exceeded. Please try again later.")
				return
			}

			// Increment count
			client.count++
			next.ServeHTTP(w, r)
		})
	}
}
