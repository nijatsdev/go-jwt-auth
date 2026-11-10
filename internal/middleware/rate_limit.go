package middleware

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/nijatsdev/go-jwt-auth/internal/response"
	"github.com/nijatsdev/go-jwt-auth/internal/utils"
)

const (
	defaultMaxClientEntries = 10_000
)

// RateLimiter holds per-endpoint rate limiting state.
type RateLimiter struct {
	mu      sync.Mutex
	clients map[string]*clientInfo
	stopCh  chan struct{}
	maxKeys int
}

type clientInfo struct {
	count     int
	resetTime time.Time
}

// NewRateLimiter creates new RateLimiter middleware.
func NewRateLimiter() *RateLimiter {
	rl := &RateLimiter{
		clients: make(map[string]*clientInfo),
		stopCh:  make(chan struct{}),
		maxKeys: defaultMaxClientEntries,
	}

	go rl.cleanup()
	return rl
}

// Stop ends the background cleanup goroutine.
func (rl *RateLimiter) Stop() {
	select {
	case <-rl.stopCh:
	default:
		close(rl.stopCh)
	}
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-rl.stopCh:
			return
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for key, info := range rl.clients {
				if now.After(info.resetTime) {
					delete(rl.clients, key)
				}
			}
			rl.mu.Unlock()
		}
	}
}

func clientIPKey(remoteAddr string) string {
	host, port, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return utils.HostFromAddr(remoteAddr)
	}
	if port != "" {
		// Direct connection: key on IP only (ephemeral port must not create new buckets).
		return host
	}
	return remoteAddr
}

// Limit creates middleware that limits requests per client IP for a named endpoint bucket.
func (rl *RateLimiter) Limit(endpoint string, limit int, window time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := endpoint + "|" + clientIPKey(r.RemoteAddr)

			rl.mu.Lock()
			allowed := rl.recordAndAllow(key, limit, window)
			rl.mu.Unlock()

			if !allowed {
				response.WriteTooManyRequestsError(w, r, "Rate limit exceeded. Please try again later.")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func (rl *RateLimiter) recordAndAllow(key string, limit int, window time.Duration) bool {
	now := time.Now()
	client, exists := rl.clients[key]

	if !exists || now.After(client.resetTime) {
		if len(rl.clients) >= rl.maxKeys && !exists {
			// Evict one expired entry or reject (fail closed under memory pressure).
			evicted := false
			for k, info := range rl.clients {
				if now.After(info.resetTime) {
					delete(rl.clients, k)
					evicted = true
					break
				}
			}
			if !evicted && len(rl.clients) >= rl.maxKeys {
				return false
			}
		}
		rl.clients[key] = &clientInfo{
			count:     1,
			resetTime: now.Add(window),
		}
		return true
	}

	if client.count >= limit {
		return false
	}

	client.count++
	return true
}
