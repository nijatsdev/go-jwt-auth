package middleware

import (
	"net/http"
	"runtime/debug"
	"strings"

	"github.com/nijatsdev/go-jwt-auth/internal/response"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog/log"
)

// Recoverer is a middleware that recovers from panics and writes a 500-error response
func Recoverer(isProduction bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rvr := recover(); rvr != nil {
					// If the panic is http.ErrAbortHandler, re-panic
					if rvr == http.ErrAbortHandler {
						panic(rvr)
					}

					ctx := r.Context()

					if isProduction {
						log.Ctx(ctx).Error().
							Interface("panic", rvr).
							Bytes("stack", debug.Stack()).
							Msg("panic recovered")
					} else {
						log.Ctx(ctx).Error().
							Msg("panic recovered")
						middleware.PrintPrettyStack(rvr)
					}

					// Write Internal Server Error response if headers not yet sent
					if !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
						response.WriteInternalServerError(w, r, "")
					}
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}
