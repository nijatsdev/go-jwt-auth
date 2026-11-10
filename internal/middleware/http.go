package middleware

import (
	"net/http"
	"runtime/debug"
	"strings"

	"github.com/nijatsdev/go-jwt-auth/internal/response"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog/log"
)

type statusCapturingWriter struct {
	http.ResponseWriter
	wroteHeader bool
}

func (w *statusCapturingWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusCapturingWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// Recoverer is a middleware that recovers from panics and writes a 500-error response
func Recoverer(isProduction bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cw := &statusCapturingWriter{ResponseWriter: w}
			defer func() {
				if rvr := recover(); rvr != nil {
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
						log.Ctx(ctx).Error().Msg("panic recovered")
						chimiddleware.PrintPrettyStack(rvr)
					}

					if strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
						return
					}
					if !cw.wroteHeader {
						response.WriteInternalServerError(cw, r, "")
					}
				}
			}()

			next.ServeHTTP(cw, r)
		})
	}
}
