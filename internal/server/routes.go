package server

import (
	"net/http"
	"time"

	"github.com/nijatsdev/go-jwt-auth/internal/middleware"
	"github.com/nijatsdev/go-jwt-auth/internal/response"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"


)

func (s *Server) registerRoutes() http.Handler {
	r := chi.NewRouter()

	origins := s.config.CORSOrigins()
	if len(origins) > 0 {
		r.Use(cors.Handler(cors.Options{
			AllowedOrigins:   origins,
			AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
			AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
			AllowCredentials: true,
			MaxAge:           300,
		}))
	}

	r.Use(middleware.TrustedRealIP(s.trustedProxies))
	r.Use(middleware.LimitRequestBody(1 << 20))

	r.Use(hlog.NewHandler(s.logger.Logger))
	r.Use(hlog.MethodHandler("method"))
	r.Use(hlog.URLHandler("url"))
	r.Use(hlog.RemoteIPHandler("remote_ip"))
	r.Use(hlog.UserAgentHandler("user_agent"))
	r.Use(hlog.RequestIDHandler("request_id", "X-Request-ID"))
	r.Use(hlog.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
		event := hlog.FromRequest(r)

		var logEvent *zerolog.Event
		switch {
		case status >= 500:
			logEvent = event.Error()
		case status >= 400:
			logEvent = event.Warn()
		default:
			logEvent = event.Info()
		}

		logEvent.
			Int("status", status).
			Int("size", size).
			Dur("duration", duration).
			Msg("HTTP request")
	}))

	r.Use(middleware.Recoverer(s.config.IsProduction))

	r.Get("/", s.welcomeHandler)
	r.Get("/health", s.healthHandler)

	r.Route("/auth", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(s.rateLimiter.Limit("auth:login_register", 5, time.Minute))
			r.Post("/login", s.authHandler.HandleLogin)
			r.Post("/register", s.authHandler.HandleRegister)
		})

		r.Group(func(r chi.Router) {
			r.Use(s.rateLimiter.Limit("auth:refresh", 10, time.Minute))
			r.Post("/refresh", s.authHandler.HandleRefresh)
		})

		r.Group(func(r chi.Router) {
			r.Use(s.authMiddleware.Authenticate)
			r.Use(s.rateLimiter.Limit("auth:session", 60, time.Minute))
			r.Post("/logout", s.authHandler.HandleLogout)
			r.Get("/sessions", s.authHandler.HandleListSessions)
			r.Delete("/sessions/{session_id}", s.authHandler.HandleRevokeSession)
		})
	})

	r.Route("/profile", func(r chi.Router) {
		r.Use(s.authMiddleware.Authenticate)
		r.Use(s.rateLimiter.Limit("profile", 100, time.Minute))
		r.Get("/", s.userHandler.HandleGetProfile)
	})

	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		response.WriteNotFoundError(w, r, "")
	})

	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		response.WriteError(w, r, "", http.StatusMethodNotAllowed)
	})

	return r
}

func (s *Server) welcomeHandler(w http.ResponseWriter, r *http.Request) {
	response.WriteSuccess(w, r, http.StatusOK, "Welcome to the Go JWT Server!", nil)
}

func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	health := s.db.Health()
	status := http.StatusOK
	switch health["status"] {
	case "down", "degraded":
		status = http.StatusServiceUnavailable
	}
	response.WriteJSON(w, r, status, health)
}
