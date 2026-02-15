package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/nijatsdev/go-jwt-auth/internal/config"
	"github.com/nijatsdev/go-jwt-auth/internal/cron"
	"github.com/nijatsdev/go-jwt-auth/internal/database"
	"github.com/nijatsdev/go-jwt-auth/internal/handlers"
	"github.com/nijatsdev/go-jwt-auth/internal/logger"
	"github.com/nijatsdev/go-jwt-auth/internal/middleware"
	"github.com/nijatsdev/go-jwt-auth/internal/services"
	"github.com/nijatsdev/go-jwt-auth/internal/store"
)

type Server struct {
	httpServer     *http.Server
	logger         *logger.Logger
	config         *config.Config
	db             database.Service
	authMiddleware *middleware.AuthMiddleware
	rateLimiter    *middleware.RateLimiter
	authHandler    *handlers.AuthHandler
	userHandler    *handlers.UserHandler
	scheduler      *cron.Scheduler
}

func NewServer() (*Server, error) {
	// Initialize configuration
	cfg, err := config.Load(".env")
	if err != nil {
		return nil, fmt.Errorf("failed to initialize config: %w", err)
	}

	// Initialize logger
	appLogger := logger.New(logger.Config{
		Level:   cfg.LogLevel,
		IsLocal: cfg.IsLocal,
	})

	// Create a database service
	dbService, err := database.New(database.Config{
		Host:     cfg.DBHost,
		Port:     cfg.DBPort,
		Database: cfg.DBDatabase,
		Username: cfg.DBUsername,
		Password: cfg.DBPassword,
		Schema:   cfg.DBSchema,
	}, appLogger)
	if err != nil {
		return nil, fmt.Errorf("failed to create database service: %w", err)
	}
	db := dbService.GetDB()

	// Initialize stores
	userStore := store.NewPostgresUserStore(db)
	refreshTokenStore := store.NewPostgresRefreshTokenStore(db)

	// Initialize transaction manager
	txManager := database.NewTxManager(db)

	// Initialize services
	authService := services.NewAuthService(
		txManager,
		userStore,
		refreshTokenStore,
		cfg.AccessTokenTTL,
		cfg.RefreshTokenTTL,
		cfg.JWTSecret,
		cfg.MaxActiveRefreshTokensPerUser,
	)

	// Initialize middleware
	authMiddleware := middleware.NewAuthMiddleware(authService)
	rateLimiter := middleware.NewRateLimiter()

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(authService)
	userHandler := handlers.NewUserHandler(userStore)

	// Create scheduler
	scheduler, err := cron.NewScheduler(
		appLogger,
		refreshTokenStore,
		cfg.ExpiredTokenRetentionDays,
		cfg.RevokedTokenRetentionDays,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create scheduler: %w", err)
	}

	// Start scheduler
	if err := scheduler.Start(); err != nil {
		return nil, fmt.Errorf("failed to start scheduler: %w", err)
	}

	// Create a server instance
	newServer := &Server{
		logger:         appLogger,
		config:         cfg,
		db:             dbService,
		authMiddleware: authMiddleware,
		rateLimiter:    rateLimiter,
		authHandler:    authHandler,
		userHandler:    userHandler,
		scheduler:      scheduler,
	}

	// Declare Server config
	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", newServer.config.Port),
		Handler:      newServer.registerRoutes(),
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	newServer.httpServer = httpServer

	return newServer, nil
}

// Start starts the HTTP server
func (s *Server) Start() error {
	s.logger.Info().
		Str("addr", s.httpServer.Addr).
		Msg("Starting HTTP server")

	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server and its components
func (s *Server) Shutdown(ctx context.Context) error {
	if err := s.scheduler.Shutdown(); err != nil {
		return err
	}

	s.logger.Info().Msg("Stopping HTTP server")
	if err := s.httpServer.Shutdown(ctx); err != nil {
		return err
	}

	if err := s.db.Close(); err != nil {
		return err
	}

	return nil
}

// GetLogger returns the server's logger
func (s *Server) GetLogger() *logger.Logger {
	return s.logger
}
