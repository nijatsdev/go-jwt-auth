package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nijatsdev/go-jwt-auth/internal/server"
)

func main() {
	srv, err := server.NewServer()
	if err != nil {
		log.Fatalf("Failed to initialize server: %v\n", err)
	}

	// Start server
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- srv.Start()
	}()

	// Setup signal handler
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Get logger
	appLogger := srv.GetLogger()

	select {
	case <-quit:
		appLogger.Info().Msg("Shutdown signal received")
	case err := <-serverDone:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			appLogger.Fatal().Err(err).Msg("Server exited unexpectedly")
		}
	}

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		appLogger.Fatal().Err(err).Msg("Server forced to shutdown")
	}

	appLogger.Info().Msg("Server stopped gracefully")
}
