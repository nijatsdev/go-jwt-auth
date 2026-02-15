package database

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nijatsdev/go-jwt-auth/internal/logger"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// Service defines database operations
type Service interface {
	Close() error
	GetDB() *sql.DB
	Health() map[string]string
}

// Config holds database configuration
type Config struct {
	Host     string
	Port     int
	Database string
	Username string
	Password string
	Schema   string
}

// PoolConfig holds connection pool settings
type PoolConfig struct {
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
}

type service struct {
	config     Config
	poolConfig PoolConfig
	logger     *logger.Logger
	db         *sql.DB
}

// New creates a new database service
func New(cfg Config, logger *logger.Logger) (Service, error) {
	poolCfg := PoolConfig{
		MaxOpenConns:    50,
		MaxIdleConns:    25,
		ConnMaxLifetime: 30 * time.Minute,
		ConnMaxIdleTime: 5 * time.Minute,
	}

	connStr := fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=disable&search_path=%s",
		cfg.Username,
		cfg.Password,
		cfg.Host,
		cfg.Port,
		cfg.Database,
		cfg.Schema,
	)

	db, err := sql.Open("pgx", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(poolCfg.MaxOpenConns)
	db.SetMaxIdleConns(poolCfg.MaxIdleConns)
	db.SetConnMaxLifetime(poolCfg.ConnMaxLifetime)
	db.SetConnMaxIdleTime(poolCfg.ConnMaxIdleTime)

	// Verify connectivity
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	logger.Info().
		Str("database", cfg.Database).
		Msg("Connected to database")

	return &service{
		config:     cfg,
		poolConfig: poolCfg,
		logger:     logger,
		db:         db,
	}, nil
}

// Close closes the database connection gracefully
func (s *service) Close() error {
	s.logger.Info().
		Str("database", s.config.Database).
		Msg("Closing database connection")

	if err := s.db.Close(); err != nil {
		return fmt.Errorf("failed to close database: %w", err)
	}

	return nil
}

// GetDB returns the underlying sql.DB instance
func (s *service) GetDB() *sql.DB {
	return s.db
}

// Health reports database health and pool pressure
func (s *service) Health() map[string]string {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	stats := make(map[string]string)

	if err := s.db.PingContext(ctx); err != nil {
		stats["status"] = "down"
		stats["error"] = err.Error()
		s.logger.Error().Err(err).Msg("Database health check failed")
		return stats
	}

	dbStats := s.db.Stats()

	stats["open_connections"] = strconv.Itoa(dbStats.OpenConnections)
	stats["in_use"] = strconv.Itoa(dbStats.InUse)
	stats["idle"] = strconv.Itoa(dbStats.Idle)
	stats["wait_count"] = strconv.FormatInt(dbStats.WaitCount, 10)
	stats["wait_duration"] = dbStats.WaitDuration.String()
	stats["max_idle_closed"] = strconv.FormatInt(dbStats.MaxIdleClosed, 10)
	stats["max_lifetime_closed"] = strconv.FormatInt(dbStats.MaxLifetimeClosed, 10)

	var warnings []string

	openRatio := float64(dbStats.OpenConnections) / float64(s.poolConfig.MaxOpenConns)

	if openRatio >= 0.8 {
		warnings = append(warnings, "High connection usage (>80% of pool)")
	}

	if dbStats.InUse >= s.poolConfig.MaxOpenConns {
		warnings = append(warnings, "Connection pool exhausted")
	}

	if dbStats.WaitDuration > 2*time.Second {
		warnings = append(warnings, "High connection wait time")
	}

	if dbStats.MaxLifetimeClosed > int64(s.poolConfig.MaxOpenConns) {
		warnings = append(warnings, "Frequent connection recycling (max lifetime)")
	}

	if len(warnings) > 0 {
		stats["status"] = "degraded"
		stats["message"] = strings.Join(warnings, "; ")
	} else {
		stats["status"] = "up"
		stats["message"] = "Database is healthy"
	}

	return stats
}
