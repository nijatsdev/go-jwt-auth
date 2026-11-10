package config

import (
	"fmt"
	"os"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	// Application config
	Port     int    `env:"PORT" env-default:"8080"`
	AppEnv   string `env:"APP_ENV" env-default:"local"`
	LogLevel string `env:"LOG_LEVEL" env-default:"info"`

	// Database config
	DBHost     string `env:"DB_HOST" env-default:"localhost"`
	DBPort     int    `env:"DB_PORT" env-default:"5432"`
	DBDatabase string `env:"DB_DATABASE" env-required:"true"`
	DBUsername string `env:"DB_USERNAME" env-required:"true"`
	DBPassword string `env:"DB_PASSWORD"`
	DBSchema   string `env:"DB_SCHEMA" env-default:"public"`
	DBSSLMode  string `env:"DB_SSLMODE" env-default:"disable"`

	// JWT config
	JWTSecret  string `env:"JWT_SECRET" env-required:"true"`
	JWTIssuer  string `env:"JWT_ISSUER" env-default:"go-jwt-auth"`
	JWTAudience string `env:"JWT_AUDIENCE" env-default:"go-jwt-auth-api"`

	// CORS (comma-separated origins; empty disables credentialed wide-open CORS)
	CORSAllowedOrigins string `env:"CORS_ALLOWED_ORIGINS"`

	// TrustedProxyCIDRs — comma-separated CIDRs; X-Forwarded-For is honored only from these peers.
	TrustedProxyCIDRs string `env:"TRUSTED_PROXY_CIDRS"`

	// Token config
	AccessTokenTTL                time.Duration `env:"ACCESS_TOKEN_TTL" env-default:"15m"`
	RefreshTokenTTL               time.Duration `env:"REFRESH_TOKEN_TTL" env-default:"168h"`
	MaxActiveRefreshTokensPerUser int           `env:"MAX_ACTIVE_REFRESH_TOKENS_PER_USER" env-default:"10"`

	// Token cleanup config
	ExpiredTokenRetentionDays int `env:"EXPIRED_TOKEN_RETENTION_DAYS" env-default:"30"`
	RevokedTokenRetentionDays int `env:"REVOKED_TOKEN_RETENTION_DAYS" env-default:"90"`

	// Custom values
	IsLocal      bool `env:"-" env-default:"false"`
	IsProduction bool `env:"-" env-default:"false"`
}

func Load(configPath string) (*Config, error) {
	cfg := &Config{}

	// First try .env file
	err := cleanenv.ReadConfig(configPath, cfg)
	if err != nil {
		if os.IsNotExist(err) {
			// Fallback to environment variables
			if err := cleanenv.ReadEnv(cfg); err != nil {
				return nil, fmt.Errorf("config load from env failed: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to load config file: %w", err)
		}
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	cfg.IsLocal = cfg.AppEnv == "local" || cfg.AppEnv == "development" || cfg.AppEnv == "dev"
	cfg.IsProduction = cfg.AppEnv == "production" || cfg.AppEnv == "prod"

	if cfg.CORSAllowedOrigins == "" && cfg.IsLocal {
		cfg.CORSAllowedOrigins = "http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000"
	}

	if cfg.TrustedProxyCIDRs == "" && cfg.IsLocal {
		cfg.TrustedProxyCIDRs = "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1/128"
	}

	return cfg, nil
}

// CORSOrigins returns parsed CORS allowed origins.
func (c *Config) CORSOrigins() []string {
	if c.CORSAllowedOrigins == "" {
		return nil
	}
	parts := make([]string, 0)
	start := 0
	for i := 0; i <= len(c.CORSAllowedOrigins); i++ {
		if i == len(c.CORSAllowedOrigins) || c.CORSAllowedOrigins[i] == ',' {
			if i > start {
				origin := c.CORSAllowedOrigins[start:i]
				for len(origin) > 0 && (origin[0] == ' ' || origin[0] == '\t') {
					origin = origin[1:]
				}
				for len(origin) > 0 && (origin[len(origin)-1] == ' ' || origin[len(origin)-1] == '\t') {
					origin = origin[:len(origin)-1]
				}
				if origin != "" {
					parts = append(parts, origin)
				}
			}
			start = i + 1
		}
	}
	return parts
}

// Additional semantic validation
func (c *Config) validate() error {
	// Validate required database fields
	if c.DBDatabase == "" {
		return fmt.Errorf("DB_DATABASE must not be empty")
	}
	if c.DBUsername == "" {
		return fmt.Errorf("DB_USERNAME must not be empty")
	}

	// Validate token TTLs
	if c.AccessTokenTTL <= 0 {
		return fmt.Errorf("ACCESS_TOKEN_TTL must be positive, got: %v", c.AccessTokenTTL)
	}
	if c.RefreshTokenTTL <= 0 {
		return fmt.Errorf("REFRESH_TOKEN_TTL must be positive, got: %v", c.RefreshTokenTTL)
	}
	if c.RefreshTokenTTL <= c.AccessTokenTTL {
		return fmt.Errorf("REFRESH_TOKEN_TTL (%v) must be greater than ACCESS_TOKEN_TTL (%v)",
			c.RefreshTokenTTL, c.AccessTokenTTL)
	}

	// Validate required JWT secret
	if c.JWTSecret == "" {
		return fmt.Errorf("JWT_SECRET must not be empty")
	}
	if len(c.JWTSecret) < 32 {
		return fmt.Errorf("JWT_SECRET must be at least 32 characters for security, got: %d", len(c.JWTSecret))
	}

	// Validate retention days
	if c.ExpiredTokenRetentionDays < 0 {
		return fmt.Errorf("EXPIRED_TOKEN_RETENTION_DAYS must be non-negative, got: %d", c.ExpiredTokenRetentionDays)
	}
	if c.RevokedTokenRetentionDays < 0 {
		return fmt.Errorf("REVOKED_TOKEN_RETENTION_DAYS must be non-negative, got: %d", c.RevokedTokenRetentionDays)
	}

	// Validate token limits
	if c.MaxActiveRefreshTokensPerUser < 1 {
		return fmt.Errorf("MAX_ACTIVE_REFRESH_TOKENS_PER_USER must be at least 1, got: %d", c.MaxActiveRefreshTokensPerUser)
	}

	// Validate port
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("PORT must be between 1 and 65535, got: %d", c.Port)
	}

	// Validate log level
	validLogLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}
	if !validLogLevels[c.LogLevel] {
		return fmt.Errorf("LOG_LEVEL must be one of (debug, info, warn, error), got: %s", c.LogLevel)
	}

	// Validate app environment
	validEnvs := map[string]bool{
		"local":       true,
		"development": true,
		"dev":         true,
		"production":  true,
		"prod":        true,
		"staging":     true,
	}
	if !validEnvs[c.AppEnv] {
		return fmt.Errorf("APP_ENV must be one of (local, development, dev, production, prod, staging), got: %s", c.AppEnv)
	}

	return nil
}
