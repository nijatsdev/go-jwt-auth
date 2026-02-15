package logger

import (
	"io"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/pkgerrors"
)

// Config holds logger configuration
type Config struct {
	Level      string
	Output     io.Writer
	IsLocal    bool
	TimeFormat string
}

// Logger wraps a zerolog.Logger value
type Logger struct {
	zerolog.Logger
}

// New creates a configured zerolog Logger
func New(cfg Config) *Logger {
	// Default output to stderr
	out := cfg.Output
	if out == nil {
		out = os.Stderr
	}

	// Default time format to unix if not set
	tf := cfg.TimeFormat
	if tf == "" {
		tf = time.RFC3339
	}

	// Pretty CLI output if local
	if cfg.IsLocal {
		out = zerolog.ConsoleWriter{
			Out:        out,
			TimeFormat: tf,
		}
	}

	// Parse and set global log level
	level := parseLevel(cfg.Level)
	zerolog.SetGlobalLevel(level)

	// Enable stacktrace support
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack

	// Set time format
	zerolog.TimeFieldFormat = tf

	// Build the logger
	baseLogger := zerolog.New(out).With().Timestamp().Logger()

	return &Logger{Logger: baseLogger}
}

func parseLevel(levelStr string) zerolog.Level {
	switch strings.ToLower(levelStr) {
	case "debug":
		return zerolog.DebugLevel
	case "info":
		return zerolog.InfoLevel
	case "warn":
		return zerolog.WarnLevel
	case "error":
		return zerolog.ErrorLevel
	default:
		return zerolog.InfoLevel
	}
}
