package database_test

import (
	"os"
	"testing"

	"github.com/nijatsdev/go-jwt-auth/internal/database"
	"github.com/nijatsdev/go-jwt-auth/internal/logger"
	"github.com/nijatsdev/go-jwt-auth/internal/testutil"
)

func TestMain(m *testing.M) {
	testutil.MustStartPostgresContainer()
	code := m.Run()
	testutil.TeardownPostgresContainer()
	os.Exit(code)
}

func getTestConfig() database.Config {
	host, port := testutil.GetHostPort()
	return database.Config{
		Host:     host,
		Port:     port,
		Database: "test_db",
		Username: "test",
		Password: "test",
		Schema:   "public",
	}
}

func getTestLogger() *logger.Logger {
	return logger.New(logger.Config{Level: "error", IsLocal: true})
}

func TestNew(t *testing.T) {
	svc, err := database.New(getTestConfig(), getTestLogger())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = svc.Close() }()

	if svc.GetDB() == nil {
		t.Error("GetDB() returned nil")
	}
}

func TestGetDB(t *testing.T) {
	svc, err := database.New(getTestConfig(), getTestLogger())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = svc.Close() }()

	db := svc.GetDB()
	if db == nil {
		t.Fatal("GetDB() returned nil")
	}

	var result int
	if err := db.QueryRow("SELECT 1").Scan(&result); err != nil {
		t.Fatalf("QueryRow() error = %v", err)
	}
}

func TestHealth(t *testing.T) {
	svc, err := database.New(getTestConfig(), getTestLogger())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = svc.Close() }()

	stats := svc.Health()

	if stats["status"] != "up" {
		t.Errorf("Health() status = %v, want up", stats["status"])
	}

	if _, ok := stats["error"]; ok {
		t.Fatalf("expected error not to be present")
	}

	if stats["message"] != "Database is healthy" {
		t.Fatalf("expected message to be 'Database is healthy', got %s", stats["message"])
	}
}

func TestClose(t *testing.T) {
	svc, err := database.New(getTestConfig(), getTestLogger())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := svc.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	db := svc.GetDB()
	if err := db.Ping(); err == nil {
		t.Error("Ping() should fail after Close()")
	}
}
