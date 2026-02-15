package testutil

import (
	"context"
	"database/sql"
	"log"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/pressly/goose/v3"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestDB holds a test database connection.
type TestDB struct {
	DB *sql.DB
}

var (
	testDB    *TestDB
	testHost  string
	testPort  int
	terminate func(context.Context, ...testcontainers.TerminateOption) error
)

// MustStartPostgresContainer starts the test container and initializes testDB.
// Call from TestMain before m.Run().
func MustStartPostgresContainer() {
	ctx := context.Background()

	container, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("test_db"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		log.Fatalf("could not start postgres container: %v", err)
	}
	terminate = container.Terminate

	host, err := container.Host(ctx)
	if err != nil {
		log.Fatalf("could not get container host: %v", err)
	}
	testHost = host

	port, err := container.MappedPort(ctx, "5432")
	if err != nil {
		log.Fatalf("could not get container port: %v", err)
	}
	testPort = port.Int()

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		log.Fatalf("could not get connection string: %v", err)
	}

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("could not connect to test database: %v", err)
	}

	// Run migrations from project migrations folder
	_, filename, _, _ := runtime.Caller(0)
	migrationsDir := filepath.Join(filepath.Dir(filename), "..", "..", "migrations")

	if err := goose.SetDialect("postgres"); err != nil {
		log.Fatalf("could not set goose dialect: %v", err)
	}
	if err := goose.Up(db, migrationsDir); err != nil {
		log.Fatalf("could not run migrations: %v", err)
	}

	testDB = &TestDB{DB: db}
}

// TeardownPostgresContainer stops the container. Call from TestMain after m.Run().
func TeardownPostgresContainer() {
	if terminate != nil {
		_ = terminate(context.Background())
	}
}

// SetupTestDB returns the shared test database, cleaning tables for isolation.
func SetupTestDB(t *testing.T) *TestDB {
	t.Helper()
	if testDB == nil {
		t.Fatal("test database not initialized - call MustStartPostgresContainer in TestMain")
	}
	testDB.CleanTables(t)
	return testDB
}

// CleanTables truncates all test tables.
func (tdb *TestDB) CleanTables(t *testing.T) {
	t.Helper()
	tables := []string{"oauth_refresh_tokens", "users"}
	for _, table := range tables {
		if _, err := tdb.DB.Exec("TRUNCATE TABLE " + table + " CASCADE"); err != nil {
			t.Fatalf("failed to truncate table %s: %v", table, err)
		}
	}
}

// GetHostPort returns the container's host and port.
func GetHostPort() (string, int) {
	return testHost, testPort
}
