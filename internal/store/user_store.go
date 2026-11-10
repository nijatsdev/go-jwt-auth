package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/nijatsdev/go-jwt-auth/internal/database"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

// User represents a registered user in the system.
type User struct {
	ID           uuid.UUID `json:"id"`
	Name         string    `json:"name"`
	Email        string    `json:"email"`
	PasswordHash password  `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// password wraps a bcrypt hash for secure password storage.
type password struct {
	hash []byte
}

// Set hashes and sets the password.hash
func (p *password) Set(plainText string) error {
	sum := sha256.Sum256([]byte(plainText))
	hash, err := bcrypt.GenerateFromPassword(sum[:], bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	p.hash = hash
	return nil
}

// Matches checks if the provided plain text password matches the stored hash
func (p *password) Matches(plainText string) (bool, error) {
	sum := sha256.Sum256([]byte(plainText))
	err := bcrypt.CompareHashAndPassword(p.hash, sum[:])
	if err != nil {
		switch {
		case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
			return false, nil
		default:
			return false, err
		}
	}
	return true, nil
}

type UserStore interface {
	Create(ctx context.Context, user *User) error
	GetByEmail(ctx context.Context, email string) (*User, error)
	GetByID(ctx context.Context, id uuid.UUID) (*User, error)
	CheckExistsByEmail(ctx context.Context, email string) (bool, error)
}

// NormalizeEmail lowercases and trims an email address for storage and lookup.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

type PostgresUserStore struct {
	db *sql.DB
}

func NewPostgresUserStore(db *sql.DB) UserStore {
	return &PostgresUserStore{db: db}
}

// getQueryable returns either transaction or database connection based on context
func (s *PostgresUserStore) getQueryable(ctx context.Context) interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
} {
	if tx, ok := database.GetTx(ctx); ok {
		return tx
	}
	return s.db
}

// GetByID retrieves a user by their ID
func (s *PostgresUserStore) GetByID(ctx context.Context, id uuid.UUID) (*User, error) {
	exec := s.getQueryable(ctx)

	user := &User{}
	query := `SELECT id, name, email, password_hash, created_at, updated_at
		FROM users
		WHERE id = $1`
	err := exec.QueryRowContext(ctx, query, id).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.PasswordHash.hash,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		log.Ctx(ctx).Err(err).Msg("Database error getting user by ID")
		return nil, err
	}
	return user, nil
}

// Create inserts a new user into the database
func (s *PostgresUserStore) Create(ctx context.Context, user *User) error {
	exec := s.getQueryable(ctx)

	query := `INSERT INTO users (name, email, password_hash)
		VALUES ($1, $2, $3)
		RETURNING id, created_at, updated_at`
	err := exec.QueryRowContext(ctx, query, user.Name, user.Email, user.PasswordHash.hash).
		Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return errors.New("duplicate email")
		}
		log.Ctx(ctx).Error().Err(err).Str("email", user.Email).Msg("Database error creating user")
		return err
	}
	return nil
}

// GetByEmail retrieves a user by their email address
func (s *PostgresUserStore) GetByEmail(ctx context.Context, email string) (*User, error) {
	exec := s.getQueryable(ctx)

	user := &User{}
	query := `SELECT id, name, email, password_hash, created_at, updated_at
	FROM users
	WHERE LOWER(email) = LOWER($1)`
	err := exec.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.PasswordHash.hash,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			log.Ctx(ctx).Error().
				Err(err).
				Str("email", email).
				Msg("Database error getting user by email")
		}
		return nil, err
	}
	return user, nil
}

// CheckExistsByEmail checks if a user with the given email exists
func (s *PostgresUserStore) CheckExistsByEmail(ctx context.Context, email string) (bool, error) {
	exec := s.getQueryable(ctx)

	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE LOWER(email) = LOWER($1))`
	err := exec.QueryRowContext(ctx, query, email).Scan(&exists)
	if err != nil {
		log.Ctx(ctx).Error().
			Err(err).
			Str("email", email).
			Msg("Database error checking email existence")
		return false, err
	}
	return exists, nil
}
