package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/rs/zerolog/log"
)

type TxKey struct{}

// TransactionManager defines the interface for transaction management.
type TransactionManager interface {
	WithTransaction(ctx context.Context, fn func(ctx context.Context) error) error
}

type TxManager struct {
	db *sql.DB
}

func NewTxManager(db *sql.DB) *TxManager {
	return &TxManager{db: db}
}

// CommitError wraps an error that should still allow transaction to commit.
type CommitError struct {
	Err error
}

func (e *CommitError) Error() string {
	return e.Err.Error()
}

func (e *CommitError) Unwrap() error {
	return e.Err
}

// NewCommitError creates an error that will commit the transaction but still return an error.
func NewCommitError(err error) error {
	return &CommitError{Err: err}
}

// IsCommitError checks if an error is a CommitError.
func IsCommitError(err error) bool {
	var commitErr *CommitError
	return errors.As(err, &commitErr)
}

// WithTransaction runs fn within a transaction.
// If fn returns nil, the transaction is committed.
// If fn returns a CommitError, the transaction is committed but the error is returned.
// If fn returns any other error, the transaction is rolled back.
func (tm *TxManager) WithTransaction(ctx context.Context, fn func(ctx context.Context) error) error {
	tx, err := tm.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
	})
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	txCtx := context.WithValue(ctx, TxKey{}, tx)

	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
	}()

	fnErr := fn(txCtx)

	// Decide to commit or rollback
	if fnErr != nil && !IsCommitError(fnErr) {
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			log.Ctx(ctx).Error().Err(rollbackErr).Msg("Failed to rollback transaction")
		}
		return fnErr
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Return the original error (unwrapped from CommitError if applicable)
	if fnErr != nil {
		var commitErr *CommitError
		if errors.As(fnErr, &commitErr) {
			return commitErr.Err
		}
	}

	return nil
}

// GetTx retrieves the transaction from context if present.
func GetTx(ctx context.Context) (*sql.Tx, bool) {
	tx, ok := ctx.Value(TxKey{}).(*sql.Tx)
	return tx, ok
}
