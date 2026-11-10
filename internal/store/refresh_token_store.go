package store

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"

	"github.com/nijatsdev/go-jwt-auth/internal/database"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// RefreshToken represents a refresh token stored in the database.
// It contains device information and rotation chain tracking for security.
type RefreshToken struct {
	ID            uuid.UUID
	UserID        uuid.UUID
	TokenHash     string
	UserAgent     string
	IPAddress     string
	DeviceID      string
	DeviceName    sql.NullString
	RotatedFrom   uuid.NullUUID
	ExpiresAt     time.Time
	CreatedAt     time.Time
	RevokedAt     sql.NullTime
	RevokedReason sql.NullString
}

// RefreshTokenResponse represents a refresh token for API responses.
// It contains session information visible to the user.
type RefreshTokenResponse struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	UserAgent  string
	IPAddress  string
	DeviceID   string
	DeviceName string
	CreatedAt  time.Time
	IsCurrent  bool
}

// RevokedReason represents why a refresh token was revoked.
type RevokedReason string

// Revocation reasons for refresh tokens.
const (
	RevokedReasonUserLogout       RevokedReason = "user_logout"
	RevokedReasonRemoteRevoke     RevokedReason = "remote_revoke"
	RevokedReasonTokenRotation    RevokedReason = "token_rotation"
	RevokedReasonDeviceReLogin    RevokedReason = "device_relogin"
	RevokedReasonSessionLimit     RevokedReason = "session_limit"
	RevokedReasonDeviceMismatch   RevokedReason = "device_mismatch"
	RevokedReasonReplayDetected   RevokedReason = "replay_detected"
	RevokedReasonGracePeriodAbuse RevokedReason = "grace_period_abuse"
)

type RefreshTokenStore interface {
	Create(ctx context.Context, token *RefreshToken) (uuid.UUID, error)
	GetByTokenHashForUpdate(ctx context.Context, tokenHash string) (*RefreshToken, error)
	CheckRotated(ctx context.Context, tokenID uuid.UUID) (bool, error)
	ListByUserID(ctx context.Context, userID uuid.UUID, refreshTokenID string) ([]*RefreshTokenResponse, error)
	RevokeRotationChain(ctx context.Context, tokenID uuid.UUID, reason RevokedReason) ([]uuid.UUID, error)
	CleanupExpired(ctx context.Context, expiredRetentionDays, revokedRetentionDays int) (int64, error)
	GetActiveChildByParent(ctx context.Context, parentID uuid.UUID) (*RefreshToken, error)
	GetActiveForwardLeaf(ctx context.Context, tokenID uuid.UUID) (*RefreshToken, error)
	Revoke(ctx context.Context, tokenID uuid.UUID, revokedReason RevokedReason) error
	GetActiveByUserAndDevice(ctx context.Context, userID uuid.UUID, deviceID string) (*RefreshToken, error)
	CountActiveSessionsByUser(ctx context.Context, userID uuid.UUID) (int, error)
	RevokeOldestActiveToken(ctx context.Context, userID uuid.UUID) error
	GetByID(ctx context.Context, tokenID uuid.UUID) (*RefreshToken, error)
	CountChildrenByParent(ctx context.Context, parentID uuid.UUID) (int, error)
}

type PostgresRefreshTokenStore struct {
	db *sql.DB
}

func NewPostgresRefreshTokenStore(db *sql.DB) RefreshTokenStore {
	return &PostgresRefreshTokenStore{db: db}
}

// getQueryable returns either transaction or database connection based on context
func (s *PostgresRefreshTokenStore) getQueryable(ctx context.Context) interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
} {
	if tx, ok := database.GetTx(ctx); ok {
		return tx
	}
	return s.db
}

// Create inserts a new refresh token into the database
func (s *PostgresRefreshTokenStore) Create(ctx context.Context, token *RefreshToken) (uuid.UUID, error) {
	db := s.getQueryable(ctx)
	query := `INSERT INTO oauth_refresh_tokens (user_id, token_hash, user_agent, ip_address, device_id, device_name, rotated_from, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id, created_at`
	err := db.QueryRowContext(ctx, query,
		token.UserID,
		token.TokenHash,
		token.UserAgent,
		token.IPAddress,
		token.DeviceID,
		token.DeviceName,
		token.RotatedFrom,
		token.ExpiresAt,
	).Scan(&token.ID, &token.CreatedAt)

	if err != nil {
		log.Ctx(ctx).Error().
			Err(err).
			Str("user_id", token.UserID.String()).
			Msg("Database error creating refresh token")
		return uuid.Nil, err
	}

	return token.ID, nil
}

// GetByTokenHashForUpdate retrieves a refresh token by its token hash with row-level lock
// This prevents race conditions during concurrent refresh attempts
func (s *PostgresRefreshTokenStore) GetByTokenHashForUpdate(ctx context.Context, tokenHash string) (*RefreshToken, error) {
	db := s.getQueryable(ctx)
	token := &RefreshToken{}
	query := `SELECT id, user_id, user_agent, ip_address, device_id, device_name, token_hash, rotated_from, expires_at, created_at, revoked_at, revoked_reason
		 FROM oauth_refresh_tokens
		 WHERE token_hash = $1
		 FOR UPDATE`
	err := db.QueryRowContext(ctx, query, tokenHash).Scan(
		&token.ID,
		&token.UserID,
		&token.UserAgent,
		&token.IPAddress,
		&token.DeviceID,
		&token.DeviceName,
		&token.TokenHash,
		&token.RotatedFrom,
		&token.ExpiresAt,
		&token.CreatedAt,
		&token.RevokedAt,
		&token.RevokedReason,
	)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			log.Ctx(ctx).Error().
				Err(err).
				Msg("Database error getting refresh token by hash for update")
		}
		return nil, err
	}
	return token, nil
}

// CheckRotated checks if a refresh token has been rotated
func (s *PostgresRefreshTokenStore) CheckRotated(ctx context.Context, tokenID uuid.UUID) (bool, error) {
	db := s.getQueryable(ctx)
	var exists bool
	query := `SELECT EXISTS (
			SELECT 1
			FROM oauth_refresh_tokens
			WHERE rotated_from = $1 )`
	err := db.QueryRowContext(ctx, query, tokenID).Scan(&exists)
	if err != nil {
		log.Ctx(ctx).Error().
			Err(err).
			Str("token_id", tokenID.String()).
			Msg("Database error checking if refresh token is rotated")
		return false, err
	}

	return exists, nil
}

// ListByUserID list all active refresh tokens by user ID
func (s *PostgresRefreshTokenStore) ListByUserID(ctx context.Context, userID uuid.UUID, refreshTokenID string) ([]*RefreshTokenResponse, error) {
	db := s.getQueryable(ctx)
	query := `SELECT id, user_id, user_agent, ip_address, device_id, device_name, created_at
		 FROM oauth_refresh_tokens
		 WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > CURRENT_TIMESTAMP ORDER BY created_at ASC`
	rows, err := db.QueryContext(ctx, query, userID)
	if err != nil {
		log.Ctx(ctx).Error().
			Err(err).
			Str("user_id", userID.String()).
			Msg("Database error listing refresh tokens by user ID")
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Ctx(ctx).Error().
				Err(err).
				Str("user_id", userID.String()).
				Msg("Database error closing rows for refresh tokens listing")
		}
	}()

	// Collect tokens
	var tokens []*RefreshTokenResponse
	for rows.Next() {
		token := &RefreshTokenResponse{}
		var deviceName sql.NullString
		err := rows.Scan(
			&token.ID,
			&token.UserID,
			&token.UserAgent,
			&token.IPAddress,
			&token.DeviceID,
			&deviceName,
			&token.CreatedAt,
		)

		if err != nil {
			log.Ctx(ctx).Error().
				Err(err).
				Str("user_id", userID.String()).
				Msg("Database error scanning refresh token row")
			return nil, err
		}

		if deviceName.Valid {
			token.DeviceName = deviceName.String
		} else {
			token.DeviceName = "Unknown"
		}

		// Mark if this is the current token
		token.IsCurrent = token.ID.String() == refreshTokenID
		tokens = append(tokens, token)
	}
	if err := rows.Err(); err != nil {
		log.Ctx(ctx).Error().
			Err(err).
			Str("user_id", userID.String()).
			Msg("Database error iterating refresh token rows")
		return nil, err
	}

	return tokens, nil
}

// RevokeRotationChain revokes all tokens in the forward rotation chain
func (s *PostgresRefreshTokenStore) RevokeRotationChain(ctx context.Context, tokenID uuid.UUID, reason RevokedReason) ([]uuid.UUID, error) {
	db := s.getQueryable(ctx)
	revokedTokens := make([]uuid.UUID, 0)
	// Revoke only ACTIVE tokens in a forward chain
	query := `WITH RECURSIVE forward_chain AS (
			SELECT id
			FROM oauth_refresh_tokens
			WHERE rotated_from = $1
			UNION ALL
			SELECT t.id
			FROM oauth_refresh_tokens t
			INNER JOIN forward_chain fc ON t.rotated_from = fc.id
		)
		UPDATE oauth_refresh_tokens
		SET revoked_at = CURRENT_TIMESTAMP,
		    revoked_reason = $2
		WHERE id IN (SELECT id FROM forward_chain) AND revoked_at IS NULL
		RETURNING id`
	rows, err := db.QueryContext(ctx, query, tokenID, string(reason))
	if err != nil {
		log.Ctx(ctx).Error().
			Err(err).
			Str("token_id", tokenID.String()).
			Msg("Database error revoking forward chain")
		return nil, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Ctx(ctx).Error().
				Err(err).
				Str("token_id", tokenID.String()).
				Msg("Database error closing rows for revoking forward chain")
		}
	}()

	// Collect revoked token IDs
	for rows.Next() {
		var id uuid.UUID
		if err = rows.Scan(&id); err != nil {
			log.Ctx(ctx).Error().
				Err(err).
				Str("token_id", tokenID.String()).
				Msg("Database error scanning revoked token ID")
			return nil, err
		}
		revokedTokens = append(revokedTokens, id)
	}
	if err := rows.Err(); err != nil {
		log.Ctx(ctx).Error().
			Err(err).
			Str("token_id", tokenID.String()).
			Msg("Database error iterating revoked token ID rows")
		return nil, err
	}

	return revokedTokens, nil
}

// CleanupExpired removes old expired and revoked tokens
func (s *PostgresRefreshTokenStore) CleanupExpired(ctx context.Context, expiredRetentionDays, revokedRetentionDays int) (int64, error) {
	query := `DELETE FROM oauth_refresh_tokens WHERE (
           -- Delete expired tokens older than retention period
           (revoked_at IS NULL AND expires_at < CURRENT_TIMESTAMP - ($1 || ' days')::INTERVAL) OR
           -- Delete revoked tokens older than retention period
           (revoked_at IS NOT NULL AND revoked_at < CURRENT_TIMESTAMP - ($2 || ' days')::INTERVAL) )`
	result, err := s.db.ExecContext(ctx, query,
		strconv.Itoa(expiredRetentionDays),
		strconv.Itoa(revokedRetentionDays),
	)
	if err != nil {
		log.Error().
			Err(err).
			Msg("Database error cleaning up expired and revoked refresh tokens")
		return 0, err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Error().
			Err(err).
			Msg("Database error getting affected rows for cleanup of refresh tokens")
		return 0, err
	}

	return rowsAffected, nil
}

// Revoke a refresh token by its ID
func (s *PostgresRefreshTokenStore) Revoke(ctx context.Context, tokenID uuid.UUID, reason RevokedReason) error {
	db := s.getQueryable(ctx)
	var revokedAt sql.NullTime
	var revokedReason sql.NullString

	query := `UPDATE oauth_refresh_tokens
		 SET revoked_at = CURRENT_TIMESTAMP, revoked_reason = $2
		 WHERE id = $1
		 RETURNING revoked_at, revoked_reason`
	err := db.QueryRowContext(ctx, query, tokenID, string(reason)).Scan(&revokedAt, &revokedReason)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			log.Ctx(ctx).Error().
				Err(err).
				Str("token_id", tokenID.String()).
				Msg("Database error revoking refresh token")
		}
		return err
	}
	return nil
}

// GetActiveByUserAndDevice retrieves an active refresh token for a specific user and device
func (s *PostgresRefreshTokenStore) GetActiveByUserAndDevice(ctx context.Context, userID uuid.UUID, deviceID string) (*RefreshToken, error) {
	db := s.getQueryable(ctx)
	token := &RefreshToken{}
	query := `SELECT id, user_id, user_agent, ip_address, device_id, device_name, token_hash, rotated_from, expires_at, created_at, revoked_at, revoked_reason
		 FROM oauth_refresh_tokens
		 WHERE user_id = $1
		   AND device_id = $2
		   AND revoked_at IS NULL
		   AND expires_at > CURRENT_TIMESTAMP
		 ORDER BY created_at DESC
		 LIMIT 1`
	err := db.QueryRowContext(ctx, query, userID, deviceID).Scan(
		&token.ID,
		&token.UserID,
		&token.UserAgent,
		&token.IPAddress,
		&token.DeviceID,
		&token.DeviceName,
		&token.TokenHash,
		&token.RotatedFrom,
		&token.ExpiresAt,
		&token.CreatedAt,
		&token.RevokedAt,
		&token.RevokedReason,
	)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			log.Ctx(ctx).Error().
				Err(err).
				Str("user_id", userID.String()).
				Str("device_id", deviceID).
				Msg("Database error getting active token by user and device")
		}
		return nil, err
	}

	return token, nil
}

// CountActiveSessionsByUser counts active sessions for a user
func (s *PostgresRefreshTokenStore) CountActiveSessionsByUser(ctx context.Context, userID uuid.UUID) (int, error) {
	db := s.getQueryable(ctx)
	var count int
	query := `SELECT COUNT(*)
		 FROM oauth_refresh_tokens
		 WHERE user_id = $1
		   AND revoked_at IS NULL
		   AND expires_at > CURRENT_TIMESTAMP`
	err := db.QueryRowContext(ctx, query, userID).Scan(&count)
	if err != nil {
		log.Ctx(ctx).Error().
			Err(err).
			Str("user_id", userID.String()).
			Msg("Database error counting active sessions")
		return 0, err
	}
	return count, nil
}

// RevokeOldestActiveToken revokes the oldest active session for a user
func (s *PostgresRefreshTokenStore) RevokeOldestActiveToken(ctx context.Context, userID uuid.UUID) error {
	db := s.getQueryable(ctx)
	query := `UPDATE oauth_refresh_tokens
		 SET revoked_at = CURRENT_TIMESTAMP, revoked_reason = $2
		 WHERE id = (
			 SELECT id
			 FROM oauth_refresh_tokens
			 WHERE user_id = $1
			   AND revoked_at IS NULL
			   AND expires_at > CURRENT_TIMESTAMP
			 ORDER BY created_at ASC
			 LIMIT 1
		 )`
	_, err := db.ExecContext(ctx, query, userID, string(RevokedReasonSessionLimit))
	if err != nil {
		log.Ctx(ctx).Error().
			Err(err).
			Str("user_id", userID.String()).
			Msg("Database error revoking oldest session")
		return err
	}
	return nil
}

// GetByID retrieves a refresh token by its ID
func (s *PostgresRefreshTokenStore) GetByID(ctx context.Context, tokenID uuid.UUID) (*RefreshToken, error) {
	db := s.getQueryable(ctx)
	token := &RefreshToken{}
	query := `SELECT id, user_id, user_agent, ip_address, device_id, device_name, token_hash, rotated_from, expires_at, created_at, revoked_at, revoked_reason
		 FROM oauth_refresh_tokens
		 WHERE id = $1`
	err := db.QueryRowContext(ctx, query, tokenID).Scan(
		&token.ID,
		&token.UserID,
		&token.UserAgent,
		&token.IPAddress,
		&token.DeviceID,
		&token.DeviceName,
		&token.TokenHash,
		&token.RotatedFrom,
		&token.ExpiresAt,
		&token.CreatedAt,
		&token.RevokedAt,
		&token.RevokedReason,
	)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			log.Ctx(ctx).Error().
				Err(err).
				Str("token_id", tokenID.String()).
				Msg("Database error getting refresh token by ID")
		}
		return nil, err
	}
	return token, nil
}

// CountChildrenByParent counts how many tokens were rotated from a parent token
func (s *PostgresRefreshTokenStore) CountChildrenByParent(ctx context.Context, parentID uuid.UUID) (int, error) {
	db := s.getQueryable(ctx)
	var count int
	query := `SELECT COUNT(*) FROM oauth_refresh_tokens WHERE rotated_from = $1`
	err := db.QueryRowContext(ctx, query, parentID).Scan(&count)
	if err != nil {
		log.Ctx(ctx).Error().
			Err(err).
			Str("parent_id", parentID.String()).
			Msg("Database error counting children by parent")
		return 0, err
	}
	return count, nil
}

// GetActiveChildByParent returns the newest active child token rotated from parentID.
func (s *PostgresRefreshTokenStore) GetActiveChildByParent(ctx context.Context, parentID uuid.UUID) (*RefreshToken, error) {
	db := s.getQueryable(ctx)
	token := &RefreshToken{}
	query := `SELECT id, user_id, user_agent, ip_address, device_id, device_name, token_hash, rotated_from, expires_at, created_at, revoked_at, revoked_reason
		 FROM oauth_refresh_tokens
		 WHERE rotated_from = $1
		   AND revoked_at IS NULL
		   AND expires_at > CURRENT_TIMESTAMP
		 ORDER BY created_at DESC
		 LIMIT 1`
	err := db.QueryRowContext(ctx, query, parentID).Scan(
		&token.ID,
		&token.UserID,
		&token.UserAgent,
		&token.IPAddress,
		&token.DeviceID,
		&token.DeviceName,
		&token.TokenHash,
		&token.RotatedFrom,
		&token.ExpiresAt,
		&token.CreatedAt,
		&token.RevokedAt,
		&token.RevokedReason,
	)
	if err != nil {
		return nil, err
	}
	return token, nil
}

// GetActiveForwardLeaf walks the forward rotation chain and returns the newest active token.
func (s *PostgresRefreshTokenStore) GetActiveForwardLeaf(ctx context.Context, tokenID uuid.UUID) (*RefreshToken, error) {
	current, err := s.GetByID(ctx, tokenID)
	if err != nil {
		return nil, err
	}

	for {
		child, childErr := s.GetActiveChildByParent(ctx, current.ID)
		if errors.Is(childErr, sql.ErrNoRows) {
			if !current.RevokedAt.Valid && time.Now().Before(current.ExpiresAt) {
				return current, nil
			}
			return nil, sql.ErrNoRows
		}
		if childErr != nil {
			return nil, childErr
		}
		current = child
	}
}
