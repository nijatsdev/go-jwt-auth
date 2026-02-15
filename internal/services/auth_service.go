package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/nijatsdev/go-jwt-auth/internal/database"
	"github.com/nijatsdev/go-jwt-auth/internal/store"
	"github.com/nijatsdev/go-jwt-auth/internal/utils"
	"github.com/rs/zerolog/log"
)

// AuthService handles authentication operations including login, logout,
// registration, token refresh, and session management.
type AuthService struct {
	userStore                     store.UserStore
	refreshTokenStore             store.RefreshTokenStore
	txManager                     database.TransactionManager
	validate                      *validator.Validate
	accessTokenTTL                time.Duration
	refreshTokenTTL               time.Duration
	jwtSecret                     []byte
	maxActiveRefreshTokensPerUser int
	gracePeriod                   time.Duration
	maxGracePeriodReuses          int
}

// NewAuthService creates a new AuthService with the given dependencies.
func NewAuthService(
	txManager database.TransactionManager,
	userStore store.UserStore,
	refreshTokenStore store.RefreshTokenStore,
	accessTokenTTL,
	refreshTokenTTL time.Duration,
	jwtSecret string,
	maxActiveRefreshTokensPerUser int) *AuthService {
	return &AuthService{
		userStore:                     userStore,
		refreshTokenStore:             refreshTokenStore,
		txManager:                     txManager,
		validate:                      validator.New(),
		accessTokenTTL:                accessTokenTTL,
		refreshTokenTTL:               refreshTokenTTL,
		jwtSecret:                     []byte(jwtSecret),
		maxActiveRefreshTokensPerUser: maxActiveRefreshTokensPerUser,
		gracePeriod:                   3 * time.Second, // Grace period for concurrent refresh requests
		maxGracePeriodReuses:          3,               // Max reuses during grace period (1 normal + 2 retry)
	}
}

// Authentication errors.
var (
	ErrInvalidCredentials   = errors.New("invalid credentials")
	ErrEmailExists          = errors.New("email already exists")
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
	ErrRefreshTokenRevoked  = errors.New("refresh token has been revoked")
	ErrRefreshTokenExpired  = errors.New("refresh token has expired")
	ErrSessionNotFound      = errors.New("session not found")
	ErrUnauthorizedSession  = errors.New("unauthorized to revoke this session")
)

// LoginResult contains the result of a successful login.
type LoginResult struct {
	AccessToken  string
	RefreshToken string
	User         *store.User
	ExpiresAt    time.Time
}

type RefreshResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// Login authenticates a user and returns a LoginResult
func (s *AuthService) Login(r *http.Request, email, password string) (*LoginResult, error) {
	ctx := r.Context()
	userAgent := r.UserAgent()
	ipAddress := r.RemoteAddr
	acceptLanguage := r.Header.Get("Accept-Language")
	acceptEncoding := r.Header.Get("Accept-Encoding")

	log.Ctx(ctx).Info().Str("email", email).Msg("Login attempt")

	// Get user by email
	user, err := s.userStore.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Ctx(ctx).Warn().Str("email", email).Msg("Login failed: user not found")
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	// Compare password hash
	matches, err := user.PasswordHash.Matches(password)
	if err != nil {
		return nil, err
	}
	if !matches {
		log.Ctx(ctx).Warn().Str("email", email).Msg("Login failed: invalid password")
		return nil, ErrInvalidCredentials
	}

	// Generate device fingerprint
	deviceID, err := utils.GenerateDeviceFingerprint(userAgent, ipAddress, acceptLanguage, acceptEncoding)
	if err != nil {
		return nil, err
	}
	deviceName := utils.ParseDeviceName(userAgent)

	var result *LoginResult

	err = s.txManager.WithTransaction(ctx, func(txCtx context.Context) error {
		// Check for existing token on this device
		existingToken, err := s.refreshTokenStore.GetActiveByUserAndDevice(txCtx, user.ID, deviceID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}

		if existingToken != nil {
			// Revoke old token on same device
			if err := s.revokeToken(txCtx, existingToken.ID, store.RevokedReasonDeviceReLogin); err != nil {
				return err
			}
			log.Ctx(txCtx).Debug().
				Str("old_token_id", existingToken.ID.String()).
				Msg("Revoked old token due to device relogin")
		} else {
			// Check session limit
			sessionCount, err := s.refreshTokenStore.CountActiveSessionsByUser(txCtx, user.ID)
			if err != nil {
				return err
			}
			if sessionCount >= s.maxActiveRefreshTokensPerUser {
				if err := s.refreshTokenStore.RevokeOldestActiveToken(txCtx, user.ID); err != nil {
					return err
				}
				log.Ctx(txCtx).Debug().
					Int("limit", s.maxActiveRefreshTokensPerUser).
					Msg("Revoked oldest session due to limit")
			}
		}

		// Generate tokens
		accessToken, refreshToken, expiresAt, err := s.generateTokens(txCtx, user, userAgent, ipAddress, deviceID, deviceName, uuid.NullUUID{})
		if err != nil {
			return err
		}

		result = &LoginResult{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			User:         user,
			ExpiresAt:    expiresAt,
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	log.Ctx(ctx).Info().
		Str("user_id", user.ID.String()).
		Str("device_id", deviceID).
		Msg("Login successful")

	return result, nil
}

// Logout revokes the current refresh token session.
func (s *AuthService) Logout(ctx context.Context, refreshTokenID uuid.UUID) error {
	if err := s.revokeToken(ctx, refreshTokenID, store.RevokedReasonUserLogout); err != nil {
		return fmt.Errorf("revoking token: %w", err)
	}

	log.Ctx(ctx).Info().
		Str("token_id", refreshTokenID.String()).
		Msg("Logout successful")

	return nil
}

// Register creates a new user account
func (s *AuthService) Register(ctx context.Context, name, email, password string) (*store.User, error) {
	log.Ctx(ctx).Info().Str("email", email).Msg("Registration attempt")

	// Check if email already exists
	exists, err := s.userStore.CheckExistsByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if exists {
		log.Ctx(ctx).Warn().Str("email", email).Msg("Registration failed: email already exists")
		return nil, ErrEmailExists
	}

	// Create a new user and hash password
	user := &store.User{
		Name:  name,
		Email: email,
	}
	if err := user.PasswordHash.Set(password); err != nil {
		log.Ctx(ctx).Error().
			Err(err).
			Str("email", email).
			Msg("Error hashing password")
		return nil, err
	}

	// Save user to a database
	if err := s.userStore.Create(ctx, user); err != nil {
		return nil, err
	}

	log.Ctx(ctx).Info().
		Str("user_id", user.ID.String()).
		Str("email", email).
		Msg("User registered successfully")

	return user, nil
}

// Refresh generates new access and refresh tokens using a valid refresh token
func (s *AuthService) Refresh(r *http.Request, refreshToken string) (*RefreshResult, error) {
	ctx := r.Context()
	userAgent := r.UserAgent()
	ipAddress := r.RemoteAddr
	acceptLanguage := r.Header.Get("Accept-Language")
	acceptEncoding := r.Header.Get("Accept-Encoding")

	log.Ctx(ctx).Info().Msg("Token refresh attempt")

	hashedToken := utils.HashToken(refreshToken)

	// Generate device fingerprint upfront
	currentDeviceID, err := utils.GenerateDeviceFingerprint(userAgent, ipAddress, acceptLanguage, acceptEncoding)
	if err != nil {
		return nil, err
	}

	var result *RefreshResult

	err = s.txManager.WithTransaction(ctx, func(txCtx context.Context) error {
		// Fetch and lock the refresh token
		token, err := s.refreshTokenStore.GetByTokenHashForUpdate(txCtx, hashedToken)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				log.Ctx(txCtx).Warn().Msg("Token refresh failed: token not found")
				return ErrRefreshTokenNotFound
			}
			return err
		}

		// Check if token expired
		if time.Now().After(token.ExpiresAt) {
			log.Ctx(txCtx).Warn().Str("token_id", token.ID.String()).Msg("Token refresh failed: expired")
			return ErrRefreshTokenExpired
		}

		// Device fingerprint mismatch detection
		if currentDeviceID != token.DeviceID {
			// Already flagged for device mismatch - no need to revoke again
			if token.RevokedReason.Valid && token.RevokedReason.String == string(store.RevokedReasonDeviceMismatch) {
				log.Ctx(txCtx).Warn().Str("token_id", token.ID.String()).Msg("Device mismatch: already flagged")
				return ErrRefreshTokenRevoked
			}

			// Revoke token and chain for security
			if err := s.revokeToken(txCtx, token.ID, store.RevokedReasonDeviceMismatch); err != nil {
				return err
			}
			if _, err := s.revokeRotationChain(txCtx, token.ID, store.RevokedReasonDeviceMismatch); err != nil {
				return err
			}
			log.Ctx(txCtx).Warn().Str("token_id", token.ID.String()).Msg("Device mismatch: revoked token chain")
			// CommitError: persist revocations but return error to user
			return database.NewCommitError(ErrRefreshTokenRevoked)
		}

		// Reuse detection
		isRotated, err := s.refreshTokenStore.CheckRotated(txCtx, token.ID)
		if err != nil {
			return err
		}

		// Grace period check
		isGracefulReuse := false
		if token.RevokedAt.Valid && token.RevokedReason.Valid &&
			token.RevokedReason.String == string(store.RevokedReasonTokenRotation) &&
			time.Now().Before(token.RevokedAt.Time.Add(s.gracePeriod)) {
			// Check grace period reuse limit
			childCount, err := s.refreshTokenStore.CountChildrenByParent(txCtx, token.ID)
			if err != nil {
				return err
			}
			if childCount == s.maxGracePeriodReuses {
				// Grace period abuse detected - too many reuses
				if err := s.revokeToken(txCtx, token.ID, store.RevokedReasonGracePeriodAbuse); err != nil {
					return err
				}
				if _, err := s.revokeRotationChain(txCtx, token.ID, store.RevokedReasonGracePeriodAbuse); err != nil {
					return err
				}
				log.Ctx(txCtx).Warn().
					Str("token_id", token.ID.String()).
					Msg("Grace period abuse: too many reuses, revoked token chain")
				// CommitError: persist revocations but return error to user
				return database.NewCommitError(ErrRefreshTokenRevoked)
			}
			log.Ctx(txCtx).Debug().Str("token_id", token.ID.String()).Msg("Token reused within grace period")
			isGracefulReuse = true
		}

		// Handle replay detection
		if isRotated && !isGracefulReuse {
			// Already flagged for replay - no need to revoke again
			if token.RevokedReason.Valid && token.RevokedReason.String == string(store.RevokedReasonReplayDetected) {
				log.Ctx(txCtx).Warn().Str("token_id", token.ID.String()).Msg("Replay detected: already flagged")
				return ErrRefreshTokenRevoked
			}

			// Revoke token and chain for security
			if err := s.revokeToken(txCtx, token.ID, store.RevokedReasonReplayDetected); err != nil {
				return err
			}
			if _, err := s.revokeRotationChain(txCtx, token.ID, store.RevokedReasonReplayDetected); err != nil {
				return err
			}
			log.Ctx(txCtx).Warn().Str("token_id", token.ID.String()).Msg("Replay detected: revoked token chain")
			// CommitError: persist revocations but return error to user
			return database.NewCommitError(ErrRefreshTokenRevoked)
		}

		// Check if token is revoked (unless graceful reuse)
		if token.RevokedAt.Valid && !isGracefulReuse {
			log.Ctx(txCtx).Warn().
				Str("token_id", token.ID.String()).
				Str("reason", token.RevokedReason.String).
				Msg("Token refresh failed: revoked")
			return ErrRefreshTokenRevoked
		}

		// Fetch user
		user, err := s.userStore.GetByID(txCtx, token.UserID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return errors.New("user not found")
			}
			return err
		}

		// Normal rotation: mark old token as rotated
		if !isRotated {
			if err := s.revokeToken(txCtx, token.ID, store.RevokedReasonTokenRotation); err != nil {
				return err
			}
		}

		// Preserve device info
		deviceName := ""
		if token.DeviceName.Valid {
			deviceName = token.DeviceName.String
		}

		// Generate new tokens
		newAccessToken, newRefreshToken, expiresAt, err := s.generateTokens(txCtx, user, userAgent, ipAddress, token.DeviceID, deviceName, uuid.NullUUID{UUID: token.ID, Valid: true})
		if err != nil {
			return err
		}

		log.Ctx(txCtx).Info().
			Str("user_id", user.ID.String()).
			Str("old_token_id", token.ID.String()).
			Msg("Token refresh successful")

		result = &RefreshResult{
			AccessToken:  newAccessToken,
			RefreshToken: newRefreshToken,
			ExpiresAt:    expiresAt,
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return result, nil
}

// ListSessions retrieves active refresh token sessions for a user
func (s *AuthService) ListSessions(ctx context.Context, userID uuid.UUID, refreshTokenID string) ([]*store.RefreshTokenResponse, error) {
	sessions, err := s.refreshTokenStore.ListByUserID(ctx, userID, refreshTokenID)
	if err != nil {
		return nil, err
	}

	// Deduplicate sessions by DeviceID
	uniqueSessions := make([]*store.RefreshTokenResponse, 0)
	seenDevices := make(map[string]bool)

	for _, session := range sessions {
		if !seenDevices[session.DeviceID] {
			uniqueSessions = append(uniqueSessions, session)
			seenDevices[session.DeviceID] = true
		}
	}

	return uniqueSessions, nil
}

// RevokeSession revokes a specific refresh token session for a user
func (s *AuthService) RevokeSession(ctx context.Context, userID uuid.UUID, sessionID string) error {
	// Parse session ID
	sessionUUID, err := uuid.Parse(sessionID)
	if err != nil {
		return ErrSessionNotFound
	}

	// Get the refresh token
	token, err := s.refreshTokenStore.GetByID(ctx, sessionUUID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrSessionNotFound
		}
		return err
	}

	// Check if token belongs to the user
	if token.UserID != userID {
		return ErrUnauthorizedSession
	}

	// Check if already revoked
	if token.RevokedAt.Valid {
		return ErrSessionNotFound
	}

	// Revoke the token (remote revoke — user is ending another device's session)
	if err := s.revokeToken(ctx, sessionUUID, store.RevokedReasonRemoteRevoke); err != nil {
		return err
	}

	log.Ctx(ctx).Info().
		Str("user_id", userID.String()).
		Str("session_id", sessionID).
		Msg("Session revoked successfully")

	return nil
}

// generateTokens creates both access and refresh tokens with device info
func (s *AuthService) generateTokens(ctx context.Context, user *store.User, userAgent, ipAddress, deviceID, deviceName string, oldTokenID uuid.NullUUID) (accessToken, refreshToken string, expirationTime time.Time, err error) {
	refreshToken, refreshTokenId, err := s.generateRefreshToken(ctx, user, userAgent, ipAddress, deviceID, deviceName, oldTokenID)
	if err != nil {
		return "", "", time.Time{}, err
	}

	accessToken, expirationTime, err = utils.GenerateAccessToken(user.ID, user.Name, user.Email, refreshTokenId, s.accessTokenTTL, s.jwtSecret)
	if err != nil {
		log.Ctx(ctx).Error().
			Err(err).
			Str("user_id", user.ID.String()).
			Msg("Error generating access token")
		return "", "", time.Time{}, err
	}

	return accessToken, refreshToken, expirationTime, nil
}

// generateRefreshToken creates and stores a new refresh token with device info
func (s *AuthService) generateRefreshToken(ctx context.Context, user *store.User, userAgent, ipAddress, deviceID, deviceName string, oldTokenID uuid.NullUUID) (string, uuid.UUID, error) {
	host, _, err := net.SplitHostPort(ipAddress)
	if err != nil {
		log.Ctx(ctx).Error().
			Err(err).
			Str("remote_addr", ipAddress).
			Msg("Error parsing IP address from remote addr")
		return "", uuid.Nil, err
	}

	rawToken, hashedToken, err := utils.GenerateRawAndHashedTokens()
	if err != nil {
		log.Ctx(ctx).Error().
			Err(err).
			Str("user_id", user.ID.String()).
			Msg("Error generating raw and hashed refresh tokens")
		return "", uuid.Nil, err
	}

	token := &store.RefreshToken{
		UserID:      user.ID,
		TokenHash:   hashedToken,
		UserAgent:   userAgent,
		IPAddress:   host,
		DeviceID:    deviceID,
		DeviceName:  sql.NullString{String: deviceName, Valid: deviceName != "" && deviceName != "Unknown"},
		RotatedFrom: oldTokenID,
		ExpiresAt:   time.Now().Add(s.refreshTokenTTL),
	}

	id, err := s.refreshTokenStore.Create(ctx, token)
	if err != nil {
		return "", uuid.Nil, err
	}

	return rawToken, id, nil
}

// revokeToken revokes a refresh token in the database
func (s *AuthService) revokeToken(ctx context.Context, tokenID uuid.UUID, reason store.RevokedReason) error {
	return s.refreshTokenStore.Revoke(ctx, tokenID, reason)
}

// revokeRotationChain revokes a rotation chain of refresh tokens
func (s *AuthService) revokeRotationChain(ctx context.Context, tokenID uuid.UUID, reason store.RevokedReason) (int, error) {
	revokedTokens, err := s.refreshTokenStore.RevokeRotationChain(ctx, tokenID, reason)
	if err != nil {
		return 0, err
	}
	return len(revokedTokens), nil
}

// ValidateInput validates the input using struct tags
func (s *AuthService) ValidateInput(data any) error {
	return s.validate.Struct(data)
}

// ValidateAccessToken verifies a JWT token and returns the claims
func (s *AuthService) ValidateAccessToken(tokenString string) (jwt.MapClaims, error) {
	return utils.ValidateAccessToken(tokenString, s.jwtSecret)
}
