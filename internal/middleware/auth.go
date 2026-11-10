package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/nijatsdev/go-jwt-auth/internal/response"
	"github.com/nijatsdev/go-jwt-auth/internal/services"
	"github.com/nijatsdev/go-jwt-auth/internal/utils"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// Key type for context values
type contextKey string

const (
	ClaimsKey contextKey = "claims"
)

type AuthMiddleware struct {
	authService *services.AuthService
}

func NewAuthMiddleware(authService *services.AuthService) *AuthMiddleware {
	return &AuthMiddleware{
		authService: authService,
	}
}

// Authenticate checks JWT tokens and adds user info to the request context
func (am *AuthMiddleware) Authenticate(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		var tokenString string

		// Extract token from the Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)

			switch {
			case len(parts) == 2 && strings.EqualFold(parts[0], "Bearer"):
				tokenString = parts[1]
			default:
				response.WriteUnauthorizedError(w, r, "Invalid authorization header")
				return
			}
		}

		if tokenString == "" {
			response.WriteUnauthorizedError(w, r, "Missing access token")
			return
		}

		// Validate the token
		claims, err := am.authService.ValidateAccessToken(tokenString)
		if err != nil {
			if errors.Is(err, utils.ErrAccessTokenExpired) {
				response.WriteUnauthorizedError(w, r, "Access token has expired")
				return
			}
			response.WriteUnauthorizedError(w, r, "Invalid access token")
			return
		}

		ctx := r.Context()

		// Add claims to context
		ctx = context.WithValue(ctx, ClaimsKey, claims)

		// get user ID from ctx
		userID, ok := GetUserID(ctx)
		if !ok {
			response.WriteUnauthorizedError(w, r, "Invalid access token")
			return
		}

		sessionID, ok := GetSessionID(ctx)
		if !ok {
			response.WriteUnauthorizedError(w, r, "Invalid access token")
			return
		}

		if err := am.authService.EnsureAccessSessionActive(ctx, userID, sessionID); err != nil {
			if errors.Is(err, services.ErrSessionInactive) {
				response.WriteUnauthorizedError(w, r, "Access token has expired")
				return
			}
			response.WriteInternalServerError(w, r, "")
			return
		}

		// Add user ID to logger context
		zerolog.Ctx(ctx).UpdateContext(func(c zerolog.Context) zerolog.Context {
			return c.Str("user_id", userID.String())
		})

		next.ServeHTTP(w, r.WithContext(ctx))
	}

	return http.HandlerFunc(fn)
}

// GetUserID retrieves the user ID from the claims in the request context
func GetUserID(ctx context.Context) (uuid.UUID, bool) {
	claims, ok := GetClaims(ctx)
	if !ok {
		return uuid.Nil, false
	}
	userIDStr, ok := claims["sub"].(string)
	if !ok {
		return uuid.Nil, false
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil, false
	}
	return userID, true
}

// GetSessionID returns the refresh session id (sid) claim when present.
func GetSessionID(ctx context.Context) (uuid.UUID, bool) {
	claims, ok := GetClaims(ctx)
	if !ok {
		return uuid.Nil, false
	}
	sid, ok := claims["sid"].(string)
	if !ok {
		return uuid.Nil, false
	}
	id, err := uuid.Parse(sid)
	if err != nil {
		return uuid.Nil, false
	}
	return id, true
}

// GetClaims retrieves the claims from the request context
func GetClaims(ctx context.Context) (jwt.MapClaims, bool) {
	claims, ok := ctx.Value(ClaimsKey).(jwt.MapClaims)
	return claims, ok
}
