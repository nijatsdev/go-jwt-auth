package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/nijatsdev/go-jwt-auth/internal/middleware"
	"github.com/nijatsdev/go-jwt-auth/internal/response"
	"github.com/nijatsdev/go-jwt-auth/internal/services"

	"github.com/go-chi/chi/v5"
)

type AuthHandler struct {
	authService *services.AuthService
}

func NewAuthHandler(authService *services.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
	}
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email,max=255"`
	Password string `json:"password" validate:"required,min=8,max=255"`
}

type RegisterRequest struct {
	Name     string `json:"name" validate:"required,min=3,max=100"`
	Email    string `json:"email" validate:"required,email,max=255"`
	Password string `json:"password" validate:"required,min=8,max=255"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

func (h *AuthHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.WriteBadRequestError(w, r, "Invalid request payload")
		return
	}

	if err := h.authService.ValidateInput(&req); err != nil {
		response.HandleValidationErrors(w, r, err)
		return
	}

	result, err := h.authService.Login(r, req.Email, req.Password)
	if err != nil {
		if errors.Is(err, services.ErrInvalidCredentials) {
			response.WriteUnauthorizedError(w, r, "Invalid credentials")
			return
		}
		response.WriteInternalServerError(w, r, "")
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	response.WriteSuccess(w, r, http.StatusOK, "Login successful", response.Envelope{
		"user":          result.User,
		"access_token":  result.AccessToken,
		"refresh_token": result.RefreshToken,
		"expires_at":    result.ExpiresAt,
	})
}

func (h *AuthHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	refreshTokenID, ok := middleware.GetSessionID(ctx)
	if !ok {
		response.WriteUnauthorizedError(w, r, "Invalid access token")
		return
	}

	err := h.authService.Logout(ctx, refreshTokenID)
	if err != nil {
		response.WriteInternalServerError(w, r, "")
		return
	}

	response.WriteSuccess(w, r, http.StatusOK, "Logout successful", nil)
}

func (h *AuthHandler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.WriteBadRequestError(w, r, "Invalid request payload")
		return
	}

	if err := h.authService.ValidateInput(&req); err != nil {
		response.HandleValidationErrors(w, r, err)
		return
	}

	user, err := h.authService.Register(ctx, req.Name, req.Email, req.Password)
	if err != nil {
		if errors.Is(err, services.ErrEmailExists) {
			response.WriteConflictError(w, r, "Email already exists")
			return
		}
		response.WriteInternalServerError(w, r, "")
		return
	}

	response.WriteSuccess(w, r, http.StatusCreated, "User registered successfully", response.Envelope{"user": user})
}

func (h *AuthHandler) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	var req RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.WriteBadRequestError(w, r, "Invalid request payload")
		return
	}

	if err := h.authService.ValidateInput(&req); err != nil {
		response.HandleValidationErrors(w, r, err)
		return
	}

	result, err := h.authService.Refresh(r, req.RefreshToken)
	if err != nil {
		if errors.Is(err, services.ErrRefreshTokenNotFound) ||
			errors.Is(err, services.ErrRefreshTokenExpired) ||
			errors.Is(err, services.ErrRefreshTokenRevoked) {
			response.WriteUnauthorizedError(w, r, "Invalid or expired refresh token")
			return
		}
		if errors.Is(err, services.ErrUserDeleted) {
			response.WriteUnauthorizedError(w, r, "Invalid or expired refresh token")
			return
		}
		response.WriteInternalServerError(w, r, "")
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	response.WriteSuccess(w, r, http.StatusOK, "Token refresh successful", response.Envelope{
		"access_token":  result.AccessToken,
		"refresh_token": result.RefreshToken,
		"expires_at":    result.ExpiresAt,
	})
}

func (h *AuthHandler) HandleListSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, ok := middleware.GetUserID(ctx)
	if !ok {
		response.WriteUnauthorizedError(w, r, "Invalid access token")
		return
	}

	claims, ok := middleware.GetClaims(ctx)
	if !ok {
		response.WriteUnauthorizedError(w, r, "Invalid access token")
		return
	}
	refreshTokenID, ok := claims["sid"].(string)
	if !ok {
		response.WriteUnauthorizedError(w, r, "Invalid access token")
		return
	}

	sessions, err := h.authService.ListSessions(ctx, userID, refreshTokenID)
	if err != nil {
		response.WriteInternalServerError(w, r, "")
		return
	}

	response.WriteSuccess(w, r, http.StatusOK, "Sessions retrieved successfully", response.Envelope{
		"sessions": sessions,
	})
}

func (h *AuthHandler) HandleRevokeSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, ok := middleware.GetUserID(ctx)
	if !ok {
		response.WriteUnauthorizedError(w, r, "Invalid access token")
		return
	}

	sessionID := chi.URLParamFromCtx(ctx, "session_id")
	if sessionID == "" {
		response.WriteBadRequestError(w, r, "Session ID is required")
		return
	}

	err := h.authService.RevokeSession(ctx, userID, sessionID)
	if err != nil {
		if errors.Is(err, services.ErrSessionNotFound) {
			response.WriteNotFoundError(w, r, "Session not found")
			return
		}
		response.WriteInternalServerError(w, r, "")
		return
	}

	response.WriteSuccess(w, r, http.StatusOK, "Session revoked successfully", response.Envelope{
		"session_id": sessionID,
		"user_id":    userID,
	})
}
