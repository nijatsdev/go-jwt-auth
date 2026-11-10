package handlers

import (
	"database/sql"
	"errors"
	"net/http"

	"github.com/nijatsdev/go-jwt-auth/internal/middleware"
	"github.com/nijatsdev/go-jwt-auth/internal/response"
	"github.com/nijatsdev/go-jwt-auth/internal/store"
)

type UserHandler struct {
	store store.UserStore
}

func NewUserHandler(store store.UserStore) *UserHandler {
	return &UserHandler{
		store: store,
	}
}

func (h *UserHandler) HandleGetProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, ok := middleware.GetUserID(ctx)
	if !ok {
		response.WriteUnauthorizedError(w, r, "Invalid access token")
		return
	}

	user, err := h.store.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			response.WriteUnauthorizedError(w, r, "Invalid access token")
			return
		}
		response.WriteInternalServerError(w, r, "")
		return
	}

	response.WriteSuccess(w, r, http.StatusOK, "", response.Envelope{"user": user})
}
