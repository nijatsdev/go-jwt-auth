package handlers

import (
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

	userID := middleware.GetUserID(ctx)

	user, err := h.store.GetByID(ctx, userID)
	if err != nil {
		response.WriteInternalServerError(w, r, "")
		return
	}

	response.WriteSuccess(w, r, http.StatusOK, "", response.Envelope{"user": user})
}
