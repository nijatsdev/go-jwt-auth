package response

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog/hlog"
	"github.com/rs/zerolog/log"
)

// ErrorResponse represents the standard error response structure
type ErrorResponse struct {
	Status    string       `json:"status"`
	Message   string       `json:"message"`
	Code      string       `json:"code,omitempty"`
	Errors    []FieldError `json:"errors,omitempty"`
	Timestamp string       `json:"timestamp,omitempty"`
	Path      string       `json:"path,omitempty"`
	RequestID string       `json:"request_id,omitempty"`
}

// FieldError represents a single field validation error
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Tag     string `json:"tag,omitempty"`
}

// Envelope wraps response data for consistency
type Envelope map[string]any

// SuccessResponse represents a standard success response structure
type SuccessResponse struct {
	Status  string   `json:"status"`
	Message string   `json:"message,omitempty"`
	Data    Envelope `json:"data,omitempty"`
}

// PaginationMeta contains pagination information
type PaginationMeta struct {
	CurrentPage int `json:"current_page"`
	PerPage     int `json:"per_page"`
	TotalPages  int `json:"total_pages"`
	TotalItems  int `json:"total_items"`
}

// PaginatedResponse represents a paginated success response
type PaginatedResponse struct {
	Status     string         `json:"status"`
	Message    string         `json:"message,omitempty" example:"Data retrieved successfully"`
	Data       Envelope       `json:"data"`
	Pagination PaginationMeta `json:"pagination"`
}

// Error codes for common scenarios
const (
	ErrCodeValidation         = "VALIDATION_ERROR"
	ErrCodeNotFound           = "NOT_FOUND"
	ErrCodeUnauthorized       = "UNAUTHORIZED"
	ErrCodeForbidden          = "FORBIDDEN"
	ErrCodeBadRequest         = "BAD_REQUEST"
	ErrCodeInternalServer     = "INTERNAL_SERVER_ERROR"
	ErrCodeConflict           = "CONFLICT"
	ErrCodeMethodNotAllowed   = "METHOD_NOT_ALLOWED"
	ErrCodeTooManyRequests    = "TOO_MANY_REQUESTS"
	ErrCodeServiceUnavailable = "SERVICE_UNAVAILABLE"
)

// WriteJSON writes a JSON response with the given status code
func WriteJSON(w http.ResponseWriter, r *http.Request, statusCode int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Ctx(r.Context()).Error().Err(err).Msg("Failed to write JSON response")
	}
}

// WriteSuccess writes a JSON success response
func WriteSuccess(w http.ResponseWriter, r *http.Request, statusCode int, message string, data Envelope) {
	response := SuccessResponse{
		Status:  "success",
		Message: message,
		Data:    data,
	}
	WriteJSON(w, r, statusCode, response)
}

// WritePaginated writes a paginated JSON success response
func WritePaginated(w http.ResponseWriter, r *http.Request, statusCode int, message string, data Envelope, pagination PaginationMeta) {
	response := PaginatedResponse{
		Status:     "success",
		Message:    message,
		Data:       data,
		Pagination: pagination,
	}
	WriteJSON(w, r, statusCode, response)
}

// WriteError writes a JSON error response
func WriteError(w http.ResponseWriter, r *http.Request, message string, statusCode int) {
	WriteErrorWithCode(w, r, message, statusCode, "")
}

// getReqID extracts the request ID from the request context
func getReqID(r *http.Request) (string, bool) {
	if r == nil {
		return "", false
	}
	id, ok := hlog.IDFromRequest(r)
	if !ok {
		return "", false
	}
	return id.String(), true
}

// WriteErrorWithCode writes a JSON error response with a specific error code
func WriteErrorWithCode(w http.ResponseWriter, r *http.Request, message string, statusCode int, code string) {
	// Determine status string based on HTTP status code
	// "fail" for 4xx (client errors), "error" for 5xx (server errors)
	status := "error"
	if statusCode >= 400 && statusCode < 500 {
		status = "fail"
	}

	// Set default error codes if not provided
	if code == "" {
		code = getDefaultErrorCode(statusCode)
	}

	// Get a request path and ID if the request is provided
	path := ""
	requestID := ""
	if r != nil {
		path = r.URL.Path
		requestID, _ = getReqID(r)
	}

	if message == "" {
		message = http.StatusText(statusCode)
	}

	response := ErrorResponse{
		Status:    status,
		Message:   message,
		Code:      code,
		Path:      path,
		RequestID: requestID,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	WriteJSON(w, r, statusCode, response)
}

// WriteNotFoundError writes a 404 not found error
func WriteNotFoundError(w http.ResponseWriter, r *http.Request, message string) {
	if message == "" {
		message = "Resource not found"
	}
	WriteErrorWithCode(w, r, message, http.StatusNotFound, ErrCodeNotFound)
}

// WriteBadRequestError writes a 400 bad request error
func WriteBadRequestError(w http.ResponseWriter, r *http.Request, message string) {
	if message == "" {
		message = "Bad request"
	}
	WriteErrorWithCode(w, r, message, http.StatusBadRequest, ErrCodeBadRequest)
}

// WriteConflictError writes a 409 conflict error
func WriteConflictError(w http.ResponseWriter, r *http.Request, message string) {
	if message == "" {
		message = "Resource conflict"
	}
	WriteErrorWithCode(w, r, message, http.StatusConflict, ErrCodeConflict)
}

// WriteInternalServerError writes a 500 internal server error
func WriteInternalServerError(w http.ResponseWriter, r *http.Request, message string) {
	if message == "" {
		message = "An error occurred. Please try again later."
	}
	WriteErrorWithCode(w, r, message, http.StatusInternalServerError, ErrCodeInternalServer)
}

// WriteUnauthorizedError writes a 401 unauthorized error
func WriteUnauthorizedError(w http.ResponseWriter, r *http.Request, message string) {
	if message == "" {
		message = "Authentication required"
	}
	WriteErrorWithCode(w, r, message, http.StatusUnauthorized, ErrCodeUnauthorized)
}

// WriteForbiddenError writes a 403 forbidden error
func WriteForbiddenError(w http.ResponseWriter, r *http.Request, message string) {
	if message == "" {
		message = "Access forbidden"
	}
	WriteErrorWithCode(w, r, message, http.StatusForbidden, ErrCodeForbidden)
}

// WriteTooManyRequestsError writes a 429 too many requests error
func WriteTooManyRequestsError(w http.ResponseWriter, r *http.Request, message string) {
	if message == "" {
		message = "Too many requests. Please try again later."
	}
	WriteErrorWithCode(w, r, message, http.StatusTooManyRequests, ErrCodeTooManyRequests)
}

// HandleValidationErrors handles validation errors from go-playground/validator
func HandleValidationErrors(w http.ResponseWriter, r *http.Request, err error) {
	var fieldErrors []FieldError

	var validationErrs validator.ValidationErrors
	ok := errors.As(err, &validationErrs)
	if !ok {
		WriteBadRequestError(w, r, "Invalid request data")
		return
	}

	for _, err := range validationErrs {
		field := toSnakeCase(err.Field())
		message := getValidationMessage(err)

		fieldErrors = append(fieldErrors, FieldError{
			Field:   field,
			Message: message,
			Tag:     err.Tag(),
		})
	}

	// Get a request path and ID if the request is provided
	path := ""
	requestID := ""
	if r != nil {
		path = r.URL.Path
		requestID, _ = getReqID(r)
	}

	response := ErrorResponse{
		Status:    "fail",
		Message:   "Validation failed",
		Code:      ErrCodeValidation,
		Errors:    fieldErrors,
		Path:      path,
		RequestID: requestID,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	WriteJSON(w, r, http.StatusUnprocessableEntity, response)
}

// getValidationMessage returns a human-readable validation message
func getValidationMessage(err validator.FieldError) string {
	field := toSnakeCase(err.Field())

	switch err.Tag() {
	case "required":
		return field + " is required"
	case "required_if":
		return field + " is required"
	case "required_unless":
		return field + " is required"
	case "required_with":
		return field + " is required"
	case "required_without":
		return field + " is required"
	case "email":
		return "invalid email format"
	case "min":
		return fmt.Sprintf("%s must be at least %s characters long", field, err.Param())
	case "max":
		return fmt.Sprintf("%s must be at most %s characters long", field, err.Param())
	case "len":
		return fmt.Sprintf("%s must be exactly %s characters long", field, err.Param())
	case "numeric":
		return field + " must be numeric"
	case "alpha":
		return field + " must contain only letters"
	case "alphanum":
		return field + " must contain only letters and numbers"
	case "url":
		return "invalid URL format"
	case "uri":
		return "invalid URI format"
	case "uuid":
		return "invalid UUID format"
	case "uuid4":
		return "invalid UUID v4 format"
	case "e164":
		return "invalid phone number format"
	case "gte":
		return fmt.Sprintf("%s must be greater than or equal to %s", field, err.Param())
	case "gt":
		return fmt.Sprintf("%s must be greater than %s", field, err.Param())
	case "lte":
		return fmt.Sprintf("%s must be less than or equal to %s", field, err.Param())
	case "lt":
		return fmt.Sprintf("%s must be less than %s", field, err.Param())
	case "oneof":
		return fmt.Sprintf("%s must be one of: %s", field, err.Param())
	case "datetime":
		return fmt.Sprintf("%s must be a valid datetime in format %s", field, err.Param())
	default:
		return field + " is invalid"
	}
}

// toSnakeCase converts a string to snake_case
func toSnakeCase(s string) string {
	var result strings.Builder
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			result.WriteRune('_')
		}
		result.WriteRune(r)
	}
	return strings.ToLower(result.String())
}

// getDefaultErrorCode returns a default error code based on the HTTP status code
func getDefaultErrorCode(statusCode int) string {
	switch statusCode {
	case http.StatusBadRequest:
		return ErrCodeBadRequest
	case http.StatusUnauthorized:
		return ErrCodeUnauthorized
	case http.StatusForbidden:
		return ErrCodeForbidden
	case http.StatusNotFound:
		return ErrCodeNotFound
	case http.StatusConflict:
		return ErrCodeConflict
	case http.StatusUnprocessableEntity:
		return ErrCodeValidation
	case http.StatusTooManyRequests:
		return ErrCodeTooManyRequests
	case http.StatusInternalServerError:
		return ErrCodeInternalServer
	case http.StatusServiceUnavailable:
		return ErrCodeServiceUnavailable
	case http.StatusMethodNotAllowed:
		return ErrCodeMethodNotAllowed
	default:
		return "UNKNOWN_ERROR"
	}
}
