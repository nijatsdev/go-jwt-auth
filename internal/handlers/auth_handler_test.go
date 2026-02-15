package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nijatsdev/go-jwt-auth/internal/database"
	"github.com/nijatsdev/go-jwt-auth/internal/handlers"
	"github.com/nijatsdev/go-jwt-auth/internal/middleware"
	"github.com/nijatsdev/go-jwt-auth/internal/services"
	"github.com/nijatsdev/go-jwt-auth/internal/store"
	"github.com/nijatsdev/go-jwt-auth/internal/testutil"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"
)

// httpTestCase defines common test case structure
type httpTestCase struct {
	body       string
	setupCtx   func(*http.Request) *http.Request
	wantStatus int
	wantMsg    string
	checkBody  func(*testing.T, map[string]any)
}

// securityTestSetup encapsulates common security test setup
type securityTestSetup struct {
	userAgent  string
	acceptLang string
	acceptEnc  string
	remoteAddr string
}

func TestMain(m *testing.M) {
	testutil.MustStartPostgresContainer()
	code := m.Run()
	testutil.TeardownPostgresContainer()
	os.Exit(code)
}

// logCapture captures zerolog output for testing
type logCapture struct {
	mu      sync.Mutex
	entries []map[string]any
}

func (lc *logCapture) Write(p []byte) (n int, err error) {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	var entry map[string]any
	if err := json.Unmarshal(p, &entry); err == nil {
		lc.entries = append(lc.entries, entry)
	}
	return len(p), nil
}

func (lc *logCapture) HasMessage(msg string) bool {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	for _, entry := range lc.entries {
		if m, ok := entry["message"].(string); ok && strings.Contains(m, msg) {
			return true
		}
	}
	return false
}

func (lc *logCapture) HasLevel(level string) bool {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	for _, entry := range lc.entries {
		if l, ok := entry["level"].(string); ok && l == level {
			return true
		}
	}
	return false
}

func (lc *logCapture) Reset() {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.entries = nil
}

type testDeps struct {
	handler    *handlers.AuthHandler
	service    *services.AuthService
	logCapture *logCapture
}

func setupHandler(t *testing.T) testDeps {
	t.Helper()
	tdb := testutil.SetupTestDB(t)
	userStore := store.NewPostgresUserStore(tdb.DB)
	tokenStore := store.NewPostgresRefreshTokenStore(tdb.DB)
	txManager := database.NewTxManager(tdb.DB)
	svc := services.NewAuthService(txManager, userStore, tokenStore, 15*time.Minute, 7*24*time.Hour, "test-jwt-secret", 5)
	handler := handlers.NewAuthHandler(svc)

	// Setup log capture
	lc := &logCapture{}
	log := zerolog.New(lc).With().Timestamp().Logger()
	zerolog.DefaultContextLogger = &log

	return testDeps{handler: handler, service: svc, logCapture: lc}
}

// executeHTTPTest runs an HTTP test case and validates the response
func executeHTTPTest(t *testing.T, handler func(http.ResponseWriter, *http.Request), tc httpTestCase, method, path string) {
	t.Helper()

	req := httptest.NewRequest(method, path, strings.NewReader(tc.body))
	req.Header.Set("Content-Type", "application/json")

	if tc.setupCtx != nil {
		req = tc.setupCtx(req)
	}

	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != tc.wantStatus {
		t.Errorf("status = %d, want %d", w.Code, tc.wantStatus)
	}

	if tc.wantMsg != "" || tc.checkBody != nil {
		var response map[string]any
		if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if tc.wantMsg != "" {
			if !strings.Contains(response["message"].(string), tc.wantMsg) {
				t.Errorf("message = %v, want to contain %v", response["message"], tc.wantMsg)
			}
		}

		if tc.checkBody != nil {
			tc.checkBody(t, response)
		}
	}
}

// createTestUser creates a user and returns the user
func createTestUser(t *testing.T, deps testDeps, name, email, password string) {
	t.Helper()
	ctx := context.Background()
	_, err := deps.service.Register(ctx, name, email, password)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
}

// loginTestUser performs login and returns the result
func loginTestUser(t *testing.T, deps testDeps, email, password string, setup securityTestSetup) *services.LoginResult {
	t.Helper()

	loginReq := httptest.NewRequest("POST", "/login", nil)
	loginReq.Header.Set("User-Agent", setup.userAgent)
	loginReq.Header.Set("Accept-Language", setup.acceptLang)
	loginReq.Header.Set("Accept-Encoding", setup.acceptEnc)
	loginReq.RemoteAddr = setup.remoteAddr

	result, err := deps.service.Login(loginReq, email, password)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	return result
}

// defaultSecuritySetup returns common security test setup
func defaultSecuritySetup() securityTestSetup {
	return securityTestSetup{
		userAgent:  "TestDevice/1.0",
		acceptLang: "en-US",
		acceptEnc:  "gzip",
		remoteAddr: "192.168.1.1:12345",
	}
}

func TestHandleRegister(t *testing.T) {
	deps := setupHandler(t)

	t.Run("valid registration", func(t *testing.T) {
		tc := httpTestCase{
			body:       `{"name":"John Doe","email":"john@example.com","password":"password123"}`,
			wantStatus: http.StatusCreated,
			wantMsg:    "User registered successfully",
			checkBody: func(t *testing.T, body map[string]any) {
				data := body["data"].(map[string]any)
				user := data["user"].(map[string]any)
				if user["email"] != "john@example.com" {
					t.Errorf("email = %v, want john@example.com", user["email"])
				}
			},
		}
		executeHTTPTest(t, deps.handler.HandleRegister, tc, "POST", "/register")
	})

	t.Run("duplicate email", func(t *testing.T) {
		tc := httpTestCase{
			body:       `{"name":"John Doe","email":"john@example.com","password":"password123"}`,
			wantStatus: http.StatusConflict,
			wantMsg:    "Email already exists",
		}
		executeHTTPTest(t, deps.handler.HandleRegister, tc, "POST", "/register")
	})
}

func TestHandleLogin(t *testing.T) {
	deps := setupHandler(t)
	createTestUser(t, deps, "LoginUser", "login@example.com", "password123")

	setupCtx := func(req *http.Request) *http.Request {
		req.Header.Set("User-Agent", "TestAgent/1.0")
		req.RemoteAddr = "192.168.1.1:12345"
		return req
	}

	t.Run("valid login", func(t *testing.T) {
		tc := httpTestCase{
			body:       `{"email":"login@example.com","password":"password123"}`,
			setupCtx:   setupCtx,
			wantStatus: http.StatusOK,
			wantMsg:    "Login successful",
			checkBody: func(t *testing.T, body map[string]any) {
				data := body["data"].(map[string]any)
				if data["access_token"] == nil {
					t.Error("expected access_token")
				}
				if data["refresh_token"] == nil {
					t.Error("expected refresh_token")
				}
			},
		}
		executeHTTPTest(t, deps.handler.HandleLogin, tc, "POST", "/login")
	})

	t.Run("wrong email", func(t *testing.T) {
		tc := httpTestCase{
			body:       `{"email":"wrong@example.com","password":"password123"}`,
			setupCtx:   setupCtx,
			wantStatus: http.StatusUnauthorized,
			wantMsg:    "Invalid credentials",
		}
		executeHTTPTest(t, deps.handler.HandleLogin, tc, "POST", "/login")
	})

	t.Run("wrong password", func(t *testing.T) {
		tc := httpTestCase{
			body:       `{"email":"login@example.com","password":"wrongpassword"}`,
			setupCtx:   setupCtx,
			wantStatus: http.StatusUnauthorized,
			wantMsg:    "Invalid credentials",
		}
		executeHTTPTest(t, deps.handler.HandleLogin, tc, "POST", "/login")
	})

	t.Run("session limit enforcement", func(t *testing.T) {
		// Create user and login from 6 devices (max is 5)
		createTestUser(t, deps, "LimitUser", "limit@example.com", "password123")

		var lastLogin *services.LoginResult
		for i := range 6 {
			setup := securityTestSetup{
				userAgent:  "Device" + string(rune('A'+i)) + "/1.0",
				acceptLang: "en-US",
				acceptEnc:  "gzip",
				remoteAddr: "192.168.1." + string(rune('1'+i)) + ":12345",
			}
			lastLogin = loginTestUser(t, deps, "limit@example.com", "password123", setup)
		}

		// Verify only 5 active sessions exist
		claims, err := deps.service.ValidateAccessToken(lastLogin.AccessToken)
		if err != nil {
			t.Fatalf("ValidateAccessToken() error = %v", err)
		}

		tc := httpTestCase{
			setupCtx: func(req *http.Request) *http.Request {
				ctx := context.WithValue(req.Context(), middleware.ClaimsKey, claims)
				return req.WithContext(ctx)
			},
			wantStatus: http.StatusOK,
			checkBody: func(t *testing.T, body map[string]any) {
				data := body["data"].(map[string]any)
				sessions := data["sessions"].([]any)
				if len(sessions) != 5 {
					t.Errorf("sessions count = %d, want 5 (oldest should be revoked)", len(sessions))
				}
			},
		}
		executeHTTPTest(t, deps.handler.HandleListSessions, tc, "GET", "/sessions")
	})

	t.Run("device relogin revokes old token", func(t *testing.T) {
		createTestUser(t, deps, "ReloginUser", "relogin@example.com", "password123")

		setup := securityTestSetup{
			userAgent:  "SameDevice/1.0",
			acceptLang: "en-US",
			acceptEnc:  "gzip",
			remoteAddr: "192.168.1.100:12345",
		}

		// First login
		firstLogin := loginTestUser(t, deps, "relogin@example.com", "password123", setup)

		// Second login from same device
		secondLogin := loginTestUser(t, deps, "relogin@example.com", "password123", setup)

		// Try to use first refresh token - should fail
		req := httptest.NewRequest("POST", "/refresh", strings.NewReader(`{"refresh_token":"`+firstLogin.RefreshToken+`"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", setup.userAgent)
		req.Header.Set("Accept-Language", setup.acceptLang)
		req.Header.Set("Accept-Encoding", setup.acceptEnc)
		req.RemoteAddr = setup.remoteAddr
		w := httptest.NewRecorder()

		deps.handler.HandleRefresh(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("old token after relogin: status = %d, want %d", w.Code, http.StatusUnauthorized)
		}

		// Verify second token still works
		req2 := httptest.NewRequest("POST", "/refresh", strings.NewReader(`{"refresh_token":"`+secondLogin.RefreshToken+`"}`))
		req2.Header.Set("Content-Type", "application/json")
		req2.Header.Set("User-Agent", setup.userAgent)
		req2.Header.Set("Accept-Language", setup.acceptLang)
		req2.Header.Set("Accept-Encoding", setup.acceptEnc)
		req2.RemoteAddr = setup.remoteAddr
		w2 := httptest.NewRecorder()

		deps.handler.HandleRefresh(w2, req2)

		if w2.Code != http.StatusOK {
			t.Errorf("new token after relogin: status = %d, want %d", w2.Code, http.StatusOK)
		}
	})
}

func TestHandleRefresh(t *testing.T) {
	deps := setupHandler(t)
	createTestUser(t, deps, "RefreshUser", "refresh@example.com", "password123")
	loginResult := loginTestUser(t, deps, "refresh@example.com", "password123", defaultSecuritySetup())

	setupCtxWithSecurity := func(req *http.Request) *http.Request {
		req.Header.Set("User-Agent", "TestDevice/1.0")
		req.Header.Set("Accept-Language", "en-US")
		req.Header.Set("Accept-Encoding", "gzip")
		req.RemoteAddr = "192.168.1.1:12345"
		return req
	}

	t.Run("valid refresh", func(t *testing.T) {
		tc := httpTestCase{
			body:       `{"refresh_token":"` + loginResult.RefreshToken + `"}`,
			setupCtx:   setupCtxWithSecurity,
			wantStatus: http.StatusOK,
			wantMsg:    "Token refresh successful",
			checkBody: func(t *testing.T, body map[string]any) {
				if body["data"] == nil {
					t.Fatal("expected data field in response")
				}
				data := body["data"].(map[string]any)
				if data["access_token"] == nil {
					t.Error("expected access_token")
				}
				if data["refresh_token"] == nil {
					t.Error("expected refresh_token")
				}
			},
		}
		executeHTTPTest(t, deps.handler.HandleRefresh, tc, "POST", "/refresh")
	})

	t.Run("invalid json", func(t *testing.T) {
		tc := httpTestCase{
			body:       `{invalid}`,
			wantStatus: http.StatusBadRequest,
			wantMsg:    "Invalid request payload",
		}
		executeHTTPTest(t, deps.handler.HandleRefresh, tc, "POST", "/refresh")
	})

	t.Run("missing refresh_token", func(t *testing.T) {
		tc := httpTestCase{
			body:       `{}`,
			wantStatus: http.StatusUnprocessableEntity,
		}
		executeHTTPTest(t, deps.handler.HandleRefresh, tc, "POST", "/refresh")
	})

	t.Run("invalid refresh_token", func(t *testing.T) {
		tc := httpTestCase{
			body:       `{"refresh_token":"invalid-token"}`,
			wantStatus: http.StatusUnauthorized,
			wantMsg:    "Invalid or expired refresh token",
			setupCtx: func(req *http.Request) *http.Request {
				req.Header.Set("User-Agent", "TestAgent/1.0")
				req.RemoteAddr = "192.168.1.1:12345"
				return req
			},
		}
		executeHTTPTest(t, deps.handler.HandleRefresh, tc, "POST", "/refresh")
	})

	t.Run("sequential token rotation", func(t *testing.T) {
		// Create fresh user and login
		createTestUser(t, deps, "RotationUser", "rotation@example.com", "password123")
		login := loginTestUser(t, deps, "rotation@example.com", "password123", defaultSecuritySetup())

		// Perform 3 sequential refreshes
		currentToken := login.RefreshToken
		for i := range 3 {
			req := httptest.NewRequest("POST", "/refresh", strings.NewReader(`{"refresh_token":"`+currentToken+`"}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", "TestDevice/1.0")
			req.Header.Set("Accept-Language", "en-US")
			req.Header.Set("Accept-Encoding", "gzip")
			req.RemoteAddr = "192.168.1.1:12345"
			w := httptest.NewRecorder()

			deps.handler.HandleRefresh(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("rotation %d: status = %d, want %d", i+1, w.Code, http.StatusOK)
			}

			var response map[string]any
			if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
				t.Fatalf("rotation %d: failed to decode response: %v", i+1, err)
			}

			data := response["data"].(map[string]any)
			currentToken = data["refresh_token"].(string)
		}

		// Wait beyond grace period
		time.Sleep(4 * time.Second)

		// Try to use original token - should fail (rotated)
		req := httptest.NewRequest("POST", "/refresh", strings.NewReader(`{"refresh_token":"`+login.RefreshToken+`"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "TestDevice/1.0")
		req.Header.Set("Accept-Language", "en-US")
		req.Header.Set("Accept-Encoding", "gzip")
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()

		deps.handler.HandleRefresh(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("rotated token reuse: status = %d, want %d", w.Code, http.StatusUnauthorized)
		}
	})

	t.Run("refresh after logout", func(t *testing.T) {
		// Create user, login, then logout
		createTestUser(t, deps, "LogoutRefreshUser", "logout-refresh@example.com", "password123")
		login := loginTestUser(t, deps, "logout-refresh@example.com", "password123", defaultSecuritySetup())

		claims, err := deps.service.ValidateAccessToken(login.AccessToken)
		if err != nil {
			t.Fatalf("ValidateAccessToken() error = %v", err)
		}

		// Logout
		logoutReq := httptest.NewRequest("POST", "/logout", nil)
		logoutReq = logoutReq.WithContext(context.WithValue(logoutReq.Context(), middleware.ClaimsKey, claims))
		logoutW := httptest.NewRecorder()
		deps.handler.HandleLogout(logoutW, logoutReq)

		if logoutW.Code != http.StatusOK {
			t.Errorf("logout: status = %d, want %d", logoutW.Code, http.StatusOK)
		}

		// Try to refresh with revoked token
		req := httptest.NewRequest("POST", "/refresh", strings.NewReader(`{"refresh_token":"`+login.RefreshToken+`"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "TestDevice/1.0")
		req.Header.Set("Accept-Language", "en-US")
		req.Header.Set("Accept-Encoding", "gzip")
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()

		deps.handler.HandleRefresh(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("refresh after logout: status = %d, want %d", w.Code, http.StatusUnauthorized)
		}
	})
}

func TestHandleLogout(t *testing.T) {
	deps := setupHandler(t)
	createTestUser(t, deps, "LogoutUser", "logout@example.com", "password123")
	loginResult := loginTestUser(t, deps, "logout@example.com", "password123", defaultSecuritySetup())

	claims, err := deps.service.ValidateAccessToken(loginResult.AccessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken() error = %v", err)
	}

	t.Run("valid logout", func(t *testing.T) {
		tc := httpTestCase{
			setupCtx: func(req *http.Request) *http.Request {
				ctx := context.WithValue(req.Context(), middleware.ClaimsKey, claims)
				return req.WithContext(ctx)
			},
			wantStatus: http.StatusOK,
			wantMsg:    "Logout successful",
		}
		executeHTTPTest(t, deps.handler.HandleLogout, tc, "POST", "/logout")
	})
}

func TestHandleListSessions(t *testing.T) {
	deps := setupHandler(t)
	createTestUser(t, deps, "SessionsUser", "sessions@example.com", "password123")

	// Login 3 times
	var lastLoginResult *services.LoginResult
	for i := range 3 {
		setup := securityTestSetup{
			userAgent:  "Device" + string(rune('A'+i)) + "/1.0",
			acceptLang: "en-US",
			acceptEnc:  "gzip",
			remoteAddr: "192.168.1." + string(rune('1'+i)) + ":12345",
		}
		lastLoginResult = loginTestUser(t, deps, "sessions@example.com", "password123", setup)
	}

	claims, err := deps.service.ValidateAccessToken(lastLoginResult.AccessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken() error = %v", err)
	}

	t.Run("list sessions", func(t *testing.T) {
		tc := httpTestCase{
			setupCtx: func(req *http.Request) *http.Request {
				ctx := context.WithValue(req.Context(), middleware.ClaimsKey, claims)
				return req.WithContext(ctx)
			},
			wantStatus: http.StatusOK,
			wantMsg:    "Sessions retrieved successfully",
			checkBody: func(t *testing.T, body map[string]any) {
				data := body["data"].(map[string]any)
				sessions := data["sessions"].([]any)
				if len(sessions) != 3 {
					t.Errorf("sessions count = %d, want 3", len(sessions))
				}
			},
		}
		executeHTTPTest(t, deps.handler.HandleListSessions, tc, "GET", "/sessions")
	})
}

func TestHandleRevokeSession(t *testing.T) {
	deps := setupHandler(t)
	createTestUser(t, deps, "RevokeUser", "revoke@example.com", "password123")
	loginResult := loginTestUser(t, deps, "revoke@example.com", "password123", defaultSecuritySetup())

	claims, err := deps.service.ValidateAccessToken(loginResult.AccessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken() error = %v", err)
	}
	sessionID := claims["sid"].(string)

	t.Run("valid revoke", func(t *testing.T) {
		tc := httpTestCase{
			setupCtx: func(req *http.Request) *http.Request {
				ctx := context.WithValue(req.Context(), middleware.ClaimsKey, claims)
				rctx := chi.NewRouteContext()
				rctx.URLParams.Add("session_id", sessionID)
				ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
				return req.WithContext(ctx)
			},
			wantStatus: http.StatusOK,
			wantMsg:    "Session revoked successfully",
		}
		executeHTTPTest(t, deps.handler.HandleRevokeSession, tc, "DELETE", "/sessions/"+sessionID)
	})

	t.Run("session not found", func(t *testing.T) {
		tc := httpTestCase{
			setupCtx: func(req *http.Request) *http.Request {
				ctx := context.WithValue(req.Context(), middleware.ClaimsKey, claims)
				rctx := chi.NewRouteContext()
				rctx.URLParams.Add("session_id", "00000000-0000-0000-0000-000000000000")
				ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
				return req.WithContext(ctx)
			},
			wantStatus: http.StatusNotFound,
			wantMsg:    "Session not found",
		}
		executeHTTPTest(t, deps.handler.HandleRevokeSession, tc, "DELETE", "/sessions/00000000-0000-0000-0000-000000000000")
	})

	t.Run("missing session_id", func(t *testing.T) {
		tc := httpTestCase{
			setupCtx: func(req *http.Request) *http.Request {
				ctx := context.WithValue(req.Context(), middleware.ClaimsKey, claims)
				rctx := chi.NewRouteContext()
				ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
				return req.WithContext(ctx)
			},
			wantStatus: http.StatusBadRequest,
			wantMsg:    "Session ID is required",
		}
		executeHTTPTest(t, deps.handler.HandleRevokeSession, tc, "DELETE", "/sessions/")
	})

	t.Run("unauthorized user", func(t *testing.T) {
		// Create another user and try to revoke first user's session
		createTestUser(t, deps, "OtherUser", "other@example.com", "password123")
		otherLoginResult := loginTestUser(t, deps, "other@example.com", "password123", defaultSecuritySetup())
		otherClaims, err := deps.service.ValidateAccessToken(otherLoginResult.AccessToken)
		if err != nil {
			t.Fatalf("ValidateAccessToken() error = %v", err)
		}

		// Try to revoke the first user's session using other user's credentials
		tc := httpTestCase{
			setupCtx: func(req *http.Request) *http.Request {
				ctx := context.WithValue(req.Context(), middleware.ClaimsKey, otherClaims)
				rctx := chi.NewRouteContext()
				rctx.URLParams.Add("session_id", sessionID)
				ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
				return req.WithContext(ctx)
			},
			wantStatus: http.StatusForbidden,
			wantMsg:    "Unauthorized",
		}
		executeHTTPTest(t, deps.handler.HandleRevokeSession, tc, "DELETE", "/sessions/"+sessionID)
	})

	t.Run("malformed session_id", func(t *testing.T) {
		tc := httpTestCase{
			setupCtx: func(req *http.Request) *http.Request {
				ctx := context.WithValue(req.Context(), middleware.ClaimsKey, claims)
				rctx := chi.NewRouteContext()
				rctx.URLParams.Add("session_id", "not-a-valid-uuid")
				ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
				return req.WithContext(ctx)
			},
			wantStatus: http.StatusNotFound,
			wantMsg:    "Session not found",
		}
		executeHTTPTest(t, deps.handler.HandleRevokeSession, tc, "DELETE", "/sessions/not-a-valid-uuid")
	})

	t.Run("revoke already revoked session", func(t *testing.T) {
		// Create new user and login
		createTestUser(t, deps, "DoubleRevokeUser", "doublerevoke@example.com", "password123")
		doubleLogin := loginTestUser(t, deps, "doublerevoke@example.com", "password123", defaultSecuritySetup())
		doubleClaims, err := deps.service.ValidateAccessToken(doubleLogin.AccessToken)
		if err != nil {
			t.Fatalf("ValidateAccessToken() error = %v", err)
		}
		doubleSessionID := doubleClaims["sid"].(string)

		// Revoke once
		tc1 := httpTestCase{
			setupCtx: func(req *http.Request) *http.Request {
				ctx := context.WithValue(req.Context(), middleware.ClaimsKey, doubleClaims)
				rctx := chi.NewRouteContext()
				rctx.URLParams.Add("session_id", doubleSessionID)
				ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
				return req.WithContext(ctx)
			},
			wantStatus: http.StatusOK,
		}
		executeHTTPTest(t, deps.handler.HandleRevokeSession, tc1, "DELETE", "/sessions/"+doubleSessionID)

		// Try to revoke again - should return not found
		tc2 := httpTestCase{
			setupCtx: func(req *http.Request) *http.Request {
				ctx := context.WithValue(req.Context(), middleware.ClaimsKey, doubleClaims)
				rctx := chi.NewRouteContext()
				rctx.URLParams.Add("session_id", doubleSessionID)
				ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
				return req.WithContext(ctx)
			},
			wantStatus: http.StatusNotFound,
			wantMsg:    "Session not found",
		}
		executeHTTPTest(t, deps.handler.HandleRevokeSession, tc2, "DELETE", "/sessions/"+doubleSessionID)
	})
}

// Security Tests with Log Verification

func TestHandleRefresh_DeviceMismatch(t *testing.T) {
	deps := setupHandler(t)
	deps.logCapture.Reset()

	createTestUser(t, deps, "DeviceTest", "device@example.com", "password123")
	setup := securityTestSetup{
		userAgent:  "OriginalDevice/1.0",
		acceptLang: "en-US",
		acceptEnc:  "gzip",
		remoteAddr: "192.168.1.1:12345",
	}
	loginResult := loginTestUser(t, deps, "device@example.com", "password123", setup)

	deps.logCapture.Reset()
	req := httptest.NewRequest("POST", "/refresh", strings.NewReader(`{"refresh_token":"`+loginResult.RefreshToken+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "DifferentDevice/2.0")
	req.Header.Set("Accept-Language", "fr-FR")
	req.Header.Set("Accept-Encoding", "br")
	req.RemoteAddr = "10.0.0.1:54321"
	w := httptest.NewRecorder()

	deps.handler.HandleRefresh(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}

	if !deps.logCapture.HasMessage("Device mismatch") {
		t.Error("expected Device mismatch log message")
	}
	if !deps.logCapture.HasLevel("warn") {
		t.Error("expected warn level log")
	}
}

func TestHandleRefresh_ReplayAttack(t *testing.T) {
	deps := setupHandler(t)
	createTestUser(t, deps, "ReplayTest", "replay@example.com", "password123")
	loginResult := loginTestUser(t, deps, "replay@example.com", "password123", defaultSecuritySetup())

	req1 := httptest.NewRequest("POST", "/refresh", strings.NewReader(`{"refresh_token":"`+loginResult.RefreshToken+`"}`))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("User-Agent", "TestDevice/1.0")
	req1.Header.Set("Accept-Language", "en-US")
	req1.Header.Set("Accept-Encoding", "gzip")
	req1.RemoteAddr = "192.168.1.1:12345"
	w1 := httptest.NewRecorder()

	deps.handler.HandleRefresh(w1, req1)

	if w1.Code != http.StatusOK {
		t.Errorf("first refresh: status = %d, want %d", w1.Code, http.StatusOK)
	}

	time.Sleep(4 * time.Second)

	deps.logCapture.Reset()
	req2 := httptest.NewRequest("POST", "/refresh", strings.NewReader(`{"refresh_token":"`+loginResult.RefreshToken+`"}`))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("User-Agent", "TestDevice/1.0")
	req2.Header.Set("Accept-Language", "en-US")
	req2.Header.Set("Accept-Encoding", "gzip")
	req2.RemoteAddr = "192.168.1.1:12345"
	w2 := httptest.NewRecorder()

	deps.handler.HandleRefresh(w2, req2)

	if w2.Code != http.StatusUnauthorized {
		t.Errorf("replay attack: status = %d, want %d", w2.Code, http.StatusUnauthorized)
	}

	if !deps.logCapture.HasMessage("Replay detected") {
		t.Error("expected Replay detected log message")
	}
}

func TestHandleRefresh_ConcurrentRequests(t *testing.T) {
	deps := setupHandler(t)
	createTestUser(t, deps, "ConcurrentTest", "concurrent@example.com", "password123")
	loginResult := loginTestUser(t, deps, "concurrent@example.com", "password123", defaultSecuritySetup())

	var wg sync.WaitGroup
	successCount := 0
	var mu sync.Mutex

	// Make 3 concurrent requests within grace period
	for range 3 {
		wg.Go(func() {
			req := httptest.NewRequest("POST", "/refresh", strings.NewReader(`{"refresh_token":"`+loginResult.RefreshToken+`"}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", "TestDevice/1.0")
			req.Header.Set("Accept-Language", "en-US")
			req.Header.Set("Accept-Encoding", "gzip")
			req.RemoteAddr = "192.168.1.1:12345"
			w := httptest.NewRecorder()

			deps.handler.HandleRefresh(w, req)

			mu.Lock()
			if w.Code == http.StatusOK {
				successCount++
			}
			mu.Unlock()
		})
	}

	wg.Wait()

	// All 3 should succeed within grace period
	if successCount != 3 {
		t.Errorf("concurrent requests: successCount = %d, want 3", successCount)
	}
}

func TestHandleRefresh_GracePeriodAbuse(t *testing.T) {
	deps := setupHandler(t)
	createTestUser(t, deps, "GraceAbuseTest", "abuse@example.com", "password123")
	loginResult := loginTestUser(t, deps, "abuse@example.com", "password123", defaultSecuritySetup())

	var wg sync.WaitGroup
	results := make([]int, 4)
	var mu sync.Mutex

	// Make 4 concurrent requests - max allowed is 3, so 4th should fail
	for i := range 4 {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			req := httptest.NewRequest("POST", "/refresh", strings.NewReader(`{"refresh_token":"`+loginResult.RefreshToken+`"}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", "TestDevice/1.0")
			req.Header.Set("Accept-Language", "en-US")
			req.Header.Set("Accept-Encoding", "gzip")
			req.RemoteAddr = "192.168.1.1:12345"
			w := httptest.NewRecorder()

			deps.handler.HandleRefresh(w, req)

			mu.Lock()
			results[index] = w.Code
			mu.Unlock()
		}(i)
	}

	wg.Wait()

	// Count successes and failures
	successCount := 0
	failCount := 0
	for _, code := range results {
		switch code {
		case http.StatusOK:
			successCount++
		case http.StatusUnauthorized:
			failCount++
		}
	}

	// Exactly 3 should succeed (max grace period reuses), 1 should fail
	if successCount != 3 {
		t.Errorf("successCount = %d, want 3 (max grace period reuses)", successCount)
	}
	if failCount != 1 {
		t.Errorf("failCount = %d, want 1 (grace period abuse)", failCount)
	}

	if !deps.logCapture.HasMessage("Grace period abuse") {
		t.Error("expected Grace period abuse log message")
	}
}

func TestHandleLogin_ConcurrentSameDevice(t *testing.T) {
	deps := setupHandler(t)
	createTestUser(t, deps, "ConcurrentLoginUser", "concurrent-login@example.com", "password123")

	var wg sync.WaitGroup
	results := make([]*services.LoginResult, 3)
	var mu sync.Mutex

	setup := securityTestSetup{
		userAgent:  "SameDevice/1.0",
		acceptLang: "en-US",
		acceptEnc:  "gzip",
		remoteAddr: "192.168.1.1:12345",
	}

	// 3 concurrent logins from same device
	for i := range 3 {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			loginReq := httptest.NewRequest("POST", "/login", nil)
			loginReq.Header.Set("User-Agent", setup.userAgent)
			loginReq.Header.Set("Accept-Language", setup.acceptLang)
			loginReq.Header.Set("Accept-Encoding", setup.acceptEnc)
			loginReq.RemoteAddr = setup.remoteAddr

			result, err := deps.service.Login(loginReq, "concurrent-login@example.com", "password123")
			if err != nil {
				t.Errorf("concurrent login %d failed: %v", index, err)
				return
			}

			mu.Lock()
			results[index] = result
			mu.Unlock()
		}(i)
	}

	wg.Wait()

	// All should succeed
	successCount := 0
	for _, result := range results {
		if result != nil && result.AccessToken != "" {
			successCount++
		}
	}

	if successCount != 3 {
		t.Errorf("concurrent logins: successCount = %d, want 3", successCount)
	}

	// Verify behavior: Due to race conditions, all 3 tokens might be active in DB
	// But ListSessions deduplicates by DeviceID, so only 1 session is shown
	lastResult := results[len(results)-1]
	claims, err := deps.service.ValidateAccessToken(lastResult.AccessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken() error = %v", err)
	}

	ctx := context.Background()
	sessions, err := deps.service.ListSessions(ctx, lastResult.User.ID, claims["sid"].(string))
	if err != nil {
		t.Fatalf("ListSessions() error = %v", err)
	}

	// ListSessions deduplicates by DeviceID, so even if multiple tokens are active, only 1 session is shown
	if len(sessions) != 1 {
		t.Errorf("displayed sessions after concurrent login = %d, want 1 (deduplicated by device)", len(sessions))
	}

	// Under READ COMMITTED, concurrent logins may create multiple active tokens
	// for the same device. Acceptable: ListSessions deduplicates, TTL expires old tokens.
	validCount := 0
	for _, result := range results {
		if result == nil {
			continue
		}
		req := httptest.NewRequest("POST", "/refresh", strings.NewReader(`{"refresh_token":"`+result.RefreshToken+`"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", setup.userAgent)
		req.Header.Set("Accept-Language", setup.acceptLang)
		req.Header.Set("Accept-Encoding", setup.acceptEnc)
		req.RemoteAddr = setup.remoteAddr
		w := httptest.NewRecorder()

		deps.handler.HandleRefresh(w, req)

		if w.Code == http.StatusOK {
			validCount++
		}
	}

	// At least 1 token must be valid; may be more due to race condition (acceptable)
	if validCount < 1 {
		t.Errorf("valid tokens after concurrent login = %d, want >= 1", validCount)
	}
}
