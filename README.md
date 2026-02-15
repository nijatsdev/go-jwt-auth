# Go JWT Auth API

A production-ready Go authentication service with JWT access tokens, refresh token rotation, and session management. Built with PostgreSQL persistence and security-first design.

## Tech Stack

- **Go** – HTTP server with [Chi](https://github.com/go-chi/chi) router
- **PostgreSQL** – persistent storage for users and refresh tokens
- **Docker** – multi-stage build with separate migration container
- **[goose](https://github.com/pressly/goose)** – database migrations
- **[zerolog](https://github.com/rs/zerolog)** – structured JSON logging
- **[testcontainers-go](https://github.com/testcontainers/testcontainers-go)** – integration tests with real PostgreSQL

## Features

- **Auth flows**: register, login, refresh, logout, session listing and revocation
- **Security controls**: refresh-token rotation, replay detection, device fingerprinting, grace period handling
- **Rate limiting**: per-endpoint limits (5/min auth, 10/min refresh, 60/min sessions, 100/min profile)
- **Structured logging**: JSON logs via zerolog with configurable log levels
- **Testing**: 42+ integration tests covering security edge cases (replay attacks, device mismatch, concurrent requests)
- **Production safeguards**: session limits per user, configurable TTLs, automatic token cleanup

## Project Structure

```txt
cmd/api/main.go             # HTTP server entrypoint with graceful shutdown
internal/
  config/                   # Environment-based configuration
  server/                   # Server setup, routes, middleware wiring
  handlers/                 # HTTP handlers (auth, user)
  services/                 # Business logic (token issuance, rotation, revocation)
  store/                    # PostgreSQL repositories (users, refresh tokens)
  middleware/               # Authentication, rate limiting, panic recovery
  database/                 # Connection pool, transaction manager
  cron/                     # Scheduled cleanup of expired/revoked tokens
  response/                 # Standardized JSON response helpers
  utils/                    # Token generation, device fingerprinting
  testutil/                 # Test helpers (container setup, DB fixtures)
  logger/                   # Logger initialization
migrations/                 # SQL migration files (goose)
```

## API Endpoints

**Authentication:**

- `POST /auth/register` – create account
- `POST /auth/login` – login and issue tokens
- `POST /auth/refresh` – rotate tokens
- `POST /auth/logout` – revoke current session
- `GET /auth/sessions` – list active sessions
- `PUT /auth/sessions/{session_id}` – revoke a session

**User:**

- `GET /profile` – fetch authenticated profile

**System:**

- `GET /` – welcome
- `GET /health` – database health check

## Security Model

- **Stateless access tokens**: Short-lived JWTs (configurable, default 15m)
- **Refresh token rotation**: New refresh token issued on each use, old token revoked
- **Replay detection**: Reuse of rotated tokens revokes entire token chain
- **Grace period**: 3-second window for concurrent requests during rotation
- **Device fingerprinting**: Tokens bound to device (User-Agent, IP, headers)
- **Session limits**: Maximum active sessions per user (default 10)

## Configuration

Copy `.env.example` to `.env` and set:

```env
# Required
DB_DATABASE=your_database
DB_USERNAME=your_username
DB_PASSWORD=your_password
JWT_SECRET=your_secret_min_32_chars

# Optional (with defaults)
PORT=8080
APP_ENV=local
LOG_LEVEL=info
ACCESS_TOKEN_TTL=15m
REFRESH_TOKEN_TTL=168h
MAX_ACTIVE_REFRESH_TOKENS_PER_USER=10
EXPIRED_TOKEN_RETENTION_DAYS=30
REVOKED_TOKEN_RETENTION_DAYS=90
```

## Quick Start

```bash
# Start PostgreSQL and app with Docker
make docker-run

# Or run locally (requires PostgreSQL and goose)
cp .env.example .env   # edit with your DB credentials
goose up               # run migrations
make run
```

## Developer Tooling

```bash
make build       # build binary
make run         # run server
make docker-run  # start with Docker Compose
make docker-down # stop Docker containers
make clean       # clean build artifacts
make watch       # auto-rebuild on file changes
make test        # run tests
```

## License

[MIT](LICENSE)
