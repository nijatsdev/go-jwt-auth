# Go JWT Auth API

Go authentication API with JWT access tokens, refresh token rotation, and session management. PostgreSQL-backed, with integration tests and production-oriented hardening.

## Tech Stack

- **Go** – HTTP server with [Chi](https://github.com/go-chi/chi) router
- **PostgreSQL** – persistent storage for users and refresh tokens
- **Docker** – multi-stage build with separate migration container (amd64/arm64)
- **[goose](https://github.com/pressly/goose)** – database migrations
- **[zerolog](https://github.com/rs/zerolog)** – structured JSON logging
- **[testcontainers-go](https://github.com/testcontainers/testcontainers-go)** – integration tests with real PostgreSQL

## Features

- **Auth flows**: register, login, refresh, logout, session listing and revocation
- **Security controls**: refresh-token rotation, replay detection, header-based device binding, grace-period handling
- **Rate limiting**: isolated per-endpoint buckets (5/min login+register, 10/min refresh, 60/min session routes, 100/min profile)
- **Structured logging**: JSON logs via zerolog with configurable log levels
- **Testing**: integration tests (handlers) plus unit tests (middleware, utils); `go test -race` in CI
- **Production safeguards**: session limits per user, configurable TTLs, automatic token cleanup, non-root Docker image

## API Endpoints

**Authentication:**

- `POST /auth/register` – create account
- `POST /auth/login` – login and issue tokens
- `POST /auth/refresh` – rotate tokens
- `POST /auth/logout` – revoke current session family (handles stale access tokens)
- `GET /auth/sessions` – list active sessions
- `DELETE /auth/sessions/{session_id}` – revoke a session

**User:**

- `GET /profile` – fetch authenticated profile

**System:**

- `GET /` – welcome
- `GET /health` – database health (`503` when down or degraded)

## Security Model

- **Access tokens**: Short-lived HS256 JWTs with `iss` / `aud` (default 15m). Protected routes re-check that the `sid` refresh session is still active (logout/revoke ends access early).
- **Refresh token rotation**: New refresh token on each use; old token revoked
- **Replay detection**: Reuse of rotated tokens revokes the rotation chain
- **Grace period**: Short window for one idempotent concurrent refresh during rotation
- **Device binding**: Fingerprint from User-Agent + `Accept-Language` + `Accept-Encoding` (IP not used)
- **Session limits**: Maximum active sessions per user (default 10)

## Configuration

Copy `.env.example` to `.env` and set:

```env
DB_DATABASE=your_database
DB_USERNAME=your_username
DB_PASSWORD=your_password
JWT_SECRET=your_secret_min_32_chars
JWT_ISSUER=go-jwt-auth
JWT_AUDIENCE=go-jwt-auth-api
```

See `.env.example` for CORS, SSL mode, TTLs, and cleanup retention.

## Quick Start

```bash
make docker-run
# or
cp .env.example .env
goose up
make run
```

## Developer Tooling

```bash
make build
make run
make test
```

## License

[MIT](LICENSE)
