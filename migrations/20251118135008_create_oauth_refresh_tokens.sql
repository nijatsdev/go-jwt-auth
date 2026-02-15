-- +goose Up
-- +goose StatementBegin
CREATE TYPE token_revoke_reason AS ENUM (
    'user_logout',
    'remote_revoke',
    'token_rotation',
    'device_relogin',
    'session_limit',
    'device_mismatch',
    'replay_detected',
    'grace_period_abuse'
);

CREATE TABLE oauth_refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    user_agent TEXT NOT NULL,
    ip_address INET NOT NULL,
    device_id VARCHAR(255) NOT NULL,
    device_name VARCHAR(255),
    rotated_from UUID REFERENCES oauth_refresh_tokens(id) ON DELETE SET NULL,
    revoked_reason token_revoke_reason,
    revoked_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_oauth_refresh_tokens_rotated_from ON oauth_refresh_tokens(rotated_from) WHERE rotated_from IS NOT NULL;
CREATE INDEX idx_oauth_refresh_tokens_user_active ON oauth_refresh_tokens(user_id, created_at) WHERE revoked_at IS NULL;
CREATE INDEX idx_oauth_refresh_tokens_user_device_active ON oauth_refresh_tokens(user_id, device_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_oauth_refresh_tokens_expired ON oauth_refresh_tokens(expires_at) WHERE revoked_at IS NULL;
CREATE INDEX idx_oauth_refresh_tokens_revoked ON oauth_refresh_tokens(revoked_at) WHERE revoked_at IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE oauth_refresh_tokens;
DROP TYPE token_revoke_reason;
-- +goose StatementEnd