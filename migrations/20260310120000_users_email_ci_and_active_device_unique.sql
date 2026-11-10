-- +goose Up
-- +goose StatementBegin
UPDATE users SET email = LOWER(TRIM(email));

CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_key ON users (LOWER(email));

CREATE UNIQUE INDEX IF NOT EXISTS oauth_refresh_tokens_user_device_active_key
    ON oauth_refresh_tokens (user_id, device_id)
    WHERE revoked_at IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS oauth_refresh_tokens_user_device_active_key;
DROP INDEX IF EXISTS users_email_lower_key;
-- +goose StatementEnd
