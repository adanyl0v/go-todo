CREATE TABLE sessions(
    id UUID PRIMARY KEY NOT NULL,
    user_id UUID NOT NULL,
    FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE,
    fingerprint TEXT NOT NULL UNIQUE,
    refresh_token TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
