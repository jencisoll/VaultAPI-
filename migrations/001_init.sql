CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

       CREATE TABLE users(
           id           UUID PRIMARY KEY DEFAULT  uuid_generate_v4(),
           email        TEXT NOT NULL UNIQUE,
           password_hash TEXT NOT     NULL ,
           role         TEXT NOT NULL DEFAULT 'user'
                            CHECK ( role IN ('user', 'admin') ),
           active       BOOLEAN  NOT NULL DEFAULT TRUE,
           created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
           updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
       );

CREATE TABLE refresh_tokens (
    id      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,

    family UUID NOT NULL DEFAULT uuid_generate_v4(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked     BOOLEAN NOT  NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_refresh_tokens_user ON  refresh_tokens(user_id);
CREATE INDEX  idx_refresh_tokens_family ON refresh_tokens(family);

CREATE OR REPLACE  FUNCTION update_updated_at()
       RETURNS TRIGGER AS $$
       BEGIN  NEW.updated_at  = NOW(); RETURN NEW; END;
    $$ LANGUAGE plpgsql;
CREATE TRIGGER users_updated_At
    BEFORE UPDATE ON users
FOR EACH ROW EXECUTE FUNCTION update_updated_at();