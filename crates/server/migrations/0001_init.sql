-- Portable schema shared by SQLite / Postgres / MySQL(MariaDB).
-- Types kept to the common subset; values are generated in Rust, so no
-- dialect-specific defaults or functions appear here.

CREATE TABLE IF NOT EXISTS admins (
    id            VARCHAR(36)  PRIMARY KEY,
    email         VARCHAR(320) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL
);

-- End users: the people who sign in to relying apps through this SSO
-- (distinct from `admins`, who manage the dashboard).
CREATE TABLE IF NOT EXISTS users (
    id            VARCHAR(36)  PRIMARY KEY,
    email         VARCHAR(320) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at    VARCHAR(40)  NOT NULL
);

CREATE TABLE IF NOT EXISTS clients (
    id                 VARCHAR(36)  PRIMARY KEY,
    client_id          VARCHAR(64)  NOT NULL UNIQUE,
    client_secret_hash VARCHAR(255) NOT NULL,
    name               VARCHAR(255) NOT NULL,
    js_origins         TEXT         NOT NULL,
    redirect_uris      TEXT         NOT NULL,
    -- JSON array of allowed email patterns; empty ([]) means allow all.
    allowed_emails     TEXT         NOT NULL DEFAULT '[]',
    created_at         VARCHAR(40)  NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_codes (
    code                  VARCHAR(128) PRIMARY KEY,
    client_id             VARCHAR(64)  NOT NULL,
    redirect_uri          VARCHAR(2048) NOT NULL,
    scope                 VARCHAR(1024) NOT NULL,
    subject               VARCHAR(64)  NOT NULL,
    code_challenge        VARCHAR(128),
    code_challenge_method VARCHAR(8),
    expires_at            VARCHAR(40)  NOT NULL
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash VARCHAR(64)  PRIMARY KEY,
    client_id  VARCHAR(64)  NOT NULL,
    subject    VARCHAR(64)  NOT NULL,
    scope      VARCHAR(1024) NOT NULL,
    expires_at VARCHAR(40)  NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_codes_client ON auth_codes (client_id);
CREATE INDEX IF NOT EXISTS idx_refresh_client ON refresh_tokens (client_id);
