-- Portable schema shared by SQLite / Postgres / MySQL(MariaDB).
-- Types kept to the common subset; values are generated in Rust, so no
-- dialect-specific defaults or functions appear here.

-- A tenant is an isolated workspace that owns OAuth clients. Managers and
-- developers belong to exactly one tenant; super admins are global.
CREATE TABLE IF NOT EXISTS tenants (
    id         VARCHAR(36)  PRIMARY KEY,
    name       VARCHAR(255) NOT NULL,
    created_at VARCHAR(40)  NOT NULL
);

-- Dashboard users (members). role ∈ super | manager | developer.
--   super     -> global; manages tenants, users, and everything
--   manager   -> own tenant; CRUD clients + secrets
--   developer -> own tenant; secrets only (no client create/delete/config)
-- tenant_id is NULL for super admins.
CREATE TABLE IF NOT EXISTS admins (
    id            VARCHAR(36)  PRIMARY KEY,
    email         VARCHAR(320) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role          VARCHAR(16)  NOT NULL DEFAULT 'manager',
    tenant_id     VARCHAR(36)
);

-- End users: the people who sign in to relying apps through this SSO
-- (distinct from `admins`, who manage the dashboard).
CREATE TABLE IF NOT EXISTS users (
    id            VARCHAR(36)  PRIMARY KEY,
    email         VARCHAR(320) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at    VARCHAR(40)  NOT NULL,
    -- Fine-grained authorization: roles, groups, and custom attributes echoed
    -- into tokens (mirrors Keycloak's realm roles / groups / user attributes).
    -- Stored as JSON TEXT (empty [] / {} = none), like clients.js_origins.
    roles        TEXT NOT NULL DEFAULT '[]',
    groups       TEXT NOT NULL DEFAULT '[]',
    attributes   TEXT NOT NULL DEFAULT '{}',
    -- Base32 TOTP secret; NULL = two-factor authentication not enrolled.
    totp_secret  VARCHAR(64),
    -- Whether the account may sign in (Keycloak "enabled"); 0 = disabled.
    enabled      INTEGER NOT NULL DEFAULT 1
);

-- Role catalog (Keycloak-style entity). A user "has" a role by name in their
-- users.roles JSON; this table is the managed, canonical list of roles.
CREATE TABLE IF NOT EXISTS roles (
    id   VARCHAR(36) PRIMARY KEY,
    name VARCHAR(64) NOT NULL UNIQUE
);

-- Group catalog. Using `user_groups` because `groups` is a SQL reserved word.
CREATE TABLE IF NOT EXISTS user_groups (
    id   VARCHAR(36) PRIMARY KEY,
    name VARCHAR(64) NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS clients (
    id                 VARCHAR(36)  PRIMARY KEY,
    client_id          VARCHAR(64)  NOT NULL UNIQUE,
    client_secret_hash VARCHAR(255) NOT NULL,
    tenant_id          VARCHAR(36),
    name               VARCHAR(255) NOT NULL,
    js_origins         TEXT         NOT NULL,
    redirect_uris      TEXT         NOT NULL,
    -- JSON array of allowed email patterns; empty ([]) means allow all.
    allowed_emails     TEXT         NOT NULL DEFAULT '[]',
    -- Which fine-grained user claims this client's tokens should carry
    -- (0/1 INTEGER, default all on). Lets a client opt out of roles/groups/
    -- attributes it doesn't need, mirroring Keycloak's client claim mapping.
    include_roles      INTEGER      NOT NULL DEFAULT 1,
    include_groups     INTEGER      NOT NULL DEFAULT 1,
    include_attributes INTEGER      NOT NULL DEFAULT 1,
    -- Resource-based authorization (Keycloak UMA-style subset). When enabled
    -- (default off), the access token carries an `authorization` claim with the
    -- resources/scopes the signed-in user may access, per `policies`.
    enable_authorization INTEGER    NOT NULL DEFAULT 0,
    -- JSON array of resources: [{name, scopes:[...]}].
    resources          TEXT         NOT NULL DEFAULT '[]',
    -- JSON array of policies: [{name, resources:[...], roles:[...], groups:[...]}].
    policies           TEXT         NOT NULL DEFAULT '[]',
    -- Require every signing-in end user to have (and use) TOTP 2FA.
    require_mfa        INTEGER      NOT NULL DEFAULT 0,
    created_at         VARCHAR(40)  NOT NULL
);

-- A client may hold up to 2 secrets at once (enforced in app), so they can be
-- rotated without recreating the client. The plaintext is never stored.
CREATE TABLE IF NOT EXISTS client_secrets (
    id          VARCHAR(36)  PRIMARY KEY,
    client_id   VARCHAR(36)  NOT NULL,
    hint        VARCHAR(16)  NOT NULL,
    secret_hash VARCHAR(255) NOT NULL,
    created_at  VARCHAR(40)  NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_client_secrets_client ON client_secrets (client_id);

CREATE TABLE IF NOT EXISTS auth_codes (
    code                  VARCHAR(128) PRIMARY KEY,
    client_id             VARCHAR(64)  NOT NULL,
    redirect_uri          VARCHAR(2048) NOT NULL,
    scope                 VARCHAR(1024) NOT NULL,
    subject               VARCHAR(64)  NOT NULL,
    code_challenge        VARCHAR(128),
    code_challenge_method VARCHAR(8),
    nonce                 VARCHAR(255),
    expires_at            VARCHAR(40)  NOT NULL
);

-- Refresh tokens rotate on use. Each token in a rotation chain shares family_id;
-- a consumed token is kept with revoked=1 (a tombstone) so replay of an already
-- rotated token is detectable and revokes the whole family.
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash VARCHAR(64)  PRIMARY KEY,
    client_id  VARCHAR(64)  NOT NULL,
    subject    VARCHAR(64)  NOT NULL,
    scope      VARCHAR(1024) NOT NULL,
    family_id  VARCHAR(64)  NOT NULL DEFAULT '',
    revoked    INTEGER      NOT NULL DEFAULT 0,
    expires_at VARCHAR(40)  NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_codes_client ON auth_codes (client_id);
CREATE INDEX IF NOT EXISTS idx_refresh_client ON refresh_tokens (client_id);
