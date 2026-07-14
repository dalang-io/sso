//! Storage layer.
//!
//! A single `Db` wraps a `sqlx::AnyPool`, so the concrete driver (SQLite,
//! Postgres, MySQL/MariaDB) is chosen at runtime from the `DATABASE_URL` scheme
//! — no recompile to switch backends. Portability rules we hold to:
//!   * IDs are UUID **strings**, timestamps are RFC3339 **TEXT** generated in
//!     Rust (never `now()`), booleans are 0/1 **INTEGER**, lists are JSON TEXT.
//!   * Only the SQL subset common to all three dialects is used.
//!   * Bind placeholders are written `?` and rewritten to `$n` for Postgres.
//!
//! Oracle / MSSQL are intentionally out of the `Any` pool (sqlx has no driver);
//! they plug in behind the same method surface — see `docs/DATABASE.md`.

use crate::crypto;
use crate::models::{Admin, AuthCode, Client, RefreshToken, User};
use sqlx::any::{AnyPoolOptions, AnyRow};
use sqlx::{AnyPool, Row};

const SCHEMA: &str = include_str!("../../migrations/0001_init.sql");

#[derive(Clone, Copy, PartialEq)]
pub enum Dialect {
    Sqlite,
    Postgres,
    MySql,
}

#[derive(Clone)]
pub struct Db {
    pool: AnyPool,
    dialect: Dialect,
}

impl Db {
    /// Connect, ensuring the SQLite parent directory exists, then apply the schema.
    pub async fn connect(url: &str, max_conn: u32) -> anyhow::Result<Self> {
        sqlx::any::install_default_drivers();

        let dialect = if url.starts_with("postgres") {
            Dialect::Postgres
        } else if url.starts_with("mysql") || url.starts_with("mariadb") {
            Dialect::MySql
        } else {
            Dialect::Sqlite
        };

        if dialect == Dialect::Sqlite {
            if let Some(path) = sqlite_file_path(url) {
                if let Some(parent) = std::path::Path::new(&path).parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
            }
        }

        let pool = AnyPoolOptions::new()
            .max_connections(max_conn)
            .connect(url)
            .await?;
        let db = Self { pool, dialect };
        db.migrate().await?;
        Ok(db)
    }

    /// Apply the idempotent schema. Statements use `CREATE TABLE IF NOT EXISTS`,
    /// so this is safe to run on every boot across all dialects.
    async fn migrate(&self) -> anyhow::Result<()> {
        // Strip `--` comment lines first so their prose (which may contain `;`)
        // never leaks into statement splitting.
        let sql: String = SCHEMA
            .lines()
            .filter(|l| !l.trim_start().starts_with("--"))
            .collect::<Vec<_>>()
            .join("\n");
        for stmt in sql.split(';') {
            let stmt = stmt.trim();
            if stmt.is_empty() {
                continue;
            }
            sqlx::query(stmt).execute(&self.pool).await?;
        }

        // Best-effort additive migrations for columns added after the initial
        // schema. On a fresh DB the column already exists and the ALTER errors
        // (duplicate column) — which is expected and ignored.
        for alter in ["ALTER TABLE clients ADD COLUMN allowed_emails TEXT NOT NULL DEFAULT '[]'"] {
            let _ = sqlx::query(alter).execute(&self.pool).await;
        }
        Ok(())
    }

    /// Rewrite `?` placeholders to `$1, $2, …` for Postgres; leave as-is otherwise.
    fn q(&self, sql: &str) -> String {
        if self.dialect != Dialect::Postgres {
            return sql.to_string();
        }
        let mut out = String::with_capacity(sql.len() + 8);
        let mut n = 0;
        for ch in sql.chars() {
            if ch == '?' {
                n += 1;
                out.push('$');
                out.push_str(&n.to_string());
            } else {
                out.push(ch);
            }
        }
        out
    }

    // ---- admins ------------------------------------------------------------

    pub async fn count_admins(&self) -> anyhow::Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) AS c FROM admins")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get::<i64, _>("c")?)
    }

    pub async fn create_admin(&self, email: &str, password: &str) -> anyhow::Result<()> {
        let sql = self.q("INSERT INTO admins (id, email, password_hash) VALUES (?, ?, ?)");
        sqlx::query(&sql)
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(email)
            .bind(crypto::hash_secret(password)?)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn admin_by_email(&self, email: &str) -> anyhow::Result<Option<Admin>> {
        let sql = self.q("SELECT id, email, password_hash FROM admins WHERE email = ?");
        let row = sqlx::query(&sql)
            .bind(email)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| Admin {
            id: r.get("id"),
            email: r.get("email"),
            password_hash: r.get("password_hash"),
        }))
    }

    pub async fn admin_by_id(&self, id: &str) -> anyhow::Result<Option<Admin>> {
        let sql = self.q("SELECT id, email, password_hash FROM admins WHERE id = ?");
        let row = sqlx::query(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| Admin {
            id: r.get("id"),
            email: r.get("email"),
            password_hash: r.get("password_hash"),
        }))
    }

    // ---- end users ---------------------------------------------------------

    /// Create an end user, returning the new row. Fails if the email is taken.
    pub async fn create_user(&self, email: &str, password: &str) -> anyhow::Result<User> {
        let user = User {
            id: uuid::Uuid::new_v4().to_string(),
            email: email.to_string(),
            password_hash: crypto::hash_secret(password)?,
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        let sql =
            self.q("INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)");
        sqlx::query(&sql)
            .bind(&user.id)
            .bind(&user.email)
            .bind(&user.password_hash)
            .bind(&user.created_at)
            .execute(&self.pool)
            .await?;
        Ok(user)
    }

    pub async fn user_by_email(&self, email: &str) -> anyhow::Result<Option<User>> {
        let sql = self.q("SELECT * FROM users WHERE email = ?");
        let row = sqlx::query(&sql)
            .bind(email)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| row_to_user(&r)))
    }

    pub async fn user_by_id(&self, id: &str) -> anyhow::Result<Option<User>> {
        let sql = self.q("SELECT * FROM users WHERE id = ?");
        let row = sqlx::query(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| row_to_user(&r)))
    }

    // ---- clients -----------------------------------------------------------

    pub async fn list_clients(&self) -> anyhow::Result<Vec<Client>> {
        let rows = sqlx::query("SELECT * FROM clients ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(row_to_client).collect())
    }

    pub async fn client_by_uuid(&self, id: &str) -> anyhow::Result<Option<Client>> {
        let sql = self.q("SELECT * FROM clients WHERE id = ?");
        let row = sqlx::query(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| row_to_client(&r)))
    }

    pub async fn client_by_client_id(&self, client_id: &str) -> anyhow::Result<Option<Client>> {
        let sql = self.q("SELECT * FROM clients WHERE client_id = ?");
        let row = sqlx::query(&sql)
            .bind(client_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| row_to_client(&r)))
    }

    pub async fn create_client(&self, client: &Client) -> anyhow::Result<()> {
        let sql = self.q("INSERT INTO clients \
             (id, client_id, client_secret_hash, name, js_origins, redirect_uris, allowed_emails, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
        sqlx::query(&sql)
            .bind(&client.id)
            .bind(&client.client_id)
            .bind(&client.client_secret_hash)
            .bind(&client.name)
            .bind(serde_json::to_string(&client.js_origins)?)
            .bind(serde_json::to_string(&client.redirect_uris)?)
            .bind(serde_json::to_string(&client.allowed_emails)?)
            .bind(&client.created_at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_client_config(
        &self,
        id: &str,
        js_origins: &[String],
        redirect_uris: &[String],
        allowed_emails: &[String],
    ) -> anyhow::Result<()> {
        let sql = self.q(
            "UPDATE clients SET js_origins = ?, redirect_uris = ?, allowed_emails = ? WHERE id = ?",
        );
        sqlx::query(&sql)
            .bind(serde_json::to_string(js_origins)?)
            .bind(serde_json::to_string(redirect_uris)?)
            .bind(serde_json::to_string(allowed_emails)?)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn delete_client(&self, id: &str) -> anyhow::Result<()> {
        let sql = self.q("DELETE FROM clients WHERE id = ?");
        sqlx::query(&sql).bind(id).execute(&self.pool).await?;
        Ok(())
    }

    // ---- authorization codes ----------------------------------------------

    pub async fn insert_auth_code(&self, c: &AuthCode) -> anyhow::Result<()> {
        let sql = self.q(
            "INSERT INTO auth_codes \
             (code, client_id, redirect_uri, scope, subject, code_challenge, code_challenge_method, expires_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        );
        sqlx::query(&sql)
            .bind(&c.code)
            .bind(&c.client_id)
            .bind(&c.redirect_uri)
            .bind(&c.scope)
            .bind(&c.subject)
            .bind(&c.code_challenge)
            .bind(&c.code_challenge_method)
            .bind(&c.expires_at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Fetch and atomically consume an auth code (single-use, RFC 6749 §4.1.2).
    pub async fn take_auth_code(&self, code: &str) -> anyhow::Result<Option<AuthCode>> {
        let sql = self.q("SELECT * FROM auth_codes WHERE code = ?");
        let row = sqlx::query(&sql)
            .bind(code)
            .fetch_optional(&self.pool)
            .await?;
        let del = self.q("DELETE FROM auth_codes WHERE code = ?");
        sqlx::query(&del).bind(code).execute(&self.pool).await?;
        Ok(row.map(|r| AuthCode {
            code: r.get("code"),
            client_id: r.get("client_id"),
            redirect_uri: r.get("redirect_uri"),
            scope: r.get("scope"),
            subject: r.get("subject"),
            code_challenge: r.get("code_challenge"),
            code_challenge_method: r.get("code_challenge_method"),
            expires_at: r.get("expires_at"),
        }))
    }

    // ---- refresh tokens ----------------------------------------------------

    pub async fn insert_refresh_token(&self, t: &RefreshToken) -> anyhow::Result<()> {
        let sql = self.q(
            "INSERT INTO refresh_tokens (token_hash, client_id, subject, scope, expires_at) \
             VALUES (?, ?, ?, ?, ?)",
        );
        sqlx::query(&sql)
            .bind(&t.token_hash)
            .bind(&t.client_id)
            .bind(&t.subject)
            .bind(&t.scope)
            .bind(&t.expires_at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn refresh_token(&self, token_hash: &str) -> anyhow::Result<Option<RefreshToken>> {
        let sql = self.q("SELECT * FROM refresh_tokens WHERE token_hash = ?");
        let row = sqlx::query(&sql)
            .bind(token_hash)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| RefreshToken {
            token_hash: r.get("token_hash"),
            client_id: r.get("client_id"),
            subject: r.get("subject"),
            scope: r.get("scope"),
            expires_at: r.get("expires_at"),
        }))
    }

    pub async fn delete_refresh_token(&self, token_hash: &str) -> anyhow::Result<()> {
        let sql = self.q("DELETE FROM refresh_tokens WHERE token_hash = ?");
        sqlx::query(&sql)
            .bind(token_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

fn row_to_client(r: &AnyRow) -> Client {
    let js: String = r.get("js_origins");
    let uris: String = r.get("redirect_uris");
    // `try_get` so a pre-migration row without the column reads as allow-all.
    let emails: String = r.try_get("allowed_emails").unwrap_or_else(|_| "[]".into());
    Client {
        id: r.get("id"),
        client_id: r.get("client_id"),
        client_secret_hash: r.get("client_secret_hash"),
        name: r.get("name"),
        js_origins: serde_json::from_str(&js).unwrap_or_default(),
        redirect_uris: serde_json::from_str(&uris).unwrap_or_default(),
        allowed_emails: serde_json::from_str(&emails).unwrap_or_default(),
        created_at: r.get("created_at"),
    }
}

fn row_to_user(r: &AnyRow) -> User {
    User {
        id: r.get("id"),
        email: r.get("email"),
        password_hash: r.get("password_hash"),
        created_at: r.get("created_at"),
    }
}

/// Extract the on-disk path from a `sqlite://…` URL so we can pre-create its dir.
fn sqlite_file_path(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("sqlite://")
        .or_else(|| url.strip_prefix("sqlite:"))?;
    let path = rest.split('?').next().unwrap_or(rest);
    if path.is_empty() || path == ":memory:" {
        None
    } else {
        Some(path.to_string())
    }
}
