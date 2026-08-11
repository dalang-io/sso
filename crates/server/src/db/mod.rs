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
use crate::models::{Admin, AuthCode, Client, ClientSecret, RefreshToken, Tenant, User};
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
        for alter in [
            "ALTER TABLE clients ADD COLUMN allowed_emails TEXT NOT NULL DEFAULT '[]'",
            "ALTER TABLE admins ADD COLUMN role VARCHAR(16) NOT NULL DEFAULT 'manager'",
            "ALTER TABLE admins ADD COLUMN tenant_id VARCHAR(36)",
            "ALTER TABLE clients ADD COLUMN tenant_id VARCHAR(36)",
            "ALTER TABLE auth_codes ADD COLUMN nonce VARCHAR(255)",
            "ALTER TABLE refresh_tokens ADD COLUMN family_id VARCHAR(64) NOT NULL DEFAULT ''",
            "ALTER TABLE refresh_tokens ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE users ADD COLUMN roles TEXT NOT NULL DEFAULT '[]'",
            "ALTER TABLE users ADD COLUMN groups TEXT NOT NULL DEFAULT '[]'",
            "ALTER TABLE users ADD COLUMN attributes TEXT NOT NULL DEFAULT '{}'",
            "ALTER TABLE clients ADD COLUMN include_roles INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE clients ADD COLUMN include_groups INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE clients ADD COLUMN include_attributes INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE clients ADD COLUMN enable_authorization INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE clients ADD COLUMN resources TEXT NOT NULL DEFAULT '[]'",
            "ALTER TABLE clients ADD COLUMN policies TEXT NOT NULL DEFAULT '[]'",
            "ALTER TABLE clients ADD COLUMN require_mfa INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE clients ADD COLUMN client_roles TEXT NOT NULL DEFAULT '[]'",
            "ALTER TABLE clients ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE users ADD COLUMN totp_secret VARCHAR(64)",
            "ALTER TABLE users ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1",
        ] {
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

    /// Create an admin with the given role and tenant (`tenant_id` None for super).
    pub async fn create_admin(
        &self,
        email: &str,
        password: &str,
        role: &str,
        tenant_id: Option<&str>,
    ) -> anyhow::Result<Admin> {
        let admin = Admin {
            id: uuid::Uuid::new_v4().to_string(),
            email: email.to_string(),
            password_hash: crypto::hash_secret(password)?,
            role: role.to_string(),
            tenant_id: tenant_id.map(|s| s.to_string()),
        };
        let sql = self.q(
            "INSERT INTO admins (id, email, password_hash, role, tenant_id) VALUES (?, ?, ?, ?, ?)",
        );
        sqlx::query(&sql)
            .bind(&admin.id)
            .bind(&admin.email)
            .bind(&admin.password_hash)
            .bind(&admin.role)
            .bind(&admin.tenant_id)
            .execute(&self.pool)
            .await?;
        Ok(admin)
    }

    /// List all members (super-admin view), newest tenants' first by email.
    pub async fn list_admins(&self) -> anyhow::Result<Vec<Admin>> {
        let rows = sqlx::query("SELECT * FROM admins ORDER BY email ASC")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(row_to_admin).collect())
    }

    pub async fn delete_admin(&self, id: &str) -> anyhow::Result<()> {
        let sql = self.q("DELETE FROM admins WHERE id = ?");
        sqlx::query(&sql).bind(id).execute(&self.pool).await?;
        Ok(())
    }

    /// Set a member's role. Returns `false` if the member doesn't exist.
    pub async fn update_admin_role(&self, id: &str, role: &str) -> anyhow::Result<bool> {
        let sql = self.q("UPDATE admins SET role = ? WHERE id = ?");
        let res = sqlx::query(&sql)
            .bind(role)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    // ---- tenants -----------------------------------------------------------

    pub async fn count_tenants(&self) -> anyhow::Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) AS c FROM tenants")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get::<i64, _>("c")?)
    }

    pub async fn list_tenants(&self) -> anyhow::Result<Vec<Tenant>> {
        let rows = sqlx::query("SELECT * FROM tenants ORDER BY created_at ASC")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(row_to_tenant).collect())
    }

    pub async fn tenant_by_id(&self, id: &str) -> anyhow::Result<Option<Tenant>> {
        let sql = self.q("SELECT * FROM tenants WHERE id = ?");
        let row = sqlx::query(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| row_to_tenant(&r)))
    }

    pub async fn create_tenant(&self, name: &str) -> anyhow::Result<Tenant> {
        let tenant = Tenant {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        let sql = self.q("INSERT INTO tenants (id, name, created_at) VALUES (?, ?, ?)");
        sqlx::query(&sql)
            .bind(&tenant.id)
            .bind(&tenant.name)
            .bind(&tenant.created_at)
            .execute(&self.pool)
            .await?;
        Ok(tenant)
    }

    pub async fn delete_tenant(&self, id: &str) -> anyhow::Result<()> {
        let sql = self.q("DELETE FROM tenants WHERE id = ?");
        sqlx::query(&sql).bind(id).execute(&self.pool).await?;
        Ok(())
    }

    /// Return an existing tenant id, creating a "Default" tenant if none exist.
    pub async fn ensure_default_tenant(&self) -> anyhow::Result<String> {
        if let Some(t) = self.list_tenants().await?.into_iter().next() {
            return Ok(t.id);
        }
        Ok(self.create_tenant("Default").await?.id)
    }

    pub async fn admin_by_email(&self, email: &str) -> anyhow::Result<Option<Admin>> {
        let sql = self.q("SELECT * FROM admins WHERE email = ?");
        let row = sqlx::query(&sql)
            .bind(email)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| row_to_admin(&r)))
    }

    pub async fn admin_by_id(&self, id: &str) -> anyhow::Result<Option<Admin>> {
        let sql = self.q("SELECT * FROM admins WHERE id = ?");
        let row = sqlx::query(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| row_to_admin(&r)))
    }

    // ---- end users ---------------------------------------------------------

    /// Create an end user, returning the new row. Fails if the email is taken.
    pub async fn create_user(&self, email: &str, password: &str) -> anyhow::Result<User> {
        let user = User {
            id: uuid::Uuid::new_v4().to_string(),
            email: email.to_string(),
            password_hash: crypto::hash_secret(password)?,
            created_at: chrono::Utc::now().to_rfc3339(),
            roles: vec![],
            groups: vec![],
            attributes: std::collections::BTreeMap::new(),
            totp_secret: None,
            enabled: true,
        };
        // `roles/groups/attributes` default to '[]'/'{}' via the schema; a fresh
        // account has no fine-grained authorization until an admin assigns it.
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

    /// List all end users, newest first (super-admin view).
    pub async fn list_users(&self) -> anyhow::Result<Vec<User>> {
        let rows = sqlx::query("SELECT * FROM users ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(row_to_user).collect())
    }

    /// Update a user's fine-grained authorization (roles, groups, attributes).
    /// Returns `false` if no user with `id` exists.
    pub async fn update_user(
        &self,
        id: &str,
        roles: &[String],
        groups: &[String],
        attributes: &std::collections::BTreeMap<String, String>,
    ) -> anyhow::Result<bool> {
        let sql = self.q("UPDATE users SET roles = ?, groups = ?, attributes = ? WHERE id = ?");
        let res = sqlx::query(&sql)
            .bind(serde_json::to_string(roles)?)
            .bind(serde_json::to_string(groups)?)
            .bind(serde_json::to_string(attributes)?)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Enable (`Some(secret)`) or disable (`None`) a user's TOTP enrollment.
    /// Returns `false` if no user with `id` exists.
    pub async fn update_user_totp(&self, id: &str, secret: Option<&str>) -> anyhow::Result<bool> {
        let sql = self.q("UPDATE users SET totp_secret = ? WHERE id = ?");
        let res = sqlx::query(&sql)
            .bind(secret)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Update a user's password (plaintext is hashed before storage).
    pub async fn update_user_password(&self, id: &str, new_password: &str) -> anyhow::Result<()> {
        let hash = crypto::hash_secret(new_password)?;
        let sql = self.q("UPDATE users SET password_hash = ? WHERE id = ?");
        sqlx::query(&sql)
            .bind(&hash)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Enable or disable a user account. Returns `false` if not found.
    pub async fn set_user_enabled(&self, id: &str, enabled: bool) -> anyhow::Result<bool> {
        let sql = self.q("UPDATE users SET enabled = ? WHERE id = ?");
        let res = sqlx::query(&sql)
            .bind(enabled as i32)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Delete an end user and their dependent rows. Returns `false` if absent.
    pub async fn delete_user(&self, id: &str) -> anyhow::Result<bool> {
        let sql = self.q("DELETE FROM users WHERE id = ?");
        let res = sqlx::query(&sql).bind(id).execute(&self.pool).await?;
        let csql = self.q("DELETE FROM user_client_roles WHERE user_id = ?");
        sqlx::query(&csql).bind(id).execute(&self.pool).await?;
        Ok(res.rows_affected() > 0)
    }

    /// Add `role` to a user's roles (by email). No-op if already present.
    pub async fn assign_role_to_user(&self, email: &str, role: &str) -> anyhow::Result<()> {
        self.add_to_user_list(email, "roles", role).await
    }
    pub async fn remove_role_from_user(&self, email: &str, role: &str) -> anyhow::Result<()> {
        self.remove_from_user_list(email, "roles", role).await
    }
    pub async fn assign_group_to_user(&self, email: &str, group: &str) -> anyhow::Result<()> {
        self.add_to_user_list(email, "groups", group).await
    }
    pub async fn remove_group_from_user(&self, email: &str, group: &str) -> anyhow::Result<()> {
        self.remove_from_user_list(email, "groups", group).await
    }

    async fn add_to_user_list(&self, email: &str, col: &str, value: &str) -> anyhow::Result<()> {
        let Some(user) = self.user_by_email(email).await? else {
            return Ok(());
        };
        let mut list = user_roles_or_groups(&user, col);
        if !list.iter().any(|r| r == value) {
            list.push(value.to_string());
            self.write_user_list(email, col, &list).await?;
        }
        Ok(())
    }

    async fn remove_from_user_list(
        &self,
        email: &str,
        col: &str,
        value: &str,
    ) -> anyhow::Result<()> {
        let Some(user) = self.user_by_email(email).await? else {
            return Ok(());
        };
        let list: Vec<String> = user_roles_or_groups(&user, col)
            .into_iter()
            .filter(|r| r != value)
            .collect();
        self.write_user_list(email, col, &list).await?;
        Ok(())
    }

    async fn write_user_list(&self, email: &str, col: &str, list: &[String]) -> anyhow::Result<()> {
        let sql = self.q(&format!("UPDATE users SET {col} = ? WHERE email = ?"));
        sqlx::query(&sql)
            .bind(serde_json::to_string(list)?)
            .bind(email)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ---- role / group catalogs --------------------------------------------

    pub async fn list_roles(&self) -> anyhow::Result<Vec<crate::models::Role>> {
        let rows = sqlx::query("SELECT * FROM roles ORDER BY name ASC")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(row_to_role).collect())
    }

    /// Create a role catalog entry. Returns `false` if the name is taken.
    pub async fn create_role(&self, name: &str) -> anyhow::Result<bool> {
        self.create_catalog("roles", name).await
    }

    pub async fn delete_role(&self, name: &str) -> anyhow::Result<()> {
        self.delete_catalog("roles", name).await
    }

    pub async fn list_groups(&self) -> anyhow::Result<Vec<crate::models::Group>> {
        let rows = sqlx::query("SELECT * FROM user_groups ORDER BY name ASC")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(row_to_group).collect())
    }

    /// Create a group catalog entry. Returns `false` if the name is taken.
    pub async fn create_group(&self, name: &str) -> anyhow::Result<bool> {
        self.create_catalog("user_groups", name).await
    }

    pub async fn delete_group(&self, name: &str) -> anyhow::Result<()> {
        self.delete_catalog("user_groups", name).await
    }

    async fn create_catalog(&self, table: &str, name: &str) -> anyhow::Result<bool> {
        let sql = self.q(&format!("INSERT INTO {table} (id, name) VALUES (?, ?)"));
        let res = sqlx::query(&sql)
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(name)
            .execute(&self.pool)
            .await;
        match res {
            Ok(_) => Ok(true),
            Err(_) => Ok(false), // duplicate/constraint -> name taken
        }
    }

    async fn delete_catalog(&self, table: &str, name: &str) -> anyhow::Result<()> {
        let sql = self.q(&format!("DELETE FROM {table} WHERE name = ?"));
        sqlx::query(&sql).bind(name).execute(&self.pool).await?;
        Ok(())
    }

    // ---- sessions ---------------------------------------------------------

    /// Record an active session for a successfully-issued user token.
    pub async fn insert_session(&self, s: &crate::models::Session) -> anyhow::Result<()> {
        let sql = self.q(
            "INSERT INTO sessions (id, email, client_id, user_agent, ip, created_at, expires_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        );
        sqlx::query(&sql)
            .bind(&s.id)
            .bind(&s.email)
            .bind(&s.client_id)
            .bind(&s.user_agent)
            .bind(&s.ip)
            .bind(&s.created_at)
            .bind(&s.expires_at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// List all active sessions, newest first.
    pub async fn list_sessions(&self) -> anyhow::Result<Vec<crate::models::Session>> {
        let rows = sqlx::query("SELECT * FROM sessions ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(row_to_session).collect())
    }

    pub async fn delete_session(&self, id: &str) -> anyhow::Result<()> {
        let sql = self.q("DELETE FROM sessions WHERE id = ?");
        sqlx::query(&sql).bind(id).execute(&self.pool).await?;
        Ok(())
    }

    /// Revoke all sessions for an end user (e.g. after disabling/reset).
    pub async fn delete_sessions_for(&self, email: &str) -> anyhow::Result<()> {
        let sql = self.q("DELETE FROM sessions WHERE email = ?");
        sqlx::query(&sql).bind(email).execute(&self.pool).await?;
        Ok(())
    }

    // ---- audit log --------------------------------------------------------

    /// Append an audit-log event.
    pub async fn write_audit(
        &self,
        actor: &str,
        action: &str,
        detail: &str,
        client_id: Option<&str>,
    ) -> anyhow::Result<()> {
        let evt = crate::models::AuditEvent {
            id: uuid::Uuid::new_v4().to_string(),
            at: chrono::Utc::now().to_rfc3339(),
            actor: actor.to_string(),
            action: action.to_string(),
            detail: (!detail.is_empty()).then(|| detail.to_string()),
            client_id: client_id.map(|s| s.to_string()),
        };
        let sql = self.q(
            "INSERT INTO audit_log (id, at, actor, action, detail, client_id) VALUES (?, ?, ?, ?, ?, ?)",
        );
        sqlx::query(&sql)
            .bind(&evt.id)
            .bind(&evt.at)
            .bind(&evt.actor)
            .bind(&evt.action)
            .bind(&evt.detail)
            .bind(&evt.client_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Most recent audit events, newest first, capped at `limit`.
    pub async fn list_audit(&self, limit: i64) -> anyhow::Result<Vec<crate::models::AuditEvent>> {
        let rows = sqlx::query("SELECT * FROM audit_log ORDER BY at DESC LIMIT ?")
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(row_to_audit).collect())
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
        // `client_secret_hash` is a legacy NOT NULL column kept for schema
        // compatibility; secrets now live in `client_secrets`. Bind an empty value.
        let sql = self.q("INSERT INTO clients \
             (id, client_id, client_secret_hash, tenant_id, name, js_origins, redirect_uris, allowed_emails, \
              include_roles, include_groups, include_attributes, enable_authorization, resources, policies, client_roles, require_mfa, enabled, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        sqlx::query(&sql)
            .bind(&client.id)
            .bind(&client.client_id)
            .bind("")
            .bind(&client.tenant_id)
            .bind(&client.name)
            .bind(serde_json::to_string(&client.js_origins)?)
            .bind(serde_json::to_string(&client.redirect_uris)?)
            .bind(serde_json::to_string(&client.allowed_emails)?)
            .bind(client.include_roles as i32)
            .bind(client.include_groups as i32)
            .bind(client.include_attributes as i32)
            .bind(client.enable_authorization as i32)
            .bind(serde_json::to_string(&client.resources)?)
            .bind(serde_json::to_string(&client.policies)?)
            .bind(serde_json::to_string(&client.client_roles)?)
            .bind(client.require_mfa as i32)
            .bind(client.enabled as i32)
            .bind(&client.created_at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Clients owned by a single tenant (manager/developer view).
    pub async fn list_clients_for_tenant(&self, tenant_id: &str) -> anyhow::Result<Vec<Client>> {
        let sql = self.q("SELECT * FROM clients WHERE tenant_id = ? ORDER BY created_at DESC");
        let rows = sqlx::query(&sql)
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(row_to_client).collect())
    }

    /// Update a client's resource-based authorization config.
    pub async fn update_client_authz(
        &self,
        id: &str,
        enable: bool,
        resources: &[crate::models::ClientResource],
        policies: &[crate::models::Policy],
    ) -> anyhow::Result<()> {
        let sql = self.q(
            "UPDATE clients SET enable_authorization = ?, resources = ?, policies = ? WHERE id = ?",
        );
        sqlx::query(&sql)
            .bind(enable as i32)
            .bind(serde_json::to_string(resources)?)
            .bind(serde_json::to_string(policies)?)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Toggle whether a client requires two-factor authentication for its users.
    pub async fn update_client_mfa(&self, id: &str, require_mfa: bool) -> anyhow::Result<()> {
        let sql = self.q("UPDATE clients SET require_mfa = ? WHERE id = ?");
        sqlx::query(&sql)
            .bind(require_mfa as i32)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Set a client's role catalog (client roles).
    pub async fn update_client_roles(&self, id: &str, roles: &[String]) -> anyhow::Result<()> {
        let sql = self.q("UPDATE clients SET client_roles = ? WHERE id = ?");
        sqlx::query(&sql)
            .bind(serde_json::to_string(roles)?)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Enable or disable a client. Disabled clients cannot authorize/token.
    pub async fn set_client_enabled(&self, id: &str, enabled: bool) -> anyhow::Result<()> {
        let sql = self.q("UPDATE clients SET enabled = ? WHERE id = ?");
        sqlx::query(&sql)
            .bind(enabled as i32)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Grant a client-scoped role to a user. Returns true if newly granted,
    /// false if it was already present. Not atomic (admin-only, low race).
    pub async fn grant_client_role(
        &self,
        user_id: &str,
        client_id: &str,
        role: &str,
    ) -> anyhow::Result<bool> {
        let exists_sql = self.q(
            "SELECT COUNT(*) AS c FROM user_client_roles WHERE user_id = ? AND client_id = ? AND role = ?",
        );
        let row = sqlx::query(&exists_sql)
            .bind(user_id)
            .bind(client_id)
            .bind(role)
            .fetch_one(&self.pool)
            .await?;
        let exists: i64 = row.try_get("c")?;
        if exists > 0 {
            return Ok(false);
        }
        let sql =
            self.q("INSERT INTO user_client_roles (user_id, client_id, role) VALUES (?, ?, ?)");
        sqlx::query(&sql)
            .bind(user_id)
            .bind(client_id)
            .bind(role)
            .execute(&self.pool)
            .await?;
        Ok(true)
    }

    /// Revoke a client-scoped role from a user.
    pub async fn revoke_client_role(
        &self,
        user_id: &str,
        client_id: &str,
        role: &str,
    ) -> anyhow::Result<()> {
        let sql = self
            .q("DELETE FROM user_client_roles WHERE user_id = ? AND client_id = ? AND role = ?");
        sqlx::query(&sql)
            .bind(user_id)
            .bind(client_id)
            .bind(role)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// All client-scoped roles granted to a user, as (client_id, role) pairs.
    pub async fn client_roles_for_user(
        &self,
        user_id: &str,
    ) -> anyhow::Result<Vec<(String, String)>> {
        let sql = self.q("SELECT client_id, role FROM user_client_roles WHERE user_id = ?");
        let rows = sqlx::query(&sql)
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .iter()
            .map(|r| (r.get::<String, _>("client_id"), r.get::<String, _>("role")))
            .collect())
    }

    // ---- client secrets ----------------------------------------------------

    /// List a client's secrets, oldest first.
    pub async fn list_client_secrets(
        &self,
        client_uuid: &str,
    ) -> anyhow::Result<Vec<ClientSecret>> {
        let sql =
            self.q("SELECT * FROM client_secrets WHERE client_id = ? ORDER BY created_at ASC");
        let rows = sqlx::query(&sql)
            .bind(client_uuid)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(row_to_secret).collect())
    }

    /// Add a secret to a client. Returns the stored row (not the plaintext).
    pub async fn add_client_secret(
        &self,
        client_uuid: &str,
        hint: &str,
        secret_hash: &str,
    ) -> anyhow::Result<ClientSecret> {
        let secret = ClientSecret {
            id: uuid::Uuid::new_v4().to_string(),
            client_id: client_uuid.to_string(),
            hint: hint.to_string(),
            secret_hash: secret_hash.to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        let sql = self.q(
            "INSERT INTO client_secrets (id, client_id, hint, secret_hash, created_at) \
             VALUES (?, ?, ?, ?, ?)",
        );
        sqlx::query(&sql)
            .bind(&secret.id)
            .bind(&secret.client_id)
            .bind(&secret.hint)
            .bind(&secret.secret_hash)
            .bind(&secret.created_at)
            .execute(&self.pool)
            .await?;
        Ok(secret)
    }

    /// Delete one secret, scoped to its client (so an id from another client can't be removed).
    pub async fn delete_client_secret(
        &self,
        client_uuid: &str,
        secret_id: &str,
    ) -> anyhow::Result<()> {
        let sql = self.q("DELETE FROM client_secrets WHERE id = ? AND client_id = ?");
        sqlx::query(&sql)
            .bind(secret_id)
            .bind(client_uuid)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Delete all of a client's secrets (used when the client itself is deleted).
    async fn delete_client_secrets(&self, client_uuid: &str) -> anyhow::Result<()> {
        let sql = self.q("DELETE FROM client_secrets WHERE client_id = ?");
        sqlx::query(&sql)
            .bind(client_uuid)
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
        claims: &crate::models::ClientClaims,
    ) -> anyhow::Result<()> {
        let sql = self.q(
            "UPDATE clients SET js_origins = ?, redirect_uris = ?, allowed_emails = ?, \
             include_roles = ?, include_groups = ?, include_attributes = ? WHERE id = ?",
        );
        sqlx::query(&sql)
            .bind(serde_json::to_string(js_origins)?)
            .bind(serde_json::to_string(redirect_uris)?)
            .bind(serde_json::to_string(allowed_emails)?)
            .bind(claims.include_roles as i32)
            .bind(claims.include_groups as i32)
            .bind(claims.include_attributes as i32)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn delete_client(&self, id: &str) -> anyhow::Result<()> {
        self.delete_client_secrets(id).await?;
        let sql = self.q("DELETE FROM clients WHERE id = ?");
        sqlx::query(&sql).bind(id).execute(&self.pool).await?;
        Ok(())
    }

    // ---- authorization codes ----------------------------------------------

    pub async fn insert_auth_code(&self, c: &AuthCode) -> anyhow::Result<()> {
        let sql = self.q(
            "INSERT INTO auth_codes \
             (code, client_id, redirect_uri, scope, subject, code_challenge, code_challenge_method, nonce, expires_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        );
        sqlx::query(&sql)
            .bind(&c.code)
            .bind(&c.client_id)
            .bind(&c.redirect_uri)
            .bind(&c.scope)
            .bind(&c.subject)
            .bind(&c.code_challenge)
            .bind(&c.code_challenge_method)
            .bind(&c.nonce)
            .bind(&c.expires_at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Fetch and atomically consume an auth code (single-use, RFC 6749 §4.1.2).
    ///
    /// The DELETE is the point of serialization: under concurrent redemption of
    /// the same code, exactly one caller sees `rows_affected == 1` and receives
    /// the code; every other caller sees 0 and is told the code is unknown/used.
    /// This closes the SELECT-then-DELETE replay race.
    pub async fn take_auth_code(&self, code: &str) -> anyhow::Result<Option<AuthCode>> {
        let sql = self.q("SELECT * FROM auth_codes WHERE code = ?");
        let Some(r) = sqlx::query(&sql)
            .bind(code)
            .fetch_optional(&self.pool)
            .await?
        else {
            return Ok(None);
        };
        let del = self.q("DELETE FROM auth_codes WHERE code = ?");
        let res = sqlx::query(&del).bind(code).execute(&self.pool).await?;
        if res.rows_affected() != 1 {
            // A concurrent request already claimed this code.
            return Ok(None);
        }
        Ok(Some(AuthCode {
            code: r.get("code"),
            client_id: r.get("client_id"),
            redirect_uri: r.get("redirect_uri"),
            scope: r.get("scope"),
            subject: r.get("subject"),
            code_challenge: r.get("code_challenge"),
            code_challenge_method: r.get("code_challenge_method"),
            nonce: r.try_get("nonce").ok(),
            expires_at: r.get("expires_at"),
        }))
    }

    // ---- refresh tokens ----------------------------------------------------

    pub async fn insert_refresh_token(&self, t: &RefreshToken) -> anyhow::Result<()> {
        let sql = self.q(
            "INSERT INTO refresh_tokens (token_hash, client_id, subject, scope, family_id, revoked, expires_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        );
        sqlx::query(&sql)
            .bind(&t.token_hash)
            .bind(&t.client_id)
            .bind(&t.subject)
            .bind(&t.scope)
            .bind(&t.family_id)
            .bind(i32::from(t.revoked))
            .bind(&t.expires_at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Look up a refresh token by hash, including revoked tombstones (the caller
    /// needs to see `revoked` to detect reuse).
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
            family_id: r.try_get("family_id").unwrap_or_default(),
            revoked: r.try_get::<i64, _>("revoked").unwrap_or(0) != 0,
            expires_at: r.get("expires_at"),
        }))
    }

    /// Atomically consume (rotate) a refresh token by flipping `revoked` 0→1.
    /// Returns true only for the single caller that won the flip; a false result
    /// means the token was already consumed (concurrent rotation or replay). The
    /// tombstone row is kept so a later reuse of the same token is detectable.
    pub async fn consume_refresh_token(&self, token_hash: &str) -> anyhow::Result<bool> {
        let sql =
            self.q("UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ? AND revoked = 0");
        let res = sqlx::query(&sql)
            .bind(token_hash)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() == 1)
    }

    /// Revoke every token in a rotation lineage — used when reuse is detected.
    pub async fn revoke_refresh_family(&self, family_id: &str) -> anyhow::Result<()> {
        if family_id.is_empty() {
            return Ok(());
        }
        let sql = self.q("UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ?");
        sqlx::query(&sql)
            .bind(family_id)
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
    let resources: String = r.try_get("resources").unwrap_or_else(|_| "[]".into());
    let policies: String = r.try_get("policies").unwrap_or_else(|_| "[]".into());
    Client {
        id: r.get("id"),
        client_id: r.get("client_id"),
        tenant_id: r.try_get("tenant_id").ok(),
        name: r.get("name"),
        js_origins: serde_json::from_str(&js).unwrap_or_default(),
        redirect_uris: serde_json::from_str(&uris).unwrap_or_default(),
        allowed_emails: serde_json::from_str(&emails).unwrap_or_default(),
        include_roles: r.try_get("include_roles").unwrap_or(1) != 0,
        include_groups: r.try_get("include_groups").unwrap_or(1) != 0,
        include_attributes: r.try_get("include_attributes").unwrap_or(1) != 0,
        enable_authorization: r.try_get("enable_authorization").unwrap_or(0) != 0,
        resources: serde_json::from_str(&resources).unwrap_or_default(),
        policies: serde_json::from_str(&policies).unwrap_or_default(),
        require_mfa: r.try_get("require_mfa").unwrap_or(0) != 0,
        enabled: r.try_get("enabled").unwrap_or(1) != 0,
        client_roles: serde_json::from_str(
            &r.try_get::<String, _>("client_roles")
                .unwrap_or_else(|_| "[]".into()),
        )
        .unwrap_or_default(),
        created_at: r.get("created_at"),
    }
}

fn row_to_secret(r: &AnyRow) -> ClientSecret {
    ClientSecret {
        id: r.get("id"),
        client_id: r.get("client_id"),
        hint: r.get("hint"),
        secret_hash: r.get("secret_hash"),
        created_at: r.get("created_at"),
    }
}

fn row_to_admin(r: &AnyRow) -> Admin {
    Admin {
        id: r.get("id"),
        email: r.get("email"),
        password_hash: r.get("password_hash"),
        // Tolerant of pre-migration rows lacking the columns.
        role: r.try_get("role").unwrap_or_else(|_| "manager".into()),
        tenant_id: r.try_get("tenant_id").ok(),
    }
}

fn row_to_tenant(r: &AnyRow) -> Tenant {
    Tenant {
        id: r.get("id"),
        name: r.get("name"),
        created_at: r.get("created_at"),
    }
}

fn row_to_user(r: &AnyRow) -> User {
    User {
        id: r.get("id"),
        email: r.get("email"),
        password_hash: r.get("password_hash"),
        created_at: r.get("created_at"),
        // JSON TEXT columns; tolerate malformed/absent values (default = none).
        roles: json_array(r, "roles"),
        groups: json_array(r, "groups"),
        attributes: json_object(r, "attributes"),
        totp_secret: r.try_get("totp_secret").ok(),
        enabled: r.try_get("enabled").unwrap_or(1) != 0,
    }
}

/// Parse a JSON-array TEXT column into a `Vec<String>`; empty on failure.
fn json_array(r: &AnyRow, col: &str) -> Vec<String> {
    r.try_get::<String, _>(col)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}
/// Parse a JSON-object TEXT column into `BTreeMap<String, String>`; empty on
/// failure. Values are coerced to strings (non-string values are dropped).
fn json_object(r: &AnyRow, col: &str) -> std::collections::BTreeMap<String, String> {
    let raw: Option<String> = r.try_get::<String, _>(col).ok();
    let Some(map) = raw.and_then(|s| serde_json::from_str::<serde_json::Map<_, _>>(&s).ok()) else {
        return std::collections::BTreeMap::new();
    };
    map.into_iter()
        .filter_map(|(k, v)| match v {
            serde_json::Value::String(s) => Some((k, s)),
            serde_json::Value::Bool(b) => Some((k, b.to_string())),
            serde_json::Value::Number(n) => Some((k, n.to_string())),
            _ => None,
        })
        .collect()
}

/// The current roles/groups list for a user (by JSON column name).
fn user_roles_or_groups(u: &crate::models::User, col: &str) -> Vec<String> {
    match col {
        "roles" => u.roles.clone(),
        _ => u.groups.clone(),
    }
}

fn row_to_role(r: &AnyRow) -> crate::models::Role {
    crate::models::Role {
        id: r.get("id"),
        name: r.get("name"),
    }
}

fn row_to_group(r: &AnyRow) -> crate::models::Group {
    crate::models::Group {
        id: r.get("id"),
        name: r.get("name"),
    }
}

fn row_to_session(r: &AnyRow) -> crate::models::Session {
    crate::models::Session {
        id: r.get("id"),
        email: r.get("email"),
        client_id: r.get("client_id"),
        user_agent: r.get("user_agent"),
        ip: r.get("ip"),
        created_at: r.get("created_at"),
        expires_at: r.get("expires_at"),
    }
}

fn row_to_audit(r: &AnyRow) -> crate::models::AuditEvent {
    crate::models::AuditEvent {
        id: r.get("id"),
        at: r.get("at"),
        actor: r.get("actor"),
        action: r.get("action"),
        detail: r.get("detail"),
        client_id: r.get("client_id"),
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
