# Database backends

Dalang SSO stores everything through a single `sqlx::Any` connection pool, so
the driver is chosen **at runtime** from the `DATABASE_URL` scheme — no
recompile to switch. SQLite is the zero-dependency default.

```env
# Embedded SQLite (default) — the file and its parent dir are auto-created
DATABASE_URL=sqlite://data/sso.db?mode=rwc

# PostgreSQL
DATABASE_URL=postgres://user:pass@host:5432/sso

# MySQL / MariaDB (same driver)
DATABASE_URL=mysql://user:pass@host:3306/sso
```

## Portability rules (why one schema runs everywhere)

`crates/server/migrations/0001_init.sql` sticks to the SQL subset common to all
three dialects. The code (`crates/server/src/db/mod.rs`) enforces:

- **IDs** are UUID *strings*; **timestamps** are RFC3339 *TEXT* generated in
  Rust (never `now()`); **booleans** are `0/1` INTEGER; **lists** (origins,
  redirect URIs) are JSON TEXT.
- Bind placeholders are written `?` and rewritten to `$1, $2, …` for Postgres
  by `Db::q()`.
- Schema is applied idempotently with `CREATE TABLE IF NOT EXISTS` on every
  boot.

Adding a column? Keep it in the portable subset, or branch on `self.dialect`.

## Scaling

- Access/id tokens are stateless JWTs — verifying them touches **no** database.
  Only refresh-token issuance/rotation and client lookups hit storage.
- For Postgres/MySQL, run read replicas and point additional SSO nodes at them;
  the app tier is stateless and scales horizontally behind a load balancer.
- Tune `DATABASE_MAX_CONNECTIONS` per node (pool size × node count must stay
  under the server's connection limit).

## Oracle / MSSQL (roadmap)

`sqlx` has no Oracle or SQL Server driver, so they are intentionally outside the
`Any` pool. The storage layer is a single struct (`Db`) with a small method
surface; an Oracle/MSSQL backend plugs in behind the same methods using a
dedicated driver (e.g. `oracle`, `tiberius`) selected by URL scheme. Until then,
`oracle://` / `mssql://` URLs are rejected at startup.
