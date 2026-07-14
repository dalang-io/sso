# Deployment

Dalang SSO ships as a single static binary plus a `.env`. It serves plain HTTP
and is designed to run behind a TLS-terminating reverse proxy.

## Production hosts

The project's production servers (either address reaches the same box):

- IPv4: `root@163.128.55.121`
- IPv6: `root@2001:df6:d2c0:4::121`

## One-command deploy

```bash
# builds a release binary, uploads it + systemd unit, (re)starts the service
./deploy/deploy.sh
# target a specific host:
SSO_HOST=root@2001:df6:d2c0:4::121 ./deploy/deploy.sh
```

`deploy.sh` never overwrites a remote `.env`. On first deploy it seeds
`.env.example` to `/opt/dalang-sso/.env` — **edit it on the server and set real
secrets before the first real start**:

```bash
ssh root@163.128.55.121
cd /opt/dalang-sso
openssl rand -hex 32                 # -> SSO_SESSION_SECRET
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out jwt_private.pem
$EDITOR .env                         # set secrets, SSO_PUBLIC_URL, DATABASE_URL, admin creds
systemctl restart sso
```

## TLS / reverse proxy (required for real use)

The server binds `127.0.0.1:8080` (see `deploy/sso.service`). Terminate TLS in
front of it:

- **Caddy** (simplest, auto-certs + PQC hybrid KEM): use `deploy/Caddyfile`.
- **Nginx** (OpenSSL ≥ 3.5): `proxy_pass http://127.0.0.1:8080;` and enable
  `ssl_ecdh_curve X25519MLKEM768:X25519;` for post-quantum key exchange.

`SSO_PUBLIC_URL` in `.env` must equal the public HTTPS origin — it becomes the
OIDC `issuer` and the base for all advertised endpoints.

## Scaling to many nodes

The app tier is stateless (JWT verification needs no DB; the admin session is a
signed cookie). To scale:

1. Point `DATABASE_URL` at Postgres/MySQL (see `docs/DATABASE.md`), not SQLite.
2. Run the binary on N nodes behind a load balancer.
3. Share the **same** `SSO_SESSION_SECRET` and JWT signing key across nodes so
   cookies and tokens verify everywhere.

See `docs/DATABASE.md` for the storage-scaling notes and `docs/PQC.md` for the
post-quantum posture.
