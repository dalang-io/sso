# Post-Quantum Cryptography (PQC)

Dalang SSO is designed to resist attacks from cryptographically-relevant quantum
computers ("harvest now, decrypt later" and future signature forgery). This
document explains what is quantum-safe today, how to turn on PQC token signing,
and what remains on the roadmap.

## Threat model

A large fault-tolerant quantum computer breaks the hardness assumptions behind
classical public-key crypto:

| Primitive               | Classical algorithm | Quantum risk        | PQC replacement            |
| ----------------------- | ------------------- | ------------------- | -------------------------- |
| Token/id_token signing  | RSA (RS256), ECDSA  | **Broken** (Shor)   | **ML-DSA** (FIPS 204)      |
| TLS key exchange        | ECDH / X25519       | **Broken** (Shor)   | **ML-KEM** (FIPS 203)      |
| Password/secret hashing | Argon2id            | Safe (Grover ≈ ½)   | Argon2id (unchanged)       |
| Token hashing / lookups | SHA-256             | Safe (Grover ≈ ½)   | SHA-256 (unchanged)        |

Symmetric and hash primitives only lose a quadratic factor to Grover's
algorithm; Argon2id and SHA-256 at our sizes keep an ample security margin.
The exposure is in the **public-key** primitives — signatures and key exchange.

## 1. Token signing — ML-DSA (built in)

Access tokens and id_tokens are JWS. The signing algorithm is selectable:

```env
# .env
SSO_TOKEN_SIGNING_ALG=ml-dsa-65   # post-quantum (FIPS 204). Default: rs256
```

- `rs256` (default) — classical RSA, maximum interop with existing OIDC client
  libraries.
- `ml-dsa-65` — [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) ML-DSA
  (a.k.a. CRYSTALS-Dilithium), NIST security category 3. Implemented with the
  audited pure-Rust [`fips204`](https://crates.io/crates/fips204) crate.

When `ml-dsa-65` is active:
- Tokens carry a JOSE header `{"alg":"ML-DSA-65", ...}` (identifier per the
  IETF JOSE/COSE PQC drafts).
- `/.well-known/jwks.json` publishes the public key as an `AKP` (Algorithm Key
  Pair) JWK, and `/.well-known/openid-configuration` advertises
  `id_token_signing_alg_values_supported: ["ML-DSA-65"]`.
- ML-DSA signatures are ~3.3 KB vs ~256 B for RSA-2048 — tokens are larger.
  Keep them in `Authorization` headers / cookies accordingly.

**Interop note:** not every third-party JWT library verifies ML-DSA yet. The
first-party SDKs in `sdks/` verify against the JWKS regardless of algorithm.
For mixed fleets, run classical `rs256` until your relying parties can verify
ML-DSA, or front them with the SDKs.

## 2. TLS key exchange — hybrid ML-KEM (deploy-time)

The SSO server speaks plain HTTP and is meant to sit behind a TLS-terminating
reverse proxy (see `docs/DEPLOY.md`). Configure the proxy for a **hybrid** key
exchange so the handshake is safe against harvest-now-decrypt-later:

- Nginx/OpenSSL 3.5+ or BoringSSL: enable group `X25519MLKEM768`.
- Caddy: PQC hybrid groups are on by default in recent builds.

Hybrid (classical + PQC) is the recommended posture: you stay secure even if one
of the two schemes is later weakened.

## 3. Roadmap

- Persisted ML-DSA signing keys + rotation (today an ephemeral key is generated
  at boot when none is configured).
- Hybrid **signatures** (RSA + ML-DSA dual-sign) for zero-downtime migration of
  relying parties.
- Native TLS in the server with a hybrid KEM (removing the proxy requirement).
- SLH-DSA (FIPS 205) as a hash-based signing alternative.
