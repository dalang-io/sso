//! Token signing abstraction with a post-quantum option.
//!
//! Two backends implement the same JWS surface:
//!   * **RS256** — classical RSA via `jsonwebtoken`; maximum interop with
//!     existing OAuth/OIDC client libraries.
//!   * **ML-DSA-65** — FIPS 204 lattice signatures (post-quantum). We emit a
//!     compact JWS by hand with `alg: "ML-DSA-65"` (the JOSE identifier from
//!     draft-ietf-cose/jose PQC) and publish the key as a JWKS `AKP` entry.
//!
//! The classical hardness that RSA/ECDSA rely on falls to Shor's algorithm on a
//! large quantum computer; ML-DSA does not. Selecting `ml-dsa-65` makes every
//! issued access/id token quantum-resistant. Password + secret hashing (Argon2)
//! and token hashing (SHA-256) are already PQ-safe at these sizes, and the TLS
//! handshake should use a hybrid KEM (X25519MLKEM768) at the proxy — see
//! `docs/PQC.md`.

use crate::crypto::Keys;
use crate::oauth::Claims;
use anyhow::Context;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer as _, Verifier as _};
use sha2::{Digest, Sha256};

/// Header line marking the persisted ML-DSA key file format.
const MLDSA_KEY_MAGIC: &str = "DALANG-MLDSA-65:1";

pub enum Signer {
    Rsa(Keys),
    // Boxed: an ML-DSA keypair is far larger than the RSA `Keys`, so keeping it
    // behind a pointer stops the enum from bloating to the ML-DSA size.
    MlDsa(Box<MlDsaSigner>),
}

impl Signer {
    /// Build the signer selected by `SSO_TOKEN_SIGNING_ALG`.
    pub fn from_config(
        alg: &str,
        rsa_pem_path: Option<&str>,
        mldsa_key_path: Option<&str>,
    ) -> anyhow::Result<Self> {
        match alg {
            "ml-dsa-65" | "mldsa65" | "ml_dsa_65" => {
                tracing::info!("token signing: ML-DSA-65 (post-quantum, FIPS 204)");
                Ok(Signer::MlDsa(Box::new(MlDsaSigner::load_or_generate(
                    mldsa_key_path,
                )?)))
            }
            _ => {
                tracing::info!("token signing: RS256 (classical)");
                Ok(Signer::Rsa(Keys::load_or_generate(rsa_pem_path)?))
            }
        }
    }

    pub fn alg(&self) -> &'static str {
        match self {
            Signer::Rsa(_) => "RS256",
            Signer::MlDsa(_) => "ML-DSA-65",
        }
    }

    /// Sign a claim set into a compact JWS.
    pub fn sign(&self, claims: &Claims) -> anyhow::Result<String> {
        match self {
            Signer::Rsa(keys) => crate::oauth::mint_rsa_jwt(keys, claims),
            Signer::MlDsa(s) => s.sign(claims),
        }
    }

    /// Verify a compact JWS and return its claims (checks signature + iss + exp).
    pub fn verify(&self, token: &str, issuer: &str) -> anyhow::Result<Claims> {
        match self {
            Signer::Rsa(keys) => crate::oauth::verify_rsa_jwt(keys, token, issuer),
            Signer::MlDsa(s) => s.verify(token, issuer),
        }
    }

    /// Public JWKS document for relying parties to verify tokens.
    pub fn jwks(&self) -> serde_json::Value {
        match self {
            Signer::Rsa(keys) => keys.jwks(),
            Signer::MlDsa(s) => s.jwks(),
        }
    }
}

/// ML-DSA-65 keypair plus a stable `kid` and precomputed public-key encoding.
pub struct MlDsaSigner {
    sk: ml_dsa_65::PrivateKey,
    pk: ml_dsa_65::PublicKey,
    pk_b64: String,
    kid: String,
}

impl MlDsaSigner {
    /// Load a persisted keypair from `path`; if the file does not exist, generate
    /// a fresh keypair and persist it so the key (and issued tokens) survive
    /// restarts and are shared across nodes. When `path` is `None`, fall back to
    /// an ephemeral key (dev only) — see the warning.
    pub fn load_or_generate(path: Option<&str>) -> anyhow::Result<Self> {
        match path {
            Some(p) => {
                let file = std::path::Path::new(p);
                if file.exists() {
                    tracing::info!("loading persisted ML-DSA key from {p}");
                    let s = std::fs::read_to_string(p)
                        .with_context(|| format!("reading ML-DSA key at {p}"))?;
                    Self::from_persisted(&s).with_context(|| format!("parsing ML-DSA key at {p}"))
                } else {
                    tracing::info!("no ML-DSA key at {p} — generating and persisting");
                    Self::generate()?.write_to(p)
                }
            }
            None => {
                tracing::warn!(
                    "no SSO_MLDSA_KEY_PATH set — generating an EPHEMERAL ML-DSA key; \
                     tokens become invalid on every restart and nodes disagree"
                );
                Self::generate()
            }
        }
    }

    pub fn generate() -> anyhow::Result<Self> {
        let (pk, sk) =
            ml_dsa_65::try_keygen().map_err(|e| anyhow::anyhow!("ml-dsa keygen: {e}"))?;
        Self::from_parts(pk, sk)
    }

    /// Build a signer from an already-expanded keypair, deriving the canonical
    /// byte encodings, base64 public key, and `kid`.
    fn from_parts(pk: ml_dsa_65::PublicKey, sk: ml_dsa_65::PrivateKey) -> anyhow::Result<Self> {
        let pk_bytes = pk.clone().into_bytes();
        let pk_b64 = URL_SAFE_NO_PAD.encode(pk_bytes);
        let kid = hex::encode(&Sha256::digest(pk_b64.as_bytes())[..8]);
        Ok(Self {
            sk,
            pk,
            pk_b64,
            kid,
        })
    }

    /// Reconstruct from the persisted file format (`MLDSA_KEY_MAGIC`, then the
    /// base64url encodings of the private and public keys, one per line).
    fn from_persisted(contents: &str) -> anyhow::Result<Self> {
        let mut lines = contents.lines();
        let magic = lines
            .next()
            .ok_or_else(|| anyhow::anyhow!("empty ML-DSA key file"))?;
        if magic != MLDSA_KEY_MAGIC {
            anyhow::bail!("unsupported ML-DSA key file format");
        }
        let sk_b64 = lines
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing private-key line"))?;
        let pk_b64 = lines
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing public-key line"))?;
        let sk_bytes: [u8; ml_dsa_65::SK_LEN] = URL_SAFE_NO_PAD
            .decode(sk_b64)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("bad private-key length"))?;
        let pk_bytes: [u8; ml_dsa_65::PK_LEN] = URL_SAFE_NO_PAD
            .decode(pk_b64)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("bad public-key length"))?;
        let sk = ml_dsa_65::PrivateKey::try_from_bytes(sk_bytes)
            .map_err(|e| anyhow::anyhow!("private key: {e}"))?;
        let pk = ml_dsa_65::PublicKey::try_from_bytes(pk_bytes)
            .map_err(|e| anyhow::anyhow!("public key: {e}"))?;
        Self::from_parts(pk, sk)
    }

    /// Persist the keypair to `path` with owner-only permissions, then return it.
    fn write_to(self, path: &str) -> anyhow::Result<Self> {
        let body = format!(
            "{MLDSA_KEY_MAGIC}\n{}\n{}",
            URL_SAFE_NO_PAD.encode(self.sk.clone().into_bytes()),
            URL_SAFE_NO_PAD.encode(self.pk.clone().into_bytes()),
        );
        std::fs::write(path, body).with_context(|| format!("writing ML-DSA key to {path}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        tracing::info!(path, "persisted ML-DSA key");
        Ok(self)
    }

    fn sign(&self, claims: &Claims) -> anyhow::Result<String> {
        let header = serde_json::json!({ "alg": "ML-DSA-65", "typ": "JWT", "kid": self.kid });
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?),
        );
        // Empty context string, matching the JOSE ML-DSA profile.
        let sig = self
            .sk
            .try_sign(signing_input.as_bytes(), &[])
            .map_err(|e| anyhow::anyhow!("ml-dsa sign: {e}"))?;
        Ok(format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig)))
    }

    fn verify(&self, token: &str, issuer: &str) -> anyhow::Result<Claims> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            anyhow::bail!("malformed JWS");
        }
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2])?;
        let sig: [u8; ml_dsa_65::SIG_LEN] = sig_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("bad signature length"))?;
        if !self.pk.verify(signing_input.as_bytes(), &sig, &[]) {
            anyhow::bail!("signature verification failed");
        }

        let claims: Claims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?;
        if claims.iss != issuer {
            anyhow::bail!("issuer mismatch");
        }
        if claims.exp < chrono::Utc::now().timestamp() {
            anyhow::bail!("token expired");
        }
        Ok(claims)
    }

    fn jwks(&self) -> serde_json::Value {
        // "AKP" (Algorithm Key Pair) is the JOSE key type for ML-DSA public keys.
        serde_json::json!({
            "keys": [{
                "kty": "AKP",
                "use": "sig",
                "alg": "ML-DSA-65",
                "kid": self.kid,
                "pub": self.pk_b64,
            }]
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate → serialize → deserialize must recover the same key (same `kid`),
    /// and a token signed by the original verifies with the reloaded one.
    #[test]
    fn mldsa_key_persisted_roundtrips() {
        let s = MlDsaSigner::generate().unwrap();
        let body = format!(
            "{MLDSA_KEY_MAGIC}\n{}\n{}",
            URL_SAFE_NO_PAD.encode(s.sk.clone().into_bytes()),
            URL_SAFE_NO_PAD.encode(s.pk.clone().into_bytes()),
        );
        let reloaded = MlDsaSigner::from_persisted(&body).unwrap();
        assert_eq!(s.kid, reloaded.kid, "kid must be stable across reload");

        let claims = Claims {
            iss: "http://issuer.test".into(),
            sub: "subject-1".into(),
            aud: "aud".into(),
            exp: chrono::Utc::now().timestamp() + 3600,
            iat: chrono::Utc::now().timestamp(),
            scope: "openid".into(),
            email: None,
            nonce: None,
            roles: vec![],
            groups: vec![],
            attributes: serde_json::Map::new(),
            authorization: None,
            resource_access: None,
        };
        let token = s.sign(&claims).unwrap();
        let verified = reloaded.verify(&token, "http://issuer.test").unwrap();
        assert_eq!(verified.sub, claims.sub);

        // Malformed files must not silently produce a key.
        assert!(MlDsaSigner::from_persisted("garbage").is_err());
    }
}
