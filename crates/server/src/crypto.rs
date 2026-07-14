//! All cryptographic primitives in one place: password + secret hashing,
//! opaque token generation, PKCE verification, and the RSA keypair used to sign
//! OIDC id_tokens (published as a JWKS at `/.well-known/jwks.json`).

use anyhow::Context;
use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::Argon2;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{DecodingKey, EncodingKey};
use rand::RngCore;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256};

/// Hash a password/secret for storage (Argon2id).
pub fn hash_secret(plain: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(plain.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("hash: {e}"))
}

/// Constant-time verification of a plaintext against a stored Argon2 hash.
pub fn verify_secret(plain: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(plain.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// A URL-safe random token (e.g. `client_id`, auth codes, refresh tokens).
pub fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// SHA-256 hex digest — used to store opaque tokens without keeping plaintext.
pub fn sha256_hex(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

/// Verify an RFC 7636 PKCE `code_verifier` against the stored challenge.
pub fn verify_pkce(verifier: &str, challenge: &str, method: &str) -> bool {
    match method {
        "S256" => {
            let digest = Sha256::digest(verifier.as_bytes());
            URL_SAFE_NO_PAD.encode(digest) == challenge
        }
        // "plain" is permitted by the spec but discouraged.
        "plain" => verifier == challenge,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_hash_roundtrips() {
        let hash = hash_secret("hunter2").unwrap();
        assert!(verify_secret("hunter2", &hash));
        assert!(!verify_secret("wrong", &hash));
    }

    #[test]
    fn pkce_s256_matches_known_vector() {
        // RFC 7636 Appendix B test vector.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(verify_pkce(verifier, challenge, "S256"));
        assert!(!verify_pkce("tampered", challenge, "S256"));
    }

    #[test]
    fn random_tokens_are_unique() {
        assert_ne!(random_token(16), random_token(16));
    }
}

/// The RSA signing material, plus a precomputed JWKS document and `kid`.
#[derive(Clone)]
pub struct Keys {
    pub encoding: EncodingKey,
    pub decoding: DecodingKey,
    pub kid: String,
    jwk_n: String,
    jwk_e: String,
}

impl Keys {
    /// Load the signing key from a PEM file, or generate an ephemeral 2048-bit
    /// key (dev only — issued tokens become invalid on restart).
    pub fn load_or_generate(pem_path: Option<&str>) -> anyhow::Result<Self> {
        let private = match pem_path {
            Some(path) => {
                let pem = std::fs::read_to_string(path)
                    .with_context(|| format!("reading JWT key at {path}"))?;
                RsaPrivateKey::from_pkcs1_pem(&pem)
                    .context("parsing RSA private key (expected PKCS#1 PEM)")?
            }
            None => {
                tracing::warn!(
                    "no SSO_JWT_PRIVATE_KEY_PATH set — generating an EPHEMERAL signing key"
                );
                RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).context("generating RSA key")?
            }
        };

        let pem = private
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .context("encoding key")?;
        let encoding = EncodingKey::from_rsa_pem(pem.as_bytes()).context("jsonwebtoken key")?;

        let pubkey = private.to_public_key();
        let pub_pem = pubkey
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .context("encoding pubkey")?;
        let decoding =
            DecodingKey::from_rsa_pem(pub_pem.as_bytes()).context("jsonwebtoken pubkey")?;

        let jwk_n = URL_SAFE_NO_PAD.encode(pubkey.n().to_bytes_be());
        let jwk_e = URL_SAFE_NO_PAD.encode(pubkey.e().to_bytes_be());
        let kid = hex::encode(&Sha256::digest(jwk_n.as_bytes())[..8]);

        Ok(Self {
            encoding,
            decoding,
            kid,
            jwk_n,
            jwk_e,
        })
    }

    /// The public JWKS document served for token verification by relying parties.
    pub fn jwks(&self) -> serde_json::Value {
        serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": self.kid,
                "n": self.jwk_n,
                "e": self.jwk_e,
            }]
        })
    }
}
