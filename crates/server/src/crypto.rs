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
use hmac::{Hmac, Mac};
use jsonwebtoken::{DecodingKey, EncodingKey};
use rand::RngCore;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use sha1::Sha1;
use sha2::{Digest, Sha256};

type HmacSha1 = Hmac<Sha1>;

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

// ---------------------------------------------------------------------------
// TOTP (RFC 6238) — used for end-user two-factor authentication.
// ---------------------------------------------------------------------------

const B32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const TOTP_STEP_SECS: u64 = 30;
/// Accepted time-drift, in steps (RFC 6238 recommends allowing ±1).
const TOTP_WINDOW: i64 = 1;

/// Generate a new random TOTP shared secret (20 random bytes, base32-encoded).
pub fn generate_totp_secret() -> String {
    let mut buf = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    base32_encode(&buf)
}

/// Verify a 6-digit TOTP code against a base32 secret, allowing ±1 time step.
pub fn verify_totp(secret_b32: &str, code: &str) -> bool {
    let Some(key) = base32_decode(secret_b32) else {
        return false;
    };
    let code = code.trim();
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let Ok(expected) = code.parse::<u32>() else {
        return false;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let counter = (now / TOTP_STEP_SECS) as i64;
    (-TOTP_WINDOW..=TOTP_WINDOW).any(|off| hotp(&key, counter + off) == expected)
}

/// HMAC-SHA1 based one-time password (RFC 4226), truncated to 6 digits.
fn hotp(key: &[u8], counter: i64) -> u32 {
    let mut mac = HmacSha1::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let offset = (result[19] & 0x0f) as usize;
    let bin = u32::from(result[offset] & 0x7f) << 24
        | u32::from(result[offset + 1]) << 16
        | u32::from(result[offset + 2]) << 8
        | u32::from(result[offset + 3]);
    bin % 1_000_000
}

/// RFC 4648 base32 decode (case-insensitive, ignores padding `=`).
pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &c in s.as_bytes() {
        if c == b'=' {
            continue; // padding
        }
        let c = c.to_ascii_uppercase();
        let v = B32_ALPHABET.iter().position(|&x| x == c)? as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

/// RFC 4648 base32 encode (no padding).
pub fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &b in bytes {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32_ALPHABET[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32_ALPHABET[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// The `otpauth://` provisioning URI for QR display.
pub fn totp_provisioning_uri(issuer: &str, account: &str, secret_b32: &str) -> String {
    format!(
        "otpauth://totp/{}?secret={}&issuer={}",
        pct(&format!("{issuer}:{account}")),
        secret_b32,
        pct(issuer),
    )
}

/// Minimal RFC 3986 percent-encoder (unreserved + `:` `@` pass through).
fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b':' | b'@') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{b:02X}"));
        }
    }
    out
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

    #[test]
    fn base32_roundtrips() {
        let bytes = b"Hello, TOTP world!";
        let enc = base32_encode(bytes);
        assert_eq!(base32_decode(&enc).unwrap(), bytes);
        // Known vector (RFC 4648 test: "foobar" -> "MZXW6YTBOI======", no padding).
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        // Case-insensitive + ignores padding.
        assert_eq!(base32_decode("mzxw6ytboi=").unwrap(), b"foobar");
    }

    #[test]
    fn totp_accepts_and_rejects() {
        let secret = generate_totp_secret();
        // Compute the current valid code the same way the verifier does, then
        // confirm it verifies and a wrong one doesn't.
        let key = base32_decode(&secret).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let code = format!("{:06}", hotp(&key, (now / 30) as i64));
        assert!(verify_totp(&secret, &code));
        assert!(!verify_totp(&secret, "000000"));
        assert!(!verify_totp(&secret, "abcdef")); // non-digits
        assert!(!verify_totp("not-base32!", &code));
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
