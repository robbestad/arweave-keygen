//! Generate and inspect Arweave JWK wallets.
//!
//! An Arweave wallet is an RSA-4096 key pair stored as a JSON Web Key (JWK).
//! The public exponent must be 65537. The wallet address is
//! `base64url(SHA-256(n))`, where `n` is the RSA modulus.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{BigUint, RsaPrivateKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// RSA modulus size required by Arweave.
pub const KEY_BITS: usize = 4096;

/// Public exponent required by Arweave (`65537`, JWK `e` = `"AQAB"`).
pub const PUBLIC_EXPONENT: u64 = 65537;

/// Arweave RSA private key in JWK form (RFC 7517 / RFC 7518).
///
/// Field order matches the canonical Arweave keyfile shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub e: String,
    pub n: String,
    pub d: String,
    pub p: String,
    pub q: String,
    pub dp: String,
    pub dq: String,
    pub qi: String,
}

/// A generated Arweave wallet: address plus JWK private key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Wallet {
    pub address: String,
    pub jwk: Jwk,
}

#[derive(Debug)]
pub enum Error {
    Rsa(rsa::Error),
    Base64(base64::DecodeError),
    Json(serde_json::Error),
    InvalidKey(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Rsa(err) => write!(f, "RSA error: {err}"),
            Error::Base64(err) => write!(f, "base64url error: {err}"),
            Error::Json(err) => write!(f, "JSON error: {err}"),
            Error::InvalidKey(msg) => write!(f, "invalid Arweave JWK: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<rsa::Error> for Error {
    fn from(err: rsa::Error) -> Self {
        Error::Rsa(err)
    }
}

impl From<base64::DecodeError> for Error {
    fn from(err: base64::DecodeError) -> Self {
        Error::Base64(err)
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Json(err)
    }
}

impl Wallet {
    /// Generate a new random Arweave wallet (RSA-4096, `e` = 65537).
    ///
    /// This typically takes 1–5 seconds.
    pub fn generate() -> Result<Self, Error> {
        let mut rng = rand::thread_rng();
        let exp = BigUint::from(PUBLIC_EXPONENT);
        let key = RsaPrivateKey::new_with_exp(&mut rng, KEY_BITS, &exp)?;
        Self::from_rsa(key)
    }

    /// Parse a JWK JSON string and derive the wallet address.
    pub fn from_jwk_json(json: &str) -> Result<Self, Error> {
        let jwk: Jwk = serde_json::from_str(json)?;
        Self::from_jwk(jwk)
    }

    /// Validate a JWK and derive its Arweave address.
    pub fn from_jwk(jwk: Jwk) -> Result<Self, Error> {
        if jwk.kty != "RSA" {
            return Err(Error::InvalidKey("kty must be RSA"));
        }
        if jwk.e != "AQAB" {
            return Err(Error::InvalidKey("public exponent e must be 65537 (AQAB)"));
        }
        let address = address_from_n(&jwk.n)?;
        Ok(Self { address, jwk })
    }

    fn from_rsa(mut key: RsaPrivateKey) -> Result<Self, Error> {
        key.precompute()?;

        if key.n().bits() != KEY_BITS {
            return Err(Error::InvalidKey("modulus must be 4096 bits"));
        }
        if key.e() != &BigUint::from(PUBLIC_EXPONENT) {
            return Err(Error::InvalidKey("public exponent e must be 65537"));
        }

        let primes = key.primes();
        if primes.len() < 2 {
            return Err(Error::InvalidKey("RSA key is missing prime factors"));
        }

        let n = key.n();
        let d = key.d();
        let p = &primes[0];
        let q = &primes[1];
        let one = BigUint::from(1u8);
        let two = BigUint::from(2u8);

        let dp = key.dp().cloned().unwrap_or_else(|| d % (p - &one));
        let dq = key.dq().cloned().unwrap_or_else(|| d % (q - &one));
        // qi = q^{-1} mod p. For prime p this equals q^{p-2} mod p.
        let qi = key
            .crt_coefficient()
            .unwrap_or_else(|| q.modpow(&(p - &two), p));

        let jwk = Jwk {
            kty: "RSA".to_string(),
            e: b64url_encode(&key.e().to_bytes_be()),
            n: b64url_encode(&n.to_bytes_be()),
            d: b64url_encode(&d.to_bytes_be()),
            p: b64url_encode(&p.to_bytes_be()),
            q: b64url_encode(&q.to_bytes_be()),
            dp: b64url_encode(&dp.to_bytes_be()),
            dq: b64url_encode(&dq.to_bytes_be()),
            qi: b64url_encode(&qi.to_bytes_be()),
        };

        let address = address_from_n(&jwk.n)?;
        Ok(Self { address, jwk })
    }

    /// Pretty-printed JWK JSON, the usual Arweave keyfile contents.
    pub fn to_jwk_json(&self) -> Result<String, Error> {
        Ok(serde_json::to_string_pretty(&self.jwk)?)
    }

    /// Pretty-printed wallet JSON: `address` plus the JWK private key.
    pub fn to_json(&self) -> Result<String, Error> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Default keyfile name used by Arweave tooling.
    pub fn default_filename(&self) -> String {
        format!("arweave-keyfile-{}.json", self.address)
    }
}

/// Base64URL-encode bytes without padding.
pub fn b64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Base64URL-decode a string (padding optional).
pub fn b64url_decode(value: &str) -> Result<Vec<u8>, Error> {
    URL_SAFE_NO_PAD.decode(value).map_err(Error::from)
}

/// Wallet address from the JWK `n` field: `base64url(SHA-256(decode(n)))`.
pub fn address_from_n(n_b64url: &str) -> Result<String, Error> {
    let n = b64url_decode(n_b64url)?;
    Ok(address_from_n_bytes(&n))
}

/// Wallet address from the raw RSA modulus bytes.
pub fn address_from_n_bytes(n: &[u8]) -> String {
    let digest = Sha256::digest(n);
    b64url_encode(&digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Official sample from the Arweave HTTP API docs.
    const SAMPLE_N: &str = "ovFF6EbOtXeg7VnojIgtChgxfU6GZ16JjVj5JFHh6NGHJnq4p059BnMphcDx1mqb3yxM73FxhEszSFLcJiPzway6eIDiXuYiT-Sf_0Wl6_wDLvEmlz43psp7WYJumwpaSyiI_1FWmOVQnTnoAIKaOYKVqzUlteiECQj7XjJl0MZH16RlEfVqVpJ_8Ier4_QXIJ8Y3pe2KF3Lg9UANFU97nuvEM94CSzX-0WIju6Lykt3DBb2YtFFg4bJjOFv3T38nCZmDh8lYjm25_1qILalsB0XRoDxQy9FLxWb4zd09JsDhL0EYAQ_hNfOnQFVOBtYEHVYMCHYH6GoTcNgxmUkZPk4AfpAqZmjDzKfVJrw4Fr68pPTEQOQEzBcIWp61P21BSkhqO4QuFinkQsSH6NdTB_3FpbhYf34Hjf-iH7hdpdWo4aoRLb8eZeZcqBRZoRmlhQnOD-PVxQR_vb9rjXSjGkCWwRbsurVLWdBh_FQn0S9Q6EHqiV8nbW-R0Rk2E76JwgMFkqGUtZj8DeEqXJ2jlAvuzp56fXeAViPEtvUj1HheO8O3LxdVYCiapWWKq4qQVoRzdiyvydYSmbztgFUhekvmjNkxLNKOh71i3hFtoXycegqZ6izrUGoF2oD24lsTKsV5lV5pwfmUjVvxtHZm54bJIMfUDYbOV6yeDjYBb8";
    const SAMPLE_ADDRESS: &str = "GRQ7swQO1AMyFgnuAPI7AvGQlW3lzuQuwlJbIpWV7xk";

    #[test]
    fn sample_n_hashes_to_documented_address() {
        assert_eq!(address_from_n(SAMPLE_N).unwrap(), SAMPLE_ADDRESS);
        assert_eq!(SAMPLE_ADDRESS.len(), 43);
    }

    #[test]
    fn exponent_65537_encodes_as_aqab() {
        let e = BigUint::from(PUBLIC_EXPONENT);
        assert_eq!(b64url_encode(&e.to_bytes_be()), "AQAB");
    }

    fn jwk_int(value: &str) -> BigUint {
        BigUint::from_bytes_be(&b64url_decode(value).unwrap())
    }

    #[test]
    fn generate_wallet_is_valid_arweave_jwk() {
        let wallet = Wallet::generate().expect("RSA-4096 keygen");

        assert_eq!(wallet.jwk.kty, "RSA");
        assert_eq!(wallet.jwk.e, "AQAB");
        assert_eq!(wallet.address.len(), 43);
        assert_eq!(address_from_n(&wallet.jwk.n).unwrap(), wallet.address);

        let n = jwk_int(&wallet.jwk.n);
        let e = jwk_int(&wallet.jwk.e);
        let d = jwk_int(&wallet.jwk.d);
        let p = jwk_int(&wallet.jwk.p);
        let q = jwk_int(&wallet.jwk.q);
        let dp = jwk_int(&wallet.jwk.dp);
        let dq = jwk_int(&wallet.jwk.dq);
        let qi = jwk_int(&wallet.jwk.qi);
        let one = BigUint::from(1u8);

        assert_eq!(n.bits(), KEY_BITS);
        assert_eq!(n, &p * &q);
        assert_eq!(e, BigUint::from(PUBLIC_EXPONENT));
        assert_eq!(dp, &d % (&p - &one));
        assert_eq!(dq, &d % (&q - &one));
        assert_eq!((&q * &qi) % &p, one);

        RsaPrivateKey::from_components(n, e, d, vec![p, q])
            .unwrap()
            .validate()
            .unwrap();

        let json = wallet.to_jwk_json().unwrap();
        let reloaded = Wallet::from_jwk_json(&json).unwrap();
        assert_eq!(reloaded.address, wallet.address);
        assert_eq!(reloaded.jwk, wallet.jwk);

        let wallet_json: serde_json::Value =
            serde_json::from_str(&wallet.to_json().unwrap()).unwrap();
        assert_eq!(wallet_json["address"], wallet.address);
        assert_eq!(wallet_json["jwk"]["kty"], "RSA");
        assert_eq!(wallet_json["jwk"]["e"], "AQAB");
        assert_eq!(
            wallet.default_filename(),
            format!("arweave-keyfile-{}.json", wallet.address)
        );
    }

    #[test]
    fn rejects_non_rsa_kty() {
        let err = Wallet::from_jwk(Jwk {
            kty: "EC".into(),
            e: "AQAB".into(),
            n: SAMPLE_N.into(),
            d: "x".into(),
            p: "x".into(),
            q: "x".into(),
            dp: "x".into(),
            dq: "x".into(),
            qi: "x".into(),
        })
        .unwrap_err();
        assert!(err.to_string().contains("RSA"));
    }
}
