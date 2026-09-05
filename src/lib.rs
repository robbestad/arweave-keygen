//! Generate and inspect Arweave JWK wallets.
//!
//! An Arweave wallet is an RSA-4096 key pair stored as a JSON Web Key (JWK).
//! The public exponent must be 65537. The wallet address is
//! `base64url(SHA-256(n))`, where `n` is the RSA modulus.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use num_bigint_dig::prime::probably_prime;
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
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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

impl std::fmt::Debug for Jwk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Jwk")
            .field("kty", &self.kty)
            .field("e", &self.e)
            .field("n", &self.n)
            .field("d", &"[REDACTED]")
            .field("p", &"[REDACTED]")
            .field("q", &"[REDACTED]")
            .field("dp", &"[REDACTED]")
            .field("dq", &"[REDACTED]")
            .field("qi", &"[REDACTED]")
            .finish()
    }
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
        let n = decode_jwk_integer(&jwk.n)?;
        if n.bits() != KEY_BITS {
            return Err(Error::InvalidKey("modulus must be 4096 bits"));
        }
        let d = decode_jwk_integer(&jwk.d)?;
        let p = decode_jwk_integer(&jwk.p)?;
        let q = decode_jwk_integer(&jwk.q)?;
        let dp = decode_jwk_integer(&jwk.dp)?;
        let dq = decode_jwk_integer(&jwk.dq)?;
        let qi = decode_jwk_integer(&jwk.qi)?;
        let one = BigUint::from(1u8);
        let two = BigUint::from(2u8);
        if d >= n || p <= two || q <= two || p == q || &p % &two != one || &q % &two != one {
            return Err(Error::InvalidKey("invalid private RSA components"));
        }
        // from_components checks n = p*q and CRT relations, not primality.
        if !probably_prime(&p, 20) || !probably_prime(&q, 20) {
            return Err(Error::InvalidKey("RSA factors p and q must be prime"));
        }
        let key = RsaPrivateKey::from_components(n, BigUint::from(PUBLIC_EXPONENT), d, vec![p, q])?;
        if key.dp() != Some(&dp)
            || key.dq() != Some(&dq)
            || key.crt_coefficient().as_ref() != Some(&qi)
        {
            return Err(Error::InvalidKey("CRT fields do not match the private key"));
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

/// Base64URL-decode a string without padding.
pub fn b64url_decode(value: &str) -> Result<Vec<u8>, Error> {
    URL_SAFE_NO_PAD.decode(value).map_err(Error::from)
}

fn decode_jwk_integer(value: &str) -> Result<BigUint, Error> {
    // Bound decoding and RSA arithmetic to the supported modulus size.
    if value.len() > (KEY_BITS / 8 * 4).div_ceil(3) {
        return Err(Error::InvalidKey("RSA component exceeds 4096 bits"));
    }
    let bytes = b64url_decode(value)?;
    if bytes.is_empty() || bytes[0] == 0 {
        return Err(Error::InvalidKey(
            "RSA components must be positive, minimally encoded integers",
        ));
    }
    Ok(BigUint::from_bytes_be(&bytes))
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

    fn sample_wallet() -> Wallet {
        static WALLET: std::sync::OnceLock<Wallet> = std::sync::OnceLock::new();
        WALLET
            .get_or_init(|| Wallet::generate().expect("RSA-4096 keygen"))
            .clone()
    }

    #[test]
    fn rejects_corrupt_import_components() {
        let wallet = sample_wallet();
        let original = serde_json::to_value(&wallet.jwk).unwrap();
        for field in ["n", "d", "p", "q", "dp", "dq", "qi"] {
            for invalid in ["", "!", "AA", "AQ", "Ag", "AQI=", "AAE"] {
                let mut value = original.clone();
                value[field] = invalid.into();
                assert!(
                    Wallet::from_jwk_json(&value.to_string()).is_err(),
                    "accepted {field}={invalid}"
                );
            }
            let mut value = original.clone();
            let changed = jwk_int(original[field].as_str().unwrap()) + BigUint::from(2u8);
            value[field] = b64url_encode(&changed.to_bytes_be()).into();
            assert!(
                Wallet::from_jwk_json(&value.to_string()).is_err(),
                "accepted inconsistent {field}"
            );
        }
        let mut jwk = wallet.jwk.clone();
        jwk.e = "Aw".into();
        assert!(Wallet::from_jwk(jwk).is_err());
        let mut jwk = wallet.jwk.clone();
        jwk.p = jwk.q.clone();
        assert!(Wallet::from_jwk(jwk).is_err());
        let mut jwk = wallet.jwk;
        jwk.d = "A".repeat(684);
        assert!(Wallet::from_jwk(jwk).is_err());
    }

    fn gcd(mut a: BigUint, mut b: BigUint) -> BigUint {
        let zero = BigUint::from(0u8);
        while b != zero {
            let r = &a % &b;
            a = b;
            b = r;
        }
        a
    }

    /// Composite p, q with matching n, d and CRT fields so the old import
    /// checks would accept the key.
    fn composite_jwk() -> Jwk {
        use num_bigint_dig::traits::ModInverse;

        let e = BigUint::from(PUBLIC_EXPONENT);
        let zero = BigUint::from(0u8);
        for p_shift in 2040..=2050 {
            for q_shift in 2040..=2050 {
                for p_add in 1u32..30 {
                    for q_add in 1u32..30 {
                        if p_add % 2 == 0 || q_add % 2 == 0 {
                            continue;
                        }
                        let p = BigUint::from(9u8)
                            * ((BigUint::from(1u8) << p_shift) + BigUint::from(p_add));
                        let q = BigUint::from(25u8)
                            * ((BigUint::from(1u8) << q_shift) + BigUint::from(q_add));
                        if p == q {
                            continue;
                        }
                        let n = &p * &q;
                        if n.bits() != KEY_BITS {
                            continue;
                        }
                        let pm1 = &p - 1u8;
                        let qm1 = &q - 1u8;
                        if &pm1 % &e == zero || &qm1 % &e == zero {
                            continue;
                        }
                        let g = gcd(pm1.clone(), qm1.clone());
                        let lambda = &pm1 / g * &qm1;
                        let Some(d) = e.clone().mod_inverse(&lambda).and_then(|v| v.to_biguint())
                        else {
                            continue;
                        };
                        let Some(qi) = q.clone().mod_inverse(&p).and_then(|v| v.to_biguint())
                        else {
                            continue;
                        };
                        let dp = &d % &pm1;
                        let dq = &d % &qm1;
                        return Jwk {
                            kty: "RSA".into(),
                            e: "AQAB".into(),
                            n: b64url_encode(&n.to_bytes_be()),
                            d: b64url_encode(&d.to_bytes_be()),
                            p: b64url_encode(&p.to_bytes_be()),
                            q: b64url_encode(&q.to_bytes_be()),
                            dp: b64url_encode(&dp.to_bytes_be()),
                            dq: b64url_encode(&dq.to_bytes_be()),
                            qi: b64url_encode(&qi.to_bytes_be()),
                        };
                    }
                }
            }
        }
        panic!("failed to construct a 4096-bit composite RSA JWK");
    }

    #[test]
    fn rejects_composite_import_factors() {
        let err = Wallet::from_jwk(composite_jwk()).unwrap_err();
        assert!(err.to_string().contains("prime"), "unexpected error: {err}");
    }

    #[test]
    fn debug_redacts_private_components() {
        let wallet = sample_wallet();
        for output in [
            format!("{:?}", wallet.jwk),
            format!("{:#?}", wallet.jwk),
            format!("{:?}", wallet),
            format!("{:#?}", wallet),
        ] {
            for secret in [
                &wallet.jwk.d,
                &wallet.jwk.p,
                &wallet.jwk.q,
                &wallet.jwk.dp,
                &wallet.jwk.dq,
                &wallet.jwk.qi,
            ] {
                assert!(!output.contains(secret));
            }
            assert!(output.contains("[REDACTED]"));
        }
    }

    #[test]
    fn base64_requires_no_padding() {
        assert_eq!(b64url_decode("AQI").unwrap(), vec![1, 2]);
        assert!(b64url_decode("AQI=").is_err());
    }

    #[test]
    fn generate_wallet_is_valid_arweave_jwk() {
        let wallet = sample_wallet();

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
