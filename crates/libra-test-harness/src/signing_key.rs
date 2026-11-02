//! A signing key the tests own, and the JWKS that publishes it.
//!
//! The tests sign their own tokens: they are the issuer, so they control every claim, every key and
//! every rotation. A token signed here verifies only against a key set the same test serves, so
//! nothing here is trusted by any real deployment.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts};
use serde_json::Value;

/// One RSA signing key, and the identifier a JWKS advertises it under.
pub struct SigningKey {
    kid: String,
    encoding: EncodingKey,
    modulus: String,
    exponent: String,
}

impl SigningKey {
    /// Generates a fresh 2048-bit key advertised under `kid`.
    ///
    /// Generating one costs enough that a test binary should generate each key it needs once.
    ///
    /// # Panics
    ///
    /// Panics if key generation or DER encoding fails, which in a test is a failure to set up.
    #[must_use]
    pub fn generate(kid: &str) -> Self {
        let mut rng = rand::rng();
        let private = RsaPrivateKey::new(&mut rng, 2048).expect("generating an RSA key");

        let modulus = URL_SAFE_NO_PAD.encode(private.n().as_ref().to_be_bytes_trimmed_vartime());
        let exponent = URL_SAFE_NO_PAD.encode(private.e().to_be_bytes_trimmed_vartime());
        let der = private.to_pkcs1_der().expect("encoding the key as DER");

        Self {
            kid: kid.to_owned(),
            encoding: EncodingKey::from_rsa_der(der.as_bytes()),
            modulus,
            exponent,
        }
    }

    /// A JWKS document advertising exactly `keys`, in the shape the proxy fetches.
    #[must_use]
    pub fn jwks(keys: &[&Self]) -> String {
        let entries: Vec<String> = keys
            .iter()
            .map(|key| {
                format!(
                    r#"{{ "kid": "{kid}", "kty": "RSA", "use": "sig", "alg": "RS256", "n": "{n}", "e": "{e}" }}"#,
                    kid = key.kid,
                    n = key.modulus,
                    e = key.exponent
                )
            })
            .collect();

        format!(r#"{{ "keys": [{}] }}"#, entries.join(", "))
    }

    /// The header a token signed by this key carries: RS256, naming this key.
    #[must_use]
    pub fn header(&self) -> Header {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone()); // the header owns its identifier, the key keeps its own

        header
    }

    /// Signs `claims` under [`SigningKey::header`].
    ///
    /// # Panics
    ///
    /// Panics if signing fails.
    #[must_use]
    pub fn sign(&self, claims: &Value) -> String {
        self.sign_with(&self.header(), claims)
    }

    /// Signs `claims` under a header of the test's own choosing, for a test about what the header
    /// says.
    ///
    /// # Panics
    ///
    /// Panics if signing fails.
    #[must_use]
    pub fn sign_with(&self, header: &Header, claims: &Value) -> String {
        encode(header, claims, &self.encoding).expect("signing a token")
    }
}
