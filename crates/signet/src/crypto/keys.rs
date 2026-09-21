use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{DecodingKey, EncodingKey, Header};
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, LineEnding};
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::Serialize;
use std::path::Path;
use std::sync::Arc;

#[derive(Clone)]
pub struct JwtKeys {
    pub kid: String,
    encoding_key: EncodingKey,
    /// The same key for verification, parsed once at startup.
    ///
    /// `jsonwebtoken` says of `DecodingKey` that it "can be re-used so make sure
    /// you only initialize it once if you can for better performance", and the
    /// verification endpoints are called once per API request by clients — the
    /// one place where parsing the RSA key per request would be a real cost, and
    /// a blocking file read inside an async handler besides.
    decoding_key: DecodingKey,
    jwks: Arc<Jwks>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(rename = "use")]
    pub key_use: String,
    pub kid: String,
    pub alg: String,
    pub n: String,
    pub e: String,
}

impl JwtKeys {
    pub fn load_or_generate(path: &Path) -> Result<Self> {
        let pem = crate::crypto::util::read_or_generate_file(path, "JWT signing key", || {
            let mut rng = rand::thread_rng();
            let private = RsaPrivateKey::new(&mut rng, 2048).context("generate RSA key")?;
            Ok(private
                .to_pkcs1_pem(LineEnding::LF)
                .context("encode PEM")?
                .to_string())
        })?;

        let private = RsaPrivateKey::from_pkcs1_pem(&pem)
            .or_else(|_| RsaPrivateKey::from_pkcs8_pem(&pem))
            .context("parse RSA private key PEM")?;
        let public = RsaPublicKey::from(&private);

        let n = URL_SAFE_NO_PAD.encode(public.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(public.e().to_bytes_be());
        let kid = crate::crypto::util::sha256_hex(&n)[..16].to_string();

        let encoding_key = EncodingKey::from_rsa_pem(pem.as_bytes()).context("encoding key")?;
        let decoding_key = DecodingKey::from_rsa_pem(pem.as_bytes()).context("decoding key")?;
        let jwks = Arc::new(Jwks {
            keys: vec![Jwk {
                kty: "RSA".into(),
                key_use: "sig".into(),
                kid: kid.clone(),
                alg: "RS256".into(),
                n,
                e,
            }],
        });

        Ok(Self {
            kid,
            encoding_key,
            decoding_key,
            jwks,
        })
    }

    pub fn jwks(&self) -> Arc<Jwks> {
        self.jwks.clone()
    }

    /// The key that verifies tokens this instance signed.
    pub fn decoding(&self) -> &DecodingKey {
        &self.decoding_key
    }

    pub fn encode<T: Serialize>(&self, claims: &T) -> Result<String> {
        let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(self.kid.clone());
        jsonwebtoken::encode(&header, claims, &self.encoding_key).context("sign jwt")
    }
}
