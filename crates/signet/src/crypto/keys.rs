use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{DecodingKey, EncodingKey, Header};
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, LineEnding};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePublicKey};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The signing key plus every retired key the instance still accepts.
///
/// Rotation used to be all-or-nothing: replacing the PEM invalidated every
/// outstanding access/id token at once. A key ring lets the operator rotate on
/// their own schedule — the new key signs, the old ones keep verifying until
/// their tokens age out, and JWKS publishes all of them so clients follow.
#[derive(Clone)]
pub struct JwtKeys {
    /// The active (signing) key id.
    pub kid: String,
    encoding_key: EncodingKey,
    /// `kid -> key`, active included. Verification picks by the token's `kid`,
    /// falling back to the active key for tokens signed before `kid` was set.
    decoding: Arc<HashMap<String, DecodingKey>>,
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
        Self::load_or_generate_with_retired(path, None)
    }

    /// Loads the active key from `path` and every retired key in `retired_dir`.
    ///
    /// A missing/empty retired directory is normal: it is what a deployment that
    /// has never rotated looks like. A malformed file in it is an error rather
    /// than a skip — silently dropping a retired key invalidates the tokens it
    /// signed, and the operator needs to know at boot, not from 401s later.
    pub fn load_or_generate_with_retired(path: &Path, retired_dir: Option<&Path>) -> Result<Self> {
        let pem = crate::crypto::util::read_or_generate_file(path, "JWT signing key", || {
            let mut rng = rand::thread_rng();
            let private = RsaPrivateKey::new(&mut rng, 2048).context("generate RSA key")?;
            Ok(private
                .to_pkcs1_pem(LineEnding::LF)
                .context("encode PEM")?
                .to_string())
        })?;

        let private = parse_private(&pem)?;
        let public = RsaPublicKey::from(&private);
        let (kid, n, e) = components(&public);
        let encoding_key = EncodingKey::from_rsa_pem(pem.as_bytes()).context("encoding key")?;
        // From the public components, NOT `DecodingKey::from_rsa_pem`: on this
        // jsonwebtoken/ring combination the PEM-built key fails verification of
        // its own signatures (found on aarch64; userinfo 401'd every client
        // while the JWKS path — components-based — kept working). The n/e pair
        // is already at hand for the JWKS, so the components constructor is the
        // natural route; `tests/jwt_roundtrip.rs` pins the property.
        let decoding_key = DecodingKey::from_rsa_components(&n, &e).context("decoding key")?;

        let mut map: HashMap<String, DecodingKey> = HashMap::new();
        map.insert(kid.clone(), decoding_key);
        let mut published = vec![Jwk {
            kty: "RSA".into(),
            key_use: "sig".into(),
            kid: kid.clone(),
            alg: "RS256".into(),
            n,
            e,
        }];

        if let Some(dir) = retired_dir {
            for (retired_kid, jwk, key) in load_retired(dir)? {
                if map.contains_key(&retired_kid) {
                    continue;
                }
                map.insert(retired_kid, key);
                published.push(jwk);
            }
            // Stable order regardless of readdir order: the JWKS body is cached
            // by clients and by intermediaries, and churn is noise. The active
            // key stays first; retired sort by kid.
            published[1..].sort_by(|a, b| a.kid.cmp(&b.kid));
        }

        Ok(Self {
            kid,
            encoding_key,
            decoding: Arc::new(map),
            jwks: Arc::new(Jwks { keys: published }),
        })
    }

    pub fn jwks(&self) -> Arc<Jwks> {
        self.jwks.clone()
    }

    /// The active key, for tests that sign and verify on the same instance.
    pub fn decoding(&self) -> &DecodingKey {
        self.decoding
            .get(&self.kid)
            .expect("the active key is always present")
    }

    /// Decodes a token with the key its `kid` names, falling back to the active
    /// key when the header carries none (tokens from before the ring existed).
    pub fn verify<T: DeserializeOwned>(
        &self,
        token: &str,
        validation: &jsonwebtoken::Validation,
    ) -> std::result::Result<jsonwebtoken::TokenData<T>, jsonwebtoken::errors::Error> {
        let header = jsonwebtoken::decode_header(token)?;
        let key = header
            .kid
            .as_deref()
            .and_then(|k| self.decoding.get(k))
            .or_else(|| self.decoding.get(&self.kid))
            .expect("the active key is always present");
        jsonwebtoken::decode::<T>(token, key, validation)
    }

    pub fn encode<T: Serialize>(&self, claims: &T) -> Result<String> {
        let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(self.kid.clone());
        jsonwebtoken::encode(&header, claims, &self.encoding_key).context("sign jwt")
    }
}

fn parse_private(pem: &str) -> Result<RsaPrivateKey> {
    RsaPrivateKey::from_pkcs1_pem(pem)
        .or_else(|_| RsaPrivateKey::from_pkcs8_pem(pem))
        .context("parse RSA private key PEM")
}

fn components(public: &RsaPublicKey) -> (String, String, String) {
    let n = URL_SAFE_NO_PAD.encode(public.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(public.e().to_bytes_be());
    let kid = crate::crypto::util::sha256_hex(&n)[..16].to_string();
    (kid, n, e)
}

/// Reads retired keys from `dir`, accepting a public or private PEM.
///
/// `signet keys rotate` writes the old key as a *public* PEM: verification is
/// all a retired key is for, and leaving private material around after it stops
/// signing is needless exposure. The private fallback is for an operator who
/// moved the old file there by hand.
fn load_retired(dir: &Path) -> Result<Vec<(String, Jwk, DecodingKey)>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("read retired key dir {}", dir.display())),
    };
    let mut out = Vec::new();
    for entry in entries {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("pem") {
            continue;
        }
        let pem = std::fs::read_to_string(&path)
            .with_context(|| format!("read retired key {}", path.display()))?;
        let public = match RsaPublicKey::from_public_key_pem(&pem) {
            Ok(public) => public,
            Err(_) => RsaPublicKey::from(&parse_private(&pem).with_context(|| {
                format!(
                    "retired key {} is neither a public nor a private PEM",
                    path.display()
                )
            })?),
        };
        let (kid, n, e) = components(&public);
        let key = DecodingKey::from_rsa_components(&n, &e)
            .with_context(|| format!("retired key {} is not a valid RSA key", path.display()))?;
        out.push((
            kid.clone(),
            Jwk {
                kty: "RSA".into(),
                key_use: "sig".into(),
                kid,
                alg: "RS256".into(),
                n,
                e,
            },
            key,
        ));
    }
    Ok(out)
}

/// Generates a new signing key, retires the current one, and returns the new kid.
///
/// The old key is published as a public PEM in `retired_dir` (the instance must
/// be restarted to load it). The new key replaces `path` atomically — written to
/// a sibling `0600` file and renamed — so a crash mid-rotation cannot leave a
/// truncated signing key behind. Nothing here touches the database: rotation is
/// a file operation, and the boot-time key load is what makes it take effect.
pub fn rotate(path: &Path, retired_dir: &Path) -> Result<String> {
    let pem = std::fs::read_to_string(path)
        .with_context(|| format!("read the current signing key {}", path.display()))?;
    let old = parse_private(&pem)?;
    let old_public = RsaPublicKey::from(&old);
    let (old_kid, ..) = components(&old_public);

    std::fs::create_dir_all(retired_dir)
        .with_context(|| format!("create retired key dir {}", retired_dir.display()))?;
    let retired_path: PathBuf = retired_dir.join(format!("{old_kid}.pem"));
    let public_pem = old_public
        .to_public_key_pem(LineEnding::LF)
        .context("encode retired public key")?;
    // A public key, so no secret handling; overwrite is fine and makes a
    // repeated `rotate` idempotent for this kid.
    std::fs::write(&retired_path, public_pem)
        .with_context(|| format!("write retired key {}", retired_path.display()))?;

    let mut rng = rand::thread_rng();
    let new = RsaPrivateKey::new(&mut rng, 2048).context("generate RSA key")?;
    let new_pem = new
        .to_pkcs1_pem(LineEnding::LF)
        .context("encode PEM")?
        .to_string();
    let tmp = path.with_extension("pem.rotating");
    // A leftover temp file from a crashed run must not block the retry.
    let _ = std::fs::remove_file(&tmp);
    crate::crypto::util::write_private(&tmp, &new_pem)
        .with_context(|| format!("write new key {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("replace signing key {}", path.display()))?;

    Ok(components(&RsaPublicKey::from(&new)).0)
}

/// Deletes all but the `keep` most recently written retired keys.
///
/// Retired keys are only needed until the tokens they signed expire (the
/// longest TTL in play bounds it: refresh tokens are issued per grant, so keep
/// enough to cover a rotation cycle rather than one access-token lifetime). A
/// public key is not a secret, so the cost of keeping too many is disk noise,
/// not exposure; the default of 3 covers "rotate, notice a problem, rotate
/// back".
pub fn prune_retired(dir: &Path, keep: usize) -> Result<usize> {
    let mut entries: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
    let reader = match std::fs::read_dir(dir) {
        Ok(reader) => reader,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e).with_context(|| format!("read {}", dir.display())),
    };
    for entry in reader {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("pem") {
            continue;
        }
        let modified = entry.metadata()?.modified()?;
        entries.push((modified, path));
    }
    entries.sort_by_key(|(modified, _)| std::cmp::Reverse(*modified));
    let mut removed = 0;
    for (_, path) in entries.into_iter().skip(keep) {
        std::fs::remove_file(&path)
            .with_context(|| format!("remove retired key {}", path.display()))?;
        removed += 1;
    }
    Ok(removed)
}
