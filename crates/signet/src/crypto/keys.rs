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
/// The old key is published as a public PEM in `retired_dir` (a running
/// instance picks the ring up on its next poll — see [`spawn_key_watcher`] —
/// and a restart loads it too). The new key replaces `path` atomically — written to
/// a sibling `0600` file and renamed — so a crash mid-rotation cannot leave a
/// truncated signing key behind. Nothing here touches the database: rotation is
/// a file operation.
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

// --- hot reload ---

/// How often the running instance re-checks the key files for rotation done
/// out-of-band (`signet keys rotate`, or a peer instance sharing the data
/// directory). Matches the runtime-settings poll cadence.
pub const KEY_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Cheap fingerprint of everything the key ring loads: the active key's bytes
/// plus the set of retired PEM filenames (those are named by kid, so a new
/// retired key is always a new name; same-name rewrite means the same key).
///
/// A missing or unreadable active key is `Ok(None)` rather than an error: the
/// watcher must never *generate* a replacement (a transient read failure or an
/// operator mid-move would otherwise mint a new key), it should just wait for
/// the file to come back.
fn ring_fingerprint(path: &Path, retired_dir: &Path) -> std::io::Result<Option<String>> {
    let pem = match std::fs::read_to_string(path) {
        Ok(pem) => pem,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut retired: Vec<String> = match std::fs::read_dir(retired_dir) {
        Ok(entries) => entries
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().extension().and_then(|e| e.to_str()) == Some("pem"))
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect(),
        Err(_) => Vec::new(), // no retired dir yet: nothing retired
    };
    let mut fingerprint = crate::crypto::util::sha256_hex(&pem);
    retired.sort();
    fingerprint.push('#');
    fingerprint.push_str(&retired.join(","));
    Ok(Some(fingerprint))
}

/// Reloads the ring from disk when the files changed since the last poll.
///
/// Returns whether a new ring was installed. `prev` carries the fingerprint
/// across polls; the caller starts it at `None` so the first poll always
/// syncs up with whatever is on disk. Reload failures keep the current ring —
/// it still verifies every token it ever signed — and the next poll retries.
pub fn reload_ring(
    keys: &arc_swap::ArcSwap<JwtKeys>,
    path: &Path,
    retired_dir: &Path,
    prev: &mut Option<String>,
) -> bool {
    let fingerprint = match ring_fingerprint(path, retired_dir) {
        Ok(fp) => match fp {
            Some(fp) => fp,
            // Key file absent: never generate in the watcher path, just wait.
            None => return false,
        },
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "key poll read failed; keeping current ring");
            return false;
        }
    };
    if Some(&fingerprint) == prev.as_ref() {
        return false;
    }
    match JwtKeys::load_or_generate_with_retired(path, Some(retired_dir)) {
        Ok(ring) => {
            let old_kid = keys.load().kid.clone();
            keys.store(Arc::new(ring));
            *prev = Some(fingerprint);
            tracing::info!(
                old_kid = %old_kid,
                new_kid = %keys.load().kid,
                "signing key ring reloaded from disk"
            );
            true
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                "key reload failed; keeping current ring (tokens it signed still verify)"
            );
            false
        }
    }
}

/// Background poller that hot-swaps the key ring when the key files change on
/// disk, so `signet keys rotate` (or a peer replica rotating a shared data
/// directory) takes effect without a restart.
///
/// There is a small TOCTOU window between the fingerprint read and the reload:
/// a file deleted exactly in between would make the reload *generate* a fresh
/// key. The rotation tooling writes via rename (the path is never absent), and
/// even the pathological case self-heals — the generated key is written back
/// and becomes the active key on disk on the next poll.
pub fn spawn_key_watcher(state: crate::state::AppState) {
    tokio::spawn(async move {
        let path = state.config.jwt_private_key_path.clone();
        let retired_dir = state.config.jwt_retired_key_dir.clone();
        let mut prev: Option<String> = None;
        let mut ticker = tokio::time::interval(KEY_POLL_INTERVAL);
        ticker.tick().await; // boot already loaded the ring; sync the fingerprint
        if let Ok(Some(fp)) = ring_fingerprint(&path, &retired_dir) {
            prev = Some(fp);
        }
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            reload_ring(&state.keys, &path, &retired_dir, &mut prev);
        }
    });
}
