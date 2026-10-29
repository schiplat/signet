//! A minimal, complete OIDC relying party for Signet.
//!
//! This is the runnable companion to `docs/client-integration.md`: the whole
//! Authorization Code + PKCE flow in one file, with every validation the doc
//! asks for actually performed. Copy it, rename the config, and you have a
//! working integration; read it top to bottom and you have the checklist.
//!
//! Endpoints it serves:
//!
//! - `GET /`               home — signed-in identity, or a sign-in link
//! - `GET /auth/login`     start the flow: state + nonce + PKCE → authorize
//! - `GET /auth/callback`  verify state → exchange code → validate id_token
//!   (iss / aud / exp / nonce / RS256 via JWKS) → upsert local user by
//!   `sub` → issue local session
//! - `GET /auth/logout`    drop the local session, then RP-initiated logout
//! - `GET /signed-out`     public landing page (logout redirect target)
//! - `GET /health`         liveness, public
//!
//! What is deliberately simplified: users and in-flight authorizations live in
//! in-memory maps (a real service puts them in its database), and the session
//! cookie is an opaque random id into the map rather than a signed token. The
//! protocol side — everything Signet actually checks — is not simplified.
//!
//! Configuration is environment variables (see `Config::from_env`), matching
//! the names in the integration guide.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
    Router,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use base64::Engine;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct Config {
    issuer: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    scopes: String,
    post_logout_redirect_uri: String,
}

impl Config {
    /// Reads the environment the same way `docs/client-integration.md` §9
    /// names the values. Everything has a dev default except the issuer and
    /// the client credentials, which cannot be guessed.
    fn from_env() -> Result<Self, String> {
        let var = |name: &str| std::env::var(name).ok();
        let default_redirect = "http://127.0.0.1:3000/auth/callback".to_string();
        Ok(Self {
            issuer: var("OIDC_ISSUER")
                .ok_or("OIDC_ISSUER is required (e.g. http://localhost:8443)")?,
            client_id: var("OIDC_CLIENT_ID").ok_or("OIDC_CLIENT_ID is required")?,
            client_secret: var("OIDC_CLIENT_SECRET").ok_or("OIDC_CLIENT_SECRET is required")?,
            redirect_uri: var("OIDC_REDIRECT_URI").unwrap_or(default_redirect.clone()),
            scopes: var("OIDC_SCOPES").unwrap_or_else(|| "openid profile email".into()),
            post_logout_redirect_uri: var("OIDC_POST_LOGOUT_REDIRECT_URI")
                .unwrap_or_else(|| default_redirect.replace("/auth/callback", "/signed-out")),
        })
    }
}

// ---------------------------------------------------------------------------
// Discovery, tokens, claims
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Discovery {
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    end_session_endpoint: Option<String>,
}

/// Only what this example needs; Signet's discovery document has more.
#[derive(Deserialize)]
struct DiscoveryDoc {
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    end_session_endpoint: Option<String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
    // `access_token` / `refresh_token` are also returned but deliberately not
    // bound: business APIs authenticate against this app's own session, not
    // against Signet's tokens (docs/client-integration.md §6).
}

/// The id_token claims this example relies on. `sub` is the primary key —
/// never key users on `email`, which an administrator can change.
#[derive(serde::Serialize, Deserialize)]
struct IdClaims {
    sub: String,
    nonce: Option<String>,
    email: Option<String>,
    name: Option<String>,
    exp: i64,
}

#[derive(Clone, Debug)]
struct User {
    sub: String,
    email: Option<String>,
    name: Option<String>,
}

/// A pending authorization: what we stashed before the browser left and must
/// find unchanged when it comes back.
struct Pending {
    verifier: String,
    nonce: String,
    created: Instant,
}

impl Pending {
    fn fresh(&self) -> bool {
        self.created.elapsed() < Duration::from_secs(10 * 60)
    }
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

struct AppState {
    cfg: Config,
    http: reqwest::Client,
    discovery: tokio::sync::OnceCell<Discovery>,
    /// JWKS cache: Signet rotates keys via `kid`, so refetching every few
    /// minutes is enough — no push needed.
    jwks: tokio::sync::RwLock<Option<(jsonwebtoken::jwk::JwkSet, Instant)>>,
    pending: Mutex<HashMap<String, Pending>>,
    sessions: Mutex<HashMap<String, User>>,
}

impl AppState {
    async fn discovery(&self) -> Result<Discovery, String> {
        self.discovery
            .get_or_try_init(|| async {
                let url = format!("{}/.well-known/openid-configuration", self.cfg.issuer);
                let doc: DiscoveryDoc = self
                    .http
                    .get(&url)
                    .send()
                    .await
                    .map_err(|e| format!("discovery GET {url} failed: {e}"))?
                    .json()
                    .await
                    .map_err(|e| format!("discovery at {url} was not valid JSON: {e}"))?;
                Ok::<_, String>(Discovery {
                    authorization_endpoint: doc.authorization_endpoint,
                    token_endpoint: doc.token_endpoint,
                    jwks_uri: doc.jwks_uri,
                    end_session_endpoint: doc.end_session_endpoint,
                })
            })
            .await
            .cloned()
    }

    async fn decoding_key(&self, kid: &str) -> Result<DecodingKey, String> {
        const CACHE_TTL: Duration = Duration::from_secs(300);
        let mut cached = self.jwks.write().await;
        let fresh = matches!(cached.as_ref(), Some((_, at)) if at.elapsed() < CACHE_TTL);
        if !fresh {
            let jwks_uri = &self.discovery().await?.jwks_uri;
            let set: jsonwebtoken::jwk::JwkSet = self
                .http
                .get(jwks_uri)
                .send()
                .await
                .map_err(|e| format!("JWKS GET {jwks_uri} failed: {e}"))?
                .json()
                .await
                .map_err(|e| format!("JWKS at {jwks_uri} was not valid JSON: {e}"))?;
            *cached = Some((set, Instant::now()));
        }
        let (set, _) = cached.as_ref().ok_or("JWKS cache empty after refresh")?;
        set.find(kid)
            .ok_or_else(|| {
                format!("JWKS has no key for kid {kid} (rotated? refetches every 5 min)")
            })
            .and_then(|jwk| DecodingKey::from_jwk(jwk).map_err(|e| e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn random_b64url() -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

/// PKCE S256: the verifier is the secret, the challenge its SHA-256, both
/// base64url without padding — exactly what Signet's authorize requires.
fn pkce_pair() -> (String, String) {
    let verifier = random_b64url();
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

fn cookie(name: &str, value: &str, max_age_secs: i64) -> Cookie<'static> {
    // SameSite=Lax is what makes the callback (a cross-site redirect target)
    // still carry the cookie while blocking other cross-site sends.
    let mut c = Cookie::build((name.to_string(), value.to_string()))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::seconds(max_age_secs))
        .build();
    if let Ok(issuer) = std::env::var("OIDC_ISSUER") {
        if issuer.starts_with("https://") {
            c.set_secure(true);
        }
    }
    c
}

const PENDING_COOKIE: &str = "qs_pending";
const SESSION_COOKIE: &str = "qs_session";

fn error_page(status: StatusCode, message: &str) -> Response {
    (
        status,
        Html(format!(
            "<h1>Sign-in failed</h1><p>{message}</p><p><a href=\"/auth/login\">Try again</a></p>"
        )),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn home(State(state): State<std::sync::Arc<AppState>>, jar: CookieJar) -> Html<String> {
    let body = match session_user(&state, &jar) {
        Some(user) => format!(
            "<h1>Hello, {}</h1><p>sub = <code>{}</code></p><p>email = {:?}</p>\
             <p><a href=\"/auth/logout\">Sign out</a></p>",
            user.name.as_deref().unwrap_or("(no name)"),
            user.sub,
            user.email
        ),
        None => "<h1>Signet quickstart client</h1><p><a href=\"/auth/login\">Sign in</a></p>"
            .to_string(),
    };
    Html(body)
}

/// Kicks off the flow. Everything the callback will later verify is minted
/// here: `state` (CSRF), `nonce` (replay), and the PKCE pair.
async fn login(
    State(state): State<std::sync::Arc<AppState>>,
    jar: CookieJar,
) -> Result<Response, Response> {
    let discovery = state
        .discovery()
        .await
        .map_err(|e| error_page(StatusCode::BAD_GATEWAY, &e))?;

    let login_state = random_b64url();
    let (verifier, challenge) = pkce_pair();
    let nonce = uuid::Uuid::new_v4().to_string();

    state.pending.lock().unwrap().insert(
        login_state.clone(),
        Pending {
            verifier,
            nonce,
            created: Instant::now(),
        },
    );

    let url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
        discovery.authorization_endpoint,
        urlencoding(&state.cfg.client_id),
        urlencoding(&state.cfg.redirect_uri),
        urlencoding(&state.cfg.scopes),
        urlencoding(&login_state),
        urlencoding(&state.pending.lock().unwrap()[&login_state].nonce),
        urlencoding(&challenge),
    );
    Ok((
        jar.add(cookie(PENDING_COOKIE, &login_state, 600)),
        Redirect::to(&url),
    )
        .into_response())
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

async fn callback(
    State(state): State<std::sync::Arc<AppState>>,
    jar: CookieJar,
    Query(q): Query<CallbackQuery>,
) -> Result<Response, Response> {
    if let Some(err) = q.error {
        return Err(error_page(
            StatusCode::UNAUTHORIZED,
            &format!(
                "authorize failed: {} ({})",
                err,
                q.error_description.unwrap_or_default()
            ),
        ));
    }
    let (Some(code), Some(returned_state)) = (q.code.as_deref(), q.state.as_deref()) else {
        return Err(error_page(StatusCode::BAD_REQUEST, "missing code or state"));
    };

    // state check: the value in the URL must be the one this browser was
    // handed when the flow started. One-time: remove on read.
    let pending = jar.get(PENDING_COOKIE).map(|c| c.value().to_string());
    let Some(pending_key) = pending.filter(|k| k == returned_state) else {
        return Err(error_page(StatusCode::UNAUTHORIZED, "state mismatch"));
    };
    let Some(pending) = state
        .pending
        .lock()
        .unwrap()
        .remove(&pending_key)
        .filter(Pending::fresh)
    else {
        return Err(error_page(
            StatusCode::UNAUTHORIZED,
            "unknown or expired sign-in",
        ));
    };
    let jar = jar.remove(PENDING_COOKIE);

    // Code + verifier → tokens (client_secret_post).
    let discovery = state
        .discovery()
        .await
        .map_err(|e| error_page(StatusCode::BAD_GATEWAY, &e))?;
    let token: TokenResponse = state
        .http
        .post(&discovery.token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", state.cfg.redirect_uri.as_str()),
            ("client_id", state.cfg.client_id.as_str()),
            ("client_secret", state.cfg.client_secret.as_str()),
            ("code_verifier", pending.verifier.as_str()),
        ])
        .send()
        .await
        .map_err(|e| {
            error_page(
                StatusCode::BAD_GATEWAY,
                &format!("token request failed: {e}"),
            )
        })?
        .json()
        .await
        .map_err(|e| {
            error_page(
                StatusCode::BAD_GATEWAY,
                &format!("token response was not JSON: {e}"),
            )
        })?;

    // id_token validation: signature (RS256, JWKS by kid), iss, aud, exp —
    // and our own nonce, which `jsonwebtoken` does not know about.
    let header = decode_header(&token.id_token).map_err(|e| {
        error_page(
            StatusCode::UNAUTHORIZED,
            &format!("id_token is not a JWT: {e}"),
        )
    })?;
    if header.alg != Algorithm::RS256 {
        return Err(error_page(
            StatusCode::UNAUTHORIZED,
            "id_token must be RS256",
        ));
    }
    let Some(kid) = header.kid else {
        return Err(error_page(
            StatusCode::UNAUTHORIZED,
            "id_token header has no kid",
        ));
    };
    let key = state
        .decoding_key(&kid)
        .await
        .map_err(|e| error_page(StatusCode::BAD_GATEWAY, &e))?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[&state.cfg.issuer]);
    validation.set_audience(&[&state.cfg.client_id]);
    let claims = decode::<IdClaims>(&token.id_token, &key, &validation)
        .map_err(|e| error_page(StatusCode::UNAUTHORIZED, &format!("id_token rejected: {e}")))?
        .claims;
    if claims.nonce.as_deref() != Some(pending.nonce.as_str()) {
        return Err(error_page(StatusCode::UNAUTHORIZED, "nonce mismatch"));
    }

    // `sub` is the stable key; upsert the local user and issue our own
    // session. (An in-memory map here; a database keyed on `sub` in a real
    // service.) The access/refresh tokens are not used further — business
    // APIs authenticate against this session, not against Signet's tokens.
    let session_id = random_b64url();
    state.sessions.lock().unwrap().insert(
        session_id.clone(),
        User {
            sub: claims.sub,
            email: claims.email,
            name: claims.name,
        },
    );
    Ok((
        jar.add(cookie(SESSION_COOKIE, &session_id, 8 * 3600)),
        Redirect::to("/"),
    )
        .into_response())
}

async fn logout(State(state): State<std::sync::Arc<AppState>>, jar: CookieJar) -> Response {
    if let Some(sid) = jar.get(SESSION_COOKIE).map(|c| c.value().to_string()) {
        state.sessions.lock().unwrap().remove(&sid);
    }
    let jar = jar.remove(SESSION_COOKIE);

    // RP-initiated logout: clear the SSO session too, and come back to a
    // page that does not require auth (see the guide's §8.5 — without a
    // public landing page the user is bounced straight back to a login form).
    let target = match state.discovery().await {
        Ok(d) => d.end_session_endpoint.as_ref().map(|end| {
            format!(
                "{}?client_id={}&post_logout_redirect_uri={}",
                end,
                urlencoding(&state.cfg.client_id),
                urlencoding(&state.cfg.post_logout_redirect_uri),
            )
        }),
        Err(_) => None,
    };
    (
        jar,
        Redirect::to(target.as_deref().unwrap_or("/signed-out")),
    )
        .into_response()
}

async fn signed_out() -> Html<&'static str> {
    Html("<h1>Signed out</h1><p><a href=\"/auth/login\">Sign in again</a></p>")
}

async fn health() -> &'static str {
    "ok"
}

fn session_user(state: &AppState, jar: &CookieJar) -> Option<User> {
    let sid = jar.get(SESSION_COOKIE)?.value();
    state.sessions.lock().unwrap().get(sid).cloned()
}

fn urlencoding(s: &str) -> String {
    // Minimal query encoding for the values this example sends.
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[tokio::main]
async fn main() {
    let cfg = match Config::from_env() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("configuration error: {e}");
            std::process::exit(2);
        }
    };
    let state = std::sync::Arc::new(AppState {
        cfg,
        http: reqwest::Client::new(),
        discovery: tokio::sync::OnceCell::new(),
        jwks: tokio::sync::RwLock::new(None),
        pending: Mutex::new(HashMap::new()),
        sessions: Mutex::new(HashMap::new()),
    });

    let app = Router::new()
        .route("/", get(home))
        .route("/auth/login", get(login))
        .route("/auth/callback", get(callback))
        .route("/auth/logout", get(logout))
        .route("/signed-out", get(signed_out))
        .route("/health", get(health))
        .with_state(state);

    let addr: SocketAddr = std::env::var("BIND")
        .unwrap_or_else(|_| "127.0.0.1:3000".into())
        .parse()
        .expect("valid BIND");
    println!("quickstart client listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    axum::serve(listener, app).await.expect("serve");
}
