use crate::state::AppState;
use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

pub async fn openid_configuration(State(state): State<AppState>) -> Json<Value> {
    let issuer = state.issuer();
    Json(json!({
        "issuer": issuer.clone(),
        "authorization_endpoint": format!("{issuer}/oauth/authorize"),
        "token_endpoint": format!("{issuer}/oauth/token"),
        "revocation_endpoint": format!("{issuer}/oauth/revoke"),
        "registration_endpoint": format!("{issuer}/oauth/register"),
        "userinfo_endpoint": format!("{issuer}/oauth/userinfo"),
        "introspection_endpoint": format!("{issuer}/oauth/introspect"),
        "jwks_uri": format!("{issuer}/oauth/jwks"),
        "end_session_endpoint": format!("{issuer}/oauth/end_session"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email", "phone", "groups"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "revocation_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "introspection_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "backchannel_logout_supported": true,
        "backchannel_logout_session_supported": false,
        "request_parameter_supported": false,
        "request_uri_parameter_supported": false,
        "code_challenge_methods_supported": ["S256"],
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "email", "name", "phone_number", "groups"],
    }))
}
