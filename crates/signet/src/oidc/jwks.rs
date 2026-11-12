use crate::state::AppState;
use axum::extract::State;
use axum::Json;
use serde_json::Value;

pub async fn jwks(State(state): State<AppState>) -> Json<Value> {
    Json(
        serde_json::to_value(state.keys.load().jwks().as_ref())
            .unwrap_or_else(|_| serde_json::json!({"keys":[]})),
    )
}
