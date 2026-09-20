use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "../../dashboard/dist"]
struct DashboardAssets;

pub async fn spa_fallback(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    if path.is_empty() {
        return serve_file("index.html");
    }
    if let Some(resp) = try_file(path) {
        return resp;
    }
    // SPA client routes
    serve_file("index.html")
}

fn try_file(path: &str) -> Option<Response> {
    let file = DashboardAssets::get(path)?;
    let mime = mime_guess::from_path(path)
        .first_or_octet_stream()
        .to_string();
    Some(
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, mime)],
            file.data.to_vec(),
        )
            .into_response(),
    )
}

fn serve_file(path: &str) -> Response {
    match try_file(path) {
        Some(resp) => resp,
        None => (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "text/plain")],
            "dashboard assets missing; build dashboard/ first",
        )
            .into_response(),
    }
}
