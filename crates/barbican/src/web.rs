//! The embedded frontend.

use axum::http::{HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};

mod assets {
    include!(concat!(env!("OUT_DIR"), "/assets.rs"));
}

const PLACEHOLDER: &str = "<!doctype html><title>barbican</title><p>The frontend wasn't built into this binary: \
    run <code>mise run web:build</code> and build again.";

fn find(path: &str) -> Option<&'static [u8]> {
    assets::FILES
        .iter()
        .find(|(name, _)| *name == path)
        .map(|(_, bytes)| *bytes)
}

fn content_type(path: &str) -> &'static str {
    match path.rsplit_once('.').map_or("", |(_, ext)| ext) {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json",
        "webmanifest" => "application/manifest+json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// Serves a file, or `index.html` for the routes of the single page app.
pub async fn serve(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    if let Some(bytes) = find(path).filter(|_| !path.is_empty()) {
        // Vite puts a content hash in every file name under assets/.
        let cache = if path.starts_with("assets/") {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        };
        return (
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static(content_type(path)),
                ),
                (header::CACHE_CONTROL, HeaderValue::from_static(cache)),
            ],
            bytes,
        )
            .into_response();
    }
    if path.starts_with("assets/") || path.starts_with("api/") {
        return StatusCode::NOT_FOUND.into_response();
    }
    let index: &[u8] = find("index.html").unwrap_or(PLACEHOLDER.as_bytes());
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-cache")),
        ],
        index,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_types() {
        assert_eq!(
            content_type("assets/index-abc.js"),
            "text/javascript; charset=utf-8"
        );
        assert_eq!(content_type("noext"), "application/octet-stream");
    }
}
