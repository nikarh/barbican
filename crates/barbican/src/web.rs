//! The embedded frontend, sent compressed (brotli or gzip, made at build time) to browsers that accept it.

use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};

/// A file of the built frontend, with its compressed copies when compressing it saved something.
struct Asset {
    name: &'static str,
    identity: &'static [u8],
    br: Option<&'static [u8]>,
    gzip: Option<&'static [u8]>,
}

mod assets {
    use super::Asset;
    include!(concat!(env!("OUT_DIR"), "/assets.rs"));
}

const PLACEHOLDER: &str = "<!doctype html><title>Barbican</title><p>The frontend wasn't built into this binary: \
    run <code>mise run web:build</code> and build again.";

static PLACEHOLDER_ASSET: Asset = Asset {
    name: "index.html",
    identity: PLACEHOLDER.as_bytes(),
    br: None,
    gzip: None,
};

fn find(path: &str) -> Option<&'static Asset> {
    assets::FILES.iter().find(|asset| asset.name == path)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Encoding {
    Br,
    Gzip,
}

/// Whether `Accept-Encoding` accepts `coding`: named, or by `*`, without `q=0`.
fn accepts(headers: &HeaderMap, coding: &str) -> bool {
    let mut named = None;
    let mut any = None;
    for value in headers.get_all(header::ACCEPT_ENCODING) {
        let Ok(value) = value.to_str() else { continue };
        for item in value.split(',') {
            let mut parts = item.split(';');
            let name = parts.next().unwrap_or("").trim();
            let zero = parts.any(|p| {
                p.trim()
                    .strip_prefix("q=")
                    .and_then(|q| q.trim().parse::<f32>().ok())
                    .is_some_and(|q| q <= 0.0)
            });
            if name.eq_ignore_ascii_case(coding) {
                named = Some(!zero);
            } else if name == "*" {
                any = Some(!zero);
            }
        }
    }
    named.or(any).unwrap_or(false)
}

/// The smallest copy of `asset` that the request accepts.
fn negotiate(asset: &Asset, headers: &HeaderMap) -> (&'static [u8], Option<Encoding>) {
    if let Some(bytes) = asset.br.filter(|_| accepts(headers, "br")) {
        return (bytes, Some(Encoding::Br));
    }
    if let Some(bytes) = asset.gzip.filter(|_| accepts(headers, "gzip")) {
        return (bytes, Some(Encoding::Gzip));
    }
    (asset.identity, None)
}

fn respond(asset: &'static Asset, cache: &'static str, headers: &HeaderMap) -> Response {
    let (bytes, encoding) = negotiate(asset, headers);
    let mut response = (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static(content_type(asset.name)),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static(cache)),
        ],
        bytes,
    )
        .into_response();
    let out = response.headers_mut();
    if asset.br.is_some() || asset.gzip.is_some() {
        // Caches in between keep a copy per encoding.
        out.insert(header::VARY, HeaderValue::from_static("accept-encoding"));
    }
    match encoding {
        Some(Encoding::Br) => {
            out.insert(header::CONTENT_ENCODING, HeaderValue::from_static("br"));
        }
        Some(Encoding::Gzip) => {
            out.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        }
        None => {}
    }
    response
}

/// Serves a file, or `index.html` for the routes of the single page app.
pub async fn serve(uri: Uri, headers: HeaderMap) -> Response {
    let path = uri.path().trim_start_matches('/');
    if let Some(asset) = find(path).filter(|_| !path.is_empty()) {
        // Vite puts a content hash in every file name under assets/.
        let cache = if path.starts_with("assets/") {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        };
        return respond(asset, cache, &headers);
    }
    if path.starts_with("assets/") || path.starts_with("api/") {
        return StatusCode::NOT_FOUND.into_response();
    }
    let index = find("index.html").unwrap_or(&PLACEHOLDER_ASSET);
    respond(index, "no-cache", &headers)
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

    fn headers(accept: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_str(accept).unwrap(),
        );
        headers
    }

    static BOTH: Asset = Asset {
        name: "assets/a.js",
        identity: b"identity",
        br: Some(b"br"),
        gzip: Some(b"gzip"),
    };

    #[test]
    fn negotiates_the_smallest_accepted() {
        let encoding = |accept: &str| negotiate(&BOTH, &headers(accept)).1;
        assert_eq!(encoding("gzip, deflate, br, zstd"), Some(Encoding::Br));
        assert_eq!(encoding("gzip, deflate"), Some(Encoding::Gzip));
        assert_eq!(encoding("br;q=0, gzip"), Some(Encoding::Gzip));
        assert_eq!(encoding("BR;q=0.5"), Some(Encoding::Br));
        assert_eq!(encoding("*"), Some(Encoding::Br));
        assert_eq!(encoding("*, br;q=0"), Some(Encoding::Gzip));
        assert_eq!(encoding("identity"), None);
        assert_eq!(negotiate(&BOTH, &HeaderMap::new()).1, None);
    }

    #[tokio::test]
    async fn sets_encoding_and_vary() {
        let response = respond(&BOTH, "no-cache", &headers("gzip, br"));
        assert_eq!(response.headers()[header::CONTENT_ENCODING], "br");
        assert_eq!(response.headers()[header::VARY], "accept-encoding");
        let response = respond(&BOTH, "no-cache", &HeaderMap::new());
        assert!(response.headers().get(header::CONTENT_ENCODING).is_none());
        assert_eq!(response.headers()[header::VARY], "accept-encoding");
    }
}
