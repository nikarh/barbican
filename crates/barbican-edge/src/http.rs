//! The edge agents' HTTPS client: one GET per connection, over TLS with the agent's certificate pinned by its
//! SHA-256 fingerprint. Agents' certificates are their own (self-signed, made on their first start): no CA, no host
//! names, just the fingerprint, which `barbican edge-fingerprint` prints on the agent.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};

/// The SHA-256 of a certificate (DER), as `barbican edge-fingerprint` writes it: hex pairs joined by colons.
#[must_use]
pub fn fingerprint(der: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, der);
    digest
        .as_ref()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Reads a fingerprint as written, with or without colons, in either case.
pub fn parse_fingerprint(text: &str) -> Result<[u8; 32], String> {
    let hex: String = text
        .trim()
        .trim_start_matches("SHA256:")
        .chars()
        .filter(|c| *c != ':')
        .collect();
    if hex.len() != 64 {
        return Err(format!("not a SHA-256 fingerprint: {text:?}"));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let pair = hex.get(i * 2..i * 2 + 2).ok_or("bad fingerprint")?;
        *byte = u8::from_str_radix(pair, 16)
            .map_err(|_| format!("not a SHA-256 fingerprint: {text:?}"))?;
    }
    Ok(out)
}

/// Accepts exactly the certificate with this fingerprint; its signatures are checked as usual.
#[derive(Debug)]
struct Pinned {
    fingerprint: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let digest = ring::digest::digest(&ring::digest::SHA256, end_entity.as_ref());
        // Public data: no need for a constant-time comparison.
        if digest.as_ref() == self.fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "the agent's certificate is {}, not the configured fingerprint",
                fingerprint(end_entity.as_ref())
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub struct Client {
    host: String,
    port: u16,
    base: String,
    tls: Arc<ClientConfig>,
    authorization: String,
    user_agent: String,
}

impl Client {
    /// For `https://<host>[:<port>][/<base path>]`, with the agent's certificate fingerprint and a token.
    pub fn new(
        url: &str,
        fingerprint: &str,
        token: &str,
        user_agent: &str,
    ) -> Result<Self, String> {
        let rest = url
            .strip_prefix("https://")
            .ok_or_else(|| format!("{url}: only https:// (the edge API is TLS only)"))?;
        let (authority, base) = rest.split_once('/').map_or((rest, ""), |(a, b)| (a, b));
        let (host, port) = match authority.rsplit_once(':') {
            // [2001:db8::1]:7380, or host:7380
            Some((h, p)) if !h.ends_with(':') && p.chars().all(|c| c.is_ascii_digit()) => (
                h.trim_start_matches('[').trim_end_matches(']'),
                p.parse().map_err(|_| format!("{url}: bad port"))?,
            ),
            _ => (authority.trim_start_matches('[').trim_end_matches(']'), 443),
        };
        if host.is_empty() {
            return Err(format!("{url}: no host"));
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = Pinned {
            fingerprint: parse_fingerprint(fingerprint)?,
            provider: Arc::clone(&provider),
        };
        let tls = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        Ok(Self {
            host: host.to_owned(),
            port,
            base: if base.is_empty() {
                String::new()
            } else {
                format!("/{}", base.trim_end_matches('/'))
            },
            tls: Arc::new(tls),
            authorization: format!("Bearer {token}"),
            user_agent: user_agent.to_owned(),
        })
    }

    /// GETs `path` (with its query), and returns the body of a 200 response, of at most `limit` bytes.
    pub fn get(&self, path: &str, timeout: Duration, limit: u64) -> Result<String, String> {
        let address = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|e| format!("{}: {e}", self.host))?
            .next()
            .ok_or_else(|| format!("{}: no address", self.host))?;
        let tcp = TcpStream::connect_timeout(&address, Duration::from_secs(10))
            .map_err(|e| format!("{address}: {e}"))?;
        tcp.set_read_timeout(Some(timeout))
            .map_err(|e| e.to_string())?;
        tcp.set_write_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| e.to_string())?;
        // The name only matters for SNI: the certificate is checked by its fingerprint.
        let name = ServerName::try_from(self.host.clone())
            .or_else(|_| ServerName::try_from("barbican".to_owned()))
            .map_err(|e| e.to_string())?;
        let connection =
            ClientConnection::new(Arc::clone(&self.tls), name).map_err(|e| e.to_string())?;
        let mut stream = StreamOwned::new(connection, tcp);
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let request = format!(
            "GET {}{path} HTTP/1.1\r\nHost: {host}:{}\r\nAuthorization: {}\r\nUser-Agent: {}\r\nAccept: */*\r\n\
             Connection: close\r\n\r\n",
            self.base, self.port, self.authorization, self.user_agent
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|e| e.to_string())?;
        let mut raw = Vec::new();
        match Read::by_ref(&mut stream)
            .take(limit + 64 * 1024)
            .read_to_end(&mut raw)
        {
            Ok(_) => {}
            // Some servers close without TLS's close_notify: what arrived is checked by its length below.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !raw.is_empty() => {}
            Err(e) => return Err(e.to_string()),
        }
        parse_response(&raw, limit)
    }
}

/// The body of a complete 200 response.
fn parse_response(raw: &[u8], limit: u64) -> Result<String, String> {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("an incomplete response")?;
    let head = std::str::from_utf8(raw.get(..end).unwrap_or(&[])).map_err(|e| e.to_string())?;
    let body = raw.get(end + 4..).unwrap_or(&[]);
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or("");
    let code = status.split_whitespace().nth(1).unwrap_or("");
    if code != "200" {
        return Err(format!(
            "HTTP {}",
            status.split_once(' ').map_or(status, |(_, s)| s)
        ));
    }
    let mut length = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            length = value.parse::<usize>().ok();
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            && value.eq_ignore_ascii_case("chunked")
        {
            chunked = true;
        }
    }
    let body = if chunked {
        dechunk(body)?
    } else if let Some(n) = length {
        body.get(..n).ok_or("the response ended early")?.to_vec()
    } else {
        body.to_vec()
    };
    if body.len() as u64 > limit {
        return Err("the response is too large".to_owned());
    }
    String::from_utf8(body).map_err(|e| e.to_string())
}

fn dechunk(mut body: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let line_end = body
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or("a broken chunk")?;
        let size_text =
            std::str::from_utf8(body.get(..line_end).unwrap_or(&[])).map_err(|e| e.to_string())?;
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| "a broken chunk size")?;
        body = body.get(line_end + 2..).ok_or("a broken chunk")?;
        if size == 0 {
            return Ok(out);
        }
        out.extend_from_slice(body.get(..size).ok_or("the response ended early")?);
        body = body.get(size + 2..).ok_or("a broken chunk")?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints() {
        let f = fingerprint(b"x");
        assert_eq!(f.len(), 95);
        assert_eq!(
            parse_fingerprint(&f).unwrap(),
            parse_fingerprint(&f.replace(':', "").to_lowercase()).unwrap()
        );
        assert!(parse_fingerprint("AB:CD").is_err());
        assert!(parse_fingerprint(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn urls() {
        let fp = "00".repeat(32);
        let c = Client::new("https://192.0.2.10:7380", &fp, "t", "ua").unwrap();
        assert_eq!(
            (c.host.as_str(), c.port, c.base.as_str()),
            ("192.0.2.10", 7380, "")
        );
        let c = Client::new("https://[2001:db8::1]:7380/x/", &fp, "t", "ua").unwrap();
        assert_eq!(
            (c.host.as_str(), c.port, c.base.as_str()),
            ("2001:db8::1", 7380, "/x")
        );
        let c = Client::new("https://agent.example", &fp, "t", "ua").unwrap();
        assert_eq!(c.port, 443);
        assert!(Client::new("http://192.0.2.10:7380", &fp, "t", "ua").is_err());
        assert!(Client::new("https://192.0.2.10", "nope", "t", "ua").is_err());
    }

    #[test]
    fn responses() {
        let ok = b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello";
        assert_eq!(parse_response(ok, 100).unwrap(), "hello");
        let chunked = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        assert_eq!(parse_response(chunked, 100).unwrap(), "hello world");
        assert_eq!(
            parse_response(b"HTTP/1.1 401 Unauthorized\r\n\r\n", 100).unwrap_err(),
            "HTTP 401 Unauthorized"
        );
        assert!(parse_response(b"HTTP/1.1 200 OK\r\ncontent-length: 9\r\n\r\nhi", 100).is_err());
        assert!(parse_response(ok, 2).is_err());
    }
}
