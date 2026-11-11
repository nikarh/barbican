//! The edge agents' connection to an agent: TLS with the agent's certificate pinned by its SHA-256 fingerprint,
//! carrying the frames of `barbican_common::edge::wire`. Agents' certificates are their own (self-signed, made on
//! their first start): no CA, no host names, just the fingerprint, which `barbican edge-fingerprint` prints on the
//! agent.
//!
//! Blocking, without a thread of its own for reading: [`Link::wait`] sleeps in `poll` until the agent sends
//! something, the daemon has something to send (its wake socket), or a deadline.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::Duration;

use barbican_common::edge::wire;
use rustix::event::{PollFd, PollFlags, poll};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};

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
    tls: Arc<ClientConfig>,
}

/// One connection to an agent.
pub struct Link {
    tls: ClientConnection,
    tcp: TcpStream,
    /// What arrived and isn't a whole frame yet, or wasn't taken yet.
    incoming: Vec<u8>,
    /// The agent closed the connection: once the frames before are taken, there is nothing more.
    closed: bool,
}

impl Client {
    /// For `https://<host>[:<port>]`, with the agent's certificate fingerprint.
    pub fn new(url: &str, fingerprint: &str) -> Result<Self, String> {
        let rest = url
            .strip_prefix("https://")
            .ok_or_else(|| format!("{url}: only https:// (the edge API is TLS only)"))?;
        let authority = rest.trim_end_matches('/');
        if authority.contains('/') {
            return Err(format!("{url}: no path (the edge API has none)"));
        }
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
            tls: Arc::new(tls),
        })
    }

    /// Connects, and completes the TLS handshake.
    pub fn connect(&self) -> Result<Link, String> {
        let address = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|e| format!("{}: {e}", self.host))?
            .next()
            .ok_or_else(|| format!("{}: no address", self.host))?;
        let tcp = TcpStream::connect_timeout(&address, Duration::from_secs(10))
            .map_err(|e| format!("{address}: {e}"))?;
        // Reads only happen once poll said there is something; writes may wait for the agent to read.
        tcp.set_read_timeout(Some(Duration::from_secs(10)))
            .and_then(|()| tcp.set_write_timeout(Some(wire::SILENCE)))
            .and_then(|()| tcp.set_nodelay(true))
            .map_err(|e| e.to_string())?;
        // The name only matters for SNI: the certificate is checked by its fingerprint.
        let name = ServerName::try_from(self.host.clone())
            .or_else(|_| ServerName::try_from("barbican".to_owned()))
            .map_err(|e| e.to_string())?;
        let tls = ClientConnection::new(Arc::clone(&self.tls), name).map_err(|e| e.to_string())?;
        let mut link = Link {
            tls,
            tcp,
            incoming: Vec::new(),
            closed: false,
        };
        while link.tls.is_handshaking() {
            link.tls
                .complete_io(&mut link.tcp)
                .map_err(|e| e.to_string())?;
        }
        // Anything that came with the handshake's last records.
        link.take_plaintext()?;
        Ok(link)
    }
}

impl Link {
    /// Sends frames (whole ones).
    pub fn send(&mut self, frames: &[u8]) -> Result<(), String> {
        self.tls
            .writer()
            .write_all(frames)
            .map_err(|e| e.to_string())?;
        self.flush()
    }

    fn flush(&mut self) -> Result<(), String> {
        while self.tls.wants_write() {
            self.tls
                .write_tls(&mut self.tcp)
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// The next whole frame that arrived (its type and payload), if any.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, String> {
        let Some(n) = wire::complete(&self.incoming).map_err(|e| e.to_string())? else {
            if self.closed {
                return Err("the agent closed the connection".to_owned());
            }
            return Ok(None);
        };
        let frame = self.incoming.get(4..n).unwrap_or_default().to_vec();
        self.incoming.drain(..n);
        Ok(Some(frame))
    }

    /// Sleeps until the agent sent something (then reads it, see [`Link::next_frame`]), `wake` is readable (then
    /// drains it), or `timeout` passed.
    pub fn wait(&mut self, wake: &UnixStream, timeout: Duration) -> Result<(), String> {
        let timeout = rustix::event::Timespec::try_from(timeout).map_err(|e| e.to_string())?;
        let (agent, woken) = {
            let mut fds = [
                PollFd::new(&self.tcp, PollFlags::IN),
                PollFd::new(wake, PollFlags::IN),
            ];
            match poll(&mut fds, Some(&timeout)) {
                Ok(_) | Err(rustix::io::Errno::INTR) => {}
                Err(e) => return Err(e.to_string()),
            }
            let [agent, woken] = fds;
            (!agent.revents().is_empty(), !woken.revents().is_empty())
        };
        if woken {
            let mut sink = [0u8; 64];
            let _ = (&*wake).read(&mut sink);
        }
        if agent {
            self.receive()?;
        }
        Ok(())
    }

    /// Reads what the socket has (it said it has something), and takes what TLS makes of it.
    fn receive(&mut self) -> Result<(), String> {
        match self.tls.read_tls(&mut self.tcp) {
            Ok(0) => {
                self.closed = true;
                return Ok(());
            }
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Interrupted => {
                return Ok(());
            }
            Err(e) => return Err(e.to_string()),
        }
        let state = self.tls.process_new_packets().map_err(|e| e.to_string())?;
        self.closed |= state.peer_has_closed();
        self.flush()?;
        self.take_plaintext()
    }

    /// Moves what TLS decrypted to `incoming`.
    fn take_plaintext(&mut self) -> Result<(), String> {
        loop {
            let len = self.incoming.len();
            if len > wire::MAX_FRAME * 4 {
                return Err("the agent sends faster than this edge takes it in".to_owned());
            }
            self.incoming.resize(len + 64 * 1024, 0);
            let read = self
                .tls
                .reader()
                .read(self.incoming.get_mut(len..).unwrap_or_default());
            match read {
                Ok(n) => {
                    self.incoming.truncate(len + n);
                    if n == 0 {
                        break;
                    }
                }
                Err(e) => {
                    self.incoming.truncate(len);
                    if e.kind() == ErrorKind::WouldBlock {
                        break;
                    }
                    return Err(e.to_string());
                }
            }
        }
        Ok(())
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
        let c = Client::new("https://192.0.2.10:7380", &fp).unwrap();
        assert_eq!((c.host.as_str(), c.port), ("192.0.2.10", 7380));
        let c = Client::new("https://[2001:db8::1]:7380/", &fp).unwrap();
        assert_eq!((c.host.as_str(), c.port), ("2001:db8::1", 7380));
        let c = Client::new("https://agent.example", &fp).unwrap();
        assert_eq!(c.port, 443);
        assert!(Client::new("https://192.0.2.10:7380/x", &fp).is_err());
        assert!(Client::new("http://192.0.2.10:7380", &fp).is_err());
        assert!(Client::new("https://192.0.2.10", "nope").is_err());
    }
}
