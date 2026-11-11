//! Talking to `nf_tables` over a netlink socket, and telling whether anyone else changed the ruleset.

use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustix::io::Errno;
use rustix::net::netlink::SocketAddrNetlink;
use rustix::net::{AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType, netlink, sockopt};

use super::Error;
use super::wire::{self, Messages, NLMSG_DONE, NLMSG_ERROR, NLMSG_OVERRUN, Writer};

/// Replies to requests, and dumps: the kernel fills messages of up to 32 KiB, errors echo up to 64 KiB.
const RECV_BUFFER: usize = 128 * 1024;
/// How long a reply may take. Transactions are applied while they are sent, so this only guards against a lost
/// reply.
const TIMEOUT: Duration = Duration::from_secs(10);

fn io_error(what: &str, e: Errno) -> Error {
    Error::Netlink(format!("{what}: {}", std::io::Error::from(e)))
}

/// An error the kernel answered with. A missing table or set is what `nft` failing means elsewhere: the table
/// needs setting up again.
fn kernel_error(code: i32) -> Error {
    let e = std::io::Error::from_raw_os_error(-code);
    if -code == Errno::NOENT.raw_os_error() {
        Error::Nft(format!("nf_tables: {e}"))
    } else {
        Error::Netlink(format!("nf_tables refused: {e}"))
    }
}

fn open() -> Result<OwnedFd, Error> {
    let fd = rustix::net::socket_with(
        AddressFamily::NETLINK,
        SocketType::RAW,
        SocketFlags::CLOEXEC,
        Some(netlink::NETFILTER),
    )
    .map_err(|e| io_error("netlink socket", e))?;
    rustix::net::bind(&fd, &SocketAddrNetlink::new(0, 0)).map_err(|e| io_error("bind", e))?;
    sockopt::set_socket_timeout(&fd, sockopt::Timeout::Recv, Some(TIMEOUT))
        .map_err(|e| io_error("SO_RCVTIMEO", e))?;
    Ok(fd)
}

fn send(fd: &OwnedFd, data: &[u8]) -> Result<(), Error> {
    let kernel = SocketAddrNetlink::new(0, 0);
    let sent = rustix::net::sendto(fd, data, SendFlags::empty(), &kernel)
        .map_err(|e| io_error("sendto", e))?;
    if sent == data.len() {
        Ok(())
    } else {
        Err(Error::Netlink(format!(
            "sent {sent} of {} bytes",
            data.len()
        )))
    }
}

/// Receives one datagram (any number of messages) into `buf`. One that doesn't fit (only an error echoing a
/// large request can be that large) is cut: its error code comes first.
fn recv(fd: &OwnedFd, buf: &mut [u8], flags: RecvFlags) -> Result<usize, Errno> {
    loop {
        match rustix::net::recv(fd, &mut *buf, flags) {
            Err(Errno::INTR) => {}
            other => return other.map(|(len, _)| len),
        }
    }
}

/// The sequence number after the messages in `data`.
fn next_seq(data: &[u8]) -> u32 {
    Messages(data).last().map_or(0, |m| m.seq).wrapping_add(1)
}

/// The sequence numbers of the messages in `data` that ask for an acknowledgement.
fn acked(data: &[u8]) -> Vec<u32> {
    Messages(data)
        .filter(|m| m.flags & wire::NLM_F_ACK != 0)
        .map(|m| m.seq)
        .collect()
}

/// The generation after one commit: the kernel counts every commit, skipping 0.
fn next_generation(generation: u32) -> u32 {
    match generation.wrapping_add(1) {
        0 => 1,
        g => g,
    }
}

struct Socket {
    fd: OwnedFd,
    seq: u32,
    sndbuf: usize,
}

/// `nf_tables` over netlink. Clones share the socket.
///
/// It also tells whether anyone else changed the ruleset, the way `nft` keeps its own cache: the kernel counts
/// every commit to `nf_tables` (of any table, by any program) in the ruleset's generation. The generation after
/// this process' last commit, or after its last read of its table, is kept; while the kernel's is still that one,
/// nothing changed. Asking costs one small request.
#[derive(Clone, Default)]
pub struct Kernel {
    socket: Arc<Mutex<Option<Socket>>>,
    /// The generation at which this process knew what its table holds.
    known: Arc<Mutex<Option<u32>>>,
}

impl std::fmt::Debug for Kernel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Kernel").finish_non_exhaustive()
    }
}

impl Kernel {
    /// Runs `f` with the socket, opening it first; a socket that failed is closed, the next call opens another.
    fn with<T>(&self, f: impl FnOnce(&mut Socket) -> Result<T, Error>) -> Result<T, Error> {
        let mut guard = self
            .socket
            .lock()
            .map_err(|_| Error::Netlink("lock poisoned".to_owned()))?;
        if guard.is_none() {
            *guard = Some(Socket {
                fd: open()?,
                seq: 1,
                sndbuf: 0,
            });
        }
        let Some(socket) = guard.as_mut() else {
            return Err(Error::Netlink("no socket".to_owned()));
        };
        let result = f(socket);
        if matches!(result, Err(Error::Netlink(_))) {
            *guard = None;
        }
        result
    }

    fn set_known(&self, generation: Option<u32>) {
        if let Ok(mut known) = self.known.lock() {
            *known = generation;
        }
    }

    fn known(&self) -> Option<u32> {
        self.known.lock().ok().and_then(|k| *k)
    }

    /// Sends a request built by `build` (given the first sequence number to use) and collects the replies to it
    /// until the dump is done (`dump`) or each message that asked for an acknowledgement got one. Replies to
    /// earlier requests (a timed-out one) are skipped. `on` sees each reply that isn't an acknowledgement.
    fn exchange(
        socket: &mut Socket,
        data: &[u8],
        dump: bool,
        on: &mut dyn FnMut(&[u8]),
    ) -> Result<(), Error> {
        let first = Messages(data).next().map_or(0, |m| m.seq);
        let last = Messages(data).last().map_or(0, |m| m.seq);
        let mut waiting = acked(data);
        if socket.sndbuf < data.len() {
            let size = data.len() + 4096;
            if sockopt::set_socket_send_buffer_size_force(&socket.fd, size).is_err() {
                sockopt::set_socket_send_buffer_size(&socket.fd, size)
                    .map_err(|e| io_error("SO_SNDBUF", e))?;
            }
            let rcv = RECV_BUFFER.max(waiting.len() * 1024);
            if sockopt::set_socket_recv_buffer_size_force(&socket.fd, rcv).is_err() {
                let _ = sockopt::set_socket_recv_buffer_size(&socket.fd, rcv);
            }
            socket.sndbuf = size;
        }
        send(&socket.fd, data)?;
        let mut buf = vec![0u8; RECV_BUFFER];
        let mut error = None;
        let mut interrupted = false;
        loop {
            if !dump && waiting.is_empty() {
                break;
            }
            // The kernel handles a request while it is sent: once one reply says it failed, whatever else it
            // answers is queued already.
            let flags = if error.is_some() {
                RecvFlags::DONTWAIT
            } else {
                RecvFlags::empty()
            };
            let len = match recv(&socket.fd, &mut buf, flags) {
                Ok(len) => len,
                Err(Errno::AGAIN) if error.is_some() => break,
                Err(e) => return Err(io_error("recv", e)),
            };
            let mut done = false;
            for message in Messages(buf.get(..len).unwrap_or(&[])) {
                if message.seq.wrapping_sub(first) > last.wrapping_sub(first) {
                    continue;
                }
                interrupted |= message.flags & wire::NLM_F_DUMP_INTR != 0;
                match message.kind {
                    NLMSG_ERROR | NLMSG_DONE => {
                        let (code, seq) = message.error().unwrap_or((0, message.seq));
                        waiting.retain(|s| *s != seq);
                        if code != 0 && error.is_none() {
                            error = Some(code);
                        }
                        done |= dump && (message.kind == NLMSG_DONE || code != 0);
                    }
                    NLMSG_OVERRUN => return Err(Error::Netlink("overrun".to_owned())),
                    _ => on(message.raw),
                }
            }
            if done {
                break;
            }
        }
        match error {
            Some(code) => Err(kernel_error(code)),
            None if interrupted => Err(Error::Netlink(
                "the ruleset changed during the dump".to_owned(),
            )),
            None => Ok(()),
        }
    }

    /// Applies a transaction (messages between a batch begin and end, each asking for an acknowledgement).
    ///
    /// What this process knows of its table stays known when the generation moved by this commit alone; if
    /// anything else committed before or meanwhile, the next [`Self::unchanged`] says so.
    pub fn transact(&self, build: &dyn Fn(u32) -> Vec<u8>) -> Result<(), Error> {
        self.with(|socket| {
            let before = Self::generation(socket)?;
            let data = build(socket.seq);
            socket.seq = next_seq(&data);
            let result = Self::exchange(socket, &data, false, &mut |_| {});
            let after = Self::generation(socket).ok();
            let alone = result.is_ok()
                && self.known() == Some(before)
                && after == Some(next_generation(before));
            self.set_known(if alone { after } else { None });
            result
        })
    }

    /// The messages of a dump, one after another.
    pub fn dump(&self, build: &dyn Fn(u32) -> Vec<u8>) -> Result<Vec<u8>, Error> {
        let mut tries = 0;
        loop {
            let result = self.with(|socket| {
                let data = build(socket.seq);
                socket.seq = next_seq(&data);
                let mut out = Vec::new();
                Self::exchange(socket, &data, true, &mut |m| out.extend_from_slice(m))?;
                Ok(out)
            });
            tries += 1;
            match result {
                Err(Error::Netlink(_)) if tries < 3 => {}
                other => return other,
            }
        }
    }

    /// The first datagram of a dump, on a socket of its own that is closed after (the kernel would otherwise keep
    /// the dump going): whether a set has elements, without reading them all.
    pub fn dump_first(&self, build: &dyn Fn(u32) -> Vec<u8>) -> Result<Vec<u8>, Error> {
        let fd = open()?;
        let data = build(1);
        send(&fd, &data)?;
        let mut buf = vec![0u8; RECV_BUFFER];
        let len = recv(&fd, &mut buf, RecvFlags::empty()).map_err(|e| io_error("recv", e))?;
        let mut out = Vec::new();
        for message in Messages(buf.get(..len).unwrap_or(&[])) {
            match message.kind {
                NLMSG_ERROR => {
                    if let Some((code, _)) = message.error()
                        && code != 0
                    {
                        return Err(kernel_error(code));
                    }
                }
                NLMSG_DONE => break,
                _ => out.extend_from_slice(message.raw),
            }
        }
        Ok(out)
    }

    fn generation(socket: &mut Socket) -> Result<u32, Error> {
        let mut w = Writer::new(socket.seq);
        w.get_gen();
        let data = w.into_bytes();
        let mut generation = None;
        // GETGEN answers with one NEWGEN message, without an acknowledgement.
        let seq = socket.seq;
        socket.seq = socket.seq.wrapping_add(1);
        send(&socket.fd, &data)?;
        let mut buf = vec![0u8; 4096];
        while generation.is_none() {
            let len =
                recv(&socket.fd, &mut buf, RecvFlags::empty()).map_err(|e| io_error("recv", e))?;
            for message in Messages(buf.get(..len).unwrap_or(&[])) {
                if message.seq != seq {
                    continue;
                }
                if message.kind == NLMSG_ERROR {
                    let code = message.error().map_or(-1, |(c, _)| c);
                    return Err(kernel_error(code));
                }
                generation = wire::parse_gen(&message);
            }
        }
        generation.ok_or_else(|| Error::Netlink("no generation".to_owned()))
    }

    /// Whether anything committed to `nf_tables` since this process last knew what its table holds. Doesn't change
    /// what is known.
    #[must_use]
    pub fn changed(&self) -> bool {
        let now = self.with(Self::generation).ok();
        now.is_none() || now != self.known()
    }

    /// Whether nothing committed to `nf_tables` since the last call or this process' own last commit. When
    /// something did, the caller reads its table back, and what it reads is known from now on: anything committed
    /// while it reads moves the generation again.
    #[must_use]
    pub fn unchanged(&self) -> bool {
        let now = self.with(Self::generation).ok();
        let same = now.is_some() && now == self.known();
        self.set_known(now);
        same
    }
}
