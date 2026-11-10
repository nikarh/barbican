//! Talking to `nf_tables` over a netlink socket, and watching its notifications.

use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustix::io::Errno;
use rustix::net::netlink::SocketAddrNetlink;
use rustix::net::{AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType, netlink, sockopt};

use super::Error;
use super::wire::{self, Messages, NLMSG_DONE, NLMSG_ERROR, NLMSG_OVERRUN, Writer};

/// The `NFNLGRP_NFTABLES` multicast group, as a bit of `nl_groups`.
const GROUP_NFTABLES: u32 = 1 << (7 - 1);
/// Replies to requests, and dumps: the kernel fills messages of up to 32 KiB, errors echo up to 64 KiB.
const RECV_BUFFER: usize = 128 * 1024;
/// How long a reply may take. Transactions are applied while they are sent, so this only guards against a lost
/// reply.
const TIMEOUT: Duration = Duration::from_secs(10);
/// A transaction larger than this is sent with the monitor unsubscribed (see [`Kernel::transact`]).
const QUIET_ABOVE: usize = 64 * 1024;
/// What the monitor's socket may hold before notifications are lost.
const MONITOR_BUFFER: usize = 4 * 1024 * 1024;

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

fn open() -> Result<(OwnedFd, u32), Error> {
    let fd = rustix::net::socket_with(
        AddressFamily::NETLINK,
        SocketType::RAW,
        SocketFlags::CLOEXEC,
        Some(netlink::NETFILTER),
    )
    .map_err(|e| io_error("netlink socket", e))?;
    rustix::net::bind(&fd, &SocketAddrNetlink::new(0, 0)).map_err(|e| io_error("bind", e))?;
    let port = rustix::net::getsockname(&fd)
        .ok()
        .and_then(|a| SocketAddrNetlink::try_from(a).ok())
        .map_or(0, |a| a.pid());
    sockopt::set_socket_timeout(&fd, sockopt::Timeout::Recv, Some(TIMEOUT))
        .map_err(|e| io_error("SO_RCVTIMEO", e))?;
    Ok((fd, port))
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

struct Socket {
    fd: OwnedFd,
    seq: u32,
    sndbuf: usize,
}

#[derive(Debug, Default)]
struct Shared {
    /// The netlink port of the socket transactions go through: notifications from it are ours.
    port: AtomicU32,
    /// Set when the table may have changed other than through us (or whether it did can't be known).
    drift: AtomicBool,
    /// Whether a [`Monitor`] watches the table.
    watching: AtomicBool,
    /// The monitor's socket and port, to unsubscribe during large transactions.
    monitor: Mutex<Option<(Arc<OwnedFd>, u32)>>,
}

/// `nf_tables` over netlink. Clones share the socket.
#[derive(Clone, Default)]
pub struct Kernel {
    socket: Arc<Mutex<Option<Socket>>>,
    shared: Arc<Shared>,
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
            let (fd, port) = open()?;
            self.shared.port.store(port, Ordering::SeqCst);
            *guard = Some(Socket {
                fd,
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
    /// One that changes many elements (`bulk`: flushing a set counts, whatever its size) is sent with the monitor
    /// unsubscribed. With a listener the kernel makes a notification of every element in the commit, holding them
    /// all until it ends: for a large set more memory than a small machine has, and a flood for the monitor.
    pub fn transact(&self, build: &dyn Fn(u32) -> Vec<u8>, bulk: bool) -> Result<(), Error> {
        self.with(|socket| {
            let data = build(socket.seq);
            socket.seq = next_seq(&data);
            let quiet = bulk || data.len() > QUIET_ABOVE;
            let monitor = if quiet {
                self.shared.monitor.lock().ok().and_then(|m| m.clone())
            } else {
                None
            };
            let Some((monitor, port)) = monitor else {
                return Self::exchange(socket, &data, false, &mut |_| {});
            };
            // Without the monitor listening the kernel doesn't make the notifications at all. What others commit
            // meanwhile is told by the generation: it moved by more than this transaction.
            let before = Self::generation(socket)?;
            let _ = rustix::net::bind(&*monitor, &SocketAddrNetlink::new(port, 0));
            let result = Self::exchange(socket, &data, false, &mut |_| {});
            let _ = rustix::net::bind(&*monitor, &SocketAddrNetlink::new(port, GROUP_NFTABLES));
            let after = Self::generation(socket)?;
            let expected = match before.wrapping_add(1) {
                0 => 1,
                g => g,
            };
            if result.is_err() || after != expected {
                self.shared.drift.store(true, Ordering::SeqCst);
            }
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
        let (fd, _) = open()?;
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

    /// Whether everything that changed the table since the last call was this process: a [`Monitor`] runs and
    /// saw nothing else. Resets what it saw.
    #[must_use]
    pub fn unchanged(&self) -> bool {
        let drift = self.shared.drift.swap(false, Ordering::SeqCst);
        self.shared.watching.load(Ordering::SeqCst) && !drift
    }

    /// Subscribes to `nf_tables`' notifications, to learn when another program changes `table`.
    pub fn monitor(&self, table: &str) -> Result<Monitor, Error> {
        let fd = rustix::net::socket_with(
            AddressFamily::NETLINK,
            SocketType::RAW,
            SocketFlags::CLOEXEC,
            Some(netlink::NETFILTER),
        )
        .map_err(|e| io_error("netlink socket", e))?;
        rustix::net::bind(&fd, &SocketAddrNetlink::new(0, GROUP_NFTABLES))
            .map_err(|e| io_error("bind", e))?;
        let port = rustix::net::getsockname(&fd)
            .ok()
            .and_then(|a| SocketAddrNetlink::try_from(a).ok())
            .map_or(0, |a| a.pid());
        if sockopt::set_socket_recv_buffer_size_force(&fd, MONITOR_BUFFER).is_err() {
            let _ = sockopt::set_socket_recv_buffer_size(&fd, MONITOR_BUFFER);
        }
        let fd = Arc::new(fd);
        if let Ok(mut m) = self.shared.monitor.lock() {
            *m = Some((Arc::clone(&fd), port));
        }
        // What happened before it subscribed is unknown.
        self.shared.drift.store(true, Ordering::SeqCst);
        self.shared.watching.store(true, Ordering::SeqCst);
        Ok(Monitor {
            fd,
            table: table.as_bytes().to_vec(),
            shared: Arc::clone(&self.shared),
            buf: vec![0u8; RECV_BUFFER],
            touched: false,
        })
    }
}

/// `nf_tables`' notifications, filtered for changes to one table by another program.
pub struct Monitor {
    fd: Arc<OwnedFd>,
    table: Vec<u8>,
    shared: Arc<Shared>,
    buf: Vec<u8>,
    /// Whether a notification of the transaction being read touched the table.
    touched: bool,
}

impl Monitor {
    /// Blocks until another program committed a change to the table (or notifications were lost, so that it
    /// can't be known). The next reconcile then reads the table back.
    pub fn wait(&mut self) -> Result<(), Error> {
        loop {
            let len = match rustix::net::recv(&*self.fd, &mut self.buf[..], RecvFlags::empty()) {
                Ok((len, _)) => len,
                Err(Errno::INTR | Errno::AGAIN) => continue,
                // The socket's buffer overflowed: notifications were lost.
                Err(Errno::NOBUFS) => {
                    self.touched = false;
                    self.shared.drift.store(true, Ordering::SeqCst);
                    return Ok(());
                }
                Err(e) => return Err(io_error("monitor", e)),
            };
            let ours = self.shared.port.load(Ordering::SeqCst);
            let mut changed = false;
            for message in Messages(self.buf.get(..len).unwrap_or(&[])) {
                if message.nft().is_none() || message.pid == ours && ours != 0 {
                    continue;
                }
                if message.nft() == Some(wire::NFT_MSG_NEWGEN) {
                    changed |= std::mem::take(&mut self.touched);
                } else if message.family() == Some(wire::NFPROTO_INET)
                    && wire::event_table(&message) == Some(self.table.as_slice())
                {
                    self.touched = true;
                }
            }
            if changed {
                self.shared.drift.store(true, Ordering::SeqCst);
                return Ok(());
            }
        }
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        self.shared.watching.store(false, Ordering::SeqCst);
        self.shared.drift.store(true, Ordering::SeqCst);
        if let Ok(mut m) = self.shared.monitor.lock() {
            *m = None;
        }
    }
}
