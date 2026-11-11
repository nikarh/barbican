//! The edge protocol's frames: how they are laid out, written and read.
//!
//! Every frame is `len: u32 LE`, then `len` bytes: the frame's type (`u8`) and its payload. `len` is at most
//! [`MAX_FRAME`]. Integers are little-endian and of fixed width; times are unix seconds (`0`: none, or never).
//!
//! ```text
//! string  = n: u16, n bytes of UTF-8
//! net     = family: u8 (4 or 6), prefix length: u8, address: 16 bytes      18 bytes
//!           (IPv4 in the first 4 bytes, the rest zero; host bits zero; no IPv4-mapped IPv6 addresses)
//! block   = net, until: u64 (0: never)                                       26 bytes
//!
//! HELLO    0x01  edge → agent   protocol: u16, flags: u8 (1 enforcing, 2 wants lists, 4 wants IPv6), seq: u64, epoch: string,
//!                               list version: string, token: string, edge version: string, backend: string
//! WELCOME  0x02  agent → edge   protocol: u16, client name: string, agent version: string
//! REFUSE   0x03  agent → edge   reason: string; the agent closes the connection after it
//! PING     0x04  both ways      nothing
//! CHANGES  0x10  agent → edge   flags: u8 (1 full, 2 more follow), seq: u64, now: u64, epoch: string,
//!                               counts: 4 × u32, blocks, unblocks (nets), allows (nets), unallows (nets)
//! LIST     0x11  agent → edge   flags: u8 (1 last), total: u32, offset: u32, version: string, n: u32, nets
//! STATUS   0x20  edge → agent   at, uptime, rss, applied: u64, blocks, listed: u64, dropped: 4 × u64
//!                               (blocked packets and bytes, listed packets and bytes), flags: u8 (1 enforcing),
//!                               version, backend, error: string, n: u16, n × upstream, then extensions
//! upstream = flags: u8 (1 connected, 2 this connection), last contact: u64, name: string, error: string
//! extension = tag: u16, n: u32, n bytes                     (unknown tags are skipped: room to grow)
//! ```
//!
//! A frame holds at most [`MAX_RECORDS`] nets or blocks: larger changes and lists come in several frames, the
//! changes with `more` set on all but the last, the list with increasing offsets and `last` on the final one. The
//! receiver applies them once all arrived.
//!
//! Reading never allocates: a decoded [`Frame`] borrows the buffer, and its records are iterated in place. Every
//! length, count, tag and prefix is checked while decoding, so iterating a decoded frame can't fail.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use super::{Changes, EdgeBlock, PROTOCOL_VERSION};
use crate::net::Net;
use crate::nft::{Counter, Counters};

/// The largest frame (its type and payload), in bytes.
pub const MAX_FRAME: usize = 4 << 20;
/// The most nets or blocks in one frame.
pub const MAX_RECORDS: usize = 65_536;
pub const NET_LEN: usize = 18;
pub const BLOCK_LEN: usize = NET_LEN + 8;
/// Each side sends a ping when it sent nothing else for this long.
pub const HEARTBEAT: Duration = Duration::from_secs(20);
/// Each side drops the connection when it heard nothing for this long.
pub const SILENCE: Duration = Duration::from_secs(60);

/// Frame types.
pub mod kind {
    pub const HELLO: u8 = 0x01;
    pub const WELCOME: u8 = 0x02;
    pub const REFUSE: u8 = 0x03;
    pub const PING: u8 = 0x04;
    pub const CHANGES: u8 = 0x10;
    pub const LIST: u8 = 0x11;
    pub const STATUS: u8 = 0x20;
}

/// Tags of a status report's extensions.
pub mod ext {
    /// Reserved: drops by address, records of `net, hour: u64, count: u64`. Not sent yet.
    pub const ADDRESS_DROPS: u16 = 1;
}

const HELLO_ENFORCING: u8 = 1;
const HELLO_LISTS: u8 = 2;
const HELLO_IPV6: u8 = 4;
const CHANGES_FULL: u8 = 1;
const CHANGES_MORE: u8 = 2;
const LIST_LAST: u8 = 1;
const STATUS_ENFORCING: u8 = 1;
const UPSTREAM_CONNECTED: u8 = 1;
const UPSTREAM_THIS: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("the frame ends early")]
    Truncated,
    #[error("a frame of {0} bytes (at most {MAX_FRAME})")]
    TooLarge(usize),
    #[error("an empty frame")]
    Empty,
    #[error("an unknown frame type {0:#04x}")]
    UnknownType(u8),
    #[error("protocol {0} (this side speaks {PROTOCOL_VERSION})")]
    Protocol(u16),
    #[error("{0}")]
    Invalid(&'static str),
    #[error("{0} bytes past the frame's content")]
    Trailing(usize),
}

/// The length a frame's 4-byte header announces: how many bytes follow it.
pub fn frame_len(header: [u8; 4]) -> Result<usize, Error> {
    let len =
        usize::try_from(u32::from_le_bytes(header)).map_err(|_| Error::TooLarge(usize::MAX))?;
    match len {
        0 => Err(Error::Empty),
        n if n > MAX_FRAME => Err(Error::TooLarge(n)),
        n => Ok(n),
    }
}

/// The size of the first whole frame in `buf` (header included), or `None` while it is incomplete.
pub fn complete(buf: &[u8]) -> Result<Option<usize>, Error> {
    let Some(header) = buf.first_chunk::<4>() else {
        return Ok(None);
    };
    let len = frame_len(*header)? + 4;
    Ok((buf.len() >= len).then_some(len))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hello<'a> {
    /// The firewall is changed; otherwise the edge runs dry.
    pub enforcing: bool,
    /// It wants the agent's list (countries and blocklists).
    pub lists: bool,
    /// Its firewall loads IPv6: otherwise the agent sends no IPv6 at all (bans, allows, list).
    pub ipv6: bool,
    /// Where its copy of the agent's state is: `epoch` and `seq` of the last changes it applied.
    pub epoch: &'a str,
    pub seq: u64,
    /// The version of the list it has.
    pub list_version: &'a str,
    pub token: &'a str,
    pub version: &'a str,
    pub backend: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Welcome<'a> {
    /// What the agent calls this edge.
    pub client: &'a str,
    pub version: &'a str,
}

/// One frame of changes. See [`Changes`] for what they mean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChangesFrame<'a> {
    pub full: bool,
    /// More frames of the same changes follow.
    pub more: bool,
    pub seq: u64,
    pub now: u64,
    pub epoch: &'a str,
    pub blocks: Blocks<'a>,
    pub unblocks: Nets<'a>,
    pub allows: Nets<'a>,
    pub unallows: Nets<'a>,
}

/// One frame of the list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListFrame<'a> {
    pub last: bool,
    /// Prefixes in the whole list.
    pub total: u32,
    /// Where this frame's prefixes start in it.
    pub offset: u32,
    pub version: &'a str,
    pub nets: Nets<'a>,
}

/// The numbers of a status report.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Report {
    /// The edge's clock when it sent the report.
    pub at: u64,
    /// Seconds since the edge agent started.
    pub uptime: u64,
    /// Its resident memory, in bytes.
    pub rss: u64,
    /// When the firewall was last brought up to date (the edge's clock).
    pub applied: Option<u64>,
    /// Addresses and prefixes it blocks for bans and deny lists.
    pub blocks: u64,
    /// Prefixes of countries and blocklists.
    pub listed: u64,
    /// What its firewall dropped, since its rules were made.
    pub dropped: Counters,
    pub enforcing: bool,
}

/// An agent the edge follows, as it reports them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Upstream<'a> {
    pub name: &'a str,
    pub connected: bool,
    /// The upstream this report is sent to.
    pub this: bool,
    /// When the edge last heard from it (the edge's clock).
    pub last_contact: Option<u64>,
    pub error: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status<'a> {
    pub report: Report,
    pub version: &'a str,
    pub backend: &'a str,
    /// Empty: none.
    pub error: &'a str,
    pub upstreams: Upstreams<'a>,
    pub extensions: Extensions<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame<'a> {
    Hello(Hello<'a>),
    Welcome(Welcome<'a>),
    Refuse(&'a str),
    Ping,
    Changes(ChangesFrame<'a>),
    List(ListFrame<'a>),
    Status(Status<'a>),
}

/// Checked nets, iterated in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nets<'a>(&'a [u8]);

impl<'a> Nets<'a> {
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len() / NET_LEN
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = Net> + 'a {
        self.0
            .as_chunks::<NET_LEN>()
            .0
            .iter()
            .filter_map(|r| read_net(r).ok())
    }
}

/// Checked blocks, iterated in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Blocks<'a>(&'a [u8]);

impl<'a> Blocks<'a> {
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len() / BLOCK_LEN
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = EdgeBlock> + 'a {
        self.0
            .as_chunks::<BLOCK_LEN>()
            .0
            .iter()
            .filter_map(|r| read_block(r).ok())
    }
}

/// Checked upstream records, iterated in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Upstreams<'a> {
    count: u16,
    bytes: &'a [u8],
}

impl<'a> Upstreams<'a> {
    #[must_use]
    pub fn len(&self) -> usize {
        usize::from(self.count)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = Upstream<'a>> + 'a {
        let mut r = Reader(self.bytes);
        std::iter::from_fn(move || read_upstream(&mut r).ok())
    }
}

/// A status report's extensions: `(tag, content)`, checked, iterated in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extensions<'a>(&'a [u8]);

impl<'a> Extensions<'a> {
    pub fn iter(&self) -> impl Iterator<Item = (u16, &'a [u8])> + 'a {
        let mut r = Reader(self.0);
        std::iter::from_fn(move || read_extension(&mut r).ok())
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let (head, rest) = self.0.split_at_checked(n).ok_or(Error::Truncated)?;
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let (head, rest) = self.0.split_first_chunk::<N>().ok_or(Error::Truncated)?;
        self.0 = rest;
        Ok(*head)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(u8::from_le_bytes(self.array()?))
    }

    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn str(&mut self) -> Result<&'a str, Error> {
        let n = self.u16()?;
        std::str::from_utf8(self.take(usize::from(n))?)
            .map_err(|_| Error::Invalid("a string that isn't UTF-8"))
    }

    fn flags(&mut self, known: u8) -> Result<u8, Error> {
        let flags = self.u8()?;
        if flags & !known == 0 {
            Ok(flags)
        } else {
            Err(Error::Invalid("unknown flags"))
        }
    }

    /// `count` records of `N` bytes, each checked by `check`.
    fn records<const N: usize, T>(
        &mut self,
        count: u32,
        check: fn(&[u8; N]) -> Result<T, Error>,
    ) -> Result<&'a [u8], Error> {
        let bytes = usize::try_from(count)
            .ok()
            .and_then(|c| c.checked_mul(N))
            .ok_or(Error::Truncated)?;
        let records = self.take(bytes)?;
        for record in records.as_chunks::<N>().0 {
            check(record)?;
        }
        Ok(records)
    }

    fn finish(self) -> Result<(), Error> {
        match self.0.len() {
            0 => Ok(()),
            n => Err(Error::Trailing(n)),
        }
    }
}

fn time(t: u64) -> Option<u64> {
    (t != 0).then_some(t)
}

fn read_net(r: &[u8; NET_LEN]) -> Result<Net, Error> {
    let ([family, len], address) = r.split_first_chunk::<2>().ok_or(Error::Truncated)?;
    let address: [u8; 16] = address.try_into().map_err(|_| Error::Truncated)?;
    let ip = match family {
        4 => {
            let (v4, rest) = address.split_first_chunk::<4>().ok_or(Error::Truncated)?;
            if rest.iter().any(|b| *b != 0) {
                return Err(Error::Invalid("an IPv4 address with more than 4 bytes"));
            }
            if *len > 32 {
                return Err(Error::Invalid("an IPv4 prefix longer than 32"));
            }
            let bits = u32::from_be_bytes(*v4);
            if bits.checked_shl(u32::from(*len)).unwrap_or(0) != 0 {
                return Err(Error::Invalid("a prefix with host bits set"));
            }
            IpAddr::V4(Ipv4Addr::from(bits))
        }
        6 => {
            if *len > 128 {
                return Err(Error::Invalid("an IPv6 prefix longer than 128"));
            }
            let bits = u128::from_be_bytes(address);
            if bits.checked_shl(u32::from(*len)).unwrap_or(0) != 0 {
                return Err(Error::Invalid("a prefix with host bits set"));
            }
            let v6 = Ipv6Addr::from(bits);
            if v6.to_ipv4_mapped().is_some() {
                return Err(Error::Invalid("an IPv4-mapped IPv6 address"));
            }
            IpAddr::V6(v6)
        }
        _ => return Err(Error::Invalid("an address family other than 4 and 6")),
    };
    Ok(Net::prefix(ip, *len))
}

fn read_block(r: &[u8; BLOCK_LEN]) -> Result<EdgeBlock, Error> {
    let (net, until) = r.split_first_chunk::<NET_LEN>().ok_or(Error::Truncated)?;
    let until: [u8; 8] = until.try_into().map_err(|_| Error::Truncated)?;
    Ok(EdgeBlock {
        net: read_net(net)?,
        until: time(u64::from_le_bytes(until)),
    })
}

fn read_upstream<'a>(r: &mut Reader<'a>) -> Result<Upstream<'a>, Error> {
    let flags = r.flags(UPSTREAM_CONNECTED | UPSTREAM_THIS)?;
    let last_contact = time(r.u64()?);
    Ok(Upstream {
        connected: flags & UPSTREAM_CONNECTED != 0,
        this: flags & UPSTREAM_THIS != 0,
        last_contact,
        name: r.str()?,
        error: r.str()?,
    })
}

fn read_extension<'a>(r: &mut Reader<'a>) -> Result<(u16, &'a [u8]), Error> {
    let tag = r.u16()?;
    let n = usize::try_from(r.u32()?).map_err(|_| Error::Truncated)?;
    Ok((tag, r.take(n)?))
}

fn changes<'a>(r: &mut Reader<'a>) -> Result<Frame<'a>, Error> {
    let flags = r.flags(CHANGES_FULL | CHANGES_MORE)?;
    let seq = r.u64()?;
    let now = r.u64()?;
    let epoch = r.str()?;
    let counts = [r.u32()?, r.u32()?, r.u32()?, r.u32()?];
    let total: u64 = counts.iter().map(|c| u64::from(*c)).sum();
    if total > MAX_RECORDS as u64 {
        return Err(Error::Invalid("too many records in one frame"));
    }
    let [nb, nu, na, nn] = counts;
    Ok(Frame::Changes(ChangesFrame {
        full: flags & CHANGES_FULL != 0,
        more: flags & CHANGES_MORE != 0,
        seq,
        now,
        epoch,
        blocks: Blocks(r.records(nb, read_block)?),
        unblocks: Nets(r.records(nu, read_net)?),
        allows: Nets(r.records(na, read_net)?),
        unallows: Nets(r.records(nn, read_net)?),
    }))
}

fn list<'a>(r: &mut Reader<'a>) -> Result<Frame<'a>, Error> {
    let flags = r.flags(LIST_LAST)?;
    let total = r.u32()?;
    let offset = r.u32()?;
    let version = r.str()?;
    let n = r.u32()?;
    if n as usize > MAX_RECORDS {
        return Err(Error::Invalid("too many records in one frame"));
    }
    if u64::from(offset) + u64::from(n) > u64::from(total) {
        return Err(Error::Invalid("list prefixes past the list's total"));
    }
    Ok(Frame::List(ListFrame {
        last: flags & LIST_LAST != 0,
        total,
        offset,
        version,
        nets: Nets(r.records(n, read_net)?),
    }))
}

fn status<'a>(r: &mut Reader<'a>) -> Result<Frame<'a>, Error> {
    let at = r.u64()?;
    let uptime = r.u64()?;
    let rss = r.u64()?;
    let applied = time(r.u64()?);
    let blocks = r.u64()?;
    let listed = r.u64()?;
    let mut counter = || -> Result<Counter, Error> {
        Ok(Counter {
            packets: r.u64()?,
            bytes: r.u64()?,
        })
    };
    let dropped = Counters {
        blocked: counter()?,
        listed: counter()?,
    };
    let flags = r.flags(STATUS_ENFORCING)?;
    let version = r.str()?;
    let backend = r.str()?;
    let error = r.str()?;
    let count = r.u16()?;
    let start = r.0;
    for _ in 0..count {
        read_upstream(r)?;
    }
    let upstreams = Upstreams {
        count,
        bytes: start.get(..start.len() - r.0.len()).unwrap_or_default(),
    };
    let extensions = Extensions(r.0);
    while !r.0.is_empty() {
        read_extension(r)?;
    }
    Ok(Frame::Status(Status {
        report: Report {
            at,
            uptime,
            rss,
            applied,
            blocks,
            listed,
            dropped,
            enforcing: flags & STATUS_ENFORCING != 0,
        },
        version,
        backend,
        error,
        upstreams,
        extensions,
    }))
}

/// Reads a frame: its type and payload, without the length header.
pub fn decode(frame: &[u8]) -> Result<Frame<'_>, Error> {
    let (&kind, payload) = frame.split_first().ok_or(Error::Empty)?;
    if frame.len() > MAX_FRAME {
        return Err(Error::TooLarge(frame.len()));
    }
    let mut r = Reader(payload);
    let decoded = match kind {
        kind::HELLO => {
            let protocol = r.u16()?;
            if u32::from(protocol) != PROTOCOL_VERSION {
                return Err(Error::Protocol(protocol));
            }
            let flags = r.flags(HELLO_ENFORCING | HELLO_LISTS | HELLO_IPV6)?;
            let seq = r.u64()?;
            Frame::Hello(Hello {
                enforcing: flags & HELLO_ENFORCING != 0,
                lists: flags & HELLO_LISTS != 0,
                ipv6: flags & HELLO_IPV6 != 0,
                seq,
                epoch: r.str()?,
                list_version: r.str()?,
                token: r.str()?,
                version: r.str()?,
                backend: r.str()?,
            })
        }
        kind::WELCOME => {
            let protocol = r.u16()?;
            if u32::from(protocol) != PROTOCOL_VERSION {
                return Err(Error::Protocol(protocol));
            }
            Frame::Welcome(Welcome {
                client: r.str()?,
                version: r.str()?,
            })
        }
        kind::REFUSE => Frame::Refuse(r.str()?),
        kind::PING => Frame::Ping,
        kind::CHANGES => changes(&mut r)?,
        kind::LIST => list(&mut r)?,
        kind::STATUS => status(&mut r)?,
        other => return Err(Error::UnknownType(other)),
    };
    r.finish()?;
    Ok(decoded)
}

/// Writes frames into a buffer (several may follow each other in it).
fn begin(out: &mut Vec<u8>, kind: u8) -> usize {
    let start = out.len();
    out.extend_from_slice(&[0; 4]);
    out.push(kind);
    start
}

fn end(out: &mut [u8], start: usize) {
    let len = u32::try_from(out.len() - start - 4).unwrap_or(u32::MAX);
    if let Some(header) = out.get_mut(start..start + 4) {
        header.copy_from_slice(&len.to_le_bytes());
    }
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    // Longer strings (only ever error messages) are cut, at a character's start.
    let mut n = s.len().min(usize::from(u16::MAX));
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    let bytes = s.as_bytes().get(..n).unwrap_or_default();
    out.extend_from_slice(&u16::try_from(n).unwrap_or(u16::MAX).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn put_u32(out: &mut Vec<u8>, n: usize) {
    out.extend_from_slice(&u32::try_from(n).unwrap_or(u32::MAX).to_le_bytes());
}

fn put_net(out: &mut Vec<u8>, net: Net) {
    let mut address = [0u8; 16];
    let family = match net.addr() {
        IpAddr::V4(v4) => {
            if let Some(head) = address.first_chunk_mut::<4>() {
                *head = v4.octets();
            }
            4
        }
        IpAddr::V6(v6) => {
            address = v6.octets();
            6
        }
    };
    out.push(family);
    out.push(net.prefix_len());
    out.extend_from_slice(&address);
}

impl Hello<'_> {
    pub fn encode(&self, out: &mut Vec<u8>) {
        let start = begin(out, kind::HELLO);
        out.extend_from_slice(
            &u16::try_from(PROTOCOL_VERSION)
                .unwrap_or(u16::MAX)
                .to_le_bytes(),
        );
        let mut flags = 0;
        if self.enforcing {
            flags |= HELLO_ENFORCING;
        }
        if self.lists {
            flags |= HELLO_LISTS;
        }
        if self.ipv6 {
            flags |= HELLO_IPV6;
        }
        out.push(flags);
        out.extend_from_slice(&self.seq.to_le_bytes());
        for s in [
            self.epoch,
            self.list_version,
            self.token,
            self.version,
            self.backend,
        ] {
            put_str(out, s);
        }
        end(out, start);
    }
}

impl Welcome<'_> {
    pub fn encode(&self, out: &mut Vec<u8>) {
        let start = begin(out, kind::WELCOME);
        out.extend_from_slice(
            &u16::try_from(PROTOCOL_VERSION)
                .unwrap_or(u16::MAX)
                .to_le_bytes(),
        );
        put_str(out, self.client);
        put_str(out, self.version);
        end(out, start);
    }
}

pub fn encode_refuse(out: &mut Vec<u8>, reason: &str) {
    let start = begin(out, kind::REFUSE);
    put_str(out, reason);
    end(out, start);
}

pub fn encode_ping(out: &mut Vec<u8>) {
    let start = begin(out, kind::PING);
    end(out, start);
}

/// Takes up to `room` items off the front of `items`.
fn part<'a, T>(items: &mut &'a [T], room: &mut usize) -> &'a [T] {
    let (head, rest) = items.split_at((*room).min(items.len()));
    *room -= head.len();
    *items = rest;
    head
}

/// Writes changes as one frame, or several of at most [`MAX_RECORDS`] records.
pub fn encode_changes(out: &mut Vec<u8>, changes: &Changes) {
    let (mut blocks, mut unblocks, mut allows, mut unallows) = (
        changes.block.as_slice(),
        changes.unblock.as_slice(),
        changes.allow.as_slice(),
        changes.unallow.as_slice(),
    );
    loop {
        let mut room = MAX_RECORDS;
        let b = part(&mut blocks, &mut room);
        let u = part(&mut unblocks, &mut room);
        let a = part(&mut allows, &mut room);
        let n = part(&mut unallows, &mut room);
        let more =
            !(blocks.is_empty() && unblocks.is_empty() && allows.is_empty() && unallows.is_empty());
        let start = begin(out, kind::CHANGES);
        let mut flags = 0;
        if changes.full {
            flags |= CHANGES_FULL;
        }
        if more {
            flags |= CHANGES_MORE;
        }
        out.push(flags);
        out.extend_from_slice(&changes.seq.to_le_bytes());
        out.extend_from_slice(&changes.now.to_le_bytes());
        put_str(out, &changes.epoch);
        for count in [b.len(), u.len(), a.len(), n.len()] {
            put_u32(out, count);
        }
        out.reserve(b.len() * BLOCK_LEN + (u.len() + a.len() + n.len()) * NET_LEN);
        for block in b {
            put_net(out, block.net);
            out.extend_from_slice(&block.until.unwrap_or(0).to_le_bytes());
        }
        for net in u.iter().chain(a).chain(n) {
            put_net(out, *net);
        }
        end(out, start);
        if !more {
            return;
        }
    }
}

/// Writes a list as one frame, or several of at most [`MAX_RECORDS`] prefixes.
pub fn encode_list(out: &mut Vec<u8>, version: &str, nets: &[Net]) {
    out.reserve(nets.len() * NET_LEN + (nets.len() / MAX_RECORDS + 1) * (32 + version.len()));
    let mut chunks = nets.chunks(MAX_RECORDS).peekable();
    let mut offset = 0;
    loop {
        let chunk = chunks.next().unwrap_or_default();
        let last = chunks.peek().is_none();
        let start = begin(out, kind::LIST);
        out.push(if last { LIST_LAST } else { 0 });
        put_u32(out, nets.len());
        put_u32(out, offset);
        put_str(out, version);
        put_u32(out, chunk.len());
        for net in chunk {
            put_net(out, *net);
        }
        end(out, start);
        offset += chunk.len();
        if last {
            return;
        }
    }
}

/// Writes a status report.
pub fn encode_status<'a>(
    out: &mut Vec<u8>,
    report: &Report,
    version: &str,
    backend: &str,
    error: &str,
    upstreams: impl IntoIterator<Item = Upstream<'a>>,
) {
    let start = begin(out, kind::STATUS);
    for n in [
        report.at,
        report.uptime,
        report.rss,
        report.applied.unwrap_or(0),
        report.blocks,
        report.listed,
        report.dropped.blocked.packets,
        report.dropped.blocked.bytes,
        report.dropped.listed.packets,
        report.dropped.listed.bytes,
    ] {
        out.extend_from_slice(&n.to_le_bytes());
    }
    out.push(if report.enforcing {
        STATUS_ENFORCING
    } else {
        0
    });
    put_str(out, version);
    put_str(out, backend);
    put_str(out, error);
    let count_at = out.len();
    out.extend_from_slice(&[0, 0]);
    let mut count: u16 = 0;
    for u in upstreams.into_iter().take(usize::from(u16::MAX)) {
        let mut flags = 0;
        if u.connected {
            flags |= UPSTREAM_CONNECTED;
        }
        if u.this {
            flags |= UPSTREAM_THIS;
        }
        out.push(flags);
        out.extend_from_slice(&u.last_contact.unwrap_or(0).to_le_bytes());
        put_str(out, u.name);
        put_str(out, u.error);
        count += 1;
    }
    if let Some(slot) = out.get_mut(count_at..count_at + 2) {
        slot.copy_from_slice(&count.to_le_bytes());
    }
    end(out, start);
}

/// Puts the frames of a list together: its version and prefixes, once the frames are whole and in order.
pub fn assemble_list<'a>(
    frames: impl IntoIterator<Item = ListFrame<'a>>,
) -> Result<(String, Vec<Net>), Error> {
    let mut frames = frames.into_iter().peekable();
    let first = *frames.peek().ok_or(Error::Invalid("no list frames"))?;
    let mut nets = Vec::with_capacity(first.total as usize);
    let mut last = false;
    for f in frames {
        if last
            || f.version != first.version
            || f.total != first.total
            || f.offset as usize != nets.len()
        {
            return Err(Error::Invalid("list frames out of order"));
        }
        nets.extend(f.nets.iter());
        last = f.last;
    }
    if !last || nets.len() != first.total as usize {
        return Err(Error::Invalid("an incomplete list"));
    }
    Ok((first.version.to_owned(), nets))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge::{Journal, ListRef, Mirror};
    use crate::nft::Block;

    fn net(s: &str) -> Net {
        s.parse().unwrap()
    }

    /// The frames in a buffer, decoded.
    fn frames(buf: &[u8]) -> Vec<Frame<'_>> {
        let mut out = Vec::new();
        let mut rest = buf;
        while let Some(n) = complete(rest).unwrap() {
            out.push(decode(&rest[4..n]).unwrap());
            rest = &rest[n..];
        }
        assert_eq!(rest, &[] as &[u8]);
        out
    }

    fn one(buf: &[u8]) -> Frame<'_> {
        let mut all = frames(buf);
        assert_eq!(all.len(), 1);
        all.remove(0)
    }

    #[test]
    fn hello_round_trip() {
        let hello = Hello {
            enforcing: true,
            lists: false,
            ipv6: true,
            epoch: "e1",
            seq: 42,
            list_version: "v",
            token: "secret-token-0123456789",
            version: "1.2.3",
            backend: "nftables table inet barbican",
        };
        let mut buf = Vec::new();
        hello.encode(&mut buf);
        assert_eq!(one(&buf), Frame::Hello(hello));
        // Another protocol is told apart before anything else is read.
        let mut other = buf.clone();
        other[5] = 99;
        assert_eq!(decode(&other[4..]), Err(Error::Protocol(99)));
    }

    #[test]
    fn small_frames_round_trip() {
        let mut buf = Vec::new();
        Welcome {
            client: "router",
            version: "0.1.0",
        }
        .encode(&mut buf);
        encode_refuse(&mut buf, "unknown token");
        encode_ping(&mut buf);
        assert_eq!(
            frames(&buf),
            vec![
                Frame::Welcome(Welcome {
                    client: "router",
                    version: "0.1.0"
                }),
                Frame::Refuse("unknown token"),
                Frame::Ping
            ]
        );
    }

    #[test]
    fn changes_round_trip_into_a_mirror() {
        let mut journal = Journal::new("e".to_owned(), 100);
        journal.set(
            &[
                Block {
                    net: net("192.0.2.1"),
                    until: Some(2_000),
                },
                Block {
                    net: net("2001:db8::/48"),
                    until: None,
                },
            ],
            &[net("10.0.0.0/8")],
            ListRef::default(),
        );
        let mut buf = Vec::new();
        encode_changes(&mut buf, &journal.since("", 0, 1_000));
        let Frame::Changes(c) = one(&buf) else {
            panic!("not changes")
        };
        assert!(c.full && !c.more);
        assert_eq!(c.blocks.len(), 2);
        assert_eq!(
            c.blocks.iter().collect::<Vec<_>>(),
            vec![
                EdgeBlock {
                    net: net("192.0.2.1"),
                    until: Some(2_000)
                },
                EdgeBlock {
                    net: net("2001:db8::/48"),
                    until: None
                }
            ]
        );
        let mut mirror = Mirror::default();
        mirror.apply(&[c], 1_010).unwrap();
        assert_eq!(mirror.blocks[&net("192.0.2.1")], Some(2_010));
        assert!(mirror.allows.contains(&net("10.0.0.0/8")));
    }

    #[test]
    fn large_changes_and_lists_come_in_chunks() {
        let blocks: Vec<Block> = (0..100_000u32)
            .map(|i| Block {
                net: Net::host(IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i))),
                until: Some(u64::from(i) + 10),
            })
            .collect();
        let mut journal = Journal::new("e".to_owned(), 10);
        journal.set(&blocks, &[], ListRef::default());
        let mut buf = Vec::new();
        encode_changes(&mut buf, &journal.since("", 0, 0));
        let changes: Vec<ChangesFrame> = frames(&buf)
            .into_iter()
            .map(|f| match f {
                Frame::Changes(c) => c,
                _ => panic!("not changes"),
            })
            .collect();
        assert_eq!(changes.len(), 2);
        assert!(changes[0].more && !changes[1].more);
        let mut mirror = Mirror::default();
        mirror.apply(&changes, 0).unwrap();
        assert_eq!(mirror.blocks.len(), 100_000);

        let nets: Vec<Net> = blocks.iter().map(|b| b.net).collect();
        let mut buf = Vec::new();
        encode_list(&mut buf, "v9", &nets);
        let lists: Vec<ListFrame> = frames(&buf)
            .into_iter()
            .map(|f| match f {
                Frame::List(l) => l,
                _ => panic!("not a list"),
            })
            .collect();
        assert_eq!(lists.len(), 2);
        assert_eq!(
            assemble_list(lists.clone()).unwrap(),
            ("v9".to_owned(), nets)
        );
        // A missing or repeated chunk is refused.
        assert!(assemble_list(lists[1..].iter().copied()).is_err());
        assert!(assemble_list(lists[..1].iter().copied()).is_err());
        assert!(assemble_list([lists[0], lists[0], lists[1]]).is_err());

        let mut buf = Vec::new();
        encode_list(&mut buf, "empty", &[]);
        let Frame::List(l) = one(&buf) else {
            panic!("not a list")
        };
        assert_eq!(assemble_list([l]).unwrap(), ("empty".to_owned(), vec![]));
    }

    #[test]
    fn status_round_trip() {
        let report = Report {
            at: 1_000,
            uptime: 60,
            rss: 3 << 20,
            applied: Some(990),
            blocks: 12,
            listed: 30_000,
            dropped: Counters {
                blocked: Counter {
                    packets: 5,
                    bytes: 300,
                },
                listed: Counter {
                    packets: 7,
                    bytes: 420,
                },
            },
            enforcing: true,
        };
        let ups = [
            Upstream {
                name: "a",
                connected: true,
                this: true,
                last_contact: Some(999),
                error: "",
            },
            Upstream {
                name: "b",
                connected: false,
                this: false,
                last_contact: None,
                error: "connection refused",
            },
        ];
        let mut buf = Vec::new();
        encode_status(&mut buf, &report, "1.0", "ipset", "", ups);
        let Frame::Status(s) = one(&buf) else {
            panic!("not a status")
        };
        assert_eq!(s.report, report);
        assert_eq!((s.version, s.backend, s.error), ("1.0", "ipset", ""));
        assert_eq!(s.upstreams.iter().collect::<Vec<_>>(), ups);
        assert_eq!(s.extensions.iter().count(), 0);

        // Extensions a later edge adds are skipped by this agent.
        let mut extended = buf.clone();
        extended.extend_from_slice(&ext::ADDRESS_DROPS.to_le_bytes());
        extended.extend_from_slice(&3u32.to_le_bytes());
        extended.extend_from_slice(&[1, 2, 3]);
        let len = u32::try_from(extended.len() - 4).unwrap();
        extended[..4].copy_from_slice(&len.to_le_bytes());
        let Frame::Status(s) = one(&extended) else {
            panic!("not a status")
        };
        assert_eq!(s.report, report);
        assert_eq!(
            s.extensions.iter().collect::<Vec<_>>(),
            vec![(ext::ADDRESS_DROPS, &[1u8, 2, 3][..])]
        );
        // But not a broken one.
        extended.truncate(extended.len() - 1);
        assert_eq!(decode(&extended[4..]), Err(Error::Truncated));
    }

    #[test]
    fn refuses_broken_frames() {
        assert_eq!(frame_len([0, 0, 0, 0]), Err(Error::Empty));
        assert!(matches!(frame_len([0, 0, 0, 1]), Err(Error::TooLarge(_))));
        assert_eq!(complete(&[5, 0, 0, 0, 1]), Ok(None));
        assert_eq!(decode(&[]), Err(Error::Empty));
        assert_eq!(decode(&[0x77]), Err(Error::UnknownType(0x77)));
        assert_eq!(decode(&[kind::PING, 0]), Err(Error::Trailing(1)));

        let mut journal = Journal::new("e".to_owned(), 10);
        journal.set(
            &[Block {
                net: net("192.0.2.0/24"),
                until: None,
            }],
            &[],
            ListRef::default(),
        );
        let mut buf = Vec::new();
        encode_changes(&mut buf, &journal.since("", 0, 0));
        let body = &buf[4..];
        // Every truncation is an error, never a panic.
        for n in 0..body.len() {
            assert!(decode(&body[..n]).is_err(), "{n} bytes");
        }
        let record = body.len() - BLOCK_LEN;
        let corrupt = |at: usize, value: u8| {
            let mut b = body.to_vec();
            b[at] = value;
            decode(&b).map(|_| ())
        };
        assert!(
            matches!(corrupt(record, 5), Err(Error::Invalid(_))),
            "family"
        );
        assert!(
            matches!(corrupt(record + 1, 33), Err(Error::Invalid(_))),
            "v4 length"
        );
        assert!(
            matches!(corrupt(record + 5, 1), Err(Error::Invalid(_))),
            "host bits"
        );
        assert!(
            matches!(corrupt(record + 7, 1), Err(Error::Invalid(_))),
            "v4 tail"
        );
        assert!(matches!(corrupt(1, 0x80), Err(Error::Invalid(_))), "flags");
        // A count larger than what follows.
        let counts = 1 + 1 + 8 + 8 + 2 + 1;
        assert_eq!(corrupt(counts, 2), Err(Error::Truncated));

        // An IPv4-mapped IPv6 address and a v6 prefix too long.
        let mut rec = [0u8; NET_LEN];
        rec[0] = 6;
        rec[1] = 128;
        rec[12] = 0xff;
        rec[13] = 0xff;
        rec[14] = 1;
        assert!(read_net(&rec).is_err());
        rec[1] = 129;
        assert!(read_net(&rec).is_err());

        // Garbage of every length never panics.
        let mut seed = 0x1234_5678_u32;
        for len in 0..512 {
            let bytes: Vec<u8> = (0..len)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 17;
                    seed ^= seed << 5;
                    seed.to_le_bytes()[0]
                })
                .collect();
            for kind in [
                kind::HELLO,
                kind::CHANGES,
                kind::LIST,
                kind::STATUS,
                kind::WELCOME,
            ] {
                let mut frame = vec![kind];
                frame.extend_from_slice(&bytes);
                let _ = decode(&frame);
            }
        }
    }

    /// A full snapshot of 25 000 bans and a list of 100 000 prefixes, as an edge gets them: decoded and applied.
    #[test]
    fn snapshot_decodes_fast() {
        let blocks: Vec<Block> = (0..25_000u32)
            .map(|i| Block {
                net: Net::host(IpAddr::V4(Ipv4Addr::from(0xc000_0000 + i))),
                until: Some(u64::from(i) + 10_000),
            })
            .collect();
        let list: Vec<Net> = (0..100_000u32)
            .map(|i| {
                if i % 4 == 0 {
                    Net::prefix(
                        IpAddr::V6(Ipv6Addr::from(u128::from(0x2001_0db8_u32 + i) << 96)),
                        32,
                    )
                } else {
                    Net::prefix(IpAddr::V4(Ipv4Addr::from(i << 8)), 24)
                }
            })
            .collect();
        let mut journal = Journal::new("e".to_owned(), 10);
        journal.set(&blocks, &[], ListRef::default());
        let mut buf = Vec::new();
        encode_changes(&mut buf, &journal.since("", 0, 0));
        encode_list(&mut buf, "v", &list);

        let started = std::time::Instant::now();
        let mut changes = Vec::new();
        let mut lists = Vec::new();
        let mut rest = buf.as_slice();
        while let Some(n) = complete(rest).unwrap() {
            match decode(&rest[4..n]).unwrap() {
                Frame::Changes(c) => changes.push(c),
                Frame::List(l) => lists.push(l),
                _ => panic!("unexpected frame"),
            }
            rest = &rest[n..];
        }
        let decoded = started.elapsed();
        let mut mirror = Mirror::default();
        mirror.apply(&changes, 0).unwrap();
        let (_, nets) = assemble_list(lists).unwrap();
        let total = started.elapsed();
        assert_eq!(mirror.blocks.len(), 25_000);
        assert_eq!(nets.len(), 100_000);
        let _ = std::io::Write::write_fmt(
            &mut std::io::stderr(),
            format_args!(
                "snapshot of {} bytes: decoded and checked in {decoded:?}, applied in {total:?} in all\n",
                buf.len()
            ),
        );
    }
}
