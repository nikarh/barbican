//! `nf_tables` messages as the kernel takes and gives them over netlink (`NETLINK_NETFILTER`), the way nft
//! (libnftnl) writes them: the element changes of a transaction, dumps of a set's elements and of a chain's rules,
//! and the ruleset's generation.
//!
//! Every value is in the layout `<linux/netlink.h>`, `<linux/netfilter/nfnetlink.h>` and
//! `<linux/netfilter/nf_tables.h>` define: a `nlmsghdr` (host byte order), a `nfgenmsg`, then attributes (`nlattr`,
//! host byte order, padded to 4 bytes) whose numbers are big-endian.

use std::net::IpAddr;

use crate::net::{Family, Net, Range};

pub const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NFNL_MSG_BATCH_BEGIN: u16 = 16;
const NFNL_MSG_BATCH_END: u16 = 17;

const NFT_MSG_NEWRULE: u8 = 6;
const NFT_MSG_GETRULE: u8 = 7;
const NFT_MSG_NEWSETELEM: u8 = 12;
const NFT_MSG_GETSETELEM: u8 = 13;
const NFT_MSG_DELSETELEM: u8 = 14;
pub const NFT_MSG_NEWGEN: u8 = 15;
const NFT_MSG_GETGEN: u8 = 16;
const NFT_MSG_DESTROYSETELEM: u8 = 30;

pub const NLM_F_REQUEST: u16 = 0x1;
pub const NLM_F_ACK: u16 = 0x4;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_CREATE: u16 = 0x400;

pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;
pub const NLMSG_OVERRUN: u16 = 4;
/// A dump saw the ruleset change while it ran: what it gave may be inconsistent.
pub const NLM_F_DUMP_INTR: u16 = 0x10;

pub const NFPROTO_INET: u8 = 1;
const AF_UNSPEC: u8 = 0;

const NLA_F_NESTED: u16 = 0x8000;
const NLA_TYPE_MASK: u16 = 0x3fff;

const NFTA_SET_ELEM_LIST_TABLE: u16 = 1;
const NFTA_SET_ELEM_LIST_SET: u16 = 2;
const NFTA_SET_ELEM_LIST_ELEMENTS: u16 = 3;
const NFTA_SET_ELEM_KEY: u16 = 1;
const NFTA_SET_ELEM_FLAGS: u16 = 3;
const NFTA_SET_ELEM_TIMEOUT: u16 = 4;
const NFTA_SET_ELEM_EXPIRATION: u16 = 5;
const NFTA_SET_ELEM_USERDATA: u16 = 6;
const NFTA_DATA_VALUE: u16 = 1;
const NFT_SET_ELEM_INTERVAL_END: u32 = 1;
/// libnftnl's element user data: a TLV of type `NFTNL_UDATA_SET_ELEM_FLAGS` holding
/// `NFTNL_SET_ELEM_F_INTERVAL_OPEN` (a host-order u32), which nft puts on an interval reaching the top of the
/// address space, since such an interval has no end element.
const UDATA_SET_ELEM_FLAGS: u8 = 1;
const SET_ELEM_F_INTERVAL_OPEN: u32 = 1;

const NFTA_GEN_ID: u16 = 1;

const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_EXPRESSIONS: u16 = 4;
const NFTA_RULE_USERDATA: u16 = 7;
const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;
const NFTA_COUNTER_BYTES: u16 = 1;
const NFTA_COUNTER_PACKETS: u16 = 2;
const UDATA_RULE_COMMENT: u8 = 0;

/// The length of a `nlmsghdr` and of a `nfgenmsg`.
pub const NLMSG_HDRLEN: usize = 16;
const NFGENMSG_LEN: usize = 4;

/// An address as a set key: its bytes in network order, 4 or 16 of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Key {
    len: u8,
    bytes: [u8; 16],
}

impl Key {
    #[must_use]
    pub fn of(ip: IpAddr) -> Self {
        let mut bytes = [0; 16];
        let len = match ip {
            IpAddr::V4(v4) => {
                bytes[..4].copy_from_slice(&v4.octets());
                4
            }
            IpAddr::V6(v6) => {
                bytes = v6.octets();
                16
            }
        };
        Self { len, bytes }
    }

    fn from_slice(data: &[u8]) -> Option<Self> {
        let mut bytes = [0; 16];
        bytes.get_mut(..data.len())?.copy_from_slice(data);
        matches!(data.len(), 4 | 16).then(|| Self {
            len: u8::try_from(data.len()).unwrap_or(0),
            bytes,
        })
    }

    /// A 32-bit value in host order, as nft keeps a `mark`.
    #[must_use]
    pub fn of_u32(value: u32) -> Self {
        let mut bytes = [0; 16];
        bytes[..4].copy_from_slice(&value.to_ne_bytes());
        Self { len: 4, bytes }
    }

    #[must_use]
    pub fn as_u32(&self) -> Option<u32> {
        Some(u32::from_ne_bytes(self.as_slice().try_into().ok()?))
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or(&[])
    }

    fn to_u128(self) -> u128 {
        let mut n = 0u128;
        for b in self.as_slice() {
            n = (n << 8) | u128::from(*b);
        }
        n
    }

    fn from_u128(len: u8, n: u128) -> Self {
        let mut bytes = [0; 16];
        let l = usize::from(len);
        for (i, b) in bytes.iter_mut().take(l).enumerate() {
            *b = u8::try_from((n >> (8 * (l - 1 - i))) & 0xff).unwrap_or(0);
        }
        Self { len, bytes }
    }

    #[must_use]
    pub fn ip(&self) -> IpAddr {
        match self.len {
            4 => IpAddr::from([self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3]]),
            _ => IpAddr::from(self.bytes),
        }
    }
}

/// One element as the kernel keeps it. An interval of a `flags interval` set is two of them: its first address,
/// and the address after its last one flagged as the end; or only the first, marked open, when it reaches the top
/// of the address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Elem {
    pub key: Key,
    pub end: bool,
    pub open: bool,
    /// The timeout to give it, in milliseconds (when adding).
    pub timeout_ms: Option<u64>,
    /// What is left of its timeout, in milliseconds (when read back).
    pub expires_ms: Option<u64>,
}

impl Elem {
    #[must_use]
    pub fn key(key: Key) -> Self {
        Self {
            key,
            end: false,
            open: false,
            timeout_ms: None,
            expires_ms: None,
        }
    }
}

/// The elements of `net` in an interval set, as nft makes them: see [`range`].
#[must_use]
pub fn interval(net: &Net, timeout_ms: Option<u64>) -> (Elem, Option<Elem>) {
    range(&Range::of(net), timeout_ms)
}

/// The elements of a range in an interval set, as nft makes them: the first address (with the timeout), and the
/// one after the last flagged as the end; or, when the range reaches the top of the address space (which has no
/// address after it), the first alone, flagged open.
#[must_use]
pub fn range(range: &Range, timeout_ms: Option<u64>) -> (Elem, Option<Elem>) {
    let family = range.family();
    let len = key_len(family);
    let (first, last) = range.bounds();
    let mut start = Elem::key(Key::from_u128(len, first));
    start.timeout_ms = timeout_ms;
    if last == family.top() {
        start.open = true;
        return (start, None);
    }
    let mut end = Elem::key(Key::from_u128(len, last + 1));
    end.end = true;
    (start, Some(end))
}

fn key_len(family: Family) -> u8 {
    match family {
        Family::V4 => 4,
        Family::V6 => 16,
    }
}

/// The range that the interval `[first, end)` is, `end` being `None` for the top of the address space. `None` for
/// an end that isn't after the first, or of another size.
#[must_use]
pub fn interval_range(first: Key, end: Option<Key>) -> Option<Range> {
    let family = match first.len {
        4 => Family::V4,
        _ => Family::V6,
    };
    let last = match end {
        None => family.top(),
        Some(e) if e.len == first.len => e.to_u128().checked_sub(1)?,
        Some(_) => return None,
    };
    Range::from_bounds(family, first.to_u128(), last)
}

/// Netlink messages being written into one buffer.
#[derive(Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
    seq: u32,
}

impl Writer {
    #[must_use]
    pub fn new(seq: u32) -> Self {
        Self {
            buf: Vec::new(),
            seq,
        }
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Starts a message; [`Self::end`] with what this returns completes it.
    fn begin(&mut self, kind: u16, flags: u16, family: u8, res_id: u16) -> usize {
        let start = self.buf.len();
        self.buf.extend_from_slice(&0u32.to_ne_bytes());
        self.buf.extend_from_slice(&kind.to_ne_bytes());
        self.buf
            .extend_from_slice(&(NLM_F_REQUEST | flags).to_ne_bytes());
        self.buf.extend_from_slice(&self.seq.to_ne_bytes());
        self.buf.extend_from_slice(&0u32.to_ne_bytes());
        self.buf.push(family);
        self.buf.push(0);
        self.buf.extend_from_slice(&res_id.to_be_bytes());
        self.seq = self.seq.wrapping_add(1);
        start
    }

    fn end(&mut self, start: usize) {
        let len = u32::try_from(self.buf.len() - start).unwrap_or(u32::MAX);
        if let Some(field) = self.buf.get_mut(start..start + 4) {
            field.copy_from_slice(&len.to_ne_bytes());
        }
    }

    fn attr(&mut self, kind: u16, data: &[u8]) {
        let len = u16::try_from(4 + data.len()).unwrap_or(u16::MAX);
        self.buf.extend_from_slice(&len.to_ne_bytes());
        self.buf.extend_from_slice(&kind.to_ne_bytes());
        self.buf.extend_from_slice(data);
        self.pad();
    }

    fn strz(&mut self, kind: u16, s: &str) {
        let mut data = Vec::with_capacity(s.len() + 1);
        data.extend_from_slice(s.as_bytes());
        data.push(0);
        self.attr(kind, &data);
    }

    fn pad(&mut self) {
        while !self.buf.len().is_multiple_of(4) {
            self.buf.push(0);
        }
    }

    fn nest(&mut self, kind: u16) -> usize {
        let start = self.buf.len();
        self.buf.extend_from_slice(&0u16.to_ne_bytes());
        self.buf
            .extend_from_slice(&(kind | NLA_F_NESTED).to_ne_bytes());
        start
    }

    fn nest_end(&mut self, start: usize) {
        let len = u16::try_from(self.buf.len() - start).unwrap_or(u16::MAX);
        if let Some(field) = self.buf.get_mut(start..start + 2) {
            field.copy_from_slice(&len.to_ne_bytes());
        }
    }

    fn elem(&mut self, index: u16, e: &Elem) {
        let nest = self.nest(index);
        if e.end {
            self.attr(
                NFTA_SET_ELEM_FLAGS,
                &NFT_SET_ELEM_INTERVAL_END.to_be_bytes(),
            );
        }
        if let Some(ms) = e.timeout_ms {
            self.attr(NFTA_SET_ELEM_TIMEOUT, &ms.to_be_bytes());
        }
        let key = self.nest(NFTA_SET_ELEM_KEY);
        self.attr(NFTA_DATA_VALUE, e.key.as_slice());
        self.nest_end(key);
        if e.open {
            let mut udata = vec![UDATA_SET_ELEM_FLAGS, 4];
            udata.extend_from_slice(&SET_ELEM_F_INTERVAL_OPEN.to_ne_bytes());
            self.attr(NFTA_SET_ELEM_USERDATA, &udata);
        }
        self.nest_end(nest);
    }

    /// The most an element takes: its nest, flags, timeout, key and user data.
    const ELEM_MAX: usize = 4 + 8 + 12 + 4 + 4 + 16 + 12;

    /// Messages adding (`NFT_MSG_NEWSETELEM`) or destroying (`NFT_MSG_DESTROYSETELEM`: no error when missing)
    /// elements, as many as it takes: an attribute holds at most 64 KiB, so each message has at most that many
    /// bytes of elements. The elements of one interval (a start and its end) stay in the same message.
    pub fn elements(&mut self, add: bool, table: &str, set: &str, groups: &[(Elem, Option<Elem>)]) {
        let (kind, flags) = if add {
            (NFT_MSG_NEWSETELEM, NLM_F_CREATE | NLM_F_ACK)
        } else {
            (NFT_MSG_DESTROYSETELEM, NLM_F_ACK)
        };
        let mut groups = groups.iter().peekable();
        while groups.peek().is_some() {
            let msg = self.begin(
                (NFNL_SUBSYS_NFTABLES << 8) | u16::from(kind),
                flags,
                NFPROTO_INET,
                0,
            );
            self.strz(NFTA_SET_ELEM_LIST_TABLE, table);
            self.strz(NFTA_SET_ELEM_LIST_SET, set);
            let list = self.nest(NFTA_SET_ELEM_LIST_ELEMENTS);
            let mut index: u16 = 0;
            while let Some((first, second)) = groups.peek() {
                if index > 0 && self.buf.len() - list + 2 * Self::ELEM_MAX > usize::from(u16::MAX) {
                    break;
                }
                for e in std::iter::once(first).chain(second) {
                    index = index.wrapping_add(1);
                    self.elem(index, e);
                }
                groups.next();
            }
            self.nest_end(list);
            self.end(msg);
        }
    }

    /// Removes every element of a set (`NFT_MSG_DELSETELEM` without elements, as `flush set`).
    pub fn flush(&mut self, table: &str, set: &str) {
        let msg = self.begin(
            (NFNL_SUBSYS_NFTABLES << 8) | u16::from(NFT_MSG_DELSETELEM),
            NLM_F_ACK,
            NFPROTO_INET,
            0,
        );
        self.strz(NFTA_SET_ELEM_LIST_SET, set);
        self.strz(NFTA_SET_ELEM_LIST_TABLE, table);
        self.end(msg);
    }

    fn batch_marker(&mut self, kind: u16) {
        let msg = self.begin(kind, 0, AF_UNSPEC, NFNL_SUBSYS_NFTABLES);
        self.end(msg);
    }

    /// Starts a transaction: what follows until [`Self::batch_end`] is applied as a whole or not at all.
    pub fn batch_begin(&mut self) {
        self.batch_marker(NFNL_MSG_BATCH_BEGIN);
    }

    pub fn batch_end(&mut self) {
        self.batch_marker(NFNL_MSG_BATCH_END);
    }

    /// Asks for a set's elements (`NFT_MSG_GETSETELEM`, a dump).
    pub fn get_elements(&mut self, table: &str, set: &str) {
        let msg = self.begin(
            (NFNL_SUBSYS_NFTABLES << 8) | u16::from(NFT_MSG_GETSETELEM),
            NLM_F_DUMP,
            NFPROTO_INET,
            0,
        );
        self.strz(NFTA_SET_ELEM_LIST_SET, set);
        self.strz(NFTA_SET_ELEM_LIST_TABLE, table);
        self.end(msg);
    }

    /// Asks for the rules of a chain (`NFT_MSG_GETRULE`, a dump).
    pub fn get_rules(&mut self, table: &str, chain: &str) {
        let msg = self.begin(
            (NFNL_SUBSYS_NFTABLES << 8) | u16::from(NFT_MSG_GETRULE),
            NLM_F_DUMP,
            NFPROTO_INET,
            0,
        );
        self.strz(NFTA_RULE_TABLE, table);
        self.strz(NFTA_RULE_CHAIN, chain);
        self.end(msg);
    }

    /// Asks for the ruleset's generation (`NFT_MSG_GETGEN`).
    pub fn get_gen(&mut self) {
        let msg = self.begin(
            (NFNL_SUBSYS_NFTABLES << 8) | u16::from(NFT_MSG_GETGEN),
            0,
            AF_UNSPEC,
            0,
        );
        self.end(msg);
    }
}

/// A received message.
#[derive(Debug, Clone, Copy)]
pub struct Message<'a> {
    pub kind: u16,
    pub flags: u16,
    pub seq: u32,
    /// After the `nlmsghdr`.
    pub payload: &'a [u8],
    /// The whole message.
    pub raw: &'a [u8],
}

impl<'a> Message<'a> {
    /// The `nf_tables` message type, when it is one.
    #[must_use]
    pub fn nft(&self) -> Option<u8> {
        (self.kind >> 8 == NFNL_SUBSYS_NFTABLES)
            .then(|| u8::try_from(self.kind & 0xff).unwrap_or(0))
    }

    /// The attributes after the `nfgenmsg`.
    #[must_use]
    pub fn attrs(&self) -> Attrs<'a> {
        Attrs(self.payload.get(NFGENMSG_LEN..).unwrap_or(&[]))
    }

    /// For `NLMSG_ERROR` (and `NLMSG_DONE`): the error (a negative errno, 0 for an acknowledgement) and the sequence number of the
    /// message it answers.
    #[must_use]
    pub fn error(&self) -> Option<(i32, u32)> {
        let code = i32::from_ne_bytes(self.payload.get(..4)?.try_into().ok()?);
        // An error echoes the header of the message it answers; `NLMSG_DONE` has only the code.
        let seq = self
            .payload
            .get(12..16)
            .and_then(|s| s.try_into().ok())
            .map_or(self.seq, u32::from_ne_bytes);
        Some((code, seq))
    }
}

/// The messages in a buffer.
#[derive(Debug, Clone)]
pub struct Messages<'a>(pub &'a [u8]);

impl<'a> Iterator for Messages<'a> {
    type Item = Message<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let header = self.0.get(..NLMSG_HDRLEN)?;
        let len = usize::try_from(u32::from_ne_bytes(header.get(..4)?.try_into().ok()?)).ok()?;
        if len < NLMSG_HDRLEN || len > self.0.len() {
            self.0 = &[];
            return None;
        }
        let message = Message {
            kind: u16::from_ne_bytes(header.get(4..6)?.try_into().ok()?),
            flags: u16::from_ne_bytes(header.get(6..8)?.try_into().ok()?),
            seq: u32::from_ne_bytes(header.get(8..12)?.try_into().ok()?),
            payload: self.0.get(NLMSG_HDRLEN..len)?,
            raw: self.0.get(..len)?,
        };
        self.0 = self.0.get(len.next_multiple_of(4)..).unwrap_or(&[]);
        Some(message)
    }
}

/// Attributes: `(type, payload)`, the type without its flags.
#[derive(Debug, Clone)]
pub struct Attrs<'a>(pub &'a [u8]);

impl<'a> Iterator for Attrs<'a> {
    type Item = (u16, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let len = usize::from(u16::from_ne_bytes(self.0.get(..2)?.try_into().ok()?));
        let kind = u16::from_ne_bytes(self.0.get(2..4)?.try_into().ok()?) & NLA_TYPE_MASK;
        if len < 4 || len > self.0.len() {
            self.0 = &[];
            return None;
        }
        let payload = self.0.get(4..len)?;
        self.0 = self.0.get(len.next_multiple_of(4)..).unwrap_or(&[]);
        Some((kind, payload))
    }
}

fn find(attrs: Attrs<'_>, kind: u16) -> Option<&[u8]> {
    attrs.into_iter().find(|(k, _)| *k == kind).map(|(_, v)| v)
}

fn be32(data: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(data.get(..4)?.try_into().ok()?))
}

fn be64(data: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(data.get(..8)?.try_into().ok()?))
}

fn strz(data: &[u8]) -> &[u8] {
    data.split(|b| *b == 0).next().unwrap_or(data)
}

/// The elements of the `NFT_MSG_NEWSETELEM` messages of a dump. `None` when one doesn't parse.
#[must_use]
pub fn parse_elements(dump: &[u8]) -> Option<Vec<Elem>> {
    let mut out = Vec::new();
    for message in Messages(dump) {
        if message.nft() == Some(NFT_MSG_NEWSETELEM) {
            out.extend(message_elements(&message)?);
        }
    }
    Some(out)
}

/// The set an element message is about, and its elements.
#[must_use]
pub fn message_elements(message: &Message<'_>) -> Option<Vec<Elem>> {
    let mut out = Vec::new();
    let Some(list) = find(message.attrs(), NFTA_SET_ELEM_LIST_ELEMENTS) else {
        return Some(out);
    };
    for (_, elem) in Attrs(list) {
        let mut e = Elem::key(Key {
            len: 0,
            bytes: [0; 16],
        });
        for (kind, value) in Attrs(elem) {
            match kind {
                NFTA_SET_ELEM_KEY => {
                    e.key = Key::from_slice(find(Attrs(value), NFTA_DATA_VALUE)?)?;
                }
                NFTA_SET_ELEM_FLAGS => e.end = be32(value)? & NFT_SET_ELEM_INTERVAL_END != 0,
                NFTA_SET_ELEM_TIMEOUT => e.timeout_ms = Some(be64(value)?),
                NFTA_SET_ELEM_EXPIRATION => e.expires_ms = Some(be64(value)?),
                NFTA_SET_ELEM_USERDATA => {
                    e.open = value.get(..2) == Some(&[UDATA_SET_ELEM_FLAGS, 4][..])
                        && value
                            .get(2..6)
                            .and_then(|v| v.try_into().ok())
                            .is_some_and(|v| u32::from_ne_bytes(v) & SET_ELEM_F_INTERVAL_OPEN != 0);
                }
                _ => {}
            }
        }
        if e.key.len == 0 {
            return None;
        }
        out.push(e);
    }
    Some(out)
}

/// The set an element message (or request) names.
#[cfg(test)]
#[must_use]
pub fn message_set<'a>(message: &Message<'a>) -> Option<&'a [u8]> {
    find(message.attrs(), NFTA_SET_ELEM_LIST_SET).map(strz)
}

/// The generation in a `NFT_MSG_NEWGEN` message.
#[must_use]
pub fn parse_gen(message: &Message<'_>) -> Option<u32> {
    if message.nft() != Some(NFT_MSG_NEWGEN) {
        return None;
    }
    be32(find(message.attrs(), NFTA_GEN_ID)?)
}

/// `(comment, packets, bytes)` of each rule with a counter in a `NFT_MSG_GETRULE` dump.
#[must_use]
pub fn parse_rule_counters(dump: &[u8]) -> Vec<(String, u64, u64)> {
    let mut out = Vec::new();
    for message in Messages(dump) {
        if message.nft() != Some(NFT_MSG_NEWRULE) {
            continue;
        }
        let mut comment = String::new();
        let (mut packets, mut bytes) = (0, 0);
        for (kind, value) in message.attrs() {
            match kind {
                NFTA_RULE_USERDATA => {
                    // TLVs of one byte of type and one of length.
                    let mut rest = value;
                    while let [t, l, tail @ ..] = rest {
                        let l = usize::from(*l);
                        let Some(v) = tail.get(..l) else { break };
                        if *t == UDATA_RULE_COMMENT {
                            comment = String::from_utf8_lossy(strz(v)).into_owned();
                        }
                        rest = tail.get(l..).unwrap_or(&[]);
                    }
                }
                NFTA_RULE_EXPRESSIONS => {
                    for (_, expr) in Attrs(value) {
                        if find(Attrs(expr), NFTA_EXPR_NAME).map(strz) != Some(b"counter") {
                            continue;
                        }
                        if let Some(data) = find(Attrs(expr), NFTA_EXPR_DATA) {
                            bytes += find(Attrs(data), NFTA_COUNTER_BYTES)
                                .and_then(be64)
                                .unwrap_or(0);
                            packets += find(Attrs(data), NFTA_COUNTER_PACKETS)
                                .and_then(be64)
                                .unwrap_or(0);
                        }
                    }
                }
                _ => {}
            }
        }
        out.push((comment, packets, bytes));
    }
    out
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Bytes from a hex dump (as `strace -e write=all` prints what nft sends).
    pub fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace()
            .map(|b| u8::from_str_radix(b, 16).unwrap())
            .collect()
    }

    /// What nft 1.1.3 sent, made into what barbican sends on purpose differently: every message asks for an
    /// acknowledgement (nft relies on errors alone), and element messages don't carry
    /// `NFTA_SET_ELEM_LIST_SET_ID`, nft's id of a set made in the same transaction (the kernel finds the set by
    /// name first).
    fn as_barbican(nft: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for m in Messages(nft) {
            let batch = m.kind >> 8 != NFNL_SUBSYS_NFTABLES;
            let mut body = m.payload[..NFGENMSG_LEN].to_vec();
            let mut rest = &m.payload[NFGENMSG_LEN..];
            while rest.len() >= 4 {
                let len = usize::from(u16::from_ne_bytes([rest[0], rest[1]]));
                let kind = u16::from_ne_bytes([rest[2], rest[3]]);
                let padded = len.next_multiple_of(4);
                if batch || kind != 4 || m.nft() != Some(NFT_MSG_NEWSETELEM) {
                    body.extend_from_slice(&rest[..padded]);
                }
                rest = &rest[padded..];
            }
            let flags = if batch { m.flags } else { m.flags | NLM_F_ACK };
            out.extend_from_slice(
                &u32::try_from(NLMSG_HDRLEN + body.len())
                    .unwrap()
                    .to_ne_bytes(),
            );
            out.extend_from_slice(&m.kind.to_ne_bytes());
            out.extend_from_slice(&flags.to_ne_bytes());
            out.extend_from_slice(&m.seq.to_ne_bytes());
            out.extend_from_slice(&0u32.to_ne_bytes());
            out.extend_from_slice(&body);
        }
        out
    }

    fn batch(f: impl FnOnce(&mut Writer)) -> Vec<u8> {
        let mut w = Writer::new(0);
        w.batch_begin();
        f(&mut w);
        w.batch_end();
        w.into_bytes()
    }

    fn net(s: &str) -> Net {
        s.parse().unwrap()
    }

    fn addr(s: &str) -> Key {
        Key::of(s.parse().unwrap())
    }

    // `nft add element inet T host4 { 198.51.100.7 timeout 3600s }`
    const HOST4: &str = "14 00 00 00 10 00 01 00  00 00 00 00 00 00 00 00
        00 00 00 0a 50 00 00 00  0c 0a 01 04 01 00 00 00  00 00 00 00 01 00 00 00  06 00 01 00 54 00 00 00
        0a 00 02 00 68 6f 73 74  34 00 00 00 08 00 04 00  00 00 00 01 20 00 03 80  1c 00 01 80 0c 00 04 00
        00 00 00 00 00 36 ee 80  0c 00 01 80 08 00 01 00  c6 33 64 07 14 00 00 00  11 00 01 00 02 00 00 00
        00 00 00 00 00 00 00 0a";

    // `nft add element inet T host6 { 2001:db8::1 }`
    const HOST6: &str = "14 00 00 00 10 00 01 00  00 00 00 00 00 00 00 00
        00 00 00 0a 50 00 00 00  0c 0a 01 04 01 00 00 00  00 00 00 00 01 00 00 00  06 00 01 00 54 00 00 00
        0a 00 02 00 68 6f 73 74  36 00 00 00 08 00 04 00  00 00 00 02 20 00 03 80  1c 00 01 80 18 00 01 80
        14 00 01 00 20 01 0d b8  00 00 00 00 00 00 00 00  00 00 00 01 14 00 00 00  11 00 01 00 02 00 00 00
        00 00 00 00 00 00 00 0a";

    // `nft add element inet T net4 { 198.51.100.0/25 timeout 600s }`, the set not empty: a start with the
    // timeout, and an end.
    const NET4: &str = "14 00 00 00 10 00 01 00  00 00 00 00 00 00 00 00
        00 00 00 0a 68 00 00 00  0c 0a 01 04 01 00 00 00  00 00 00 00 01 00 00 00  06 00 01 00 54 00 00 00
        09 00 02 00 6e 65 74 34  00 00 00 00 08 00 04 00  00 00 00 03 38 00 03 80  1c 00 01 80 0c 00 04 00
        00 00 00 00 00 09 27 c0  0c 00 01 80 08 00 01 00  c6 33 64 00 18 00 02 80  08 00 03 00 00 00 00 01
        0c 00 01 80 08 00 01 00  c6 33 64 80 14 00 00 00  11 00 01 00 02 00 00 00  00 00 00 00 00 00 00 0a";

    // `nft add element inet T list4 { 240.0.0.0/4 }`: up to the top of the address space, no end, an open flag in
    // the user data.
    const TOP4: &str = "14 00 00 00 10 00 01 00  00 00 00 00 00 00 00 00
        00 00 00 0a 50 00 00 00  0c 0a 01 04 01 00 00 00  00 00 00 00 01 00 00 00  06 00 01 00 54 00 00 00
        0a 00 02 00 6c 69 73 74  34 00 00 00 08 00 04 00  00 00 00 04 20 00 03 80  1c 00 01 80 0c 00 01 80
        08 00 01 00 f0 00 00 00  0a 00 06 00 01 04 01 00  00 00 00 00 14 00 00 00  11 00 01 00 02 00 00 00
        00 00 00 00 00 00 00 0a";

    // `nft add element inet T list6 { 2001:db8::/32 }` into the empty set: nft starts with an end at `::`.
    const LIST6: &str = "14 00 00 00 10 00 01 00  00 00 00 00 00 00 00 00
        00 00 00 0a 98 00 00 00  0c 0a 01 04 01 00 00 00  00 00 00 00 01 00 00 00  06 00 01 00 54 00 00 00
        0a 00 02 00 6c 69 73 74  36 00 00 00 08 00 04 00  00 00 00 05 68 00 03 80  24 00 01 80 08 00 03 00
        00 00 00 01 18 00 01 80  14 00 01 00 00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 00 1c 00 02 80
        18 00 01 80 14 00 01 00  20 01 0d b8 00 00 00 00  00 00 00 00 00 00 00 00  24 00 03 80 08 00 03 00
        00 00 00 01 18 00 01 80  14 00 01 00 20 01 0d b9  00 00 00 00 00 00 00 00  00 00 00 00 14 00 00 00
        11 00 01 00 02 00 00 00  00 00 00 00 00 00 00 0a";

    // `nft flush set inet T list4`
    const FLUSH: &str = "14 00 00 00 10 00 01 00  00 00 00 00 00 00 00 00
        00 00 00 0a 28 00 00 00  0e 0a 01 00 01 00 00 00  00 00 00 00 01 00 00 00  0a 00 02 00 6c 69 73 74
        34 00 00 00 06 00 01 00  54 00 00 00 14 00 00 00  11 00 01 00 02 00 00 00  00 00 00 00 00 00 00 0a";

    #[test]
    fn host_elements_as_nft_sends_them() {
        let mut e = Elem::key(addr("198.51.100.7"));
        e.timeout_ms = Some(3_600_000);
        let ours = batch(|w| w.elements(true, "T", "host4", &[(e, None)]));
        assert_eq!(ours, as_barbican(&hex(HOST4)));

        let e = Elem::key(addr("2001:db8::1"));
        let ours = batch(|w| w.elements(true, "T", "host6", &[(e, None)]));
        assert_eq!(ours, as_barbican(&hex(HOST6)));
    }

    #[test]
    fn intervals_as_nft_sends_them() {
        let ours = batch(|w| {
            w.elements(
                true,
                "T",
                "net4",
                &[interval(&net("198.51.100.0/25"), Some(600_000))],
            );
        });
        assert_eq!(ours, as_barbican(&hex(NET4)));

        let ours =
            batch(|w| w.elements(true, "T", "list4", &[interval(&net("240.0.0.0/4"), None)]));
        assert_eq!(ours, as_barbican(&hex(TOP4)));

        let mut zero = Elem::key(addr("::"));
        zero.end = true;
        let ours = batch(|w| {
            w.elements(
                true,
                "T",
                "list6",
                &[(zero, None), interval(&net("2001:db8::/32"), None)],
            );
        });
        assert_eq!(ours, as_barbican(&hex(LIST6)));
    }

    #[test]
    fn flush_and_destroy_as_nft_sends_them() {
        let ours = batch(|w| w.flush("T", "list4"));
        assert_eq!(ours, as_barbican(&hex(FLUSH)));

        // `nft destroy element inet T net4 { 203.0.113.0/24 }`, less the timeout and expiration nft copies from its
        // cache into the start element (deleting goes by key and flags alone).
        let nft = "14 00 00 00 10 00 01 00  00 00 00 00 00 00 00 00  00 00 00 0a
            54 00 00 00 1e 0a 05 00  01 00 00 00 00 00 00 00  01 00 00 00 06 00 01 00  54 00 00 00
            09 00 02 00 6e 65 74 34  00 00 00 00 2c 00 03 80  10 00 01 80 0c 00 01 80  08 00 01 00 cb 00 71 00
            18 00 02 80 08 00 03 00  00 00 00 01 0c 00 01 80  08 00 01 00 cb 00 72 00
            14 00 00 00 11 00 01 00  02 00 00 00 00 00 00 00  00 00 00 0a";
        let ours = batch(|w| {
            w.elements(
                false,
                "T",
                "net4",
                &[interval(&net("203.0.113.0/24"), None)],
            );
        });
        assert_eq!(ours, hex(nft));
    }

    #[test]
    fn requests_as_nft_sends_them() {
        let mut w = Writer::new(0);
        w.get_elements("T", "net4");
        assert_eq!(
            w.into_bytes(),
            hex(
                "28 00 00 00 0d 0a 01 03  00 00 00 00 00 00 00 00  01 00 00 00 09 00 02 00
                 6e 65 74 34 00 00 00 00  06 00 01 00 54 00 00 00"
            )
        );
        let mut w = Writer::new(0);
        w.get_gen();
        assert_eq!(
            w.into_bytes(),
            hex("14 00 00 00 10 0a 01 00  00 00 00 00 00 00 00 00  00 00 00 00")
        );
    }

    #[test]
    fn large_changes_are_split_into_messages() {
        let groups: Vec<_> = (0..10_000u32)
            .map(|i| {
                let ip = std::net::Ipv4Addr::from(0x0a00_0000 + (i << 8));
                interval(&Net::prefix(ip.into(), 24), Some(1000))
            })
            .collect();
        let ours = batch(|w| w.elements(true, "T", "net4", &groups));
        let mut elements = 0;
        let mut messages = 0;
        for m in Messages(&ours) {
            if m.nft() == Some(NFT_MSG_NEWSETELEM) {
                messages += 1;
                let list = find(m.attrs(), NFTA_SET_ELEM_LIST_ELEMENTS).unwrap();
                assert!(u16::try_from(list.len() + 4).is_ok());
                elements += Attrs(list).count();
            }
        }
        assert!(messages > 1);
        assert_eq!(elements, 20_000);
    }

    #[test]
    fn intervals_of_prefixes() {
        let (start, end) = interval(&net("198.51.100.0/25"), None);
        assert_eq!(start.key, addr("198.51.100.0"));
        assert_eq!(end.unwrap().key, addr("198.51.100.128"));
        assert!(end.unwrap().end);
        // The end of the last prefix before the top carries over.
        let (_, end) = interval(&net("203.0.113.255"), None);
        assert_eq!(end.unwrap().key, addr("203.0.114.0"));
        let (start, end) = interval(&net("ffff:ffff::/32"), None);
        assert!(start.open && end.is_none());

        // The last address before the top ends at the top.
        let (_, end) = interval(&net("255.255.255.254"), None);
        assert_eq!(end.unwrap().key, addr("255.255.255.255"));

        let range = |s: &str| s.parse::<Range>().unwrap();
        assert_eq!(
            interval_range(addr("198.51.100.0"), Some(addr("198.51.100.128"))),
            Some(range("198.51.100.0/25"))
        );
        assert_eq!(
            interval_range(addr("240.0.0.0"), None),
            Some(range("240.0.0.0/4"))
        );
        assert_eq!(
            interval_range(addr("ff00::"), None),
            Some(range("ff00::/8"))
        );
        assert_eq!(
            interval_range(addr("192.0.2.5"), Some(addr("192.0.2.6"))),
            Some(range("192.0.2.5"))
        );
        assert_eq!(
            interval_range(addr("192.0.2.10"), Some(addr("192.0.2.21"))),
            Some(range("192.0.2.10-192.0.2.20"))
        );
        assert_eq!(
            interval_range(addr("192.0.2.1"), Some(addr("192.0.2.1"))),
            None
        );
        assert_eq!(
            interval_range(addr("192.0.2.1"), Some(addr("0.0.0.0"))),
            None
        );
        assert_eq!(
            interval_range(addr("192.0.2.1"), Some(addr("2001:db8::"))),
            None
        );
    }

    #[test]
    fn ranges_as_nft_sends_them() {
        let range = |s: &str| s.parse::<Range>().unwrap();
        // `nft add element inet T list4 { 192.0.2.10-192.0.2.20 }`: the set not empty, a start and an end.
        let (start, end) = super::range(&range("192.0.2.10-192.0.2.20"), None);
        assert_eq!(
            (start.key, start.end, start.open),
            (addr("192.0.2.10"), false, false)
        );
        let end = end.unwrap();
        assert_eq!((end.key, end.end), (addr("192.0.2.21"), true));
        // Up to the top: no end, open, as for a prefix up to the top.
        let (start, end) = super::range(&range("250.0.0.0-255.255.255.255"), None);
        assert!(start.open && end.is_none());
        let (start, end) = super::range(
            &range("ffff::1-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
            Some(5),
        );
        assert!(start.open && end.is_none() && start.timeout_ms == Some(5));
        // A prefix as a range is the prefix.
        assert_eq!(
            super::range(&range("198.51.100.0-198.51.100.127"), Some(600_000)),
            interval(&net("198.51.100.0/25"), Some(600_000))
        );
        let ours = batch(|w| {
            w.elements(
                true,
                "T",
                "list4",
                &[super::range(&range("240.0.0.0-255.255.255.255"), None)],
            );
        });
        assert_eq!(ours, as_barbican(&hex(TOP4)));
    }

    /// A dump of `net4` holding 198.51.100.0/25 (timeout 600 s, 599.936 s left) and the end at 0.0.0.0 nft
    /// added below it, in the kernel's order (descending), then `NLMSG_DONE`.
    pub const NET4_DUMP: &str = "84 00 00 00 0c 0a 02 00  00 00 00 00 c5 04 00 00
        01 00 00 5d 06 00 01 00  54 00 00 00 09 00 02 00  6e 65 74 34 00 00 00 00  5c 00 03 00 18 00 01 00
        0c 00 01 00 08 00 01 00  c6 33 64 80 08 00 03 00  00 00 00 01 28 00 01 00  0c 00 01 00 08 00 01 00
        c6 33 64 00 0c 00 04 00  00 00 00 00 00 09 27 c0  0c 00 05 00 00 00 00 00  00 09 27 80 18 00 01 00
        0c 00 01 00 08 00 01 00  00 00 00 00 08 00 03 00  00 00 00 01
        2c 00 00 00 0c 0a 02 00  00 00 00 00 c5 04 00 00  01 00 00 5d 06 00 01 00  54 00 00 00 09 00 02 00
        6e 65 74 34 00 00 00 00  04 00 03 00
        14 00 00 00 03 00 02 00  00 00 00 00 c5 04 00 00  00 00 00 00";

    #[test]
    fn parses_a_dump() {
        let elems = parse_elements(&hex(NET4_DUMP)).unwrap();
        assert_eq!(elems.len(), 3);
        assert_eq!(elems[0].key, addr("198.51.100.128"));
        assert!(elems[0].end);
        assert_eq!(elems[1].key, addr("198.51.100.0"));
        assert!(!elems[1].end);
        assert_eq!(elems[1].timeout_ms, Some(600_000));
        assert_eq!(elems[1].expires_ms, Some(599_936));
        assert_eq!(elems[2].key, addr("0.0.0.0"));
        assert!(elems[2].end);
    }

    #[test]
    fn parses_rule_counters() {
        // A rule `ip saddr @host4 counter packets 3 bytes 180 drop comment "blocked"`, as the kernel dumps it.
        let dump = hex("5c 01 00 00 06 0a 02 08  00 00 00 00 ec 06 00 00
            01 00 00 7e 06 00 01 00  52 00 00 00 0f 00 02 00  70 72 65 72 6f 75 74 69  6e 67 00 00 0c 00 03 00
            00 00 00 00 00 00 00 03  14 01 04 00 24 00 01 00  09 00 01 00 6d 65 74 61  00 00 00 00 14 00 02 00
            08 00 02 00 00 00 00 0f  08 00 01 00 00 00 00 01  2c 00 01 00 08 00 01 00  63 6d 70 00 20 00 02 00
            08 00 01 00 00 00 00 01  08 00 02 00 00 00 00 00  0c 00 03 00 05 00 01 00  02 00 00 00 34 00 01 00
            0c 00 01 00 70 61 79 6c  6f 61 64 00 24 00 02 00  08 00 01 00 00 00 00 01  08 00 02 00 00 00 00 01
            08 00 03 00 00 00 00 0c  08 00 04 00 00 00 00 04  30 00 01 00 0b 00 01 00  6c 6f 6f 6b 75 70 00 00
            20 00 02 00 0a 00 01 00  68 6f 73 74 34 00 00 00  08 00 02 00 00 00 00 01  08 00 05 00 00 00 00 00
            2c 00 01 00 0c 00 01 00  63 6f 75 6e 74 65 72 00  1c 00 02 00 0c 00 01 00  00 00 00 00 00 00 00 b4
            0c 00 02 00 00 00 00 00  00 00 00 03 30 00 01 00  0e 00 01 00 69 6d 6d 65  64 69 61 74 65 00 00 00
            1c 00 02 00 08 00 01 00  00 00 00 00 10 00 02 00  0c 00 02 00 08 00 01 00  00 00 00 00 0e 00 07 00
            00 08 62 6c 6f 63 6b 65  64 00 00 00");
        assert_eq!(
            parse_rule_counters(&dump),
            vec![("blocked".to_owned(), 3, 180)]
        );
    }

    #[test]
    fn generation() {
        // NFT_MSG_NEWGEN of generation 93, as the kernel sends it.
        let gen_msg = hex(
            "2c 00 00 00 0f 0a 00 00  00 00 00 00 c5 04 00 00  00 00 00 5d
            08 00 01 00 00 00 00 5d  08 00 02 00 00 00 04 c5  08 00 03 00 6e 66 74 00",
        );
        let m = Messages(&gen_msg).next().unwrap();
        assert_eq!(parse_gen(&m), Some(93));
    }
}
