//! What an edge keeps on flash between restarts, in a compact binary form: flash wears with every write, so the
//! files are small and written rarely.
//!
//! Two files: the state (each upstream's bans and allows, rewritten at most every `persist_interval`) and, next to it
//! with the extension `lists`, the upstreams' lists (rewritten only when one of them changed: countries and blocklists
//! change a few times a day, bans all the time). Lists hold only the families the firewall loads.
//!
//! Layout (integers little-endian): a magic of 8 bytes, then per file
//!
//! * state: `saved_at` u64, upstream count u16; per upstream: name, epoch (u16 length + UTF-8 each), seq u64, then
//!   blocks (nets, each followed by its end, u64, `u64::MAX` for never) and allows (nets);
//! * lists: upstream count u16; per upstream: name, version, then nets;
//!
//! where nets are an IPv4 count u32 and that many 5-byte records (address, prefix length), then an IPv6 count u32 and
//! 17-byte records. A state written by an older version (JSON) is still read.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use barbican_common::edge::Mirror;
use barbican_common::net::{Family, Net};

const STATE_MAGIC: &[u8; 8] = b"BRBNst01";
const LISTS_MAGIC: &[u8; 8] = b"BRBNls01";
const V4: usize = 5;
const V6: usize = 17;

/// What is saved: each upstream's mirror and list (with its version), and when.
#[derive(Debug, Default, PartialEq, Eq, serde::Deserialize)]
pub struct Saved {
    pub saved_at: u64,
    pub mirrors: BTreeMap<String, Mirror>,
    pub lists: BTreeMap<String, Vec<Net>>,
    #[serde(default)]
    pub list_versions: BTreeMap<String, String>,
}

/// The file of the lists, next to the state's.
#[must_use]
pub fn lists_path(state: &Path) -> PathBuf {
    state.with_extension("lists")
}

struct Writer(Vec<u8>);

impl Writer {
    fn u16(&mut self, v: usize) -> Result<(), String> {
        let v = u16::try_from(v).map_err(|_| "too many".to_owned())?;
        self.0.extend_from_slice(&v.to_le_bytes());
        Ok(())
    }

    fn u32(&mut self, v: usize) -> Result<(), String> {
        let v = u32::try_from(v).map_err(|_| "too many".to_owned())?;
        self.0.extend_from_slice(&v.to_le_bytes());
        Ok(())
    }

    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    fn str(&mut self, s: &str) -> Result<(), String> {
        self.u16(s.len())?;
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }

    /// Nets, IPv4 first, each followed by what `extra` writes.
    fn nets<'a>(
        &mut self,
        nets: &(impl Iterator<Item = &'a Net> + Clone),
        mut extra: impl FnMut(&mut Self, &Net),
    ) -> Result<(), String> {
        for family in [Family::V4, Family::V6] {
            let of = nets.clone().filter(|n| n.family() == family);
            self.u32(of.clone().count())?;
            for net in of {
                self.0.extend_from_slice(&net.to_bytes());
                extra(self, net);
            }
        }
        Ok(())
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.0.len() < n {
            return Err("truncated".to_owned());
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u16(&mut self) -> Result<usize, String> {
        let b: [u8; 2] = self.take(2)?.try_into().map_err(|_| "truncated")?;
        Ok(usize::from(u16::from_le_bytes(b)))
    }

    fn u32(&mut self) -> Result<usize, String> {
        let b: [u8; 4] = self.take(4)?.try_into().map_err(|_| "truncated")?;
        usize::try_from(u32::from_le_bytes(b)).map_err(|_| "too large".to_owned())
    }

    fn u64(&mut self) -> Result<u64, String> {
        let b: [u8; 8] = self.take(8)?.try_into().map_err(|_| "truncated")?;
        Ok(u64::from_le_bytes(b))
    }

    fn str(&mut self) -> Result<String, String> {
        let n = self.u16()?;
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| "not UTF-8".to_owned())
    }

    /// Nets in place: records of a fixed size, each followed by `extra` bytes.
    fn nets(&mut self, extra: usize) -> Result<Vec<(Net, &'a [u8])>, String> {
        let mut out = Vec::new();
        for size in [V4, V6] {
            let n = self.u32()?;
            let bytes = self.take(n.checked_mul(size + extra).ok_or("too large")?)?;
            for record in bytes.chunks_exact(size + extra) {
                let (net, rest) = record.split_at(size);
                let net = Net::from_bytes(net).ok_or("an invalid net")?;
                out.push((net, rest));
            }
        }
        Ok(out)
    }
}

/// The state file's bytes.
pub fn encode_state(saved: &Saved) -> Result<Vec<u8>, String> {
    let mut w = Writer(Vec::with_capacity(64 * 1024));
    w.0.extend_from_slice(STATE_MAGIC);
    w.u64(saved.saved_at);
    w.u16(saved.mirrors.len())?;
    for (name, m) in &saved.mirrors {
        w.str(name)?;
        w.str(&m.epoch)?;
        w.u64(m.seq);
        w.nets(&m.blocks.keys(), |w, net| {
            w.u64(m.blocks.get(net).copied().flatten().unwrap_or(u64::MAX));
        })?;
        w.nets(&m.allows.iter(), |_, _| {})?;
    }
    Ok(w.0)
}

/// The lists file's bytes: of each list only the families loaded (`ipv6`), so that it stays small.
pub fn encode_lists(saved: &Saved, ipv6: bool) -> Result<Vec<u8>, String> {
    let mut w = Writer(Vec::with_capacity(512 * 1024));
    w.0.extend_from_slice(LISTS_MAGIC);
    w.u16(saved.lists.len())?;
    for (name, nets) in &saved.lists {
        w.str(name)?;
        // A list saved without IPv6 isn't the list of its version once IPv6 is on: it is fetched again then.
        let version = saved.list_versions.get(name).map_or("", String::as_str);
        w.str(&if ipv6 {
            version.to_owned()
        } else {
            format!("{version}\0v4")
        })?;
        w.nets(
            &nets.iter().filter(|n| ipv6 || n.family() == Family::V4),
            |_, _| {},
        )?;
    }
    Ok(w.0)
}

fn decode_state(bytes: &[u8], saved: &mut Saved) -> Result<(), String> {
    let mut r = Reader(bytes);
    if r.take(8)? != STATE_MAGIC {
        return Err("not a state file".to_owned());
    }
    saved.saved_at = r.u64()?;
    for _ in 0..r.u16()? {
        let name = r.str()?;
        let epoch = r.str()?;
        let seq = r.u64()?;
        let blocks = r
            .nets(8)?
            .into_iter()
            .map(|(net, end)| {
                let end: [u8; 8] = end.try_into().unwrap_or([0xff; 8]);
                let end = u64::from_le_bytes(end);
                (net, (end != u64::MAX).then_some(end))
            })
            .collect();
        let allows: BTreeSet<Net> = r.nets(0)?.into_iter().map(|(n, _)| n).collect();
        saved.mirrors.insert(
            name,
            Mirror {
                epoch,
                seq,
                blocks,
                allows,
            },
        );
    }
    Ok(())
}

fn decode_lists(bytes: &[u8], ipv6: bool, saved: &mut Saved) -> Result<(), String> {
    let mut r = Reader(bytes);
    if r.take(8)? != LISTS_MAGIC {
        return Err("not a lists file".to_owned());
    }
    for _ in 0..r.u16()? {
        let name = r.str()?;
        let version = r.str()?;
        let nets = r.nets(0)?.into_iter().map(|(n, _)| n).collect();
        // Saved without IPv6 while it is on now (or the other way round): its version is no longer known.
        let version = match version.strip_suffix("\0v4") {
            Some(v) if !ipv6 => v.to_owned(),
            None if ipv6 => version,
            _ => String::new(),
        };
        saved.list_versions.insert(name.clone(), version);
        saved.lists.insert(name, nets);
    }
    Ok(())
}

/// Reads what was saved; nothing (and a warning) when it can't be.
pub fn load(state: &Path, ipv6: bool, warn: &dyn Fn(String)) -> Saved {
    let mut saved = Saved::default();
    let Ok(bytes) = std::fs::read(state) else {
        return saved;
    };
    if bytes.first() == Some(&b'{') {
        // Written by an older version: everything in one JSON document.
        return serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            warn(format!("{}: {e}; starting empty", state.display()));
            Saved::default()
        });
    }
    if let Err(e) = decode_state(&bytes, &mut saved) {
        warn(format!("{}: {e}; starting empty", state.display()));
        return Saved::default();
    }
    let lists = lists_path(state);
    if let Ok(bytes) = std::fs::read(&lists)
        && let Err(e) = decode_lists(&bytes, ipv6, &mut saved)
    {
        warn(format!(
            "{}: {e}; the lists are fetched again",
            lists.display()
        ));
        saved.lists.clear();
        saved.list_versions.clear();
    }
    saved
}

/// Writes a file whole: a partial one is renamed over it, so a power cut leaves the old or the new.
pub fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let partial = path.with_extension("part");
    std::fs::write(&partial, bytes)
        .and_then(|()| std::fs::rename(&partial, path))
        .map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;

    fn net(s: &str) -> Net {
        s.parse().unwrap()
    }

    fn sample() -> Saved {
        let mut saved = Saved {
            saved_at: 1_700_000_000,
            ..Saved::default()
        };
        saved.mirrors.insert(
            "files".into(),
            Mirror {
                epoch: "e1".into(),
                seq: 42,
                blocks: [
                    (net("198.51.100.7"), Some(1_700_003_600)),
                    (net("203.0.113.0/24"), None),
                    (net("2001:db8::7"), Some(5)),
                ]
                .into_iter()
                .collect(),
                allows: [net("192.0.2.0/24"), net("2001:db8:1::/48")]
                    .into_iter()
                    .collect(),
            },
        );
        saved.lists.insert(
            "files".into(),
            vec![net("203.0.113.0/24"), net("2001:db8:2::/48")],
        );
        saved.list_versions.insert("files".into(), "v1".into());
        saved
    }

    #[test]
    fn round_trips_and_keeps_only_the_families_loaded() {
        let dir = std::env::temp_dir().join(format!("barbican-saved-{}", std::process::id()));
        let state = dir.join("state.bin");
        let saved = sample();
        write(&state, &encode_state(&saved).unwrap()).unwrap();
        write(&lists_path(&state), &encode_lists(&saved, true).unwrap()).unwrap();
        assert_eq!(load(&state, true, &|e| panic!("{e}")), saved);

        // Without IPv6 the list file holds IPv4 only, and its version is kept only while IPv6 stays off.
        write(&lists_path(&state), &encode_lists(&saved, false).unwrap()).unwrap();
        let v4 = load(&state, false, &|e| panic!("{e}"));
        assert_eq!(v4.lists["files"], vec![net("203.0.113.0/24")]);
        assert_eq!(v4.list_versions["files"], "v1");
        assert_eq!(v4.mirrors, saved.mirrors);
        assert_eq!(
            load(&state, true, &|e| panic!("{e}")).list_versions["files"],
            ""
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn small() {
        // 24 000 bans of single IPv4 addresses take 13 bytes each.
        let mut saved = Saved::default();
        let blocks = (0..24_000u32)
            .map(|i| {
                (
                    Net::host(IpAddr::from((0xC633_0000u32 | i).to_be_bytes())),
                    Some(1),
                )
            })
            .collect();
        saved.mirrors.insert(
            "a".into(),
            Mirror {
                blocks,
                ..Mirror::default()
            },
        );
        assert!(encode_state(&saved).unwrap().len() < 24_000 * 13 + 64);
    }

    #[test]
    fn garbage_and_truncation_are_errors() {
        let bytes = encode_state(&sample()).unwrap();
        for n in 0..bytes.len() {
            assert!(decode_state(&bytes[..n], &mut Saved::default()).is_err());
        }
        assert!(decode_state(b"BRBNst01garbage!", &mut Saved::default()).is_err());
    }

    #[test]
    fn reads_the_old_json() {
        let dir = std::env::temp_dir().join(format!("barbican-saved-json-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let state = dir.join("state.json");
        std::fs::write(
            &state,
            r#"{"saved_at":7,"mirrors":{"files":{"epoch":"e","seq":3,"blocks":{},"allows":[]}},"lists":{}}"#,
        )
        .unwrap();
        let saved = load(&state, true, &|e| panic!("{e}"));
        assert_eq!(saved.saved_at, 7);
        assert_eq!(saved.mirrors["files"].seq, 3);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
