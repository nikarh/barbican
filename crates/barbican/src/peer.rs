//! Who may use the UI's unix socket: checked on every connection with the kernel's credentials of the peer
//! (`SO_PEERCRED`, `SO_PEERGROUPS`), not only by the socket file's mode. A process may use it when it runs as root, as
//! the agent's own user, or with the socket's group as its primary or one of its supplementary groups (a container
//! given the group with `group_add` has it as a supplementary group). Everything else is refused, and logged.
//!
//! The UI is full control over the agent: what it bans, allows and blocks. The socket is its only way in.

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use tokio::net::{UnixListener, UnixStream};

/// Who may connect: the owner and the group of the socket file (the agent's user, and `ui.socket_group`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Allowed {
    pub uid: u32,
    pub gid: u32,
}

impl Allowed {
    /// The owner and group of the socket at `path`, as the agent made it.
    pub fn of(path: &Path) -> io::Result<Self> {
        let meta = std::fs::metadata(path)?;
        Ok(Self {
            uid: meta.uid(),
            gid: meta.gid(),
        })
    }

    /// Whether a peer with these credentials may use the socket.
    #[must_use]
    pub fn admits(self, peer: &Peer) -> bool {
        peer.uid == 0
            || peer.uid == self.uid
            || peer.gid == self.gid
            || peer.groups.contains(&self.gid)
    }
}

/// The credentials of the process at the other end of a connection, as the kernel recorded them when it connected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub pid: Option<i32>,
    pub uid: u32,
    pub gid: u32,
    /// Its supplementary groups.
    pub groups: Vec<u32>,
}

impl Peer {
    pub fn of(stream: &UnixStream) -> io::Result<Self> {
        let cred = stream.peer_cred()?;
        Ok(Self {
            pid: cred.pid(),
            uid: cred.uid(),
            gid: cred.gid(),
            groups: peer_groups(stream.as_fd())?,
        })
    }
}

/// The peer's supplementary groups (`SO_PEERGROUPS`, Linux 4.13 and later), as group ids of this process' user
/// namespace.
#[allow(unsafe_code)]
fn peer_groups(fd: BorrowedFd<'_>) -> io::Result<Vec<u32>> {
    // Enough for any ordinary process; the kernel says how many it has when it has more, and we ask again.
    let mut groups: Vec<libc::gid_t> = vec![0; 64];
    loop {
        let size = std::mem::size_of_val(groups.as_slice());
        let mut len =
            libc::socklen_t::try_from(size).map_err(|_| io::Error::other("too many groups"))?;
        // SAFETY: `groups` is a live, writable buffer of `len` bytes for the whole call, `len` points to a valid
        // socklen_t, and `fd` is an open socket borrowed for the call. The kernel writes at most `len` bytes into the
        // buffer and the size it used (or needs) into `len`.
        let result = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERGROUPS,
                groups.as_mut_ptr().cast(),
                &raw mut len,
            )
        };
        let used = usize::try_from(len).unwrap_or(0) / std::mem::size_of::<libc::gid_t>();
        if result == 0 {
            groups.truncate(used.min(groups.len()));
            return Ok(groups);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ERANGE) && used > groups.len() && used <= 65_536 {
            groups.resize(used, 0);
            continue;
        }
        return Err(error);
    }
}

/// The UI's unix socket, admitting only the peers its [`Allowed`] admits: every connection is checked before a byte
/// of it is read.
pub struct CheckedListener {
    listener: UnixListener,
    allowed: Allowed,
}

impl CheckedListener {
    #[must_use]
    pub fn new(listener: UnixListener, allowed: Allowed) -> Self {
        Self { listener, allowed }
    }
}

impl axum::serve::Listener for CheckedListener {
    type Io = UnixStream;
    type Addr = tokio::net::unix::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, address) = match self.listener.accept().await {
                Ok(accepted) => accepted,
                Err(e) => {
                    // Out of file descriptors and such: as axum's own listeners do, wait a little and go on.
                    tracing::warn!(error = %e, "Accepting on the UI socket failed");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };
            match Peer::of(&stream) {
                Ok(peer) if self.allowed.admits(&peer) => return (stream, address),
                Ok(peer) => tracing::warn!(
                    pid = ?peer.pid,
                    uid = peer.uid,
                    gid = peer.gid,
                    groups = ?peer.groups,
                    "Refused a connection to the UI socket: neither root, the agent's user, nor in its group"
                ),
                Err(e) => tracing::warn!(
                    error = %e,
                    "Refused a connection to the UI socket: its peer's credentials are unknown"
                ),
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(uid: u32, gid: u32, groups: &[u32]) -> Peer {
        Peer {
            pid: Some(1),
            uid,
            gid,
            groups: groups.to_vec(),
        }
    }

    #[test]
    fn admits_root_owner_and_group_members_only() {
        let allowed = Allowed {
            uid: 61_234,
            gid: 461,
        };
        assert!(allowed.admits(&peer(0, 0, &[])));
        assert!(allowed.admits(&peer(61_234, 61_234, &[])));
        assert!(allowed.admits(&peer(1000, 461, &[])));
        // A container given the group with group_add: a supplementary group.
        assert!(allowed.admits(&peer(65_534, 65_534, &[461])));
        assert!(!allowed.admits(&peer(1000, 1000, &[10, 998])));
        assert!(!allowed.admits(&peer(65_534, 65_534, &[])));
    }

    #[tokio::test]
    async fn reads_this_process_credentials() {
        let dir = std::env::temp_dir().join(format!("barbican-peer-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let allowed = Allowed::of(&path).unwrap();
        let client = tokio::spawn({
            let path = path.clone();
            async move { UnixStream::connect(path).await.unwrap() }
        });
        let (server, _) = listener.accept().await.unwrap();
        let _client = client.await.unwrap();
        let me = Peer::of(&server).unwrap();
        assert_eq!(me.uid, allowed.uid);
        assert_eq!(me.pid, Some(i32::try_from(std::process::id()).unwrap()));
        // The supplementary groups are this process' own.
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let mine: Vec<u32> = status
            .lines()
            .find_map(|l| l.strip_prefix("Groups:"))
            .unwrap()
            .split_whitespace()
            .map(|g| g.parse().unwrap())
            .collect();
        let mut theirs = me.groups.clone();
        theirs.sort_unstable();
        let mut mine = mine;
        mine.sort_unstable();
        assert_eq!(theirs, mine);
        assert!(allowed.admits(&me));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
