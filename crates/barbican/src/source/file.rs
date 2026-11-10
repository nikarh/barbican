//! A log file, followed across rotation (renamed or truncated). On its own thread with blocking reads; the line
//! buffer is reused. The cursor is `<inode>:<offset>`: after a restart reading goes on there if the file is the same,
//! and starts at its end otherwise (lines without times can't be put in order with what was already read).

use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;

use super::Feeder;
use crate::app::now;

const POLL: Duration = Duration::from_millis(500);

/// Where to start reading a file just opened.
fn start(saved: Option<(u64, u64)>, first: bool, inode: u64, len: u64) -> u64 {
    match saved {
        Some((i, offset)) if first && i == inode && offset <= len => offset,
        _ if first => len,
        // A file that replaced the one being read (rotation) is read from its start.
        _ => 0,
    }
}

pub fn run(mut feeder: Feeder, path: &Path, handle: &tokio::runtime::Handle) {
    let saved = handle.block_on(feeder.saved_cursor()).and_then(|c| {
        let (inode, offset) = c.split_once(':')?;
        Some((inode.parse::<u64>().ok()?, offset.parse::<u64>().ok()?))
    });
    let mut first = true;
    let mut line = String::new();
    loop {
        let opened = File::open(path).and_then(|f| f.metadata().map(|m| (f, m)));
        let (file, meta) = match opened {
            Ok(x) => x,
            Err(e) => {
                feeder.failed(&format!("{}: {e}", path.display()));
                std::thread::sleep(Duration::from_secs(5));
                first = false;
                continue;
            }
        };
        let inode = meta.ino();
        let mut offset = start(saved, first, inode, meta.len());
        first = false;
        let mut reader = BufReader::new(file);
        if reader.seek(SeekFrom::Start(offset)).is_err() {
            continue;
        }
        feeder.connected();
        line.clear();
        loop {
            match reader.read_line(&mut line) {
                Ok(0) => {
                    handle.block_on(feeder.cursor(format!("{inode}:{offset}")));
                    std::thread::sleep(POLL);
                    // Replaced (another inode at the path) or truncated: start over with the new file.
                    match std::fs::metadata(path) {
                        Ok(m) if m.ino() == inode && m.len() >= offset => {}
                        _ => break,
                    }
                }
                Ok(n) => {
                    offset += n as u64;
                    // A line still being written stays in the buffer until its newline arrives.
                    if !line.ends_with('\n') {
                        continue;
                    }
                    if !feeder.blocking_line(&line, now()) {
                        return;
                    }
                    line.clear();
                }
                Err(e) => {
                    feeder.failed(&e.to_string());
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starting_points() {
        assert_eq!(start(Some((7, 100)), true, 7, 500), 100);
        assert_eq!(start(Some((7, 900)), true, 7, 500), 500);
        assert_eq!(start(Some((8, 100)), true, 7, 500), 500);
        assert_eq!(start(None, true, 7, 500), 500);
        assert_eq!(start(Some((7, 100)), false, 9, 500), 0);
    }
}
