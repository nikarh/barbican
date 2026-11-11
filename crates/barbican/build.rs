//! Sets `BARBICAN_VERSION` (the package version plus `BARBICAN_VERSION_SUFFIX`, e.g. `-dev+abc1234` for builds of main)
//! and embeds the built frontend (`web/dist`) into the binary. Without it, the binary still builds and serves a
//! placeholder page, so that the backend can be developed without node.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo::rerun-if-env-changed=BARBICAN_VERSION_SUFFIX");
    let suffix = std::env::var("BARBICAN_VERSION_SUFFIX").unwrap_or_default();
    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    println!("cargo::rustc-env=BARBICAN_VERSION={version}{suffix}");

    let root = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap_or_default());
    let dist = root.join("..").join("..").join("web").join("dist");
    println!("cargo::rerun-if-changed={}", dist.display());

    let mut files = Vec::new();
    if dist.is_dir() {
        collect(&dist, &dist, &mut files);
    }
    files.sort();

    // Each file with its brotli and gzip copies (`name.br`, `name.gz`), when the build made them.
    let include = |path: &Path| format!("include_bytes!({:?})", path.display().to_string());
    let variant = |path: &Path, ext: &str| {
        let mut name = path.as_os_str().to_owned();
        name.push(ext);
        let path = PathBuf::from(name);
        if path.is_file() {
            format!("Some({})", include(&path))
        } else {
            "None".to_owned()
        }
    };
    let mut out = String::from("pub static FILES: &[Asset] = &[\n");
    for (name, path) in &files {
        // The copies themselves, which the build names with these exact extensions.
        if path
            .extension()
            .is_some_and(|ext| ext == "br" || ext == "gz")
        {
            continue;
        }
        let _ = writeln!(
            out,
            "    Asset {{ name: {name:?}, identity: {}, br: {}, gzip: {} }},",
            include(path),
            variant(path, ".br"),
            variant(path, ".gz"),
        );
    }
    out.push_str("];\n");

    let target = PathBuf::from(std::env::var_os("OUT_DIR").unwrap_or_default()).join("assets.rs");
    if let Err(e) = std::fs::write(&target, out) {
        panic!("writing {}: {e}", target.display());
    }
}

fn collect(dist: &Path, dir: &Path, files: &mut Vec<(String, PathBuf)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(dist, &path, files);
        } else if let Ok(name) = path.strip_prefix(dist) {
            let name = name
                .components()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            files.push((name, path));
        }
    }
}
