//! Sets `BARBICAN_VERSION`: the package version plus `BARBICAN_VERSION_SUFFIX` (e.g. `-dev+abc1234` for builds of
//! main), so a bug report tells which build it was.

fn main() {
    println!("cargo::rerun-if-env-changed=BARBICAN_VERSION_SUFFIX");
    let suffix = std::env::var("BARBICAN_VERSION_SUFFIX").unwrap_or_default();
    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    println!("cargo::rustc-env=BARBICAN_VERSION={version}{suffix}");
}
