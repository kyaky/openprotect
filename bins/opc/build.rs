//! Capture a human-meaningful build version for `opc` at compile time and
//! expose it as the `OPC_VERSION` env var (read via `env!`/`option_env!`).
//!
//! Priority:
//!   1. `GITHUB_REF_NAME` when it looks like a release tag (`v*`) — this is
//!      the exact tag the CI release build was cut from (e.g. `v0.2.0-alpha.20`).
//!   2. `git describe --tags --always --dirty` — for local builds, yields
//!      e.g. `v0.2.0-alpha.20-3-gabc1234` or `-dirty`.
//!   3. `CARGO_PKG_VERSION` as a last resort.

use std::path::Path;
use std::process::Command;

fn main() {
    let version = std::env::var("GITHUB_REF_NAME")
        .ok()
        .filter(|v| v.starts_with('v'))
        .or_else(git_describe)
        .or_else(|| std::env::var("CARGO_PKG_VERSION").ok())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=OPC_VERSION={version}");
    println!("cargo:rerun-if-env-changed=GITHUB_REF_NAME");
    // Rebuild when the checked-out commit/tag changes, if we're in a git tree.
    for p in ["../../.git/HEAD", "../../.git/packed-refs"] {
        if Path::new(p).exists() {
            println!("cargo:rerun-if-changed={p}");
        }
    }
}

fn git_describe() -> Option<String> {
    let out = Command::new("git")
        .args(["describe", "--tags", "--always", "--dirty"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}
