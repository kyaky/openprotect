//! Authentication engine for GlobalProtect.
//!
//! Provides the [`AuthProvider`] plugin trait and concrete implementations
//! (password, SAML, Okta, certificate).

pub mod client;
pub mod context;
pub mod error;
pub mod hip;
pub mod okta;
pub mod password;
pub mod saml_common;
pub mod saml_paste;

pub use client::GpClient;
pub use context::AuthContext;
pub use error::AuthError;
pub use okta::{OktaAuthConfig, OktaAuthProvider};
pub use password::PasswordAuthProvider;
pub use saml_paste::SamlPasteAuthProvider;

use async_trait::async_trait;
use gp_proto::{Credential, PreloginResponse};

/// Trait implemented by each authentication method.
///
/// Providers are selected based on the prelogin response and return a
/// [`Credential`] that can be used for portal config retrieval or
/// gateway login.
#[async_trait]
pub trait AuthProvider: Send + Sync {
    /// Human-readable name (e.g. `"password"`, `"saml-browser"`).
    fn name(&self) -> &str;

    /// Whether this provider can handle the given prelogin response.
    fn can_handle(&self, prelogin: &PreloginResponse) -> bool;

    /// Run the authentication flow and return credentials.
    async fn authenticate(
        &self,
        prelogin: &PreloginResponse,
        ctx: &AuthContext,
    ) -> Result<Credential, AuthError>;
}

#[cfg(test)]
mod mutation_marker_guard_tests {
    //! Issue #36 audit contingency: during the resweep an external
    //! mutation harness left an uncommitted ALL-CAPS marker in
    //! production source (`mask_secret_key_values` gained an early
    //! `return text.to_string();` behind such a marker, silently
    //! disabling the secret-masking lane while the suite still claimed
    //! green). A shipped branch must never carry one. This test walks
    //! every workspace `.rs` under `crates/` and `bins/` and fails if
    //! any line contains the marker's uppercase prefix. The needle is
    //! assembled by `concat!` so this file (and this comment, which
    //! deliberately spells the word in lowercase) never self-matches.
    use std::fs;
    use std::path::{Path, PathBuf};

    const MARKER_PREFIX: &str = concat!("MUTA", "TION");

    fn collect_rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return; // unreadable dir: the existence assertions below cover it
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if path.is_dir() {
                // `target` (build output) and VCS dirs can hold copies
                // of sources; only first-party checked sources count.
                if name == "target" || name.starts_with('.') {
                    continue;
                }
                collect_rust_files(&path, out);
            } else if name.ends_with(".rs") {
                out.push(path);
            }
        }
    }

    #[test]
    fn no_leftover_mutation_harness_markers_in_workspace_sources() {
        let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace = crate_dir
            .parent()
            .and_then(Path::parent)
            .expect("crates/<name> layout");
        let mut offenders: Vec<String> = Vec::new();
        let mut total = 0usize;
        for root in ["crates", "bins"] {
            let dir = workspace.join(root);
            assert!(dir.is_dir(), "expected workspace dir {dir:?}");
            let mut files = Vec::new();
            collect_rust_files(&dir, &mut files);
            assert!(!files.is_empty(), "no .rs files found under {dir:?}");
            for file in files {
                total += 1;
                let Ok(src) = fs::read_to_string(&file) else {
                    offenders.push(format!("{}: UNREADABLE", file.display()));
                    continue;
                };
                for (no, line) in src.lines().enumerate() {
                    if line.contains(MARKER_PREFIX) {
                        offenders.push(format!("{}:{}: {}", file.display(), no + 1, line.trim()));
                    }
                }
            }
        }
        assert!(total > 30, "guard sanity: only {total} files walked");
        assert!(
            offenders.is_empty(),
            "{}/{MARKER_PREFIX}-style marker(s) found in checked              sources — a mutation harness leftover must never be committed (issue #36 audit):
{}",
            offenders.len(),
            offenders.join("
")
        );
    }
}
