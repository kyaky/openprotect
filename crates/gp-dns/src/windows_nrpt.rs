//! Native Windows NRPT (Name Resolution Policy Table) backend.
//!
//! Bypasses the `DnsClient` PowerShell module entirely. Every
//! `Add-DnsClientNrptRule` / `Get-DnsClientNrptRule` /
//! `Remove-DnsClientNrptRule` call cold-starts a fresh
//! `powershell.exe` plus the `DnsClient` PSModule — 5-15 s each on
//! a quiet box, much worse with EDR scanning. We've seen real
//! `opc connect` runs sit at "applying 2 nameserver(s)" for 8+
//! minutes while PS spun up, occasionally wedging in a kernel-mode
//! wait that `taskkill /F /T` could not interrupt.
//!
//! The fix is what Tailscale does on Windows: write directly to
//! `HKLM\SYSTEM\CurrentControlSet\Services\DnsCache\Parameters\DnsPolicyConfig`,
//! then signal `SERVICE_CONTROL_PARAMCHANGE` to the `DnsCache`
//! service so it reloads. A two-IP rule applies in under 50 ms
//! and is immune to the EDR cold-start tax.
//!
//! ## Schema (per MS-GPNRPT)
//!
//! Each rule is a subkey containing:
//!
//! | Value               | Type           | Content                              |
//! |---------------------|----------------|--------------------------------------|
//! | `Version`           | `REG_DWORD`    | `1`                                  |
//! | `Name`              | `REG_MULTI_SZ` | namespace(s), e.g. `.example.com`    |
//! | `GenericDNSServers` | `REG_SZ`       | `"10.0.0.1;10.0.0.2"` (semi-colon)   |
//! | `ConfigOptions`     | `REG_DWORD`    | `0x8` — enable generic DNS server    |
//!
//! ## Group Policy interaction
//!
//! If `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`
//! has any subkeys, GP NRPT entries override every local rule and
//! our work is silently ignored. We detect that case and fail loudly
//! so the user knows their split DNS isn't going to take effect —
//! better than a silent miss.
//!
//! ## Key naming
//!
//! Rule subkeys are named `openprotect-<instance>-<random hex>`,
//! where `<instance>` is the opc `--instance` flag (default
//! `"default"`). The shared `openprotect-` prefix lets a future
//! blanket recovery tool find any of our rules; the per-instance
//! segment makes cleanup safe to run while a sibling `opc -i other`
//! is still alive — its rules are owned by a different prefix.
//! The trailing random hex keeps two rules of the same instance
//! from colliding when one connect installs multiple namespaces.

use std::ffi::OsString;
use std::io;
use std::net::IpAddr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

use thiserror::Error;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE};
use winreg::{RegKey, RegValue};

/// Local-policy NRPT path. This is where `Add-DnsClientNrptRule`
/// writes when no GP rules are in force.
const LOCAL_NRPT_PATH: &str =
    r"SYSTEM\CurrentControlSet\Services\DnsCache\Parameters\DnsPolicyConfig";

/// Group Policy NRPT path. If it contains any subkeys, those rules
/// take priority over everything in `LOCAL_NRPT_PATH`.
const GP_NRPT_PATH: &str = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig";

/// Common prefix on every rule key we own. The full key shape is
/// `openprotect-<instance>-<random hex>`. The shared `openprotect-`
/// prefix lets a future blanket recovery tool find our rules, but
/// per-instance cleanup must match the more specific
/// `openprotect-<instance>-` prefix so two `opc -i NAME` instances
/// running side-by-side never delete each other's live NRPT rules.
pub(crate) const RULE_KEY_PREFIX: &str = "openprotect-";

/// Build the per-instance prefix that scopes ownership of rule keys.
///
/// The instance name must contain only ASCII alphanumeric + `-` / `_`
/// so it can't smuggle a `\` into the registry subkey path (which
/// would be a path-traversal-style bug, even though HKLM registry
/// doesn't have filesystem traversal it still allows nested key
/// creation). Any other character makes the prefix include a hash
/// of the raw name rather than silently stripping the offending
/// characters — silent stripping would collide two distinct names
/// (`evil\foo` and `evilfoo` both becoming `openprotect-evilfoo-`)
/// and the recovery sweep could then delete the wrong instance's
/// live rules.
///
/// Empty / fully-stripped input falls back to `default-`. opc's CLI
/// already validates `--instance` upstream to the allowed character
/// set so this code path stays cold in practice; the hash fallback
/// is defence-in-depth for any future caller that hasn't validated.
fn instance_prefix(instance: &str) -> String {
    let safe = instance
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if instance.is_empty() {
        return format!("{RULE_KEY_PREFIX}default-");
    }
    if safe {
        return format!("{RULE_KEY_PREFIX}{instance}-");
    }
    // Unsanitised name — derive a stable 16-hex-char tag that's
    // unique per raw input, so two distinct callers never collide.
    // FNV-1a is overkill-proof here; collision probability for the
    // handful of instance names a single host will ever see is
    // effectively zero. We deliberately avoid `std::hash::Hasher`
    // because its default DefaultHasher is not stable across Rust
    // versions and we need deterministic prefixes for cleanup.
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in instance.as_bytes() {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{RULE_KEY_PREFIX}h{hash:016x}-")
}

/// Which openprotect-owned NRPT rules a sweep / enumeration targets.
///
/// `Instance` is the safe default used by connect-time recovery and
/// `opc recover` (no flag): it only ever touches rules whose key
/// matches `openprotect-<instance>-`, so a sibling `opc -i other`
/// process's live rules are never disturbed.
///
/// `All` is the blanket recovery hammer behind `opc recover --all`:
/// it matches the shared `openprotect-` prefix across every instance.
/// Callers MUST gate it on "no other opc is alive" — see the doc on
/// `cleanup_scope`.
#[derive(Debug, Clone, Copy)]
pub enum NrptScope<'a> {
    /// Only rules owned by this opc instance name.
    Instance(&'a str),
    /// Every openprotect-owned rule, regardless of instance.
    All,
}

/// The registry-subkey-name prefix that selects the rules in `scope`.
fn scope_prefix(scope: NrptScope) -> String {
    match scope {
        NrptScope::Instance(instance) => instance_prefix(instance),
        NrptScope::All => RULE_KEY_PREFIX.to_string(),
    }
}

/// `ConfigOptions` bitmask: enable the `GenericDNSServers` field.
/// Other bits (DNSSEC, DirectAccess, IDN, proxy) stay off.
const CONFIG_OPTIONS_GENERIC_DNS: u32 = 0x8;

#[derive(Debug, Error)]
pub enum NrptError {
    #[error("registry I/O: {0}: {1}")]
    Reg(&'static str, #[source] io::Error),

    #[error("Group Policy NRPT rules are active — they override local NRPT and our split DNS would be silently ignored. Ask your IT admin to clear the GPO at {0}, or run opc without --dns-zone.")]
    GpoConflict(&'static str),

    #[error("Service Control Manager: {0}: {1}")]
    Scm(&'static str, #[source] io::Error),

    #[error("DnsCache service rejected SERVICE_CONTROL_PARAMCHANGE: GetLastError = {0}")]
    ParamChange(u32),
}

/// One NRPT rule to install.
#[derive(Debug, Clone)]
pub struct NrptRule {
    /// Single namespace this rule applies to. NRPT supports multiple
    /// namespaces per rule (via `REG_MULTI_SZ`); we keep it 1-per-rule
    /// for simpler cleanup and because UNSW-style configs typically
    /// have very few distinct zones.
    pub namespace: String,
    /// Servers to send queries for `namespace` to. Order is preserved.
    pub servers: Vec<IpAddr>,
}

/// Result of `apply_native` — the registry key names we created. Hand
/// these to `remove_native` on disconnect.
#[derive(Debug, Default)]
pub struct AppliedRules {
    pub rule_key_names: Vec<String>,
}

/// Install one registry rule per `NrptRule` and signal `DnsCache` to
/// reload. Returns the key names so revert can delete by exact match.
///
/// `instance` scopes the rule key names — see [`instance_prefix`].
/// Pass the same string to [`cleanup_stale_native`] on shutdown /
/// pre-connect recovery so a sibling `opc -i other` instance's
/// rules are never touched.
pub fn apply_native(instance: &str, rules: &[NrptRule]) -> Result<AppliedRules, NrptError> {
    check_gp_clear()?;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let (parent, _disp) = hklm
        .create_subkey(LOCAL_NRPT_PATH)
        .map_err(|e| NrptError::Reg("open DnsPolicyConfig", e))?;

    let prefix = instance_prefix(instance);
    let mut created = AppliedRules::default();

    for rule in rules {
        let key_name = generate_rule_key_name(&prefix);
        if let Err(e) = write_rule(&parent, &key_name, rule) {
            // Roll back rules we already created so a partial install
            // doesn't pollute the registry on error.
            for existing in &created.rule_key_names {
                let _ = parent.delete_subkey_all(existing);
            }
            return Err(e);
        }
        created.rule_key_names.push(key_name);
    }

    // If the SCM reload fails, the freshly-written rules sit in the
    // registry but `DnsCache` doesn't know about them — and we never
    // returned `AppliedRules` to the caller, so the revert path can't
    // clean them up either. Roll back here so we don't leak rules
    // that have no live owner.
    if let Err(e) = paramchange() {
        for existing in &created.rule_key_names {
            let _ = parent.delete_subkey_all(existing);
        }
        return Err(e);
    }
    Ok(created)
}

/// Remove a single rule key by exact name. Idempotent — missing keys
/// are not an error (a previous revert may have already cleaned it).
pub fn remove_native(key_name: &str) -> Result<(), NrptError> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let parent = match hklm.open_subkey_with_flags(LOCAL_NRPT_PATH, KEY_WRITE) {
        Ok(k) => k,
        // Missing parent is fine — there's nothing to clean.
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(NrptError::Reg("open DnsPolicyConfig", e)),
    };
    match parent.delete_subkey_all(key_name) {
        Ok(()) => Ok(()),
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(NrptError::Reg("delete rule key", e)),
    }
}

/// Sweep every rule key owned by the named `instance`. Returns the
/// count removed. Used on connect-time recovery (crash from a
/// previous run of THIS instance) and as a belt-and-suspenders
/// revert step. Pass the same `instance` you passed to
/// [`apply_native`] — anything else would silently delete the
/// rules of a sibling `opc -i other` process that's still alive.
///
/// Always triggers a `DnsCache` paramchange — even when no
/// registry keys were deleted. A clean previous `revert_with` may
/// have already removed our keys from the registry but left the
/// `DnsCache` in-memory cache pointing at them; without an
/// unconditional paramchange here, the cache continues hijacking
/// DNS for our namespaces and the next portal prelogin would
/// deadlock trying to resolve through an unreachable internal
/// resolver. paramchange against an empty rule set is cheap.
pub fn cleanup_stale_native(instance: &str) -> Result<usize, NrptError> {
    cleanup_scope(NrptScope::Instance(instance))
}

/// Sweep every openprotect-owned rule key in `scope`, then signal a
/// `DnsCache` reload. Returns the count removed. `cleanup_stale_native`
/// is the `Instance` special-case; `opc recover --all` uses `All`.
///
/// SAFETY (caller's responsibility): `NrptScope::All` matches the
/// rules of EVERY instance, including a sibling `opc -i other` that
/// is still alive. Callers must only pass `All` once they've
/// confirmed no other opc session is running, or they'll tear down a
/// live sibling's split DNS. `Instance` is always safe.
///
/// Always triggers a `DnsCache` paramchange — even when no registry
/// keys were deleted — so a previous `revert` that cleared the keys
/// but left the in-memory cache pointing at them can't keep
/// hijacking DNS. paramchange against an empty rule set is cheap.
pub fn cleanup_scope(scope: NrptScope) -> Result<usize, NrptError> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let parent = match hklm.open_subkey_with_flags(LOCAL_NRPT_PATH, KEY_READ | KEY_WRITE) {
        Ok(k) => k,
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(NrptError::Reg("open DnsPolicyConfig", e)),
    };
    let prefix = scope_prefix(scope);
    let names: Vec<String> = parent
        .enum_keys()
        .filter_map(Result::ok)
        .filter(|n| n.starts_with(&prefix))
        .collect();
    let count = names.len();
    for name in names {
        let _ = parent.delete_subkey_all(&name);
    }
    if let Err(e) = paramchange() {
        tracing::warn!("wintun-nrpt: paramchange after cleanup failed: {e}");
    }
    Ok(count)
}

/// Count (do NOT delete) the openprotect-owned rule keys in `scope`.
/// Read-only — backs `opc doctor`. Returns 0 when the parent key is
/// absent (nothing was ever installed).
pub fn count_scope(scope: NrptScope) -> Result<usize, NrptError> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let parent = match hklm.open_subkey_with_flags(LOCAL_NRPT_PATH, KEY_READ) {
        Ok(k) => k,
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(NrptError::Reg("open DnsPolicyConfig", e)),
    };
    let prefix = scope_prefix(scope);
    let count = parent
        .enum_keys()
        .filter_map(Result::ok)
        .filter(|n| n.starts_with(&prefix))
        .count();
    Ok(count)
}

/// Verify the Group Policy NRPT path has no rules. If it does, the
/// local-policy rules we write are ignored by `DnsCache`. We fail
/// loudly rather than silently produce broken split DNS.
fn check_gp_clear() -> Result<(), NrptError> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let gp = match hklm.open_subkey_with_flags(GP_NRPT_PATH, KEY_READ) {
        Ok(k) => k,
        // GP path absent = no policy rules = good.
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(NrptError::Reg("open GP DnsPolicyConfig", e)),
    };
    let any_rule = gp.enum_keys().filter_map(Result::ok).next().is_some();
    if any_rule {
        Err(NrptError::GpoConflict(GP_NRPT_PATH))
    } else {
        // Key exists but has no subkeys. Some references say an
        // empty GP key can still suppress local NRPT rules — see
        // Tailscale's `wgengine/router/dns/nrpt_windows.go` which
        // deletes the empty key on detection. We're more
        // conservative: leave it alone (a future GPO update might
        // add rules and complaining now would be noisy), and
        // only fail loudly when subkeys actually exist.
        Ok(())
    }
}

/// Write the 4 registry values that make up one NRPT rule.
fn write_rule(parent: &RegKey, key_name: &str, rule: &NrptRule) -> Result<(), NrptError> {
    let (rule_key, _disp) = parent
        .create_subkey(key_name)
        .map_err(|e| NrptError::Reg("create rule subkey", e))?;

    // Version: REG_DWORD = 1 (current schema revision per MS-GPNRPT).
    rule_key
        .set_value("Version", &1u32)
        .map_err(|e| NrptError::Reg("write Version", e))?;

    // Name: REG_MULTI_SZ. winreg has no first-class REG_MULTI_SZ
    // helper, so we hand-encode: each string is UTF-16 LE NUL-
    // terminated, and the whole list is double-NUL-terminated.
    // winreg 0.56 changed RegValue::bytes from Vec<u8> to Cow<'_, [u8]>
    // so we can hand it a borrowed slice; we still own the Vec from
    // encode_multi_sz so an owned Cow is the simplest, copy-free choice.
    let name_value = RegValue {
        bytes: encode_multi_sz(&[rule.namespace.as_str()]).into(),
        vtype: winreg::enums::REG_MULTI_SZ,
    };
    rule_key
        .set_raw_value("Name", &name_value)
        .map_err(|e| NrptError::Reg("write Name", e))?;

    // GenericDNSServers: REG_SZ, semicolons separate multiple servers.
    let joined: String = rule
        .servers
        .iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(";");
    rule_key
        .set_value("GenericDNSServers", &joined)
        .map_err(|e| NrptError::Reg("write GenericDNSServers", e))?;

    // ConfigOptions: REG_DWORD, bit 0x8 = "use GenericDNSServers".
    rule_key
        .set_value("ConfigOptions", &CONFIG_OPTIONS_GENERIC_DNS)
        .map_err(|e| NrptError::Reg("write ConfigOptions", e))?;

    Ok(())
}

/// Build the raw bytes for a `REG_MULTI_SZ` value from a list of
/// strings: each string UTF-16 LE + NUL, list double-NUL terminated.
pub(crate) fn encode_multi_sz(strings: &[&str]) -> Vec<u8> {
    let mut buf = Vec::<u8>::with_capacity(64);
    for s in strings {
        for u in OsString::from(*s).encode_wide() {
            buf.extend_from_slice(&u.to_le_bytes());
        }
        buf.extend_from_slice(&[0, 0]); // end-of-string NUL
    }
    // Final empty string = double-NUL terminator. If the list is
    // empty we still need a terminator so the value parses.
    buf.extend_from_slice(&[0, 0]);
    buf
}

/// Generate a unique subkey name with the given per-instance prefix.
/// 8 hex chars from the OS PRNG is enough to avoid collisions between
/// a handful of concurrent rules per machine.
fn generate_rule_key_name(instance_prefix: &str) -> String {
    let mut buf = [0u8; 8];
    if winreg_random_bytes(&mut buf).is_err() {
        // Fall back to a process-id-mixed timestamp so we never
        // return a static name even when the OS RNG misbehaves.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let pid = std::process::id() as u64;
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = ((now ^ pid).wrapping_shr((i * 8) as u32) & 0xff) as u8;
        }
    }
    let mut s = String::with_capacity(instance_prefix.len() + buf.len() * 2);
    s.push_str(instance_prefix);
    for b in buf {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Best-effort wrapper around `BCryptGenRandom`. Returns `Err` if the
/// OS RNG is unavailable (e.g. very old Windows) — the caller falls
/// back to a time/pid-mixed name.
fn winreg_random_bytes(buf: &mut [u8]) -> io::Result<()> {
    use windows_sys::Win32::Security::Cryptography::{
        BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    };
    let status = unsafe {
        BCryptGenRandom(
            ptr::null_mut(),
            buf.as_mut_ptr(),
            buf.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status as i32))
    }
}

/// Public façade so other callers in this crate (e.g. the revert
/// path in `lib.rs::flush_dns_cache`) can drive a reload without
/// going through `apply_native` / `cleanup_stale_native`.
pub fn paramchange_public() -> Result<(), NrptError> {
    paramchange()
}

/// Notify the `DnsCache` service to reload its policy from the
/// registry. Without this the rules sit in the registry and have no
/// effect on resolution.
fn paramchange() -> Result<(), NrptError> {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, SC_MANAGER_CONNECT,
        SERVICE_CONTROL_PARAMCHANGE, SERVICE_PAUSE_CONTINUE, SERVICE_STATUS,
    };

    let svc_name: Vec<u16> = "DnsCache\0".encode_utf16().collect();

    unsafe {
        let scm = OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT);
        if scm.is_null() {
            return Err(NrptError::Scm(
                "OpenSCManagerW",
                io::Error::from_raw_os_error(GetLastError() as i32),
            ));
        }
        let svc = OpenServiceW(scm, svc_name.as_ptr(), SERVICE_PAUSE_CONTINUE);
        if svc.is_null() {
            let err = GetLastError();
            CloseServiceHandle(scm);
            return Err(NrptError::Scm(
                "OpenServiceW(DnsCache)",
                io::Error::from_raw_os_error(err as i32),
            ));
        }
        let mut status: SERVICE_STATUS = std::mem::zeroed();
        let ok = ControlService(svc, SERVICE_CONTROL_PARAMCHANGE, &mut status);
        let err = if ok == 0 { GetLastError() } else { 0 };
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        if ok == 0 {
            return Err(NrptError::ParamChange(err));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_multi_sz_single_string_double_nul_terminated() {
        let bytes = encode_multi_sz(&[".example.com"]);
        // The string itself is 12 chars × 2 = 24 bytes,
        // plus 2 bytes NUL after the string,
        // plus 2 bytes final terminator = 28 bytes.
        assert_eq!(bytes.len(), 12 * 2 + 2 + 2);
        // Last 4 bytes must be \0\0\0\0 (string-terminating NUL + list terminator).
        assert_eq!(&bytes[bytes.len() - 4..], &[0, 0, 0, 0]);
    }

    #[test]
    fn encode_multi_sz_empty_list_is_just_terminator() {
        let bytes = encode_multi_sz(&[]);
        // No strings, only the final double-NUL terminator.
        assert_eq!(bytes, vec![0, 0]);
    }

    #[test]
    fn generate_rule_key_name_starts_with_prefix_and_is_unique() {
        let prefix = instance_prefix("default");
        let a = generate_rule_key_name(&prefix);
        let b = generate_rule_key_name(&prefix);
        assert!(a.starts_with(RULE_KEY_PREFIX));
        assert!(a.starts_with(&prefix));
        assert!(b.starts_with(&prefix));
        // prefix + 8 bytes × 2 hex chars.
        assert_eq!(a.len(), prefix.len() + 16);
        assert_ne!(a, b, "rule names should be random per call");
    }

    #[test]
    fn scope_prefix_all_matches_every_instances_key() {
        // The blanket "recover --all" scope must prefix-match a rule
        // key from ANY instance, so a leak left by `opc -i work` is
        // swept even when the user never names that instance again.
        let all = scope_prefix(NrptScope::All);
        assert_eq!(all, RULE_KEY_PREFIX);
        let work_key = generate_rule_key_name(&instance_prefix("work"));
        let home_key = generate_rule_key_name(&instance_prefix("home"));
        assert!(
            work_key.starts_with(&all),
            "work key {work_key} not matched by All"
        );
        assert!(
            home_key.starts_with(&all),
            "home key {home_key} not matched by All"
        );
    }

    #[test]
    fn scope_prefix_instance_isolates_siblings() {
        // The default instance-scoped scope must NOT match a sibling
        // instance's live rule — that's the safety the per-instance
        // prefix exists to provide.
        let work = scope_prefix(NrptScope::Instance("work"));
        assert_eq!(work, "openprotect-work-");
        let work_key = generate_rule_key_name(&instance_prefix("work"));
        let home_key = generate_rule_key_name(&instance_prefix("home"));
        assert!(work_key.starts_with(&work));
        assert!(!home_key.starts_with(&work));
    }

    #[test]
    fn instance_prefix_isolates_two_instances() {
        let work = instance_prefix("work");
        let home = instance_prefix("home");
        assert_ne!(work, home);
        // A rule key built for `work` must NOT start with `home`'s
        // prefix — otherwise `cleanup_stale_native("home")` would
        // delete the work instance's live rule.
        let work_key = generate_rule_key_name(&work);
        assert!(work_key.starts_with(&work));
        assert!(!work_key.starts_with(&home));
    }

    #[test]
    fn instance_prefix_sanitises_unsafe_chars() {
        // `\` would otherwise nest a registry subkey under our
        // parent, turning a rule key into a path. The illegal-char
        // path hashes the raw input, so the output stays inside our
        // own subkey space and never contains the offending bytes.
        let prefix = instance_prefix(r"evil\..\..\Software");
        assert!(!prefix.contains('\\'));
        assert!(!prefix.contains('.'));
        assert!(prefix.starts_with("openprotect-h"));
        // Empty input falls back to `default-`, but illegal-char
        // inputs go through the hash path — two distinct unsafe
        // names must NOT collide.
        assert_eq!(instance_prefix(""), "openprotect-default-");
        let only_slashes = instance_prefix("///");
        let only_dots = instance_prefix("...");
        assert!(only_slashes.starts_with("openprotect-h"));
        assert!(only_dots.starts_with("openprotect-h"));
        assert_ne!(
            only_slashes, only_dots,
            "distinct unsafe instance names must hash to distinct prefixes"
        );
    }

    #[test]
    fn instance_prefix_does_not_collide_after_stripping() {
        // Regression: the old filter-and-format implementation
        // collapsed `evil\foo` and `evilfoo` to the same prefix
        // because it silently stripped `\`. The hash path must
        // keep them distinct.
        let a = instance_prefix("evil\\foo");
        let b = instance_prefix("evilfoo");
        assert_ne!(a, b);
        assert!(a.starts_with("openprotect-h"));
        // `evilfoo` is all-safe so it goes through the plain path.
        assert_eq!(b, "openprotect-evilfoo-");
    }
}
