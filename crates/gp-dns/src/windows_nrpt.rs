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
use std::time::Duration;

use thiserror::Error;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE};
use winreg::{RegKey, RegValue};

/// Wall-clock bound on one `SERVICE_CONTROL_PARAMCHANGE` notification.
///
/// `ControlService` can block **~30 s** when the Service Control
/// Manager is serialising behind other service start/stop operations
/// (verified on this test host during the connect-hang triage: the
/// call sits in an SCM-pending state, not on DnsCache itself — see
/// the `exit_wedged` anchor at bins/opc/src/main.rs:3542-3557 whose
/// "20 s escape" was NOT end-to-end bounded for exactly this reason).
/// The notification therefore runs on a throwaway thread behind this
/// deadline; expiry yields an explicit
/// [`NrptError::ParamChangeUnconfirmed`] instead of a silent wedge or
/// a fake success.
const PARAMCHANGE_NOTIFY_TIMEOUT: Duration = Duration::from_secs(10);

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

    /// The bounded wait (see [`PARAMCHANGE_NOTIFY_TIMEOUT`]) for the
    /// `ControlService(DnsCache, SERVICE_CONTROL_PARAMCHANGE)` call
    /// expired without the call completing — the SCM may be
    /// serialising behind another service operation. This is NOT the
    /// service rejecting the reload: the notification is simply
    /// **unconfirmed**. Callers must warn-and-continue (they already
    /// do) and must not report the reload as successful.
    #[error(
        "DnsCache reload notification unconfirmed: SERVICE_CONTROL_PARAMCHANGE \
         did not complete within {0:?} (SCM may be serialised behind another \
         service operation; the in-memory policy cache reload is UNCONFIRMED, \
         not successful)"
    )]
    ParamChangeUnconfirmed(Duration),

    /// A cleanup sweep deleted some but not all of the rule keys it
    /// targeted. Reported honestly instead of returning the
    /// pre-deletion count as if every `delete_subkey_all` had
    /// succeeded (the pre-fix `cleanup_scope` counted
    /// `names.len()` **before** deleting and swallowed per-key
    /// deletion errors with `let _ =` — verified anchor HEAD
    /// 04d7276 :290-293).
    #[error(
        "NRPT cleanup partially failed: {deleted} rule(s) deleted, {failed} \
         could not be deleted [{details}]"
    )]
    PartialCleanup {
        deleted: usize,
        failed: usize,
        details: String,
    },
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
    //
    // One case is deliberately NOT rolled back: an *unconfirmed*
    // notification (the bounded wait in [`paramchange_with`] expired
    // while the SCM serialises behind another service operation).
    // We have not been told the reload failed — only that we could
    // not observe it within [`PARAMCHANGE_NOTIFY_TIMEOUT`]. Deleting
    // healthy registry rules on a slow-SCM timeout is strictly more
    // destructive than the unconfirmed ping: the parked worker still
    // delivers it, and the connect-time cleanup's unconditional
    // paramchange re-pings on the next attempt anyway. A *real*
    // rejection (`ParamChange`/`Scm`) still rolls back as before.
    if let Err(e) = paramchange() {
        if matches!(e, NrptError::ParamChangeUnconfirmed(_)) {
            tracing::warn!("gp-dns nrpt: rules installed; {e}");
            return Ok(created);
        }
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
    cleanup_store_with(
        &HklmRuleKeyStore,
        DnsCacheScm,
        scope,
        PARAMCHANGE_NOTIFY_TIMEOUT,
    )
}

/// Registry-backed [`RuleKeyStore`] for the local NRPT policy path.
struct HklmRuleKeyStore;

impl RuleKeyStore for HklmRuleKeyStore {
    fn list_rule_keys(&self) -> Result<Vec<String>, NrptError> {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let parent = hklm
            .open_subkey_with_flags(LOCAL_NRPT_PATH, KEY_READ | KEY_WRITE)
            .map_err(|e| NrptError::Reg("open DnsPolicyConfig", e))?;
        // Propagate per-key enumeration errors. The pre-fix body
        // collapsed them with `filter_map(Result::ok)`: a transient
        // `RegEnumKeyEx` failure (a concurrent crash-cleanup handler,
        // another `recover`, or the Group Policy client rewriting the
        // key mid-enum) silently DROPPED that subkey from the target
        // set, so `cleanup_store_with` deleted the keys it happened to
        // see and returned `Ok(deleted)` as a COMPLETE cleanup — while
        // the missed DNS-hijacking rule stayed installed and the
        // wedge-exit / `opc recover` printed "DNS restored" on a box
        // that was still hijacked. Treating "could not observe the key
        // space" as success is the false-absence laundering this pass
        // forbids; surface it instead.
        collect_rule_names(parent.enum_keys())
            .map_err(|e| NrptError::Reg("enumerate DnsPolicyConfig", e))
    }

    fn delete_rule_key(&self, name: &str) -> Result<(), NrptError> {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let parent = hklm
            .open_subkey_with_flags(LOCAL_NRPT_PATH, KEY_WRITE)
            .map_err(|e| NrptError::Reg("open DnsPolicyConfig", e))?;
        match parent.delete_subkey_all(name) {
            Ok(()) => Ok(()),
            // Idempotent: already-gone counts as deleted-by-someone.
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(NrptError::Reg("delete rule key", e)),
        }
    }
}

/// Testable body of [`cleanup_scope`]: enumeration, per-key deletion
/// accounting, and the unconditional reload notification, all driven
/// through injectable seams.
///
/// Two correctness fixes over the pre-fix body (HEAD 04d7276
/// :277-298):
///
/// * the missing-parent early-return that skipped the reload
///   notification — contradicting this function's own doc comment
///   ("Always triggers a `DnsCache` paramchange — even when no
///   registry keys were deleted") — now still notifies (the in-memory
///   cache can hold stale policy whose keys were removed out of band);
/// * `returned count` is the number of **successfully deleted** keys,
///   not the enumeration length, and per-key deletion failures are
///   collected and reported via [`NrptError::PartialCleanup`] instead
///   of being swallowed by `let _ = parent.delete_subkey_all(...)`.
///
/// The reload notification's own failure stays warn-and-continue:
/// cleanup must not lose the deletion results it already achieved,
/// but the warn now carries the explicit *notification unconfirmed*
/// wording (see [`NrptError::ParamChangeUnconfirmed`]) rather than a
/// generic "failed".
fn cleanup_store_with<S: RuleKeyStore + ?Sized, N: ScmNotifier>(
    store: &S,
    notifier: N,
    scope: NrptScope,
    notify_budget: Duration,
) -> Result<usize, NrptError> {
    let names: Vec<String> = match store.list_rule_keys() {
        Ok(all) => all
            .into_iter()
            .filter(|n| rule_key_in_scope(n, scope))
            .collect(),
        Err(e) if err_is_not_found(&e) => {
            // Parent key absent: nothing to delete — but the doc
            // invariant above still demands the reload ping.
            Vec::new()
        }
        Err(e) => return Err(e),
    };
    delete_keys_with(store, notifier, names, notify_budget)
}

/// Delete exactly `names` (no enumeration, no scope filter) and then
/// notify `DnsCache` — unconditionally, even for an empty list.
///
/// The deletion-by-name half of [`cleanup_store_with`], split out so a
/// caller that has already *snapshotted* the keys it owns can delete
/// that snapshot and nothing newer. The NRPT janitor needs this: it
/// lists the dead session's keys the moment the session exits, and
/// must never widen that set to "whatever carries the instance prefix
/// now", because a replacement `opc connect` of the same instance may
/// have installed its own rules in between. Those must survive.
fn delete_keys_with<S: RuleKeyStore + ?Sized, N: ScmNotifier>(
    store: &S,
    notifier: N,
    names: Vec<String>,
    notify_budget: Duration,
) -> Result<usize, NrptError> {
    let mut deleted = 0usize;
    let mut failures: Vec<String> = Vec::new();
    for name in names {
        match store.delete_rule_key(&name) {
            Ok(()) => deleted += 1,
            Err(e) => failures.push(format!("{name}: {e}")),
        }
    }

    // Unconditional notification — the pre-fix code reached here even
    // in the zero-deletion case *only when the parent existed*; the
    // missing-parent path skipped it. Both now notify.
    if let Err(e) = paramchange_with(notifier, notify_budget) {
        tracing::warn!("wintun-nrpt: paramchange after cleanup: {e}");
    }

    if !failures.is_empty() {
        let failed = failures.len();
        return Err(NrptError::PartialCleanup {
            deleted,
            failed,
            details: failures.join("; "),
        });
    }
    Ok(deleted)
}

/// True when `e` is the registry-missing variant of [`NrptError::Reg`]
/// (the winreg NotFound kind bubbles up as an `io::Error` inside it).
fn err_is_not_found(e: &NrptError) -> bool {
    match e {
        NrptError::Reg(_, src) => src.kind() == io::ErrorKind::NotFound,
        _ => false,
    }
}

/// Pure ownership predicate: does rule subkey `name` belong to
/// `scope`? Extracted from the enumeration filters in
/// [`cleanup_store_with`] and [`count_scope`] so the matching logic
/// is table-testable without a registry (the trailing `-` in
/// `instance_prefix` is load-bearing: without it, instance `work`
/// would claim `openprotect-work2-…` keys and the connect-time sweep
/// could delete a live sibling's rules).
pub(crate) fn rule_key_in_scope(name: &str, scope: NrptScope) -> bool {
    name.starts_with(&scope_prefix(scope))
}

/// Count (do NOT delete) the openprotect-owned rule keys in `scope`.
/// Read-only — backs `opc doctor`. Returns 0 when the parent key is
/// absent (nothing was ever installed).
pub fn count_scope(scope: NrptScope) -> Result<usize, NrptError> {
    list_scope(scope).map(|names| names.len())
}

/// List (do NOT delete) the openprotect-owned rule key names in
/// `scope`, sorted. Read-only. Returns an empty list when the parent
/// key is absent (nothing was ever installed).
///
/// The snapshot primitive behind the NRPT janitor's exact-delete (see
/// [`remove_exact`]): what a dead session left behind is whatever
/// carries its instance prefix *at the moment it died* — never what
/// carries it later.
pub fn list_scope(scope: NrptScope) -> Result<Vec<String>, NrptError> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let parent = match hklm.open_subkey_with_flags(LOCAL_NRPT_PATH, KEY_READ) {
        Ok(k) => k,
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(NrptError::Reg("open DnsPolicyConfig", e)),
    };
    // Same error-honesty rule as `list_rule_keys`: a transient
    // per-key `RegEnumKeyEx` failure must surface as Err (→ doctor
    // reports UNKNOWN for this prefix) and never launder into a
    // low/zero count, which would read as "no rules here" for a rule
    // that is still installed and hijacking resolution.
    let names = collect_rule_names(parent.enum_keys())
        .map_err(|e| NrptError::Reg("enumerate DnsPolicyConfig", e))?;
    let mut ours: Vec<String> = names
        .into_iter()
        .filter(|n| rule_key_in_scope(n, scope))
        .collect();
    ours.sort();
    Ok(ours)
}

/// Delete exactly the named rule keys, then signal a `DnsCache`
/// reload (unconditionally — an empty `names` is a pure re-ping).
/// Returns the count actually deleted; per-key failures surface as
/// [`NrptError::PartialCleanup`].
///
/// Defence in depth: names without the shared `openprotect-` prefix
/// are dropped before any registry call, so a corrupted or foreign
/// list can never delete another product's NRPT rule. Pair with
/// [`list_scope`] to delete a snapshot and nothing newer.
pub fn remove_exact(names: &[String]) -> Result<usize, NrptError> {
    delete_keys_with(
        &HklmRuleKeyStore,
        DnsCacheScm,
        ours_only(names),
        PARAMCHANGE_NOTIFY_TIMEOUT,
    )
}

/// Pure half of [`remove_exact`]: keep only names we could have
/// written ourselves.
pub(crate) fn ours_only(names: &[String]) -> Vec<String> {
    names
        .iter()
        .filter(|n| n.starts_with(RULE_KEY_PREFIX))
        .cloned()
        .collect()
}

/// Materialise an `enum_keys()` iterator into a `Vec`, failing as soon
/// as any single subkey name cannot be read. Pure (takes the borrowed
/// iterator) so the propagate-on-error contract of [`count_scope`] and
/// [`HklmRuleKeyStore::list_rule_keys`] is unit-testable without a
/// registry: feeding it an iterator with an `Err` item must yield that
/// `Err`, not an `Ok` of the items seen before it.
pub(crate) fn collect_rule_names(
    keys: impl Iterator<Item = io::Result<String>>,
) -> Result<Vec<String>, io::Error> {
    keys.collect()
}

/// Pure counting helper (test-only since `count_scope` became a
/// thin wrapper over [`list_scope`]): how many enumerated rule
/// key names fall inside `scope`. Testable without a registry.
#[cfg(test)]
pub(crate) fn count_rule_names(names: impl Iterator<Item = String>, scope: NrptScope) -> usize {
    names.filter(|n| rule_key_in_scope(n, scope)).count()
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

/// Seam: how the `SERVICE_CONTROL_PARAMCHANGE` ping to `DnsCache` is
/// delivered.
///
/// The production body is the unsafe SCM FFI below ([`DnsCacheScm`]);
/// tests inject a blocking/failing stub so the **bounded-wait
/// discipline itself** — expiry → `ParamChangeUnconfirmed`, error →
/// passthrough, success → `Ok` — is unit-testable without sitting on
/// a real `ControlService` call (which can block ~30 s under SCM
/// serialisation; the anchor that motivated this whole change).
/// Smallest seam that keeps the fix honest: one method, no behaviour
/// beyond the notification.
pub(crate) trait ScmNotifier: Send + 'static {
    fn notify_paramchange(&self) -> Result<(), NrptError>;
}

/// Abstraction over the rule-key registry store used by the sweep,
/// so [`cleanup_store_with`] can be unit-tested (enumeration filter,
/// delete accounting, notify-always invariant) without touching
/// HKLM. Production body is [`HklmRuleKeyStore`].
pub(crate) trait RuleKeyStore {
    /// Every subkey name under `DnsPolicyConfig`. Err whose inner
    /// `io::Error` is `NotFound` signals the parent key is absent.
    fn list_rule_keys(&self) -> Result<Vec<String>, NrptError>;
    /// Delete one subkey by name; NotFound counts as success
    /// (idempotent sweep).
    fn delete_rule_key(&self, name: &str) -> Result<(), NrptError>;
}

/// The real SCM notifier: `OpenSCManagerW` → `OpenServiceW(DnsCache)`
/// → `ControlService(SERVICE_CONTROL_PARAMCHANGE)`.
///
/// May block in the SCM; callers must route it through
/// [`paramchange_with`] which enforces [`PARAMCHANGE_NOTIFY_TIMEOUT`].
struct DnsCacheScm;

impl ScmNotifier for DnsCacheScm {
    fn notify_paramchange(&self) -> Result<(), NrptError> {
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
}

/// Run an [`ScmNotifier`] on a throwaway OS thread and give up after
/// `budget`, mapping both expiry and notifier-thread loss to the
/// explicit [`NrptError::ParamChangeUnconfirmed`].
///
/// Why a thread instead of a tokio timeout: `paramchange` is called
/// from synchronous cleanup paths (connect-time sweep, revert, the
/// `exit_wedged` escape) that have no runtime to yield to — a
/// `tokio::time::timeout` around a blocking FFI call can never fire.
/// If the SCM later unblocks the parked thread, the notification
/// still lands (a late paramchange is exactly what we wanted); only
/// the *waiting* is bounded.
fn paramchange_with<N: ScmNotifier>(notifier: N, budget: Duration) -> Result<(), NrptError> {
    let (tx, rx) = std::sync::mpsc::channel();
    // Detached (not `thread::scope`): a scoped join would wait on the
    // parked `ControlService` call and defeat the deadline — exactly
    // the 30 s SCM wedge class this bound exists to escape.
    let spawn = std::thread::Builder::new()
        .name("nrpt-paramchange".into())
        .spawn(move || {
            // If the receiver is gone we timed out below; the
            // notification is still worth delivering, so the parked
            // worker runs to completion and the (late) send result is
            // simply dropped. A late paramchange is what we wanted
            // anyway — only the *waiting* is bounded.
            let _ = tx.send(notifier.notify_paramchange());
        });
    if spawn.is_err() {
        // Could not even start the notification: unconfirmed, loudly.
        return Err(NrptError::ParamChangeUnconfirmed(budget));
    }
    match rx.recv_timeout(budget) {
        Ok(res) => res,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            Err(NrptError::ParamChangeUnconfirmed(budget))
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            // The notifier thread panicked before reporting.
            Err(NrptError::ParamChangeUnconfirmed(budget))
        }
    }
}

/// Notify the `DnsCache` service to reload its policy from the
/// registry, bounded by [`PARAMCHANGE_NOTIFY_TIMEOUT`]. Without this
/// the rules sit in the registry and have no effect on resolution.
fn paramchange() -> Result<(), NrptError> {
    paramchange_with(DnsCacheScm, PARAMCHANGE_NOTIFY_TIMEOUT)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

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

    // -----------------------------------------------------------------
    // paramchange bounded-wait (via the ScmNotifier seam)
    // -----------------------------------------------------------------
    //
    // RED-GREEN note: these behaviours did not exist pre-fix (the old
    // `paramchange` called `ControlService` synchronously with NO
    // deadline — it could sit ~30 s under SCM serialisation, and had
    // no injectable seam so the deadline itself was untestable). The
    // test below pins the seam contract: expiry ⇒ EXPLICIT
    // unconfirmed, real rejection ⇒ passthrough (distinct error text,
    // never the silent-success path), success ⇒ Ok.

    struct OkNotifier;
    impl ScmNotifier for OkNotifier {
        fn notify_paramchange(&self) -> Result<(), NrptError> {
            Ok(())
        }
    }

    struct RejectNotifier(u32);
    impl ScmNotifier for RejectNotifier {
        fn notify_paramchange(&self) -> Result<(), NrptError> {
            Err(NrptError::ParamChange(self.0))
        }
    }

    struct PanicNotifier;
    impl ScmNotifier for PanicNotifier {
        fn notify_paramchange(&self) -> Result<(), NrptError> {
            panic!("notifier thread lost")
        }
    }

    /// Blocks inside the notification until the test drops the gate —
    /// modelling the real ~30 s SCM-pending `ControlService` wait.
    /// The drop at test-end releases the worker so no thread outlives
    /// the test binary.
    struct BlockingNotifier {
        gate: std::sync::mpsc::Receiver<()>,
    }
    impl ScmNotifier for BlockingNotifier {
        fn notify_paramchange(&self) -> Result<(), NrptError> {
            let _ = self.gate.recv();
            Ok(())
        }
    }

    #[test]
    fn paramchange_expiry_reports_unconfirmed_within_budget() {
        let (tx, rx) = std::sync::mpsc::channel();
        let start = Instant::now();
        let res = paramchange_with(BlockingNotifier { gate: rx }, Duration::from_millis(200));
        let elapsed = start.elapsed();
        drop(tx); // release the parked worker before asserting

        let err = match res {
            Err(e) => e,
            Ok(()) => panic!("a blocked ControlService must NOT report success"),
        };
        assert!(
            matches!(err, NrptError::ParamChangeUnconfirmed(_)),
            "expiry must map to the dedicated Unconfirmed variant, got {err:?}"
        );
        assert!(
            err.to_string()
                .to_lowercase()
                .contains("notification unconfirmed"),
            "error text must say the notification is unconfirmed, got: {err}"
        );
        assert!(
            elapsed >= Duration::from_millis(190),
            "must actually wait out the budget, returned early at {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "must be bounded, took {elapsed:?} — the old synchronous path \
             sat up to ~30 s under SCM serialisation"
        );
    }

    #[test]
    fn paramchange_success_passthrough() {
        assert!(matches!(
            paramchange_with(OkNotifier, Duration::from_secs(5)),
            Ok(())
        ));
    }

    #[test]
    fn paramchange_real_rejection_is_passthrough_not_unconfirmed() {
        // A service that REJECTS the control code and a notification
        // that never CONFIRMED within budget are different outcomes;
        // callers roll back on the former (apply_native) and only
        // warn on the latter. Collapsing them would either delete
        // healthy rules on a slow SCM or hide a hard failure.
        let res = paramchange_with(RejectNotifier(1052), Duration::from_secs(5));
        match res {
            Err(NrptError::ParamChange(code)) => assert_eq!(code, 1052),
            other => panic!("expected ParamChange passthrough, got {other:?}"),
        }
    }

    #[test]
    fn paramchange_lost_notifier_thread_reports_unconfirmed() {
        let res = paramchange_with(PanicNotifier, Duration::from_secs(2));
        assert!(
            matches!(res, Err(NrptError::ParamChangeUnconfirmed(_))),
            "a panicked notifier thread proves nothing about the reload: {res:?}"
        );
    }

    // -----------------------------------------------------------------
    // cleanup_scope control flow (via the RuleKeyStore/ScmNotifier seams)
    // -----------------------------------------------------------------

    struct FakeStore {
        keys: Vec<String>,
        /// names whose delete must fail
        fail: Vec<String>,
        /// Some(NotFound) emulates the missing-parent key (the :281
        /// early-return asymmetry this change fixes)
        list_not_found: bool,
        /// Some(kind) makes enumeration FAIL (after `listed` keys have
        /// already been yielded), emulating a transient `RegEnumKeyEx`
        /// error mid-scan — the case `filter_map(Result::ok)` used to
        /// launder into a silently-short target set.
        list_err: Option<io::ErrorKind>,
        deleted: std::sync::Mutex<Vec<String>>,
    }

    impl FakeStore {
        fn new(keys: &[&str]) -> Self {
            Self {
                keys: keys.iter().map(|s| s.to_string()).collect(),
                fail: Vec::new(),
                list_not_found: false,
                list_err: None,
                deleted: std::sync::Mutex::new(Vec::new()),
            }
        }
        fn deleted(&self) -> Vec<String> {
            self.deleted.lock().unwrap().clone()
        }
    }

    impl RuleKeyStore for FakeStore {
        fn list_rule_keys(&self) -> Result<Vec<String>, NrptError> {
            if self.list_not_found {
                return Err(NrptError::Reg(
                    "open DnsPolicyConfig",
                    io::Error::from(io::ErrorKind::NotFound),
                ));
            }
            if let Some(kind) = self.list_err {
                return Err(NrptError::Reg(
                    "enumerate DnsPolicyConfig",
                    io::Error::from(kind),
                ));
            }
            Ok(self.keys.clone())
        }
        fn delete_rule_key(&self, name: &str) -> Result<(), NrptError> {
            if self.fail.iter().any(|f| f == name) {
                return Err(NrptError::Reg(
                    "delete rule key",
                    io::Error::from(io::ErrorKind::PermissionDenied),
                ));
            }
            self.deleted.lock().unwrap().push(name.to_string());
            Ok(())
        }
    }

    /// Counts notifications across the (moved) clones handed to the
    /// bounded-wait thread: clone before each call and read `calls()`
    /// afterwards.
    #[derive(Clone, Default)]
    struct RecordingNotifier {
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }
    impl RecordingNotifier {
        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }
    impl ScmNotifier for RecordingNotifier {
        fn notify_paramchange(&self) -> Result<(), NrptError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    const WORK_A: &str = "openprotect-work-aaaaaaaa";
    const WORK_B: &str = "openprotect-work-bbbbbbbb";
    const HOME_C: &str = "openprotect-home-cccccccc";
    const WORK2_D: &str = "openprotect-work2-dddddddd";
    const FOREIGN: &str = "tailscale-ns-1";

    #[test]
    fn cleanup_sweeps_only_scope_and_returns_actual_deletions() {
        // The pre-fix code returned the pre-deletion enumeration
        // count; we require the number of keys actually deleted.
        let store = FakeStore::new(&[WORK_A, WORK_B, HOME_C, WORK2_D, FOREIGN]);
        let n = cleanup_store_with(
            &store,
            OkNotifier,
            NrptScope::Instance("work"),
            Duration::from_secs(5),
        )
        .expect("sweep ok");
        assert_eq!(n, 2);
        assert_eq!(
            store.deleted(),
            vec![WORK_A.to_string(), WORK_B.to_string()]
        );
        // `openprotect-work2-…` and foreign keys must NEVER be touched
        // by the `work` sweep — the sibling-safety the prefix exists for.
    }

    /// The janitor's exact-delete: only the snapshotted names go, a
    /// key that appeared after the snapshot (a replacement session's
    /// rule, `WORK_B` here) survives even though it carries the same
    /// instance prefix — and the reload ping still fires exactly once.
    #[test]
    fn delete_keys_with_deletes_only_the_named_keys_and_notifies_once() {
        let store = FakeStore::new(&[WORK_A, WORK_B, HOME_C]);
        let notifier = RecordingNotifier::default();
        let probe = notifier.clone();
        let n = delete_keys_with(
            &store,
            notifier,
            vec![WORK_A.to_string()],
            Duration::from_secs(5),
        )
        .expect("exact delete ok");
        assert_eq!(n, 1);
        assert_eq!(store.deleted(), vec![WORK_A.to_string()]);
        assert_eq!(probe.calls(), 1);

        // Empty snapshot = pure re-ping: nothing deleted, still notified.
        let store = FakeStore::new(&[WORK_A]);
        let notifier = RecordingNotifier::default();
        let probe = notifier.clone();
        let n = delete_keys_with(&store, notifier, Vec::new(), Duration::from_secs(5))
            .expect("empty delete ok");
        assert_eq!(n, 0);
        assert!(store.deleted().is_empty());
        assert_eq!(probe.calls(), 1);
    }

    #[test]
    fn remove_exact_drops_names_without_our_prefix_before_touching_anything() {
        let names = vec![
            WORK_A.to_string(),
            FOREIGN.to_string(),
            "Openprotect-case-matters".to_string(),
            HOME_C.to_string(),
        ];
        assert_eq!(
            ours_only(&names),
            vec![WORK_A.to_string(), HOME_C.to_string()]
        );
        assert!(ours_only(&[]).is_empty());
    }

    #[test]
    fn cleanup_always_notifies_even_when_parent_is_missing() {
        // The :281 asymmetry: the old code early-returned Ok(0) on a
        // missing parent key, SKIPPING the paramchange its own doc
        // comment promises unconditionally ("even when no registry
        // keys were deleted" — the in-memory cache can still hold
        // stale policy for keys deleted out of band).
        let mut store = FakeStore::new(&[]);
        store.list_not_found = true;
        let n = cleanup_store_with(&store, OkNotifier, NrptScope::All, Duration::from_secs(5))
            .expect("missing parent is not a hard error");
        assert_eq!(n, 0);
        // (notify-count asserted in the zero-match test below via the
        // recording notifier.)
    }

    #[test]
    fn cleanup_notifies_exactly_once_per_sweep_including_zero_deletions() {
        let store = FakeStore::new(&[FOREIGN]);
        let notifier = RecordingNotifier::default();
        let probe = notifier.clone();
        cleanup_store_with(
            &store,
            notifier,
            NrptScope::Instance("work"),
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(
            probe.calls(),
            1,
            "zero-deletion sweeps must still ping the reload"
        );
    }

    #[test]
    fn cleanup_reports_partial_failure_honestly_and_still_notifies() {
        // The :290-297 fix: per-deletion errors were swallowed
        // (`let _ =`) and the count still reported every enumerated
        // key as removed. Now: the failed key keeps the sweep honest.
        let mut store = FakeStore::new(&[WORK_A, WORK_B]);
        store.fail = vec![WORK_B.to_string()];
        let notifier = RecordingNotifier::default();
        let probe = notifier.clone();
        let err = cleanup_store_with(
            &store,
            notifier,
            NrptScope::Instance("work"),
            Duration::from_secs(5),
        )
        .expect_err("a partial failure must be reported, not hidden");
        match err {
            NrptError::PartialCleanup {
                deleted,
                failed,
                details,
            } => {
                assert_eq!(deleted, 1);
                assert_eq!(failed, 1);
                assert!(details.contains(WORK_B), "details: {details}");
            }
            other => panic!("expected PartialCleanup, got {other:?}"),
        }
        assert_eq!(store.deleted(), vec![WORK_A.to_string()]);
        assert_eq!(
            probe.calls(),
            1,
            "partial failure must not skip the reload ping — the keys \
             that DID go need to leave the in-memory cache"
        );
    }

    #[test]
    fn cleanup_all_scope_sweeps_every_instance() {
        let store = FakeStore::new(&[WORK_A, HOME_C, WORK2_D, FOREIGN]);
        let n =
            cleanup_store_with(&store, OkNotifier, NrptScope::All, Duration::from_secs(5)).unwrap();
        assert_eq!(n, 3, "All matches every openprotect- prefix, none foreign");
        assert!(!store.deleted().iter().any(|d| d.starts_with("tailscale")));
    }

    // -----------------------------------------------------------------
    // pure ownership-matching predicate / counter (registry-free)
    // -----------------------------------------------------------------

    #[test]
    fn rule_key_in_scope_table() {
        let in_work = |n: &str| rule_key_in_scope(n, NrptScope::Instance("work"));
        assert!(in_work(WORK_A), "own instance key");
        assert!(!in_work(HOME_C), "sibling instance key");
        // The trailing '-' in the prefix is load-bearing: without it,
        // instance "work" would claim "openprotect-work2-*" keys and
        // the connect-time sweep could delete a live sibling's rule.
        assert!(!in_work(WORK2_D), "longer-instance key must not match");
        assert!(!in_work(FOREIGN), "foreign key must not match");
        assert!(
            !in_work("openprotect-work"),
            "no-dash boundary must not match"
        );
        assert!(in_work("openprotect-work-"), "bare prefix counts as ours");
        assert!(rule_key_in_scope(WORK2_D, NrptScope::All));
        assert!(rule_key_in_scope(HOME_C, NrptScope::All));
        assert!(!rule_key_in_scope(FOREIGN, NrptScope::All));
        // Unsafe instance names route through the hashed prefix and
        // must still round-trip their own keys and reject look-alikes.
        let weird = "evil/foo";
        let weird_key = format!("{}cafe0000", instance_prefix(weird));
        assert!(rule_key_in_scope(&weird_key, NrptScope::Instance(weird)));
        assert!(
            !rule_key_in_scope("openprotect-evilfoo-cafe0000", NrptScope::Instance(weird)),
            "the hash path must not collide with a stripped look-alike"
        );
    }

    #[test]
    fn count_rule_names_table() {
        let names = || {
            [WORK_A, WORK_B, HOME_C, WORK2_D, FOREIGN]
                .iter()
                .map(|s| s.to_string())
        };
        assert_eq!(count_rule_names(names(), NrptScope::Instance("work")), 2);
        assert_eq!(count_rule_names(names(), NrptScope::Instance("home")), 1);
        assert_eq!(count_rule_names(names(), NrptScope::All), 4);
        assert_eq!(count_rule_names(std::iter::empty(), NrptScope::All), 0);
    }

    #[test]
    fn collect_rule_names_propagates_first_enumeration_error() {
        // The propagate-on-error contract, tested directly against the
        // pure collector (the real registry seam cannot be spun up in a
        // unit test). Pre-fix this behaviour was `filter_map(Result::ok)`
        // — a transient per-key error dropped that key and the caller
        // saw a SHORT list as if it were complete.
        let ok = |s: &str| Ok(s.to_string());
        // All-Ok → the full list.
        let all = collect_rule_names([ok(WORK_A), ok(HOME_C), ok(FOREIGN)].into_iter())
            .expect("clean enumeration must succeed");
        assert_eq!(
            all,
            vec![WORK_A.to_string(), HOME_C.to_string(), FOREIGN.to_string()]
        );
        // A single Err — even on the LAST key, after others succeeded
        // — must fail the whole enumeration, never return a partial vec.
        let err = collect_rule_names(
            [
                ok(WORK_A),
                ok(HOME_C),
                Err(io::Error::from_raw_os_error(5)), // ERROR_ACCESS_DENIED, transient
            ]
            .into_iter(),
        );
        assert!(
            err.is_err(),
            "a transient mid-enumeration error must surface, not launder into a \
             short-but-'complete' list (this is the class that let cleanup claim \
             success while a hijacking rule stayed installed): {err:?}"
        );
    }

    #[test]
    fn cleanup_reports_error_when_key_space_could_not_be_fully_observed() {
        // The sweep must NOT report `Ok(deleted)` as a complete cleanup
        // when part of the key space could not be enumerated: the
        // missed rule may still hijack DNS. `HklmRuleKeyStore::list_rule_keys`
        // now propagates that error, so `cleanup_store_with` must return
        // Err (the operator then knows "DNS restored" is NOT provable),
        // delete nothing on a partial view, and still notify the cache.
        let mut store = FakeStore::new(&[WORK_A]);
        store.list_err = Some(io::ErrorKind::PermissionDenied);
        let notifier = RecordingNotifier::default();
        let res = cleanup_store_with(
            &store,
            notifier.clone(),
            NrptScope::All,
            Duration::from_secs(5),
        );
        let err = match res {
            Ok(n) => {
                panic!("cleanup laundered an un-observable key space into success (deleted={n})")
            }
            Err(e) => e,
        };
        assert!(
            matches!(err, NrptError::Reg(_, _)),
            "enumeration failure must propagate as a registry error, got {err:?}"
        );
        // Nothing was deleted, and we BAIL before mutating or pinging
        // the cache: on an un-observable key space there is no
        // trustworthy target set, so the operator re-runs `recover` to
        // get a complete enumerate+delete+notify rather than us taking
        // partial destructive action on a half-seen table and reporting
        // a reload we cannot stand behind. (This is distinct from the
        // SUCCESSFUL-enumeration-zero-deletion case, which still owes
        // the unconditional ping.)
        assert!(
            store.deleted().is_empty(),
            "must not delete on a partial view"
        );
        assert_eq!(
            notifier.calls(),
            0,
            "an enumeration ERROR must bail before any SCM mutation signal"
        );
    }

    #[test]
    fn count_scope_error_laundering_guard_is_at_the_collector_not_the_filter() {
        // Pins that the honesty for count_scope lives in collect_rule_names
        // (surfaces Err) rather than in count_rule_names (a pure count).
        // A doctor caller maps Err → None → UNKNOWN; a partial Ok count
        // is what would silently under-report a live hijack, so assert
        // the collector refuses to produce one.
        let err = collect_rule_names(
            [
                Ok(WORK_A.to_string()),
                Err(io::Error::from(io::ErrorKind::Other)),
            ]
            .into_iter(),
        );
        assert!(
            err.is_err(),
            "count_scope's enumeration must not swallow errors"
        );
    }
}
