# Fix plan: macOS stale DNS state (leaked /etc/resolver files + networksetup fallback)

Source of the incident report: `/Users/kyaky/openprotect/dev-prompt-stale-resolver.md` (2026-10-30).
Verification: 5-agent adversarial review (393k tokens, 274 tool calls) plus first-hand live probes on this
machine. Target revision: `origin/main` = `a79ac7b` ("ci+opc(win): Windows CI gate, InstanceScan
completeness, one cancel/drain/join path (#60)").

## 1. Verdict on the report

The report is substantially correct. ~40 falsifiable claims checked: all core claims confirmed against the
code at both `d5e46b5` (what the local snapshot matched) and `origin/main`; 7 partial (citation-level
corrections only); 0 refuted. The causal chain was reproduced live on this machine:

- `/etc/resolver/unsw.edu.au` exists, born 2026-10-30 00:30:36, 70 bytes, byte-for-byte the output of
  `write_macos_resolver_files` for servers `[129.94.0.196, 129.94.0.197]` + search `ad.unsw.edu.au`
  (24+24+22 bytes).
- `scutil --dns` resolver #8 (domain `unsw.edu.au` -> 129.94.0.196/197) was ACTIVE at verification time.
- `dig @129.94.0.196` times out; default-path `dig` answers in 4 ms via 192.168.88.1;
  `dscacheutil` on the portal name hung >45 s then returned empty. `getaddrinfo` probe hung past 30 s.
- The file survived a reboot (born 00:30:36, boot ~19:42 same day).
- Binary-level: deployed `opc` contains 36 `/Users/runner` paths (GitHub CI release build) and exactly one
  `hickory` string, which is reqwest's own `cfg(not(feature = "hickory-dns"))` unreachable-message:
  hickory is OFF, so reqwest resolves via GaiResolver -> getaddrinfo, which the per-domain file hijacks.

Root defect (both revs): `write_macos_resolver_files` uses `create_new(true)`; on `AlreadyExists` it warns
and skips, never recording the domain in `AppliedDnsState.macos_resolver_domains`, so `revert` can never
remove a pre-existing file. An abnormal exit (SIGKILL, SIGHUP, panic, power loss) therefore strands the
file permanently: no macOS startup sweep exists (the Windows NRPT sweep + crash_cleanup are
`#[cfg(windows)]`), `opc recover` is a hard-coded Unix no-op, and `opc disconnect` only talks IPC to a
live session. On the next connect, prelogin (the first network call) must resolve the portal host, which
sits inside the hijacked zone, getaddrinfo wedges until the 15 s `connect_timeout` fires
("client error (Connect): operation timed out"). Every consumer of libsystem resolution (browsers, GUI
apps) is wedged for that zone too, not just opc.

## 2. Corrections to the report (none change the substance)

1. Source-tree premise: `/Users/kyaky/AIOPS/Playground/openprotect` was NOT a git worktree at `a79ac7b`
   with uncommitted Windows NRPT changes. It was a stale CRLF snapshot matching `d5e46b5` (2026-09-30)
   with zero content modifications (verified file-by-file). It has since been synced to `origin/main`.
   macOS-relevant code is identical between the two revs (line shift +25 in gp-dns).
2. reqwest declaration is at `Cargo.toml:86-94` at both revs, not `:64-76` (that range is the comment
   block). The report's `HEAD:86-94` was correct.
3. `grep -aci hickory` on the binary is 1, not 0: the hit is reqwest's own compiled-in panic string from
   the not-hickory branch, which is precisely the report's cited evidence. `hickory_resolver`,
   `hickory_proto`, `trust_dns` are all genuinely 0.
4. CLI enum has more variants than listed: `Status`, hidden `HipReport`, and (at HEAD) hidden
   `NrptJanitor`. Any code matching on `Commands` exhaustively must cover them. No macOS repair subcommand
   exists at either rev.
5. Flush recipe overstated: configd's IPMonitor logged `/etc/resolver changed` 0.7 s after the file
   appeared and pushed DNS configuration to XPC peers with NO HUP (system log evidence). `dscacheutil
   -flushcache` is documented as cache-only; SIGHUP is undocumented for mDNSResponder. Deletion-side
   pickup is the only unproven half. The plan keeps the existing best-effort flush helper and does not
   build on the HUP.
6. The dig/nslookup exclusion is documented in `dig(1)` and `nslookup(1)` ("macOS NOTICE"), not in
   `resolver(5)`, which attributes per-domain routing to the "Super" DNS client without naming
   getaddrinfo/mDNSResponder.
7. "dscacheutil 挂起超过 15s" understates it: >45 s observed here.
8. Report missed that non-Windows `opc doctor` is not a pure no-op (it still IPC-enumerates sessions;
   only the leak fields are hard-coded zeros), and that the macOS root check (`ensure_macos_connect_privileges`)
   is `cfg(target_os = "macos")`-only.
9. Report missed several facts that shape the fix (see section 3).

## 3. New findings that shape the fix

1. **Second macOS leak surface.** `apply_macos_networksetup` has a no-split-domains fallback that runs
   `networksetup -setdnsservers <active-service>` globally (origin `crates/gp-dns/src/lib.rs:728-746`),
   with prior values saved ONLY in in-memory `AppliedDnsState` (no serde/persistence anywhere; struct at
   origin `lib.rs:222-242`). A killed opc in that mode leaves the machine's global DNS pointed at dead VPN
   resolvers with no recovery path. `opc recover`'s Unix no-op comment ("the Unix DNS backends don't leak
   a machine-wide rule", origin `bins/opc/src/main.rs:2603-2605`) is false for this path.
2. **res_query bypasses /etc/resolver** (proven live with a C probe: `_res.nsaddr_list` contained exactly
   the `/etc/resolv.conf` trio, `res_query` answered in 0 s while `getaddrinfo` hung 30 s+). A bootstrap
   pin via libresolv is feasible. It can only use LAN/ISP upstreams, which suffices for the public portal
   name but can never reach VPN-internal split-DNS names.
3. **reqwest `connect_timeout` covers DNS resolution** (confirmed in reqwest 0.12.28 + hyper-util 0.1.20
   sources: the timeout wraps the whole connector call, HttpConnector resolves inside it). The observed
   error is the 15 s bound firing during resolution, not an infinite hang. The `spawn_blocking`
   getaddrinfo thread is not cancellable and keeps running after the timeout (orphaned lookup, harmless
   but real).
4. **A `.resolve()` pin does not bypass a configured proxy** (hostname is handed to the proxy). `system-proxy`
   is enabled and opc never opts out; `scutil --proxy` showed no proxies in this incident, so the DNS
   explanation stands, but the pin's interaction with proxies must be documented.
5. **configd reports `reach = Reachable` for the black-holed servers**, so any reachability-gated fallback
   in the fix must not trust SC reach flags.
6. **Windows sweep hardening at HEAD** must be mirrored: `InstanceScan::Incomplete` never licenses deletion
   (origin `main.rs:3059-3075`), and an `own_alive` guard never sweeps our own live instance
   (origin `main.rs:3289-3297`).
7. **Windows flush lesson**: the Windows sweep flushes unconditionally even when nothing was deleted; the
   macOS flush currently runs only on the split-DNS apply branch, and never on the networksetup fallback
   (apply or revert). Fix the coverage while touching this code.
8. `DnsConfig` already carries `instance` and `session_token` at HEAD (`main.rs:7271-7278`; token added by
   0442842 for Windows NRPT) - the macOS marker can reuse both with no new plumbing.
9. `#` comment tolerance inside `/etc/resolver` files is documented only by example in `resolver(5)`;
   opc's own test parser tolerates `#` but macOS's parser tolerance must be verified with a scratch-domain
   write test before the marker ships.

## 4. Fix milestones (each independently shippable)

### M1. Ownership marker + adopt semantics in gp-dns (fixes the orphan mechanism)

**Status: implemented (uncommitted at this revision).**

Rewrite `write_macos_resolver_files` (origin `crates/gp-dns/src/lib.rs:769-844`):

- Body becomes marker header + existing content:
  `# managed by openprotect (opc) v1`, `# instance <instance>`, `# session <session_token>`, then the
  existing `nameserver`/`search` lines. Both fields already arrive in `DnsConfig`; the instance/session
  values are validated as marker-safe (no newline, no leading `#`, instance non-empty) before use.
- Existing-file handling replaces `create_new`-or-warn:
  1. Marker present AND its instance matches `config.instance` -> adopt: rewrite atomically (temp file
     in `/etc/resolver` + `rename`, bytes fsynced before the rename) and record the domain for revert.
     A marker'd file owned by a DIFFERENT instance is refused (a live sibling's zone must never be
     taken over; its own revert would delete the file out from under the new session).
  2. No marker, but bytes are exactly what we would write, or exactly the legacy pre-marker body for
     the current servers/search -> adopt the same way (covers the legacy leak format that caused this
     incident).
  3. Anything else -> new `DnsError::ForeignResolverFile { zone, path }`. The connect path turns this
     into a blocking error with remediation text (`sudo rm`, or `--dns-zone` elsewhere).
  Abort paths roll back only files the call CREATED; adopted files predate the call and survive every
  abort. The `--replace-resolver-files` flag from the original design is deferred to M3 (where
  `opc recover` provides the consent path); M1 ships adopt-or-fail.
- Unit tests: marker generation/detection; the three branches; cross-instance refusal; revert-only-own
  regression; atomic rename path; split-branch apply/revert flush coverage via an injected resolver dir.

### M2. Startup sweep before prelogin (fixes the deadlock end to end)

New `gp_dns::sweep_stale_macos_resolver(...)` + a `#[cfg(target_os = "macos")]` block in `opc connect`
adjacent to the Windows sweep block (origin `main.rs:3264-3327`), still before prelogin
(origin `main.rs:3341-3350`):

- Scan `/etc/resolver/` for files whose NAME is in this connect's split zones (zone == filename per
  `resolver(5)`).
- Liveness mirror of Windows: `gp_ipc::enumerate_live_instances_with_liveness()` tri-state; scan
  `Incomplete` -> delete nothing (fail-closed); all endpoints `Absent` -> blanket; otherwise narrow to
  files whose marker instance is ours-and-absent, with the `own_alive` guard (never touch our own files if
  our endpoint is not provably absent).
- Classification: marker-managed -> ours; legacy exact format match
  (`^(nameserver <ip>\n)+ (search <domain>\n)*$`, byte-identical to our writer) -> ours if no live owner;
  anything else -> foreign, never deleted here (M1's error branch handles it).
- Legacy-file deletion is additionally gated on a LIVE DNS probe: the sweep sends a single UDP A-query
  for the portal host to each nameserver the file lists (1 s cap each) and deletes only when every one
  of them black-holes. Any answering server means the file is a working resolver config someone
  deliberately installed (prelogin resolves through it fine) and it is kept. This replaced the original
  shape-only heuristic after the adversarial review showed it would silently delete hand-written
  working files. The probe's minimal wire codec (`build_dns_a_query`/`dns_response_matches`) is unit
  tested and is the seed of M5's bootstrap resolver.
- Crash leftovers of the atomic writer (`*.opc-tmp-*` names) are reclaimed in the same sweep under the
  same blanket gate (a temp file may be mid-rename while any opc session is alive).
- After deletion: unconditional best-effort `flush_macos_dns_cache` (even when zero deletions), mirroring
  the Windows paramchange lesson.
- Log every decision (deleted what and why; kept what and why; the destructive `sudo rm` advice is
  reserved for genuinely foreign files, not for kept legacy/marker'd files that a live sibling may own).

M1 + M2 close the reported incident: stale file present -> swept before prelogin -> connect succeeds.

### M3. recover / doctor / disconnect + DNS state journal (covers both leak surfaces)

**Status: implemented (commits 9f69a2c + 86ea04d).**

- New on-disk DNS journal in gp-dns (serde_json): written at apply to
  `/var/db/openprotect/dns-<instance>.json` (0600, root, atomic), removed on successful revert. Contents:
  resolver domains, networksetup service + prior servers/search. This is the only way to restore the
  networksetup fallback after a crash (prior values are currently memory-only), and doubles as ownership
  evidence for the sweep. The journal is the macOS analog of Windows' self-describing registry key names.
- `opc recover` (replace the Unix no-op at origin `main.rs:2601-2613`): enumerate `/etc/resolver/*`,
  classify (marker instance / legacy / foreign), liveness-gate deletions as in M2 (instance argument +
  `--all`, `--all` refused on incomplete scans, mirroring Windows `recover_platform` origin:2518-2581),
  restore networksetup values from the journal when present, unconditional flush, verbose reporting.
  Update the false comment about Unix backends.
- `opc doctor` (origin `main.rs:3009-3026`): macOS branch reports per-domain resolvers from
  `scutil --dns`, `/etc/resolver` inventory + classification, networksetup current vs journal; read-only.
- `opc disconnect` (origin `main.rs:2284-2358`): when IPC reports NotRunning, run the M2-style sweep for
  this instance (marker-owned + journal-backed legacy files) instead of printing "no running opc session"
  and giving up.
- No new top-level subcommand; keep `Status` / `HipReport` / `NrptJanitor` arms intact.

### M4. Exit safety (best effort; M2 remains the real guarantee)

**Status: graceful-exit parts implemented (commit 7ab5c86: SIGHUP/SIGQUIT into the cooperative
cancel path, DnsStateGuard last-resort revert on unwind); the crash handler is deferred pending
the lock-free registry design above.**

- Port crash_cleanup to unix: at apply time register the exact created file paths so a fatal-signal
  handler can unlink them. DESIGN CONSTRAINT (per the alignment review): the handler cannot lock a
  `Mutex<Vec<CString>>` - the registry must be a lock-free structure (e.g. an `AtomicPtr` to a leaked,
  immutable path array swapped once at arm time, or a pre-registered single CString set per instance).
  The handler performs ONLY async-signal-safe `unlink()` calls (no flush, no fork/exec;
  networksetup restoration is impossible in a handler and relies on M3's journal), then re-raises via
  the default disposition. Panic hook (normal context) may additionally flush.
- Arm timing mirrors Windows (origin `main.rs:7314-7317`: armed before `gp_dns::apply`).
- `shutdown_signal` (origin `main.rs:1969-1987`): add `SignalKind::hangup()` (SIGHUP) and SIGQUIT so
  terminal hangup takes the graceful teardown path (which already reverts DNS) instead of dying silently.
- Drop guard around `dns_state` (`Option<AppliedDnsState>` currently moved into teardown closures at
  origin `main.rs:7246`/`7414`): revert on Drop unless disarmed after explicit teardown; idempotent
  (NotFound -> Ok already holds for files).

### M5. Bootstrap pin (R5; strongly recommended)

**Status: implemented (commit 9d95906: libresolv res_query on a bounded blocking thread feeding
the existing resolve_override at the advertised port; 4s cap degrades to unpinned).**

- Before prelogin: `spawn_blocking` { `res_init()`, shrink `_res.retrans`/`_res.retry` (e.g. 2000 ms / 1),
  `res_query(portal_host, A)` (+ AAAA) } bounded by an 8 s wall clock. Proven to bypass `/etc/resolver`.
- On success: feed the address through the existing `resolve_override` -> reqwest `.resolve()` mechanism
  (origin `crates/gp-auth/src/client.rs:127-130`), covering prelogin and the auth chain.
- On failure/timeout: continue unpinned (current behavior). Best-effort hardening, never a hard dependency.
- No hickory-dns: the report's argument holds (per-domain hijack wedges every getaddrinfo consumer; an
  opc-only bypass would leave browsers/GUI wedged and misses the lifecycle problem).
- Follow-up issue (out of scope here): whether the portal client should opt out of proxies (`.no_proxy()`)
  given the pin/proxy interaction and that a VPN client silently honouring system proxies is questionable.

### M6. Tests and rollout

- Unit: marker; adopt/overwrite/error branches; legacy-format matcher; journal round-trip; revert
  regression.
- Integration (macOS CI, root): per report section 5 - stale file -> connect succeeds; `kill -9` ->
  reconnect self-heals; clean disconnect -> file gone and `scutil --dns` per-domain resolver gone;
  foreign `/etc/resolver/test.example` untouched.
- Manual: replay the original UNSW command from the incident after M1+M2.
- `docs/macos.md`: document the sweep/adopt behavior and keep the manual rescue commands until the fix
  ships in a release.

## 5. Pre-implementation live checks (on this Mac)

1. `#` comment tolerance in `/etc/resolver/<scratch-domain>` (write a marker-bearing file for a domain we
   control, resolve, delete) - unblocks M1's marker.
2. configd pickup latency for file DELETION (the add event is proven at 0.7 s; deletion unproven) -
   informs whether the flush after sweep is load-bearing.
3. res_* linkage on macOS (`-lresolv` vs libSystem built-ins) and whether mutating `_res.retrans/retry`
   before the query is honoured - unblocks M5.

## 6. Known limitations accepted at the M3-M5 revision (documented in code)

1. Mixed-version window: a legacy-format file written by a LIVE sibling running an OLD (pre-marker)
   binary with identical VPN values is byte-indistinguishable from our own stale leftover and is adopted
   at apply; the sibling's later revert deletes it. Narrow (upgrade transition only) and self-heals on
   the next connect; the M3 DNS-state journal replaces the heuristic.
2. Sweep scope is portal-host-suffix zones only. A stale file covering only the GATEWAY host (not a
   portal suffix) survives one hop later into gateway_login; the M5 bootstrap pin covers that hop.
   The pin is A-record-only: an IPv6-only portal name yields no pin and connects unpinned (AAAA
   support is a follow-up).
3. Unix liveness surfaces documented in gp-ipc: a live listener with a full accept backlog answers
   `ECONNREFUSED` (classified Absent - accepted collateral, the dead-session mainline must read as
   absence), and a manually removed socket directory hides live sessions from the scan.
4. `# session` is currently an empty value in macOS markers (`nrpt_session_token()` is Windows-only);
   instance-level ownership is what the sweep keys on. A real cross-platform token lands with M4.
5. The M5 pin is frozen at connect time: re-auth clients inherit the connect-time portal IP (the
   gateway lane refreshes its pin on gateway change; the portal lane does not yet). If a portal IP
   changes mid-session, re-auth dials the stale IP. Refresh-on-reauth is the follow-up.
6. The pin resolves through libresolv, which consults /etc/resolv.conf upstreams ONLY: it ignores
   /etc/hosts and macOS per-interface scoped resolvers. An operator's /etc/hosts portal entry is
   overridden by the pin once it engages; if hosts-file precedence matters, compare against
   getaddrinfo or skip the pin when the host is present there (follow-up).
7. The SIGHUP install overrides an inherited SIG_IGN (nohup'd sessions now disconnect on hangup
   instead of surviving it), and SIGQUIT no longer force-terminates: a teardown wedged in a
   subprocess leaves Ctrl-C/SIGTERM/SIGQUIT inert and SIGKILL from another terminal is the remaining
   escape. A long-lived signal task feeding the auth/reauth waits (which currently miss SIGHUP in
   unwatched windows) is the follow-up.
8. Journal durability stops at file fsync (no directory fsync after the rename): a power cut can
   lose the rename itself, degrading to the pre-journal status quo - safe, never wrong-direction.
9. CI gap: the macOS CI job exercises gp-route only; the gp-dns/opc macOS paths in this series run
   only in local `cargo test` today. M6 wires them into CI before release.

## 7. User-facing interim workaround (unchanged from the report)

```
sudo rm -f /etc/resolver/unsw.edu.au
sudo dscacheutil -flushcache
```

(The `killall -HUP mDNSResponder` step is probably unnecessary - configd auto-detected the file's creation
within 0.7 s - but harmless as belt-and-braces.)
