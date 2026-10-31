#!/usr/bin/env bash
# selftest-resolver.sh — macOS root self-test for the resolver fix series
# (M1-M5: marker/adopt semantics, pre-connect sweep, DNS journal, recover).
#
# Covers the plan's acceptance criteria that do NOT need a live portal
# login (docs/fix-macos-resolver-stale-state.md §5/M6). Run as root:
#
#   sudo scripts/selftest-resolver.sh
#
# Everything the script creates uses the `selftest` prefix and is
# cleaned up on exit (including the networksetup DNS restore). The two
# connect-level acceptance tests (stale file -> connect succeeds;
# kill -9 -> reconnect self-heals) need real credentials and are
# printed at the end as manual steps.
#
# NOTE: the legacy-file deletion test relies on a DNS probe against
# TEST-NET addresses. On a network that intercepts port 53 the probe
# sees "answers" and the file is (correctly) kept as a working config
# — run this off-network or accept that T1 reports KEEP there.

set -u

# Defaults to the repo's own fresh release build; the deployed binary
# in a release directory may predate the fix series.
OPC_BIN="${OPC_BIN:-$PWD/target/release/opc}"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); printf 'PASS: %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf 'FAIL: %s\n' "$*"; }
note() { printf -- '-- %s\n' "$*"; }

RESOLVER_DIR="/etc/resolver"
JOURNAL_DIR="/var/db/openprotect"
MARKER="# managed by openprotect (opc) v1"

mkdir -p "$RESOLVER_DIR"

# ---------------------------------------------------------------------------
# Cleanup: everything we touch is restored on exit, in reverse order.
# ---------------------------------------------------------------------------
SVC=""
PRIOR_DNS=""
PRIOR_SEARCH=""
CREATED_FILES=()

cleanup() {
    for f in "${CREATED_FILES[@]}"; do
        rm -f "$f"
    done
    if [ -n "$SVC" ] && [ -n "$PRIOR_DNS" ]; then
        if [ "$PRIOR_DNS" = "EMPTY" ]; then
            networksetup -setdnsservers "$SVC" Empty >/dev/null 2>&1
        else
            # shellcheck disable=SC2086
            networksetup -setdnsservers "$SVC" $PRIOR_DNS >/dev/null 2>&1
        fi
    fi
    if [ -n "$SVC" ] && [ -n "$PRIOR_SEARCH" ]; then
        if [ "$PRIOR_SEARCH" = "EMPTY" ]; then
            networksetup -setsearchdomains "$SVC" Empty >/dev/null 2>&1
        else
            # shellcheck disable=SC2086
            networksetup -setsearchdomains "$SVC" $PRIOR_SEARCH >/dev/null 2>&1
        fi
    fi
    rm -f "$JOURNAL_DIR"/dns-selftest*.json
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# T1. Legacy pre-marker file with black-holing servers is reclaimed by
#     `opc recover` (blanket gate: no opc sessions assumed here).
# ---------------------------------------------------------------------------
t1_legacy_sweep() {
    note "T1: legacy stale file is reclaimed by opc recover"
    local f="$RESOLVER_DIR/selftest-legacy.example"
    printf 'nameserver 192.0.2.53\nnameserver 192.0.2.54\nsearch selftest.invalid\n' >"$f"
    CREATED_FILES+=("$f")
    "$OPC_BIN" recover -i selftest-legacy >/dev/null 2>&1
    if [ ! -f "$f" ]; then
        pass "T1 legacy file swept"
    else
        fail "T1 legacy file survived recover (DNS interception? see header note)"
    fi
}

# ---------------------------------------------------------------------------
# T2. A hand-written (comment-bearing) file is NEVER touched.
# ---------------------------------------------------------------------------
t2_foreign_untouched() {
    note "T2: hand-written foreign file is never touched"
    local f="$RESOLVER_DIR/selftest-foreign.example"
    printf '# hand-written by the operator\nnameserver 192.0.2.53\noptions timeout:1\n' >"$f"
    CREATED_FILES+=("$f")
    "$OPC_BIN" recover -i selftest >/dev/null 2>&1
    if [ -f "$f" ]; then
        pass "T2 foreign file untouched"
    else
        fail "T2 foreign file was DELETED by recover"
    fi
}

# ---------------------------------------------------------------------------
# T3. A marker'd file of a dead instance is reclaimed; a marker'd file
#     of another (absent but differently-named) instance is kept when
#     out of scope.
# ---------------------------------------------------------------------------
t3_marker_reclaim() {
    note "T3: marker'd dead-instance file is reclaimed via recover -i"
    local f="$RESOLVER_DIR/selftest-dead.example"
    printf '%s\n# instance selftest-dead\n# session\nnameserver 192.0.2.53\n' "$MARKER" >"$f"
    CREATED_FILES+=("$f")
    "$OPC_BIN" recover -i selftest-dead >/dev/null 2>&1
    if [ ! -f "$f" ]; then
        pass "T3 marker'd dead-instance file swept"
    else
        fail "T3 marker'd dead-instance file survived"
    fi

    local g="$RESOLVER_DIR/selftest-other.example"
    printf '%s\n# instance selftest-alive\n# session\nnameserver 192.0.2.53\n' "$MARKER" >"$g"
    CREATED_FILES+=("$g")
    "$OPC_BIN" recover -i selftest-dead >/dev/null 2>&1
    if [ -f "$g" ]; then
        pass "T3b out-of-scope marker'd file untouched"
    else
        fail "T3b out-of-scope marker'd file was deleted"
    fi
}

# ---------------------------------------------------------------------------
# T4. Journal restore: a journal left by a "crashed" session restores
#     the priors on the service and retires the journal.
#     MUTATES system DNS during the test; the trap restores it.
# ---------------------------------------------------------------------------
t4_journal_restore() {
    note "T4: DNS journal restore (networksetup swap round-trip)"
    SVC="$(networksetup -listallnetworkservices | awk 'NR==2 {print $0}')"
    if [ -z "$SVC" ]; then
        fail "T4 could not determine a network service"
        return
    fi
    local cur
    cur="$(networksetup -getdnsservers "$SVC" 2>/dev/null)"
    if grep -q "There aren't any" <<<"$cur"; then
        PRIOR_DNS="EMPTY"
    else
        PRIOR_DNS="$(echo "$cur" | tr '\n' ' ' | sed 's/ *$//')"
    fi
    local curs
    curs="$(networksetup -getsearchdomains "$SVC" 2>/dev/null)"
    if grep -q "There aren't any" <<<"$curs"; then
        PRIOR_SEARCH="EMPTY"
    else
        PRIOR_SEARCH="$(echo "$curs" | tr '\n' ' ' | sed 's/ *$//')"
    fi

    # "Crashed session": swap the service DNS to TEST-NET values and
    # write the journal a real apply would have left behind.
    networksetup -setdnsservers "$SVC" 192.0.2.53 >/dev/null 2>&1
    mkdir -p "$JOURNAL_DIR"
    # The real apply keys global-swap journals by (instance, service),
    # case-folded like gp-dns's sanitizer.
    local svc_key
    svc_key="$(printf '%s' "$SVC" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9._-]/-/g')"
    local jf="$JOURNAL_DIR/dns-selftest-$svc_key.json"
    local prior_json search_json
    if [ "$PRIOR_DNS" = "EMPTY" ]; then
        prior_json="[]"
    else
        # shellcheck disable=SC2086
        prior_json="[$(printf '"%s"' "$(echo "$PRIOR_DNS" | sed 's/ /","/g')")]"
    fi
    if [ "$PRIOR_SEARCH" = "EMPTY" ]; then
        search_json="[]"
    else
        # shellcheck disable=SC2086
        search_json="[$(printf '"%s"' "$(echo "$PRIOR_SEARCH" | sed 's/ /","/g')")]"
    fi
    cat >"$jf" <<EOF
{"version":1,"instance":"selftest","pid":99999,"applied_at_unix":0,
 "ifname":"utun9","backend":"macos-network-setup",
 "macos_service":"$SVC","macos_prior_servers":$prior_json,
 "macos_prior_search_domains":$search_json,
 "macos_search_domains_changed":false,
 "macos_applied_servers":["192.0.2.53"],
 "macos_resolver_domains":[]}
EOF
    chmod 600 "$jf"
    "$OPC_BIN" recover -i selftest >/dev/null 2>&1
    local after after_norm
    after="$(networksetup -getdnsservers "$SVC" 2>/dev/null)"
    if grep -q "There aren't any" <<<"$after"; then
        after_norm="EMPTY"
    else
        after_norm="$(echo "$after" | tr '\n' ' ' | sed 's/ *$//')"
    fi
    if [ "$after_norm" = "$PRIOR_DNS" ]; then
        pass "T4 journal restore wrote the priors back"
    else
        fail "T4 service DNS is '$after_norm', expected priors '$PRIOR_DNS'"
    fi
    if [ ! -f "$jf" ]; then
        pass "T4b journal retired after clean restore"
    else
        fail "T4b journal survived a clean restore"
    fi
}

# ---------------------------------------------------------------------------
# T5/T6. macOS parser tolerance for the marker header (resolver(5)
#        comment lines) + configd's pickup of file DELETION, and a
#        doctor smoke test.
# ---------------------------------------------------------------------------
t5_marker_tolerance_and_delete_pickup() {
    note "T5: macOS parses marker-bearing resolver files (plan live check 1)"
    local f="$RESOLVER_DIR/selftest-marker-test"
    printf '%s\n# instance selftest\nnameserver 192.0.2.53\n' "$MARKER" >"$f"
    CREATED_FILES+=("$f")
    sleep 2
    if scutil --dns | grep -q "selftest-marker-test"; then
        pass "T5 marker-bearing file registered as a per-domain resolver"
    else
        fail "T5 macOS did NOT register the marker-bearing file (comments rejected?)"
    fi

    note "T5b: configd picks up file deletion (plan live check 2)"
    local start end gone=0
    start=$(date +%s)
    rm -f "$f"
    CREATED_FILES=("${CREATED_FILES[@]/$f/}")
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        sleep 0.5
        if ! scutil --dns | grep -q "selftest-marker-test"; then
            gone=1
            break
        fi
    done
    end=$(date +%s)
    if [ "$gone" = 1 ]; then
        pass "T5b per-domain resolver dropped after deletion (within $((end - start + 1))s)"
    else
        fail "T5b per-domain resolver still active 5s after deletion (flush needed?)"
        dscacheutil -flushcache
    fi
}

t6_doctor_smoke() {
    note "T6: opc doctor smoke test"
    if "$OPC_BIN" doctor >/dev/null 2>&1; then
        pass "T6 doctor exits cleanly"
    else
        fail "T6 doctor failed"
    fi
}

# ---------------------------------------------------------------------------
main() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "must run as root: sudo $0" >&2
        exit 2
    fi
    if ! [ -x "$OPC_BIN" ]; then
        echo "opc binary not found at $OPC_BIN" >&2
        echo "build it first: cargo build --release -p opc (or set OPC_BIN)" >&2
        exit 2
    fi
    # The blanket-gated tests need a machine with NO opc session alive:
    # recover (correctly) refuses to touch legacy files and journals
    # while anything may own them.
    if pgrep -x opc >/dev/null 2>&1; then
        echo "an opc session appears to be running (pgrep -x opc): stop it first," >&2
        echo "the blanket-gated reclaim tests would be refused by design" >&2
        exit 2
    fi
    t1_legacy_sweep
    t2_foreign_untouched
    t3_marker_reclaim
    t4_journal_restore
    t5_marker_tolerance_and_delete_pickup
    t6_doctor_smoke

    cat <<'EOF'

== Manual connect-level acceptance (needs real credentials) ==========
1. With /etc/resolver/<zone> stale (or right after T1 recreates it),
   run the original failing connect; expect the sweep line
   "pre-connect sweep removed stale /etc/resolver/<zone>" and a
   successful tunnel.
2. kill -9 the session pid, then reconnect: expect self-heal.
3. `opc disconnect`: expect the resolver file gone and
   `scutil --dns` free of the zone's per-domain resolver.
=======================================================================
EOF
    printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
    [ "$FAIL" -eq 0 ]
}

main "$@"
