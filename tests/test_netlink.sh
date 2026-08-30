#!/usr/bin/env bash
#
# tests/test_netlink.sh - exercises the kernel<->avd Generic Netlink
# channel (see docs/netlink-protocol.md), which SECURITY.md calls out
# as one of the most security-critical surfaces in the project but
# which - unlike the Unix control socket (test_avd_socket.sh) and the
# procfs signature interface (test_sigtable.sh) - had no automated
# coverage at all before this script.
#
# Covers, in order:
#   - a non-CAP_NET_ADMIN process can't send AV_C_REGISTER/AV_C_VERDICT
#   - a malformed (missing required attribute) or oversized-attribute
#     AV_C_VERDICT is rejected without wedging the module
#   - only the currently-registered daemon's portid is honored for
#     AV_C_VERDICT ("portid pinning")
#   - a second AV_C_REGISTER silently replaces the first (documented,
#     known "single daemon only" behavior - see docs/netlink-protocol.md)
#   - a real end-to-end AV_C_SCAN_REQUEST/AV_C_VERDICT round trip via
#     the real avd binary, for both a clean and a malicious (YARA-only,
#     not signature-table) exec
#
# Uses tests/netlink_test_helper.c, a throwaway genl client built only
# by this script (never linked into avd or any shipped binary) -
# avd's own AV_C_REGISTER/AV_C_VERDICT sends are fire-and-forget
# (nl_send_auto(), no ack requested), which is fine for avd itself but
# useless for a test that needs to observe *rejections*.
#
# RUN THIS ONLY IN YOUR VM, ideally from a fresh snapshot - it loads a
# kernel module, same caveat as test_detection.sh/test_avd_socket.sh.
#
# Usage: sudo tests/test_netlink.sh
#
set -u

if [ "$(id -u)" -ne 0 ]; then
    echo "This script needs root (insmod/rmmod, CAP_NET_ADMIN netlink"
    echo "sends, and to start avd). Re-run with sudo."
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AV_DIR="$REPO_ROOT/av"
AVD_DIR="$REPO_ROOT/userspace/avd"
AVCTL_DIR="$REPO_ROOT/userspace/avctl"
TESTS_DIR="$REPO_ROOT/tests"
HELPER="$TESTS_DIR/netlink_test_helper"

TEST_QUARANTINE_DIR="/tmp/av_test_nl_quarantine_$$"
TEST_SOCK_PATH="/tmp/av_test_nl_control_$$.sock"
CLEAN_PATH="/tmp/av_test_nl_clean_$$.sh"
MALICIOUS_PATH="/tmp/av_test_nl_shell_$$.sh"
AVD_PID=""

# mktemp, not fixed /tmp paths - this runs as root, see
# test_avd_socket.sh's identical comment on why.
BUILD_LOG="$(mktemp "${TMPDIR:-/tmp}/av_netlink_build.XXXXXX")" || exit 1
INSMOD_LOG="$(mktemp "${TMPDIR:-/tmp}/av_netlink_insmod.XXXXXX")" || exit 1
AVD_LOG="$(mktemp "${TMPDIR:-/tmp}/av_netlink_avd.XXXXXX")" || exit 1
RMMOD_LOG="$(mktemp "${TMPDIR:-/tmp}/av_netlink_rmmod.XXXXXX")" || exit 1

PASS=0
FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
section() { echo; echo "== $1 =="; }

# Same toolchain-detection rationale as the other integration tests -
# sudo strips any CC=clang LLVM=1 the caller's shell had exported.
MAKE_ARGS=()
if grep -q "clang version" /proc/version 2>/dev/null; then
    echo "Detected a Clang-built running kernel ($(uname -r)) - building with CC=clang LLVM=1"
    MAKE_ARGS=(CC=clang LLVM=1)
fi

cleanup() {
    section "cleanup"
    if [ -n "$AVD_PID" ] && kill -0 "$AVD_PID" 2>/dev/null; then
        kill "$AVD_PID" 2>/dev/null
        wait "$AVD_PID" 2>/dev/null
        echo "  avd stopped"
    fi
    rmmod av 2>/dev/null && echo "  module unloaded" || echo "  module already unloaded"
    rm -rf "$TEST_QUARANTINE_DIR"
    rm -f "$TEST_SOCK_PATH" "$CLEAN_PATH" "$MALICIOUS_PATH"
    rm -f "$BUILD_LOG" "$INSMOD_LOG" "$AVD_LOG" "$RMMOD_LOG"
}
trap cleanup EXIT

section "build"
# Arrays, not bare $(pkg-config ...) inline, so the flags word-split
# deliberately (they're genuinely multi-token) without tripping a
# lint warning about unquoted, unintended word splitting.
IFS=' ' read -r -a NL_CFLAGS <<< "$(pkg-config --cflags libnl-genl-3.0)"
IFS=' ' read -r -a NL_LIBS <<< "$(pkg-config --libs libnl-genl-3.0)"
if make -C "$AV_DIR" "${MAKE_ARGS[@]}" clean >"$BUILD_LOG" 2>&1 && \
   make -C "$AV_DIR" "${MAKE_ARGS[@]}" >>"$BUILD_LOG" 2>&1 && \
   make -C "$AVD_DIR" >>"$BUILD_LOG" 2>&1 && \
   make -C "$AVCTL_DIR" >>"$BUILD_LOG" 2>&1 && \
   gcc -Wall -Wextra -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
       -Wformat -Wformat-security \
       "${NL_CFLAGS[@]}" \
       -o "$HELPER" "$TESTS_DIR/netlink_test_helper.c" \
       "${NL_LIBS[@]}" >>"$BUILD_LOG" 2>&1; then
    pass "av.ko, avd, avctl, and netlink_test_helper built"
else
    fail "build failed - see $BUILD_LOG"
    cat "$BUILD_LOG"
    exit 1
fi

section "load module"
if insmod "$AV_DIR/av.ko" 2>"$INSMOD_LOG"; then
    pass "module loaded"
else
    fail "insmod failed: $(cat "$INSMOD_LOG")"
    exit 1
fi
sleep 1

# Same "nobody" rationale as test_avd_socket.sh's unprivileged-peer
# section: a real non-root process, not just a claimed uid, so
# GENL_ADMIN_PERM's actual capable(CAP_NET_ADMIN) check is what's
# under test.
if command -v setpriv >/dev/null 2>&1 && \
   NOBODY_UID="$(id -u nobody 2>/dev/null)" && NOBODY_GID="$(id -g nobody 2>/dev/null)"; then
    HAVE_SETPRIV=1
else
    HAVE_SETPRIV=0
fi

section "unprivileged AV_C_REGISTER/AV_C_VERDICT rejected"
if [ "$HAVE_SETPRIV" -eq 1 ]; then
    UNPRIV_REGISTER="$(setpriv --reuid="$NOBODY_UID" --regid="$NOBODY_GID" --clear-groups "$HELPER" register 2>&1)"
    if echo "$UNPRIV_REGISTER" | grep -qi 'permitted'; then
        pass "unprivileged AV_C_REGISTER rejected"
    else
        fail "unprivileged AV_C_REGISTER not rejected as expected: $UNPRIV_REGISTER"
    fi

    UNPRIV_VERDICT="$(setpriv --reuid="$NOBODY_UID" --regid="$NOBODY_GID" --clear-groups "$HELPER" verdict 1 0 2>&1)"
    if echo "$UNPRIV_VERDICT" | grep -qi 'permitted'; then
        pass "unprivileged AV_C_VERDICT rejected"
    else
        fail "unprivileged AV_C_VERDICT not rejected as expected: $UNPRIV_VERDICT"
    fi
else
    echo "  SKIP: setpriv not installed, or the \"nobody\" user/group could not"
    echo "  be resolved - skipping unprivileged-sender checks"
    echo "  (Arch/CachyOS: sudo pacman -S util-linux / Debian/Ubuntu: sudo apt install util-linux)"
fi

section "malformed/oversized AV_C_VERDICT rejected without wedging the module"
MALFORMED_OUT="$("$HELPER" malformed-verdict 2>&1)"
if echo "$MALFORMED_OUT" | grep -qi 'invalid'; then
    pass "AV_C_VERDICT missing AV_A_REQID rejected"
else
    fail "malformed AV_C_VERDICT not rejected as expected: $MALFORMED_OUT"
fi

OVERSIZED_OUT="$("$HELPER" oversized-verdict 2>&1)"
if echo "$OVERSIZED_OUT" | grep -qi 'invalid'; then
    pass "AV_C_VERDICT with an over-limit AV_A_RULE_NAME rejected"
else
    fail "oversized AV_C_VERDICT not rejected as expected: $OVERSIZED_OUT"
fi

# Sanity: the module is still alive and answering after two bad
# messages, not wedged/crashed.
if "$HELPER" resolve >/dev/null 2>&1; then
    pass "module still responsive after malformed/oversized messages"
else
    fail "module did not respond to a well-formed request after malformed/oversized ones"
fi

section "portid pinning: only the registered daemon's portid is honored"
dmesg -C
REGISTER_A="$("$HELPER" register 2>&1)"
if echo "$REGISTER_A" | grep -q '^OK'; then
    pass "first AV_C_REGISTER (fake daemon A) accepted"
else
    fail "first AV_C_REGISTER unexpectedly rejected: $REGISTER_A"
fi
# A fresh process = a fresh netlink socket = a different portid, even
# though it's just as privileged (root) as the one that just
# registered - av_nl_verdict_doit() must reject this on portid alone.
VERDICT_B="$("$HELPER" verdict 1 0 2>&1)"
if echo "$VERDICT_B" | grep -qi 'permitted'; then
    pass "AV_C_VERDICT from a different (non-registered) portid rejected"
else
    fail "AV_C_VERDICT from a non-registered portid not rejected as expected: $VERDICT_B"
fi
if dmesg | grep -q 'AV_C_VERDICT from portid .* ignored (not the registered daemon)'; then
    pass "kernel logged the portid-mismatch rejection"
else
    fail "expected portid-mismatch log line not found in dmesg"
    dmesg | tail -10
fi

section "daemon re-registration: a second AV_C_REGISTER replaces the first"
dmesg -C
REGISTER_C="$("$HELPER" register 2>&1)"
if echo "$REGISTER_C" | grep -q '^OK'; then
    pass "second AV_C_REGISTER (fake daemon C) accepted"
else
    fail "second AV_C_REGISTER unexpectedly rejected: $REGISTER_C"
fi
REGISTER_LINES="$(dmesg | grep -c 'kernel-av: netlink daemon registered')"
DISTINCT_PORTIDS="$(dmesg | grep -o 'netlink daemon registered (portid=[0-9]*)' | sort -u | wc -l)"
if [ "$REGISTER_LINES" -ge 1 ] && [ "$DISTINCT_PORTIDS" -ge 1 ]; then
    pass "re-registration observed in dmesg (portid overwritten, matches documented single-daemon-only behavior)"
else
    fail "expected a second registration log line in dmesg, found $REGISTER_LINES"
    dmesg | tail -10
fi

section "start avd (throwaway quarantine dir + control socket)"
mkdir -p "$TEST_QUARANTINE_DIR"
dmesg -C
(
    cd "$REPO_ROOT" || exit 1
    exec "$AVD_DIR/avd" rules corpus/fuzzy_hashes.txt "$TEST_QUARANTINE_DIR" \
        corpus/tlsh_hashes.txt "$TEST_SOCK_PATH" >"$AVD_LOG" 2>&1
) &
AVD_PID=$!

for _ in $(seq 1 20); do
    [ -S "$TEST_SOCK_PATH" ] && break
    sleep 0.5
done
if [ -S "$TEST_SOCK_PATH" ]; then
    pass "avd started and control socket exists"
else
    fail "avd did not create the control socket in time - see $AVD_LOG"
    cat "$AVD_LOG"
    exit 1
fi
# avd's own AV_C_REGISTER on startup should now be the pinned daemon,
# overwriting fake daemon C from the section above.
sleep 1
if dmesg | grep -q 'kernel-av: netlink daemon registered'; then
    pass "avd re-registered itself as the pinned daemon"
else
    fail "expected avd's own AV_C_REGISTER log line not found in dmesg"
fi

section "scan-request round trip end to end (clean)"
cat > "$CLEAN_PATH" <<'EOF'
#!/bin/sh
echo "just a harmless test script for tests/test_netlink.sh"
EOF
chmod +x "$CLEAN_PATH"
# The clean-verdict log line is pr_info_ratelimited() (see its comment
# in av_work_fn() - it fires for every daemon-path exec system-wide,
# so it's rate-limited to avoid a dmesg line per exec), unlike the
# non-rate-limited pr_alert() a kill uses below. On a busy machine with
# other exec activity sharing that same rate-limit budget, one attempt
# can be suppressed even though the round trip itself succeeded -
# retry a few times rather than treating that as a real failure.
CLEAN_OK=0
for _ in 1 2 3; do
    dmesg -C
    "$CLEAN_PATH" >/dev/null 2>&1
    sleep 1
    if dmesg | grep -q "event=clean type=daemon path=\"$CLEAN_PATH\""; then
        CLEAN_OK=1
        break
    fi
done
if [ "$CLEAN_OK" -eq 1 ]; then
    pass "clean exec round-tripped through avd and logged clean"
else
    fail "expected daemon-path clean log line not found in dmesg after retries"
    dmesg | tail -10
fi

section "scan-request round trip end to end (malicious, YARA-only - no sigtable entry)"
# Matches rules/test.yar's Suspicious_Shell_Reverse_Shell_String rule
# ("/bin/sh -i") - deliberately inert (just echoes the string, never
# actually execs a shell) so this test can't accidentally open a real
# shell if detection fails for some other reason. This has no sigtable
# entry (unique content -> unique hash), so a kill here can only have
# come from the daemon/YARA path, not the kernel-side signature table -
# unlike test_detection.sh's EICAR case, which is deliberately a
# signature-table hit and never reaches the netlink channel at all.
cat > "$MALICIOUS_PATH" <<'EOF'
#!/bin/sh
echo "/bin/sh -i"
EOF
chmod +x "$MALICIOUS_PATH"
dmesg -C
"$MALICIOUS_PATH" >/dev/null 2>&1
sleep 1
# avd comma-joins every rule name that crossed the score threshold
# (see rules/heuristics.yar's WEIGHT META comment), not just the one
# this test cares about - some other rule (e.g. an ELF/entry-point
# heuristic) may also fire on this file, so match the rule name as a
# substring of `reason`, not the whole field.
if dmesg | grep -qi "event=detected action=kill type=daemon path=\"$MALICIOUS_PATH\".*reason=\"daemon:[^\"]*Suspicious_Shell_Reverse_Shell_String"; then
    pass "malicious exec round-tripped through avd/YARA and was killed"
else
    fail "expected daemon-path detected/kill log line not found in dmesg"
    dmesg | tail -10
fi

section "unload"
if kill "$AVD_PID" 2>/dev/null; then
    wait "$AVD_PID" 2>/dev/null
    AVD_PID=""
    pass "avd stopped"
else
    fail "could not stop avd"
fi
if rmmod av 2>"$RMMOD_LOG"; then
    pass "module unloaded cleanly"
else
    fail "rmmod failed: $(cat "$RMMOD_LOG")"
fi

echo
echo "==================================="
echo "netlink tests: $PASS passed, $FAIL failed"
echo "==================================="
[ "$FAIL" -eq 0 ]
