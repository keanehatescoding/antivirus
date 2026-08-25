#!/usr/bin/env bash
#
# tests/test_avd_socket.sh - exercises avd's control socket protocol
# (see docs/avd-socket-protocol.md): STATUS, VERDICTS RECENT, SCAN,
# and QUARANTINE LIST/RESTORE/DELETE. Runs everything as root (this
# script requires root anyway, for insmod/rmmod), so it does NOT cover
# the SO_PEERCRED permission gate that rejects SCAN/QUARANTINE
# RESTORE/DELETE from a non-root peer - that would need a second,
# unprivileged connection alongside the root one this script already
# makes, which is a real gap worth closing separately, not something
# to claim coverage of here.
#
# Unlike test_sigtable.sh (which expects the module already loaded and
# never touches avd), this script builds and loads the module AND
# starts avd itself, against a throwaway quarantine dir and control
# socket path - it does not touch your real /var/lib/av-quarantine or
# /run/avd/control.sock.
#
# RUN THIS ONLY IN YOUR VM, ideally from a fresh snapshot - it loads a
# kernel module, same caveat as test_detection.sh.
#
# Usage: sudo tests/test_avd_socket.sh
#
set -u

if [ "$(id -u)" -ne 0 ]; then
    echo "This script needs root (insmod/rmmod, and to exercise avd's"
    echo "root-only SCAN/QUARANTINE RESTORE/QUARANTINE DELETE verbs as root)."
    echo "Re-run with sudo."
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AV_DIR="$REPO_ROOT/av"
AVD_DIR="$REPO_ROOT/userspace/avd"
AVCTL_DIR="$REPO_ROOT/userspace/avctl"
AVCTL="$AVCTL_DIR/avctl"

TEST_QUARANTINE_DIR="/tmp/av_test_quarantine_$$"
TEST_SOCK_PATH="/tmp/av_test_control_$$.sock"
TEST_FILE="/tmp/av_test_socket_sample_$$.bin"
AVD_PID=""

# mktemp, not a fixed /tmp/av_socket_*.log path - this script runs as
# root, and a fixed world-writable-directory path is a classic
# symlink-planting target: another local user could pre-create a
# symlink there pointing anywhere, and a root redirect into it would
# truncate/overwrite whatever it points to. Same reasoning as
# userspace/avd/Makefile's checkdeps target.
BUILD_LOG="$(mktemp "${TMPDIR:-/tmp}/av_socket_build.XXXXXX")" || exit 1
INSMOD_LOG="$(mktemp "${TMPDIR:-/tmp}/av_socket_insmod.XXXXXX")" || exit 1
AVD_LOG="$(mktemp "${TMPDIR:-/tmp}/av_socket_avd.XXXXXX")" || exit 1
SOCAT_LOG="$(mktemp "${TMPDIR:-/tmp}/av_socket_socat.XXXXXX")" || exit 1
AVCTL_LOG="$(mktemp "${TMPDIR:-/tmp}/av_socket_avctl.XXXXXX")" || exit 1
RMMOD_LOG="$(mktemp "${TMPDIR:-/tmp}/av_socket_rmmod.XXXXXX")" || exit 1

PASS=0
FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
section() { echo; echo "== $1 =="; }

# Same toolchain-detection rationale as test_detection.sh - sudo
# strips any CC=clang LLVM=1 the caller's shell had exported, so
# detect the running kernel's actual build toolchain directly instead
# of trusting inherited environment variables.
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
    rm -f "$TEST_SOCK_PATH" "$TEST_FILE"
    rm -f "$BUILD_LOG" "$INSMOD_LOG" "$AVD_LOG" "$SOCAT_LOG" "$AVCTL_LOG" "$RMMOD_LOG"
}
trap cleanup EXIT

section "build"
if make -C "$AV_DIR" "${MAKE_ARGS[@]}" clean >"$BUILD_LOG" 2>&1 && \
   make -C "$AV_DIR" "${MAKE_ARGS[@]}" >>"$BUILD_LOG" 2>&1 && \
   make -C "$AVD_DIR" >>"$BUILD_LOG" 2>&1 && \
   make -C "$AVCTL_DIR" >>"$BUILD_LOG" 2>&1; then
    pass "av.ko, avd, and avctl built"
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

section "start avd (throwaway quarantine dir + control socket)"
mkdir -p "$TEST_QUARANTINE_DIR"
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

export AVD_SOCK_PATH="$TEST_SOCK_PATH"

# STATUS/VERDICTS RECENT have no avctl subcommand (the GUI talks to
# them directly - see docs/avd-socket-protocol.md), so exercise the
# raw wire protocol with socat if it's available. Not a hard
# dependency: skip gracefully rather than failing the whole suite over
# a missing optional tool, since avctl already covers the
# security-relevant verbs (SCAN, QUARANTINE *) below either way.
section "STATUS / VERDICTS RECENT (raw protocol via socat)"
if command -v socat >/dev/null 2>&1; then
    STATUS_RESP="$(printf 'STATUS\n' | socat - "UNIX-CONNECT:$TEST_SOCK_PATH" 2>"$SOCAT_LOG")"
    if echo "$STATUS_RESP" | grep -q '^OK$' && echo "$STATUS_RESP" | grep -q '^COUNT 1$'; then
        pass "STATUS returns OK/COUNT 1"
    else
        fail "STATUS response malformed: $STATUS_RESP"
    fi

    VERDICTS_RESP="$(printf 'VERDICTS RECENT 5\n' | socat - "UNIX-CONNECT:$TEST_SOCK_PATH" 2>>"$SOCAT_LOG")"
    if echo "$VERDICTS_RESP" | grep -q '^OK$'; then
        pass "VERDICTS RECENT 5 returns OK"
    else
        fail "VERDICTS RECENT response malformed: $VERDICTS_RESP"
    fi

    BOGUS_RESP="$(printf 'NOT A REAL COMMAND\n' | socat - "UNIX-CONNECT:$TEST_SOCK_PATH" 2>>"$SOCAT_LOG")"
    if echo "$BOGUS_RESP" | grep -q '^ERR '; then
        pass "unknown command rejected with ERR"
    else
        fail "unknown command not rejected as expected: $BOGUS_RESP"
    fi
else
    echo "  SKIP: socat not installed - skipping raw-protocol STATUS/VERDICTS checks"
    echo "  (Arch/CachyOS: sudo pacman -S socat / Debian/Ubuntu: sudo apt install socat)"
fi

section "SCAN a clean file"
printf 'just some harmless test bytes\n' > "$TEST_FILE"
if "$AVCTL" scan "$TEST_FILE" 2>"$AVCTL_LOG" | grep -q '^CLEAN:'; then
    pass "scan of a harmless file reports CLEAN"
else
    fail "expected CLEAN, got: $(cat "$AVCTL_LOG")"
fi

section "SCAN the EICAR test string (should convict via YARA)"
# shellcheck disable=SC2016
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$TEST_FILE"
SCAN_OUT="$("$AVCTL" scan "$TEST_FILE" 2>"$AVCTL_LOG")"
if echo "$SCAN_OUT" | grep -q '^MALICIOUS:'; then
    pass "EICAR scan reports MALICIOUS"
else
    fail "expected MALICIOUS, got: $SCAN_OUT ($(cat "$AVCTL_LOG"))"
fi
if [ ! -e "$TEST_FILE" ]; then
    pass "EICAR file was quarantined (original path gone)"
else
    fail "EICAR file still present at original path after a MALICIOUS scan"
fi

section "QUARANTINE LIST shows the quarantined EICAR file"
LIST_OUT="$("$AVCTL" quarantine list 2>"$AVCTL_LOG")"
if echo "$LIST_OUT" | grep -q "$TEST_FILE"; then
    pass "quarantine list shows the original path"
else
    fail "quarantine list missing expected entry: $LIST_OUT"
fi
QID="$(echo "$LIST_OUT" | tail -n +2 | awk -v f="$TEST_FILE" '$0 ~ f {print $1}' | head -1)"

section "QUARANTINE RESTORE puts it back"
if [ -n "$QID" ] && "$AVCTL" quarantine restore "$QID" >"$AVCTL_LOG" 2>&1; then
    pass "restore command succeeded"
else
    fail "restore command failed: $(cat "$AVCTL_LOG" 2>/dev/null) (id=$QID)"
fi
if [ -e "$TEST_FILE" ]; then
    pass "file exists at original path after restore"
else
    fail "file missing at original path after restore"
fi

section "re-scan + QUARANTINE DELETE removes it for good"
"$AVCTL" scan "$TEST_FILE" >/dev/null 2>&1  # re-quarantine (still the EICAR content)
LIST_OUT="$("$AVCTL" quarantine list 2>/dev/null)"
QID="$(echo "$LIST_OUT" | tail -n +2 | awk -v f="$TEST_FILE" '$0 ~ f {print $1}' | head -1)"
if [ -n "$QID" ] && "$AVCTL" quarantine delete "$QID" >"$AVCTL_LOG" 2>&1; then
    pass "delete command succeeded"
else
    fail "delete command failed: $(cat "$AVCTL_LOG" 2>/dev/null) (id=$QID)"
fi
if "$AVCTL" quarantine list 2>/dev/null | grep -q "$TEST_FILE"; then
    fail "quarantine list still shows the deleted entry"
else
    pass "quarantine list no longer shows the deleted entry"
fi
rm -f "$TEST_FILE"

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
echo "avd socket tests: $PASS passed, $FAIL failed"
echo "==================================="
[ "$FAIL" -eq 0 ]
