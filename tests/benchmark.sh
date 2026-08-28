#!/usr/bin/env bash
#
# benchmark.sh - v1.0.0: measures the actual overhead the kernel hooks
# add to execve and openat, by timing many iterations with the module
# unloaded (baseline) vs loaded, and reporting the delta.
#
# NEEDS ROOT (insmod/rmmod) and the module already built (av/av.ko).
# Run this in your VM, on an otherwise-idle system for a meaningful
# reading - background activity (package updates, other builds) will
# add noise to both runs but especially the loaded one, since every
# execve/openat on the system goes through the hooks, not just this
# benchmark's own.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ITERATIONS="${ITERATIONS:-2000}"

if [ "$(id -u)" -ne 0 ]; then
    echo "This script needs root (insmod/rmmod). Re-run with sudo."
    exit 1
fi

# mktemp -d, not fixed /tmp/av_bench_* paths - this script runs as
# root, and a fixed world-writable-directory path is a classic
# symlink-planting target: another local user could pre-create a
# symlink at e.g. /tmp/av_bench_harness before this runs, and gcc -o
# (which follows symlinks) would then overwrite whatever it points to.
# A private, unpredictably-named, 0700 directory closes this off
# entirely - same reasoning as tests/test_avd_socket.sh's mktemp use
# and userspace/avd/Makefile's checkdeps target.
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/av_bench.XXXXXX")" || exit 1
trap 'rm -rf "$WORKDIR"' EXIT
BENCH_BIN="$WORKDIR/av_bench_harness"

# A module MUST be built with the same compiler family as the running
# kernel (see the top-level README's toolchain section and
# test_detection.sh). Detect it the same way test_detection.sh does,
# rather than inheriting CC/LLVM from the environment.
MAKE_ARGS=()
if grep -q "clang version" /proc/version 2>/dev/null; then
    echo "Detected a Clang-built running kernel ($(uname -r)) - building with CC=clang LLVM=1"
    MAKE_ARGS=(CC=clang LLVM=1)
fi

echo "=== Building benchmark harness ==="
# Unquoted heredoc delimiter (not << 'EOF') so $WORKDIR below expands -
# safe here since the harness source itself contains no '$' or
# backticks for the shell to misinterpret.
cat > "$WORKDIR/av_bench_harness.c" << EOF
/* Small timing harness: N iterations of fork+execve+wait (/bin/true),
 * and N iterations of open+close on a scratch file. Reports average
 * microseconds per operation. Not part of the shipped project - a
 * throwaway diagnostic tool. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <time.h>

static double now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

static void bench_execve(int n) {
    double start = now_us();
    for (int i = 0; i < n; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            int devnull = open("/dev/null", O_WRONLY);
            dup2(devnull, 1);
            dup2(devnull, 2);
            execl("/bin/true", "true", (char *)NULL);
            _exit(127);
        }
        waitpid(pid, NULL, 0);
    }
    double elapsed = now_us() - start;
    printf("execve: %d iterations, %.2f us/op total (fork+exec+wait)\n",
           n, elapsed / n);
}

static void bench_openat(int n) {
    double start = now_us();
    for (int i = 0; i < n; i++) {
        int fd = open("$WORKDIR/av_bench_scratch.txt", O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0)
            close(fd);
    }
    double elapsed = now_us() - start;
    printf("openat (write-intent): %d iterations, %.2f us/op\n", n, elapsed / n);
}

int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 1000;
    bench_execve(n);
    bench_openat(n);
    return 0;
}
EOF
gcc -O2 -o "$BENCH_BIN" "$WORKDIR/av_bench_harness.c"

echo
echo "=== Baseline: module NOT loaded ==="
rmmod av 2>/dev/null || true
"$BENCH_BIN" "$ITERATIONS" | tee "$WORKDIR/av_bench_baseline.txt"

echo
echo "=== Loading module ==="
make -C "$REPO_ROOT/av" "${MAKE_ARGS[@]}" >/dev/null
insmod "$REPO_ROOT/av/av.ko"
sleep 1

echo
echo "=== With module loaded ==="
"$BENCH_BIN" "$ITERATIONS" | tee "$WORKDIR/av_bench_loaded.txt"

echo
echo "=== Cleanup ==="
rmmod av

echo
echo "=== Comparison ==="
echo "baseline (no module):"
cat "$WORKDIR/av_bench_baseline.txt"
echo
echo "with module loaded:"
cat "$WORKDIR/av_bench_loaded.txt"
echo
echo "Note on interpreting these numbers:"
echo "- execve overhead includes the FULL detection pipeline: hashing"
echo "  (MD5+SHA1+SHA256), signature lookup, and - if no signature"
echo "  match - waiting up to DAEMON_TIMEOUT_MS (12000ms) for avd. If"
echo "  avd is NOT running, expect a LARGE per-op number here, since"
echo "  every single execve is paying the full netlink timeout. Run"
echo "  this with avd running (registered) for a realistic reading."
echo "- openat overhead should be much smaller - the hook only does"
echo "  work for write-intent opens, and even then most just increment"
echo "  a counter and check a fixed sensitive-path list, no hashing."
echo "- these numbers reflect THIS specific VM's CPU, storage, and"
echo "  scheduler contention - do not treat them as representative of"
echo "  other hardware. Report the delta as a proportion (e.g. 3.2x"
echo "  slower) alongside the raw numbers, since raw microsecond"
echo "  figures alone are hard to contextualize."
