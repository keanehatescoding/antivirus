#!/usr/bin/env bash
#
# tests/test_avd_sigroute.sh - regression test for avd's SIGINT/SIGTERM
# routing (see the pthread_sigmask block/unblock in main() in
# userspace/avd/avd.c).
#
# Failure mode this guards: all threads inherit their creator's signal
# mask, so with the mask left unblocked a process-directed SIGTERM (as
# sent by kill(1), systemctl stop, or Ctrl-C's SIGINT) can run avd's
# termination handler on a scan-worker or control thread instead of the
# main thread. `running` then goes to 0 where nothing observes it while
# the main thread stays blocked in nl_recvmsgs_default() forever -
# shutdown hangs. The fix blocks both signals before any
# pthread_create() (workers inherit them blocked) and unblocks them
# only in the main thread, so the kernel always picks the main thread's
# EINTR-able receive loop for delivery.
#
# What this runs: a small harness replicating avd's exact mask sequence
# (block -> spawn worker -> unblock in main only) then delivers 50
# process-directed kills from the worker and asserts every one ran its
# handler on the main thread and woke its blocking pause(). 50 rounds
# (not 1): with the mask left unblocked delivery is a coin flip per
# round, so one round would pass unfixed code half the time, while 50
# consecutive main-thread deliveries by chance is ~2^-50. The harness
# uses alarm(15) so a regression that re-hangs delivery fails loudly
# instead of wedging CI.
#
# Pure userspace, no kernel module or root needed - safe standalone:
#   tests/test_avd_sigroute.sh
#
set -euo pipefail

BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/av_test_sigroute.XXXXXX")" || exit 1
cleanup() { rm -rf "$BUILD_DIR"; }
trap cleanup EXIT

cat > "$BUILD_DIR/sigroute.c" <<'EOF'
/* Harness for tests/test_avd_sigroute.sh - mirrors avd.c main()'s
 * signal-mask sequence (pthread_sigmask(SIG_BLOCK) before
 * pthread_create(), SIG_UNBLOCK in the main thread only) and checks
 * process-directed SIGTERM always lands on the main thread. Not part
 * of the shipped avd binary. */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define ROUNDS 50

static volatile sig_atomic_t got;
static pid_t main_tid;
static pid_t handler_tid;

static pid_t gettid_self(void) { return (pid_t)syscall(SYS_gettid); }

static void on_term(int signum) {
  (void)signum;
  handler_tid = gettid_self();
  got = 1;
}

static int ack_pipe[2];

static void *worker_main(void *arg) {
  char c;
  int i;
  sigset_t cur;

  (void)arg;

  /* Regression check on the first half of avd's fix: the worker must
   * inherit SIGTERM blocked. If it didn't, the kernel could deliver a
   * process-directed SIGTERM here instead of to the main thread. */
  pthread_sigmask(SIG_BLOCK, NULL, &cur);
  if (!sigismember(&cur, SIGTERM)) {
    fprintf(stderr, "FAIL: worker thread inherited SIGTERM unblocked\n");
    _exit(3);
  }

  /* Each round: wait for the main thread's ack (meaning it has armed
   * got = 0 and is parked in pause()), then send one process-directed
   * SIGTERM exactly as kill(1)/systemctl stop/Ctrl-C would. */
  for (i = 0; i < ROUNDS; i++) {
    ssize_t n;

    do {
      n = read(ack_pipe[0], &c, 1);
    } while (n < 0 && errno == EINTR);
    if (n != 1) {
      fprintf(stderr, "FAIL: worker ack read failed: %s\n", strerror(errno));
      _exit(4);
    }
    if (kill(getpid(), SIGTERM) != 0) {
      fprintf(stderr, "FAIL: kill failed: %s\n", strerror(errno));
      _exit(4);
    }
  }
  return NULL;
}

int main(void) {
  struct sigaction sa;
  sigset_t block;
  pthread_t worker;
  int i;

  main_tid = gettid_self();

  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = on_term;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0; /* no SA_RESTART, same as avd.c: pause() must EINTR out */
  if (sigaction(SIGTERM, &sa, NULL) != 0) {
    fprintf(stderr, "FAIL: sigaction: %s\n", strerror(errno));
    return 2;
  }

  /* avd.c's sequence: block before pthread_create() ... */
  sigemptyset(&block);
  sigaddset(&block, SIGTERM);
  if (pthread_sigmask(SIG_BLOCK, &block, NULL) != 0) {
    fprintf(stderr, "FAIL: block: %s\n", strerror(errno));
    return 2;
  }

  if (pipe(ack_pipe) != 0) {
    fprintf(stderr, "FAIL: pipe: %s\n", strerror(errno));
    return 2;
  }
  if (pthread_create(&worker, NULL, worker_main, NULL) != 0) {
    fprintf(stderr, "FAIL: pthread_create: %s\n", strerror(errno));
    return 2;
  }

  /* ... unblock in the main thread only. */
  if (pthread_sigmask(SIG_UNBLOCK, &block, NULL) != 0) {
    fprintf(stderr, "FAIL: unblock: %s\n", strerror(errno));
    return 2;
  }

  /* Hang guard: a routing regression parks the main thread in pause()
   * past the ack with nothing to wake it. Die loudly instead of
   * wedging the suite (default SIGALRM disposition terminates us). */
  alarm(15);

  for (i = 0; i < ROUNDS; i++) {
    got = 0;
    /* Arm-then-ack ordering matters: the worker may only kill after
     * this ack, and the ack is written after got = 0, so a delivery
     * can never slip in between and get clobbered by the reset. */
    if (write(ack_pipe[1], "x", 1) != 1) {
      fprintf(stderr, "FAIL: ack write: %s\n", strerror(errno));
      return 2;
    }
    while (!got)
      pause(); /* EINTRs out via on_term, same shape as avd's recv loop */
    if (handler_tid != main_tid) {
      fprintf(stderr,
              "FAIL: round %d: handler ran on tid %d, main is %d "
              "(signal landed on worker thread)\n",
              i, (int)handler_tid, (int)main_tid);
      return 1;
    }
  }

  alarm(0);
  pthread_join(worker, NULL);
  printf("PASS: %d/%d process-directed SIGTERMs handled on main thread\n",
         ROUNDS, ROUNDS);
  return 0;
}
EOF

CC="${CC:-gcc}"
# shellcheck disable=SC2086
$CC -Wall -Wextra -O2 -o "$BUILD_DIR/sigroute" "$BUILD_DIR/sigroute.c" -pthread
"$BUILD_DIR/sigroute"
