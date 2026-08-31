/*
 * avctl - userspace CLI for /proc/kernel_av_signatures,
 * /proc/kernel_av_trusted, /proc/kernel_av_protected, and
 * /proc/kernel_av_daemon_policy.
 *
 * Usage:
 *   avctl add <md5|sha1|sha256> <hex> <name>
 *   avctl del <md5|sha1|sha256> <hex>
 *   avctl list
 *   avctl trust add <sha256-hex> <name>
 *   avctl trust del <sha256-hex>
 *   avctl trust list
 *   avctl protect add <absolute-path>
 *   avctl protect del <absolute-path>
 *   avctl protect list
 *   avctl policy get
 *   avctl policy set <fail-open|fail-closed>
 *   avctl save <file>
 *   avctl load <file>
 *   avctl scan <absolute-path>
 *   avctl quarantine list
 *   avctl quarantine restore <id>
 *   avctl quarantine delete <id>
 *
 * The four /proc-backed groups above (sig/trust/protect/policy) talk
 * directly to the av kernel module, same as always. scan/quarantine
 * are different: they talk to avd's control socket instead (see
 * docs/avd-socket-protocol.md) - avd, not the kernel module, is what
 * runs YARA/fuzzy/TLSH scanning and owns the quarantine directory.
 * `avd` must be running for these three commands; the /proc-backed
 * ones only need the kernel module loaded, independent of avd.
 *
 * This is a plain userspace program (built with the host's regular gcc,
 * NOT the kernel headers/toolchain - see Makefile in this directory).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/un.h>

#define PROC_PATH "/proc/kernel_av_signatures"
#define TRUST_PROC_PATH "/proc/kernel_av_trusted"
#define PROTECTED_PROC_PATH "/proc/kernel_av_protected"
#define POLICY_PROC_PATH "/proc/kernel_av_daemon_policy"

/* Matches avd's own DEFAULT_CONTROL_SOCK_PATH (userspace/avd/avd.c) -
 * not shared via a header since the two sides only need to agree on
 * the plain-text wire protocol (docs/avd-socket-protocol.md), not on
 * any C struct. Override with AVD_SOCK_PATH, same env var avd itself
 * accepts, for tests/non-default installs. */
#define CONTROL_SOCK_PATH_DEFAULT "/run/avd/control.sock"

/* Must match the kernel side's own field-width limits: AV_HASH_HEX_MAXLEN
 * (av/sigtable.h) / SHA256_HEX_LEN (av/behavior.c) for hashes, and
 * AV_SIG_NAME_LEN-1 (av/sigtable.h) / TRUST_NAME_LEN-1 (av/behavior.c)
 * for names - i.e. sig_proc_write()'s and trust_proc_write()'s
 * "%64s %63[^\n]" sscanf() field widths. Not #include'd directly (those
 * are kernel-only headers pulling in <linux/types.h>) - mirrored here
 * as the userspace-side half of the same contract. Checking the total
 * formatted `cmd` buffer against sizeof(cmd) (as every command below
 * already does) catches an oversized WRITE, but not an oversized
 * INDIVIDUAL FIELD that still fits in cmd[] - the kernel's sscanf()
 * would silently truncate/misparse that field instead of avctl's own
 * snprintf(), so it has to be rejected here first. */
#define AVCTL_HASH_HEX_MAXLEN 64
#define AVCTL_NAME_MAXLEN 63

/* Rejects (rather than lets the kernel's own %Ns/%N[^\n] sscanf()
 * silently truncate) a hash/name/etc. field that's longer than the
 * kernel-side parser will actually accept, or that contains an
 * embedded newline. The newline case is its own kind of truncation:
 * the kernel's "%63[^\n]" name field stops at the first '\n' even when
 * the whole field is well under the length limit, so e.g. a name of
 * "first\nsecond" (under 63 bytes total) would sail through a
 * length-only check, get stored as just "first" on the kernel side,
 * yet still have avctl's own confirmation message echo back the full,
 * un-truncated caller-supplied string. */
static int check_field_len(const char *label, const char *s, size_t max)
{
    size_t len = strlen(s);

    if (strchr(s, '\n')) {
        fprintf(stderr, "avctl: %s must not contain a newline\n", label);
        return -1;
    }
    if (len > max) {
        fprintf(stderr, "avctl: %s too long (%zu bytes, max %zu)\n", label,
                len, max);
        return -1;
    }
    return 0;
}

/* Rejects anything that isn't exactly one of the three algorithm names
 * parse_algo() (av/sigtable.c) accepts, case-insensitively - not just
 * for the obvious "typo'd algorithm name" case, but because this is
 * also what stops a crafted algo argument containing embedded
 * whitespace (e.g. "sha256 <a second, attacker-chosen hash>") from
 * shifting sig_proc_write()'s "%7s %7s %64s %63[^\n]" field boundaries
 * and getting a different hash stored than the one avctl's own
 * confirmation message prints. None of the three real algorithm names
 * contain whitespace, so this check alone also closes that off. */
static int check_algo(const char *algo)
{
    if (strcasecmp(algo, "md5") && strcasecmp(algo, "sha1") &&
        strcasecmp(algo, "sha256")) {
        fprintf(stderr,
                "avctl: unknown algorithm \"%s\" (expected md5, sha1, or sha256)\n",
                algo);
        return -1;
    }
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s add <md5|sha1|sha256> <hex> <name>\n"
        "  %s del <md5|sha1|sha256> <hex>\n"
        "  %s list\n"
        "  %s trust add <sha256-hex> <name>\n"
        "  %s trust del <sha256-hex>\n"
        "  %s trust list\n"
        "  %s protect add <absolute-path>\n"
        "  %s protect del <absolute-path>\n"
        "  %s protect list\n"
        "  %s policy get\n"
        "  %s policy set <fail-open|fail-closed>\n"
        "  %s save <file|->\n"
        "  %s load <file>\n"
        "  %s scan <absolute-path>\n"
        "  %s quarantine list\n"
        "  %s quarantine restore <id>\n"
        "  %s quarantine delete <id>\n",
        prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog,
        prog, prog, prog, prog, prog, prog);
}

static int do_list_generic(const char *path, const char *header_algo)
{
    FILE *f = fopen(path, "r");
    char line[512];

    if (!f) {
        fprintf(stderr, "avctl: could not open %s: %s\n"
                         "(is the av module loaded? try: sudo insmod av.ko)\n",
                path, strerror(errno));
        return 1;
    }

    if (header_algo) {
        printf("%-8s %-64s %s\n", header_algo, "HASH", "NAME");
        while (fgets(line, sizeof(line), f)) {
            char algo[8], hex[65], name[128];
            if (sscanf(line, "%7s %64s %127[^\n]", algo, hex, name) == 3)
                printf("%-8s %-64s %s\n", algo, hex, name);
        }
    } else {
        printf("%-64s %s\n", "SHA256", "NAME");
        while (fgets(line, sizeof(line), f)) {
            char hex[65], name[128];
            if (sscanf(line, "%64s %127[^\n]", hex, name) == 2)
                printf("%-64s %s\n", hex, name);
        }
    }
    fclose(f);
    return 0;
}

static int do_list(void)
{
    return do_list_generic(PROC_PATH, "ALGO");
}

static int do_trust_list(void)
{
    return do_list_generic(TRUST_PROC_PATH, NULL);
}

/* Not do_list_generic(): the protected-path list is one path per
 * line, not hash/name pairs. */
static int do_protect_list(void)
{
    FILE *f = fopen(PROTECTED_PROC_PATH, "r");
    char line[PATH_MAX + 8];

    if (!f) {
        fprintf(stderr, "avctl: could not open %s: %s\n"
                         "(is the av module loaded? try: sudo insmod av.ko)\n",
                PROTECTED_PROC_PATH, strerror(errno));
        return 1;
    }

    printf("PROTECTED PATH\n");
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n')
            line[len - 1] = '\0';
        if (line[0])
            printf("%s\n", line);
    }
    fclose(f);
    return 0;
}

static int write_command_to(const char *path, const char *cmd)
{
    int fd = open(path, O_WRONLY);
    ssize_t written;
    int saved_errno;
    size_t cmd_len;
    char *buf;

    if (fd < 0) {
        saved_errno = errno;
        fprintf(stderr, "avctl: could not open %s: %s\n"
                         "(is the av module loaded? try: sudo insmod av.ko)\n",
                path, strerror(saved_errno));
        return -saved_errno;
    }

    /* Kernel-side proc write handlers require a trailing newline as an
     * explicit "this is a complete, non-truncated command" marker (see
     * protected_proc_write()'s comment in av/behavior.c) - build ONE
     * buffer with it appended and issue a SINGLE write() for the
     * whole thing, rather than a second write() call for just "\n"
     * afterward, which would itself land at a nonzero file offset and
     * get rejected as an unexpected continuation of the first. */
    cmd_len = strlen(cmd);
    buf = malloc(cmd_len + 2);
    if (!buf) {
        close(fd);
        fprintf(stderr, "avctl: out of memory\n");
        return -ENOMEM;
    }
    memcpy(buf, cmd, cmd_len);
    buf[cmd_len] = '\n';
    buf[cmd_len + 1] = '\0';

    written = write(fd, buf, cmd_len + 1);
    saved_errno = errno; /* capture before close()/free() can touch it */
    free(buf);
    close(fd);

    if (written < 0) {
        fprintf(stderr, "avctl: write failed: %s\n"
                         "(need sudo? malformed hash/algo?)\n", strerror(saved_errno));
        return -saved_errno;
    }

    return 0;
}

static int write_command(const char *cmd)
{
    return write_command_to(PROC_PATH, cmd);
}

/* save/load: /proc/kernel_av_signatures, /proc/kernel_av_trusted, and
 * /proc/kernel_av_daemon_policy are all in-memory kernel state with no
 * persistence of their own - everything resets to its default on
 * `rmmod` (the policy specifically always comes back up as fail-open,
 * regardless of what it was set to before unload). save dumps all
 * four into one file as replayable write-commands (not the
 * pretty-printed list() format); load replays them. A "sig ",
 * "trust ", "protect ", or "policy " line prefix says which /proc
 * file each line targets; the rest of the line is passed through
 * VERBATIM as the write() payload, so names/paths containing spaces
 * round-trip correctly (the underlying /proc write handlers already
 * treat everything after the hash/command as the rest-of-line value -
 * see sig_proc_write()/trust_proc_write()/protected_proc_write()/
 * daemon_policy_proc_write() in the kernel module). Line buffer sized
 * for PATH_MAX (protected-path entries can be much longer than a
 * sha256 signature/name line).
 *
 * Written to a `path.tmp` temp file first, then rename()'d into place
 * only once every write and both fclose()s have succeeded - a plain
 * fopen(path, "w") would let a mid-dump failure (disk full, a /proc
 * read that goes away) leave a truncated file at `path` with a "success"
 * exit code indistinguishable from a real, complete snapshot. That
 * distinction matters beyond this file: scripts/av-reload.sh trusts
 * do_save()'s exit code alone to decide whether it's safe to rmmod.
 *
 * path == "-": writes the same replayable line format straight to
 * stdout instead of a file - used by callers that want machine-
 * parseable current state without a throwaway save file (the GUI's
 * unprivileged periodic refresh of signatures/trust/protected/policy
 * runs plain `avctl save -`, no root needed - see
 * docs/avd-socket-protocol.md's note on why this reuses save's
 * existing format rather than adding a second read protocol). No
 * atomic tmp-file+rename dance in this mode: that exists to protect an
 * ON-DISK snapshot from a mid-write failure leaving a truncated-but-
 * "successful" file at `path` (see above) - a pipe has no such
 * leftover-corrupt-file failure mode to protect against. The summary
 * line goes to stderr instead of stdout in this mode, so stdout stays
 * pure, directly-parseable data for the caller. */
static void save_abort(FILE *out, const char *tmp_path, int to_stdout)
{
    if (!to_stdout) {
        fclose(out);
        unlink(tmp_path);
    }
}

static int do_save(const char *path)
{
    FILE *out;
    FILE *in;
    char line[PATH_MAX + 16];
    char tmp_path[PATH_MAX + 8];
    int sig_count = 0, trust_count = 0, protect_count = 0;
    int werr = 0;
    int to_stdout = !strcmp(path, "-");

    if (to_stdout) {
        out = stdout;
    } else {
        if (strlen(path) >= PATH_MAX) {
            fprintf(stderr, "avctl: path too long (max %d bytes)\n", PATH_MAX - 1);
            return 1;
        }
        snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);

        out = fopen(tmp_path, "w");
        if (!out) {
            fprintf(stderr, "avctl: could not open %s for writing: %s\n",
                    tmp_path, strerror(errno));
            return 1;
        }

        werr |= fprintf(out, "# kernel-av state dump - replay with: avctl load %s\n", path) < 0;
    }

    in = fopen(PROC_PATH, "r");
    if (!in) {
        fprintf(stderr, "avctl: could not open %s: %s\n"
                         "(is the av module loaded? try: sudo insmod av.ko)\n",
                PROC_PATH, strerror(errno));
        save_abort(out, tmp_path, to_stdout);
        return 1;
    }
    while (fgets(line, sizeof(line), in)) {
        char algo[8], hex[65], name[128];

        if (sscanf(line, "%7s %64s %127[^\n]", algo, hex, name) == 3) {
            werr |= fprintf(out, "sig add %s %s %s\n", algo, hex, name) < 0;
            sig_count++;
        }
    }
    fclose(in);

    in = fopen(TRUST_PROC_PATH, "r");
    if (!in) {
        fprintf(stderr, "avctl: could not open %s: %s\n"
                         "(is the av module loaded? try: sudo insmod av.ko)\n",
                TRUST_PROC_PATH, strerror(errno));
        save_abort(out, tmp_path, to_stdout);
        return 1;
    }
    while (fgets(line, sizeof(line), in)) {
        char hex[65], name[128];

        if (sscanf(line, "%64s %127[^\n]", hex, name) == 2) {
            werr |= fprintf(out, "trust add %s %s\n", hex, name) < 0;
            trust_count++;
        }
    }
    fclose(in);

    in = fopen(PROTECTED_PROC_PATH, "r");
    if (!in) {
        fprintf(stderr, "avctl: could not open %s: %s\n"
                         "(is the av module loaded? try: sudo insmod av.ko)\n",
                PROTECTED_PROC_PATH, strerror(errno));
        save_abort(out, tmp_path, to_stdout);
        return 1;
    }
    while (fgets(line, sizeof(line), in)) {
        size_t len = strlen(line);

        if (len > 0 && line[len - 1] == '\n')
            line[len - 1] = '\0';
        if (line[0]) {
            werr |= fprintf(out, "protect add %s\n", line) < 0;
            protect_count++;
        }
    }
    fclose(in);

    in = fopen(POLICY_PROC_PATH, "r");
    if (!in) {
        fprintf(stderr, "avctl: could not open %s: %s\n"
                         "(is the av module loaded? try: sudo insmod av.ko)\n",
                POLICY_PROC_PATH, strerror(errno));
        save_abort(out, tmp_path, to_stdout);
        return 1;
    }
    if (fgets(line, sizeof(line), in)) {
        size_t len = strlen(line);

        if (len > 0 && line[len - 1] == '\n')
            line[len - 1] = '\0';
        if (line[0])
            werr |= fprintf(out, "policy %s\n", line) < 0;
    }
    fclose(in);

    if (to_stdout) {
        if (fflush(out) != 0)
            werr = 1;
        if (werr) {
            fprintf(stderr, "avctl: write error while saving to stdout\n");
            return 1;
        }
        fprintf(stderr,
                "saved %d signature(s), %d trusted entr%s, %d protected path%s, "
                "and the daemon-unavailable policy to stdout\n",
                sig_count, trust_count, trust_count == 1 ? "y" : "ies",
                protect_count, protect_count == 1 ? "" : "s");
        return 0;
    }

    if (fclose(out) != 0)
        werr = 1;

    if (werr) {
        fprintf(stderr, "avctl: write error while saving to %s\n", tmp_path);
        unlink(tmp_path);
        return 1;
    }

    if (rename(tmp_path, path) != 0) {
        fprintf(stderr, "avctl: could not rename %s to %s: %s\n",
                tmp_path, path, strerror(errno));
        unlink(tmp_path);
        return 1;
    }

    printf("saved %d signature(s), %d trusted entr%s, %d protected path%s, "
           "and the daemon-unavailable policy to %s\n",
           sig_count, trust_count, trust_count == 1 ? "y" : "ies",
           protect_count, protect_count == 1 ? "" : "s", path);
    return 0;
}

/* do_load() forwards each "sig "/"trust " line's fields (`rest`, the
 * text after that prefix) straight to write_command()/
 * write_command_to() - unlike do_trust()/the top-level add/del
 * commands, it never ran them through check_field_len()/check_algo()
 * first. A load file (hand-edited, or round-tripped through something
 * other than avctl's own `save`) with an oversized hash/name hits the
 * exact same kernel-side "%64s %63[^\n]" silent-misparse risk those
 * checks exist for. Parses just enough of `rest`'s own structure to
 * apply the same checks before forwarding - protect/policy lines have
 * no hash/name/algo fields in this shape, so this only covers "sig"/
 * "trust". Field buffers here are sized well beyond
 * AVCTL_HASH_HEX_MAXLEN/AVCTL_NAME_MAXLEN on purpose: reading (and
 * then rejecting) the true full length of an oversized field, rather
 * than quietly re-truncating it at the same width the kernel would
 * have, is what makes the length check meaningful. */
static int validate_sig_or_trust_fields(const char *kind, const char *rest)
{
    char op[8], field_a[512], field_b[512];
    int n;

    if (!strcmp(kind, "sig")) {
        char algo[8];

        n = sscanf(rest, "%7s %7s %511s %511[^\n]", op, algo, field_a, field_b);
        if (n < 3)
            return 0; /* let write_command() report the real parse error */
        if (check_algo(algo))
            return -1;
        if (check_field_len("hash", field_a, AVCTL_HASH_HEX_MAXLEN))
            return -1;
        if (n == 4 && check_field_len("name", field_b, AVCTL_NAME_MAXLEN))
            return -1;
    } else {
        n = sscanf(rest, "%7s %511s %511[^\n]", op, field_a, field_b);
        if (n < 2)
            return 0;
        if (check_field_len("hash", field_a, AVCTL_HASH_HEX_MAXLEN))
            return -1;
        if (n == 3 && check_field_len("name", field_b, AVCTL_NAME_MAXLEN))
            return -1;
    }
    return 0;
}

static int do_load(const char *path)
{
    FILE *f = fopen(path, "r");
    char line[PATH_MAX + 16];
    int loaded = 0, skipped = 0, errors = 0;

    if (!f) {
        fprintf(stderr, "avctl: could not open %s: %s\n", path, strerror(errno));
        return 1;
    }

    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        const char *rest;
        int ret;

        if (len > 0 && line[len - 1] == '\n')
            line[--len] = '\0';
        if (line[0] == '\0' || line[0] == '#')
            continue;

        if (!strncmp(line, "sig ", 4)) {
            rest = line + 4;
            if (validate_sig_or_trust_fields("sig", rest)) {
                errors++;
                continue;
            }
            ret = write_command(rest);
        } else if (!strncmp(line, "trust ", 6)) {
            rest = line + 6;
            if (validate_sig_or_trust_fields("trust", rest)) {
                errors++;
                continue;
            }
            ret = write_command_to(TRUST_PROC_PATH, rest);
        } else if (!strncmp(line, "protect ", 8)) {
            rest = line + 8;
            ret = write_command_to(PROTECTED_PROC_PATH, rest);
        } else if (!strncmp(line, "policy ", 7)) {
            rest = line + 7;
            ret = write_command_to(POLICY_PROC_PATH, rest);
        } else {
            fprintf(stderr, "avctl: load: malformed line (expected "
                             "'sig ', 'trust ', 'protect ', or 'policy ' "
                             "prefix): %s\n",
                    line);
            errors++;
            continue;
        }

        if (ret == -EEXIST) {
            /* Expected on a re-load: the module always seeds the
             * default EICAR test signature at insmod time, so
             * replaying a save file taken after that seed will hit
             * this for that one entry specifically. Not a failure. */
            printf("already present, skipping: %s\n", rest);
            skipped++;
        } else if (ret) {
            fprintf(stderr, "avctl: load: failed on line: %s\n", line);
            errors++;
        } else {
            loaded++;
        }
    }
    fclose(f);

    printf("loaded %d, skipped %d (already present), %d error%s\n",
           loaded, skipped, errors, errors == 1 ? "" : "s");

    return errors ? 1 : 0;
}

static int do_trust(int argc, char **argv)
{
    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    if (!strcmp(argv[2], "list")) {
        return do_trust_list();
    } else if (!strcmp(argv[2], "add")) {
        char cmd[256];
        char name[192];
        size_t off = 0;
        int i, n;

        if (argc < 5) {
            usage(argv[0]);
            return 1;
        }

        if (check_field_len("hash", argv[3], AVCTL_HASH_HEX_MAXLEN))
            return 1;

        /* Join every remaining argv[] into one space-separated name
         * instead of using only argv[4] - the kernel side's
         * trust_proc_write() already parses the rest of the line as
         * the name via "%63[^\n]" (save/load round-trip multi-word
         * names fine through that same path), so an unquoted
         * multi-word name like `avctl trust add <hash> My Program`
         * was silently losing everything after the first word only
         * because avctl itself dropped it before it ever reached the
         * kernel. */
        name[0] = '\0';
        for (i = 4; i < argc && off < sizeof(name) - 1; i++) {
            int m = snprintf(name + off, sizeof(name) - off, "%s%s",
                              i > 4 ? " " : "", argv[i]);
            /* m >= remaining means snprintf() would have truncated -
             * reject rather than silently store a cut-off name (it
             * would then also silently pass the AVCTL_NAME_MAXLEN
             * check below despite the caller's real name being
             * longer). */
            if (m < 0 || (size_t)m >= sizeof(name) - off) {
                fprintf(stderr, "avctl: name too long\n");
                return 1;
            }
            off += (size_t)m;
        }

        if (check_field_len("name", name, AVCTL_NAME_MAXLEN))
            return 1;

        /* Reject rather than let snprintf() below silently truncate -
         * a truncated write would ask the kernel to trust a DIFFERENT
         * (shorter) hash than the one printed back to the caller, with
         * no error either side. Same reasoning as do_protect()'s
         * add/del length checks. */
        n = snprintf(cmd, sizeof(cmd), "add %s %s", argv[3], name);
        if (n < 0 || (size_t)n >= sizeof(cmd)) {
            fprintf(stderr, "avctl: hash/name too long to format\n");
            return 1;
        }
        if (write_command_to(TRUST_PROC_PATH, cmd))
            return 1;
        printf("trusted: %s (%s)\n", argv[3], name);
    } else if (!strcmp(argv[2], "del")) {
        char cmd[256];
        int n;

        if (argc < 4) {
            usage(argv[0]);
            return 1;
        }
        if (check_field_len("hash", argv[3], AVCTL_HASH_HEX_MAXLEN))
            return 1;
        n = snprintf(cmd, sizeof(cmd), "del %s", argv[3]);
        if (n < 0 || (size_t)n >= sizeof(cmd)) {
            fprintf(stderr, "avctl: hash too long to format\n");
            return 1;
        }
        if (write_command_to(TRUST_PROC_PATH, cmd))
            return 1;
        printf("untrusted: %s\n", argv[3]);
    } else {
        usage(argv[0]);
        return 1;
    }

    return 0;
}

static int do_protect(int argc, char **argv)
{
    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    if (!strcmp(argv[2], "list")) {
        return do_protect_list();
    } else if (!strcmp(argv[2], "add")) {
        char cmd[PATH_MAX + 8];
        int n;

        if (argc < 4) {
            usage(argv[0]);
            return 1;
        }
        if (argv[3][0] != '/') {
            fprintf(stderr, "avctl: protect add requires an absolute path\n");
            return 1;
        }
        /* check_field_len(), not just a length check: a truncated
         * write would ask the kernel side to protect a DIFFERENT
         * (shorter) path than the one printed back to the caller with
         * no error either side, and '\n' is a legal byte in a Linux
         * filename that would truncate the same way at the kernel's
         * line-oriented proc parser - same reasoning as
         * do_quarantine_restore()'s identical check. */
        if (check_field_len("path", argv[3], PATH_MAX - 1))
            return 1;
        n = snprintf(cmd, sizeof(cmd), "add %s", argv[3]);
        if (n < 0 || (size_t)n >= sizeof(cmd)) {
            fprintf(stderr, "avctl: path too long to format\n");
            return 1;
        }
        if (write_command_to(PROTECTED_PROC_PATH, cmd))
            return 1;
        printf("protected: %s\n", argv[3]);
    } else if (!strcmp(argv[2], "del")) {
        char cmd[PATH_MAX + 8];
        int n;

        if (argc < 4) {
            usage(argv[0]);
            return 1;
        }
        /* See the "add" branch above for why this is check_field_len()
         * and not just a length check. */
        if (check_field_len("path", argv[3], PATH_MAX - 1))
            return 1;
        n = snprintf(cmd, sizeof(cmd), "del %s", argv[3]);
        if (n < 0 || (size_t)n >= sizeof(cmd)) {
            fprintf(stderr, "avctl: path too long to format\n");
            return 1;
        }
        if (write_command_to(PROTECTED_PROC_PATH, cmd))
            return 1;
        printf("unprotected: %s\n", argv[3]);
    } else {
        usage(argv[0]);
        return 1;
    }

    return 0;
}

/* Unlike sig/trust/protect's "add"/"del" verbs, the kernel side here
 * (daemon_policy_proc_write() in av/main.c) expects the raw value
 * ("fail-open" or "fail-closed") with no leading verb - so `set`
 * passes argv[3] straight through to write_command_to() rather than
 * building a "<verb> <value>" command string. */
static int do_policy(int argc, char **argv)
{
    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    if (!strcmp(argv[2], "get")) {
        FILE *f = fopen(POLICY_PROC_PATH, "r");
        char line[32];

        if (!f) {
            fprintf(stderr, "avctl: could not open %s: %s\n"
                             "(is the av module loaded? try: sudo insmod av.ko)\n",
                    POLICY_PROC_PATH, strerror(errno));
            return 1;
        }
        if (fgets(line, sizeof(line), f))
            fputs(line, stdout);
        fclose(f);
    } else if (!strcmp(argv[2], "set")) {
        if (argc < 4) {
            usage(argv[0]);
            return 1;
        }
        if (strcmp(argv[3], "fail-open") && strcmp(argv[3], "fail-closed")) {
            fprintf(stderr, "avctl: policy set requires fail-open or "
                             "fail-closed, got: %s\n", argv[3]);
            return 1;
        }
        if (write_command_to(POLICY_PROC_PATH, argv[3]))
            return 1;
        printf("daemon-unavailable policy: %s\n", argv[3]);
    } else {
        usage(argv[0]);
        return 1;
    }

    return 0;
}

/* ------------------------------------------------------------------
 * avd control socket client - scan/quarantine. See
 * docs/avd-socket-protocol.md for the wire protocol this speaks.
 * ------------------------------------------------------------------ */

static const char *control_sock_path(void)
{
    const char *p = getenv("AVD_SOCK_PATH");
    return p ? p : CONTROL_SOCK_PATH_DEFAULT;
}

/*
 * Connects to avd's control socket, sends `cmd` followed by a newline,
 * and reads the whole response into a malloc'd, NUL-terminated buffer
 * (caller frees it via *out). avd closes the connection after exactly
 * one response (one command per connection - see
 * docs/avd-socket-protocol.md), so reading until EOF is how a client
 * knows the response is complete; no length prefix needed. Returns 0
 * with *out set on success, -1 (with an error already printed) on any
 * connection/IO failure.
 */
static int control_request(const char *cmd, char **out)
{
    struct sockaddr_un addr;
    char *buf, *grown;
    size_t cap, len, cmd_len;
    ssize_t n;
    char *req;
    int fd;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "avctl: socket() failed: %s\n", strerror(errno));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", control_sock_path());

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr,
                "avctl: could not connect to avd control socket %s: %s\n"
                "(is avd running? try: systemctl status avd)\n",
                control_sock_path(), strerror(errno));
        close(fd);
        return -1;
    }

    cmd_len = strlen(cmd);
    req = malloc(cmd_len + 2);
    if (!req) {
        fprintf(stderr, "avctl: out of memory\n");
        close(fd);
        return -1;
    }
    memcpy(req, cmd, cmd_len);
    req[cmd_len] = '\n';
    req[cmd_len + 1] = '\0';
    n = write(fd, req, cmd_len + 1);
    free(req);
    if (n != (ssize_t)(cmd_len + 1)) {
        fprintf(stderr, "avctl: write to control socket failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    shutdown(fd, SHUT_WR);

    cap = 65536;
    buf = malloc(cap);
    if (!buf) {
        fprintf(stderr, "avctl: out of memory\n");
        close(fd);
        return -1;
    }
    len = 0;
    for (;;) {
        n = read(fd, buf + len, cap - len - 1);
        if (n < 0) {
            /* A signal arriving mid-read makes read() return -1/EINTR
             * even though the connection is fine and more of the
             * response may still be coming - retry rather than
             * treating an interrupted call as a real failure (same
             * EINTR handling as write_all()/read_line() on avd's side
             * of this same protocol). */
            if (errno == EINTR)
                continue;
            break;
        }
        if (n == 0)
            break;
        len += (size_t)n;
        if (len >= cap - 1) {
            cap *= 2;
            grown = realloc(buf, cap);
            if (!grown) {
                fprintf(stderr, "avctl: out of memory\n");
                free(buf);
                close(fd);
                return -1;
            }
            buf = grown;
        }
    }
    close(fd);

    if (n < 0) {
        fprintf(stderr, "avctl: read from control socket failed: %s\n", strerror(errno));
        free(buf);
        return -1;
    }

    buf[len] = '\0';
    *out = buf;
    return 0;
}

/*
 * Splits *cursor at the next '\n' (mutating the buffer in place, same
 * way strtok() would - fine here since `resp` is a private, one-shot
 * heap buffer nothing else reads), returning the line just consumed
 * and advancing *cursor past it. Returns NULL once *cursor is empty.
 */
static char *next_line(char **cursor)
{
    char *start = *cursor;
    char *nl;

    if (!start || !*start)
        return NULL;

    nl = strchr(start, '\n');
    if (nl) {
        *nl = '\0';
        *cursor = nl + 1;
    } else {
        *cursor = start + strlen(start);
    }
    return start;
}

/*
 * Consumes and checks the response's first line: "OK" returns 1,
 * leaving *cursor positioned right after it for callers that need
 * more lines (e.g. do_quarantine_list()'s COUNT/rows). "ERR <msg>"
 * prints <msg> to stderr and returns 0; anything else is treated as a
 * protocol error, also reported, also returns 0.
 */
static int expect_ok(char **cursor)
{
    const char *line = next_line(cursor);

    if (line && !strcmp(line, "OK"))
        return 1;
    if (line && !strncmp(line, "ERR ", 4))
        fprintf(stderr, "avctl: %s\n", line + 4);
    else
        fprintf(stderr, "avctl: malformed response from avd control socket\n");
    return 0;
}

static int do_scan(const char *path)
{
    char cmd[PATH_MAX + 8];
    char *resp, *cursor;
    const char *line;
    int n;

    if (path[0] != '/') {
        fprintf(stderr, "avctl: scan requires an absolute path\n");
        return 1;
    }
    /* check_field_len() rather than a bare length check: a path is a
     * filename component away from user control (av-gui's scan page
     * takes it straight from a GtkFileDialog, and '\n' is a legal
     * byte in a Linux filename), and this is formatted straight into
     * a line-oriented control-socket command below - see
     * do_quarantine_restore()'s identical comment for why an embedded
     * newline here would let a crafted path smuggle a second,
     * attacker-influenced line past avd's parser. */
    if (check_field_len("path", path, PATH_MAX - 1))
        return 1;
    n = snprintf(cmd, sizeof(cmd), "SCAN %s", path);
    if (n < 0 || (size_t)n >= sizeof(cmd)) {
        fprintf(stderr, "avctl: path too long to format\n");
        return 1;
    }

    if (control_request(cmd, &resp))
        return 1;

    cursor = resp;
    if (!expect_ok(&cursor)) {
        free(resp);
        return 1;
    }

    next_line(&cursor); /* "COUNT 1" - always exactly one row for SCAN */
    line = next_line(&cursor);
    if (line) {
        char verdict[16] = "", rule[128] = "", sha[128] = "";
        int score = 0;

        sscanf(line, "%15[^\t]\t%127[^\t]\t%d\t%127[^\t\n]", verdict, rule,
               &score, sha);
        if (!strcmp(verdict, "MALICIOUS"))
            printf("MALICIOUS: %s%s%s (score=%d)\nsha256: %s\n", path,
                   rule[0] ? " - " : "", rule, score, sha);
        else
            printf("CLEAN: %s\nsha256: %s\n", path, sha);
    } else {
        fprintf(stderr, "avctl: malformed scan response from avd\n");
        free(resp);
        return 1;
    }

    free(resp);
    return 0;
}

static int do_quarantine_list(void)
{
    char *resp, *cursor;
    const char *line;

    if (control_request("QUARANTINE LIST", &resp))
        return 1;

    cursor = resp;
    if (!expect_ok(&cursor)) {
        free(resp);
        return 1;
    }
    next_line(&cursor); /* "COUNT n" - row count already implicit in
                         * how many rows follow before END, no need to
                         * parse the number out separately here */

    printf("%-40s %-6s %-20s %s\n", "ID", "RULE", "TIMESTAMP", "ORIGINAL PATH");
    while ((line = next_line(&cursor)) != NULL && strcmp(line, "END")) {
        char id[256] = "", path[PATH_MAX] = "", rule[128] = "", sha[128] = "";
        /* Path field width built from sizeof(path) - 1, not a
         * hardcoded 4095 - scanf field widths can't take a runtime
         * '*' argument the way printf precision can, so the format
         * string itself is built at runtime instead. This keeps the
         * width tied to the actual buffer size even if PATH_MAX (or
         * this array) ever changes, rather than a magic number that
         * could silently drift out of sync with it. */
        char fmt[64];
        long ts = 0;
        int fmt_len;

        fmt_len = snprintf(fmt, sizeof(fmt),
                            "%%255[^\t]\t%%%zu[^\t]\t%%ld\t%%127[^\t]\t%%127[^\t\n]",
                            sizeof(path) - 1);
        if (fmt_len < 0 || (size_t)fmt_len >= sizeof(fmt))
            continue; /* shouldn't happen - fmt is generously sized */

        sscanf(line, fmt, id, path, &ts, rule, sha);
        (void)sha; /* not shown in the table - avctl quarantine list is a
                   * human-facing summary; the GUI reads the same
                   * response and shows the full sha256 itself */
        printf("%-40s %-6s %-20ld %s\n", id, rule, ts, path);
    }

    free(resp);
    return 0;
}

/* Not tied to a kernel-side field width like AVCTL_HASH_HEX_MAXLEN/
 * AVCTL_NAME_MAXLEN above - avd's own quarantine_id_valid()
 * (userspace/avd/avd.c) is what actually bounds a valid id, at
 * PATH_MAX - 32. This just needs to be comfortably under
 * do_quarantine_restore()/do_quarantine_delete()'s cmd[300] buffer so
 * check_field_len() rejects an oversized/newline-containing id before
 * the snprintf() truncation check below even runs. */
#define AVCTL_ID_MAXLEN 255

static int do_quarantine_restore(const char *id)
{
    char cmd[300];
    char *resp, *cursor;
    int n;

    /* Every other field formatted into a control-socket command
     * (hash, name, path) is run through check_field_len(), which
     * rejects both an over-length value and one containing an
     * embedded newline - a raw newline here would let a
     * caller-supplied id make avd's line-oriented parser see a
     * second, attacker-influenced line. */
    if (check_field_len("id", id, AVCTL_ID_MAXLEN))
        return 1;

    /* Reject up front rather than letting snprintf() silently
     * truncate: a truncated id would ask avd to restore a DIFFERENT
     * (shorter, likely nonexistent) quarantine entry than the one
     * named on the command line, with no error either side - same
     * reasoning as do_protect()'s identical up-front length check. */
    n = snprintf(cmd, sizeof(cmd), "QUARANTINE RESTORE %s", id);
    if (n < 0 || (size_t)n >= sizeof(cmd)) {
        fprintf(stderr, "avctl: quarantine id too long\n");
        return 1;
    }
    if (control_request(cmd, &resp))
        return 1;

    cursor = resp;
    if (!expect_ok(&cursor)) {
        free(resp);
        return 1;
    }
    printf("restored: %s\n", id);
    free(resp);
    return 0;
}

static int do_quarantine_delete(const char *id)
{
    char cmd[300];
    char *resp, *cursor;
    int n;

    /* See do_quarantine_restore()'s identical check for why this
     * rejects an embedded newline. */
    if (check_field_len("id", id, AVCTL_ID_MAXLEN))
        return 1;

    /* See do_quarantine_restore()'s identical check for why this
     * rejects rather than lets snprintf() silently truncate. */
    n = snprintf(cmd, sizeof(cmd), "QUARANTINE DELETE %s", id);
    if (n < 0 || (size_t)n >= sizeof(cmd)) {
        fprintf(stderr, "avctl: quarantine id too long\n");
        return 1;
    }
    if (control_request(cmd, &resp))
        return 1;

    cursor = resp;
    if (!expect_ok(&cursor)) {
        free(resp);
        return 1;
    }
    printf("deleted: %s\n", id);
    free(resp);
    return 0;
}

static int do_quarantine(int argc, char **argv)
{
    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    if (!strcmp(argv[2], "list")) {
        return do_quarantine_list();
    } else if (!strcmp(argv[2], "restore")) {
        if (argc < 4) {
            usage(argv[0]);
            return 1;
        }
        return do_quarantine_restore(argv[3]);
    } else if (!strcmp(argv[2], "delete")) {
        if (argc < 4) {
            usage(argv[0]);
            return 1;
        }
        return do_quarantine_delete(argv[3]);
    } else {
        usage(argv[0]);
        return 1;
    }
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (!strcmp(argv[1], "list")) {
        return do_list();
    } else if (!strcmp(argv[1], "trust")) {
        return do_trust(argc, argv);
    } else if (!strcmp(argv[1], "protect")) {
        return do_protect(argc, argv);
    } else if (!strcmp(argv[1], "policy")) {
        return do_policy(argc, argv);
    } else if (!strcmp(argv[1], "save")) {
        if (argc < 3) {
            usage(argv[0]);
            return 1;
        }
        return do_save(argv[2]);
    } else if (!strcmp(argv[1], "load")) {
        if (argc < 3) {
            usage(argv[0]);
            return 1;
        }
        return do_load(argv[2]);
    } else if (!strcmp(argv[1], "scan")) {
        if (argc < 3) {
            usage(argv[0]);
            return 1;
        }
        return do_scan(argv[2]);
    } else if (!strcmp(argv[1], "quarantine")) {
        return do_quarantine(argc, argv);
    } else if (!strcmp(argv[1], "add")) {
        char cmd[256];
        int n;

        if (argc < 5) {
            usage(argv[0]);
            return 1;
        }
        if (check_algo(argv[2]))
            return 1;
        if (check_field_len("hash", argv[3], AVCTL_HASH_HEX_MAXLEN))
            return 1;
        if (check_field_len("name", argv[4], AVCTL_NAME_MAXLEN))
            return 1;
        /* Reject rather than let snprintf() below silently truncate -
         * a truncated write would register a DIFFERENT (shorter) hash
         * in the kernel than the one printed back to the caller, with
         * no error either side. Same reasoning as do_protect()'s
         * add/del length checks. */
        n = snprintf(cmd, sizeof(cmd), "add %s %s %s", argv[2], argv[3], argv[4]);
        if (n < 0 || (size_t)n >= sizeof(cmd)) {
            fprintf(stderr, "avctl: signature type/hash/name too long to format\n");
            return 1;
        }
        if (write_command(cmd))
            return 1;
        printf("added %s signature: %s (%s)\n", argv[2], argv[3], argv[4]);
    } else if (!strcmp(argv[1], "del")) {
        char cmd[256];
        int n;

        if (argc < 4) {
            usage(argv[0]);
            return 1;
        }
        if (check_algo(argv[2]))
            return 1;
        if (check_field_len("hash", argv[3], AVCTL_HASH_HEX_MAXLEN))
            return 1;
        n = snprintf(cmd, sizeof(cmd), "del %s %s", argv[2], argv[3]);
        if (n < 0 || (size_t)n >= sizeof(cmd)) {
            fprintf(stderr, "avctl: signature type/hash too long to format\n");
            return 1;
        }
        if (write_command(cmd))
            return 1;
        printf("removed %s signature: %s\n", argv[2], argv[3]);
    } else {
        usage(argv[0]);
        return 1;
    }

    return 0;
}
