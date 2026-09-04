"""Resolve the avctl binary path for av-gui's two call sites.

procfs_client.py calls avctl directly, unprivileged (`avctl save -`);
pkexec_helper.py calls it via pkexec, privileged (`pkexec avctl ...`).
Both historically did `os.environ.get("AVCTL_PATH", "/usr/local/bin/avctl")`
with no validation. For the unprivileged read path that only risks showing
fake data; for the pkexec path an attacker-controlled AVCTL_PATH could get
pkexec'd with elevated trust for the wrong binary while the polkit policy
(`packaging/org.hyprav.avctl.policy`) only authorizes the installed
`@BINDIR@/avctl` (issue #97).

The privileged resolver below is therefore strict: an env-provided path is
used only if it is absolute, resolves (via realpath) to a basename of
`avctl`, and is a root-owned, non-group/other-writable regular file that is
executable. Anything else falls back to the first existing system default.
The full cross-check against the policy's exact exec.path still happens in
polkit itself (a non-matching path is denied or falls back to the generic
org.freedesktop.policykit.exec action); this check just guarantees we never
ask pkexec to elevate anything but a system-owned avctl in the first place.

Inside a Flatpak sandbox (see host_exec.py) the host's filesystem is not
visible, so ownership/existence checks would always fail even for the
legitimate host avctl. There we only enforce "absolute + basename avctl"
and leave enforcement to host-side pkexec/polkit.
"""
import os
import stat

from . import host_exec

DEFAULT_AVCTL_PATH = "/usr/local/bin/avctl"
_FALLBACK_CANDIDATES = ("/usr/local/bin/avctl", "/usr/bin/avctl")


def _looks_like_avctl(real):
    """Returns True if a resolved path has avctl's expected basename."""
    return os.path.basename(real) == "avctl"


def _is_trusted_system_binary(real):
    """Returns True if `real` is a root-owned, non-writable-by-others
    executable regular file. Guards the pkexec path against an
    attacker planting or redirecting AVCTL_PATH to something they can
    modify."""
    try:
        st = os.stat(real)
    except OSError:
        return False
    if not stat.S_ISREG(st.st_mode):
        return False
    if not os.access(real, os.X_OK):
        return False
    if st.st_uid != 0:
        return False
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return False
    return True


def resolve_privileged_avctl_path():
    """Validated avctl path for `pkexec avctl ...` (pkexec_helper.py).

    Uses $AVCTL_PATH only when it passes the checks above; otherwise
    falls back to the first existing system candidate, else the default.
    Never returns a relative path."""
    raw = os.environ.get("AVCTL_PATH")
    if raw and os.path.isabs(raw):
        real = os.path.realpath(raw)
        if _looks_like_avctl(real):
            if host_exec.in_flatpak_sandbox():
                # Can't stat host files from inside the sandbox; enforce
                # shape only and let host-side pkexec/polkit decide.
                return real
            if _is_trusted_system_binary(real):
                return real
    for cand in _FALLBACK_CANDIDATES:
        try:
            real = os.path.realpath(cand)
        except OSError:
            continue
        if not _looks_like_avctl(real):
            continue
        if host_exec.in_flatpak_sandbox():
            return real
        try:
            if _is_trusted_system_binary(real):
                return real
        except OSError:
            continue
    return DEFAULT_AVCTL_PATH


def resolve_unprivileged_avctl_path():
    """Validated avctl path for direct unprivileged reads (procfs_client.py).

    No privilege elevation is involved here, so a from-source dev run
    pointing AVCTL_PATH at a user-owned build tree is legitimate and must
    keep working. Only enforce "absolute + executable regular file";
    fall back to the default otherwise."""
    raw = os.environ.get("AVCTL_PATH")
    if raw and os.path.isabs(raw):
        real = os.path.realpath(raw)
        if host_exec.in_flatpak_sandbox():
            return real
        try:
            st = os.stat(real)
        except OSError:
            pass
        else:
            if stat.S_ISREG(st.st_mode) and os.access(real, os.X_OK):
                return real
    return DEFAULT_AVCTL_PATH
