"""Raw client for avd's control socket (unprivileged verbs only).

See docs/avd-socket-protocol.md for the full wire protocol. This
module only speaks the three read-only verbs (STATUS, VERDICTS RECENT,
QUARANTINE LIST) - the three privileged verbs (SCAN, QUARANTINE
RESTORE/DELETE) go through pkexec_helper.py + avctl instead, since
avd's own SO_PEERCRED check would reject them from this unprivileged
GUI process even if we sent them directly.
"""
import os
import socket

DEFAULT_SOCK_PATH = "/run/avd/control.sock"


def _sock_path():
    return os.environ.get("AVD_SOCK_PATH", DEFAULT_SOCK_PATH)


class AvdError(Exception):
    """Raised for a connection failure or an ERR response from avd."""


def _request(cmd):
    """Sends one command line and returns the full response text. avd
    closes the connection after exactly one response (one command per
    connection - see the protocol doc), so reading until EOF is how a
    client knows the response is complete; there is no length prefix.
    """
    path = _sock_path()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(path)
            sock.sendall((cmd + "\n").encode("utf-8"))
            sock.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
    except OSError as exc:
        raise AvdError(
            f"could not connect to avd control socket {path}: {exc} "
            "(is avd running?)"
        ) from exc
    return b"".join(chunks).decode("utf-8", errors="replace")


def _parse_rows(resp):
    """Parses an "OK\\nCOUNT n\\n<rows>\\nEND\\n" response into a list
    of tab-split field lists. Raises AvdError on an "ERR ..." response
    or anything else malformed."""
    lines = resp.split("\n")
    if not lines or lines[0] != "OK":
        if lines and lines[0].startswith("ERR "):
            raise AvdError(lines[0][4:])
        raise AvdError("malformed response from avd control socket")

    rows = []
    for line in lines[1:]:
        if line.startswith("COUNT ") or line == "":
            continue
        if line == "END":
            break
        rows.append(line.split("\t"))
    return rows


def status():
    """Returns a dict: uptime_secs, rules_loaded, fuzzy_corpus_count,
    tlsh_corpus_count, scan_queue_len, scan_threads (all int)."""
    rows = _parse_rows(_request("STATUS"))
    if not rows:
        raise AvdError("STATUS returned no data")
    keys = [
        "uptime_secs", "rules_loaded", "fuzzy_corpus_count",
        "tlsh_corpus_count", "scan_queue_len", "scan_threads",
    ]
    return dict(zip(keys, (int(v) for v in rows[0])))


def verdicts_recent(n=100):
    """Returns a list of dicts (newest first): id, timestamp, pid,
    path, sha256, verdict, rule_name, score, on_demand."""
    rows = _parse_rows(_request(f"VERDICTS RECENT {int(n)}"))
    keys = [
        "id", "timestamp", "pid", "path", "sha256", "verdict",
        "rule_name", "score", "on_demand",
    ]
    return [dict(zip(keys, r)) for r in rows]


def quarantine_list():
    """Returns a list of dicts: id, original_path, timestamp,
    rule_name, sha256."""
    rows = _parse_rows(_request("QUARANTINE LIST"))
    keys = ["id", "original_path", "timestamp", "rule_name", "sha256"]
    return [dict(zip(keys, r)) for r in rows]
