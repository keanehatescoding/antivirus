"""Dashboard page - avd's STATUS plus a summary of state read via
`avctl save -` (signature/trust/protected counts, current policy)."""
import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from .. import avd_client, path_validation, procfs_client

_ROWS = [
    "avd status", "uptime", "rules loaded", "fuzzy corpus entries",
    "TLSH corpus entries", "scan queue depth", "scan worker threads",
    "signatures", "trusted binaries", "protected paths",
    "daemon-unavailable policy",
]


class Page:
    def __init__(self):
        self.widget = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=12,
            margin_top=16, margin_bottom=16, margin_start=16, margin_end=16,
        )

        grid = Gtk.Grid(row_spacing=6, column_spacing=16)
        self.widget.append(grid)

        self._value_labels = {}
        for i, label in enumerate(_ROWS):
            key_lbl = Gtk.Label(label=label + ":", xalign=1)
            key_lbl.add_css_class("dim-label")
            val_lbl = Gtk.Label(label="-", xalign=0)
            grid.attach(key_lbl, 0, i, 1, 1)
            grid.attach(val_lbl, 1, i, 1, 1)
            self._value_labels[label] = val_lbl

        self._error_label = Gtk.Label(xalign=0, wrap=True)
        self._error_label.add_css_class("error")
        self.widget.append(self._error_label)

        self.refresh()

    def _set(self, key, value):
        self._value_labels[key].set_label(str(value))

    def refresh(self):
        """Updates the dashboard with current status from avd and the kernel module."""
        errors = []

        try:
            st = avd_client.status()
            self._set("avd status", "running")
            self._set("uptime", f"{st['uptime_secs']}s")
            self._set("rules loaded", "yes" if st["rules_loaded"] else "no")
            self._set("fuzzy corpus entries", st["fuzzy_corpus_count"])
            self._set("TLSH corpus entries", st["tlsh_corpus_count"])
            self._set("scan queue depth", st["scan_queue_len"])
            self._set("scan worker threads", st["scan_threads"])
        except avd_client.AvdError as exc:
            self._set("avd status", "unreachable")
            for key in _ROWS[1:7]:
                self._set(key, "-")
            errors.append(path_validation.for_display(f"avd: {exc}"))

        try:
            state = procfs_client.read_state()
            self._set("signatures", len(state["signatures"]))
            self._set("trusted binaries", len(state["trust"]))
            self._set("protected paths", len(state["protected"]))
            self._set(
                "daemon-unavailable policy",
                path_validation.for_display(state["policy"] or "-"),
            )
        except procfs_client.ProcfsError as exc:
            for key in _ROWS[7:]:
                self._set(key, "-")
            errors.append(path_validation.for_display(f"avctl: {exc}"))

        self._error_label.set_label("\n".join(errors))
