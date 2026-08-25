"""Policy page - fail-open/fail-closed toggle for what happens to an
exec when avd can't produce a verdict in time
(/proc/kernel_av_daemon_policy via avctl policy set)."""
import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from .. import procfs_client, pkexec_helper


class Page:
    def __init__(self, toast_fn):
        self._toast = toast_fn
        self._updating = False

        outer = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=12,
            margin_top=16, margin_bottom=16, margin_start=16, margin_end=16,
        )

        outer.append(Gtk.Label(
            label="What should happen to an exec when avd can't produce a "
                  "verdict in time (not running, crashed, or slow)?",
            xalign=0, wrap=True,
        ))

        self._fail_open_radio = Gtk.CheckButton(label="Fail open (allow the exec) — default")
        self._fail_closed_radio = Gtk.CheckButton(label="Fail closed (kill the exec)")
        self._fail_closed_radio.set_group(self._fail_open_radio)
        self._fail_open_radio.connect("toggled", self._on_toggled)
        self._fail_closed_radio.connect("toggled", self._on_toggled)
        outer.append(self._fail_open_radio)
        outer.append(self._fail_closed_radio)

        self._error_label = Gtk.Label(xalign=0, wrap=True)
        self._error_label.add_css_class("error")
        outer.append(self._error_label)

        self.widget = outer
        self.refresh()

    def refresh(self):
        self._error_label.set_label("")
        try:
            state = procfs_client.read_state()
        except procfs_client.ProcfsError as exc:
            self._error_label.set_label(f"avctl: {exc}")
            return

        self._updating = True
        if state["policy"] == "fail-closed":
            self._fail_closed_radio.set_active(True)
        else:
            self._fail_open_radio.set_active(True)
        self._updating = False

    def _on_toggled(self, button):
        if self._updating or not button.get_active():
            return
        value = "fail-closed" if button is self._fail_closed_radio else "fail-open"

        def done(ok, stdout, stderr):
            if ok:
                self._toast(f"Policy set to {value}")
            else:
                self._toast(f"Policy change failed: {(stderr or stdout).strip() or 'unknown error'}")
                self.refresh()  # revert the toggle to the actual current state
        pkexec_helper.run_privileged(["policy", "set", value], done)
