# Flatpak: hyprav-gui

Packages the GTK4 management console (`userspace/av-gui`) only -
**not** the kernel module (`av.ko`/`hyprav-dkms`) or the privileged
`avd` system daemon. Neither of those can be sandboxed this way: a
DKMS-built out-of-tree kernel module and a root `systemd` service that
talks to it over netlink aren't things a Flatpak (or any sandboxed
userspace format) can contain. Install `hyprav` + `hyprav-dkms`
natively first - via the Arch `PKGBUILD`, Debian `debian/`, or Fedora
`hyprav.spec` under `packaging/` - then this Flatpak is a thin client
on top of that installation, same as running `av-gui` from a native
package would be. See the top-level README's "GUI: av-gui" section for
what av-gui actually does.

## Why the sandbox needs escaping

av-gui's own privileged/unprivileged calls always target the HOST:

- **Unprivileged reads** go straight to avd's control socket
  (`/run/avd/control.sock` by default) and to `avctl save -`.
- **Privileged writes** (every add/remove/restore/delete/scan button)
  run `pkexec avctl ...`, gated by the `org.hyprav.avctl.policy`
  polkit action installed alongside the native `hyprav` package.

Both of those only exist on the host, never inside the sandbox, so
this manifest's `finish-args` grant:

- `--filesystem=/run/avd:ro` - direct read access to avd's control
  socket.
- `--talk-name=org.freedesktop.Flatpak` - lets
  `userspace/av-gui/av_gui/host_exec.py` run `avctl`/`pkexec` via
  `flatpak-spawn --host` instead of inside the sandbox, the same
  mechanism tools like GNOME Builder use for host toolchain access.
  `host_exec.py` only adds that prefix when `/.flatpak-info` exists
  (i.e. only inside this build) - native installs and the AppImage
  build are unaffected.

## Build

Bump `runtime-version` in `org.hyprav.avgui.yml` to whatever's
currently available first if `49` has aged out (already bumped once
from `47`, which fell off Flathub between this manifest being written
and first built).

```bash
flatpak install flathub org.gnome.Platform//49 org.gnome.Sdk//49
flatpak-builder --user --install --force-clean \
    build-dir packaging/flatpak/org.hyprav.avgui.yml
flatpak run org.hyprav.avgui
```
