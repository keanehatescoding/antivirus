# Split package, same reasoning as packaging/arch/PKGBUILD and
# debian/control: av.ko is version-pinned to whatever kernel it's
# built against, so it ships as DKMS source (hyprav-dkms) and is
# rebuilt automatically against every installed kernel, instead of
# being compiled here at rpmbuild time. avd/avctl (hyprav) and the
# GTK4 console (hyprav-gui) are plain userspace and get built normally.
#
# CONFIRMED BROKEN, NOT YET FIXED: Fedora's own tlsh.spec (checked
# f41 through f44 and rawhide at src.fedoraproject.org/rpms/tlsh) only
# builds tlsh-doc and python3-tlsh - the Python bindings. There is no
# tlsh-devel, no libtlsh.so, no /usr/include/tlsh.h anywhere in
# current Fedora; the C library package this project's Makefiles
# assume (`tlsh` on Arch, `libtlsh-dev` on Debian) simply does not
# exist here, and hasn't for a long time (python3-tlsh's spec still
# carries `Obsoletes: tlsh-devel < 3.17.0` from whenever it was
# dropped). No COPR providing a current tlsh-devel-equivalent was
# found either. `BuildRequires: tlsh-devel` below WILL fail to
# resolve - this spec cannot build as written until that's addressed
# (e.g. vendoring upstream TLSH's C++ source into %build, or dropping
# TLSH support for the Fedora build specifically).

%global gitcommit 32d9af8

Name:           hyprav
Version:        0.9.0.129.g%{gitcommit}
Release:        1%{?dist}
Summary:        Kernel-level Linux antivirus (kprobe execve/file monitor + YARA/entropy/fuzzy-hash daemon)

# SPDX identifier (current Fedora Licensing Guidelines). Older Fedora
# releases (pre F38-ish) used the short name "GPLv3" instead - adjust
# if targeting one of those.
License:        GPL-3.0-only
URL:            https://github.com/keanehatescoding/antivirus
Source0:        %{url}/archive/%{gitcommit}/antivirus-%{gitcommit}.tar.gz

BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  make
BuildRequires:  pkgconfig
BuildRequires:  pkgconfig(libnl-genl-3.0)
BuildRequires:  yara-devel
BuildRequires:  ssdeep-devel
BuildRequires:  tlsh-devel
BuildRequires:  systemd-rpm-macros

%description
HyprAV is a kprobe-based kernel module (av.ko) that hooks execve and
file events, does fast hash/counter checks in-kernel, and defers
anything heavier - YARA matching, ELF structural analysis, entropy
scoring, ssdeep/TLSH fuzzy hashing - to avd, a privileged userspace
daemon it talks to over netlink. avctl is the CLI (and polkit-gated
privileged entry point) for managing avd's signatures, trust list,
protected paths, policy, on-demand scans, and quarantine.

This base package installs avd and avctl. See hyprav-dkms for the
kernel module and hyprav-gui for the GTK4 management console.

%package -n hyprav-dkms
Summary:        HyprAV kprobe-based execve/file-event kernel module (DKMS)
Requires:       dkms
Requires(post): dkms
Requires(preun): dkms
BuildArch:      noarch

%description -n hyprav-dkms
Out-of-tree kernel module (av.ko) that hooks execve and file events
via kprobes and talks to the avd userspace daemon over netlink for
anything heavier. Ships as DKMS source and is rebuilt automatically
against every installed kernel.

x86_64 only as shipped - the module hooks __x64_sys_execve by symbol
name; arm64 needs source changes to hook __arm64_sys_execve instead.

%package -n hyprav-gui
Summary:        GTK4 management console for HyprAV
BuildArch:      noarch
Requires:       %{name} = %{version}-%{release}
Requires:       python3
Requires:       python3-gobject
Requires:       gtk4

%description -n hyprav-gui
Dashboard (avd status + counts), detections (recent verdict history),
quarantine (list/restore/delete), an on-demand scan page, and
signatures/trust list/protected paths/policy management, sitting on
top of avd and avctl. A normal desktop app, not a daemon - launch it
on demand. Privileged actions go through pkexec avctl, gated by the
org.hyprav.avctl.manage polkit action installed by the base package.

%prep
%autosetup -n antivirus-%{gitcommit}

%build
make -C userspace/avd
make -C userspace/avctl

%install
make -C userspace/avd install DESTDIR=%{buildroot} PREFIX=%{_prefix} UNITDIR=%{_unitdir}
make -C userspace/avctl install DESTDIR=%{buildroot} PREFIX=%{_prefix} POLKIT_ACTIONDIR=%{_datadir}/polkit-1/actions
install -dm755 %{buildroot}%{_localstatedir}/lib/av-quarantine

install -dm755 %{buildroot}%{_usrsrc}/hyprav-av-%{version}
cp -r av/* %{buildroot}%{_usrsrc}/hyprav-av-%{version}/
# KDIR override for the same reason as the Arch/Debian packaging:
# dkms may build against a kernel that isn't the one `uname -r`
# currently reports (e.g. mid kernel-upgrade, before reboot).
cat > %{buildroot}%{_usrsrc}/hyprav-av-%{version}/dkms.conf <<EOF
PACKAGE_NAME="hyprav-av"
PACKAGE_VERSION="%{version}"
BUILT_MODULE_NAME[0]="av"
DEST_MODULE_LOCATION[0]="/kernel/drivers/misc"
AUTOINSTALL="yes"
MAKE[0]="make KDIR=\${kernel_source_dir}"
CLEAN="make KDIR=\${kernel_source_dir} clean"
EOF

make -C userspace/av-gui install DESTDIR=%{buildroot} PREFIX=%{_prefix}

%post
%systemd_post avd.service

%preun
%systemd_preun avd.service

%postun
%systemd_postun_with_restart avd.service

%post -n hyprav-dkms
dkms add -m hyprav-av -v %{version} || :
dkms autoinstall -m hyprav-av -v %{version} || :

%preun -n hyprav-dkms
dkms remove -m hyprav-av -v %{version} --all || :

%files
%license LICENSE
%doc README.md
%{_bindir}/avd
%{_bindir}/avctl
%{_unitdir}/avd.service
%{_datadir}/polkit-1/actions/org.hyprav.avctl.policy
%dir %{_sysconfdir}/hyprav
%dir %{_sysconfdir}/hyprav/rules
%config(noreplace) %{_sysconfdir}/hyprav/rules/*.yar
%config(noreplace) %{_sysconfdir}/hyprav/fuzzy_hashes.txt
%config(noreplace) %{_sysconfdir}/hyprav/tlsh_hashes.txt
%dir %{_localstatedir}/lib/av-quarantine

%files -n hyprav-dkms
%license LICENSE
%{_usrsrc}/hyprav-av-%{version}/

%files -n hyprav-gui
%license LICENSE
%{_bindir}/av-gui
%{_prefix}/lib/hyprav/av-gui/
%{_datadir}/applications/av-gui.desktop

%changelog
* Tue Aug 25 2026 Your Name <you@example.com> - 0.9.0.129.g32d9af8-1
- Initial packaging: hyprav-dkms (av.ko kernel module), hyprav
  (avd daemon + avctl CLI), hyprav-gui (GTK4 console).
