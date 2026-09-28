# User-prepared Debian Live SSD with Nexus tools

This is the intended operator workflow for Boot: the user supplies and starts
the Debian Live system, configures its own persistence, uses the existing
Nexus-owned tools installer, then checks the SSD on a separate PC. Boot assists
with the checklist and evidence; it does not build Debian, write media, or own
the persistence lifecycle.

This is guidance, not a claim that a particular Live image, SSD, persistence
configuration, Nexus package set, or PC has been tested together. The separate
PC check remains open until it is performed and its sanitized evidence is
recorded. QEMU evidence is not a substitute.

## 1. Identify the exact Live system

Record the user-supplied image name/version, architecture, and SHA-256, and
preserve its existing boot and partition layout. Do not infer layout from an
ISO file size or from another prototype. Confirm that this exact image uses
Debian `live-boot` and supports its persistence feature; different Live images
may have different boot parameters and persistence support.

The [Debian Live Manual](https://live-team.pages.debian.net/live-manual/)
describes the `persistence` boot parameter and persistence volumes. When that
parameter is enabled, `live-boot` probes local storage for matching persistence
volumes; Boot does not quarantine other attached storage. Under that mechanism,
a volume is selected by its supported label/GPT name and needs a
`persistence.conf` file at its filesystem root. The
[`persistence.conf(5)` manual](https://manpages.debian.org/trixie/live-boot-doc/persistence.conf.5.en.html)
defines custom mount entries and restrictions. Consult the documentation
matching the exact Live image before changing anything.

Boot does not provide partitioning, formatting, encryption, or disk-write
commands. The user chooses and performs any media/persistence setup with their
own authorized method. Never guess which disk is the SSD or reuse another
prototype's partition sizes or layout.

## 2. Choose and verify persistence yourself

Debian Live persistence is opt-in for supported images. The user chooses which
paths or state to retain and configures the exact Live system accordingly. A
`/ union` configuration is whole-root persistence; custom entries are
selective and have path limitations. Neither choice is prescribed by Boot.
Portable persistence may expose retained data if unencrypted; encrypted
persistence is available only when the exact image and its boot configuration
support it. Boot does not create keys, format encrypted volumes, unlock them,
or claim that encryption is enabled.

Test persistence with a harmless marker in a path selected by the user, reboot
the Live system, and confirm whether that marker survives. This checks only the
chosen image and persistence configuration; it does not establish a Boot-owned
allowlist or a host-storage no-write guarantee.

## 3. Use the existing Nexus tools installer

Boot does not package or replace the Nexus installer. Follow the matching
Nexus release's own instructions and use its existing
[`packaging/install.sh`](https://github.com/01rabbit/Azazel-Nexus/blob/36a4759079c6eccd8ba2dfa894ed0dac005ff5c0/packaging/install.sh)
only after its prerequisites are satisfied. At the source checked for this
guide (Azazel-Nexus `main` commit
`36a4759079c6eccd8ba2dfa894ed0dac005ff5c0`, package version
`0.0.1.dev0`), the script expects Nexus runtime entrypoints to have already
been staged under `/usr/libexec/azazel`; it also requires Python 3.11 or
newer. Creating the
declared service accounts and ownership requires root, and applying the
service-manager stage requires systemd to be running. A run with
`--without-service-manager` explicitly skips masking/enabling units and is not
evidence of a fully configured installation.

The installer writes configuration/state under `/etc/azazel` and
`/var/lib/azazel`, installs unit files under `/lib/systemd/system`, and installs
a systemd preset under `/lib/systemd/system-preset`. Review the current Nexus
installer and package manifest for the exact release before deciding which
paths the user's persistence configuration must retain. Persisting `/home`
alone may not retain a system-wide installation. Do not copy an old path list
without checking the current Nexus release.

The current installer masks governed operational units and enables only its
activation controller; it does not start the operational network during
installation. Boot does not admit providers, fetch models, commission a
network, or activate Edge. Follow Nexus-owned instructions for any later
operator-authorized steps.

## 4. Separate-PC boot check

After the user has prepared the SSD and completed their persistence setup,
boot that exact SSD on the separately designated PC. This is a hardware check,
not a Boot image-build step. Do not change firmware or Secure Boot settings as
part of this runbook. If the image does not boot under the PC's current
configuration, record the refusal/failure and stop; do not infer support from
QEMU or from a different PC.

Record, without secrets or raw disk identifiers:

- exact Live image version and SHA-256;
- persistence mode selected by the user and whether the harmless marker
  survived a reboot;
- PC model/firmware and observed Secure Boot state, without claiming broader
  compatibility;
- whether the Live system reached userspace on that separate PC;
- Nexus installer version, whether all declared prerequisites were present,
  and the resulting Nexus status;
- whether selected Nexus files/services remain present after reboot according
  to the user's persistence configuration;
- failures, workarounds, and any firmware or media changes (none are performed
  by Boot).

A successful run proves only this image, persistence configuration, installer
version, SSD, and PC combination. It does not prove Secure Boot compatibility,
other hardware, a Boot writer, Boot-owned persistence, or production readiness.
