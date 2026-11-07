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

Boot does not package or replace the Nexus installer. For this guide the
reference is [Nexus main `3d9a2a68`](https://github.com/01rabbit/Azazel-Nexus/blob/3d9a2a68d9e60105b183e33d0d1ee5040796616d/docs/debian-live-install.md).
Its optional MIO dependency pins source `989dd959`, version
`0.1.0.dev20261107+gited860f2`. This identifies the reference tuple, not a
production admission or a claim that another version is compatible. Obtain
and verify the exact packages and their dependencies independently. Public
source availability is not authorization to deploy or enable services.

The reviewed install profile is Debian 13, with amd64 as the deployment
baseline and arm64 restricted to lab software verification; neither is a
hardware qualification. The installer needs Python 3.11 or newer, both Nexus
and Nexus runtime distributions installed as regular packages in the same
stable environment, a verified source tree, root and a running systemd for the
full integration stage. Runtime includes a Linux native extension and requires a
matching wheel. See the linked Nexus guide for the complete prerequisites,
offline bundle and platform checks. The installer itself generates and checks
the fixed runtime wrappers before account, state-directory and systemd changes;
it does not create the Python environment or install its packages.

The Python 3.11 floor is a package/test requirement, not the complete systemd
installation requirement. For the normal service-manager stage, the staged
wrappers must resolve to interpreter `/usr/bin/python3.13` and import paths
under `/usr/lib/python3.13` or `/opt/azazel-nexus/venv`, as required by the
AppArmor profiles. The example venv must resolve to these actual paths; an
arbitrary Python 3.13 installation is not sufficient. See the fixed Nexus
[operations deception section, AppArmor profiles](https://github.com/01rabbit/Azazel-Nexus/blob/3d9a2a68d9e60105b183e33d0d1ee5040796616d/docs/operations.md#deception-lite-decoy-network-196)
for the full conditions.

Once the operator has independently approved host integration and satisfied
those prerequisites, follow the Nexus guide's installation command. The
installer creates accounts and state/configuration, installs units, masks
governed units and enables the activation controller. It does not start the
operational network during installation. `--without-service-manager` omits
the manager stage and is not a completed systemd installation.

Inspect the installed environment using the read-only commands shown by Nexus:

```sh
/opt/azazel-nexus/venv/bin/azazel-nexus setup
/opt/azazel-nexus/venv/bin/azazel-nexus status
```

A successful `setup` command means guidance was produced, not that installation,
commissioning or admission succeeded. Preserve the output with sensitive data
removed and investigate any refusal or unknown state. If prerequisites fail,
stop and preserve the existing system and installer output; do not retry with
weakened checks. A failed installer can leave staged wrappers or other partial
changes: consult the Nexus guide and its operations recovery instructions
before any retry or restoration. Boot has no automatic rollback or uninstall.
Review Nexus's path inventory before choosing persistence; `/home` alone may
not retain a system-wide installation. Boot does not admit providers, fetch
models, commission a network, or activate Edge.

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
