# Issue map

Current Boot scope is recorded in
[ADR-0012](adr/0012-existing-environment-tooling.md): user assistance and a
possible bounded tool installer in an environment supplied and started by the
user. Boot does not create/remaster an OS, build/write media, own initramfs or
USB persistence, or provide the Nexus base installer.

## Active issues

None. As of 2026-09-28, all issues for the retired bootable-OS, image-builder,
writer, initramfs, persistence and physical-HIL direction have been closed as
no longer planned. Bootstrap issue #1 was closed as not planned because its
USB-SSD product premise was superseded before those hardware criteria were met. Issue bodies
and comments remain on GitHub as history; closure does not mean their old
hardware acceptance criteria were met.

## How to start new work

Do not reopen a retired issue to reuse its implementation plan. For one
concrete user-assistance tool, first create a new issue using the
[tool proposal template](tool-proposal-template.md). It must state why the tool
belongs in Boot rather than Nexus, its supported host, authenticated inputs,
privileges and exact side effects, operator approval, rollback/uninstall, and
synthetic/software verification. No feature, host environment, network access,
provider admission, model fetch, or Edge activation is currently approved.
