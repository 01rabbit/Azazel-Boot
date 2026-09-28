# Issue map

Current Boot scope is recorded in
[ADR-0012](adr/0012-existing-environment-tooling.md): user assistance and a
possible bounded tool installer in an environment supplied and started by the
user. Boot does not install/build/remaster an OS, write media, own the
persistence volume, or provide/replace the Nexus installer. Guidance for
user-configured Debian Live persistence and separate-PC boot verification is
in scope.

## Active issues

- [#61](https://github.com/01rabbit/Azazel-Boot/issues/61) — document and
  verify the user's own Debian Live persistence configuration against the
  current Nexus installer paths. This is not a Boot-managed manifest, mount
  service, or selective-persistence implementation.
- [#63](https://github.com/01rabbit/Azazel-Boot/issues/63) — verify the
  user-prepared SSD on a separate PC, including boot, Nexus installer/status,
  and persistence across reboot. Hardware evidence is pending; QEMU/R10/R11
  reports do not satisfy it.

## Retired issues

The following former Boot issues remain closed as `not_planned`, because their
acceptance criteria required Boot-owned OS construction, media writing,
initramfs quarantine, encrypted persistence lifecycle, runtime authority,
or prototype signing rather than the current user-managed flow:

`#1 #4 #6 #8–12 #16 #17 #26–28 #40–42 #49 #52 #55 #57–60 #62 #65 #66`.
Their comments and earlier measurements are historical; closure does not mean
the former engineering or hardware criteria passed. In particular, R10/R11,
builder evidence, and QEMU runs are not accepted as evidence for #61 or #63.

## How to start new work

Do not reopen a retired builder/writer issue to reuse its implementation plan.
For the current workflow, update #61/#63 with exact image, installer, and
hardware evidence. A new executable helper still needs a proposal using the
[tool proposal template](tool-proposal-template.md), including why it belongs
in Boot rather than Nexus, supported host, authenticated inputs, privileges,
exact side effects, approval, rollback/uninstall, and tests. No autonomous
partitioning/writing, provider admission, model fetch, network activation, or
Edge activation is approved.
