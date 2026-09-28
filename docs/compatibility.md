# Host compatibility

**No host environment is yet hardware-verified.** The intended user-managed
flow is a user-supplied Debian Live SSD on a separate PC, followed by the
existing Nexus tools installer. The exact Live image and PC combination have
not been qualified, and Boot has no operational installer or runtime.

Any future executable tool proposal must list exact OS/distribution versions,
architectures, privilege requirements, package manager assumptions, and
offline/online behavior. A user-prepared image or an individual PC boot test
does not establish general compatibility. Compatibility is not inferred from
a QEMU result or the fact that a Python package imports.
