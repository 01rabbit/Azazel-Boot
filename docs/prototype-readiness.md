# Implementation readiness

Boot has no active image or media prototype. The historical R11 ISO, build
inputs, initramfs/QEMU outputs, and builder/writer tooling were removed when
their scope was retired. They are not current inputs, supported procedures,
or evidence for a Boot installer.

The repository currently provides only `azazel-boot status`. No installer,
host mutation, network fetch, provider admission, model acquisition, or Edge
activation is implemented.

Before starting one helper tool, use the
[tool proposal template](tool-proposal-template.md) to record its user problem,
why it belongs in Boot rather than Nexus, supported host, pinned inputs,
privileges, exact effects, approval, failure/rollback, and tests. Implement
only after that proposal is reviewed. Do not rebuild retired ISO/QEMU artifacts
as a prerequisite or as evidence for the new scope.
