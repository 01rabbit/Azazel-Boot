# Implementation readiness

Boot does not build or retain an OS image or media writer. The historical R11
and R10 images, build inputs, initramfs/QEMU outputs, and builder/writer tooling
are not current inputs or acceptance evidence. A future run uses an exact
user-supplied Debian Live image and user-prepared SSD; Boot does not substitute
another image.

The repository currently provides only `azazel-boot status` and the
user-managed Live/Nexus operator guidance. No Boot installer, host mutation,
network fetch, provider admission, model acquisition, or Edge activation is
implemented. No separate-PC boot check has yet been recorded.

Use [the operator guide](user-prepared-live.md) for the intended user-provided
image, persistence, Nexus installer, and separate-PC boot workflow. The actual
image/SSD and PC evidence are still required. Do not rebuild retired ISO/QEMU
artifacts as a prerequisite or treat historical QEMU runs as a substitute.
Before implementing a separate Boot helper, use the
[tool proposal template](tool-proposal-template.md) and obtain review.
