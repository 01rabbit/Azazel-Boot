# Threat model for Boot tooling

Status: **initial boundary; concrete installer threat model is pending a
defined tool and host contract**.

Azazel-Boot runs inside an operating environment selected and started by the
user. It does not create that OS, write boot media, repartition disks, or claim
to protect an entire host from a compromised kernel or administrator. The
current repository has no operational installer.

## Protected boundaries

- Boot cannot grant itself, a provider, a model, or an installed tool decision
  or enforcement authority. Azazel-Edge remains the sole authority.
- No helper may fetch remote content or admit a provider by default.
- No OS-image build, block-device writer, partitioner, formatter, firmware
  change, or Secure Boot change is part of Boot.
- A future installer must name every package and target path, verify pinned
  inputs before changes, request explicit approval for declared host changes,
  and fail closed on unknown input or target state.
- Logs and status output must not expose credentials, private keys, or
  unnecessary host identifiers.

## Out of scope until separately specified

Physical-media no-write guarantees, initramfs quarantine, USB persistence,
LUKS lifecycle, surprise-removal handling, laptop compatibility claims, and
firmware behavior belonged to the retired bootable-OS design. They are not
claims or implementation requirements for the current helper-tool scope.

If a future Boot helper needs elevated privilege, network access, provider
admission, or Edge activation, that is a new security boundary and must be
reviewed before implementation. The present document does not authorize it.
