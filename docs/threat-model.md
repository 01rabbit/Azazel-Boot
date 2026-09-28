# Threat model for Boot tooling

Status: **initial boundary; concrete installer threat model is pending a
defined tool and host contract**.

Azazel-Boot assists with an operating environment and Debian Live SSD supplied
and started by the user. It does not create that OS, write boot media,
repartition disks, or claim to protect an entire host from a compromised
kernel or administrator. The current repository has no operational installer.

## Protected boundaries

- Boot cannot grant itself, a provider, a model, or an installed tool decision
  or enforcement authority. Azazel-Edge remains the sole authority.
- No helper may fetch remote content or admit a provider by default.
- No OS-image build, block-device writer, partitioner, formatter, firmware
  change, or Secure Boot change is part of Boot.
- A user-performed boot test on a designated separate PC is in scope, but Boot
  does not guarantee that the host's internal storage is untouched. Debian
  Live's persistence discovery and the exact image's other boot behavior must
  be understood by the operator; Boot does not provide initramfs quarantine.
- A future installer must name every package and target path, verify pinned
  inputs before changes, request explicit approval for declared host changes,
  and fail closed on unknown input or target state.
- Logs and status output must not expose credentials, private keys, or
  unnecessary host identifiers.

## Out of scope until separately specified

Physical-media no-write guarantees, initramfs quarantine, Boot-managed
persistence/LUKS lifecycle, surprise-removal handling, general laptop
compatibility, and firmware behavior belonged to the retired bootable-OS
design. The current PC test is one recorded observation, not a compatibility
claim or host-storage safety guarantee.

If a future Boot helper needs elevated privilege, network access, provider
admission, or Edge activation, that is a new security boundary and must be
reviewed before implementation. The present document does not authorize it.
