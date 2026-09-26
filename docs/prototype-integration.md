# Boot/Nexus prototype integration

`tools/prototype_integration.py` is the umbrella-level fixture harness for the
first end-to-end seam. It reads a C5 inspection manifest, requires the C5
verdict to be `pass`, then drives Boot's declarative stage runner with a Nexus
installer facade at these stages:

```text
UEFI → initramfs quarantine → immutable root → Boot userspace
     → Nexus install → status → generation change → rollback
```

The harness writes only below the explicitly supplied fixture roots and result
path. It does not invoke QEMU, systemd, a firmware, a network, a block device,
or a production image builder. Its result is always
`evidence_class=qemu_fixture_only`, with `hardware_verified=false` and
`builder_selected=false`.

Example:

```sh
python tools/prototype_integration.py \
  --boot-root ../Azazel-Boot-audit-worktree \
  --nexus-root ../Azazel-Nexus-harness \
  --c5-manifest /tmp/c5-manifest.json \
  --nexus-fixture-root /tmp/azazel-nexus-fixture \
  --result /tmp/azazel-prototype-result.json
```

The C5 manifest must be produced by a fixture or an image inspector. A passing
single-host C5 result does not establish the two-independent-builder
reproducibility requirement, and this harness does not select a builder. The
result records `c5_source=inspection_fixture` so the C5 evaluator's
`measured_on_a_built_initramfs` vocabulary is not mistaken for hardware
evidence.
